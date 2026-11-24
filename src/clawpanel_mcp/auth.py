"""ClawPanel OAuth — client identity for the client-facing MCP.

Same OAuth 2.1 machinery as zme-mcp (ZeuglabOAuthProvider pattern): DCR,
PKCE, authorization codes, refresh, revocation — plus the ClawPanel twist:

  login = email + passphrase
  email → `profiles` table (service call, server-side) → tenant_id + user_id
  passphrase + scopes → CLAWPANEL_OAUTH_PROFILES env (alpha; DB table in beta)

The tenant becomes part of the token principal: every tool call resolves the
bearer token back to its durable grant and a current workspace membership.
Tools never accept tenant input from the client.

Scopes mirror the mcp_tokens vocabulary already in clawpanel_db:
  brain   — agents, workspace status, chat history
  memory  — memory search + remember
  kb      — KB search/fetch
  drive   — reserved (drive_nodes tools land in beta)
"""
from __future__ import annotations

import json
import os
import re
import secrets
import time
import urllib.parse
from html import escape
from typing import Any

import anyio
from pydantic import AnyUrl

from fastmcp.server.auth.providers.in_memory import InMemoryOAuthProvider
from mcp.server.auth.handlers.metadata import MetadataHandler
from mcp.server.auth.middleware.client_auth import AuthenticationError, ClientAuthenticator
from mcp.server.auth.provider import AccessToken, AuthorizationParams, RefreshToken, TokenError
from mcp.server.auth.routes import REVOCATION_PATH, build_metadata, cors_middleware
from mcp.server.auth.settings import ClientRegistrationOptions, RevocationOptions
from mcp.shared.auth import OAuthClientInformationFull
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from starlette.routing import Route

ALL_SCOPES = ["brain", "memory", "kb", "drive", "approvals", "edit", "create"]
WORK_READ_SCOPE = "work:read"
HOST_SCOPES = ["approvals", "edit", "create"]  # workspace-host capabilities
OAUTH_TOKEN = re.compile(r"[A-Za-z0-9._~-]{1,512}")
AUTH_METADATA_PATH = "/.well-known/oauth-authorization-server"
REVOCATION_HEADERS = {"Cache-Control": "no-store", "Pragma": "no-cache"}
AUTH_PAGE_HEADERS = {"Cache-Control": "no-store", "Referrer-Policy": "no-referrer"}

LOGIN_PAGE = """<!doctype html><html><head><meta charset="utf-8">
<title>ClawPanel · sign in</title><meta name="viewport" content="width=device-width,initial-scale=1">
<style>body{{font-family:ui-sans-serif,system-ui;background:#0c1014;color:#e8e6e1;
display:grid;place-items:center;height:100vh;margin:0}}
form{{background:#131a21;border:1px solid #25313c;border-radius:12px;padding:2rem;
width:320px;display:grid;gap:.9rem}}
h1{{font-size:1.05rem;margin:0;font-weight:600}}p{{font-size:.8rem;color:#8fa0ae;margin:0}}
input{{background:#0c1014;border:1px solid #25313c;border-radius:8px;color:#e8e6e1;
padding:.6rem .7rem;font-size:.9rem}}
button{{background:#4f8ef7;border:0;border-radius:8px;padding:.65rem;font-weight:600;
cursor:pointer;color:#fff}}.err{{color:#e08585;font-size:.8rem}}</style></head>
<body><form method="post">
<h1>ClawPanel</h1>
<p>{client} wants access to your workspace. Sign in with the email on your
ClawPanel account.{work_notice}</p>
{error}
<input type="email" name="email" placeholder="you@company.com" autocomplete="username" required>
<input type="password" name="passphrase" placeholder="passphrase"
 autocomplete="current-password" required>
{hidden}
<button type="submit">Authorize</button></form></body></html>"""


class ClawpanelOAuthProvider(InMemoryOAuthProvider):
    def __init__(self, base_url: str, db, profiles_cfg: dict[str, dict], *, work_read: bool = False):
        self.valid_scopes = [*ALL_SCOPES, WORK_READ_SCOPE] if work_read else ALL_SCOPES
        self.default_scopes = ["kb", WORK_READ_SCOPE] if work_read else ["kb"]
        super().__init__(
            base_url=base_url,
            client_registration_options=ClientRegistrationOptions(
                enabled=True, valid_scopes=self.valid_scopes, default_scopes=self.default_scopes),
            revocation_options=RevocationOptions(enabled=True),
            required_scopes=["kb"],
        )
        self.db = db
        self.client_authenticator = ClientAuthenticator(self)
        self.profiles_cfg = {k.strip().lower(): v for k, v in profiles_cfg.items()}
        self._code_principal: dict[str, dict] = {}

    # -- principal plumbing -------------------------------------------------

    async def register_client(self, client_info):  # type: ignore[override]
        await anyio.to_thread.run_sync(self.db.save_client, client_info.model_dump(mode="json"))
        await super().register_client(client_info)

    async def get_client(self, client_id: str):  # type: ignore[override]
        client = await super().get_client(client_id)
        if client is None:
            row = await anyio.to_thread.run_sync(self.db.load_client, client_id)
            if row:
                client = OAuthClientInformationFull.model_validate(row)
                self.clients[client_id] = client
        return client

    def _token_record(self, token, principal: dict) -> dict:
        access = self.access_tokens[token.access_token]
        record = {
            "access_token": token.access_token, "refresh_token": token.refresh_token,
            "client_id": access.client_id, "scopes": access.scopes,
            "expires_at": access.expires_at, "principal": principal,
        }
        self._revoke_internal(access_token_str=token.access_token)
        return record

    def _admitted(self, row: dict | None) -> bool:
        principal = row.get("principal") if row else None
        if not principal:
            return False
        try:
            return self.db.has_workspace_membership(principal["user_id"], principal["tenant_id"])
        except (KeyError, TypeError, ValueError):
            return False

    def _active_access(self, token: str) -> dict | None:
        try:
            row = self.db.load_oauth_token_by_access(token)
            if row and row["expires_at"] and row["expires_at"] > time.time() and self._admitted(row):
                return row
        except Exception:
            # A storage outage cannot grant access based on a stale identity.
            return None
        return None

    def _active_refresh(self, client_id: str, token: str) -> dict | None:
        try:
            row = self.db.load_oauth_token_by_refresh(token)
            if row and row["client_id"] == client_id and self._admitted(row):
                return row
        except Exception:
            return None
        return None

    async def load_access_token(self, token: str):  # type: ignore[override]
        row = await anyio.to_thread.run_sync(self._active_access, token)
        if row:
            return AccessToken(token=token, client_id=row["client_id"], scopes=row["scopes"],
                               expires_at=row["expires_at"])
        return None

    async def load_refresh_token(self, client, refresh_token: str):  # type: ignore[override]
        row = await anyio.to_thread.run_sync(self._active_refresh, client.client_id, refresh_token)
        if row:
            return RefreshToken(token=refresh_token, client_id=row["client_id"], scopes=row["scopes"])
        return None

    async def revoke_token(self, token) -> None:  # type: ignore[override]
        await anyio.to_thread.run_sync(
            lambda: self.db.delete_oauth_token(token.token, refresh=isinstance(token, RefreshToken)))

    async def exchange_authorization_code(self, client, authorization_code):  # type: ignore[override]
        principal = self._code_principal.pop(authorization_code.code, None)
        if not await anyio.to_thread.run_sync(self._admitted, {"principal": principal}):
            raise TokenError("invalid_grant", "Current workspace access is required.")
        token = await super().exchange_authorization_code(client, authorization_code)
        await anyio.to_thread.run_sync(self.db.save_oauth_token, self._token_record(token, principal))
        return token

    async def exchange_refresh_token(self, client, refresh_token, scopes):  # type: ignore[override]
        row = await anyio.to_thread.run_sync(self._active_refresh, client.client_id, refresh_token.token)
        if not row:
            raise TokenError("invalid_grant", "The connection expired or was revoked.")
        current = RefreshToken(token=refresh_token.token, client_id=row["client_id"], scopes=row["scopes"])
        token = await super().exchange_refresh_token(client, current, scopes)
        updated = await anyio.to_thread.run_sync(
            self.db.rotate_oauth_token, refresh_token.token, self._token_record(token, row["principal"]))
        if not updated:
            raise TokenError("invalid_grant", "The connection expired or was revoked.")
        return token

    async def principal_for(self, token: str) -> dict | None:
        row = await anyio.to_thread.run_sync(self._active_access, token)
        return {**row["principal"], "scopes": row["scopes"]} if row else None

    # -- routes ---------------------------------------------------------------

    def get_routes(self, mcp_path: str | None = None) -> list[Route]:
        routes = super().get_routes(mcp_path)
        metadata = build_metadata(self.base_url, self.service_documentation_url,
                                  self.client_registration_options, self.revocation_options)
        for field in ("token_endpoint_auth_methods_supported", "revocation_endpoint_auth_methods_supported"):
            setattr(metadata, field, [*getattr(metadata, field), "none"])
        get_metadata = cors_middleware(MetadataHandler(metadata).handle, ["GET", "OPTIONS"])
        replaced = ("/authorize", REVOCATION_PATH, AUTH_METADATA_PATH)
        return [r for r in routes if getattr(r, "path", None) not in replaced] + [
            Route(AUTH_METADATA_PATH, get_metadata, methods=["GET", "OPTIONS"]),
            Route("/authorize", self._authorize_get, methods=["GET"]),
            Route("/authorize", self._authorize_post, methods=["POST"]),
            Route(REVOCATION_PATH, cors_middleware(self._revoke_connection, ["POST", "OPTIONS"]),
                  methods=["POST", "OPTIONS"]),
        ]

    async def _revoke_connection(self, request: Request) -> Response:
        try:
            client = await self.client_authenticator.authenticate_request(request)
        except AuthenticationError:
            return JSONResponse({"error": "unauthorized_client"}, status_code=401, headers=REVOCATION_HEADERS)

        token = (await request.form()).get("token")
        if not isinstance(token, str) or not token:
            return JSONResponse({"error": "invalid_request"}, status_code=400, headers=REVOCATION_HEADERS)
        if OAUTH_TOKEN.fullmatch(token):
            try:
                await anyio.to_thread.run_sync(self.db.revoke_oauth_connection, client.client_id, token)
            except Exception:
                return JSONResponse({"error": "temporarily_unavailable"}, status_code=503, headers=REVOCATION_HEADERS)
        return Response(status_code=200, headers=REVOCATION_HEADERS)

    async def _authorize_get(self, request: Request) -> HTMLResponse:
        return self._page(dict(request.query_params), error="")

    async def _authorize_post(self, request: Request) -> Any:
        form = await request.form()
        q = {k: str(v) for k, v in form.items()
             if k not in ("email", "passphrase", "workspace") and isinstance(v, str)}
        email = str(form.get("email", "")).strip().lower()
        secret = str(form.get("passphrase", ""))
        cfg = self.profiles_cfg.get(email)

        # The website password is the connector password: verify against
        # Supabase auth first so password rotations propagate automatically.
        # The env passphrase remains as a legacy fallback (and the only path
        # when Supabase auth is unreachable). Accounts dropped from
        # CLAWPANEL_OAUTH_PROFILES accept ONLY their website password.
        ok = await anyio.to_thread.run_sync(self.db.verify_password, email, secret)
        if ok is not True and not (ok is None and cfg and secrets.compare_digest(cfg.get("secret", ""), secret)):
            return self._page(q, error='<span class="err">Unknown email or bad password.</span>')

        profile = await anyio.to_thread.run_sync(self.db.resolve_profile, email)
        if not profile:
            return self._page(q, error='<span class="err">No ClawPanel workspace '
                                       'for this email.</span>')

        # One email, several workspaces: the connector's tenant comes from a
        # CHOSEN membership (picker page), not profiles.tenant_id. Single-
        # membership accounts skip the picker entirely.
        memberships = await anyio.to_thread.run_sync(self.db.memberships_for, email)
        if not memberships:
            return self._page(q, error='<span class="err">No ClawPanel workspace '
                                       'for this email.</span>')
        picked = memberships[0]
        if len(memberships) > 1:
            choice = str(form.get("workspace", "")).strip()
            match = next((m for m in memberships
                          if choice in (m["slug"], m["tenant_id"])), None)
            if match is None:
                return self._workspace_page(q, memberships, email)
            picked = match
        # Env-less accounts (password-only) get the workspace-user scopes.
        default_scopes = ["brain", "memory", *self.default_scopes]
        scopes = [s for s in (cfg.get("scopes", default_scopes) if cfg else default_scopes)
                  if s in self.valid_scopes]
        try:
            client = await self.get_client(str(q["client_id"]))
            if client is None:
                return self._page(q, error='<span class="err">Unregistered client.</span>')
            registered = (client.scope or "kb").split()
            requested = client.validate_scope(q.get("scope"))
            grant = [scope for scope in (registered if requested is None else requested) if scope in scopes]
            if "kb" not in grant or (requested is not None and len(grant) != len(requested)):
                return self._page(q, error='<span class="err">This account cannot grant the requested scopes.</span>')
            params = AuthorizationParams(
                redirect_uri=client.validate_redirect_uri(AnyUrl(str(q["redirect_uri"]))),
                redirect_uri_provided_explicitly=True,
                state=q.get("state") or None,
                scopes=grant,
                code_challenge=str(q["code_challenge"]),
                resource=q.get("resource") or None,
            )
            redirect_url = await super().authorize(client, params)
            code = urllib.parse.parse_qs(
                urllib.parse.urlparse(redirect_url).query).get("code", [None])[0]
            if code:
                self._code_principal[code] = {
                    "email": email,
                    "tenant_id": str(picked["tenant_id"]),
                    "user_id": str(profile["user_id"]),
                    "scopes": grant}
            return RedirectResponse(redirect_url, status_code=303)
        except Exception:
            return self._page(q, error='<span class="err">This authorization request is invalid or expired.</span>')

    def _page(self, q: dict[str, Any], error: str) -> HTMLResponse:
        hidden = "".join(
            f'<input type="hidden" name="{escape(k)}" value="{escape(str(v))}">' for k, v in q.items())
        notice = (" The connection can read your accessible Work issues and linked shared Library documents."
                  if WORK_READ_SCOPE in self.valid_scopes else "")
        return HTMLResponse(LOGIN_PAGE.format(
            client=escape(str(q.get("client_id", "An MCP client"))), error=error, hidden=hidden,
            work_notice=notice),
            headers=AUTH_PAGE_HEADERS)

    def _workspace_page(self, q: dict[str, Any], memberships: list[dict],
                        email: str = "") -> HTMLResponse:
        """Select the workspace, then confirm the connection with the password."""
        options = "".join(
            f'<option value="{escape(m["slug"] or m["tenant_id"])}">'
            f'{escape(m["name"] or m["slug"] or m["tenant_id"])}</option>'
            for m in memberships)
        hidden = "".join(
            f'<input type="hidden" name="{escape(k)}" value="{escape(str(v))}">' for k, v in q.items())
        return HTMLResponse(f"""<!doctype html><html><head><meta charset="utf-8">
<title>ClawPanel · pick a workspace</title><meta name="viewport" content="width=device-width,initial-scale=1">
<style>body{{font-family:ui-sans-serif,system-ui;background:#0c1014;color:#e8e6e1;
display:grid;place-items:center;height:100vh;margin:0}}
form{{background:#131a21;border:1px solid #25313c;border-radius:12px;padding:2rem;
width:320px;display:grid;gap:.9rem}}
h1{{font-size:1.05rem;margin:0;font-weight:600}}p{{font-size:.8rem;color:#8fa0ae;margin:0}}
select{{background:#0c1014;border:1px solid #25313c;border-radius:8px;color:#e8e6e1;
padding:.6rem .7rem;font-size:.9rem}}
button{{background:#4f8ef7;border:0;border-radius:8px;padding:.65rem;font-weight:600;
cursor:pointer;color:#fff}}</style></head>
<body><form method="post">
<h1>Pick a workspace</h1>
<p>This account belongs to {len(memberships)} workspaces. Which one should
this connection use?</p>
{hidden}
<label>Email <input type="email" name="email" value="{escape(email)}" autocomplete="username" required></label>
<label>Password <input type="password" name="passphrase" autocomplete="current-password" required></label>
<select name="workspace" required>{options}</select>
<button type="submit">Connect</button></form></body></html>""", headers=AUTH_PAGE_HEADERS)


RINGS = ("alpha", "beta", "prod")


def build_auth(base_url: str, db, *, work_read: bool = False) -> ClawpanelOAuthProvider | None:
    ring = (os.environ.get("CLAWPANEL_RING") or "alpha").strip().lower()
    if ring not in RINGS:
        raise RuntimeError(f"CLAWPANEL_RING must be one of {RINGS}")
    cfg_json = os.environ.get("CLAWPANEL_OAUTH_PROFILES", "")
    if not cfg_json:
        raise RuntimeError(
            "clawpanel-mcp HTTP needs CLAWPANEL_OAUTH_PROFILES — JSON like "
            '{"client@co.com": {"secret": "…", "scopes": ["brain","memory","kb"]}}')
    profiles_cfg = json.loads(cfg_json)
    return ClawpanelOAuthProvider(base_url=base_url, db=db, profiles_cfg=profiles_cfg, work_read=work_read)
