"""ClawPanel OAuth — client identity for the client-facing MCP.

Same OAuth 2.1 machinery as zme-mcp (ZeuglabOAuthProvider pattern): DCR,
PKCE, authorization codes, refresh, revocation — plus the ClawPanel twist:

  login = email + passphrase
  email → `profiles` table (service call, server-side) → tenant_id + user_id
  passphrase + scopes → CLAWPANEL_OAUTH_PROFILES env (alpha; DB table in beta)

The tenant becomes part of the token principal: every tool call resolves the
bearer token back to (email, tenant_id, scopes) through this provider's
in-memory principal map. Tools never accept tenant input from the client.

Scopes mirror the mcp_tokens vocabulary already in clawpanel_db:
  brain   — agents, workspace status, chat history
  memory  — memory search + remember
  kb      — KB search/fetch
  drive   — reserved (drive_nodes tools land in beta)
"""
from __future__ import annotations

import json
import os
import secrets
import urllib.parse
from typing import Any

from fastmcp.server.auth.providers.in_memory import InMemoryOAuthProvider
from mcp.server.auth.provider import AuthorizationParams
from mcp.server.auth.settings import ClientRegistrationOptions
from starlette.requests import Request
from starlette.responses import HTMLResponse, RedirectResponse
from starlette.routing import Route

ALL_SCOPES = ["brain", "memory", "kb", "drive"]

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
ClawPanel account.</p>
{error}
<input type="email" name="email" placeholder="you@company.com" autocomplete="username" required>
<input type="password" name="passphrase" placeholder="passphrase"
 autocomplete="current-password" required>
{hidden}
<button type="submit">Authorize</button></form></body></html>"""


class ClawpanelOAuthProvider(InMemoryOAuthProvider):
    def __init__(self, base_url: str, db, profiles_cfg: dict[str, dict]):
        super().__init__(
            base_url=base_url,
            client_registration_options=ClientRegistrationOptions(
                enabled=True, valid_scopes=ALL_SCOPES, default_scopes=["kb"]),
            required_scopes=["kb"],
        )
        self.db = db
        self.profiles_cfg = {k.strip().lower(): v for k, v in profiles_cfg.items()}
        # token string -> {"email","tenant_id","user_id","scopes"}
        self.principals: dict[str, dict] = {}
        self._code_principal: dict[str, dict] = {}

    # -- principal plumbing -------------------------------------------------

    async def exchange_authorization_code(self, client, authorization_code):  # type: ignore[override]
        token = await super().exchange_authorization_code(client, authorization_code)
        principal = self._code_principal.pop(authorization_code.code, None)
        if principal:
            self.principals[token.access_token] = principal
        return token

    async def exchange_refresh_token(self, client, refresh_token, scopes):  # type: ignore[override]
        token = await super().exchange_refresh_token(client, refresh_token, scopes)
        # carry the principal across the refresh: old access token -> new
        old_access = self._refresh_to_access_map.get(refresh_token.token)
        principal = self.principals.get(old_access) if old_access else None
        if principal:
            self.principals[token.access_token] = principal
        return token

    def principal_for(self, token_str: str) -> dict | None:
        return self.principals.get(token_str)

    # -- routes ---------------------------------------------------------------

    def get_routes(self, mcp_path: str | None = None) -> list[Route]:
        routes = super().get_routes(mcp_path)
        return [r for r in routes if not (getattr(r, "path", None) == "/authorize")] + [
            Route("/authorize", self._authorize_get, methods=["GET"]),
            Route("/authorize", self._authorize_post, methods=["POST"]),
        ]

    async def _authorize_get(self, request: Request) -> HTMLResponse:
        return self._page(dict(request.query_params), error="")

    async def _authorize_post(self, request: Request) -> Any:
        form = await request.form()
        q = {k: str(v) for k, v in form.items()
             if k not in ("email", "passphrase") and isinstance(v, str)}
        email = str(form.get("email", "")).strip().lower()
        secret = str(form.get("passphrase", ""))
        cfg = self.profiles_cfg.get(email)

        if not cfg or cfg["secret"] != secret:
            return self._page(q, error='<span class="err">Unknown email or bad passphrase.</span>')

        profile = self.db.resolve_profile(email)
        if not profile:
            return self._page(q, error='<span class="err">No ClawPanel workspace '
                                       'for this email.</span>')
        scopes = [s for s in cfg.get("scopes", ["kb"]) if s in ALL_SCOPES]
        try:
            client = await self.get_client(str(q["client_id"]))
            if client is None:
                return self._page(q, error='<span class="err">Unregistered client.</span>')
            params = AuthorizationParams(
                redirect_uri=str(q["redirect_uri"]),
                redirect_uri_provided_explicitly=True,
                state=q.get("state") or None,
                scopes=scopes,  # profile config decides — never the request
                code_challenge=str(q["code_challenge"]),
                resource=q.get("resource") or None,
            )
            redirect_url = await super().authorize(client, params)
            code = urllib.parse.parse_qs(
                urllib.parse.urlparse(redirect_url).query).get("code", [None])[0]
            if code:
                self._code_principal[code] = {
                    "email": email,
                    "tenant_id": str(profile["tenant_id"]),
                    "user_id": str(profile["user_id"]),
                    "scopes": scopes}
            return RedirectResponse(redirect_url, status_code=303)
        except Exception as e:  # noqa: BLE001
            return self._page(q, error=f'<span class="err">{type(e).__name__}: {e}</span>')

    def _page(self, q: dict[str, Any], error: str) -> HTMLResponse:
        hidden = "".join(
            f'<input type="hidden" name="{k}" value="{v}">' for k, v in q.items())
        return HTMLResponse(LOGIN_PAGE.format(
            client=q.get("client_id", "An MCP client"), error=error, hidden=hidden))


RINGS = ("alpha", "beta", "prod")


def build_auth(base_url: str, db) -> ClawpanelOAuthProvider | None:
    ring = (os.environ.get("CLAWPANEL_RING") or "alpha").strip().lower()
    if ring not in RINGS:
        raise RuntimeError(f"CLAWPANEL_RING must be one of {RINGS}")
    cfg_json = os.environ.get("CLAWPANEL_OAUTH_PROFILES", "")
    if not cfg_json:
        raise RuntimeError(
            "clawpanel-mcp HTTP needs CLAWPANEL_OAUTH_PROFILES — JSON like "
            '{"client@co.com": {"secret": "…", "scopes": ["brain","memory","kb"]}}')
    profiles_cfg = json.loads(cfg_json)
    return ClawpanelOAuthProvider(base_url=base_url, db=db, profiles_cfg=profiles_cfg)
