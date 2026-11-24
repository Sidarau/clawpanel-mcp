import asyncio
import threading
import time
import unittest
from urllib.parse import parse_qs, urlparse

from mcp.server.auth.provider import TokenError
from mcp.shared.auth import OAuthClientInformationFull
from pydantic import AnyUrl

from clawpanel_mcp.auth import ClawpanelOAuthProvider


class GrantStore:
    def __init__(self):
        self.lock = threading.Lock()
        self.admitted = True
        self.available = True
        self.password_valid = True
        self.row = {
            "client_id": "review-client",
            "access_token": "fixture-access",
            "refresh_token": "fixture-refresh",
            "scopes": ["kb", "brain"],
            "expires_at": int(time.time()) + 600,
            "principal": {"tenant_id": "fixture-workspace", "user_id": "fixture-user"},
        }

    def has_workspace_membership(self, user, tenant):
        return self.admitted and (user, tenant) == ("fixture-user", "fixture-workspace")

    def _by(self, token, key):
        if not self.available:
            raise OSError("Storage unavailable")
        with self.lock:
            return self.row.copy() if self.row and self.row[key] == token else None

    def load_oauth_token_by_access(self, token):
        return self._by(token, "access_token")

    def load_oauth_token_by_refresh(self, token):
        return self._by(token, "refresh_token")

    def delete_oauth_token(self, token, *, refresh=False):
        key = "refresh_token" if refresh else "access_token"
        with self.lock:
            if self.row and self.row[key] == token:
                self.row = None

    def rotate_oauth_token(self, old_refresh, row):
        with self.lock:
            if not self.row or self.row["refresh_token"] != old_refresh:
                return False
            self.row = row
            return True

    def save_oauth_token(self, row):
        self.row = row

    def verify_password(self, email, password):
        return self.password_valid

    def resolve_profile(self, email):
        return {"user_id": "fixture-user"}

    def memberships_for(self, email):
        return [{"tenant_id": "fixture-workspace", "slug": "review", "name": "Review workspace"}]


class Form:
    def __init__(self, **values):
        self.values = values

    async def form(self):
        return self.values


class OAuthGrantTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.store = GrantStore()
        self.a = ClawpanelOAuthProvider("https://connector.example", self.store, {})
        self.b = ClawpanelOAuthProvider("https://connector.example", self.store, {})
        self.client = OAuthClientInformationFull(
            client_id="review-client", redirect_uris=[AnyUrl("https://consumer.example/callback")], scope="kb brain",
        )

    async def test_revoke_denies_both_replicas_after_prior_access(self):
        access = await self.a.load_access_token("fixture-access")
        self.assertIsNotNone(access)
        self.assertIsNotNone(await self.b.principal_for("fixture-access"))
        await self.a.revoke_token(access)
        self.assertIsNone(await self.b.load_access_token("fixture-access"))
        self.assertIsNone(await self.b.principal_for("fixture-access"))
        self.assertIsNone(await self.b.load_refresh_token(self.client, "fixture-refresh"))

    async def test_membership_loss_and_storage_outage_fail_closed(self):
        self.assertIsNotNone(await self.a.load_access_token("fixture-access"))
        self.store.admitted = False
        self.assertIsNone(await self.a.load_access_token("fixture-access"))
        self.assertIsNone(await self.a.load_refresh_token(self.client, "fixture-refresh"))
        self.store.admitted = True
        self.store.available = False
        self.assertIsNone(await self.a.principal_for("fixture-access"))

    async def test_cross_replica_refresh_has_one_winner_and_cannot_restore_old_scopes(self):
        refresh = await self.a.load_refresh_token(self.client, "fixture-refresh")
        results = await asyncio.gather(
            self.a.exchange_refresh_token(self.client, refresh, ["kb"]),
            self.b.exchange_refresh_token(self.client, refresh, ["kb"]),
            return_exceptions=True,
        )
        tokens = [result for result in results if not isinstance(result, BaseException)]
        self.assertEqual(len(tokens), 1)
        self.assertIsInstance(next(result for result in results if isinstance(result, BaseException)), TokenError)
        self.assertIsNone(await self.a.load_access_token("fixture-access"))
        self.assertIsNone(await self.b.load_refresh_token(self.client, "fixture-refresh"))
        self.assertEqual((await self.a.principal_for(tokens[0].access_token))["scopes"], ["kb"])

    async def test_workspace_selection_escapes_client_and_workspace_attributes(self):
        page = self.a._workspace_page({"state": '"state'}, [
            {"name": "Review & testing", "slug": '"workspace', "tenant_id": "fixture"},
        ], 'reviewer@example.test')
        body = page.body.decode()
        self.assertIn('value="&quot;state"', body)
        self.assertIn('value="&quot;workspace"', body)
        self.assertIn('Review &amp; testing', body)
        self.assertIn('type="password" name="passphrase"', body)
        self.assertNotIn('type="hidden" name="passphrase"', body)

    async def test_authorization_rejects_wrong_redirect_and_persists_exact_scope(self):
        self.a.clients["review-client"] = self.client
        request = {"email": "review@example.test", "passphrase": "fixture-password", "client_id": "review-client",
                   "code_challenge": "fixture-challenge", "redirect_uri": "https://consumer.example/callback",
                   "scope": "kb"}
        self.assertEqual((await self.a._authorize_post(Form(
            **{**request, "redirect_uri": "https://invalid.example/callback"}))).status_code, 200)
        response = await self.a._authorize_post(Form(**request))
        code = parse_qs(urlparse(response.headers["location"]).query)["code"][0]
        authorization = await self.a.load_authorization_code(self.client, code)
        token = await self.a.exchange_authorization_code(self.client, authorization)
        self.assertEqual((await self.b.principal_for(token.access_token))["scopes"], ["kb"])

    async def test_legacy_passphrase_does_not_override_rejected_account_password(self):
        self.store.password_valid = False
        self.a.profiles_cfg["review@example.test"] = {"secret": "fixture-password"}
        self.a.clients["review-client"] = self.client
        response = await self.a._authorize_post(Form(
            email="review@example.test", passphrase="fixture-password", client_id="review-client",
            redirect_uri="https://consumer.example/callback", code_challenge="fixture-challenge",
        ))
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Unknown email or bad password", response.body)


if __name__ == "__main__":
    unittest.main()
