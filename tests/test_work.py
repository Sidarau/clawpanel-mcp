import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlparse

import httpx
from mcp.shared.auth import OAuthClientInformationFull
from pydantic import AnyUrl

from clawpanel_mcp.auth import ClawpanelOAuthProvider, WORK_READ_SCOPE
from clawpanel_mcp.work import WORK_ISSUE_URL, read_work_issue
from test_oauth_grants import Form, GrantStore


class WorkIssueTests(unittest.IsolatedAsyncioTestCase):
    def fake_transport(self, handler):
        transport = httpx.MockTransport(handler)
        create_client = httpx.AsyncClient
        return patch("clawpanel_mcp.work.httpx.AsyncClient",
                     side_effect=lambda **kwargs: create_client(transport=transport, **kwargs))

    async def test_forwards_only_issue_and_current_bearer_to_first_party(self):
        def handle(request):
            self.assertEqual(str(request.url), WORK_ISSUE_URL)
            self.assertEqual(request.method, "POST")
            self.assertEqual(request.headers["Authorization"], "Bearer fixture-token")
            self.assertEqual(request.content, b'{"issue":"ZEU-10"}')
            return httpx.Response(200, json={"issue": {"id": "ZEU-10"}, "sops": [{"title": "SOP"}]})

        with self.fake_transport(handle):
            result = await read_work_issue("fixture-token", "ZEU-10")
        self.assertEqual(result["sops"][0]["title"], "SOP")

    async def test_does_not_follow_redirects_with_the_bearer(self):
        seen = []

        def handle(request):
            seen.append(str(request.url))
            return httpx.Response(307, headers={"Location": "https://alternate.example/fixture"})

        with self.fake_transport(handle), self.assertRaisesRegex(RuntimeError, "could not load"):
            await read_work_issue("fixture-token", "ZEU-10")
        self.assertEqual(seen, [WORK_ISSUE_URL])

    async def test_ignores_untrusted_error_body(self):
        for status, message in [(401, "Reconnect"), (404, "unavailable"), (503, "could not load")]:
            with self.subTest(status=status):
                with self.fake_transport(lambda request: httpx.Response(status, text="server details")):
                    with self.assertRaisesRegex(RuntimeError, message):
                        await read_work_issue("fixture-token", "ZEU-10")

    async def test_opt_in_requests_work_scope_without_widening_an_explicit_kb_grant(self):
        store = GrantStore()
        legacy = ClawpanelOAuthProvider("https://connector.example", store, {})
        provider = ClawpanelOAuthProvider("https://connector.example", store, {}, work_read=True)
        self.assertEqual(legacy.default_scopes, ["kb"])
        self.assertEqual(provider.default_scopes, ["kb", WORK_READ_SCOPE])
        client = OAuthClientInformationFull(
            client_id="review-client", redirect_uris=[AnyUrl("https://consumer.example/callback")],
            scope=f"kb {WORK_READ_SCOPE}",
        )
        provider.clients[client.client_id] = client
        base = dict(email="review@example.test", passphrase="fixture-password", client_id="review-client",
                    code_challenge="fixture-challenge", redirect_uri="https://consumer.example/callback")
        for requested, expected in [(WORK_READ_SCOPE + " kb", ["work:read", "kb"]), ("kb", ["kb"])]:
            form = await provider._authorize_post(Form(**base, scope=requested))
            code = parse_qs(urlparse(form.headers["location"]).query)["code"][0]
            auth = await provider.load_authorization_code(client, code)
            credential = await provider.exchange_authorization_code(client, auth)
            grant = await provider.principal_for(credential.access_token)
            self.assertEqual(grant["scopes"], expected)
        provider.profiles_cfg["review@example.test"] = {"scopes": ["kb"]}
        denied = await provider._authorize_post(Form(**base, scope="kb " + WORK_READ_SCOPE))
        self.assertEqual(denied.status_code, 200)
        self.assertIn(b"cannot grant", denied.body)

    async def test_member_connection_has_work_only_and_tracks_current_membership(self):
        store = GrantStore()
        provider = ClawpanelOAuthProvider("https://connector.example", store, {
            "review@example.test": {"scopes": ["kb", "brain", "create"]},
        }, work_read=True, member_work_only=True)
        self.assertEqual(provider.default_scopes, [WORK_READ_SCOPE])
        self.assertEqual(provider.valid_scopes, [WORK_READ_SCOPE])
        self.assertIsNone(await provider.load_access_token("fixture-access"))
        client = OAuthClientInformationFull(
            client_id="review-client", redirect_uris=[AnyUrl("https://consumer.example/callback")],
            scope="kb work:read create",
        )
        provider.clients[client.client_id] = client
        request = dict(email="review@example.test", passphrase="fixture-password", client_id="review-client",
                       code_challenge="fixture-challenge", redirect_uri="https://consumer.example/callback")
        denied = await provider._authorize_post(Form(**request, scope="work:read create"))
        self.assertIn(b"cannot grant", denied.body)
        accepted = await provider._authorize_post(Form(**request, scope=WORK_READ_SCOPE))
        code = parse_qs(urlparse(accepted.headers["location"]).query)["code"][0]
        authorization = await provider.load_authorization_code(client, code)
        credential = await provider.exchange_authorization_code(client, authorization)
        self.assertEqual((await provider.load_access_token(credential.access_token)).scopes, [WORK_READ_SCOPE])
        self.assertEqual((await provider.principal_for(credential.access_token))["tenant_id"], "fixture-workspace")
        store.admitted = False
        self.assertIsNone(await provider.load_access_token(credential.access_token))
        self.assertIsNone(await provider.load_refresh_token(client, credential.refresh_token))
