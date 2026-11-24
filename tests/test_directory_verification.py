import os
import unittest
from unittest.mock import patch

import httpx

from clawpanel_mcp.server import build_server


class DirectoryVerificationTests(unittest.IsolatedAsyncioTestCase):
    async def request(self, token, method="GET"):
        with patch.dict(os.environ, {"CLAWPANEL_OPENAI_APPS_CHALLENGE": token}):
            with patch("clawpanel_mcp.server._client"), patch("clawpanel_mcp.server.build_auth", return_value=None):
                server = build_server()
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=server.http_app(path="/mcp")),
                base_url="https://connector.example",
            ) as client:
                return await client.request(method, "/.well-known/openai-apps-challenge")

    async def test_returns_exact_configured_token_as_plain_text(self):
        token = "fixture-challenge_345"
        response = await self.request(token)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content, token.encode("ascii"))
        self.assertEqual(response.headers["content-type"], "text/plain; charset=utf-8")
        self.assertEqual(response.headers["cache-control"], "no-store")

    async def test_unconfigured_or_malformed_token_returns_not_found(self):
        for token in ("", "fixture\n", "two values", "caf\N{LATIN SMALL LETTER E WITH ACUTE}"):
            with self.subTest(token=token):
                response = await self.request(token)
                self.assertEqual(response.status_code, 404)
                self.assertEqual(response.headers["cache-control"], "no-store")

    async def test_mutating_method_cannot_publish_a_token(self):
        response = await self.request("fixture-challenge_345", "POST")
        self.assertEqual(response.status_code, 405)
