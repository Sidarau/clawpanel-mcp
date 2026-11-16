from __future__ import annotations

import json
import unittest
from functools import wraps
from unittest.mock import patch

import httpx
from fastmcp.server.auth import AccessToken

from clawpanel_mcp import server


SWITCH_TENANT = "11111111-1111-4111-8111-111111111111"
OTHER_TENANT = "22222222-2222-4222-8222-222222222222"
FLAG = "CLAWPANEL_WORK_LIBRARY_MODE_11111111_1111_4111_8111_111111111111"


class FakeDB:
    def __init__(self):
        self.calls = []

    def load_oauth_token_by_access(self, token):
        return None

    def search_kb(self, tenant, query, k):
        self.calls.append(("search", tenant))
        return [{"id": "fixture-chunk", "heading": "Fixture cloud data"}]

    def ingest_kb(self, tenant, title, text, source_url, user):
        self.calls.append(("ingest", tenant))
        return {"id": "fixture-page", "chunks": 1, "ingested": True}

    def agents_list(self, tenant):
        self.calls.append(("agents", tenant))
        return [{"name": "fixture agent"}]

    def memory_add(self, tenant, user, content):
        self.calls.append(("remember_note", tenant))
        return {"id": "fixture-memory"}


def with_connector(test):
    @wraps(test)
    async def run(self):
        self.db = FakeDB()
        with (patch.dict(server.os.environ, {"CLAWPANEL_OAUTH_PROFILES": "{}"}) as self.env,
              patch.object(server, "_db", self.db), patch.object(server, "_provider", None)):
            self.env.pop(FLAG, None)
            app = server.build_server(base_url="https://fixture.test").http_app(
                path="/mcp", stateless_http=True, json_response=True,
            )
            scopes = ["kb", "brain", "memory"]
            for token, tenant in [("fixture-old-token", SWITCH_TENANT), ("fixture-other-token", OTHER_TENANT)]:
                server._provider.access_tokens[token] = AccessToken(token=token, client_id="fixture-client", scopes=scopes)
                server._provider.principals[token] = {"tenant_id": tenant, "user_id": "fixture-user", "scopes": scopes}
            async with app.router.lifespan_context(app), httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app), base_url="https://fixture.test",
            ) as self.http:
                await test(self)
    return run


class WorkLibraryCutoverTests(unittest.IsolatedAsyncioTestCase):

    async def request(self, method, params=None, token="fixture-old-token"):
        return await self.http.post("/mcp", json={
            "jsonrpc": "2.0", "id": 1, "method": method, "params": params or {},
        }, headers={
            "Accept": "application/json, text/event-stream",
            "Authorization": f"Bearer {token}",
        })

    async def discover(self, token="fixture-old-token"):
        response = await self.request("tools/list", token=token)
        self.assertEqual(response.status_code, 200)
        return {tool["name"] for tool in response.json()["result"]["tools"]}

    async def call(self, name, arguments, token="fixture-old-token"):
        response = await self.request("tools/call", {"name": name, "arguments": arguments}, token)
        self.assertEqual(response.status_code, 200)
        return response.json()["result"]

    @with_connector
    async def test_same_existing_token_is_frozen_then_server_owned(self):
        retired = {
            "search": {"query": "fixture"},
            "fetch": {"id": "fixture-chunk"},
            "ingest": {"title": "Fixture", "text": "Fixture"},
            "activity": {},
        }
        self.assertTrue(retired.keys() <= await self.discover())
        self.assertIn("fixture-chunk", json.dumps(await self.call("search", retired["search"])))
        self.db.calls.clear()

        for mode, expected in [("frozen", "temporarily unavailable"), ("server", "on this workplace's server"),
                               ("misconfigured", "temporarily unavailable")]:
            with self.subTest(mode=mode):
                self.env[FLAG] = mode
                self.assertTrue(retired.keys().isdisjoint(await self.discover()))
                for name, arguments in retired.items():
                    result = await self.call(name, arguments)
                    self.assertTrue(result["isError"], name)
                    self.assertIn(expected, json.dumps(result), name)
                for action, parameters in [("ingest_text", retired["ingest"]), ("recent_activity", {})]:
                    result = await self.call("studio", {"action": action, "params": parameters})
                    self.assertIn(expected, json.dumps(result), action)
                studio = json.dumps(await self.call("studio", {"action": "list"}))
                self.assertIn("remember_note", studio)
                self.assertNotIn("ingest_text", studio)
                self.assertNotIn("recent_activity", studio)
                self.assertEqual(self.db.calls, [])

        self.env[FLAG] = "cloud"
        self.assertIn("fixture-page", json.dumps(await self.call("ingest", retired["ingest"])))
        self.assertEqual(self.db.calls, [("ingest", SWITCH_TENANT)])

    @with_connector
    async def test_other_workplace_and_non_library_tools_remain_available(self):
        self.env[FLAG] = "server"
        self.assertIn("search", await self.discover("fixture-other-token"))
        self.assertIn("fixture-chunk", json.dumps(await self.call("search", {"query": "fixture"}, "fixture-other-token")))
        self.assertIn("fixture agent", json.dumps(await self.call("agents", {})))
        self.assertIn("fixture-memory", json.dumps(await self.call("studio", {
            "action": "remember_note", "params": {"text": "fixture"},
        })))
        self.assertEqual(self.db.calls, [("search", OTHER_TENANT), ("agents", SWITCH_TENANT), ("remember_note", SWITCH_TENANT)])

    @with_connector
    async def test_unknown_token_cannot_discover_or_call(self):
        for method in ("tools/list", "tools/call"):
            response = await self.request(method, {"name": "search", "arguments": {"query": "fixture"}}, token="fixture-rejected-token")
            self.assertEqual(response.status_code, 401)
        self.assertEqual(self.db.calls, [])
