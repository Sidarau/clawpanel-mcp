"""clawpanel-mcp — ClawPanel clients' workspaces as an MCP server.

Tools (tenant-scoped by the OAuth token — clients only ever see their own
workspace):

  work_issue_read      read a Work issue and linked Library SOPs (scope: work:read)
  search / fetch       ChatGPT-compatible pair over the tenant KB (scope: kb)
  ingest               add a document to the tenant KB, searchable via search (scope: kb)
  memory_search        semantic search over workspace memory (scope: memory)
  remember             add a memory item (scope: memory)
  agents               the workspace's agents (scope: brain)
  workspace_status     agents + recent workflow runs + tool activity (scope: brain)
  chat_history         recent workspace chat messages (scope: brain)

Transport: streamable HTTP at /mcp with OAuth 2.1 (DCR + PKCE). Health at
/healthz. This is the client-facing sibling of zme-mcp — same auth model,
tenant-aware.
"""
from __future__ import annotations

import os
from typing import Annotated, Any

import anyio
from fastmcp import FastMCP
from fastmcp.server.dependencies import get_access_token
from mcp.types import ToolAnnotations
from pydantic import Field
from starlette.responses import PlainTextResponse

from .auth import WORK_READ_SCOPE, build_auth
from .backend import ClawpanelDB
from .work import read_work_issue

INSTRUCTIONS = """\
ClawPanel — your OpenClaw workspace as tools. Search your knowledge base
(search/fetch), add documents to it (ingest — extracted text from
PDFs/docs/images becomes searchable), search and add to workspace memory
(memory_search/remember), and see what your agents are doing (agents,
workspace_status, chat_history). Everything is scoped to your own workspace."""

_db: ClawpanelDB | None = None
_provider = None

READ_ONLY = ToolAnnotations(readOnlyHint=True, destructiveHint=False,
                            idempotentHint=True, openWorldHint=False)
WRITE_MEMO = ToolAnnotations(readOnlyHint=False, destructiveHint=False,
                             idempotentHint=False, openWorldHint=False)
WRITE_KB = ToolAnnotations(readOnlyHint=False, destructiveHint=False,
                           idempotentHint=True, openWorldHint=False)


def _client() -> ClawpanelDB:
    global _db
    if _db is None:
        _db = ClawpanelDB()
    return _db


async def _principal() -> dict:
    """Current caller's identity from the bearer token."""
    tok = get_access_token()
    if tok is None or _provider is None:
        raise RuntimeError("no authenticated principal")
    p = await _provider.principal_for(tok.token)
    if not p:
        raise RuntimeError("token has no workspace principal — re-authenticate")
    return p


def build_server(*, base_url: str = "") -> FastMCP:
    global _provider
    db = _client()
    work_read = os.environ.get("CLAWPANEL_CONNECTOR_WORK_READ") == "1"
    _provider = build_auth(base_url, db, work_read=work_read)
    mcp = FastMCP(name="clawpanel-mcp", instructions=INSTRUCTIONS, auth=_provider)

    challenge = os.environ.get("CLAWPANEL_OPENAI_APPS_CHALLENGE", "")

    @mcp.custom_route("/.well-known/openai-apps-challenge", methods=["GET"], include_in_schema=False)
    async def openai_apps_challenge(_request):
        headers = {"Cache-Control": "no-store"}
        if not challenge or not challenge.isascii() or not challenge.isprintable() or any(c.isspace() for c in challenge):
            return PlainTextResponse("Not found", status_code=404, headers=headers)
        return PlainTextResponse(challenge, headers=headers)

    from fastmcp.server.auth import require_scopes

    if work_read:
        @mcp.tool(title="Read a ClawPanel Work issue", annotations=READ_ONLY,
                  auth=[require_scopes(WORK_READ_SCOPE)])
        async def work_issue_read(
            issue: Annotated[str, Field(
                min_length=1, max_length=80,
                description="Work issue UUID, Work identifier such as ZEU-10, or linear:<source issue UUID> for an imported issue.",
            )],
        ) -> dict[str, Any]:
            """Read one issue in the connected workspace, with recent comments and
            shared Library SOPs linked from its description. Returns source links
            for the SOPs and the Linear source UUID for imported issues. Use the issue reference that the user provides or selects."""
            token = get_access_token()
            if token is None:
                raise RuntimeError("Reconnect ClawPanel with Work read access.")
            return await read_work_issue(token.token, issue)

    # -- KB (ChatGPT deep-research compatible pair) --------------------------

    @mcp.tool(title="Search workspace knowledge", annotations=READ_ONLY, auth=[require_scopes("kb")])
    async def search(query: str) -> dict[str, Any]:
        """Search your workspace knowledge base. Returns
        {results: [{id, title, url}]} — call fetch(id) for full content."""
        p = await _principal()
        rows = await anyio.to_thread.run_sync(
            lambda: _client().search_kb(p["tenant_id"], query, k=8))
        return {"results": [
            {"id": r.get("chunk_id") or r.get("id"),
             "title": r.get("heading") or r.get("source_title") or "(chunk)",
             "url": r.get("source_url") or f"clawpanel://chunks/{r.get('chunk_id') or r.get('id')}"}
            for r in rows]}

    @mcp.tool(title="Read a knowledge search result", annotations=READ_ONLY, auth=[require_scopes("kb")])
    async def fetch(id: str) -> dict[str, Any]:
        """Fetch the full content of one search result by id."""
        p = await _principal()
        row = await anyio.to_thread.run_sync(
            lambda: _client().fetch_chunk(p["tenant_id"], id))
        if not row:
            return {"id": id, "title": "", "text": "", "url": "",
                    "metadata": {"error": "not found in your workspace"}}
        return {"id": row["id"],
                "title": row.get("heading") or "(chunk)",
                "text": row.get("content") or "",
                "url": f"clawpanel://chunks/{row['id']}",
                "metadata": {"chunk_index": row.get("chunk_index")}}

    @mcp.tool(title="Save a workspace document", annotations=WRITE_KB, auth=[require_scopes("kb")])
    async def ingest(title: str, text: str,
                     source_url: str | None = None) -> dict[str, Any]:
        """Add a document to your workspace knowledge base so it becomes
        searchable. Pass the extracted text from a PDF/doc/image plus a short
        title (and the source URL when you have one). Returns
        {ingested: true, chunks: n, id} — re-ingesting the same source
        updates it in place instead of duplicating."""
        p = await _principal()
        res = await anyio.to_thread.run_sync(
            lambda: _client().ingest_kb(p["tenant_id"], title, text,
                                        source_url, p["user_id"]))
        return res

    # -- memory -----------------------------------------------------------------

    @mcp.tool(title="Search workspace memory", annotations=READ_ONLY, auth=[require_scopes("memory")])
    async def memory_search(query: str, k: int = 5) -> str:
        """Semantic search over your workspace's memory."""
        p = await _principal()
        rows = await anyio.to_thread.run_sync(
            lambda: _client().memory_search(p["tenant_id"], query, k))
        if not rows:
            return f"No memories match {query!r}."
        return "\n\n".join(
            f"- {(r.get('content') or '')[:300]}" for r in rows)

    @mcp.tool(title="Save a workspace memory", annotations=WRITE_MEMO, auth=[require_scopes("memory")])
    async def remember(text: str) -> str:
        """Add a memory item to your workspace (a note, decision, or fact)."""
        p = await _principal()
        row = await anyio.to_thread.run_sync(
            lambda: _client().memory_add(p["tenant_id"], p["user_id"], text))
        rid = row.get("id") if isinstance(row, dict) else None
        return f"remembered {rid or '(id unknown)'} in your workspace memory"

    @mcp.tool(title="Read recent workspace activity", annotations=READ_ONLY, auth=[require_scopes("memory")])
    async def activity(limit: int = 40) -> str:
        """The workspace's cross-surface trail, newest first: board changes,
        documents ingested, and memories added — each with its timestamp and
        who did it (by email). Use this for "what did X add today/yesterday"
        questions; limit caps the entries returned."""
        p = await _principal()
        rows = await anyio.to_thread.run_sync(
            lambda: _client().activity(p["tenant_id"], min(100, max(1, limit))))
        if not rows:
            return "No activity recorded yet."
        verb = {"kb_ingest": "added doc", "memory_add": "remembered"}
        return "\n".join(
            f"- {r.get('at', '?')} · {r.get('actor') or 'workspace'} · "
            f"{verb.get(r.get('action') or '', (r.get('action') or '').replace('_', ' '))}"
            + (f" — {r['title']}" if r.get("title") else "")
            for r in rows)

    # -- workspace (brain) --------------------------------------------------------

    @mcp.tool(title="List workspace agents", annotations=READ_ONLY, auth=[require_scopes("brain")])
    async def agents() -> str:
        """List your workspace's agents (name, model, gateway)."""
        p = await _principal()
        rows = await anyio.to_thread.run_sync(
            lambda: _client().agents_list(p["tenant_id"]))
        if not rows:
            return "No agents in your workspace yet."
        return "\n".join(
            f"- {r['name']} · {r.get('default_model') or 'default model'}"
            + (f" · {r['gateway_url']}" if r.get("gateway_url") else "")
            for r in rows)

    @mcp.tool(title="Create a workspace agent", annotations=WRITE_MEMO, auth=[require_scopes("create")])
    async def create_agent(name: str, system_prompt: str,
                           default_model: str | None = None) -> str:
        """Create a new agent in your workspace (host scope: create)."""
        p = await _principal()
        row = await anyio.to_thread.run_sync(
            lambda: _client().create_agent(p["tenant_id"], name, system_prompt,
                                           default_model))
        return f"created agent {row.get('name')} ({row.get('id')})"

    @mcp.tool(title="Update a workspace agent", annotations=WRITE_MEMO, auth=[require_scopes("edit")])
    async def update_agent(agent_id: str, name: str | None = None,
                           system_prompt: str | None = None,
                           default_model: str | None = None,
                           persona: str | None = None) -> str:
        """Edit an existing agent — name, prompt, model, or persona
        (host scope: edit). Only the fields you pass are changed."""
        p = await _principal()
        fields = {"name": name, "system_prompt": system_prompt,
                  "default_model": default_model, "persona": persona}
        row = await anyio.to_thread.run_sync(
            lambda: _client().update_agent(p["tenant_id"], agent_id, fields))
        return f"updated agent {row.get('name')} ({row.get('id')})"

    @mcp.tool(title="Read workspace status", annotations=READ_ONLY, auth=[require_scopes("brain")])
    async def workspace_status() -> str:
        """What your workspace is doing: agents, recent workflow runs,
        recent tool activity."""
        p = await _principal()
        agents_rows, runs, calls = await anyio.to_thread.run_sync(
            lambda: (_client().agents_list(p["tenant_id"]),
                     _client().recent_runs(p["tenant_id"], 10),
                     _client().tool_call_stats(p["tenant_id"])))
        out = [f"agents: {len(agents_rows)} "
               f"({', '.join(a['name'] for a in agents_rows) or 'none'})"]
        out.append(f"recent runs: {len(runs)}")
        for r in runs[:5]:
            out.append(f"  - {r.get('status')} · {r.get('trigger') or '?'}"
                       f" · {str(r.get('updated_at'))[:19]}"
                       + (f" · ERROR: {str(r.get('error'))[:80]}" if r.get("error") else ""))
        ok = sum(1 for c in calls if c.get("status") == "ok")
        out.append(f"tool calls (last {len(calls)}): {ok} ok, {len(calls) - ok} failed")
        return "\n".join(out)

    @mcp.tool(title="Read recent workspace chats", annotations=READ_ONLY, auth=[require_scopes("brain")])
    async def chat_history(limit: int = 20) -> str:
        """Recent chat messages in your workspace."""
        p = await _principal()
        rows = await anyio.to_thread.run_sync(
            lambda: _client().chat_history(p["tenant_id"], min(limit, 50)))
        if not rows:
            return "No chat messages yet."
        return "\n".join(
            f"[{str(r.get('created_at'))[:16]}] {r.get('role')}: "
            f"{(r.get('content') or '')[:200]}" for r in rows)

    # -- orchestrator: one stable tool, ever-growing server-side registry ------
    # New capabilities are added as REGISTRY ACTIONS (server-side) instead of
    # new MCP tools, because ChatGPT caches the tool list at connect time —
    # a new action needs no reconnect; a new tool does. The GPT discovers
    # what's available at runtime via action="list".
    from clawpanel_mcp.orchestrator import ACTIONS, run_action

    @mcp.tool(title="Run a workspace Studio action", annotations=WRITE_MEMO, auth=[require_scopes("memory")])
    async def studio(action: str, params: dict[str, Any] | None = None) -> str:
        """General-purpose workspace action runner — the extensible surface.
        New capabilities appear here WITHOUT reconnecting this connector:
        call studio("list") to see every action with its parameters, then
        studio(action_name, {...}) to run it. Prefer this when the dedicated
        tools don't cover what you need."""
        p = await _principal()
        if action in ("list", "list_actions", "help"):
            lines = [f"{name} — {meta['description']}"
                     + (f" (params: {meta['params']})" if meta.get("params") else "")
                     for name, meta in sorted(ACTIONS.items())]
            return "Available studio actions:\n" + "\n".join(lines)
        try:
            return await anyio.to_thread.run_sync(
                lambda: run_action(action, params or {}, p, _client()))
        except KeyError:
            return (f"Unknown studio action {action!r}. "
                    f"Call studio(\"list\") for the available actions.")
        except PermissionError as e:
            return f"Not permitted: {e}"
        except Exception as e:
            return f"studio action {action!r} failed: {e}"

    return mcp


def main() -> None:
    import argparse

    p = argparse.ArgumentParser(prog="clawpanel-mcp",
                                description="ClawPanel client workspace as an MCP server")
    p.add_argument("--http", action="store_true",
                   help="serve streamable HTTP at /mcp (the only supported mode — "
                        "tenant identity comes from OAuth, so stdio is not offered)")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8000)
    args = p.parse_args()

    import uvicorn
    base_url = os.environ.get("CLAWPANEL_BASE_URL") or f"http://{args.host}:{args.port}"
    mcp = build_server(base_url=base_url)

    @mcp.custom_route("/healthz", methods=["GET"], include_in_schema=False)
    async def healthz(request):
        return PlainTextResponse("ok")

    uvicorn.run(mcp.http_app(path="/mcp"), host=args.host, port=args.port,
                log_level="info")


if __name__ == "__main__":
    main()
