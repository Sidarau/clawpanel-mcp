"""clawpanel-mcp — ClawPanel clients' workspaces as an MCP server.

Tools (tenant-scoped by the OAuth token — clients only ever see their own
workspace):

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
from typing import Any

import anyio
from fastmcp import FastMCP
from fastmcp.server.dependencies import get_access_token
from fastmcp.tools.tool import ToolAnnotations

from .auth import build_auth
from .backend import ClawpanelDB

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


def _principal() -> dict:
    """Current caller's identity from the bearer token."""
    tok = get_access_token()
    if tok is None or _provider is None:
        raise RuntimeError("no authenticated principal")
    p = _provider.principal_for(tok.token)
    if not p:
        raise RuntimeError("token has no workspace principal — re-authenticate")
    return p


def build_server(*, base_url: str = "") -> FastMCP:
    global _provider
    db = _client()
    _provider = build_auth(base_url, db)
    mcp = FastMCP(name="clawpanel-mcp", instructions=INSTRUCTIONS, auth=_provider)

    from fastmcp.server.auth import require_scopes

    # -- KB (ChatGPT deep-research compatible pair) --------------------------

    @mcp.tool(annotations=READ_ONLY, auth=[require_scopes("kb")])
    async def search(query: str) -> dict[str, Any]:
        """Search your workspace knowledge base. Returns
        {results: [{id, title, url}]} — call fetch(id) for full content."""
        p = _principal()
        rows = await anyio.to_thread.run_sync(
            lambda: _client().search_kb(p["tenant_id"], query, k=8))
        return {"results": [
            {"id": r.get("chunk_id") or r.get("id"),
             "title": r.get("heading") or r.get("source_title") or "(chunk)",
             "url": r.get("source_url") or f"clawpanel://chunks/{r.get('chunk_id') or r.get('id')}"}
            for r in rows]}

    @mcp.tool(annotations=READ_ONLY, auth=[require_scopes("kb")])
    async def fetch(id: str) -> dict[str, Any]:
        """Fetch the full content of one search result by id."""
        p = _principal()
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

    @mcp.tool(annotations=WRITE_KB, auth=[require_scopes("kb")])
    async def ingest(title: str, text: str,
                     source_url: str | None = None) -> dict[str, Any]:
        """Add a document to your workspace knowledge base so it becomes
        searchable. Pass the extracted text from a PDF/doc/image plus a short
        title (and the source URL when you have one). Returns
        {ingested: true, chunks: n, id} — re-ingesting the same source
        updates it in place instead of duplicating."""
        p = _principal()
        res = await anyio.to_thread.run_sync(
            lambda: _client().ingest_kb(p["tenant_id"], title, text,
                                        source_url, p["user_id"]))
        return res

    # -- memory -----------------------------------------------------------------

    @mcp.tool(annotations=READ_ONLY, auth=[require_scopes("memory")])
    async def memory_search(query: str, k: int = 5) -> str:
        """Semantic search over your workspace's memory."""
        p = _principal()
        rows = await anyio.to_thread.run_sync(
            lambda: _client().memory_search(p["tenant_id"], query, k))
        if not rows:
            return f"No memories match {query!r}."
        return "\n\n".join(
            f"- {(r.get('content') or '')[:300]}" for r in rows)

    @mcp.tool(annotations=WRITE_MEMO, auth=[require_scopes("memory")])
    async def remember(text: str) -> str:
        """Add a memory item to your workspace (a note, decision, or fact)."""
        p = _principal()
        row = await anyio.to_thread.run_sync(
            lambda: _client().memory_add(p["tenant_id"], p["user_id"], text))
        rid = row.get("id") if isinstance(row, dict) else None
        return f"remembered {rid or '(id unknown)'} in your workspace memory"

    # -- workspace (brain) --------------------------------------------------------

    @mcp.tool(annotations=READ_ONLY, auth=[require_scopes("brain")])
    async def agents() -> str:
        """List your workspace's agents (name, model, gateway)."""
        p = _principal()
        rows = await anyio.to_thread.run_sync(
            lambda: _client().agents_list(p["tenant_id"]))
        if not rows:
            return "No agents in your workspace yet."
        return "\n".join(
            f"- {r['name']} · {r.get('default_model') or 'default model'}"
            + (f" · {r['gateway_url']}" if r.get("gateway_url") else "")
            for r in rows)

    @mcp.tool(annotations=WRITE_MEMO, auth=[require_scopes("create")])
    async def create_agent(name: str, system_prompt: str,
                           default_model: str | None = None) -> str:
        """Create a new agent in your workspace (host scope: create)."""
        p = _principal()
        row = await anyio.to_thread.run_sync(
            lambda: _client().create_agent(p["tenant_id"], name, system_prompt,
                                           default_model))
        return f"created agent {row.get('name')} ({row.get('id')})"

    @mcp.tool(annotations=WRITE_MEMO, auth=[require_scopes("edit")])
    async def update_agent(agent_id: str, name: str | None = None,
                           system_prompt: str | None = None,
                           default_model: str | None = None,
                           persona: str | None = None) -> str:
        """Edit an existing agent — name, prompt, model, or persona
        (host scope: edit). Only the fields you pass are changed."""
        p = _principal()
        fields = {"name": name, "system_prompt": system_prompt,
                  "default_model": default_model, "persona": persona}
        row = await anyio.to_thread.run_sync(
            lambda: _client().update_agent(p["tenant_id"], agent_id, fields))
        return f"updated agent {row.get('name')} ({row.get('id')})"

    @mcp.tool(annotations=READ_ONLY, auth=[require_scopes("brain")])
    async def workspace_status() -> str:
        """What your workspace is doing: agents, recent workflow runs,
        recent tool activity."""
        p = _principal()
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

    @mcp.tool(annotations=READ_ONLY, auth=[require_scopes("brain")])
    async def chat_history(limit: int = 20) -> str:
        """Recent chat messages in your workspace."""
        p = _principal()
        rows = await anyio.to_thread.run_sync(
            lambda: _client().chat_history(p["tenant_id"], min(limit, 50)))
        if not rows:
            return "No chat messages yet."
        return "\n".join(
            f"[{str(r.get('created_at'))[:16]}] {r.get('role')}: "
            f"{(r.get('content') or '')[:200]}" for r in rows)

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
        from starlette.responses import PlainTextResponse
        return PlainTextResponse("ok")

    uvicorn.run(mcp.http_app(path="/mcp"), host=args.host, port=args.port,
                log_level="info")


if __name__ == "__main__":
    main()
