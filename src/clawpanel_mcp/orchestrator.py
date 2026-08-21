"""Orchestrator action registry for the `studio` MCP tool.

Why this exists: ChatGPT caches a connector's tool list at connect time, so
every NEW MCP tool forces a reconnect. Actions registered here ride through
the single stable `studio` tool — deploy the server and the capability is
live for every connected client, no reconnect.

Adding an action:
    @action("name", scope="memory", description="…", params="foo, bar?")
    def _name(db, p, foo, bar=None):
        return "…"

`db` is the ClawpanelDB client, `p` the principal
{email, tenant_id, user_id, scopes}. Handlers are sync (the tool wraps them
in anyio.to_thread). Raise ValueError for bad params, PermissionError to
refuse. Scopes are enforced against the principal before the handler runs.
"""

from __future__ import annotations

from typing import Any, Callable

Handler = Callable[..., str]

ACTIONS: dict[str, dict[str, Any]] = {}


def action(name: str, *, scope: str, description: str,
           params: str = "") -> Callable[[Handler], Handler]:
    def deco(fn: Handler) -> Handler:
        ACTIONS[name] = {"fn": fn, "scope": scope,
                         "description": description, "params": params}
        return fn
    return deco


def run_action(name: str, params: dict, principal: dict, db) -> str:
    meta = ACTIONS.get(name)
    if meta is None:
        raise KeyError(name)
    need = meta["scope"]
    have = set(principal.get("scopes") or [])
    if need not in have:
        raise PermissionError(
            f"action {name!r} needs the {need!r} scope; this connection has "
            f"{sorted(have) or 'none'}")
    if not isinstance(params, dict):
        raise ValueError("params must be an object")
    return meta["fn"](db, principal, **params)


# -- seed actions -------------------------------------------------------------

@action("recent_activity", scope="memory",
        description="Newest-first workspace trail: board changes, docs "
                    "ingested, memories saved — with timestamps and actors.",
        params="limit? (default 40)")
def _recent_activity(db, p, limit: int = 40) -> str:
    rows = db.activity(p["tenant_id"], min(100, max(1, int(limit))))
    if not rows:
        return "No activity recorded yet."
    verb = {"kb_ingest": "added doc", "memory_add": "remembered"}
    return "\n".join(
        f"- {r.get('at', '?')} · {r.get('actor') or 'workspace'} · "
        f"{verb.get(r.get('action') or '', (r.get('action') or '').replace('_', ' '))}"
        + (f" — {r['title']}" if r.get("title") else "")
        for r in rows)


@action("ingest_text", scope="kb",
        description="Add a document to the knowledge base (same engine as the "
                    "ingest tool; idempotent per source).",
        params="title, text, source_url?")
def _ingest_text(db, p, title: str, text: str,
                 source_url: str | None = None) -> str:
    res = db.ingest_kb(p["tenant_id"], title, text, source_url, p["user_id"])
    return f"ingested {res.get('chunks', 0)} chunks (page {res.get('id')})"


@action("remember_note", scope="memory",
        description="Save a note, decision, or fact to workspace memory.",
        params="text")
def _remember_note(db, p, text: str) -> str:
    row = db.memory_add(p["tenant_id"], p["user_id"], text)
    rid = row.get("id") if isinstance(row, dict) else None
    return f"remembered {rid or '(id unknown)'}"
