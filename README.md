# clawpanel-mcp

**Your ClawPanel workspace, as an MCP server.** Clients connect from ChatGPT
(deep-research compatible), Claude, or any MCP client over OAuth 2.1 — and see
only their own workspace: knowledge base, memory, agents, and activity.

This is the client-facing sibling of [zme-mcp](https://github.com/Sidarau/zme-mcp)
and the **alpha ring** of ClawPanel's public API surface.

## Tools

| Tool | What it does | Scope |
|---|---|---|
| `search` / `fetch` | ChatGPT-compatible pair over the tenant KB — `{results: [{id, title, url}]}`, `fetch(id)` → full text | `kb` |
| `ingest` | Add a document (extracted text) to the tenant KB; searchable via `search`/`fetch` afterward. Idempotent per source | `kb` |
| `memory_search` | Semantic search over workspace memory | `memory` |
| `remember` | Add a memory item (note, decision, fact) | `memory` |
| `agents` | The workspace's agents (name, model, gateway) | `brain` |
| `workspace_status` | Agents + recent workflow runs + tool activity | `brain` |
| `chat_history` | Recent workspace chat messages | `brain` |

Every tool is **tenant-scoped by the OAuth token**. The client never passes a
tenant id; the server resolves it from the authenticated profile and filters
every query server-side.

## How auth works (alpha)

Full OAuth 2.1: DCR, PKCE, authorization codes, refresh, revocation.

1. ChatGPT/Claude discovers metadata, registers itself (DCR), opens `/authorize`.
2. The client signs in with **their ClawPanel email + passphrase**.
3. The server resolves email → `profiles` row → `tenant_id` and issues a token
   whose scopes come from server-side profile config — never from the request.
4. Scopes mirror the `mcp_tokens` vocabulary: `brain`, `memory`, `kb`, `drive`.

Rings: `alpha` (passphrases in env, in-memory sessions) → `beta` (Supabase
auth sessions, persistent grants) → `prod` (per-profile labels, RLS-enforced
direct connections). Token contract is frozen from alpha.

## Configuration

| Variable | Purpose |
|---|---|
| `CLAWPANEL_DB_URL` | Supabase project URL (defaults to the clawpanel_db project) |
| `CLAWPANEL_DB_KEY` | service-role JWT. **Server-only** — it bypasses RLS, so tenant isolation is enforced in code on every query. Auto-resolves from NoxKey `zeuglab/clawpanel/CLAWPANEL_DB_SERVICE_ROLE_JWT` on macOS. |
| `CLAWPANEL_OAUTH_PROFILES` | JSON: `{"client@co.com": {"secret": "…", "scopes": ["brain","memory","kb"]}}` |
| `CLAWPANEL_BASE_URL` | Public URL (for OAuth metadata/redirects) |
| `CLAWPANEL_RING` | `alpha` (default) / `beta` / `prod` |
| `NVIDIA_API_KEY` | Optional — enables vector arm of hybrid KB search and semantic memory search |

## Run

```bash
uvicorn-grade Docker deploy: see Dockerfile + fly.toml → flyctl deploy
# local:
CLAWPANEL_OAUTH_PROFILES='{...}' clawpanel-mcp --http --port 8080
# → POST /mcp · GET /healthz · OAuth at /.well-known/*
```

## Connect from ChatGPT

Settings → Security and login → Developer mode → on, then
chatgpt.com/plugins → **+** → `https://clawpanel-mcp.fly.dev/mcp` → sign in
with your ClawPanel email + passphrase. Works in deep research (`search`/`fetch`
make your KB citable).

## Verification

`scripts/verify_clawpanel.py` runs the full OAuth dance for two tenants and
asserts **tenant isolation** (each sees only their own agents/chat, cross-tenant
fetch returns nothing), scope gating, and every tool against live data.
