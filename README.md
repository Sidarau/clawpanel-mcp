# clawpanel-mcp

**Your ClawPanel workspace, as an MCP server.** Clients connect from ChatGPT
(deep-research compatible), Claude, or any MCP client over OAuth 2.1 — and see
only their own workspace: knowledge base, memory, agents, and activity.

This is the client-facing sibling of [zme-mcp](https://github.com/Sidarau/zme-mcp)
and an existing compatibility connector for cloud workspaces. The hosted web
API and the linked workplace server have separate connection contracts.

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

## How auth works

Full OAuth 2.1: DCR, PKCE, authorization codes, refresh, revocation.

1. ChatGPT/Claude discovers metadata, registers itself (DCR), opens `/authorize`.
2. The client signs in with their ClawPanel email and account password. A
   configured legacy connector passphrase may still work for an existing profile.
3. The server looks up the authenticated account's memberships and asks the user
   to choose a workplace if necessary. It binds the token to the chosen
   membership and server-assigned scopes.
4. Scopes mirror the `mcp_tokens` vocabulary: `brain`, `memory`, `kb`, `drive`.

OAuth client registrations and grants persist across restarts. The former
`CLAWPANEL_RING` setting was a label; it did not select an auth implementation.

## Configuration

| Variable | Purpose |
|---|---|
| `CLAWPANEL_DB_URL` | Supabase project URL (defaults to the clawpanel_db project) |
| `CLAWPANEL_DB_KEY` | service-role JWT. **Server-only** — it bypasses RLS, so tenant isolation is enforced in code on every query. Auto-resolves from NoxKey `zeuglab/clawpanel/CLAWPANEL_DB_SERVICE_ROLE_JWT` on macOS. |
| `CLAWPANEL_OAUTH_PROFILES` | JSON: `{"client@co.com": {"secret": "…", "scopes": ["brain","memory","kb"]}}` |
| `CLAWPANEL_BASE_URL` | Public URL (for OAuth metadata/redirects) |
| `NVIDIA_API_KEY` | Optional — enables vector arm of hybrid KB search and semantic memory search |
| `CLAWPANEL_WORK_LIBRARY_MODE_<TENANT>` | Matches the hosted web cutover setting. `<TENANT>` is the authenticated workplace UUID, uppercase with hyphens replaced by underscores. See [cutover checks](docs/WORK_LIBRARY_CUTOVER.md). |

## Run

```bash
# Local, with credentials privately injected:
CLAWPANEL_OAUTH_PROFILES='{...}' clawpanel-mcp --http --port 8080
# → POST /mcp · GET /healthz · OAuth at /.well-known/*
```

## Connect from ChatGPT

Settings → Security and login → Developer mode → on, then
Use the [existing connector instructions](docs/CUSTOM_GPT.md) for a cloud
workplace. For linked Work and Library, use the connection supplied by the
workplace server.

## Verification

`uv run --locked python -m unittest discover -s tests -v` verifies the cutover
contract with a synthetic database over authenticated MCP HTTP. The separate
`scripts/verify_clawpanel.py` is a live smoke tool that performs writes; use it
only against an approved test workplace.

## KB ingestion (`ingest`)

`ingest(title, text, source_url=None)` chunks the text with a word-window
splitter (≤460 estimated tokens/chunk, well under the 512-token embed cap) and
writes `zme_chunks` rows for the caller's tenant. Notes on the live schema:

- This project has **no `sources` table** and no `source_url` column on chunks.
  The `zme_chunks_one_parent` constraint requires every chunk to link to exactly
  one parent (`drive_node_id` XOR `kb_page_id`), so each ingested doc also
  creates a **`kb_pages` row** (unique per-tenant `slug`, full text as
  `body_md`) and chunks link to it via `kb_page_id`.
- `content_tsv` is a **generated stored column** (context_prefix + heading +
  content), so the lexical arm of `zme_search` picks up new chunks
  automatically — no trigger to maintain.
- Chunks are embedded with `nvidia/nv-embedqa-e5-v5` using
  **`input_type=passage`** (the stored side; queries use `input_type=query` —
  the model is asymmetric). Embeddings are 1024-dim `vector(1024)` and the
  vector arm is HNSW-indexed; both arms verified live end-to-end.
- **Idempotent per source**: the marker (`sha256(source_url)` or
  `sha256(title+text)`) lives in `context_prefix` and drives the slug;
  re-ingesting the same source updates the page and replaces its chunks in
  place instead of duplicating.
