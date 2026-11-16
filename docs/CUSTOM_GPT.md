# ClawPanel Custom GPT — setup

This guide describes the existing cloud compatibility connector. Confirm that
the user's workplace still serves its knowledge base through this connector
before onboarding them. Connected workplace servers have their own connection.
Each user signs in independently and selects a workplace they belong to.

## 1. The connector (each user, once)

ChatGPT → Settings → Security and login → Developer mode → on.
chatgpt.com/plugins → **+** → `https://clawpanel-mcp.fly.dev/mcp`
→ sign in with your ClawPanel account. Choose the intended workplace if
prompted. Keep any existing compatibility passphrase in its approved vault.

## 2. The GPT (workspace owner, once)

chatgpt.com → Explore GPTs → **Create**:

- **Name:** ClawPanel
- **Description:** Talk to your OpenClaw workspace — its knowledge, memory, and agents.
- **Instructions:**

```
You are the ClawPanel assistant. You answer questions about the user's own
OpenClaw workspace using the connected tools.

Rules:
- For facts, decisions, and "what do we know about X": use search/fetch (KB)
  and memory_search first. Cite what you find; say when the workspace has
  nothing.
- For "what is my workspace doing": use workspace_status and agents.
- For "what did we discuss": use chat_history.
- When the user asks you to note, remember, or record something: use remember,
  and confirm what was stored.
- You only ever see THIS user's workspace. Never speculate about other
  workspaces or clients. Never invent tool results.
- Be concise. Lead with the answer.
```

- **Conversation starters:**
  - "What's my workspace been doing today?"
  - "What do we know about <topic>?"
  - "Remember this: <decision>"
- Publish as **Link-only** (clients get the link from you).

## Why not GPT "Actions"?

GPT Actions speak OpenAPI/REST; this server speaks MCP + OAuth 2.1 DCR, which
is ChatGPT's native, per-user, revocable connector flow. Actions would also
force one shared credential for the whole GPT — breaking tenant isolation.
The connector path keeps identity per-user, which is the entire security model.
