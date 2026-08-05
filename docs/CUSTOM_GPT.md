# ClawPanel Custom GPT — setup

OpenAI has no API for creating GPTs — this is a 3-minute manual setup, once.
The design below is **per-tenant by construction**: the GPT carries only
personality and instructions; each user adds the ClawPanel connector and signs
in with *their own* email, so every user of the same GPT sees only *their own*
workspace. There is no way for one client to land in another's data.

## 1. The connector (each user, once)

ChatGPT → Settings → Security and login → Developer mode → on.
chatgpt.com/plugins → **+** → `https://clawpanel-mcp.fly.dev/mcp`
→ sign in with your ClawPanel email + passphrase.

(The passphrase is issued with the workspace — alpha ring. In beta this becomes
Supabase auth; the URL stays the same.)

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

## 3. Client onboarding message (copy/paste)

```
Your ClawPanel GPT: <link>
1. Open it, then add the connector when prompted
   (URL: https://clawpanel-mcp.fly.dev/mcp).
2. Sign in with <their-email> and your passphrase: <issued-per-client>
You only ever see your own workspace — the sign-in is what scopes you.
```

## Why not GPT "Actions"?

GPT Actions speak OpenAPI/REST; this server speaks MCP + OAuth 2.1 DCR, which
is ChatGPT's native, per-user, revocable connector flow. Actions would also
force one shared credential for the whole GPT — breaking tenant isolation.
The connector path keeps identity per-user, which is the entire security model.
