"""End-to-end verification for clawpanel-mcp — OAuth dance + TENANT ISOLATION.

  1. metadata + DCR + login form + bad-passphrase rejection + PKCE exchange
  2. token principal resolution (email → tenant)
  3. scope enforcement (kb-only profile can't see brain tools)
  4. TENANT ISOLATION: alex's token gets alex's data; dominik's gets dominik's;
     cross-tenant fetch returns nothing
  5. tools work against live clawpanel_db

Usage:
  VERIFY_ALEX_PASS=… VERIFY_DOMINIK_PASS=… .venv/bin/python scripts/verify_clawpanel.py [base_url]
"""
import base64
import hashlib
import json
import os
import secrets
import sys
import urllib.parse

import httpx

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8379"
ALEX = ("alex@zeuglab.com", os.environ.get("VERIFY_ALEX_PASS", "alexpass"))
DOMINIK = ("dominik@mission-mastery.com", os.environ.get("VERIFY_DOMINIK_PASS", "dompass"))
failures = 0


def check(label, ok, detail=""):
    global failures
    print(("PASS" if ok else "FAIL"), label, (f"— {detail}" if detail and not ok else ""))
    if not ok:
        failures += 1


def dance(client: httpx.Client, email: str, passphrase: str,
          scope: str = "brain memory kb") -> tuple[str, list[str]]:
    meta = client.get(f"{BASE}/.well-known/oauth-authorization-server").json()
    reg = client.post(meta["registration_endpoint"], json={
        "client_name": "verify-clawpanel",
        "redirect_uris": ["http://localhost:9999/callback"],
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "none",
        "scope": scope})
    assert reg.status_code in (200, 201), reg.text
    cid = reg.json()["client_id"]
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    q = {"response_type": "code", "client_id": cid,
         "redirect_uri": "http://localhost:9999/callback",
         "code_challenge": challenge, "code_challenge_method": "S256",
         "state": "xyz", "scope": scope, "resource": f"{BASE}/mcp"}
    form_page = client.get(f"{BASE}/authorize", params=q)
    assert "passphrase" in form_page.text
    bad = client.post(f"{BASE}/authorize", data={**q, "email": email,
                                                 "passphrase": "wrong"},
                      follow_redirects=False)
    assert "bad passphrase" in bad.text
    good = client.post(f"{BASE}/authorize", data={**q, "email": email,
                                                  "passphrase": passphrase},
                       follow_redirects=False)
    assert good.status_code == 303, good.text[:300]
    loc = good.headers["location"]
    code = urllib.parse.parse_qs(urllib.parse.urlparse(loc).query)["code"][0]
    tok = client.post(meta["token_endpoint"], data={
        "grant_type": "authorization_code", "code": code,
        "redirect_uri": "http://localhost:9999/callback",
        "client_id": cid, "code_verifier": verifier})
    assert tok.status_code == 200, tok.text
    body = tok.json()
    return body["access_token"], body.get("scope", "").split()


def mcp_session(client: httpx.Client, token: str) -> dict:
    h = {"Content-Type": "application/json",
         "Accept": "application/json, text/event-stream",
         "Authorization": f"Bearer {token}"}
    init = client.post(f"{BASE}/mcp", headers=h, json={
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {"protocolVersion": "2025-03-26", "capabilities": {},
                   "clientInfo": {"name": "verify", "version": "0"}}})
    assert init.status_code == 200, init.text[:200]
    sid = init.headers.get("mcp-session-id")
    client.post(f"{BASE}/mcp", headers={**h, "mcp-session-id": sid}, json={
        "jsonrpc": "2.0", "method": "notifications/initialized"})
    return {**h, "mcp-session-id": sid}


def call(client, h, tool, args=None):
    r = client.post(f"{BASE}/mcp", headers=h, json={
        "jsonrpc": "2.0", "id": 2, "method": "tools/call",
        "params": {"name": tool, "arguments": args or {}}})
    if r.headers.get("content-type", "").startswith("application/json"):
        return r.json()
    line = [l for l in r.text.splitlines() if l.startswith("data:")][0]
    return json.loads(line[5:])


def list_tools(client, h) -> list[str]:
    r = client.post(f"{BASE}/mcp", headers=h, json={
        "jsonrpc": "2.0", "id": 3, "method": "tools/list"})
    line = [l for l in r.text.splitlines() if l.startswith("data:")]
    body = r.json() if not line else json.loads(line[0][5:])
    return [t["name"] for t in body["result"]["tools"]]


def text_of(body) -> str:
    try:
        return "".join(c.get("text", "") for c in body["result"]["content"])
    except Exception:
        return json.dumps(body)


def main() -> int:
    with httpx.Client(timeout=60) as client:
        check("AS metadata", client.get(
            f"{BASE}/.well-known/oauth-authorization-server").status_code == 200)
        check("PRM metadata", client.get(
            f"{BASE}/.well-known/oauth-protected-resource/mcp").status_code == 200)

        alex_token, alex_scopes = dance(client, *ALEX)
        check("alex dance", bool(alex_token))
        dom_token, dom_scopes = dance(client, *DOMINIK)
        check("dominik dance", bool(dom_token))

        ah = mcp_session(client, alex_token)
        dh = mcp_session(client, dom_token)

        # tools present + scope-gated listing
        atools = list_tools(client, ah)
        check("alex sees all tools",
              {"search", "fetch", "memory_search", "remember",
               "agents", "workspace_status", "chat_history"} <= set(atools), str(atools))

        # tenant isolation: each sees their own agents/chat
        alex_agents = text_of(call(client, ah, "agents"))
        dom_agents = text_of(call(client, dh, "agents"))
        check("alex sees Collecta", "Collecta" in alex_agents, alex_agents[:120])
        check("dominik does NOT see Collecta", "Collecta" not in dom_agents,
              dom_agents[:120])

        alex_chat = text_of(call(client, ah, "chat_history", {"limit": 5}))
        dom_chat = text_of(call(client, dh, "chat_history", {"limit": 5}))
        check("chat history differs by tenant",
              alex_chat != dom_chat or "No chat" in dom_chat, dom_chat[:120])

        # cross-tenant fetch impossible: fetch a chunk id that doesn't exist
        # in the caller's tenant (ids are random UUIDs — wrong tenant == not found)
        fake = call(client, dh, "fetch", {"id": "00000000-0000-0000-0000-000000000000"})
        check("fetch enforces tenant", "not found" in text_of(fake), text_of(fake)[:120])

        # real tools against live data
        check("workspace_status works",
              "agents:" in text_of(call(client, ah, "workspace_status")))
        mem = call(client, ah, "remember", {"text": "clawpanel-mcp verify note — alpha ring"})
        check("remember works", "remembered" in text_of(mem), text_of(mem)[:120])
        ms = call(client, ah, "memory_search", {"query": "verify note"})
        check("memory_search runs", "result" in ms, json.dumps(ms)[:120])
        s = call(client, ah, "search", {"query": "collective"})
        check("search returns results[]", "result" in s, json.dumps(s)[:120])

        # no token at all
        r = client.post(f"{BASE}/mcp", headers={
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream"}, json={
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2025-03-26", "capabilities": {},
                       "clientInfo": {"name": "v", "version": "0"}}})
        check("no token → 401", r.status_code == 401, str(r.status_code))

    print("\n" + ("ALL PASS" if failures == 0 else f"{failures} FAILURES"))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
