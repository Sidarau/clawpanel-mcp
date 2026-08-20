"""clawpanel_db data path — direct PostgREST, no local scripts.

Talks to the ClawPanel v2 Supabase project with the service-role JWT.
**service_role bypasses RLS**, so every method takes an explicit tenant_id
and filters on it — tenant isolation is enforced here, in code, on every
single query. The authenticated principal's tenant comes from the OAuth
layer (auth.py); tools never accept a tenant argument from the client.
"""
from __future__ import annotations

import json
import os
import subprocess
import urllib.error
import urllib.request
from typing import Any

DEFAULT_BASE_URL = "https://nacktuyfdgobhzsqjtjv.supabase.co"
NOXKEY_SERVICE = "zeuglab/clawpanel/CLAWPANEL_DB_SERVICE_ROLE_JWT"
NOXKEY_NVIDIA = "zeuglab/eve/NVIDIA_API_KEY"
EMBEDDING_MODEL = "nvidia/nv-embedqa-e5-v5"  # 1024-dim, asymmetric: query/passage


def _noxkey(path: str) -> str | None:
    try:
        r = subprocess.run(["noxkey", "get", path, "--raw"],
                           capture_output=True, text=True, timeout=30)
        v = r.stdout.strip()
        return v if r.returncode == 0 and v else None
    except Exception:
        return None


class ClawpanelDB:
    def __init__(self) -> None:
        self.base = (os.environ.get("CLAWPANEL_DB_URL") or DEFAULT_BASE_URL).rstrip("/")
        key = os.environ.get("CLAWPANEL_DB_KEY") or _noxkey(NOXKEY_SERVICE)
        if not key:
            raise RuntimeError(
                "clawpanel-mcp: missing Supabase service key. Set CLAWPANEL_DB_KEY "
                f"(or store it in NoxKey at {NOXKEY_SERVICE}).")
        self.key = key
        self.nvidia = os.environ.get("NVIDIA_API_KEY") or _noxkey(NOXKEY_NVIDIA)

    # -- HTTP primitives ----------------------------------------------------

    def rpc(self, fn: str, args: dict) -> Any:
        req = urllib.request.Request(
            f"{self.base}/rest/v1/rpc/{fn}",
            data=json.dumps(args).encode(),
            headers=self._headers() | {"Content-Type": "application/json"},
            method="POST")
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                return json.loads(resp.read())
        except urllib.error.HTTPError as e:
            raise RuntimeError(f"rpc {fn} -> {e.code} {e.read()[:300]}") from e

    def get(self, table: str, params: str) -> Any:
        req = urllib.request.Request(f"{self.base}/rest/v1/{table}?{params}",
                                     headers=self._headers())
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                return json.loads(resp.read())
        except urllib.error.HTTPError as e:
            raise RuntimeError(f"get {table} -> {e.code} {e.read()[:300]}") from e

    def post(self, table: str, row: dict) -> Any:
        req = urllib.request.Request(
            f"{self.base}/rest/v1/{table}",
            data=json.dumps(row).encode(),
            headers=self._headers() | {"Content-Type": "application/json",
                                       "Prefer": "return=representation"},
            method="POST")
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                return json.loads(resp.read())
        except urllib.error.HTTPError as e:
            raise RuntimeError(f"post {table} -> {e.code} {e.read()[:300]}") from e

    def _headers(self) -> dict:
        return {"apikey": self.key, "Authorization": f"Bearer {self.key}"}

    # -- identity -------------------------------------------------------------

    def resolve_profile(self, email: str) -> dict | None:
        """email → {user_id, tenant_id}. The OAuth login gate calls this."""
        rows = self.get("profiles", f"email=eq.{urllib.parse.quote(email)}&limit=1")
        return rows[0] if rows else None

    # -- KB (zme_*) -------------------------------------------------------------

    def embed_query(self, text: str) -> list[float] | None:
        if not self.nvidia:
            return None
        req = urllib.request.Request(
            "https://integrate.api.nvidia.com/v1/embeddings",
            data=json.dumps({"model": EMBEDDING_MODEL, "input": [text],
                             "input_type": "query",  # asymmetric model — never 'passage'
                             "encoding_format": "float"}).encode(),
            headers={"Authorization": f"Bearer {self.nvidia}",
                     "Content-Type": "application/json"}, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                return json.loads(resp.read())["data"][0]["embedding"]
        except Exception:
            return None  # fall back to lexical arm silently

    def search_kb(self, tenant: str, query: str, k: int = 8) -> list[dict]:
        """Tenant-scoped hybrid retrieval over zme_chunks (RLS table; we also
        pass p_tenant and filter defensively)."""
        args: dict[str, Any] = {"p_tenant": tenant, "q_text": query, "k": k}
        emb = self.embed_query(query)
        if emb:
            args["q_embedding"] = emb
        rows = self.rpc("zme_search", args) or []
        return [r for r in rows if str(r.get("tenant_id")) in (tenant, "None", "")]

    def fetch_chunk(self, tenant: str, chunk_id: str) -> dict | None:
        rows = self.get("zme_chunks",
                        f"id=eq.{chunk_id}&tenant_id=eq.{tenant}&limit=1")
        return rows[0] if rows else None

    # -- memory -----------------------------------------------------------------

    def memory_search(self, tenant: str, query: str, k: int = 5) -> list[dict]:
        emb = self.embed_query(query)
        if emb:
            try:
                return self.rpc("match_memory", {
                    "p_tenant": tenant, "p_query_embedding": emb,
                    "p_match_count": k}) or []
            except RuntimeError:
                pass  # match_memory not deployed on this backend — fall through
        # lexical fallback when no embedding key or no match_memory RPC
        q = urllib.parse.quote(query.replace(" ", " | "))
        return self.get("memory_items",
                        f"tenant_id=eq.{tenant}&content_tsv=fts.{q}"
                        f"&order=created_at.desc&limit={k}")

    def memory_add(self, tenant: str, user_id: str, content: str) -> dict:
        rows = self.post("memory_items", {
            "tenant_id": tenant,
            "content": content,
            "metadata": {"source": "clawpanel-mcp", "user_id": user_id},
            "scope": "shared", "layer": "raw"})
        return rows[0] if isinstance(rows, list) and rows else rows

    # -- workspace ---------------------------------------------------------------

    def agents_list(self, tenant: str) -> list[dict]:
        return self.get("agents",
                        f"tenant_id=eq.{tenant}&select=id,name,default_model,"
                        f"gateway_url,persona,updated_at&order=updated_at.desc")

    def create_agent(self, tenant: str, name: str, system_prompt: str,
                     default_model: str | None = None) -> dict:
        row: dict[str, Any] = {"tenant_id": tenant, "name": name,
                               "system_prompt": system_prompt}
        if default_model:
            row["default_model"] = default_model
        rows = self.post("agents", row)
        return rows[0] if isinstance(rows, list) and rows else rows

    def update_agent(self, tenant: str, agent_id: str, fields: dict) -> dict:
        allowed = {"name", "system_prompt", "default_model", "persona"}
        body = {k: v for k, v in fields.items() if k in allowed and v is not None}
        if not body:
            raise RuntimeError("update_agent: nothing editable in fields "
                               f"(allowed: {sorted(allowed)})")
        req = urllib.request.Request(
            f"{self.base}/rest/v1/agents?id=eq.{agent_id}&tenant_id=eq.{tenant}",
            data=json.dumps(body).encode(),
            headers=self._headers() | {"Content-Type": "application/json",
                                       "Prefer": "return=representation"},
            method="PATCH")
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                rows = json.loads(resp.read())
        except urllib.error.HTTPError as e:
            raise RuntimeError(f"patch agents -> {e.code} {e.read()[:300]}") from e
        if not rows:
            raise RuntimeError("agent not found in your workspace")
        return rows[0]

    def recent_runs(self, tenant: str, limit: int = 10) -> list[dict]:
        return self.get("workflow_runs",
                        f"tenant_id=eq.{tenant}&select=id,agent_id,status,trigger,"
                        f"error,started_at,updated_at&order=updated_at.desc&limit={limit}")

    def tool_call_stats(self, tenant: str) -> list[dict]:
        return self.get("tool_calls",
                        f"tenant_id=eq.{tenant}&select=tool,status"
                        f"&order=started_at.desc&limit=100")

    def chat_history(self, tenant: str, limit: int = 20) -> list[dict]:
        return self.get("chat_messages",
                        f"tenant_id=eq.{tenant}&select=role,content,created_at,agent_id"
                        f"&order=created_at.desc&limit={limit}")


import urllib.parse  # noqa: E402  (kept at bottom: used by methods above)
