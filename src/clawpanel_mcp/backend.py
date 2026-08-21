"""clawpanel_db data path — direct PostgREST, no local scripts.

Talks to the ClawPanel v2 Supabase project with the service-role JWT.
**service_role bypasses RLS**, so every method takes an explicit tenant_id
and filters on it — tenant isolation is enforced here, in code, on every
single query. The authenticated principal's tenant comes from the OAuth
layer (auth.py); tools never accept a tenant argument from the client.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from typing import Any

DEFAULT_BASE_URL = "https://stxavgjhbfjbyperqcsy.supabase.co"
NOXKEY_SERVICE = "zeuglab/clawpanel/CLAWPANEL_DB_SERVICE_ROLE_JWT"
NOXKEY_NVIDIA = "zeuglab/eve/NVIDIA_API_KEY"
EMBEDDING_MODEL = "nvidia/nv-embedqa-e5-v5"  # 1024-dim, asymmetric: query/passage
EMBED_VARIANT = "nv-embedqa-e5-v5:passage"
INGEST_CHUNKER = "clawpanel-word-window-v1"  # ≤460 tokens/chunk (512 embed cap)
INGEST_MAX_CHUNK_TOKENS = 440  # conservative word-window cap (≈4 chars/token)


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

    def delete(self, table: str, params: str) -> None:
        req = urllib.request.Request(f"{self.base}/rest/v1/{table}?{params}",
                                     headers=self._headers(), method="DELETE")
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                resp.read()
        except urllib.error.HTTPError as e:
            raise RuntimeError(f"delete {table} -> {e.code} {e.read()[:300]}") from e

    def patch(self, table: str, params: str, body: dict) -> Any:
        req = urllib.request.Request(
            f"{self.base}/rest/v1/{table}?{params}",
            data=json.dumps(body).encode(),
            headers=self._headers() | {"Content-Type": "application/json",
                                       "Prefer": "return=representation"},
            method="PATCH")
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                return json.loads(resp.read())
        except urllib.error.HTTPError as e:
            raise RuntimeError(f"patch {table} -> {e.code} {e.read()[:300]}") from e

    def _headers(self) -> dict:
        return {"apikey": self.key, "Authorization": f"Bearer {self.key}"}

    # -- identity -------------------------------------------------------------

    # -- OAuth client persistence ------------------------------------------
    # DCR registrations live in memory on the provider; every fly restart
    # wiped them and stranded connected ChatGPT clients at "Unregistered
    # client". Mirror registrations into this table so they survive.

    def save_client(self, client: dict) -> None:
        req = urllib.request.Request(
            f"{self.base}/rest/v1/mcp_clients",
            data=json.dumps({"client_id": client["client_id"], "client": client}).encode(),
            headers=self._headers() | {"Content-Type": "application/json",
                                       "Prefer": "resolution=merge-duplicates,return=minimal"},
            method="POST")
        try:
            with urllib.request.urlopen(req, timeout=30):
                pass
        except Exception:
            pass  # best-effort: memory still serves this run

    def load_client(self, client_id: str) -> dict | None:
        try:
            rows = self.get("mcp_clients", f"client_id=eq.{client_id}&select=client&limit=1")
            return rows[0]["client"] if rows else None
        except Exception:
            return None

    # -- OAuth token persistence -------------------------------------------
    # Same failure mode as mcp_clients: access/refresh tokens lived only in
    # provider memory, and fly's auto-stop ("stop" when idle) wiped them —
    # every connected ChatGPT session showed "connection has expired" after
    # the next idle stop. Mirror issued tokens here, rehydrate on a memory
    # miss, delete on revoke/rotation. Best-effort like save_client: memory
    # still serves the current run if the DB write fails.

    def save_oauth_token(self, *, access_token: str, refresh_token: str,
                         client_id: str, scopes: list[str],
                         expires_at: int | None, principal: dict) -> None:
        req = urllib.request.Request(
            f"{self.base}/rest/v1/mcp_oauth_tokens",
            data=json.dumps({
                "access_token": access_token, "refresh_token": refresh_token,
                "client_id": client_id, "scopes": scopes,
                "expires_at": expires_at, "principal": principal}).encode(),
            headers=self._headers() | {"Content-Type": "application/json",
                                       "Prefer": "resolution=merge-duplicates,return=minimal"},
            method="POST")
        try:
            with urllib.request.urlopen(req, timeout=30):
                pass
        except Exception:
            pass  # best-effort: memory still serves this run

    def load_oauth_token_by_access(self, access_token: str) -> dict | None:
        try:
            rows = self.get("mcp_oauth_tokens",
                            f"access_token=eq.{access_token}&limit=1")
            return rows[0] if rows else None
        except Exception:
            return None

    def load_oauth_token_by_refresh(self, refresh_token: str) -> dict | None:
        try:
            rows = self.get("mcp_oauth_tokens",
                            f"refresh_token=eq.{refresh_token}&limit=1")
            return rows[0] if rows else None
        except Exception:
            return None

    def delete_oauth_token(self, access_token: str) -> None:
        try:
            self.delete("mcp_oauth_tokens", f"access_token=eq.{access_token}")
        except Exception:
            pass

    def resolve_profile(self, email: str) -> dict | None:
        """email → {user_id, tenant_id}. The OAuth login gate calls this."""
        rows = self.get("profiles", f"email=eq.{urllib.parse.quote(email)}&limit=1")
        return rows[0] if rows else None

    def memberships_for(self, email: str) -> list[dict]:
        """Every workspace this email belongs to: [{tenant_id, slug, name}].

        One login can belong to several tenants (alex@ is in opencollective
        AND mitchiesmind); the connector principal must come from a chosen
        membership, not the single profiles.tenant_id row — which for alex@
        points at an empty orphan tenant from signup."""
        profile = self.resolve_profile(email)
        if not profile:
            return []
        try:
            rows = self.get("workspace_members",
                            f"user_id=eq.{profile['user_id']}"
                            "&select=tenant_id,tenants(slug,name)")
        except Exception:
            return [{"tenant_id": str(profile["tenant_id"]), "slug": None,
                     "name": None}]
        out = [{"tenant_id": str(r["tenant_id"]),
                "slug": (r.get("tenants") or {}).get("slug"),
                "name": (r.get("tenants") or {}).get("name")
                or (r.get("tenants") or {}).get("slug")}
               for r in rows]
        if not out:  # no memberships: fall back to the profile tenant
            out = [{"tenant_id": str(profile["tenant_id"]), "slug": None,
                    "name": None}]
        return out

    def verify_password(self, email: str, password: str) -> bool | None:
        """Check email+password against Supabase auth (the website credential).

        True = correct, False = definitively wrong, None = auth unreachable
        (caller may fall back to the legacy env passphrase)."""
        req = urllib.request.Request(
            f"{self.base}/auth/v1/token?grant_type=password",
            data=json.dumps({"email": email, "password": password}).encode(),
            headers=self._headers() | {"Content-Type": "application/json"},
            method="POST")
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return resp.status == 200
        except urllib.error.HTTPError:
            return False  # 400/401: wrong password — definitive
        except Exception:
            return None  # network/5xx: inconclusive

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
        pass p_tenant and filter defensively). zme_search returns chunk ids but
        not headings — enrich with a single batched lookup so search results
        carry a real title."""
        args: dict[str, Any] = {"p_tenant": tenant, "q_text": query, "k": k}
        emb = self.embed_query(query)
        if emb:
            args["q_embedding"] = emb
        rows = self.rpc("zme_search", args) or []
        rows = [r for r in rows if str(r.get("tenant_id")) in (tenant, "None", "")]
        if rows:
            ids = ",".join(str(r.get("chunk_id") or r.get("id")) for r in rows)
            heads = self.get("zme_chunks",
                             f"tenant_id=eq.{tenant}&id=in.({ids})"
                             f"&select=id,heading,chunk_index")
            by_id = {str(h["id"]): h for h in heads}
            for r in rows:
                h = by_id.get(str(r.get("chunk_id") or r.get("id")))
                if h:
                    r["heading"] = h.get("heading") or r.get("heading")
        return rows

    def fetch_chunk(self, tenant: str, chunk_id: str) -> dict | None:
        rows = self.get("zme_chunks",
                        f"id=eq.{chunk_id}&tenant_id=eq.{tenant}&limit=1")
        return rows[0] if rows else None

    # -- KB ingest --------------------------------------------------------------

    def embed_passage(self, text: str) -> str | None:
        """pgvector literal for one passage (input_type=passage — the stored
        side of the asymmetric nv-embedqa-e5-v5; queries use input_type=query).
        None when no NVIDIA key or the call fails — caller skips embedding and
        the lexical arm (content_tsv) still covers retrieval."""
        if not self.nvidia:
            return None
        req = urllib.request.Request(
            "https://integrate.api.nvidia.com/v1/embeddings",
            data=json.dumps({"model": EMBEDDING_MODEL, "input": [text],
                             "input_type": "passage",
                             "encoding_format": "float"}).encode(),
            headers={"Authorization": f"Bearer {self.nvidia}",
                     "Content-Type": "application/json"}, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=120) as resp:
                vec = json.loads(resp.read())["data"][0]["embedding"]
            return "[" + ",".join(f"{x:.7f}" for x in vec) + "]"
        except Exception:
            return None

    @staticmethod
    def _token_estimate(text: str) -> int:
        """Rough ≈4 chars/token (≥1 per whitespace-separated word)."""
        return max(1, (len(text) + 3) // 4)

    def chunk_text(self, text: str,
                   max_tokens: int = INGEST_MAX_CHUNK_TOKENS) -> list[str]:
        """Simple word-window splitter — chunks stay ≤ max_tokens (≈4
        chars/token), well under the 512-token embed cap."""
        words = text.split()
        chunks: list[str] = []
        cur: list[str] = []
        cur_tok = 0
        for w in words:
            wt = self._token_estimate(w)
            if cur and cur_tok + wt > max_tokens:
                chunks.append(" ".join(cur))
                cur, cur_tok = [], 0
            cur.append(w)
            cur_tok += wt
        if cur:
            chunks.append(" ".join(cur))
        return [c for c in chunks if c.strip()]

    def ingest_kb(self, tenant: str, title: str, text: str,
                  source_url: str | None = None,
                  user_id: str | None = None) -> dict:
        """Chunk + store a document in the tenant's KB and embed each chunk
        (input_type=passage) when an NVIDIA key is present.

        Every chunk row needs exactly one parent (zme_chunks_one_parent), so
        each ingested doc gets a kb_pages row (the closest thing this schema
        has to a `sources` table — it carries title/body and a per-tenant
        unique slug) and chunks link to it via kb_page_id.

        Idempotent: the doc's marker (sha256 of source_url, or title+text)
        lives in context_prefix and drives the slug; re-ingesting the same
        source updates the page and replaces its chunks in place instead of
        duplicating.
        """
        text = (text or "").strip()
        if not text:
            raise RuntimeError("ingest: empty text — nothing to add to the KB")
        title = (title or "Untitled").strip() or "Untitled"
        marker = "doc:" + hashlib.sha256(
            (source_url or f"{title}\n{text}").encode()).hexdigest()[:16]
        slug = self._page_slug(title, marker)
        now = datetime.now(timezone.utc).isoformat()

        # source row: one kb_page per ingested doc, upserted by (tenant, slug)
        page = self.get("kb_pages",
                        f"tenant_id=eq.{tenant}&slug=eq.{slug}&limit=1")
        page_body = {"tenant_id": tenant, "slug": slug, "title": title,
                     "body_md": text, "summary": text[:300],
                     "visibility": "workspace", "updated_at": now}
        if page:
            rows = self.patch("kb_pages", f"tenant_id=eq.{tenant}&slug=eq.{slug}",
                              {k: v for k, v in page_body.items()
                               if k not in ("tenant_id", "slug")})
        else:
            # kb_pages.created_by is a uuid FK to auth.users (schema-native) —
            # store the user id, never the email.
            if user_id:
                page_body["created_by"] = user_id
            rows = self.post("kb_pages", page_body)
        page = rows[0] if isinstance(rows, list) and rows else rows
        page_id = page.get("id") if isinstance(page, dict) else None
        if not page_id:
            raise RuntimeError("ingest: could not create kb page")

        # replace this doc's previous chunks in place (no duplication)
        existing = self.get("zme_chunks",
                            f"tenant_id=eq.{tenant}&context_prefix=eq.{marker}"
                            f"&select=id")
        if existing:
            ids = ",".join(str(r["id"]) for r in existing)
            self.delete("zme_chunks",
                        f"tenant_id=eq.{tenant}&id=in.({ids})")

        chunks = self.chunk_text(text)
        embedded = 0
        first_id: str | None = None
        for i, chunk in enumerate(chunks):
            row: dict[str, Any] = {
                "tenant_id": tenant,
                "kb_page_id": page_id,
                "chunk_index": i,
                "heading": title,
                "context_prefix": marker,
                "content": chunk,
                "content_hash": hashlib.sha256(chunk.encode()).hexdigest(),
                "token_count": self._token_estimate(chunk),
                "chunker_version": INGEST_CHUNKER,
            }
            vec = self.embed_passage(chunk)
            if vec:
                row["embedding"] = vec
                row["embed_variant"] = EMBED_VARIANT
                row["embedded_at"] = now
                embedded += 1
            got = self.post("zme_chunks", row)
            got = got[0] if isinstance(got, list) and got else got
            if first_id is None and isinstance(got, dict):
                first_id = got.get("id")
        return {"ingested": True, "chunks": len(chunks),
                "id": first_id, "embedded": embedded}

    @staticmethod
    def _page_slug(title: str, marker: str) -> str:
        """Deterministic per-doc slug: slugified title + marker suffix, so
        (tenant, slug) is unique and stable across re-ingests."""
        base = re.sub(r"[^a-z0-9]+", "-", title.lower()).strip("-")[:40]
        return f"mcp-{base or 'doc'}-{marker[4:]}".strip("-")

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
            "created_by": user_id,  # uuid FK, same convention as kb_pages
            "metadata": {"source": "clawpanel-mcp", "user_id": user_id},
            "scope": "shared", "layer": "raw"})
        return rows[0] if isinstance(rows, list) and rows else rows

    def activity(self, tenant: str, limit: int = 40) -> list[dict]:
        """Cross-surface trail for one tenant, newest first:
        pm_events (board changes) + kb_pages (docs ingested) + memory_items
        (notes remembered). Each entry: {at, actor, action, title}."""
        out: list[dict] = []
        try:
            for e in self.get("pm_events",
                              f"tenant_id=eq.{tenant}"
                              f"&order=created_at.desc&limit={limit}"):
                out.append({"at": e.get("created_at"), "actor": e.get("actor"),
                            "action": e.get("action"),
                            "title": e.get("ref") or e.get("node_id")})
        except Exception:
            pass
        for p in self.get("kb_pages",
                          f"tenant_id=eq.{tenant}"
                          f"&select=title,created_by,created_at"
                          f"&order=created_at.desc&limit={limit}"):
            out.append({"at": p.get("created_at"), "actor": p.get("created_by"),
                        "action": "kb_ingest", "title": p.get("title")})
        for m in self.get("memory_items",
                          f"tenant_id=eq.{tenant}"
                          f"&select=content,created_by,created_at"
                          f"&order=created_at.desc&limit={limit}"):
            out.append({"at": m.get("created_at"), "actor": m.get("created_by"),
                        "action": "memory_add",
                        "title": (m.get("content") or "")[:80]})
        out.sort(key=lambda x: x.get("at") or "", reverse=True)

        # created_by on kb/memory rows is a user uuid — resolve to email so
        # the trail reads as people, not ids.
        ids = {r["actor"] for r in out
               if r.get("actor") and "@" not in str(r["actor"])}
        if ids:
            quoted = ",".join(str(i) for i in ids)
            try:
                profs = self.get("profiles",
                                 f"user_id=in.({quoted})&select=user_id,email")
                by_id = {str(pr["user_id"]): pr.get("email") for pr in profs}
                for r in out:
                    if r.get("actor") in by_id:
                        r["actor"] = by_id[r["actor"]]
            except Exception:
                pass
        return out[:limit]

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
