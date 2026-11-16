# Standalone MCP connector during a Work and Library switch

This Fly app uses its existing cloud database directly. A change to the hosted
`/api/mcp` route or the workplace link does not change what this connector can
read or write. Apply this policy to the standalone host before allowing new
server writes. The [ZEUG-436 handoff](https://linear.app/zeug/issue/ZEUG-436)
owns the rollout order and exact target workplace.

| Mode | Standalone MCP behavior |
| --- | --- |
| `cloud` or unset | Existing authorized cloud operations. |
| `frozen` or an invalid value | Refuse retired tools and actions during the switch. |
| `server` | Refuse those tools and actions, directing callers to the workplace server. |

The restriction covers `search`, `fetch`, `ingest`, `activity`, and the
equivalent `studio` actions. It uses the tenant from the authenticated token
on every discovery and invocation, including cached client tool lists. Agent,
chat and the separate `memory_items` tools stay available. The shared ZME
service remains a separate dependency during the staged rollout.

1. Verify the exact tested image and mode on every machine that serves this
   app. Start in cloud mode. With one existing credential for the target
   workplace and a second for an unaffected workplace, compare `tools/list`,
   an approved read, and an unrelated tool such as `agents`.
2. Freeze the target across both hosts. Verify the target's cached calls and
   `studio` aliases fail, while the unaffected workplace keeps working. Verify
   that all older instances have stopped serving and all already admitted
   legacy writes have finished. `ingest` uses several requests, so a failed
   request still needs reconciliation against the old store before promotion.
3. After the cutover owner closes the direct database and job gates, switch the
   target to server mode. Run the same denial and compatibility checks through
   the public endpoints. An old image or any legacy Work or Library read/write
   still reaching the target store is a stop condition.

The connector guard blocks new requests at admission. It is not a transaction
fence for in-flight writes, external privileged clients, or direct PostgREST and
RPC access. Roll back to cloud mode only with the release owner's authorization
and after reconciling any writes already accepted by the workplace server.
