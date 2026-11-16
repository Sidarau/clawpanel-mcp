"""Keep the standalone connector aligned with the web cutover policy."""

from __future__ import annotations

import os

from fastmcp.exceptions import ToolError
from fastmcp.server.middleware import Middleware


# These tools do not read or write the old Work/Library store. Studio filters
# its action registry separately. New tools are hidden until classified here.
_COMPATIBILITY_TOOLS = frozenset({
    "agents", "create_agent", "update_agent", "workspace_status", "chat_history",
    "memory_search", "remember", "studio",
})


def authority_message(tenant_id: str) -> str | None:
    flag = "CLAWPANEL_WORK_LIBRARY_MODE_" + tenant_id.replace("-", "_").upper()
    mode = os.getenv(flag)
    if mode is None or mode == "cloud":
        return None
    if mode == "server":
        return "Work and Library are on this workplace's server."
    return "Work and Library are temporarily unavailable during the workplace switch."


class WorkLibraryCutover(Middleware):
    def __init__(self, principal):
        self._principal = principal

    async def on_list_tools(self, context, call_next):
        tools = await call_next(context)
        if authority_message(self._principal()["tenant_id"]):
            return [tool for tool in tools if tool.name in _COMPATIBILITY_TOOLS]
        return tools

    async def on_call_tool(self, context, call_next):
        if context.message.name not in _COMPATIBILITY_TOOLS:
            if message := authority_message(self._principal()["tenant_id"]):
                raise ToolError(message)
        return await call_next(context)
