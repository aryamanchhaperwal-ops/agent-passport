"""Registry of controlled local tools.

The registry is the ONLY lookup from a tool name to a tool implementation.
The SecurityGateway resolves tools through it; agents never receive tool
objects, only names — so there is no agent->tool path that skips the
gateway. Registration is fixed at construction; there is no runtime way
for an agent to add or replace tools.
"""

from __future__ import annotations

from typing import Any

from app.tools.base import CalendarReadTool, EmailReadTool, EmailSendTool, FilesReadTool, FilesWriteTool, PaymentsTransferTool, Tool, ToolResult


class ToolRegistry:
    """Fixed mapping of tool name -> simulated tool."""

    def __init__(self, tools: list[Tool] | None = None) -> None:
        if tools is None:
            tools = [
                CalendarReadTool(),
                EmailReadTool(),
                EmailSendTool(),
                FilesReadTool(),
                FilesWriteTool(),
                PaymentsTransferTool(),
            ]
        self._tools: dict[str, Tool] = {}
        for tool in tools:
            if tool.name in self._tools:
                raise ValueError(f"duplicate tool name {tool.name!r}")
            self._tools[tool.name] = tool

    def get(self, tool_name: str) -> Tool | None:
        return self._tools.get(tool_name)

    def required_scope(self, tool_name: str) -> str | None:
        tool = self._tools.get(tool_name)
        return tool.required_scope if tool else None

    def names(self) -> list[str]:
        return sorted(self._tools)

    def execute(self, tool_name: str, arguments: dict[str, Any]) -> ToolResult:
        """Execute a tool WITHOUT any authorization check.

        Package-internal: only the SecurityGateway may call this, after the
        Phase 1 verifier returned ALLOW. It exists so the gateway does not
        need to know individual tool classes.
        """
        tool = self._tools.get(tool_name)
        if tool is None:
            raise KeyError(f"unknown tool {tool_name!r}")
        return tool.execute(arguments)


def default_registry() -> ToolRegistry:
    """The standard Phase 2 toolset (all local simulations).

    Returns a FRESH registry on every call so each runtime owns its own
    tool instances (isolated execute counts, no hidden shared state).
    Hosts that need one shared instance should create it explicitly and
    pass it to both the runtime and the gateway.
    """
    return ToolRegistry()


__all__ = ["ToolRegistry", "default_registry"]
