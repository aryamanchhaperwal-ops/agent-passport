"""Controlled local tool simulations for Phase 2.

Every tool here is a LOCAL SIMULATION. Nothing connects to real payment
systems, mail servers, calendars, or cloud storage. Each tool declares the
scope required to run it; the tool NEVER decides authorization — the
SecurityGateway consults the Phase 1 deterministic verifier BEFORE any tool
code executes, so a DENY means the tool function is never even entered.

Execution counting (`execute_count`) exists so tests can PROVE the gateway
enforcement boundary: an unauthorized call must leave the count at zero.
"""

from __future__ import annotations

import secrets
from typing import Any, Protocol

from pydantic import BaseModel, ConfigDict, Field


class ToolResult(BaseModel):
    """Structured output of a simulated tool execution."""

    model_config = ConfigDict(frozen=True)

    tool: str
    ok: bool
    simulated: bool = True
    data: dict[str, Any] = Field(default_factory=dict)


class Tool(Protocol):
    """Contract every controlled tool implements. Authorization is NOT part
    of this contract — tools assume the gateway already verified scope."""

    @property
    def name(self) -> str: ...

    @property
    def required_scope(self) -> str: ...

    @property
    def execute_count(self) -> int: ...

    def execute(self, arguments: dict[str, Any]) -> ToolResult: ...


class SimulatedTool:
    """Base for local simulated tools. Counts every real invocation."""

    def __init__(self, name: str, required_scope: str) -> None:
        self._name = name
        self._required_scope = required_scope
        self._execute_count = 0

    @property
    def name(self) -> str:
        return self._name

    @property
    def required_scope(self) -> str:
        return self._required_scope

    @property
    def execute_count(self) -> int:
        return self._execute_count

    def execute(self, arguments: dict[str, Any]) -> ToolResult:  # pragma: no cover
        raise NotImplementedError

    def _mark_executed(self) -> None:
        self._execute_count += 1


def _sim_id(prefix: str) -> str:
    return f"{prefix}-{secrets.token_hex(6).upper()}"


class CalendarReadTool(SimulatedTool):
    def __init__(self) -> None:
        super().__init__("calendar.read", "calendar.read")

    def execute(self, arguments: dict[str, Any]) -> ToolResult:
        self._mark_executed()
        return ToolResult(
            tool=self._name,
            ok=True,
            data={
                "event_id": _sim_id("CAL"),
                "availability": ["2026-09-21T10:00Z", "2026-09-21T14:00Z"],
                "queried_days": int(arguments.get("days", 7)),
            },
        )


class EmailReadTool(SimulatedTool):
    def __init__(self) -> None:
        super().__init__("email.read", "email.read")

    def execute(self, arguments: dict[str, Any]) -> ToolResult:
        self._mark_executed()
        return ToolResult(
            tool=self._name,
            ok=True,
            data={
                "message_ids": [_sim_id("MSG")],
                "mailbox": str(arguments.get("mailbox", "inbox")),
            },
        )


class EmailSendTool(SimulatedTool):
    def __init__(self) -> None:
        super().__init__("email.send", "email.send")

    def execute(self, arguments: dict[str, Any]) -> ToolResult:
        self._mark_executed()
        return ToolResult(
            tool=self._name,
            ok=True,
            data={
                "message_id": _sim_id("MSG"),
                "to": str(arguments.get("to", "undisclosed@local.test")),
                "subject": str(arguments.get("subject", "(no subject)")),
            },
        )


class FilesReadTool(SimulatedTool):
    def __init__(self) -> None:
        super().__init__("files.read", "files.read")

    def execute(self, arguments: dict[str, Any]) -> ToolResult:
        self._mark_executed()
        return ToolResult(
            tool=self._name,
            ok=True,
            data={
                "path": str(arguments.get("path", "/local/simulated")),
                "entries": ["notes.txt", "plan.md"],
            },
        )


class FilesWriteTool(SimulatedTool):
    def __init__(self) -> None:
        super().__init__("files.write", "files.write")

    def execute(self, arguments: dict[str, Any]) -> ToolResult:
        self._mark_executed()
        return ToolResult(
            tool=self._name,
            ok=True,
            data={
                "path": str(arguments.get("path", "/local/simulated/out.txt")),
                "bytes_written": len(str(arguments.get("content", ""))),
            },
        )


class PaymentsTransferTool(SimulatedTool):
    """SIMULATED payment. Produces a fake transaction id and touches no
    external system whatsoever."""

    def __init__(self) -> None:
        super().__init__("payments.transfer", "payments.transfer")

    def execute(self, arguments: dict[str, Any]) -> ToolResult:
        self._mark_executed()
        amount = arguments.get("amount", 0)
        try:
            amount = round(float(amount), 2)
        except (TypeError, ValueError):
            amount = 0.0
        return ToolResult(
            tool=self._name,
            ok=True,
            data={
                "status": "executed",
                "transaction_id": _sim_id("SIM"),
                "amount": amount,
                "currency": str(arguments.get("currency", "USD")),
                "note": "SIMULATION ONLY - no real funds moved",
            },
        )
