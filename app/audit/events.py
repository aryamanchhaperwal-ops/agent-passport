"""In-memory audit event system for Phase 2.

Every tool request produces exactly one event — ALLOW or DENY, executed or
not — recorded BEFORE anything else happens with the decision. Events are
append-only for the lifetime of the process; this feeds the Phase 3
dashboard later (no database yet, by design).
"""

from __future__ import annotations

import itertools
import secrets
from datetime import UTC, datetime

from pydantic import BaseModel, ConfigDict, Field


def _event_id() -> str:
    return f"evt_{secrets.token_hex(8)}"


class AuditEvent(BaseModel):
    """One security-relevant occurrence, machine-readable for the dashboard."""

    model_config = ConfigDict(frozen=True)

    event_id: str = Field(default_factory=_event_id)
    event: str                      # e.g. "TOOL_REQUEST"
    timestamp: datetime             # timezone-aware UTC
    agent: str | None = None
    tool: str | None = None
    requested_scope: str | None = None
    decision: str                   # "ALLOW" | "DENY" | other gateway outcomes
    reason: str | None = None
    executed: bool = False
    delegation_id: str | None = None
    detail: str | None = None


from typing import Protocol

class AuditStore(Protocol):
    def record(self, event: AuditEvent) -> AuditEvent: ...
    def all_events(self) -> list[AuditEvent]: ...
    def count(self) -> int: ...
    def clear(self) -> None: ...

class InMemoryAuditStore(AuditStore):
    """Thread-safe-enough append-only in-memory event log."""

    def __init__(self) -> None:
        self._events: list[AuditEvent] = []
        self._counter = itertools.count(1)

    def record(self, event: AuditEvent) -> AuditEvent:
        self._events.append(event)
        return event

    def all_events(self) -> list[AuditEvent]:
        return list(self._events)

    def count(self) -> int:
        return len(self._events)

    def clear(self) -> None:
        """Test convenience only — never used by production code paths."""
        self._events.clear()


def tool_request_event(
    *,
    agent: str | None,
    tool: str | None,
    requested_scope: str | None,
    decision: str,
    reason: str | None,
    executed: bool,
    delegation_id: str | None = None,
    detail: str | None = None,
) -> AuditEvent:
    """Build the standard TOOL_REQUEST event emitted by the gateway."""
    return AuditEvent(
        event="TOOL_REQUEST",
        timestamp=datetime.now(UTC),
        agent=agent,
        tool=tool,
        requested_scope=requested_scope,
        decision=decision,
        reason=reason,
        executed=executed,
        delegation_id=delegation_id,
        detail=detail,
    )


__all__ = ["AuditEvent", "AuditStore", "tool_request_event"]
