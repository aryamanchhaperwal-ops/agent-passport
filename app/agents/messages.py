"""Typed internal agent messages.

All inter-agent communication goes through validated Pydantic models — no
arbitrary Python objects cross an agent boundary, so nothing can smuggle a
tool handle or an authorization decision through a message.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


def _utc_now() -> datetime:
    return datetime.now(UTC)


class AgentMessage(BaseModel):
    """One message between agents (or human -> agent)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    message_id: str = Field(min_length=8, max_length=64)
    sender: str = Field(min_length=1, max_length=128)
    recipient: str = Field(min_length=1, max_length=128)
    task: str = Field(min_length=1, max_length=4000)
    tool_name: str | None = Field(default=None, max_length=128)
    requested_scope: str | None = Field(default=None, max_length=128)
    arguments: dict[str, Any] = Field(default_factory=dict)
    parent_delegation_id: str | None = Field(default=None, max_length=128)
    timestamp: datetime = Field(default_factory=_utc_now)

    @field_validator("tool_name", "requested_scope", "parent_delegation_id")
    @classmethod
    def _not_blank(cls, v: str | None) -> str | None:
        if v is not None and not v.strip():
            return None
        return v


class AgentPlan(BaseModel):
    """Structured output of the planner: what to do and with what tool."""

    model_config = ConfigDict(frozen=True)

    plan_id: str = Field(min_length=8, max_length=64)
    task: str = Field(min_length=1, max_length=4000)
    tool_name: str = Field(min_length=1, max_length=128)
    arguments: dict[str, Any] = Field(default_factory=dict)
    rationale: str = Field(default="", max_length=2000)
    created_at: datetime = Field(default_factory=_utc_now)


def new_message_id() -> str:
    import secrets

    return f"msg_{secrets.token_hex(8)}"


__all__ = ["AgentMessage", "AgentPlan", "new_message_id"]
