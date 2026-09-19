"""Agent B — Specialist.

Refines the planner's delegation into a concrete execution request and
delegates to Agent C. B cannot expand its authority in any way that
matters: an over-broad credential it mints is rejected deterministically
by the verifier at the gateway (SCOPE_ESCALATION).
"""

from __future__ import annotations

import datetime as _dt

from app.agents.base import BaseAgent
from app.agents.messages import new_message_id
from app.core.delegation import Delegation, DelegationBuilder
from app.core.identity import AgentIdentity
from app.llm.base import AgentProposal


class Specialist(BaseAgent):
    """Agent B."""

    def __init__(
        self,
        identity: AgentIdentity,
        delegation: Delegation,
        provider,
        builder: DelegationBuilder,
    ) -> None:
        super().__init__(identity, delegation, provider)
        self._builder = builder

    def refine(self, task: str) -> AgentProposal | None:
        """Turn the delegated subtask into a proposed tool call."""
        return self.propose(
            "You are Agent B (specialist). Respond with one JSON object "
            '{"tool": ..., "arguments": ..., "rationale": ...} '
            "proposing exactly one tool call for the subtask.",
            task,
        )

    def delegate_to_executor(
        self,
        executor: AgentIdentity,
        scopes: list[str],
        *,
        ttl: _dt.timedelta | None = None,
    ) -> Delegation:
        """Issue C's credential. Sign-anything, verify-later: if scopes
        exceed B's own authority the credential is still well-formed, but
        the gateway will deterministically DENY any use of it."""
        return self._builder.issue_child(
            self.identity, executor, scopes, self.delegation, ttl=ttl or _dt.timedelta(minutes=30)
        )


__all__ = ["Specialist"]
