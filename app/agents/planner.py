"""Agent A — Planner.

Receives high-level tasks, uses the configured LLM to produce a structured
plan, and narrows its own authority into a delegation for Agent B. It has
no tool references and no gateway access; it can only propose and delegate.
"""

from __future__ import annotations

import datetime as _dt

from app.agents.base import BaseAgent
from app.agents.messages import AgentPlan, new_message_id
from app.core.delegation import Delegation, DelegationBuilder
from app.core.identity import AgentIdentity
from app.llm.base import AgentProposal


class Planner(BaseAgent):
    """Agent A. Delegates a narrowed subset of its scopes to Agent B."""

    def __init__(
        self,
        identity: AgentIdentity,
        delegation: Delegation,
        provider,
        builder: DelegationBuilder,
    ) -> None:
        super().__init__(identity, delegation, provider)
        self._builder = builder

    def plan(self, task: str) -> AgentPlan | None:
        """Reason about the task; return a structured plan or None."""
        proposal: AgentProposal | None = self.propose(
            "You are Agent A (planner). Respond with one JSON object "
            '{"tool": ..., "arguments": ..., "rationale": ...} '
            "proposing exactly one tool call for the task.",
            task,
        )
        if proposal is None:
            return None
        return AgentPlan(
            plan_id=new_message_id(),
            task=task,
            tool_name=proposal.tool_name,
            arguments=proposal.arguments,
            rationale=proposal.rationale,
        )

    def delegate_to_specialist(
        self,
        specialist: AgentIdentity,
        scopes: list[str],
        *,
        ttl=None,
    ) -> Delegation:
        """Issue B's credential as a strict subset of A's own authority.

        Delegation is NOT authorization: the builder will sign whatever it
        is asked (A or B may be compromised), and the SecurityGateway's
        verifier rejects any over-broad credential at request time.
        """
        return self._builder.issue_child(
            self.identity, specialist, scopes, self.delegation,
            ttl=ttl or _dt.timedelta(minutes=30),
        )


__all__ = ["Planner"]
