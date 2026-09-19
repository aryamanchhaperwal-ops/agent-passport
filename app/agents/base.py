"""Agent base class.

An agent wraps a Phase 1 `AgentIdentity` (never a second identity system),
its own delegation credential, and an LLM provider. Agents PROPOSE via the
LLM; they hold no authorization logic and no tool references. The only
object in the system that can execute a tool is the SecurityGateway, and
only the runtime wires agents to it.
"""

from __future__ import annotations

from app.core.delegation import Delegation
from app.core.identity import AgentIdentity
from app.llm.base import AgentProposal, LLMProvider, parse_proposal
from app.agents.messages import new_message_id


class BaseAgent:
    """Shared plumbing for planner / specialist / executor."""

    def __init__(
        self,
        identity: AgentIdentity,
        delegation: Delegation,
        provider: LLMProvider,
    ) -> None:
        self._identity = identity
        self._delegation = delegation
        self._provider = provider

    @property
    def agent_id(self) -> str:
        return self._identity.agent_id

    @property
    def identity(self) -> AgentIdentity:
        return self._identity

    @property
    def delegation(self) -> Delegation:
        """This agent's own credential (never contains private keys)."""
        return self._delegation

    @property
    def effective_scopes(self) -> list[str]:
        return [str(s) for s in self._delegation.scopes]

    def propose(self, system: str, task: str) -> AgentProposal | None:
        """Ask the LLM for a proposal. Malformed output -> None (fail
        closed); the proposal itself carries no authority."""
        try:
            raw = self._provider.generate(system, task)
        except Exception:
            return None
        return parse_proposal(raw)

    def message_to(self, recipient: str, task: str, **fields) -> "AgentMessage":
        from app.agents.messages import AgentMessage

        return AgentMessage(
            message_id=new_message_id(),
            sender=self.agent_id,
            recipient=recipient,
            task=task,
            parent_delegation_id=self._delegation.delegation_id,
            **fields,
        )


__all__ = ["BaseAgent"]
