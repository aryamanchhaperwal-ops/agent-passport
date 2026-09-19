"""Agent C — Executor.

Agent C never touches tool implementations. Its ONLY way to affect the
world is to submit a proposal to the SecurityGateway together with its
delegation chain; the gateway re-derives authorization from cryptography.
Anything C (or its LLM) claims about being authorized is ignored.
"""

from __future__ import annotations

from app.agents.base import BaseAgent
from app.gateway.security_gateway import GatewayResult, SecurityGateway
from app.llm.base import AgentProposal


class Executor(BaseAgent):
    """Agent C."""

    def __init__(
        self,
        identity,
        delegation,
        provider,
        gateway: SecurityGateway,
        chain_provider,
    ) -> None:
        super().__init__(identity, delegation, provider)
        self._gateway = gateway
        self._chain_provider = chain_provider  # callable -> full chain list

    def prepare(self, task: str) -> AgentProposal | None:
        """Ask the LLM what tool to call. The result is a PROPOSAL only."""
        return self.propose(
            "You are Agent C (executor). Respond with one JSON object "
            '{"tool": ..., "arguments": ..., "rationale": ...} '
            "proposing exactly one tool call.",
            task,
        )

    def attempt(self, tool_name: str, arguments: dict | None = None) -> GatewayResult:
        """Submit a tool request through the SecurityGateway.

        There is deliberately no other method here that could reach a tool.
        """
        return self._gateway.authorize_and_execute(
            agent_id=self.agent_id,
            chain=self._chain_provider(),
            tool_name=tool_name,
            arguments=arguments or {},
        )


__all__ = ["Executor"]
