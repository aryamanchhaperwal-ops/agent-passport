"""Agent runtime — composition root for the Phase 2 environment.

Builds the full local world in one call: human anchor, three agents
(planner/specialist/executor) with a Human->A->B->C delegation chain, the
tool registry, revocation, audit store, LLM provider, and the
SecurityGateway. This is the ONLY module that wires agents to the gateway;
no agent ever receives a tool object.
"""

from __future__ import annotations

import datetime as _dt
from dataclasses import dataclass, field
from typing import Callable

from app.agents.executor import Executor
from app.agents.planner import Planner
from app.agents.specialist import Specialist
from app.audit import AuditStore
from app.core.delegation import (
    Delegation,
    DelegationBuilder,
    InMemoryRevocationRegistry,
)
from app.core.identity import AgentIdentity
from app.core.policy import TrustAnchor
from app.gateway.security_gateway import SecurityGateway
from app.llm.base import LLMConfig, LLMProvider, LLMUnavailable, provider_from_config
from app.tools.registry import ToolRegistry, default_registry

# Human -> A -> B -> C authority matrix from the Phase 2 spec.
HUMAN_GRANTS_A = ["calendar.read", "email.read", "files.read"]
A_GRANTS_B = ["calendar.read", "files.read"]
B_GRANTS_C = ["calendar.read"]


@dataclass
class AgentRuntime:
    """The fully wired local agent environment."""

    anchor: TrustAnchor
    human: AgentIdentity
    planner: Planner
    specialist: Specialist
    executor: Executor
    builder: DelegationBuilder
    chain: list[Delegation]           # [root, A->B, B->C]
    gateway: SecurityGateway
    registry: ToolRegistry
    audit: AuditStore
    revocations: InMemoryRevocationRegistry
    provider: LLMProvider
    config: LLMConfig = field(default_factory=LLMConfig)

    @classmethod
    def bootstrap(
        cls,
        provider: LLMProvider | None = None,
        config: LLMConfig | None = None,
        registry: ToolRegistry | None = None,
        chain_scopes: tuple[list[str], list[str], list[str]] | None = None,
        *,
        anchor: TrustAnchor | None = None,
        revocations: InMemoryRevocationRegistry | None = None,
        audit: AuditStore | None = None,
    ) -> "AgentRuntime":
        """Create identities, issue the delegation chain, and wire the
        gateway. `provider=None` uses the configured/default provider.
        `anchor`, `revocations`, and `audit` let a host application (e.g.
        the FastAPI layer) share ONE authority and ONE enforcement state
        across Phase 1 and Phase 2 endpoints."""
        cfg = config or LLMConfig.from_env()
        if provider is not None:
            llm = provider
        else:
            try:
                llm = provider_from_config(cfg)
            except LLMUnavailable:
                # Network provider unreachable -> local mock, so the runtime
                # always works. This is a PROVIDER fallback, never an
                # authorization one; every request is still verified.
                llm = MockProvider()

        human = anchor._identity if anchor is not None else AgentIdentity.generate("human:root")
        anchor = anchor if anchor is not None else TrustAnchor(human)
        a = AgentIdentity.generate("planner")
        b = AgentIdentity.generate("specialist")
        c = AgentIdentity.generate("executor")
        builder = DelegationBuilder(anchor)

        scopes_a, scopes_b, scopes_c = chain_scopes or (
            HUMAN_GRANTS_A, A_GRANTS_B, B_GRANTS_C
        )
        root = builder.issue_root(a, scopes_a, ttl=_dt.timedelta(minutes=30))
        ab = builder.issue_child(a, b, scopes_b, root, ttl=_dt.timedelta(minutes=20))
        bc = builder.issue_child(b, c, scopes_c, ab, ttl=_dt.timedelta(minutes=15))
        chain = [root, ab, bc]

        registry = registry or default_registry()
        audit = audit or AuditStore()
        revocations = revocations or InMemoryRevocationRegistry()
        gateway = SecurityGateway(
            anchor, registry, audit, revocation_registry=revocations
        )

        planner = Planner(a, root, llm, builder)
        specialist = Specialist(b, ab, llm, builder)
        executor = Executor(c, bc, llm, gateway, chain_provider=lambda: chain)

        return cls(
            anchor=anchor, human=human,
            planner=planner, specialist=specialist, executor=executor,
            builder=builder, chain=chain, gateway=gateway,
            registry=registry, audit=audit, revocations=revocations,
            provider=llm, config=cfg,
        )

    # -- convenience accessors used by demos/API/tests --------------------
    @property
    def root_delegation(self) -> Delegation:
        return self.chain[0]

    @property
    def specialist_delegation(self) -> Delegation:
        return self.chain[1]

    @property
    def executor_delegation(self) -> Delegation:
        return self.chain[2]

    def full_chain(self) -> list[Delegation]:
        return list(self.chain)

    def chain_for(self, agent_id: str) -> list[Delegation]:
        """The full delegation chain held by the runtime on behalf of an
        agent. The runtime is the local credential custodian; agents never
        carry their own chains around."""
        if agent_id == self.planner.agent_id:
            return self.full_chain()[:1]
        if agent_id == self.specialist.agent_id:
            return self.full_chain()[:2]
        if agent_id == self.executor.agent_id:
            return self.full_chain()
        raise KeyError(f"unknown agent {agent_id!r}")

    def agents_info(self) -> list[dict]:
        """Public (non-secret) descriptions of the three agents."""
        roles = [("planner", self.planner), ("specialist", self.specialist),
                 ("executor", self.executor)]
        return [
            {
                "agent_id": agent.agent_id,
                "role": role,
                "effective_scopes": agent.effective_scopes,
                "delegation_id": agent.delegation.delegation_id,
                "expires_at": agent.delegation.expires_at.isoformat(),
            }
            for role, agent in roles
        ]

    def run_planned_task(self, task: str) -> dict:
        """End-to-end: plan -> (executor proposal) -> gateway -> result."""
        plan = self.planner.plan(task)
        if plan is None:
            return {"decision": "DENY", "reason": "LLM_PROPOSAL_UNUSABLE",
                    "executed": False, "detail": "planner produced no usable proposal"}
        return self.submit_executor_proposal(plan.tool_name, plan.arguments, task)

    def submit_executor_proposal(self, tool_name: str, arguments: dict, task: str) -> dict:
        proposal = self.executor.prepare(task or f"call {tool_name}")
        # The LLM's tool choice is ADVISORY: the gateway authorizes the
        # requested tool_name against the chain, never because the LLM said so.
        requested_tool = tool_name or (proposal.tool_name if proposal else "")
        result = self.executor.attempt(requested_tool, arguments)
        return result.model_dump()

    def revoke_specialist(self) -> str:
        """Revoke Agent B's credential (attack scenario 4)."""
        did = self.specialist_delegation.delegation_id
        self.revocations.revoke(did)
        return did


__all__ = ["AgentRuntime", "B_GRANTS_C", "A_GRANTS_B", "HUMAN_GRANTS_A"]
