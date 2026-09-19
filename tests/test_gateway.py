"""SecurityGateway tests — the enforcement boundary of Phase 2.

The critical property: DENY means the tool function is never entered
(proven via execute_count), and ALLOW executes exactly once.
"""

from __future__ import annotations

import pytest

from app.agents.runtime import AgentRuntime
from app.audit import AuditStore
from app.core.delegation import InMemoryRevocationRegistry, sign_delegation
from app.core.identity import AgentIdentity
from app.gateway import SecurityGateway
from app.tools.registry import ToolRegistry
from app.tools.base import CalendarReadTool


@pytest.fixture()
def rt():
    from app.llm.mock import MockProvider

    return AgentRuntime.bootstrap(provider=MockProvider())


class TestGatewayDecisions:
    def test_valid_request_allows_and_executes_once(self, rt):
        result = rt.gateway.authorize_and_execute(
            rt.executor.agent_id, rt.full_chain(), "calendar.read", {"days": 2}
        )
        assert result.decision == "ALLOW"
        assert result.reason == "AUTHORIZED"
        assert result.executed is True
        assert result.tool_result is not None
        assert rt.registry.get("calendar.read").execute_count == 1

    def test_unauthorized_scope_denies_without_execution(self, rt):
        pay_before = rt.registry.get("payments.transfer").execute_count
        result = rt.gateway.authorize_and_execute(
            rt.executor.agent_id, rt.full_chain(), "payments.transfer", {"amount": 99}
        )
        assert result.decision == "DENY"
        assert result.reason == "UNAUTHORIZED_SCOPE"
        assert result.executed is False
        assert rt.registry.get("payments.transfer").execute_count == pay_before

    def test_forged_delegation_denied(self, rt):
        chain = rt.full_chain()
        forged = chain[2].model_copy(update={"signature": "ab" * 64})
        result = rt.gateway.authorize_and_execute(
            rt.executor.agent_id, [chain[0], chain[1], forged], "calendar.read"
        )
        assert result.decision == "DENY"
        assert result.reason == "INVALID_SIGNATURE"
        # Nothing was authorized in this runtime, so nothing ever executed.
        assert rt.registry.get("calendar.read").execute_count == 0

    def test_expired_delegation_denied(self, rt):
        from datetime import UTC, datetime, timedelta

        result = rt.gateway.authorize_and_execute(
            rt.executor.agent_id, rt.full_chain(), "calendar.read",
            now=datetime.now(UTC) + timedelta(hours=1),
        )
        assert result.decision == "DENY"
        assert result.reason == "EXPIRED_DELEGATION"
        assert result.executed is False

    def test_revoked_delegation_denied(self, rt):
        rt.revoke_specialist()
        result = rt.gateway.authorize_and_execute(
            rt.executor.agent_id, rt.full_chain(), "calendar.read"
        )
        assert result.decision == "DENY"
        assert result.reason == "REVOKED_DELEGATION"
        assert result.executed is False

    def test_scope_escalation_chain_denied(self, rt):
        """Compromised B mints an over-broad credential for C."""
        overbroad = rt.specialist.delegate_to_executor(
            rt.executor.identity, ["payments.transfer"]
        )
        chain = [rt.chain[0], rt.chain[1], overbroad]
        result = rt.gateway.authorize_and_execute(
            rt.executor.agent_id, chain, "payments.transfer", {"amount": 10}
        )
        assert result.decision == "DENY"
        assert result.reason == "SCOPE_ESCALATION"
        assert rt.registry.get("payments.transfer").execute_count == 0

    def test_unknown_tool_denied(self, rt):
        result = rt.gateway.authorize_and_execute(
            rt.executor.agent_id, rt.full_chain(), "bank.account.drain"
        )
        assert result.decision == "DENY"
        assert result.reason == "UNKNOWN_TOOL"

    def test_wrong_agent_id_denied(self, rt):
        result = rt.gateway.authorize_and_execute(
            "agent:imposter", rt.full_chain(), "calendar.read"
        )
        assert result.decision == "DENY"
        assert result.reason == "SUBJECT_MISMATCH"

    def test_empty_chain_denied(self, rt):
        result = rt.gateway.authorize_and_execute(rt.executor.agent_id, [], "calendar.read")
        assert result.decision == "DENY"

    def test_non_serializable_arguments_denied(self, rt):
        result = rt.gateway.authorize_and_execute(
            rt.executor.agent_id, rt.full_chain(), "calendar.read",
            {"fn": lambda: "evil"},
        )
        assert result.decision == "DENY"
        assert result.reason == "INVALID_REQUEST"
        assert rt.registry.get("calendar.read").execute_count == 0


class TestGatewayAudit:
    def test_every_request_produces_one_event(self, rt):
        rt.gateway.authorize_and_execute(
            rt.executor.agent_id, rt.full_chain(), "calendar.read"
        )
        rt.gateway.authorize_and_execute(
            rt.executor.agent_id, rt.full_chain(), "payments.transfer"
        )
        events = rt.audit.all_events()
        assert len(events) == 2
        assert [e.decision for e in events] == ["ALLOW", "DENY"]
        assert events[1].tool == "payments.transfer"
        assert events[1].executed is False
        assert events[1].delegation_id == rt.executor_delegation.delegation_id


class TestGatewayIndependence:
    def test_gateway_uses_injected_registry_not_default(self):
        """A custom registry proves the gateway has no hidden tool access."""
        registry = ToolRegistry([CalendarReadTool()])
        human = AgentIdentity.generate("human:root")
        from app.core.policy import TrustAnchor
        from app.core.delegation import DelegationBuilder

        anchor = TrustAnchor(human)
        a = AgentIdentity.generate("planner")
        root = DelegationBuilder(anchor).issue_root(a, ["calendar.read"])
        gateway = SecurityGateway(anchor, registry, AuditStore())
        result = gateway.authorize_and_execute(a.agent_id, [root], "calendar.read")
        assert result.decision == "ALLOW"
        assert registry.get("calendar.read").execute_count == 1
