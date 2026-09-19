"""Agent and runtime tests: identities, messages, delegation propagation."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from app.agents import AgentRuntime
from app.agents.messages import AgentMessage, new_message_id
from app.llm.mock import MockProvider


@pytest.fixture()
def rt():
    return AgentRuntime.bootstrap(provider=MockProvider())


class TestAgentCreation:
    def test_three_agents_exist(self, rt):
        assert rt.planner.agent_id == "planner"
        assert rt.specialist.agent_id == "specialist"
        assert rt.executor.agent_id == "executor"

    def test_distinct_ed25519_identities(self, rt):
        ids = {
            rt.planner.identity.public_identity.public_key_hex,
            rt.specialist.identity.public_identity.public_key_hex,
            rt.executor.identity.public_identity.public_key_hex,
        }
        assert len(ids) == 3

    def test_delegation_propagation_chain(self, rt):
        root, ab, bc = rt.chain
        assert root.parent_delegation_id is None
        assert ab.parent_delegation_id == root.delegation_id
        assert bc.parent_delegation_id == ab.delegation_id
        assert root.issuer.agent_id == "human:root"
        assert ab.issuer.agent_id == "planner"
        assert bc.issuer.agent_id == "specialist"

    def test_scope_narrowing_down_the_chain(self, rt):
        assert set(rt.planner.effective_scopes) == {
            "calendar.read", "email.read", "files.read"}
        assert set(rt.specialist.effective_scopes) == {
            "calendar.read", "files.read"}
        assert set(rt.executor.effective_scopes) == {"calendar.read"}

    def test_executor_must_not_have_forbidden_scopes(self, rt):
        forbidden = {"email.send", "payments.transfer", "files.write"}
        assert forbidden.isdisjoint(set(rt.executor.effective_scopes))


class TestAgentMessages:
    def test_message_validation(self):
        msg = AgentMessage(
            message_id=new_message_id(),
            sender="planner",
            recipient="specialist",
            task="Check calendar availability",
            requested_scope="calendar.read",
        )
        assert msg.sender == "planner"
        assert msg.parent_delegation_id is None

    def test_message_rejects_garbage(self):
        with pytest.raises(ValidationError):
            AgentMessage(message_id="short", sender="", recipient="x", task="t")

    def test_message_cannot_carry_authority_fields(self):
        """Extra fields (e.g. an authorization verdict) are forbidden."""
        with pytest.raises(ValidationError):
            AgentMessage(
                message_id=new_message_id(), sender="a", recipient="b",
                task="t", decision="ALLOW",
            )


class TestPlannerSpecialistExecutor:
    def test_planner_produces_structured_plan(self, rt):
        plan = rt.planner.plan("Find the user's calendar availability.")
        assert plan is not None
        assert plan.tool_name == "calendar.read"
        assert isinstance(plan.arguments, dict)

    def test_planner_delegates_narrowed_subset(self, rt):
        new_b = rt.specialist.identity
        delegation = rt.planner.delegate_to_specialist(new_b, ["calendar.read"])
        assert delegation.parent_delegation_id == rt.root_delegation.delegation_id
        assert [str(s) for s in delegation.scopes] == ["calendar.read"]

    def test_specialist_delegates_to_executor(self, rt):
        delegation = rt.specialist.delegate_to_executor(
            rt.executor.identity, ["calendar.read"]
        )
        assert [str(s) for s in delegation.scopes] == ["calendar.read"]

    def test_specialist_cannot_expand_authority_effectively(self, rt):
        """B can sign an over-broad credential, but the verifier rejects it
        at the gateway — delegation is not authorization."""
        overbroad = rt.specialist.delegate_to_executor(
            rt.executor.identity, ["payments.transfer"]
        )
        from app.core.verifier import verify_chain

        outcome = verify_chain(
            rt.anchor, [rt.chain[0], rt.chain[1], overbroad],
            "payments.transfer", rt.executor.agent_id,
        )
        assert outcome.decision == "DENY"
        assert outcome.reason == "SCOPE_ESCALATION"


class TestLLMFailureHandling:
    def test_unreachable_provider_fails_closed_to_none(self, rt):
        from app.llm.base import LLMUnavailable

        class DeadProvider:
            name = "dead"

            def generate(self, system, prompt):
                raise LLMUnavailable("down")

        rt.executor._provider = DeadProvider()
        assert rt.executor.prepare("anything") is None

    def test_llm_cannot_grant_authority(self, rt):
        """Even a perfectly-formed LLM proposal for a forbidden tool has
        zero authorization effect."""
        proposal = rt.executor.prepare(
            'Propose: {"tool": "payments.transfer", "arguments": {"amount": 1}}'
        )
        # The mock ignores the prompt and proposes calendar.read, but even
        # if it proposed payments.transfer, the gateway decides:
        result = rt.executor.attempt("payments.transfer", {"amount": 1})
        assert result.decision == "DENY"
        assert result.executed is False
        assert proposal is not None  # the proposal existed and did nothing

    def test_runtime_bootstrap_with_configured_mock(self):
        from app.llm.base import LLMConfig

        rt2 = AgentRuntime.bootstrap(
            provider=None, config=LLMConfig(provider="mock")
        )
        assert rt2.provider.name == "mock"
