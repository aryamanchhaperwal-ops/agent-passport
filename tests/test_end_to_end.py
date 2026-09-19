"""End-to-end integration: Human -> A -> B -> C -> gateway -> tool.

The second scenario is the most important test in the suite: a DENY must
mean the tool function was NEVER entered (execute_count == 0), not a DENY
verdict pasted on top of a real execution.
"""

from __future__ import annotations

import pytest

from app.agents import AgentRuntime
from app.llm.mock import MockProvider


@pytest.fixture()
def rt():
    return AgentRuntime.bootstrap(provider=MockProvider())


class TestEndToEnd:
    def test_valid_chain_executes_tool_exactly_once(self, rt):
        """Human -> A -> B -> C -> calendar.read -> ALLOW -> 1 execution."""
        result = rt.gateway.authorize_and_execute(
            rt.executor.agent_id, rt.full_chain(), "calendar.read", {"days": 7}
        )
        assert result.decision == "ALLOW"
        assert result.reason == "AUTHORIZED"
        assert result.executed is True
        assert result.tool_result.tool == "calendar.read"
        assert result.tool_result.simulated is True
        assert rt.registry.get("calendar.read").execute_count == 1

    def test_unauthorized_tool_denied_and_never_executes(self, rt):
        """Agent C -> payments.transfer -> DENY -> 0 executions. Period."""
        result = rt.gateway.authorize_and_execute(
            rt.executor.agent_id, rt.full_chain(), "payments.transfer",
            {"amount": 9999.99, "to": "attacker"},
        )
        assert result.decision == "DENY"
        assert result.executed is False
        assert result.tool_result is None
        assert rt.registry.get("payments.transfer").execute_count == 0

    def test_full_pipeline_through_planning(self, rt):
        """plan (LLM) -> executor proposal -> gateway -> tool."""
        output = rt.run_planned_task("Find the user's calendar availability.")
        assert output["decision"] == "ALLOW"
        assert output["executed"] is True
        assert rt.registry.get("calendar.read").execute_count == 1

    def test_allowed_then_denied_sequence(self, rt):
        """One runtime: ALLOW once, then a DENY with zero extra executions."""
        rt.gateway.authorize_and_execute(
            rt.executor.agent_id, rt.full_chain(), "calendar.read")
        rt.gateway.authorize_and_execute(
            rt.executor.agent_id, rt.full_chain(), "payments.transfer")
        assert rt.registry.get("calendar.read").execute_count == 1
        assert rt.registry.get("payments.transfer").execute_count == 0

    def test_email_and_files_denied_for_executor(self, rt):
        """C holds only calendar.read; every other tool is out of reach."""
        for tool in ("email.read", "email.send", "files.read", "files.write"):
            result = rt.gateway.authorize_and_execute(
                rt.executor.agent_id, rt.full_chain(), tool)
            assert result.decision == "DENY"
            assert result.reason == "UNAUTHORIZED_SCOPE"
        # Nothing but the earlier ALLOW cases ever executed.
        counts = {
            name: rt.registry.get(name).execute_count
            for name in rt.registry.names()
        }
        assert all(count == 0 for count in counts.values())

    def test_specialist_may_use_its_own_scopes(self, rt):
        """Agent B itself can execute what it legitimately holds."""
        result = rt.gateway.authorize_and_execute(
            rt.specialist.agent_id, rt.chain_for(rt.specialist.agent_id),
            "files.read",
        )
        assert result.decision == "ALLOW"
        assert rt.registry.get("files.read").execute_count == 1
