"""Phase 3 dashboard API tests.

The dashboard buttons hit these endpoints; the security property under
test is that they all route through the SAME gateway/verifier as Phase 2
and that every presented fact (checks, executed, reason) is derived
backend-side, never by the UI.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.core.delegation import InMemoryRevocationRegistry
from app.core.identity import AgentIdentity
from app.core.policy import TrustAnchor
from app.main import create_app


@pytest.fixture()
def client():
    return TestClient(create_app(TrustAnchor(AgentIdentity.generate("human:root")),
                                  InMemoryRevocationRegistry()))


class TestDemoState:
    def test_state_snapshot_shape(self, client):
        state = client.get("/demo/state").json()
        assert [a["agent_id"] for a in state["agents"]] == [
            "planner", "specialist", "executor"]
        assert all(a["status"] == "ACTIVE" for a in state["agents"])
        assert len(state["links"]) == 3
        assert all(link["valid"] for link in state["links"])
        assert state["gateway_online"] is True
        assert state["last"] is None
        assert state["stats"]["total_decisions"] == 0

    def test_scope_narrowing_visible_in_state(self, client):
        state = client.get("/demo/state").json()
        human = state["chain_summary"]["human_scopes"]
        executor = state["chain_summary"]["executor_scopes"]
        assert "calendar.read" in executor
        assert executor != human  # authority narrowed down the chain
        assert "payments.transfer" not in executor


class TestDemoFlow:
    def test_legitimate_request_allows_and_executes(self, client):
        body = client.post("/demo/legitimate").json()
        result = body["result"]
        assert result["decision"] == "ALLOW"
        assert result["reason"] == "AUTHORIZED"
        assert result["executed"] is True
        assert body["state"]["last"]["checks"] == {
            "identity": True, "chain": True, "signature": True,
            "revocation": True, "expiry": True, "scope": True,
        }

    def test_scope_escalation_denied_and_tool_not_executed(self, client):
        body = client.post("/demo/attack/scope-escalation").json()
        result = body["result"]
        assert result["decision"] == "DENY"
        assert result["reason"] == "UNAUTHORIZED_SCOPE"
        assert result["executed"] is False
        assert result["tool_result"] is None
        assert body["state"]["last"]["checks"]["scope"] is False

    def test_signature_tampering_denied(self, client):
        body = client.post("/demo/attack/signature-tampering").json()
        result = body["result"]
        assert result["decision"] == "DENY"
        assert result["reason"] == "INVALID_SIGNATURE"
        assert result["executed"] is False
        tamper = body["tamper"]
        assert tamper["modified_field"] == "scopes"
        assert tamper["original_scopes"] != tamper["tampered_scopes"]

    def test_revoke_then_legitimate_denied(self, client):
        client.post("/demo/revoke-specialist")
        body = client.post("/demo/legitimate").json()
        assert body["result"]["decision"] == "DENY"
        assert body["result"]["reason"] == "REVOKED_DELEGATION"
        executor = [a for a in body["state"]["agents"] if a["agent_id"] == "executor"][0]
        assert executor["status"] == "BLOCKED"

    def test_full_hackathon_sequence(self, client):
        """The exact demo flow from the Phase 3 spec, end to end."""
        # STEP 2: legitimate -> ALLOW + executed
        r = client.post("/demo/legitimate").json()["result"]
        assert (r["decision"], r["executed"]) == ("ALLOW", True)
        # STEP 3: escalation -> DENY, not executed
        r = client.post("/demo/attack/scope-escalation").json()["result"]
        assert (r["decision"], r["reason"], r["executed"]) == (
            "DENY", "UNAUTHORIZED_SCOPE", False)
        # STEP 4: tampering -> DENY, not executed
        r = client.post("/demo/attack/signature-tampering").json()["result"]
        assert (r["decision"], r["reason"], r["executed"]) == (
            "DENY", "INVALID_SIGNATURE", False)
        # STEP 5: revoke B -> legitimate request now DENIED
        client.post("/demo/revoke-specialist")
        r = client.post("/demo/legitimate").json()["result"]
        assert (r["decision"], r["reason"]) == ("DENY", "REVOKED_DELEGATION")
        # STEP 6: reset -> clean state again
        state = client.post("/demo/reset").json()
        assert state["stats"]["total_decisions"] == 0
        assert all(a["status"] == "ACTIVE" for a in state["agents"])
        # ...and the demo can be repeated: legitimate works again
        r = client.post("/demo/legitimate").json()["result"]
        assert (r["decision"], r["executed"]) == ("ALLOW", True)

    def test_reset_clears_events_and_decisions(self, client):
        client.post("/demo/legitimate")
        client.post("/demo/attack/scope-escalation")
        state = client.post("/demo/reset").json()
        assert state["stats"] == {
            "total_decisions": 0, "allowed": 0, "denied": 0,
            "blocked_actions": 0, "audit_events": 3,  # the 3 delegations
        }
        assert state["last"] is None

    def test_events_are_recorded_backend_side(self, client):
        client.post("/demo/legitimate")
        client.post("/demo/attack/scope-escalation")
        events = client.get("/demo/state").json()["events"]
        kinds = [(e["event"], e["decision"]) for e in events]
        assert ("TOOL_REQUEST", "ALLOW") in kinds
        assert ("TOOL_REQUEST", "DENY") in kinds
        assert ("DELEGATION", "ISSUED") in kinds

    def test_denied_request_never_executes_tool(self, client):
        """A denied demo attack returns no tool result at all."""
        body = client.post("/demo/attack/scope-escalation").json()
        assert body["result"]["executed"] is False
        assert body["result"]["tool_result"] is None
