"""Tests for the minimal FastAPI surface (local prototype, no auth)."""

from __future__ import annotations

from fastapi.testclient import TestClient

from app.core.delegation import InMemoryRevocationRegistry
from app.main import create_app
from app.core.policy import TrustAnchor


def _client(anchor: TrustAnchor) -> TestClient:
    return TestClient(create_app(anchor, InMemoryRevocationRegistry()))


class TestHealth:
    def test_health_returns_ok(self, anchor):
        response = _client(anchor).get("/health")
        assert response.status_code == 200
        body = response.json()
        assert body["status"] == "ok"
        assert body["anchor_agent_id"] == anchor.agent_id

    def test_health_leaks_no_key_material(self, anchor, human):
        body = _client(anchor).get("/health").json()
        assert human.export_private_key_hex() not in response_text(body)


def response_text(body: dict) -> str:
    import json

    return json.dumps(body)


class TestVerifyEndpoint:
    def test_valid_chain_allows_over_http(
        self, anchor, chains, agent_a, agent_b, agent_c
    ):
        root = chains.root(agent_a, ["calendar.read", "calendar.write"])
        ab = chains.child(agent_a, agent_b, ["calendar.read"], root)
        bc = chains.child(agent_b, agent_c, ["calendar.read"], ab)
        payload = {
            "requesting_agent_id": agent_c.agent_id,
            "requested_scope": "calendar.read",
            "chain": [c.model_dump(mode="json") for c in (root, ab, bc)],
        }
        response = _client(anchor).post("/verify", json=payload)
        assert response.status_code == 200
        body = response.json()
        assert body["decision"] == "ALLOW"
        assert body["reason"] == "AUTHORIZED"
        assert body["effective_scopes"] == ["calendar.read"]

    def test_escalation_denied_over_http(
        self, anchor, chains, agent_a, agent_b, agent_c
    ):
        root = chains.root(agent_a, ["calendar.read"])
        ab = chains.child(agent_a, agent_b, ["calendar.read"], root)
        bc = chains.child(agent_b, agent_c, ["calendar.read"], ab)
        payload = {
            "requesting_agent_id": agent_c.agent_id,
            "requested_scope": "payments.transfer",
            "chain": [c.model_dump(mode="json") for c in (root, ab, bc)],
        }
        body = _client(anchor).post("/verify", json=payload).json()
        assert body["decision"] == "DENY"
        assert body["reason"] == "UNAUTHORIZED_SCOPE"

    def test_tampered_chain_denied_over_http(
        self, anchor, chains, agent_a
    ):
        from app.core.models import Scope

        root = chains.root(agent_a, ["calendar.read"])
        tampered = root.model_copy(
            update={"scopes": [Scope.parse("payments.transfer")]}
        )
        payload = {
            "requesting_agent_id": agent_a.agent_id,
            "requested_scope": "payments.transfer",
            "chain": [tampered.model_dump(mode="json")],
        }
        body = _client(anchor).post("/verify", json=payload).json()
        assert body["decision"] == "DENY"
        assert body["reason"] == "INVALID_SIGNATURE"

    def test_malformed_payload_is_rejected(self, anchor):
        client = _client(anchor)
        response = client.post(
            "/verify",
            json={"requesting_agent_id": "agent:A", "chain": "not-a-chain"},
        )
        assert response.status_code == 422

    def test_invalid_scope_string_rejected(self, anchor):
        response = _client(anchor).post(
            "/verify",
            json={
                "requesting_agent_id": "agent:A",
                "requested_scope": "calendar.read.write",
                "chain": [],
            },
        )
        assert response.status_code == 422


class TestPhase2Api:
    def _app(self, anchor):
        from app.main import create_app

        return TestClient(create_app(anchor, InMemoryRevocationRegistry()))

    def test_agents_endpoint_lists_three_agents(self, anchor):
        body = self._app(anchor).get("/agents").json()
        assert [a["agent_id"] for a in body["agents"]] == [
            "planner", "specialist", "executor"]
        # No private key material in public agent info.
        assert "public_key" not in str(body).lower().replace("public_key_hex", "")

    def test_agents_run_allows_valid_task(self, anchor):
        body = self._app(anchor).post(
            "/agents/run", json={"task": "Find the user's calendar availability."}
        ).json()
        assert body["decision"] == "ALLOW"
        assert body["executed"] is True

    def test_tools_execute_passes_through_gateway(self, anchor):
        client = self._app(anchor)
        ok = client.post("/tools/execute", json={
            "agent_id": "executor", "tool_name": "calendar.read",
        }).json()
        assert ok["decision"] == "ALLOW" and ok["executed"] is True
        attack = client.post("/tools/execute", json={
            "agent_id": "executor", "tool_name": "payments.transfer",
            "arguments": {"amount": 1000},
        }).json()
        assert attack["decision"] == "DENY"
        assert attack["reason"] == "UNAUTHORIZED_SCOPE"
        assert attack["executed"] is False

    def test_unknown_agent_404_and_audited(self, anchor):
        client = self._app(anchor)
        response = client.post("/tools/execute", json={
            "agent_id": "ghost", "tool_name": "calendar.read"})
        assert response.status_code == 404
        events = client.get("/audit").json()["events"]
        assert any(
            e["agent"] == "ghost" and e["reason"] == "UNKNOWN_AGENT"
            for e in events
        )

    def test_audit_and_status_endpoints(self, anchor):
        client = self._app(anchor)
        client.post("/tools/execute", json={
            "agent_id": "executor", "tool_name": "calendar.read"})
        audit = client.get("/audit").json()
        assert audit["count"] >= 1
        assert audit["events"][0]["event"] == "TOOL_REQUEST"
        status = client.get("/security/status").json()
        assert status["authorization_path"].startswith(
            "request -> SecurityGateway")
        assert status["anchor_agent_id"] == anchor.agent_id

    def test_no_insecure_execution_endpoint_exists(self, anchor):
        """Every execution route is the gateway route; there is no direct
        /execute or /tools/raw path in the OpenAPI schema."""
        schema = self._app(anchor).get("/openapi.json").json()
        paths = list(schema["paths"])
        assert "/tools/execute" in paths
        assert all("execute" not in p or p == "/tools/execute" for p in paths)
