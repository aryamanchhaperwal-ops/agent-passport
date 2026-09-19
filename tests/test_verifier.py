"""Verifier success-path tests: valid chains authorize scoped actions."""

from __future__ import annotations

from app.core.verifier import verify_chain


class TestValidChains:
    def test_valid_root_delegation_allows(self, anchor, chains, agent_a):
        root = chains.root(agent_a, ["calendar.read", "calendar.write"])
        outcome = verify_chain(
            anchor, [root], "calendar.read", agent_a.agent_id
        )
        assert outcome.decision == "ALLOW"
        assert outcome.reason == "AUTHORIZED"
        assert outcome.agent == agent_a.agent_id
        assert set(outcome.effective_scopes) == {"calendar.read", "calendar.write"}

    def test_valid_two_hop_allows(self, anchor, chains, agent_a, agent_b):
        root = chains.root(agent_a, ["calendar.read", "calendar.write"])
        child = chains.child(agent_a, agent_b, ["calendar.read"], root)
        outcome = verify_chain(anchor, [root, child], "calendar.read", agent_b.agent_id)
        assert outcome.decision == "ALLOW"
        assert set(outcome.effective_scopes) == {"calendar.read"}

    def test_valid_three_hop_chain_allows(self, anchor, chains, agent_a, agent_b, agent_c):
        """The canonical Human -> A -> B -> C scenario."""
        root = chains.root(agent_a, ["calendar.read", "calendar.write"])
        ab = chains.child(agent_a, agent_b, ["calendar.read"], root)
        bc = chains.child(agent_b, agent_c, ["calendar.read"], ab)
        outcome = verify_chain(
            anchor, [root, ab, bc], "calendar.read", agent_c.agent_id
        )
        assert outcome.decision == "ALLOW"
        assert outcome.agent == agent_c.agent_id
        assert outcome.effective_scopes == ["calendar.read"]

    def test_child_ttl_clamped_to_parent_window(self, anchor, chains, agent_a, agent_b):
        """Issuance clamps a child's requested ttl to the parent's remaining
        validity (validity inheritance); the resulting chain is valid."""
        from datetime import timedelta

        root = chains.root(agent_a, ["calendar.read"], ttl=timedelta(minutes=10))
        child = chains.child(agent_a, agent_b, ["calendar.read"], root, ttl=timedelta(minutes=30))
        assert child.expires_at <= root.expires_at
        outcome = verify_chain(anchor, [root, child], "calendar.read", agent_b.agent_id)
        assert outcome.decision == "ALLOW"

    def test_allow_structure_has_effective_scopes(self, anchor, chains, agent_a):
        root = chains.root(agent_a, ["calendar.read"])
        outcome = verify_chain(anchor, [root], "calendar.read", agent_a.agent_id)
        assert isinstance(outcome.effective_scopes, list)
        assert outcome.detail is None
