"""Scope-attenuation tests: children may only narrow, never widen."""

from __future__ import annotations

from app.core.errors import DenyReason
from app.core.policy import ScopeSet, check_scope_attenuation
from app.core.verifier import verify_chain

from .conftest import expect_deny


class TestAttenuationUnit:
    def test_subset_attenuation_holds(self):
        parent = ScopeSet.from_strings(["calendar.read", "calendar.write"])
        child = ScopeSet.from_strings(["calendar.read"])
        assert check_scope_attenuation(child, parent) == []

    def test_escalation_detected(self):
        parent = ScopeSet.from_strings(["calendar.read"])
        child = ScopeSet.from_strings(["calendar.read", "email.send"])
        missing = check_scope_attenuation(child, parent)
        assert [str(s) for s in missing] == ["email.send"]

    def test_identical_scopes_hold(self):
        parent = ScopeSet.from_strings(["calendar.read"])
        child = ScopeSet.from_strings(["calendar.read"])
        assert check_scope_attenuation(child, parent) == []


class TestAttenuationInChains:
    def test_valid_narrowing_two_hop(self, anchor, chains, agent_a, agent_b):
        root = chains.root(agent_a, ["calendar.read", "calendar.write"])
        child = chains.child(agent_a, agent_b, ["calendar.read"], root)
        outcome = verify_chain(anchor, [root, child], "calendar.read", agent_b.agent_id)
        assert outcome.decision == "ALLOW"

    def test_child_grants_scope_it_does_not_have(self, anchor, chains, agent_a, agent_b, agent_c):
        """A (holder of calendar.read only) grants B email.send -> DENY."""
        root = chains.root(agent_a, ["calendar.read"])
        # Build the credential manually so the builder doesn't block us:
        # issuance is *capable* of producing bad credentials (the signer may
        # be malicious); the VERIFIER is what stops them.
        child = chains.child(agent_a, agent_b, ["email.send"], root)
        outcome = verify_chain(anchor, [root, child], "email.send", agent_b.agent_id)
        expect_deny(outcome, DenyReason.SCOPE_ESCALATION)

    def test_child_grants_scope_parent_chain_lacks(
        self, anchor, chains, agent_a, agent_b, agent_c
    ):
        """A has payments.transfer but B (its child) tries to grant it on."""
        root = chains.root(agent_a, ["payments.transfer"])
        ab = chains.child(agent_a, agent_b, ["payments.transfer"], root)
        bc = chains.child(agent_b, agent_c, ["payments.read"], ab)
        outcome = verify_chain(
            anchor, [root, ab, bc], "payments.read", agent_c.agent_id
        )
        expect_deny(outcome, DenyReason.SCOPE_ESCALATION)

    def test_equal_scopes_allowed_but_no_widening(
        self, anchor, chains, agent_a, agent_b, agent_c
    ):
        root = chains.root(agent_a, ["calendar.read"])
        ab = chains.child(agent_a, agent_b, ["calendar.read"], root)
        bc = chains.child(agent_b, agent_c, ["calendar.read"], ab)
        outcome = verify_chain(anchor, [root, ab, bc], "calendar.read", agent_c.agent_id)
        assert outcome.decision == "ALLOW"

    def test_three_hop_escalation_detected_at_any_hop(
        self, anchor, chains, agent_a, agent_b, agent_c
    ):
        root = chains.root(agent_a, ["calendar.read", "calendar.write"])
        ab = chains.child(agent_a, agent_b, ["calendar.read"], root)
        bc = chains.child(agent_b, agent_c, ["calendar.write"], ab)  # B lacks calendar.write
        outcome = verify_chain(
            anchor, [root, ab, bc], "calendar.write", agent_c.agent_id
        )
        expect_deny(outcome, DenyReason.SCOPE_ESCALATION)
