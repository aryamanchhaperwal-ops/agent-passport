"""Validity-inheritance tests: a child can never outlive its parent.

Invariants under test:
  - At issuance, the builder clamps child.expires_at to the parent's
    remaining validity (child.expires_at <= parent.expires_at).
  - At verification, effective expiry is monotonically non-increasing from
    root to leaf, so authorization is bounded by EVERY ancestor's window —
    including hand-crafted credentials that bypass the builder's clamp.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from app.core.delegation import sign_delegation
from app.core.errors import DenyReason, VerificationError
from app.core.verifier import verify_chain

from .conftest import expect_deny


class TestIssuanceClamping:
    def test_child_expiring_before_parent_allows(
        self, anchor, chains, agent_a, agent_b
    ):
        """Requirement 1: child expires strictly before parent -> ALLOW."""
        root = chains.root(agent_a, ["calendar.read"], ttl=timedelta(hours=1))
        child = chains.child(
            agent_a, agent_b, ["calendar.read"], root, ttl=timedelta(minutes=10)
        )
        assert child.expires_at < root.expires_at
        outcome = verify_chain(anchor, [root, child], "calendar.read", agent_b.agent_id)
        assert outcome.decision == "ALLOW"

    def test_builder_clamps_overlong_requested_ttl(
        self, anchor, chains, agent_a, agent_b
    ):
        """A requested ttl longer than the parent's remaining validity is
        clamped at issuance, never silently granted."""
        root = chains.root(agent_a, ["calendar.read"], ttl=timedelta(minutes=30))
        child = chains.child(
            agent_a, agent_b, ["calendar.read"], root, ttl=timedelta(hours=5)
        )
        assert child.expires_at == root.expires_at
        outcome = verify_chain(anchor, [root, child], "calendar.read", agent_b.agent_id)
        assert outcome.decision == "ALLOW"

    def test_child_expiring_equal_to_parent_allows(
        self, anchor, chains, agent_a, agent_b
    ):
        """Requirement 2: child expires exactly at parent expiry -> ALLOW."""
        root = chains.root(agent_a, ["calendar.read"], ttl=timedelta(minutes=30))
        child = chains.child(
            agent_a, agent_b, ["calendar.read"], root, ttl=timedelta(minutes=30)
        )
        assert child.expires_at == root.expires_at
        outcome = verify_chain(anchor, [root, child], "calendar.read", agent_b.agent_id)
        assert outcome.decision == "ALLOW"

    def test_clamp_propagates_down_three_hops(
        self, anchor, chains, agent_a, agent_b, agent_c
    ):
        root = chains.root(agent_a, ["calendar.read"], ttl=timedelta(minutes=30))
        ab = chains.child(agent_a, agent_b, ["calendar.read"], root, ttl=timedelta(hours=2))
        bc = chains.child(agent_b, agent_c, ["calendar.read"], ab, ttl=timedelta(hours=2))
        assert ab.expires_at == root.expires_at
        assert bc.expires_at == root.expires_at
        outcome = verify_chain(anchor, [root, ab, bc], "calendar.read", agent_c.agent_id)
        assert outcome.decision == "ALLOW"

    def test_expired_parent_cannot_be_extended(self, anchor, chains, agent_a, agent_b):
        """Issuance refuses to extend an already-expired parent."""
        past = datetime.now(UTC) - timedelta(hours=2)
        root = chains.root(
            agent_a, ["calendar.read"], issued_at=past, ttl=timedelta(minutes=30)
        )
        with pytest.raises(VerificationError):
            chains.child(agent_a, agent_b, ["calendar.read"], root)


class TestVerificationEnforcement:
    def _handcrafted_overlong_child(self, chains, agent_a, agent_b):
        """A malicious (or compromised) issuer hand-crafts and re-signs a
        child whose expires_at outlives its parent — bypassing the builder's
        clamp. The verifier must still reject it."""
        root = chains.root(agent_a, ["calendar.read"], ttl=timedelta(minutes=30))
        child = chains.child(
            agent_a, agent_b, ["calendar.read"], root, ttl=timedelta(minutes=10)
        )
        extended = sign_delegation(
            child.model_copy(
                update={"expires_at": root.expires_at + timedelta(hours=1)}
            ),
            agent_a,
        )
        return root, extended

    def test_child_expiring_after_parent_denied(
        self, anchor, chains, agent_a, agent_b
    ):
        """Requirement 3: child expiration after parent expiration -> DENY."""
        root, extended = self._handcrafted_overlong_child(chains, agent_a, agent_b)
        assert extended.expires_at > root.expires_at
        outcome = verify_chain(
            anchor, [root, extended], "calendar.read", agent_b.agent_id
        )
        expect_deny(outcome, DenyReason.EXCEEDS_PARENT_VALIDITY)

    def test_overlong_grandchild_denied(
        self, anchor, chains, agent_a, agent_b, agent_c
    ):
        """The monotonicity check applies at every hop, not just the first."""
        root = chains.root(agent_a, ["calendar.read"], ttl=timedelta(minutes=30))
        ab = chains.child(
            agent_a, agent_b, ["calendar.read"], root, ttl=timedelta(minutes=20)
        )
        bc = chains.child(
            agent_b, agent_c, ["calendar.read"], ab, ttl=timedelta(minutes=10)
        )
        tampered = sign_delegation(
            bc.model_copy(
                update={"expires_at": root.expires_at + timedelta(days=1)}
            ),
            agent_b,
        )
        outcome = verify_chain(
            anchor, [root, ab, tampered], "calendar.read", agent_c.agent_id
        )
        expect_deny(outcome, DenyReason.EXCEEDS_PARENT_VALIDITY)

    def test_previously_valid_child_unauthorized_after_ancestor_expires(
        self, anchor, chains, agent_a, agent_b
    ):
        """Requirement 4: a previously valid child cannot remain authorized
        after ANY ancestor expires."""
        root = chains.root(agent_a, ["calendar.read"], ttl=timedelta(minutes=30))
        child = chains.child(
            agent_a, agent_b, ["calendar.read"], root, ttl=timedelta(minutes=30)
        )
        now = datetime.now(UTC)
        before = verify_chain(
            anchor, [root, child], "calendar.read", agent_b.agent_id, now=now
        )
        assert before.decision == "ALLOW"

        after = verify_chain(
            anchor, [root, child], "calendar.read", agent_b.agent_id,
            now=now + timedelta(minutes=31),
        )
        expect_deny(after, DenyReason.EXPIRED_DELEGATION)
        assert root.delegation_id in (after.detail or "")

    def test_intermediate_ancestor_expiry_bounds_leaf(
        self, anchor, chains, agent_a, agent_b, agent_c
    ):
        """Effective expiry is monotonic: when a MIDDLE credential is the
        earliest to expire, the leaf loses authority at that moment even
        though the root is still alive."""
        root = chains.root(agent_a, ["calendar.read"], ttl=timedelta(hours=1))
        ab = chains.child(
            agent_a, agent_b, ["calendar.read"], root, ttl=timedelta(minutes=10)
        )
        bc = chains.child(
            agent_b, agent_c, ["calendar.read"], ab, ttl=timedelta(minutes=5)
        )
        now = datetime.now(UTC)
        mid = now + timedelta(minutes=11)  # ab and bc expired, root alive
        outcome = verify_chain(
            anchor, [root, ab, bc], "calendar.read", agent_c.agent_id, now=mid
        )
        expect_deny(outcome, DenyReason.EXPIRED_DELEGATION)
        assert ab.delegation_id in (outcome.detail or "")

    def test_monotonic_chain_with_decreasing_windows_allows(
        self, anchor, chains, agent_a, agent_b, agent_c
    ):
        """Strictly decreasing windows are the well-formed case."""
        root = chains.root(agent_a, ["calendar.read"], ttl=timedelta(hours=1))
        ab = chains.child(
            agent_a, agent_b, ["calendar.read"], root, ttl=timedelta(minutes=30)
        )
        bc = chains.child(
            agent_b, agent_c, ["calendar.read"], ab, ttl=timedelta(minutes=10)
        )
        assert root.expires_at >= ab.expires_at >= bc.expires_at
        outcome = verify_chain(anchor, [root, ab, bc], "calendar.read", agent_c.agent_id)
        assert outcome.decision == "ALLOW"

    def test_tampering_child_expiry_breaks_signature(
        self, anchor, chains, agent_a, agent_b
    ):
        """Requirement 5: editing expires_at WITHOUT re-signing invalidates
        the signature — the expiry is inside the signed payload."""
        root = chains.root(agent_a, ["calendar.read"], ttl=timedelta(minutes=30))
        child = chains.child(
            agent_a, agent_b, ["calendar.read"], root, ttl=timedelta(minutes=10)
        )
        tampered = child.model_copy(
            update={"expires_at": root.expires_at + timedelta(hours=1)}
        )
        outcome = verify_chain(
            anchor, [root, tampered], "calendar.read", agent_b.agent_id
        )
        expect_deny(outcome, DenyReason.INVALID_SIGNATURE)
