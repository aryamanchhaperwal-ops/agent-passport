"""Attack/failure-case tests — the adversarial heart of the suite.

Every test here models a concrete threat from the README threat model:
compromised intermediary, malicious child, forged credential, tampering,
expired/revoked authority, broken chains, and malformed input.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from app.core.delegation import new_delegation_id, sign_delegation
from app.core.errors import DenyReason
from app.core.identity import AgentIdentity
from app.core.models import Delegation, Scope
from app.core.verifier import verify_chain

from .conftest import expect_deny


def _in_future(seconds: int = 0, **kwargs) -> datetime:
    return datetime.now(UTC) + timedelta(seconds=seconds, **kwargs)


class TestSignatureAttacks:
    def test_modified_signature_fails(self, anchor, chains, agent_a, agent_b):
        root = chains.root(agent_a, ["calendar.read"])
        child = chains.child(agent_a, agent_b, ["calendar.read"], root)
        tampered = child.model_copy(update={"signature": "00" * 64})
        outcome = verify_chain(anchor, [root, tampered], "calendar.read", agent_b.agent_id)
        expect_deny(outcome, DenyReason.INVALID_SIGNATURE)

    def test_forged_signature_wrong_key(self, anchor, chains, agent_a, attacker):
        """Attacker signs a credential pretending to be issued by A."""
        root = chains.root(agent_a, ["calendar.read"])
        forged = root.model_copy(
            update={
                "subject": attacker.public_identity,
                "signature": attacker.sign(
                    root.model_copy(update={"signature": None}).canonical_bytes()
                ),
            }
        )
        outcome = verify_chain(anchor, [forged], "calendar.read", attacker.agent_id)
        expect_deny(outcome, DenyReason.INVALID_SIGNATURE)

    def test_self_signed_root_rejected(self, anchor, chains, attacker):
        """Attacker mints their own root — must fail against the anchor key."""
        from app.core.delegation import DelegationBuilder
        from app.core.policy import TrustAnchor

        fake_anchor = TrustAnchor(attacker)
        builder = DelegationBuilder(fake_anchor)
        cred = builder.issue_root(attacker, ["payments.transfer"])
        outcome = verify_chain(anchor, [cred], "payments.transfer", attacker.agent_id)
        expect_deny(outcome, DenyReason.INVALID_CHAIN)

    def test_signature_from_unrelated_valid_credential(
        self, anchor, chains, agent_a, agent_b
    ):
        """Reusing a valid signature from another credential must fail."""
        cred1 = chains.root(agent_a, ["calendar.read"])
        cred2 = chains.root(agent_a, ["email.read"])
        swapped = cred2.model_copy(update={"signature": cred1.signature})
        outcome = verify_chain(anchor, [swapped], "email.read", agent_a.agent_id)
        expect_deny(outcome, DenyReason.INVALID_SIGNATURE)


class TestTimeAttacks:
    def test_expired_delegation_denied(self, anchor, chains, agent_a):
        past = datetime.now(UTC) - timedelta(hours=2)
        cred = chains.root(
            agent_a, ["calendar.read"], issued_at=past, ttl=timedelta(minutes=30)
        )
        outcome = verify_chain(anchor, [cred], "calendar.read", agent_a.agent_id)
        expect_deny(outcome, DenyReason.EXPIRED_DELEGATION)

    def test_expired_parent_taints_child(self, anchor, chains, agent_a, agent_b):
        past = datetime.now(UTC) - timedelta(hours=2)
        root = chains.root(
            agent_a, ["calendar.read"], issued_at=past, ttl=timedelta(minutes=30)
        )
        # Child was issued while the parent was still valid, so its own
        # expiry was clamped to the parent's; both are now expired and the
        # parent's expiry is what taints the chain.
        child = chains.child(
            agent_a, agent_b, ["calendar.read"], root, issued_at=past
        )
        outcome = verify_chain(anchor, [root, child], "calendar.read", agent_b.agent_id)
        expect_deny(outcome, DenyReason.EXPIRED_DELEGATION)

    def test_future_issued_beyond_clock_skew_denied(
        self, anchor, chains, agent_a
    ):
        future = datetime.now(UTC) + timedelta(minutes=30)
        cred = chains.root(agent_a, ["calendar.read"], issued_at=future)
        outcome = verify_chain(anchor, [cred], "calendar.read", agent_a.agent_id)
        expect_deny(outcome, DenyReason.NOT_YET_VALID)

    def test_future_issued_within_clock_skew_allowed(
        self, anchor, chains, agent_a
    ):
        future = datetime.now(UTC) + timedelta(minutes=2)  # within 5 min default
        cred = chains.root(agent_a, ["calendar.read"], issued_at=future)
        outcome = verify_chain(anchor, [cred], "calendar.read", agent_a.agent_id)
        assert outcome.decision == "ALLOW"

    def test_clock_skew_is_configurable(self, anchor, chains, agent_a):
        future = datetime.now(UTC) + timedelta(minutes=2)
        cred = chains.root(agent_a, ["calendar.read"], issued_at=future)
        strict = verify_chain(
            anchor, [cred], "calendar.read", agent_a.agent_id,
            max_clock_skew=timedelta(0),
        )
        expect_deny(strict, DenyReason.NOT_YET_VALID)

    def test_expires_before_issued_rejected(self, anchor, chains, agent_a, human):
        """A *validly signed* credential over an impossible window (expires
        before issued) is still rejected by time validation: its inverted
        window manifests as an already-expired credential."""
        issued = datetime.now(UTC)
        expires = issued - timedelta(minutes=1)
        cred = chains.root(
            agent_a, ["calendar.read"], issued_at=issued, ttl=timedelta(minutes=30)
        )
        tampered = sign_delegation(
            cred.model_copy(update={"expires_at": expires}), human
        )
        outcome = verify_chain(anchor, [tampered], "calendar.read", agent_a.agent_id)
        expect_deny(outcome, DenyReason.EXPIRED_DELEGATION)


class TestChainIntegrityAttacks:
    def test_broken_parent_reference(self, anchor, chains, agent_a, agent_b, agent_c):
        root = chains.root(agent_a, ["calendar.read"])
        ab = chains.child(agent_a, agent_b, ["calendar.read"], root)
        orphaned = chains.child(
            agent_b, agent_c, ["calendar.read"], ab, delegation_id="dlg_orphan_12345678"
        )
        unlinked = orphaned.model_copy(update={"parent_delegation_id": "dlg_missing_0000000"})
        outcome = verify_chain(
            anchor, [root, ab, unlinked], "calendar.read", agent_c.agent_id
        )
        expect_deny(outcome, DenyReason.PARENT_NOT_FOUND)
    def test_wrong_issuer(self, anchor, chains, agent_a, agent_b, agent_c):
        root = chains.root(agent_a, ["calendar.read"])
        ab = chains.child(agent_a, agent_b, ["calendar.read"], root)
        # C issues a credential pretending B delegated to C — C is not the
        # subject of the parent credential it claims to extend.
        forged = chains.child(agent_c, agent_c, ["calendar.read"], ab)
        outcome = verify_chain(anchor, [root, ab, forged], "calendar.read", agent_c.agent_id)
        expect_deny(outcome, DenyReason.SUBJECT_MISMATCH)

    def test_wrong_subject_relayed(self, anchor, chains, agent_a, agent_b, attacker):
        root = chains.root(agent_a, ["calendar.read"])
        ab = chains.child(agent_a, agent_b, ["calendar.read"], root)
        retargeted = ab.model_copy(update={"subject": attacker.public_identity})
        outcome = verify_chain(anchor, [root, retargeted], "calendar.read", attacker.agent_id)
        expect_deny(outcome, DenyReason.INVALID_SIGNATURE)

    def test_chain_started_midway_rejected(
        self, anchor, chains, agent_a, agent_b
    ):
        """Presenting only a child credential without its parent."""
        root = chains.root(agent_a, ["calendar.read"])
        ab = chains.child(agent_a, agent_b, ["calendar.read"], root)
        outcome = verify_chain(anchor, [ab], "calendar.read", agent_b.agent_id)
        expect_deny(outcome, DenyReason.INVALID_CHAIN)

    def test_chain_with_no_root_parent(self, anchor, chains, agent_a, agent_b):
        """A child credential re-presented as a root must fail — its own
        signature is valid but it is not signed by the anchor."""
        root = chains.root(agent_a, ["calendar.read"])
        child = chains.child(agent_a, agent_b, ["calendar.read"], root)
        bad_root = child.model_copy(update={"parent_delegation_id": None})
        outcome = verify_chain(anchor, [bad_root], "calendar.read", agent_b.agent_id)
        expect_deny(outcome, DenyReason.INVALID_CHAIN)
    def test_valid_child_signature_but_invalid_parent_chain(
        self, anchor, chains, agent_a, agent_b, agent_c
    ):
        """The key property: a fully valid child is worthless if any ancestor
        is broken. Here the parent chain's signature fails; the child's own
        signature is genuinely valid."""
        root = chains.root(agent_a, ["calendar.read"])
        ab = chains.child(agent_a, agent_b, ["calendar.read"], root)
        bc = chains.child(agent_b, agent_c, ["calendar.read"], ab)
        tampered_root = root.model_copy(
            update={"scopes": [Scope.parse("calendar.read"), Scope.parse("email.send")]}
        )
        outcome = verify_chain(
            anchor, [tampered_root, ab, bc], "calendar.read", agent_c.agent_id
        )
        expect_deny(outcome, DenyReason.INVALID_SIGNATURE)

    def test_swapped_hop_order_rejected(self, anchor, chains, agent_a, agent_b):
        root = chains.root(agent_a, ["calendar.read"])
        ab = chains.child(agent_a, agent_b, ["calendar.read"], root)
        outcome = verify_chain(anchor, [ab, root], "calendar.read", agent_b.agent_id)
        expect_deny(outcome, DenyReason.INVALID_CHAIN)

    def test_depth_limit_enforced(self, anchor, chains):
        """Build a 12-hop chain; the verifier must refuse it outright."""
        identities = [AgentIdentity.generate(f"chain:{i}") for i in range(13)]
        credentials = [chains.root(identities[0], ["calendar.read"])]
        for issuer, subject in zip(identities, identities[1:]):
            credentials.append(
                chains.child(issuer, subject, ["calendar.read"], credentials[-1])
            )
        leaf = identities[-1]
        outcome = verify_chain(
            anchor, credentials, "calendar.read", leaf.agent_id
        )
        expect_deny(outcome, DenyReason.DELEGATION_DEPTH_EXCEEDED)


class TestRevocation:
    def test_revoked_root_delegation_denied(
        self, anchor, chains, agent_a, revocation_registry
    ):
        root = chains.root(agent_a, ["calendar.read"])
        revocation_registry.revoke(root.delegation_id)
        outcome = verify_chain(
            anchor, [root], "calendar.read", agent_a.agent_id,
            revocation_registry=revocation_registry,
        )
        expect_deny(outcome, DenyReason.REVOKED_DELEGATION)

    def test_revoked_midchain_credential_taints_descendants(
        self, anchor, chains, agent_a, agent_b, agent_c, revocation_registry
    ):
        root = chains.root(agent_a, ["calendar.read"])
        ab = chains.child(agent_a, agent_b, ["calendar.read"], root)
        bc = chains.child(agent_b, agent_c, ["calendar.read"], ab)
        revocation_registry.revoke(ab.delegation_id)
        outcome = verify_chain(
            anchor, [root, ab, bc], "calendar.read", agent_c.agent_id,
            revocation_registry=revocation_registry,
        )
        expect_deny(outcome, DenyReason.REVOKED_DELEGATION)

    def test_unrevoked_chain_still_allows(
        self, anchor, chains, agent_a, revocation_registry
    ):
        root = chains.root(agent_a, ["calendar.read"])
        revocation_registry.revoke("dlg_not_a_real_id_0001")
        outcome = verify_chain(
            anchor, [root], "calendar.read", agent_a.agent_id,
            revocation_registry=revocation_registry,
        )
        assert outcome.decision == "ALLOW"


class TestTampering:
    def test_tampered_scope(self, anchor, chains, agent_a):
        root = chains.root(agent_a, ["calendar.read"])
        tampered = root.model_copy(update={"scopes": [Scope.parse("payments.transfer")]})
        outcome = verify_chain(
            anchor, [tampered], "payments.transfer", agent_a.agent_id
        )
        expect_deny(outcome, DenyReason.INVALID_SIGNATURE)

    def test_tampered_expiration(self, anchor, chains, agent_a):
        root = chains.root(agent_a, ["calendar.read"], ttl=timedelta(minutes=1))
        extended = root.model_copy(
            update={"expires_at": datetime.now(UTC) + timedelta(days=365)}
        )
        outcome = verify_chain(anchor, [extended], "calendar.read", agent_a.agent_id)
        expect_deny(outcome, DenyReason.INVALID_SIGNATURE)

    def test_tampered_delegation_id(self, anchor, chains, agent_a):
        root = chains.root(agent_a, ["calendar.read"])
        tampered = root.model_copy(update={"delegation_id": "dlg_replaced_id_9999"})
        outcome = verify_chain(anchor, [tampered], "calendar.read", agent_a.agent_id)
        expect_deny(outcome, DenyReason.INVALID_SIGNATURE)

    def test_tampered_field_makes_parent_reference_fail(
        self, anchor, chains, agent_a, agent_b
    ):
        """Changing a parent's id breaks the child's parent pointer too;
        the parent's tampered signature is detected first."""
        root = chains.root(agent_a, ["calendar.read"])
        ab = chains.child(agent_a, agent_b, ["calendar.read"], root)
        retagged_root = root.model_copy(update={"delegation_id": "dlg_retagged_000001"})
        outcome = verify_chain(anchor, [retagged_root, ab], "calendar.read", agent_b.agent_id)
        # The verifier validates parent links before signatures, so the
        # dangling child reference is reported precisely.
        expect_deny(outcome, DenyReason.PARENT_NOT_FOUND)

class TestMalformedCredentials:
    def test_empty_chain(self, anchor):
        outcome = verify_chain(anchor, [], "calendar.read", "agent:A")
        expect_deny(outcome, DenyReason.INVALID_REQUEST)

    def test_wrong_type_chain(self, anchor):
        outcome = verify_chain(anchor, "not-a-list", "calendar.read", "agent:A")
        expect_deny(outcome, DenyReason.INVALID_REQUEST)

    def test_credential_from_dict_with_bad_types(self, anchor):
        outcome = verify_chain(
            anchor,
            [{"delegation_id": 123, "issuer": "not-a-ref"}],
            "calendar.read",
            "agent:A",
        )
        expect_deny(outcome, DenyReason.MALFORMED_CREDENTIAL)

    def test_credential_missing_required_field(self, anchor):
        outcome = verify_chain(
            anchor,
            [{"delegation_id": "dlg_short", "issuer": {}}],
            "calendar.read",
            "agent:A",
        )
        expect_deny(outcome, DenyReason.MALFORMED_CREDENTIAL)

    def test_unparseable_requested_scope(self, anchor, chains, agent_a):
        root = chains.root(agent_a, ["calendar.read"])
        outcome = verify_chain(anchor, [root], "calendar.read.write", agent_a.agent_id)
        expect_deny(outcome, DenyReason.INVALID_REQUEST)

    def test_requester_not_leaf_subject(self, anchor, chains, agent_a, agent_b):
        """A holds the credential but B tries to act on it."""
        root = chains.root(agent_a, ["calendar.read"])
        outcome = verify_chain(anchor, [root], "calendar.read", agent_b.agent_id)
        expect_deny(outcome, DenyReason.SUBJECT_MISMATCH)

    def test_unauthorized_scope_on_valid_chain(self, anchor, chains, agent_a):
        """Valid chain, but the requested scope is simply not granted."""
        root = chains.root(agent_a, ["calendar.read"])
        outcome = verify_chain(anchor, [root], "payments.transfer", agent_a.agent_id)
        expect_deny(outcome, DenyReason.UNAUTHORIZED_SCOPE)


class TestReplayProtection:
    def test_modified_id_is_a_different_broken_credential(
        self, anchor, chains, agent_a
    ):
        """The same credential with a modified ID is rejected outright —
        it is not accepted as 'a different valid credential'."""
        root = chains.root(agent_a, ["calendar.read"])
        mutated = root.model_copy(update={"delegation_id": new_delegation_id()})
        outcome = verify_chain(anchor, [mutated], "calendar.read", agent_a.agent_id)
        expect_deny(outcome, DenyReason.INVALID_SIGNATURE)

    def test_exact_replay_is_bound_to_same_authority(self, anchor, chains, agent_a):
        """Re-presenting the identical credential confers no new authority:
        it authorizes exactly what the original did — nothing more."""
        root = chains.root(agent_a, ["calendar.read"])
        first = verify_chain(anchor, [root], "calendar.read", agent_a.agent_id)
        second = verify_chain(anchor, [root], "calendar.read", agent_a.agent_id)
        assert first.decision == second.decision == "ALLOW"
        assert first.effective_scopes == second.effective_scopes
        escalated = verify_chain(anchor, [root], "payments.transfer", agent_a.agent_id)
        expect_deny(escalated, DenyReason.UNAUTHORIZED_SCOPE)
