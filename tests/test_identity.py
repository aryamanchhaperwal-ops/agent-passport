"""Success-path tests: identity, issuance, and valid delegation chains."""

from __future__ import annotations

from datetime import timedelta

from app.core.delegation import (
    new_delegation_id,
    sign_delegation,
    verify_delegation_signature,
)
from app.core.identity import AgentIdentity, verify_signature_with_public_key
from app.core.models import Scope


class TestIdentity:
    def test_generate_identity(self, human):
        assert human.agent_id == "human:root"
        assert len(human.public_identity.public_key_hex) == 64

    def test_sign_and_verify_roundtrip(self, human):
        data = b"canonical-bytes"
        sig = human.sign(data)
        assert human.verify(data, sig) is True

    def test_verify_rejects_wrong_data(self, human):
        sig = human.sign(b"original")
        assert human.verify(b"modified", sig) is False

    def test_deterministic_signatures(self, human):
        data = b"same-input"
        assert human.sign(data) == human.sign(data)

    def test_public_serialization_has_no_private_material(self, human):
        exported = human.export_public()
        assert set(exported.keys()) == {"agent_id", "public_key_hex"}
        priv = human.export_private_key_hex()
        assert priv not in str(exported)

    def test_reproducible_from_private_key(self, human):
        restored = AgentIdentity.from_private_key_hex(
            human.agent_id, human.export_private_key_hex()
        )
        data = b"roundtrip"
        assert restored.verify(data, human.sign(data)) is True

    def test_standalone_public_verify(self, human):
        data = b"payload"
        sig = human.sign(data)
        assert (
            verify_signature_with_public_key(
                human.public_identity.public_key_hex, data, sig
            )
            is True
        )
        assert (
            verify_signature_with_public_key(
                human.public_identity.public_key_hex, b"tampered", sig
            )
            is False
        )

    def test_public_key_length_enforced(self):
        assert verify_signature_with_public_key("abcd", b"x", "00" * 64) is False


class TestIssuance:
    def test_root_delegation_signed_by_anchor(self, chains, agent_a):
        cred = chains.root(agent_a, ["calendar.read", "calendar.write"])
        assert verify_delegation_signature(cred) is True
        assert cred.parent_delegation_id is None

    def test_child_delegation_signed_by_issuer(self, chains, agent_a, agent_b):
        root = chains.root(agent_a, ["calendar.read"])
        child = chains.child(agent_a, agent_b, ["calendar.read"], root)
        assert verify_delegation_signature(child) is True
        assert child.parent_delegation_id == root.delegation_id

    def test_delegation_ids_are_unique(self):
        ids = {new_delegation_id() for _ in range(100)}
        assert len(ids) == 100
        for i in ids:
            assert i.startswith("dlg_")

    def test_resigning_replaces_signature(self, chains, agent_a, human):
        cred = chains.root(agent_a, ["calendar.read"])
        tampered = cred.model_copy(update={"scopes": [Scope.parse("email.send")]})
        resigned = sign_delegation(tampered, human)
        assert verify_delegation_signature(resigned) is True

    def test_negative_ttl_rejected(self, chains, agent_a):
        import pytest

        from app.core.errors import VerificationError

        with pytest.raises(VerificationError):
            chains.root(agent_a, ["calendar.read"], ttl=timedelta(0))
