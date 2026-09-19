"""Success-path tests for delegation issuance and single-hop validity."""

from __future__ import annotations

import json

from app.core.delegation import verify_delegation_signature
from app.core.models import Delegation, canonicalize


class TestCanonicalization:
    def test_canonical_bytes_are_deterministic(self, chains, agent_a):
        cred = chains.root(agent_a, ["calendar.read", "email.read"])
        rebuilt = Delegation.model_validate_json(cred.model_dump_json())
        assert canonicalize(rebuilt) == canonicalize(cred)

    def test_key_order_does_not_change_signature(self, chains, agent_a):
        cred = chains.root(agent_a, ["calendar.read"])
        # Round-trip through a dict with reversed key order.
        data = json.loads(cred.model_dump_json())
        reordered = Delegation.model_validate(dict(reversed(list(data.items()))))
        assert verify_delegation_signature(reordered) is True

    def test_signature_covers_scopes(self, chains, agent_a):
        from app.core.models import Scope

        cred = chains.root(agent_a, ["calendar.read"])
        tampered = cred.model_copy(update={"scopes": [Scope.parse("payments.transfer")]})
        assert verify_delegation_signature(tampered) is False

    def test_signature_covers_expiration(self, chains, agent_a):
        from datetime import UTC, datetime, timedelta

        cred = chains.root(agent_a, ["calendar.read"])
        tampered = cred.model_copy(
            update={"expires_at": datetime.now(UTC) + timedelta(days=10)}
        )
        assert verify_delegation_signature(tampered) is False

    def test_signature_covers_delegation_id(self, chains, agent_a):
        cred = chains.root(agent_a, ["calendar.read"])
        tampered = cred.model_copy(update={"delegation_id": "dlg_tampered_id_123"})
        assert verify_delegation_signature(tampered) is False

    def test_signature_covers_signature_field_itself(self, chains, agent_a):
        # Swapping in an arbitrary signature string must not validate — the
        # signature is over the unsigned canonical form, so any substitution
        # (including a valid signature from a DIFFERENT credential) fails.
        cred_a = chains.root(agent_a, ["calendar.read"])
        cred_b = chains.root(agent_a, ["email.read"])
        swapped = cred_a.model_copy(update={"signature": cred_b.signature})
        assert verify_delegation_signature(swapped) is False


class TestSingleHop:
    def test_root_signature_verifies(self, chains, agent_a):
        cred = chains.root(agent_a, ["calendar.read"])
        assert verify_delegation_signature(cred) is True

    def test_unknown_fields_rejected(self, chains, agent_a):
        import pytest

        from pydantic import ValidationError

        cred = chains.root(agent_a, ["calendar.read"])
        data = json.loads(cred.model_dump_json())
        data["injected_field"] = "evil"
        with pytest.raises(ValidationError):
            Delegation.model_validate(data)

    def test_naive_timestamps_rejected(self):
        import pytest

        from datetime import UTC, datetime, timedelta

        from pydantic import ValidationError

        from app.core.models import AgentRef, Delegation

        ref = AgentRef(agent_id="x", public_key_hex="ab" * 32)
        with pytest.raises(ValidationError):
            Delegation(
                delegation_id="dlg_test_naive_timestamp",
                issuer=ref,
                subject=ref,
                scopes=[{"namespace": "calendar", "action": "read"}],
                issued_at=datetime.now().replace(tzinfo=None),
                expires_at=datetime.now(UTC) + timedelta(hours=1),
            )

    def test_invalid_scope_format_rejected(self):
        import pytest

        from app.core.models import Scope

        with pytest.raises(ValueError):
            Scope.parse("calendar.read.write")

    def test_scope_deduplication_and_sorting(self):
        from app.core.models import Scope

        s1 = Scope.parse("email.read")
        s2 = Scope.parse("calendar.read")
        s3 = Scope.parse("calendar.read")
        merged = {s1, s2, s3}
        assert len(merged) == 2
        assert sorted((s.namespace, s.action) for s in merged) == [
            ("calendar", "read"),
            ("email", "read"),
        ]
