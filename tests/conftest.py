"""Shared fixtures for AgentPassport tests.

Everything runs against fresh, in-memory keys generated per test session.
No private key material is ever written to disk.
"""

from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from app.core.delegation import (
    Delegation,
    DelegationBuilder,
    InMemoryRevocationRegistry,
)
from app.core.errors import DenyReason
from app.core.identity import AgentIdentity
from app.core.policy import TrustAnchor
from app.core.verifier import VerificationOutcome, verify_chain


@pytest.fixture()
def human() -> AgentIdentity:
    return AgentIdentity.generate("human:root")


@pytest.fixture()
def anchor(human: AgentIdentity) -> TrustAnchor:
    return TrustAnchor(human)


@pytest.fixture()
def agent_a() -> AgentIdentity:
    return AgentIdentity.generate("agent:A")


@pytest.fixture()
def agent_b() -> AgentIdentity:
    return AgentIdentity.generate("agent:B")


@pytest.fixture()
def agent_c() -> AgentIdentity:
    return AgentIdentity.generate("agent:C")


@pytest.fixture()
def attacker() -> AgentIdentity:
    return AgentIdentity.generate("agent:attacker")


@pytest.fixture()
def builder(anchor: TrustAnchor) -> DelegationBuilder:
    return DelegationBuilder(anchor)


@pytest.fixture()
def revocation_registry() -> InMemoryRevocationRegistry:
    return InMemoryRevocationRegistry()


@pytest.fixture(autouse=True)
def db_cleanup():
    """Ensure database is clean before each test to prevent cross-test contamination."""
    from app.db.database import SessionLocal, engine
    from app.db.models import Base, AgentRecord, DelegationRecord, RevocationRecord, AuditRecord
    
    # Create tables if they don't exist
    Base.metadata.create_all(bind=engine)
    
    with SessionLocal() as session:
        session.query(AuditRecord).delete()
        session.query(RevocationRecord).delete()
        session.query(DelegationRecord).delete()
        session.query(AgentRecord).delete()
        session.commit()

class ChainBuilder:
    """Helper for constructing valid chains quickly in tests."""

    def __init__(self, anchor: TrustAnchor, builder: DelegationBuilder) -> None:
        self.anchor = anchor
        self.builder = builder

    def root(
        self,
        subject: AgentIdentity,
        scopes: list[str],
        *,
        issued_at: datetime | None = None,
        ttl: timedelta = timedelta(minutes=30),
        delegation_id: str | None = None,
    ) -> Delegation:
        return self.builder.issue_root(
            subject, scopes, issued_at=issued_at, ttl=ttl, delegation_id=delegation_id
        )

    def child(
        self,
        issuer: AgentIdentity,
        subject: AgentIdentity,
        scopes: list[str],
        parent: Delegation,
        *,
        issued_at: datetime | None = None,
        ttl: timedelta = timedelta(minutes=30),
        delegation_id: str | None = None,
    ) -> Delegation:
        return self.builder.issue_child(
            issuer, subject, scopes, parent,
            issued_at=issued_at, ttl=ttl, delegation_id=delegation_id,
        )


@pytest.fixture()
def chains(anchor: TrustAnchor, builder: DelegationBuilder) -> ChainBuilder:
    return ChainBuilder(anchor, builder)


def expect_deny(outcome: VerificationOutcome, reason: DenyReason) -> None:
    assert outcome.decision == "DENY", f"expected DENY, got {outcome}"
    assert outcome.reason == reason.value, (
        f"expected {reason.value}, got {outcome.reason} ({outcome.detail})"
    )

@pytest.fixture(autouse=True)
def dev_auth_mode(monkeypatch):
    from app.core.config import settings
    monkeypatch.setattr(settings, "auth_mode", "dev")
