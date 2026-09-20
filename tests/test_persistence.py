import pytest
from app.db.database import SessionLocal, engine
from app.db.models import Base, AgentRecord, DelegationRecord, RevocationRecord, AuditRecord
from app.repositories import AgentRepository, DbAuditStore, DbRevocationRegistry
from app.core.identity import AgentIdentity
from app.audit import tool_request_event
from datetime import datetime, UTC

@pytest.fixture(autouse=True)
def setup_db():
    Base.metadata.create_all(bind=engine)
    yield
    # Clean up after tests
    with SessionLocal() as session:
        session.query(AuditRecord).delete()
        session.query(RevocationRecord).delete()
        session.query(DelegationRecord).delete()
        session.query(AgentRecord).delete()
        session.commit()

def test_agent_persistence():
    identity = AgentIdentity.generate("test-agent")
    repo = AgentRepository()
    repo.save(identity)
    
    with SessionLocal() as session:
        record = session.query(AgentRecord).filter_by(id="test-agent").first()
        assert record is not None
        assert record.public_key == identity.public_identity.public_key_hex
        assert record.status == "ACTIVE"

def test_audit_persistence():
    store = DbAuditStore()
    event = tool_request_event(
        agent="test-agent",
        tool="test.tool",
        requested_scope="test.scope",
        decision="ALLOW",
        reason="OK",
        executed=True,
    )
    store.record(event)
    
    events = store.all_events()
    assert len(events) == 1
    assert events[0].agent == "test-agent"
    assert events[0].tool == "test.tool"
    assert events[0].decision == "ALLOW"

def test_revocation_persistence():
    registry = DbRevocationRegistry()
    registry.revoke("test-delegation-id", reason="compromised")
    
    assert registry.is_revoked("test-delegation-id")
    
    with SessionLocal() as session:
        record = session.query(RevocationRecord).filter_by(delegation_id="test-delegation-id").first()
        assert record is not None
        assert record.reason == "compromised"
