import pytest
from fastapi.testclient import TestClient
from app.main import create_app
from app.core.policy import TrustAnchor
from app.core.identity import AgentIdentity
from app.core.delegation import InMemoryRevocationRegistry
from app.repositories.organization import OrganizationRepository
from app.repositories.user import UserRepository
from app.repositories.agent import AgentRepository, DelegationRepository
from app.core.rbac import Role
from app.db.database import SessionLocal, engine
from app.db.models import Base, AuditRecord, RevocationRecord, DelegationRecord, AgentRecord, UserRecord, OrganizationRecord

@pytest.fixture(scope="module")
def app_client():
    human = AgentIdentity.generate("human:root")
    anchor = TrustAnchor(human)
    app = create_app(anchor, InMemoryRevocationRegistry())
    return TestClient(app)

@pytest.fixture(autouse=True)
def setup_tenants():
    # Setup test DB
    Base.metadata.create_all(bind=engine)
    with SessionLocal() as session:
        session.query(AuditRecord).delete()
        session.query(RevocationRecord).delete()
        session.query(DelegationRecord).delete()
        session.query(AgentRecord).delete()
        session.query(UserRecord).delete()
        session.query(OrganizationRecord).delete()
        session.commit()
        
    org_repo = OrganizationRepository()
    org_a = org_repo.create("org_a", "Org A", "org-a")
    org_b = org_repo.create("org_b", "Org B", "org-b")
    
    user_repo = UserRepository()
    user_repo.create("user_a_owner", "org_a", "owner@a.com", "Owner A", Role.OWNER.value)
    user_repo.create("user_a_viewer", "org_a", "viewer@a.com", "Viewer A", Role.VIEWER.value)
    user_repo.create("user_b_owner", "org_b", "owner@b.com", "Owner B", Role.OWNER.value)

    agent_repo = AgentRepository()
    agent_a = AgentIdentity.generate("agent_a")
    agent_repo.save(agent_a, "org_a")
    
    agent_b = AgentIdentity.generate("agent_b")
    agent_repo.save(agent_b, "org_b")
    
    yield


def test_tenant_isolation_agents(app_client):
    # Org A owner accessing agents
    res = app_client.get("/api/agents", headers={"X-User-Id": "user_a_owner"})
    assert res.status_code == 200
    agents = res.json()
    assert len(agents) == 1
    assert agents[0]["id"] == "agent_a"
    
    # Org B owner accessing agents
    res = app_client.get("/api/agents", headers={"X-User-Id": "user_b_owner"})
    assert res.status_code == 200
    agents = res.json()
    assert len(agents) == 1
    assert agents[0]["id"] == "agent_b"
    
    # Direct get Agent B by Org A user
    res = app_client.get("/api/agents/agent_b", headers={"X-User-Id": "user_a_owner"})
    assert res.status_code == 404

def test_viewer_cannot_manage_delegations(app_client):
    # Viewer A tries to revoke a delegation (requires MANAGE_DELEGATIONS)
    # We will simulate a delegation existing for org_a
    from app.repositories.agent import DelegationRepository
    from app.core.identity import AgentIdentity
    from app.core.delegation import DelegationBuilder
    from app.core.policy import TrustAnchor
    from datetime import timedelta
    
    a = AgentIdentity.generate("a")
    b = AgentIdentity.generate("b")
    root = DelegationBuilder(TrustAnchor(a)).issue_root(b, ["calendar.read"], ttl=timedelta(minutes=5))
    DelegationRepository().save(root, "org_a")
    
    res = app_client.post(f"/api/delegations/{root.delegation_id}/revoke", headers={"X-User-Id": "user_a_viewer"})
    assert res.status_code == 403
    assert res.json()["detail"] == "Insufficient RBAC permissions"

def test_tenant_isolation_revoke(app_client):
    from app.repositories.agent import DelegationRepository
    from app.core.identity import AgentIdentity
    from app.core.delegation import DelegationBuilder
    from app.core.policy import TrustAnchor
    from datetime import timedelta
    
    a = AgentIdentity.generate("a2")
    b = AgentIdentity.generate("b2")
    root = DelegationBuilder(TrustAnchor(a)).issue_root(b, ["calendar.read"], ttl=timedelta(minutes=5))
    DelegationRepository().save(root, "org_b")
    
    # Org A owner tries to revoke Org B delegation
    res = app_client.post(f"/api/delegations/{root.delegation_id}/revoke", headers={"X-User-Id": "user_a_owner"})
    assert res.status_code == 404
    
    # Org B owner tries to revoke Org B delegation
    res = app_client.post(f"/api/delegations/{root.delegation_id}/revoke", headers={"X-User-Id": "user_b_owner"})
    assert res.status_code == 200
