import pytest
from fastapi.testclient import TestClient
import jwt
from datetime import datetime, timezone, timedelta
from app.main import create_app
from app.core.policy import TrustAnchor
from app.core.identity import AgentIdentity
from app.core.delegation import InMemoryRevocationRegistry
from app.core.apikey import generate_api_key
from app.repositories.organization import OrganizationRepository
from app.repositories.user import UserRepository
from app.repositories.apikey import ApiKeyRepository
from app.core.rbac import Role
from app.db.database import SessionLocal, engine
from app.db.models import Base, ApiKeyRecord, UserRecord, OrganizationRecord
from app.core.config import settings

@pytest.fixture(scope="module")
def app_client():
    human = AgentIdentity.generate("human:root")
    anchor = TrustAnchor(human)
    app = create_app(anchor, InMemoryRevocationRegistry())
    return TestClient(app)

@pytest.fixture(autouse=True)
def setup_auth_db():
    Base.metadata.create_all(bind=engine)
    with SessionLocal() as session:
        session.query(ApiKeyRecord).delete()
        session.query(UserRecord).delete()
        session.query(OrganizationRecord).delete()
        session.commit()
        
    org_repo = OrganizationRepository()
    org_repo.create("org_auth", "Org Auth", "org-auth")
    
    user_repo = UserRepository()
    user_repo.create("user_auth", "org_auth", "auth@a.com", "Auth User", Role.OWNER.value)
    
    yield

def test_unauthenticated(app_client):
    res = app_client.get("/api/agents")
    assert res.status_code == 401

def test_api_key_auth(app_client):
    # Generate API key
    raw_key, prefix, key_hash = generate_api_key()
    repo = ApiKeyRepository()
    repo.create("key1", "user_auth", "org_auth", "Test Key", key_hash, prefix, ["*"])
    
    res = app_client.get("/api/organization", headers={"Authorization": f"Bearer {raw_key}"})
    assert res.status_code == 200
    assert res.json()["id"] == "org_auth"

def test_api_key_scope_denial(app_client):
    raw_key, prefix, key_hash = generate_api_key()
    repo = ApiKeyRepository()
    repo.create("key2", "user_auth", "org_auth", "Read Only", key_hash, prefix, ["read_only"])
    
    # Can access read-only
    res = app_client.get("/api/agents", headers={"Authorization": f"Bearer {raw_key}"})
    assert res.status_code == 200
    
    # Cannot access manage_delegations (revoke endpoint requires manage_delegations)
    res = app_client.post("/api/delegations/some_id/revoke", headers={"Authorization": f"Bearer {raw_key}"})
    assert res.status_code == 403
    assert res.json()["detail"] == "API key missing required scope"

def test_jwt_auth(app_client, monkeypatch):
    monkeypatch.setattr(settings, "auth_mode", "prod")
    monkeypatch.setattr(settings, "jwt_issuer", "test-issuer")
    monkeypatch.setattr(settings, "jwt_audience", "test-audience")
    
    # Mock jwks client
    class MockJWKS:
        def get_signing_key_from_jwt(self, token):
            class Key:
                key = "secret"
            return Key()
    
    import app.core.auth
    monkeypatch.setattr(app.core.auth, "_jwks_client", MockJWKS())
    
    # Valid token
    token = jwt.encode(
        {"sub": "user_auth", "org_id": "org_auth", "role": "OWNER", "exp": datetime.now(timezone.utc) + timedelta(hours=1), "iss": "test-issuer", "aud": "test-audience"},
        "secret",
        algorithm="HS256" # For test mock
    )
    # mock settings algorithm
    monkeypatch.setattr(settings, "jwt_algorithms", ["HS256"])
    
    res = app_client.get("/api/organization", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 200
    assert res.json()["id"] == "org_auth"
    
    # Expired token
    expired = jwt.encode(
        {"sub": "user_auth", "org_id": "org_auth", "role": "OWNER", "exp": datetime.now(timezone.utc) - timedelta(hours=1), "iss": "test-issuer", "aud": "test-audience"},
        "secret",
        algorithm="HS256"
    )
    res = app_client.get("/api/organization", headers={"Authorization": f"Bearer {expired}"})
    assert res.status_code == 401
    assert "Invalid JWT" in res.json()["detail"]

