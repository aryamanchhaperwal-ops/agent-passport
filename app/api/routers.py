from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from typing import List
from app.db.models import UserRecord
from app.api.deps import get_current_user, require_role
from app.core.rbac import Action
from app.repositories.organization import OrganizationRepository
from app.repositories.user import UserRepository
from app.repositories.agent import AgentRepository, DelegationRepository

router = APIRouter()

# --- Organizations ---

class OrgResponse(BaseModel):
    id: str
    name: str
    slug: str

@router.get("/organization", response_model=OrgResponse)
def get_organization(user: UserRecord = Depends(require_role(Action.READ_ONLY))):
    repo = OrganizationRepository()
    org = repo.get(user.organization_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    return {"id": org.id, "name": org.name, "slug": org.slug}

# --- Users ---

class UserResponse(BaseModel):
    id: str
    email: str
    display_name: str
    role: str

@router.get("/users", response_model=List[UserResponse])
def list_users(user: UserRecord = Depends(require_role(Action.READ_ONLY))):
    from app.db.database import SessionLocal
    with SessionLocal() as session:
        users = session.query(UserRecord).filter_by(organization_id=user.organization_id).all()
        return [{"id": u.id, "email": u.email, "display_name": u.display_name, "role": u.role} for u in users]

@router.get("/users/{user_id}", response_model=UserResponse)
def get_user(user_id: str, user: UserRecord = Depends(require_role(Action.READ_ONLY))):
    repo = UserRepository()
    target_user = repo.get(user_id)
    if not target_user or target_user.organization_id != user.organization_id:
        raise HTTPException(status_code=404, detail="User not found")
    return {"id": target_user.id, "email": target_user.email, "display_name": target_user.display_name, "role": target_user.role}

# --- Agents ---

class AgentResponse(BaseModel):
    id: str
    name: str | None
    public_key: str
    status: str

@router.get("/agents", response_model=List[AgentResponse])
def list_agents(user: UserRecord = Depends(require_role(Action.READ_ONLY))):
    repo = AgentRepository()
    agents = repo.get_by_org(user.organization_id)
    return [{"id": a.id, "name": a.name, "public_key": a.public_key, "status": a.status} for a in agents]

@router.get("/agents/{agent_id}", response_model=AgentResponse)
def get_agent(agent_id: str, user: UserRecord = Depends(require_role(Action.READ_ONLY))):
    repo = AgentRepository()
    agent = repo.get(agent_id)
    if not agent or agent.organization_id != user.organization_id:
        raise HTTPException(status_code=404, detail="Agent not found")
    return {"id": agent.id, "name": agent.name, "public_key": agent.public_key, "status": agent.status}

# --- Delegations ---

class DelegationResponse(BaseModel):
    id: str
    issuer_id: str
    subject_id: str
    status: str

@router.get("/delegations", response_model=List[DelegationResponse])
def list_delegations(user: UserRecord = Depends(require_role(Action.READ_ONLY))):
    repo = DelegationRepository()
    delegations = repo.get_by_org(user.organization_id)
    return [{"id": d.id, "issuer_id": d.issuer_id, "subject_id": d.subject_id, "status": d.status} for d in delegations]

@router.get("/delegations/{delegation_id}", response_model=DelegationResponse)
def get_delegation(delegation_id: str, user: UserRecord = Depends(require_role(Action.READ_ONLY))):
    repo = DelegationRepository()
    delegation = repo.get(delegation_id)
    if not delegation or delegation.organization_id != user.organization_id:
        raise HTTPException(status_code=404, detail="Delegation not found")
    return {"id": delegation.id, "issuer_id": delegation.issuer_id, "subject_id": delegation.subject_id, "status": delegation.status}

@router.post("/delegations/{delegation_id}/revoke")
def revoke_delegation(delegation_id: str, user: UserRecord = Depends(require_role(Action.MANAGE_DELEGATIONS))):
    repo = DelegationRepository()
    delegation = repo.get(delegation_id)
    if not delegation or delegation.organization_id != user.organization_id:
        raise HTTPException(status_code=404, detail="Delegation not found")
    
    from app.repositories.revocation import DbRevocationRegistry
    registry = DbRevocationRegistry()
    registry.revoke(delegation_id, reason="Revoked by user", revoked_by=user.id)
    return {"status": "revoked"}
