from app.db.models import AgentRecord, DelegationRecord
from app.core.identity import AgentIdentity
from app.core.delegation import Delegation
from app.db.database import SessionLocal

class AgentRepository:
    def save(self, identity: AgentIdentity, organization_id: str | None = None, status: str = "ACTIVE") -> None:
        with SessionLocal() as session:
            record = session.query(AgentRecord).filter_by(id=identity.agent_id).first()
            if not record:
                record = AgentRecord(
                    id=identity.agent_id,
                    organization_id=organization_id,
                    public_key=identity.public_identity.public_key_hex,
                    status=status
                )
                session.add(record)
                session.commit()

    def get_by_org(self, organization_id: str) -> list[AgentRecord]:
        with SessionLocal() as session:
            return session.query(AgentRecord).filter_by(organization_id=organization_id).all()

    def get(self, id: str) -> AgentRecord | None:
        with SessionLocal() as session:
            return session.query(AgentRecord).filter_by(id=id).first()

class DelegationRepository:
    def save(self, delegation: Delegation, organization_id: str | None = None, status: str = "ACTIVE") -> None:
        with SessionLocal() as session:
            record = session.query(DelegationRecord).filter_by(id=delegation.delegation_id).first()
            if not record:
                record = DelegationRecord(
                    id=delegation.delegation_id,
                    organization_id=organization_id,
                    issuer_id=delegation.issuer.agent_id,
                    subject_id=delegation.subject.agent_id,
                    parent_id=delegation.parent_delegation_id,
                    scopes=[str(s) for s in delegation.scopes],
                    issued_at=delegation.issued_at,
                    expires_at=delegation.expires_at,
                    credential_data=delegation.model_dump(mode="json"),
                    status=status
                )
                session.add(record)
                session.commit()

    def get_by_org(self, organization_id: str) -> list[DelegationRecord]:
        with SessionLocal() as session:
            return session.query(DelegationRecord).filter_by(organization_id=organization_id).all()

    def get(self, id: str) -> DelegationRecord | None:
        with SessionLocal() as session:
            return session.query(DelegationRecord).filter_by(id=id).first()
