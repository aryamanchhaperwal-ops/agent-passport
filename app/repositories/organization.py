from sqlalchemy.orm import Session
from app.db.models import OrganizationRecord
from app.db.database import SessionLocal

class OrganizationRepository:
    def create(self, id: str, name: str, slug: str) -> OrganizationRecord:
        with SessionLocal() as session:
            org = OrganizationRecord(id=id, name=name, slug=slug)
            session.add(org)
            session.commit()
            session.refresh(org)
            return org

    def get(self, id: str) -> OrganizationRecord | None:
        with SessionLocal() as session:
            return session.query(OrganizationRecord).filter_by(id=id).first()

