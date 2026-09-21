from typing import List
from app.db.models import ApiKeyRecord
from app.db.database import SessionLocal

class ApiKeyRepository:
    def create(self, id: str, user_id: str, organization_id: str, name: str, key_hash: str, prefix: str, scopes: List[str]) -> ApiKeyRecord:
        with SessionLocal() as session:
            record = ApiKeyRecord(
                id=id,
                user_id=user_id,
                organization_id=organization_id,
                name=name,
                key_hash=key_hash,
                prefix=prefix,
                scopes=scopes
            )
            session.add(record)
            session.commit()
            session.refresh(record)
            return record

    def get_by_prefix(self, prefix: str) -> ApiKeyRecord | None:
        with SessionLocal() as session:
            return session.query(ApiKeyRecord).filter_by(prefix=prefix, status="ACTIVE").first()
            
    def revoke(self, id: str) -> None:
        with SessionLocal() as session:
            record = session.query(ApiKeyRecord).filter_by(id=id).first()
            if record:
                record.status = "REVOKED"
                session.commit()
