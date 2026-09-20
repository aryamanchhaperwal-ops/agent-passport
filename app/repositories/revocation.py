import datetime
from app.core.delegation import RevocationRegistry
from app.db.models import RevocationRecord
from app.db.database import SessionLocal

class DbRevocationRegistry(RevocationRegistry):
    def is_revoked(self, delegation_id: str) -> bool:
        with SessionLocal() as session:
            record = session.query(RevocationRecord).filter(
                RevocationRecord.delegation_id == delegation_id
            ).first()
            return record is not None

    def revoke(self, delegation_id: str, reason: str | None = None, revoked_by: str | None = None) -> None:
        """Revoke a delegation (only if not already revoked)."""
        if not self.is_revoked(delegation_id):
            with SessionLocal() as session:
                record = RevocationRecord(
                    delegation_id=delegation_id,
                    reason=reason,
                    revoked_by=revoked_by,
                    revoked_at=datetime.datetime.now(datetime.UTC)
                )
                session.add(record)
                session.commit()
