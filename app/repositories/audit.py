from app.audit.events import AuditEvent
from app.db.models import AuditRecord
from app.db.database import SessionLocal

class DbAuditStore:
    """Database-backed audit store."""

    def record(self, event: AuditEvent) -> AuditEvent:
        with SessionLocal() as session:
            record = AuditRecord(
                event_id=event.event_id,
                event=event.event,
                timestamp=event.timestamp,
                agent=event.agent,
                tool=event.tool,
                requested_scope=event.requested_scope,
                decision=event.decision,
                reason=event.reason,
                executed=event.executed,
                delegation_id=event.delegation_id,
                detail=event.detail
            )
            session.add(record)
            session.commit()
        return event

    def all_events(self) -> list[AuditEvent]:
        with SessionLocal() as session:
            records = session.query(AuditRecord).order_by(AuditRecord.timestamp.asc()).all()
            return [
                AuditEvent(
                    event_id=r.event_id,
                    event=r.event,
                    timestamp=r.timestamp,
                    agent=r.agent,
                    tool=r.tool,
                    requested_scope=r.requested_scope,
                    decision=r.decision,
                    reason=r.reason,
                    executed=r.executed,
                    delegation_id=r.delegation_id,
                    detail=r.detail
                )
                for r in records
            ]

    def count(self) -> int:
        with SessionLocal() as session:
            return session.query(AuditRecord).count()

    def clear(self) -> None:
        """Test convenience only."""
        with SessionLocal() as session:
            session.query(AuditRecord).delete()
            session.commit()
