import datetime
from sqlalchemy import String, Boolean, DateTime, JSON, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.sql import func
from app.db.database import Base

class AgentRecord(Base):
    __tablename__ = "agents"

    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    public_key: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="ACTIVE")
    created_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class DelegationRecord(Base):
    __tablename__ = "delegations"

    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    issuer_id: Mapped[str] = mapped_column(String(128), ForeignKey("agents.id"), nullable=False, index=True)
    subject_id: Mapped[str] = mapped_column(String(128), ForeignKey("agents.id"), nullable=False, index=True)
    parent_id: Mapped[str | None] = mapped_column(String(128), ForeignKey("delegations.id"), nullable=True, index=True)
    
    scopes: Mapped[str] = mapped_column(JSON, nullable=False) # Store scopes as JSON array of strings
    
    issued_at: Mapped[datetime.datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime.datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    
    credential_data: Mapped[str] = mapped_column(JSON, nullable=False) # Full JSON dump of the credential
    status: Mapped[str] = mapped_column(String(32), default="ACTIVE")
    
    created_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class RevocationRecord(Base):
    __tablename__ = "revocations"

    delegation_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    reason: Mapped[str | None] = mapped_column(String(255), nullable=True)
    revoked_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    revoked_by: Mapped[str | None] = mapped_column(String(128), nullable=True)


class AuditRecord(Base):
    __tablename__ = "audit_events"

    event_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    event: Mapped[str] = mapped_column(String(64), nullable=False)
    timestamp: Mapped[datetime.datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    agent: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    tool: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    requested_scope: Mapped[str | None] = mapped_column(String(255), nullable=True)
    decision: Mapped[str] = mapped_column(String(32), nullable=False)
    reason: Mapped[str | None] = mapped_column(String(255), nullable=True)
    executed: Mapped[bool] = mapped_column(Boolean, default=False)
    delegation_id: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    detail: Mapped[str | None] = mapped_column(String(1024), nullable=True)
