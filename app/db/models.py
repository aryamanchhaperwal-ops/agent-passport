import datetime
from sqlalchemy import String, Boolean, DateTime, JSON, ForeignKey, MetaData
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.sql import func
from app.db.database import Base

convention = {
  "ix": "ix_%(column_0_label)s",
  "uq": "uq_%(table_name)s_%(column_0_name)s",
  "ck": "ck_%(table_name)s_%(constraint_name)s",
  "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
  "pk": "pk_%(table_name)s"
}
Base.metadata.naming_convention = convention

class OrganizationRecord(Base):
    __tablename__ = "organizations"
    
    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    slug: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(32), default="ACTIVE")
    created_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

class UserRecord(Base):
    __tablename__ = "users"
    
    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    organization_id: Mapped[str] = mapped_column(String(128), ForeignKey("organizations.id"), nullable=False, index=True)
    email: Mapped[str] = mapped_column(String(255), nullable=False, unique=True, index=True)
    display_name: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(String(32), default="VIEWER")
    status: Mapped[str] = mapped_column(String(32), default="ACTIVE")
    created_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

class AgentRecord(Base):
    __tablename__ = "agents"

    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    organization_id: Mapped[str | None] = mapped_column(String(128), ForeignKey("organizations.id"), nullable=True, index=True)
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
    organization_id: Mapped[str | None] = mapped_column(String(128), ForeignKey("organizations.id"), nullable=True, index=True)
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

