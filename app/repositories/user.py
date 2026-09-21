from sqlalchemy.orm import Session
from app.db.models import UserRecord
from app.db.database import SessionLocal

class UserRepository:
    def create(self, id: str, organization_id: str, email: str, display_name: str, role: str) -> UserRecord:
        with SessionLocal() as session:
            user = UserRecord(
                id=id,
                organization_id=organization_id,
                email=email,
                display_name=display_name,
                role=role
            )
            session.add(user)
            session.commit()
            session.refresh(user)
            return user

    def get(self, id: str) -> UserRecord | None:
        with SessionLocal() as session:
            return session.query(UserRecord).filter_by(id=id).first()

    def get_by_email(self, email: str) -> UserRecord | None:
        with SessionLocal() as session:
            return session.query(UserRecord).filter_by(email=email).first()
