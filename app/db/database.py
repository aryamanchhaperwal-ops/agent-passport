import os
from typing import Generator

from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

# Use a local SQLite database by default
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./agentpassport.db")

# For SQLite, we need connect_args to allow multiple threads to share the same connection
# if necessary, though typical FastAPI apps use per-request sessions.
connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}

engine = create_engine(DATABASE_URL, connect_args=connect_args)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

def get_db() -> Generator:
    """FastAPI dependency for database sessions."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

