import logging
from typing import Generator
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base, Session
from app.core.config import settings

logger = logging.getLogger(__name__)

# Create SQLAlchemy engine with pre-ping enabled for connection pool resilience
engine = create_engine(
    settings.DATABASE_URL,
    pool_pre_ping=True,
    pool_size=10,
    max_overflow=20,
    echo=settings.DEBUG
)

# Create SessionLocal class for generating database sessions
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Base class for declarative ORM models
Base = declarative_base()


def get_db() -> Generator[Session, None, None]:
    """
    FastAPI Dependency for database session management.
    Ensures that database sessions are cleanly opened and closed per request.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    """
    Initialize database tables automatically during application startup.
    Creates all defined ORM tables if they do not already exist in PostgreSQL.
    """
    try:
        logger.info("Initializing database schema and checking tables...")
        # Import models here to ensure they are registered with Base.metadata before create_all
        import app.models  # noqa: F401
        Base.metadata.create_all(bind=engine)
        logger.info("Database schema initialization completed successfully.")
    except Exception as e:
        logger.error(f"Failed to initialize database tables: {e}")
        # We don't raise here during startup if Postgres is temporarily unreachable in dev/testing,
        # but log the exception clearly.
