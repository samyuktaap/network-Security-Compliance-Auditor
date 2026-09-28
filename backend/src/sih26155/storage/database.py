"""
Database engine and session factory.

Supports Supabase PostgreSQL (via DATABASE_URL in .env) with a local development fallback.
"""

from __future__ import annotations

import logging
import os
from contextlib import contextmanager
from pathlib import Path
from typing import Generator

from dotenv import load_dotenv
from sqlalchemy import create_engine, event, text
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Connection URL & Environment Configuration
# ---------------------------------------------------------------------------

# Find the project root and load .env
PROJECT_ROOT = Path(__file__).resolve().parents[4]
ENV_FILE = PROJECT_ROOT / ".env"

if ENV_FILE.exists():
    load_dotenv(ENV_FILE, override=True)
else:
    load_dotenv(override=True)

_DATABASE_URL: str = os.getenv(
    "DATABASE_URL",
    "sqlite:///./data/compliance.db",   # fallback if DATABASE_URL not set
)

db_type = _DATABASE_URL.split("://")[0] if "://" in _DATABASE_URL else "sqlite"
logger.info("Database initialized with driver/type: %s", db_type)

# SQLite needs check_same_thread=False for FastAPI and busy timeout to avoid locked DB
_connect_args: dict = (
    {"check_same_thread": False, "timeout": 30}
    if _DATABASE_URL.startswith("sqlite")
    else {}
)

engine = create_engine(
    _DATABASE_URL,
    connect_args=_connect_args,
    pool_pre_ping=True,     # detect stale connections
    echo=False,
)

if _DATABASE_URL.startswith("sqlite"):
    @event.listens_for(engine, "connect")
    def _set_sqlite_pragmas(dbapi_connection, connection_record):
        """Enables Write-Ahead Logging (WAL) and normal sync for improved concurrent writes."""
        cursor = dbapi_connection.cursor()
        try:
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.execute("PRAGMA synchronous=NORMAL")
        except Exception as exc:
            logger.debug("Failed setting SQLite WAL pragma: %s", exc)
        finally:
            cursor.close()

    if os.getenv("ENVIRONMENT", "").lower() in ("production", "prod"):
        logger.warning(
            "CRITICAL ARCHITECTURAL WARNING: SQLite is active in a PRODUCTION environment. "
            "Please configure DATABASE_URL=postgresql+psycopg2://... for high concurrency."
        )

SessionLocal = sessionmaker(
    bind=engine,
    autocommit=False,
    autoflush=False,
    expire_on_commit=False,
)


def check_db_health() -> bool:
    """Verifies active connectivity to the underlying database."""
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
            return True
    except Exception as exc:
        logger.error("Database health check failed: %s", exc)
        return False


# ---------------------------------------------------------------------------
# Declarative base
# ---------------------------------------------------------------------------

class Base(DeclarativeBase):
    pass


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def create_all_tables() -> None:
    """Create all ORM-mapped tables if they do not already exist."""
    from sih26155.storage import repositories  # noqa: F401
    Base.metadata.create_all(bind=engine)


@contextmanager
def get_db() -> Generator[Session, None, None]:
    """Context-manager that yields a DB session and handles commit/rollback."""
    db = SessionLocal()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def get_db_session() -> Generator[Session, None, None]:
    """FastAPI dependency -- yields a session per request."""
    with get_db() as db:
        yield db
