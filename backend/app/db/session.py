from __future__ import annotations

from collections.abc import Generator

from sqlalchemy import create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from app.core import config
from app.core.logging import get_logger

logger = get_logger("main")


class Base(DeclarativeBase):
    pass


def _normalize_database_url(database_url: str) -> str:
    if database_url.startswith("postgresql://"):
        return database_url.replace("postgresql://", "postgresql+psycopg://", 1)
    if database_url.startswith("postgres://"):
        return database_url.replace("postgres://", "postgresql+psycopg://", 1)
    return database_url


_engine: Engine | None = None
_SessionLocal: sessionmaker[Session] | None = None


def persistence_enabled() -> bool:
    return bool(config.DATABASE_URL)


def _build_engine() -> Engine | None:
    if not persistence_enabled():
        return None
    database_url = _normalize_database_url(config.DATABASE_URL)
    connect_args = {"check_same_thread": False} if database_url.startswith("sqlite") else {}
    return create_engine(
        database_url,
        future=True,
        pool_pre_ping=True,
        connect_args=connect_args,
    )


def _ensure_session_factory() -> sessionmaker[Session] | None:
    global _engine, _SessionLocal
    if _SessionLocal is not None:
        return _SessionLocal
    _engine = _build_engine()
    if _engine is None:
        return None
    _SessionLocal = sessionmaker(bind=_engine, autoflush=False, autocommit=False, future=True)
    return _SessionLocal


def get_engine() -> Engine | None:
    _ensure_session_factory()
    return _engine


def initialize_database() -> None:
    if not persistence_enabled():
        logger.info("database_persistence_disabled")
        return
    from app.db.models import ProofArtifactRecord, PermitRecord, ReserveEvidenceRecord  # noqa: F401

    engine = get_engine()
    if engine is None:
        return
    Base.metadata.create_all(bind=engine)
    logger.info("database_initialized")


def get_db() -> Generator[Session | None, None, None]:
    """Yield a SQLAlchemy session, or None when persistence is disabled."""
    session_factory = _ensure_session_factory()
    if session_factory is None:
        # Keep dependency injection stable even when persistence is disabled.
        yield None
        return
    db = session_factory()
    try:
        yield db
    finally:
        db.close()
