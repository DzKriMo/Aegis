from __future__ import annotations

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import sessionmaker

from ..config import settings
from .models import Base

_ENGINE = None
_SESSION = None


def get_engine():
    global _ENGINE, _SESSION
    if _ENGINE is None:
        _ENGINE = create_engine(settings.database_url, echo=False, future=True)
        _SESSION = sessionmaker(bind=_ENGINE)
    return _ENGINE


def get_session():
    if not settings.aegis_db_enabled:
        return None
    if _SESSION is None:
        get_engine()
    return _SESSION()


def init_db():
    if not settings.aegis_db_enabled:
        return
    engine = get_engine()
    try:
        Base.metadata.create_all(engine)
        inspector = inspect(engine)
        columns = {col["name"] for col in inspector.get_columns("aegis_sessions")}
        with engine.begin() as conn:
            if "created_at" not in columns:
                conn.execute(text("ALTER TABLE aegis_sessions ADD COLUMN created_at INTEGER"))
            if "title" not in columns:
                conn.execute(text("ALTER TABLE aegis_sessions ADD COLUMN title VARCHAR(200)"))
    except OperationalError as exc:
        if "already exists" not in str(exc).lower():
            raise
