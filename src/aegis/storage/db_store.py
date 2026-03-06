import json
import time
import hashlib
from datetime import datetime, timezone
from typing import Dict, Any
from sqlalchemy import inspect, text

from ..telemetry.collector import emit
from .db import get_session, get_engine, init_db
from .models import SessionRecord, EventRecord


class DbStore:
    def __init__(self):
        init_db()
        self._risk_state: Dict[str, Dict[str, Any]] = {}
        self._event_hash_cache: Dict[str, str] = {}
        self._ensure_session_owner_columns()
        self._supports_session_username = self._detect_session_username_support()
        self._supports_session_title = self._detect_session_title_support()

    def _ensure_session_owner_columns(self) -> None:
        try:
            engine = get_engine()
            cols = {c["name"] for c in inspect(engine).get_columns("aegis_sessions")}
            ddl = []
            if "user_id" not in cols:
                ddl.append("ALTER TABLE aegis_sessions ADD COLUMN user_id INTEGER")
            if "username" not in cols:
                ddl.append("ALTER TABLE aegis_sessions ADD COLUMN username VARCHAR(64)")
            if "title" not in cols:
                ddl.append("ALTER TABLE aegis_sessions ADD COLUMN title VARCHAR(160)")
            if not ddl:
                return
            with engine.begin() as conn:
                for stmt in ddl:
                    conn.execute(text(stmt))
        except Exception:
            return

    def _detect_session_username_support(self) -> bool:
        try:
            engine = get_engine()
            cols = {c["name"] for c in inspect(engine).get_columns("aegis_sessions")}
            return "username" in cols
        except Exception:
            return False

    def _detect_session_title_support(self) -> bool:
        try:
            engine = get_engine()
            cols = {c["name"] for c in inspect(engine).get_columns("aegis_sessions")}
            return "title" in cols
        except Exception:
            return False

    def _default_risk_state(self) -> Dict[str, Any]:
        return {
            "cumulative_risk_score": 0.0,
            "goal_drift_score": 0.0,
            "injection_attempt_count": 0,
            "sensitive_tool_attempts": 0,
            "quarantined": False,
            "last_event_hash": "GENESIS",
        }

    def create_session(self, session_id: str, tenant_id: int | None = None, username: str | None = None, title: str | None = None):
        s = get_session()
        if s is None:
            return
        rec = SessionRecord(session_id=session_id, tenant_id=tenant_id)
        if self._supports_session_username:
            rec.username = username
        if self._supports_session_title:
            rec.title = title or "New Chat"
        s.add(rec)
        s.commit()
        s.close()
        self._risk_state[session_id] = self._default_risk_state()
        self._event_hash_cache[session_id] = "GENESIS"

    def session_exists(self, session_id: str) -> bool:
        s = get_session()
        if s is None:
            return False
        exists = s.query(SessionRecord).filter_by(session_id=session_id).first() is not None
        s.close()
        return exists

    def _prev_event_hash(self, session_id: str) -> str:
        cached = self._event_hash_cache.get(session_id)
        if cached:
            return cached
        s = get_session()
        if s is None:
            return "GENESIS"
        row = s.query(EventRecord).filter_by(session_id=session_id).order_by(EventRecord.id.desc()).first()
        s.close()
        if not row:
            self._event_hash_cache[session_id] = "GENESIS"
            return "GENESIS"
        try:
            payload = json.loads(row.payload)
            prev = str(payload.get("event_hash") or "GENESIS")
            self._event_hash_cache[session_id] = prev
            return prev
        except Exception:
            return "GENESIS"

    def log_event(self, session_id: str, event: Dict[str, Any]):
        if "ts" not in event:
            event["ts"] = time.time()

        # Human-friendly timestamp for logs and API consumers.
        event["ts_readable"] = datetime.fromtimestamp(float(event["ts"]), tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        prev_hash = self._prev_event_hash(session_id)
        event["prev_event_hash"] = prev_hash
        canonical = json.dumps(event, sort_keys=True, ensure_ascii=True, separators=(",", ":"))
        event_hash = hashlib.sha256((prev_hash + canonical).encode("utf-8")).hexdigest()
        event["event_hash"] = event_hash
        self._event_hash_cache[session_id] = event_hash
        st = self.get_risk_state(session_id)
        st["last_event_hash"] = event_hash
        self._risk_state[session_id] = st

        emit({"session_id": session_id, **event})
        s = get_session()
        if s is None:
            return
        payload = json.dumps(event)
        rec = EventRecord(session_id=session_id, stage=event.get("stage"), payload=payload)
        s.add(rec)
        s.commit()
        s.close()

    def get_session(self, session_id: str) -> Dict[str, Any]:
        s = get_session()
        if s is None:
            return {}
        sess = s.query(SessionRecord).filter_by(session_id=session_id).first()
        events = s.query(EventRecord).filter_by(session_id=session_id).order_by(EventRecord.id.asc()).all()
        s.close()
        return {
            "session_id": session_id,
            "username": getattr(sess, "username", None) if self._supports_session_username else None,
            "title": getattr(sess, "title", None) if self._supports_session_title else None,
            "events": [json.loads(e.payload) for e in events],
            "risk_state": self.get_risk_state(session_id),
        }

    def list_sessions(self) -> Dict[str, Dict[str, Any]]:
        s = get_session()
        if s is None:
            return {}
        sessions = s.query(SessionRecord).all()
        result = {}
        for sess in sessions:
            count = s.query(EventRecord).filter_by(session_id=sess.session_id).count()
            latest = (
                s.query(EventRecord)
                .filter_by(session_id=sess.session_id)
                .order_by(EventRecord.id.desc())
                .first()
            )
            last_event_ts = None
            if latest is not None:
                try:
                    payload = json.loads(latest.payload)
                    ts = payload.get("ts")
                    if ts is not None:
                        last_event_ts = float(ts)
                except Exception:
                    last_event_ts = None
            result[sess.session_id] = {
                "username": getattr(sess, "username", None) if self._supports_session_username else None,
                "title": getattr(sess, "title", None) if self._supports_session_title else None,
                "events": [None] * count,
                "last_event_ts": last_event_ts,
                "risk_state": self.get_risk_state(sess.session_id),
            }
        s.close()
        return result

    def get_session_username(self, session_id: str) -> str | None:
        if not self._supports_session_username:
            return None
        s = get_session()
        if s is None:
            return None
        sess = s.query(SessionRecord).filter_by(session_id=session_id).first()
        s.close()
        username = getattr(sess, "username", None)
        return str(username) if username else None

    def get_session_title(self, session_id: str) -> str | None:
        if not self._supports_session_title:
            return None
        s = get_session()
        if s is None:
            return None
        sess = s.query(SessionRecord).filter_by(session_id=session_id).first()
        s.close()
        title = getattr(sess, "title", None)
        return str(title) if title else None

    def set_session_title(self, session_id: str, title: str) -> None:
        if not self._supports_session_title:
            return
        cleaned = str(title or "").strip()
        if not cleaned:
            return
        s = get_session()
        if s is None:
            return
        sess = s.query(SessionRecord).filter_by(session_id=session_id).first()
        if sess is not None:
            sess.title = cleaned
            s.commit()
        s.close()

    # approvals not persisted in DB for demo
    def add_pending_approval(self, session_id: str, approval_hash: str):
        pass

    def is_approved(self, session_id: str, approval_hash: str) -> bool:
        return False

    def approve(self, session_id: str, approval_hash: str) -> bool:
        return False

    def get_risk_state(self, session_id: str) -> Dict[str, Any]:
        if session_id not in self._risk_state:
            self._risk_state[session_id] = self._default_risk_state()
        return dict(self._risk_state.get(session_id) or self._default_risk_state())

    def set_risk_state(self, session_id: str, state: Dict[str, Any]) -> None:
        merged = self._default_risk_state()
        merged.update(self._risk_state.get(session_id) or {})
        existing_hash = str(merged.get("last_event_hash", "GENESIS"))
        merged.update(state or {})
        new_hash = str(merged.get("last_event_hash", "GENESIS"))
        if new_hash == "GENESIS" and existing_hash != "GENESIS":
            merged["last_event_hash"] = existing_hash
        self._risk_state[session_id] = merged
