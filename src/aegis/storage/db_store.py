import json
import time
import hashlib
from datetime import datetime, timezone
from typing import Dict, Any

from ..telemetry.collector import emit
from .db import get_session, init_db
from .models import SessionRecord, EventRecord


class DbStore:
    def __init__(self):
        init_db()
        self._risk_state: Dict[str, Dict[str, Any]] = {}
        self._event_hash_cache: Dict[str, str] = {}

    def _default_risk_state(self) -> Dict[str, Any]:
        return {
            "cumulative_risk_score": 0.0,
            "goal_drift_score": 0.0,
            "injection_attempt_count": 0,
            "sensitive_tool_attempts": 0,
            "quarantined": False,
            "last_event_hash": "GENESIS",
        }

    def create_session(self, session_id: str, tenant_id: int | None = None):
        s = get_session()
        if s is None:
            return
        rec = SessionRecord(session_id=session_id, tenant_id=tenant_id)
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
        events = s.query(EventRecord).filter_by(session_id=session_id).order_by(EventRecord.id.asc()).all()
        s.close()
        return {"events": [json.loads(e.payload) for e in events], "risk_state": self.get_risk_state(session_id)}

    def list_sessions(self) -> Dict[str, Dict[str, Any]]:
        s = get_session()
        if s is None:
            return {}
        sessions = s.query(SessionRecord).all()
        result = {}
        for sess in sessions:
            count = s.query(EventRecord).filter_by(session_id=sess.session_id).count()
            result[sess.session_id] = {"events": [None] * count, "risk_state": self.get_risk_state(sess.session_id)}
        s.close()
        return result

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
        merged.update(state or {})
        self._risk_state[session_id] = merged
