import json
import time
import hashlib
from datetime import datetime, timezone
from typing import Dict, Any

from ..telemetry.collector import emit
from .db import get_session, init_db
from .models import SessionRecord, EventRecord, ApprovalRecord


class DbStore:
    def __init__(self):
        init_db()
        self._risk_state: Dict[str, Dict[str, Any]] = {}
        self._event_hash_cache: Dict[str, str] = {}
        self._pending_approvals: Dict[str, Dict[str, Dict[str, Any]]] = {}

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
        rec = SessionRecord(session_id=session_id, tenant_id=tenant_id, created_at=int(time.time()), title=None)
        s.add(rec)
        s.commit()
        s.close()
        self._risk_state[session_id] = self._default_risk_state()
        self._event_hash_cache[session_id] = "GENESIS"
        self._pending_approvals[session_id] = {}

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
            "title": (sess.title if sess else None),
            "created_at": (sess.created_at if sess else None),
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
            result[sess.session_id] = {
                "session_id": sess.session_id,
                "title": sess.title,
                "created_at": sess.created_at,
                "events": [None] * count,
                "risk_state": self.get_risk_state(sess.session_id),
            }
        s.close()
        return result

    def update_session_title(self, session_id: str, title: str, force: bool = False) -> None:
        s = get_session()
        if s is None:
            return
        sess = s.query(SessionRecord).filter_by(session_id=session_id).first()
        if sess is None:
            s.close()
            return
        if force or not sess.title:
            sess.title = title
            s.commit()
        s.close()

    def delete_session(self, session_id: str) -> bool:
        s = get_session()
        if s is None:
            return False
        sess = s.query(SessionRecord).filter_by(session_id=session_id).first()
        if sess is None:
            s.close()
            return False
        s.query(EventRecord).filter_by(session_id=session_id).delete()
        s.query(ApprovalRecord).filter_by(session_id=session_id).delete()
        s.delete(sess)
        s.commit()
        s.close()
        self._risk_state.pop(session_id, None)
        self._event_hash_cache.pop(session_id, None)
        self._pending_approvals.pop(session_id, None)
        return True

    def clear_sessions(self) -> int:
        s = get_session()
        if s is None:
            return 0
        count = s.query(SessionRecord).count()
        s.query(EventRecord).delete()
        s.query(ApprovalRecord).delete()
        s.query(SessionRecord).delete()
        s.commit()
        s.close()
        self._risk_state = {}
        self._event_hash_cache = {}
        self._pending_approvals = {}
        return count

    def add_pending_approval(self, session_id: str, approval_hash: str, metadata: Dict[str, Any] | None = None):
        pending = self._pending_approvals.setdefault(session_id, {})
        pending[approval_hash] = dict(metadata or {})

    def list_pending_approvals(self, session_id: str) -> list[Dict[str, Any]]:
        pending = self._pending_approvals.get(session_id, {})
        return [{"approval_hash": h, **meta} for h, meta in pending.items()]

    def is_approved(
        self,
        session_id: str,
        approval_hash: str,
        stage: str | None = None,
        context: Dict[str, Any] | None = None,
        tool_name: str | None = None,
    ) -> bool:
        s = get_session()
        if s is None:
            return False
        now = int(time.time())
        rows = s.query(ApprovalRecord).filter_by(active=True).all()
        ctx = context or {}
        for row in rows:
            if row.expires_at and row.expires_at <= now:
                continue
            scope = row.scope or "exact"
            if scope == "exact" and row.approval_hash == approval_hash:
                s.close()
                return True
            if scope == "stage" and row.stage == stage and row.environment in {None, ctx.get("environment")}:
                s.close()
                return True
            if scope == "tool" and row.tool_name == tool_name and row.environment in {None, ctx.get("environment")}:
                s.close()
                return True
            if scope == "session" and row.session_id == session_id:
                s.close()
                return True
            if scope == "tenant" and row.tenant_id is not None and row.tenant_id == str(ctx.get("tenant_id")):
                s.close()
                return True
        s.close()
        return False

    def approve(
        self,
        session_id: str,
        approval_hash: str,
        actor: str | None = None,
        scope: str = "exact",
        expires_in_seconds: int = 3600,
        reusable: bool = True,
        reason: str | None = None,
    ) -> bool:
        pending = self._pending_approvals.setdefault(session_id, {})
        meta = pending.get(approval_hash, {})
        if approval_hash not in pending and scope == "exact":
            return False
        if approval_hash in pending:
            del pending[approval_hash]
        s = get_session()
        if s is None:
            return False
        row = ApprovalRecord(
            session_id=session_id,
            approval_hash=approval_hash,
            scope=scope,
            actor=actor,
            reason=reason,
            stage=meta.get("stage"),
            tool_name=meta.get("tool_name"),
            tenant_id=str(meta.get("tenant_id")) if meta.get("tenant_id") is not None else None,
            environment=meta.get("environment"),
            reusable=reusable,
            active=True,
            expires_at=(int(time.time()) + max(int(expires_in_seconds), 0)) if expires_in_seconds else None,
            metadata_json=json.dumps(meta),
        )
        s.add(row)
        s.commit()
        s.close()
        return True

    def list_reusable_approvals(self, session_id: str | None = None) -> list[Dict[str, Any]]:
        s = get_session()
        if s is None:
            return []
        q = s.query(ApprovalRecord).filter_by(active=True)
        if session_id is not None:
            q = q.filter_by(session_id=session_id)
        rows = q.all()
        now = int(time.time())
        out = []
        for row in rows:
            if row.expires_at and row.expires_at <= now:
                continue
            metadata = {}
            if row.metadata_json:
                try:
                    metadata = json.loads(row.metadata_json)
                except Exception:
                    metadata = {}
            out.append(
                {
                    "approval_hash": row.approval_hash,
                    "scope": row.scope,
                    "actor": row.actor,
                    "reason": row.reason,
                    "stage": row.stage,
                    "tool_name": row.tool_name,
                    "tenant_id": row.tenant_id,
                    "environment": row.environment,
                    "reusable": row.reusable,
                    "expires_at": row.expires_at,
                    "session_id": row.session_id,
                    "metadata": metadata,
                }
            )
        s.close()
        return out

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

    def reset_risk_state(self, session_id: str) -> Dict[str, Any]:
        existing_hash = str((self._risk_state.get(session_id) or {}).get("last_event_hash", self._event_hash_cache.get(session_id, "GENESIS")))
        reset = self._default_risk_state()
        reset["last_event_hash"] = existing_hash
        self._risk_state[session_id] = reset
        return dict(reset)
