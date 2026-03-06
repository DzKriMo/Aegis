from typing import Dict, Any
import time
import json
import hashlib
from datetime import datetime, timezone

from ..telemetry.collector import emit


class InMemoryStore:
    def __init__(self):
        self.sessions: Dict[str, Dict[str, Any]] = {}

    def create_session(self, session_id: str, username: str | None = None, title: str | None = None):
        self.sessions[session_id] = {
            "username": username,
            "title": title or "New Chat",
            "created_ts": time.time(),
            "events": [],
            "pending_approvals": set(),
            "approved": set(),
            "risk_state": {
                "cumulative_risk_score": 0.0,
                "goal_drift_score": 0.0,
                "injection_attempt_count": 0,
                "sensitive_tool_attempts": 0,
                "quarantined": False,
                "last_event_hash": "GENESIS",
            },
        }

    def session_exists(self, session_id: str) -> bool:
        return session_id in self.sessions

    def log_event(self, session_id: str, event: Dict[str, Any]):
        if "ts" not in event:
            event["ts"] = time.time()

        # Human-friendly timestamp for logs and API consumers.
        event["ts_readable"] = datetime.fromtimestamp(float(event["ts"]), tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        state = self.sessions[session_id]["risk_state"]
        prev_hash = str(state.get("last_event_hash", "GENESIS"))
        event["prev_event_hash"] = prev_hash
        canonical = json.dumps(event, sort_keys=True, ensure_ascii=True, separators=(",", ":"))
        event_hash = hashlib.sha256((prev_hash + canonical).encode("utf-8")).hexdigest()
        event["event_hash"] = event_hash
        state["last_event_hash"] = event_hash

        self.sessions[session_id]["events"].append(event)
        emit({"session_id": session_id, **event})

    def add_pending_approval(self, session_id: str, approval_hash: str):
        self.sessions[session_id]["pending_approvals"].add(approval_hash)

    def is_approved(self, session_id: str, approval_hash: str) -> bool:
        return approval_hash in self.sessions[session_id]["approved"]

    def approve(self, session_id: str, approval_hash: str) -> bool:
        pending = self.sessions[session_id]["pending_approvals"]
        if approval_hash not in pending:
            return False
        pending.remove(approval_hash)
        self.sessions[session_id]["approved"].add(approval_hash)
        return True

    def get_session(self, session_id: str) -> Dict[str, Any]:
        return self.sessions.get(session_id, {})

    def get_session_username(self, session_id: str) -> str | None:
        sess = self.sessions.get(session_id) or {}
        username = sess.get("username")
        return str(username) if username else None

    def get_session_title(self, session_id: str) -> str | None:
        sess = self.sessions.get(session_id) or {}
        title = sess.get("title")
        return str(title) if title else None

    def set_session_title(self, session_id: str, title: str) -> None:
        if session_id not in self.sessions:
            return
        cleaned = str(title or "").strip()
        if not cleaned:
            return
        self.sessions[session_id]["title"] = cleaned

    def list_sessions(self) -> Dict[str, Dict[str, Any]]:
        out: Dict[str, Dict[str, Any]] = {}
        for sid, data in self.sessions.items():
            events = list(data.get("events") or [])
            last_event_ts = None
            if events:
                try:
                    ts = events[-1].get("ts")
                    if ts is not None:
                        last_event_ts = float(ts)
                except Exception:
                    last_event_ts = None
            copied = dict(data)
            copied["last_event_ts"] = last_event_ts
            out[sid] = copied
        return out

    def get_risk_state(self, session_id: str) -> Dict[str, Any]:
        sess = self.sessions.get(session_id) or {}
        return dict(sess.get("risk_state") or {})

    def set_risk_state(self, session_id: str, state: Dict[str, Any]) -> None:
        if session_id not in self.sessions:
            self.create_session(session_id)
        merged = dict(self.sessions[session_id].get("risk_state") or {})
        existing_hash = str(merged.get("last_event_hash", "GENESIS"))
        merged.update(state or {})
        new_hash = str(merged.get("last_event_hash", "GENESIS"))
        if new_hash == "GENESIS" and existing_hash != "GENESIS":
            merged["last_event_hash"] = existing_hash
        self.sessions[session_id]["risk_state"] = merged
