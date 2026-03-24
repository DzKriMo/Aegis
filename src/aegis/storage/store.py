from typing import Dict, Any
import time
import json
import hashlib
from datetime import datetime, timezone

from ..telemetry.collector import emit


class InMemoryStore:
    def __init__(self):
        self.sessions: Dict[str, Dict[str, Any]] = {}
        self.reusable_approvals: list[Dict[str, Any]] = []

    def create_session(self, session_id: str):
        now = int(time.time())
        self.sessions[session_id] = {
            "session_id": session_id,
            "created_at": now,
            "title": None,
            "events": [],
            "pending_approvals": {},
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

    def _approval_active(self, approval: Dict[str, Any]) -> bool:
        expires_at = approval.get("expires_at")
        return expires_at in (None, 0) or float(expires_at) > time.time()

    def _scope_matches(
        self,
        approval: Dict[str, Any],
        session_id: str,
        approval_hash: str,
        stage: str | None,
        context: Dict[str, Any] | None,
        tool_name: str | None,
    ) -> bool:
        if not approval.get("active", True) or not self._approval_active(approval):
            return False
        scope = str(approval.get("scope") or "exact")
        if scope == "exact":
            return approval.get("approval_hash") == approval_hash
        if scope == "stage":
            return approval.get("stage") == stage and approval.get("environment") in {None, context.get("environment") if context else None}
        if scope == "tool":
            return approval.get("tool_name") == tool_name and approval.get("environment") in {None, context.get("environment") if context else None}
        if scope == "session":
            return approval.get("session_id") == session_id
        if scope == "tenant":
            return approval.get("tenant_id") is not None and approval.get("tenant_id") == ((context or {}).get("tenant_id"))
        return False

    def add_pending_approval(self, session_id: str, approval_hash: str, metadata: Dict[str, Any] | None = None):
        self.sessions[session_id]["pending_approvals"][approval_hash] = dict(metadata or {})

    def list_pending_approvals(self, session_id: str) -> list[Dict[str, Any]]:
        pending = self.sessions.get(session_id, {}).get("pending_approvals", {})
        return [{"approval_hash": h, **meta} for h, meta in pending.items()]

    def is_approved(
        self,
        session_id: str,
        approval_hash: str,
        stage: str | None = None,
        context: Dict[str, Any] | None = None,
        tool_name: str | None = None,
    ) -> bool:
        if approval_hash in self.sessions[session_id]["approved"]:
            return True
        return any(self._scope_matches(a, session_id, approval_hash, stage, context or {}, tool_name) for a in self.reusable_approvals)

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
        pending = self.sessions[session_id]["pending_approvals"]
        meta = pending.get(approval_hash, {})
        if approval_hash not in pending and scope == "exact":
            return False
        if approval_hash in pending:
            del pending[approval_hash]
        self.sessions[session_id]["approved"].add(approval_hash)
        approval = {
            "session_id": session_id,
            "approval_hash": approval_hash,
            "scope": scope,
            "actor": actor,
            "reason": reason,
            "stage": meta.get("stage"),
            "tool_name": meta.get("tool_name"),
            "tenant_id": meta.get("tenant_id"),
            "environment": meta.get("environment"),
            "reusable": reusable,
            "active": True,
            "expires_at": int(time.time()) + max(int(expires_in_seconds), 0) if expires_in_seconds else None,
            "metadata": meta,
        }
        if reusable:
            self.reusable_approvals.append(approval)
        return True

    def list_reusable_approvals(self, session_id: str | None = None) -> list[Dict[str, Any]]:
        out = [a for a in self.reusable_approvals if (session_id is None or a.get("session_id") == session_id)]
        return [dict(a) for a in out if self._approval_active(a) and a.get("active", True)]

    def get_session(self, session_id: str) -> Dict[str, Any]:
        return self.sessions.get(session_id, {})

    def list_sessions(self) -> Dict[str, Dict[str, Any]]:
        return self.sessions

    def update_session_title(self, session_id: str, title: str, force: bool = False) -> None:
        sess = self.sessions.get(session_id)
        if not sess:
            return
        if force or not sess.get("title"):
            sess["title"] = title

    def delete_session(self, session_id: str) -> bool:
        if session_id not in self.sessions:
            return False
        del self.sessions[session_id]
        self.reusable_approvals = [a for a in self.reusable_approvals if a.get("session_id") != session_id]
        return True

    def clear_sessions(self) -> int:
        count = len(self.sessions)
        self.sessions = {}
        self.reusable_approvals = []
        return count

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

    def reset_risk_state(self, session_id: str) -> Dict[str, Any]:
        if session_id not in self.sessions:
            self.create_session(session_id)
        existing = dict(self.sessions[session_id].get("risk_state") or {})
        last_hash = str(existing.get("last_event_hash", "GENESIS"))
        reset = {
            "cumulative_risk_score": 0.0,
            "goal_drift_score": 0.0,
            "injection_attempt_count": 0,
            "sensitive_tool_attempts": 0,
            "quarantined": False,
            "last_event_hash": last_hash,
        }
        self.sessions[session_id]["risk_state"] = reset
        return dict(reset)
