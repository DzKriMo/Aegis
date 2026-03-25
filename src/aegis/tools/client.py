from __future__ import annotations

from typing import Dict, Any, Optional, List
import requests


class AegisClient:
    def __init__(self, base_url: str, api_key: str):
        self.base_url = base_url.rstrip("/")
        self.headers = {"x-api-key": api_key}
        self.session = requests.Session()
        self.session.headers.update(self.headers)
        self.timeout_short = 30
        self.timeout_long = 120

    def create_session(self) -> str:
        r = self.session.post(f"{self.base_url}/sessions", timeout=10)
        r.raise_for_status()
        return r.json()["session_id"]

    def approve(
        self,
        session_id: str,
        approval_hash: str,
        actor: str = "agent",
        scope: str = "exact",
        expires_in_seconds: int = 3600,
        reusable: bool = True,
        reason: Optional[str] = None,
    ) -> Dict[str, Any]:
        payload = {
            "approval_hash": approval_hash,
            "actor": actor,
            "scope": scope,
            "expires_in_seconds": expires_in_seconds,
            "reusable": reusable,
            "reason": reason,
        }
        r = self.session.post(f"{self.base_url}/sessions/{session_id}/approvals/decision", json=payload, timeout=self.timeout_short)
        r.raise_for_status()
        return r.json()

    def send_message(self, session_id: str, content: str, **kwargs) -> Dict[str, Any]:
        payload = {"content": content}
        payload.update(kwargs)
        r = self.session.post(f"{self.base_url}/sessions/{session_id}/messages", json=payload, timeout=self.timeout_long)
        r.raise_for_status()
        return r.json()

    def execute_tool(
        self,
        session_id: str,
        tool_name: str,
        payload: Dict[str, Any],
        environment: Optional[str] = None,
        allowlist: Optional[List[str]] = None,
        denylist: Optional[List[str]] = None,
        filesystem_root: Optional[str] = None,
        **kwargs,
    ) -> Dict[str, Any]:
        body = {
            "tool_name": tool_name,
            "payload": payload,
            "environment": environment,
            "allowlist": allowlist or [],
            "denylist": denylist or [],
            "filesystem_root": filesystem_root,
        }
        body.update(kwargs)
        r = self.session.post(f"{self.base_url}/sessions/{session_id}/tools/execute", json=body, timeout=self.timeout_long)
        r.raise_for_status()
        return r.json()

    def guard_input(self, session_id: str, content: str, **kwargs) -> Dict[str, Any]:
        payload = {"content": content}
        payload.update(kwargs)
        r = self.session.post(f"{self.base_url}/sessions/{session_id}/guard/input", json=payload, timeout=self.timeout_long)
        r.raise_for_status()
        return r.json()

    def guard_output(self, session_id: str, content: str, **kwargs) -> Dict[str, Any]:
        payload = {"content": content}
        payload.update(kwargs)
        r = self.session.post(f"{self.base_url}/sessions/{session_id}/guard/output", json=payload, timeout=self.timeout_long)
        r.raise_for_status()
        return r.json()

    def get_risk(self, session_id: str) -> Dict[str, Any]:
        r = self.session.get(f"{self.base_url}/sessions/{session_id}/risk", timeout=self.timeout_short)
        r.raise_for_status()
        return r.json()

    def reset_risk(self, session_id: str) -> Dict[str, Any]:
        r = self.session.post(f"{self.base_url}/sessions/{session_id}/risk/reset", timeout=self.timeout_short)
        r.raise_for_status()
        return r.json()
