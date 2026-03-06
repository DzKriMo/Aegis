from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional


@dataclass
class LeastPrivilegeDecision:
	allowed: bool
	require_approval: bool
	message: str
	sanitized_payload: Dict[str, Any]


def enforce_least_privilege(
	tool_name: str,
	payload: Dict[str, Any] | None,
	role: Optional[str],
	environment: Optional[str],
) -> LeastPrivilegeDecision:
	payload = dict(payload or {})
	normalized_role = str(role or "").strip().lower()
	normalized_env = str(environment or "").strip().lower()

	if tool_name == "shell":
		if normalized_role != "admin":
			return LeastPrivilegeDecision(False, False, "Shell tool requires admin role", {})
		if normalized_env == "prod":
			return LeastPrivilegeDecision(False, True, "Shell in prod requires explicit approval", {})

	if tool_name == "http_fetch":
		method = str(payload.get("method", "GET")).upper()
		payload["method"] = method
		if method not in {"GET", "HEAD"}:
			return LeastPrivilegeDecision(False, False, "Only GET/HEAD allowed by least-privilege policy", payload)

	return LeastPrivilegeDecision(True, False, "allowed", payload)
