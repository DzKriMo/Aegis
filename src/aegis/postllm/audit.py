from __future__ import annotations

from typing import Any, Dict, List
import hashlib
import json
import time


def build_audit_evidence(
	session_id: str,
	request_id: str,
	stage: str,
	risk_score: float,
	reasons: List[str] | None = None,
	details: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
	payload = {
		"session_id": session_id,
		"request_id": request_id,
		"stage": stage,
		"risk_score": float(risk_score),
		"reasons": list(reasons or []),
		"details": details or {},
		"ts": time.time(),
	}
	canonical = json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
	payload["audit_id"] = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
	return payload
