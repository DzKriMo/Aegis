from __future__ import annotations

from typing import Any, Dict


def assess_tool_provenance(tool_name: str, environment: str | None, result: Any) -> Dict[str, Any]:
    score_map = {
        "json_transform": 0.95,
        "filesystem_read": 0.9,
        "directory_list": 0.92,
        "filesystem_write": 0.82,
        "filesystem_edit": 0.84,
        "filesystem_patch": 0.84,
        "file_find": 0.93,
        "repo_map": 0.94,
        "text_search": 0.9,
        "shell": 0.58,
        "http_fetch": 0.42,
    }
    score = float(score_map.get(tool_name, 0.5))
    reasons = [f"base:{tool_name}"]
    if environment == "prod":
        score -= 0.08
        reasons.append("prod_penalty")
    body = ""
    if isinstance(result, dict):
        body = str(result.get("body") or result.get("stdout") or result.get("content") or "")[:4000].lower()
    suspicious_tokens = ["<script", "ignore previous", "api_key", "authorization: bearer", "developer mode", "disable guardrails"]
    if tool_name == "http_fetch":
        suspicious_tokens.append("system prompt")
    if any(token in body for token in suspicious_tokens):
        score -= 0.25
        reasons.append("untrusted_payload_pattern")
    if any(token in body for token in ["traceback", "exception", "permission denied", "unauthorized"]):
        score -= 0.1
        reasons.append("error_like_output")
    score = max(0.0, min(1.0, score))
    trust = "high" if score >= 0.8 else ("medium" if score >= 0.55 else "low")
    return {"score": score, "trust": trust, "reasons": reasons}
