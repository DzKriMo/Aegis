from __future__ import annotations

from typing import Any, Dict
import re
from dataclasses import dataclass

import httpx

from ..config import settings


_PUBLIC_REDACTION_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "[SSN]"),
    (re.compile(r"\b(?:\d[ -]*?){13,19}\b"), "[PAYMENT_CARD]"),
    (re.compile(r"\b[\w\.-]+@[\w\.-]+\.\w+\b"), "[EMAIL]"),
    (re.compile(r"\b\+?\d[\d\-\s\(\)]{7,}\b"), "[PHONE]"),
    (re.compile(r"\b(?:api[-_ ]?key|secret|token|bearer)\b\s*[:=]\s*[^\s,;]+", re.IGNORECASE), "[CREDENTIAL]"),
]
_SENSITIVE_HINTS = re.compile(
    r"\b(ssn|social security|credit card|card number|cvv|secret|api key|token|private key|password|passwd|jwt|access key|pii|confidential)\b",
    re.IGNORECASE,
)
_EMAIL_RE = re.compile(r"\b([\w\.-]+)@([\w\.-]+\.\w+)\b", re.IGNORECASE)
_URL_RE = re.compile(r"\bhttps?://([^/\s:]+)", re.IGNORECASE)
_HIGH_ENTROPY_TOKEN_RE = re.compile(r"\b[A-Za-z0-9_\-]{24,}\b")


@dataclass
class ModelRouteResult:
    text: str
    route: str
    endpoint: str
    model: str
    anonymized: bool
    privacy_score: float
    reasons: list[str]


def _extract_content(resp_json: Dict[str, Any]) -> str:
    choices = resp_json.get("choices") or []
    if not choices:
        return ""
    message = (choices[0] or {}).get("message") or {}
    content = message.get("content")
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: list[str] = []
        for item in content:
            if isinstance(item, dict) and isinstance(item.get("text"), str):
                parts.append(item["text"])
        return "\n".join(parts).strip()
    return ""


def anonymize_for_public_model(text: str) -> str:
    out = text
    for pattern, replacement in _PUBLIC_REDACTION_PATTERNS:
        out = pattern.sub(replacement, out)
    return out


def _contains_company_domain(text: str, company_domains: list[str]) -> bool:
    domains = {d.strip().lower() for d in company_domains if d and d.strip()}
    if not domains:
        return False
    for _, domain in _EMAIL_RE.findall(text or ""):
        d = domain.lower().strip()
        if d in domains or any(d.endswith(f".{cd}") for cd in domains):
            return True
    for host in _URL_RE.findall(text or ""):
        h = host.lower().strip()
        if h in domains or any(h.endswith(f".{cd}") for cd in domains):
            return True
    return False


def _privacy_score(prompt_text: str, route_hint: Dict[str, Any] | None = None) -> tuple[float, list[str]]:
    route_hint = route_hint or {}
    metadata = route_hint.get("metadata") or {}
    labels = {str(v).upper() for v in (route_hint.get("labels") or [])}
    private_labels = {str(v).upper() for v in (settings.aegis_private_labels or [])}
    llm_cls = route_hint.get("llm_classification") or {}
    risk = float(route_hint.get("policy_risk_score", route_hint.get("risk_score", 0.0)) or 0.0)
    text = prompt_text or ""
    lower = text.lower()

    score = 0.0
    reasons: list[str] = []

    if bool(metadata.get("force_private_model", False)) or bool(route_hint.get("force_private_model", False)):
        return 99.0, ["force_private_model"]

    label_hits = labels.intersection(private_labels)
    if label_hits:
        score += 2.0
        reasons.append(f"private_labels:{','.join(sorted(label_hits))}")

    if risk >= float(settings.aegis_private_risk_threshold):
        score += 1.0
        reasons.append(f"risk>={settings.aegis_private_risk_threshold}")

    cls_hits = [k for k in ("pii", "secrets", "data_leakage", "exfiltration") if bool(llm_cls.get(k, False))]
    if cls_hits:
        score += 1.5
        reasons.append(f"llm_flags:{','.join(cls_hits)}")

    if _SENSITIVE_HINTS.search(text):
        score += 1.0
        reasons.append("sensitive_hint")

    if _contains_company_domain(text, settings.aegis_private_company_domains or []):
        score += 1.5
        reasons.append("company_domain")

    keyword_hits = []
    for keyword in settings.aegis_private_keywords or []:
        k = str(keyword or "").strip().lower()
        if k and k in lower:
            keyword_hits.append(k)
    if keyword_hits:
        score += min(1.5, 0.6 * len(keyword_hits))
        reasons.append(f"private_keywords:{','.join(sorted(set(keyword_hits))[:3])}")

    if _HIGH_ENTROPY_TOKEN_RE.search(text) and re.search(r"\b(key|token|secret|credential|auth)\b", lower):
        score += 1.0
        reasons.append("high_entropy_token")

    return score, reasons


def select_model_route(prompt_text: str, route_hint: Dict[str, Any] | None = None) -> str:
    mode = (settings.aegis_model_routing_mode or "single").strip().lower()
    route_hint = route_hint or {}

    if mode in {"single", "disabled"}:
        return "single"
    if mode == "always_private":
        return "private"
    if mode == "always_public":
        return "public"

    score, _ = _privacy_score(prompt_text, route_hint=route_hint)
    if score >= float(settings.aegis_private_min_score):
        return "private"

    if mode in {"sensitivity", "metadata"}:
        return "public"
    return "single"


def _route_target(route: str) -> tuple[str, str, int]:
    if route == "private":
        return (
            settings.aegis_private_model_endpoint,
            settings.aegis_private_model_name,
            settings.aegis_private_model_timeout,
        )
    if route == "public":
        return (
            settings.aegis_public_model_endpoint,
            settings.aegis_public_model_name,
            settings.aegis_public_model_timeout,
        )
    return (
        settings.aegis_model_endpoint,
        settings.aegis_model_name,
        settings.aegis_model_timeout,
    )


def generate_text_routed(prompt_text: str, route_hint: Dict[str, Any] | None = None) -> ModelRouteResult:
    privacy_score, reasons = _privacy_score(prompt_text, route_hint=route_hint)
    route = select_model_route(prompt_text, route_hint=route_hint)
    endpoint, model_name, timeout = _route_target(route)

    outbound = prompt_text
    anonymized = False
    if route == "public" and settings.aegis_public_anonymize_enabled:
        outbound = anonymize_for_public_model(prompt_text)
        anonymized = outbound != prompt_text

    payload: Dict[str, Any] = {
        "model": model_name,
        "temperature": 0.1,
        "max_tokens": settings.aegis_model_max_tokens,
        "messages": [
            {"role": "system", "content": settings.aegis_model_system_prompt},
            {"role": "user", "content": outbound},
        ],
    }
    with httpx.Client(timeout=timeout) as client:
        resp = client.post(endpoint, json=payload)
        resp.raise_for_status()
        text = _extract_content(resp.json()).strip()
        if text:
            return ModelRouteResult(
                text=text,
                route=route,
                endpoint=endpoint,
                model=model_name,
                anonymized=anonymized,
                privacy_score=float(privacy_score),
                reasons=reasons,
            )
        raise RuntimeError("Model returned empty content")


def generate_text(prompt_text: str, route_hint: Dict[str, Any] | None = None, return_meta: bool = False):
    routed = generate_text_routed(prompt_text, route_hint=route_hint)
    if return_meta:
        return routed.text, {
            "route": routed.route,
            "endpoint": routed.endpoint,
            "model": routed.model,
            "anonymized": routed.anonymized,
            "privacy_score": routed.privacy_score,
            "reasons": routed.reasons,
        }
    return routed.text
