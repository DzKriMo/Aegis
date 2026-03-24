from __future__ import annotations

import json
import math
import re
from pathlib import Path
from typing import Dict, Any
import numpy as np

from ..config import settings
from .llm_client import classify_text
from .simple import (
    INJECTION_PATTERNS,
    JAILBREAK_PATTERNS,
    EXFIL_PATTERNS,
    SECRET_PATTERNS,
    POLICY_VIOLATION,
    PII_PATTERNS,
    DATA_LEAKAGE,
    GOAL_HIJACK,
    INTERNAL_PROMPT_EXTRACTION_PATTERNS,
    HIGH_RISK_ABUSE_PATTERNS,
)

_TOKEN_RE = re.compile(r"[a-z0-9_]+")
_OBVIOUSLY_SAFE_RE = re.compile(
    r"^\s*(?:hi|hello|hey|yo|sup|thanks|thank you|ok|okay|cool|nice|test|ping|good morning|good afternoon|good evening)(?:[!.?]+)?\s*$",
    re.IGNORECASE,
)
_MODEL_CACHE: Dict[str, Any] | None = None
_MODEL_ERR: str | None = None


def _tokenize(text: str) -> list[str]:
    return _TOKEN_RE.findall((text or "").lower())


def _resolve_model_path() -> Path:
    raw = settings.aegis_local_classifier_path or "models/guardrail_nb.json"
    p = Path(raw)
    if p.is_absolute():
        return p
    return Path(__file__).resolve().parents[3] / p


def _load_model() -> Dict[str, Any] | None:
    global _MODEL_CACHE, _MODEL_ERR
    if _MODEL_CACHE is not None:
        return _MODEL_CACHE
    if _MODEL_ERR is not None:
        return None
    path = _resolve_model_path()
    if not path.exists():
        _MODEL_ERR = f"model_not_found:{path}"
        return None
    try:
        if path.suffix.lower() == ".joblib":
            try:
                import joblib  # type: ignore
            except Exception as exc:
                _MODEL_ERR = f"joblib_unavailable:{exc}"
                return None
            obj = joblib.load(path)
            if isinstance(obj, dict):
                _MODEL_CACHE = obj
            else:
                _MODEL_CACHE = {"model_type": "tfidf_lr", "pipeline": obj}
            return _MODEL_CACHE
        _MODEL_CACHE = json.loads(path.read_text(encoding="utf-8"))
        return _MODEL_CACHE
    except Exception as exc:
        _MODEL_ERR = str(exc)
        return None


def _log_score(tokens: list[str], class_name: str, model: Dict[str, Any]) -> float:
    priors = model.get("class_priors", {})
    likelihoods = model.get("likelihoods", {})
    default = model.get("default_log_likelihood", {})

    prior = float(priors.get(class_name, 1e-12))
    score = math.log(max(prior, 1e-12))
    ll = likelihoods.get(class_name, {})
    dll = float(default.get(class_name, -30.0))
    for t in tokens:
        score += float(ll.get(t, dll))
    return score


def _softmax(logits: Dict[str, float]) -> Dict[str, float]:
    m = max(logits.values())
    ex = {k: math.exp(v - m) for k, v in logits.items()}
    z = sum(ex.values()) or 1.0
    return {k: v / z for k, v in ex.items()}


def _nb_predict(model: Dict[str, Any], text: str) -> Dict[str, float]:
    classes = model.get("classes", ["ALLOW", "WARN", "BLOCK"])
    tokens = _tokenize(text)
    logits = {c: _log_score(tokens, c, model) for c in classes}
    return _softmax(logits)


def _lr_predict(model: Dict[str, Any], text: str) -> Dict[str, float]:
    pipeline = model.get("pipeline")
    if pipeline is None:
        raise RuntimeError("tfidf_lr model missing pipeline")
    probs = pipeline.predict_proba([text])[0]
    classes = list(getattr(pipeline, "classes_", ["ALLOW", "WARN", "BLOCK"]))
    return {str(c): float(p) for c, p in zip(classes, probs)}


def _stack_predict(model: Dict[str, Any], text: str) -> Dict[str, float]:
    lr = model.get("lr_pipeline")
    lgbm = model.get("lgbm_model")
    classes = [str(c) for c in model.get("classes", ["ALLOW", "WARN", "BLOCK"])]
    if lr is None or lgbm is None:
        raise RuntimeError("stack_lgbm model missing lr_pipeline/lgbm_model")
    lr_probs = lr.predict_proba([text])[0]
    low = (text or "").lower()
    feats = np.array(
        [[
            float(lr_probs[0]),
            float(lr_probs[1]) if len(lr_probs) > 1 else 0.0,
            float(lr_probs[2]) if len(lr_probs) > 2 else 0.0,
            1.0 if "system prompt" in low else 0.0,
            1.0 if "ignore previous instructions" in low else 0.0,
            1.0 if "api key" in low or "/etc/passwd" in low else 0.0,
            1.0 if "rm -rf" in low or "reverse shell" in low else 0.0,
            min(len(low), 4096) / 4096.0,
        ]]
    )
    probs = lgbm.predict_proba(feats)[0]
    return {c: float(p) for c, p in zip(classes, probs)}


def _llm_appeal_label(text: str) -> Dict[str, Any]:
    llm = classify_text(text)
    high = any(
        bool(llm.get(k, False))
        for k in ("prompt_injection", "jailbreak", "goal_hijack", "exfiltration", "secrets", "policy_violation")
    )
    medium = any(bool(llm.get(k, False)) for k in ("data_leakage", "pii"))
    if high:
        return {"label": "BLOCK", "confidence": 0.66, "source": "llm_appeal", "classification": llm}
    if medium:
        return {"label": "WARN", "confidence": 0.56, "source": "llm_appeal", "classification": llm}
    return {"label": "ALLOW", "confidence": 0.55, "source": "llm_appeal", "classification": llm}


def _is_obviously_safe_text(text: str) -> bool:
    normalized = " ".join(str(text or "").strip().split())
    if not normalized or len(normalized) > 48:
        return False
    if any(ch.isdigit() for ch in normalized):
        return False
    if any(token in normalized.lower() for token in ("env", "token", "secret", "system prompt", "ignore previous", "passwd", "api key")):
        return False
    return bool(_OBVIOUSLY_SAFE_RE.fullmatch(normalized))


def _match_any(patterns: list[str], text: str) -> bool:
    return any(re.search(pattern, text, re.IGNORECASE) for pattern in patterns)


def _looks_like_pan(value: str) -> bool:
    digits = re.sub(r"\D", "", value or "")
    if len(digits) < 13 or len(digits) > 19:
        return False
    total = 0
    reverse = digits[::-1]
    for idx, ch in enumerate(reverse):
        n = ord(ch) - ord("0")
        if idx % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def _hybrid_predict(text: str) -> Dict[str, Any]:
    lowered = str(text or "").strip().lower()
    reasons: list[str] = []

    block_checks = [
        ("prompt_injection", INJECTION_PATTERNS),
        ("jailbreak", JAILBREAK_PATTERNS),
        ("goal_hijack", GOAL_HIJACK),
        ("internal_prompt_extraction", INTERNAL_PROMPT_EXTRACTION_PATTERNS),
        ("exfiltration", EXFIL_PATTERNS),
        ("secrets", SECRET_PATTERNS),
        ("policy_violation", POLICY_VIOLATION),
        ("high_risk_abuse", HIGH_RISK_ABUSE_PATTERNS),
    ]
    warn_checks = [
        ("data_leakage", DATA_LEAKAGE),
    ]

    block_hits = [name for name, patterns in block_checks if _match_any(patterns, lowered)]
    warn_hits = [name for name, patterns in warn_checks if _match_any(patterns, lowered)]

    if re.search(r"\bwhat(?:'s| is)?\b.{0,24}\b(?:the )?content(?:s)?\b.{0,24}\b(?:of|inside|in)\b.{0,16}\b(?:env|environment|\.env)\b", lowered, re.IGNORECASE):
        block_hits.append("exfiltration.content_request")
    if re.search(r"\bforget\b.{0,24}\b(?:all|any)\b.{0,24}\b(?:above|previous|prior)\b", lowered, re.IGNORECASE):
        block_hits.append("prompt_injection.forget_above")

    if re.search(PII_PATTERNS[0], lowered):
        warn_hits.append("pii.ssn")
    if any(_looks_like_pan(m.group(0)) for m in re.finditer(PII_PATTERNS[1], lowered)):
        warn_hits.append("pii.card")

    reasons.extend(block_hits)
    reasons.extend(hit for hit in warn_hits if hit not in reasons)

    if _is_obviously_safe_text(text):
        return {
            "label": "ALLOW",
            "confidence": 0.97,
            "scores": {"ALLOW": 0.97, "BLOCK": 0.02, "WARN": 0.01},
            "reasons": [],
        }

    token_count = len(_tokenize(lowered))
    if block_hits:
        confidence = min(0.82 + 0.06 * min(len(block_hits), 2), 0.97)
        warn_score = max(0.02, 0.10 - 0.02 * len(block_hits))
        allow_score = max(0.01, 1.0 - confidence - warn_score)
        return {
            "label": "BLOCK",
            "confidence": round(confidence, 6),
            "scores": {
                "ALLOW": round(allow_score, 6),
                "BLOCK": round(confidence, 6),
                "WARN": round(warn_score, 6),
            },
            "reasons": reasons,
        }
    if warn_hits:
        confidence = min(0.72 + 0.05 * min(len(warn_hits), 3), 0.9)
        block_score = 0.05 if any(hit.startswith("pii.") for hit in warn_hits) else 0.03
        allow_score = max(0.05, 1.0 - confidence - block_score)
        return {
            "label": "WARN",
            "confidence": round(confidence, 6),
            "scores": {
                "ALLOW": round(allow_score, 6),
                "BLOCK": round(block_score, 6),
                "WARN": round(confidence, 6),
            },
            "reasons": reasons,
        }

    if token_count <= 3:
        allow_conf = 0.94
    elif token_count <= 10:
        allow_conf = 0.89
    else:
        allow_conf = 0.84
    return {
        "label": "ALLOW",
        "confidence": round(allow_conf, 6),
        "scores": {
            "ALLOW": round(allow_conf, 6),
            "BLOCK": round((1.0 - allow_conf) * 0.55, 6),
            "WARN": round((1.0 - allow_conf) * 0.45, 6),
        },
        "reasons": [],
    }


def classify_guardrail_label(text: str) -> Dict[str, Any]:
    if not settings.aegis_local_classifier_enabled:
        return {"enabled": False, "label": "ALLOW", "confidence": 0.0, "scores": {}}

    hybrid = _hybrid_predict(text)
    label = str(hybrid["label"])
    conf = float(hybrid["confidence"])
    probs = dict(hybrid["scores"])
    uncertain = conf < float(settings.aegis_local_appeal_conf_threshold)
    appeal = None
    if settings.aegis_local_appeal_llm_enabled and settings.aegis_llm_enabled and uncertain:
        try:
            appeal = _llm_appeal_label(text)
            # Only escalate severity from appeal court.
            rank = {"ALLOW": 0, "WARN": 1, "BLOCK": 2}
            if rank.get(str(appeal["label"]), 0) > rank.get(label, 0):
                label = str(appeal["label"])
                conf = max(conf, float(appeal.get("confidence", conf)))
        except Exception as exc:
            appeal = {"__error__": str(exc)}

    return {
        "enabled": True,
        "label": label,
        "confidence": round(conf, 6),
        "scores": {k: round(float(v), 6) for k, v in probs.items()},
        "model_type": "hybrid_rules_v2",
        "uncertain": uncertain,
        "appeal": appeal,
        "reasons": list(hybrid.get("reasons") or []),
    }
