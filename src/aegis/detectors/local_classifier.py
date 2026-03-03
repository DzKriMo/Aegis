from __future__ import annotations

import json
import math
import re
from pathlib import Path
from typing import Dict, Any
import numpy as np

from ..config import settings
from .llm_client import classify_text

_TOKEN_RE = re.compile(r"[a-z0-9_]+")
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


def classify_guardrail_label(text: str) -> Dict[str, Any]:
    if not settings.aegis_local_classifier_enabled:
        return {"enabled": False, "label": "ALLOW", "confidence": 0.0, "scores": {}}

    model = _load_model()
    if model is None:
        return {
            "enabled": True,
            "label": "ALLOW",
            "confidence": 0.0,
            "scores": {},
            "__error__": _MODEL_ERR or "model_load_failed",
        }

    model_type = str(model.get("model_type", "naive_bayes"))
    try:
        if model_type in {"tfidf_lr", "logreg_tfidf"}:
            probs = _lr_predict(model, text)
        elif model_type in {"stack_lgbm"}:
            probs = _stack_predict(model, text)
        else:
            probs = _nb_predict(model, text)
    except Exception as exc:
        return {
            "enabled": True,
            "label": "ALLOW",
            "confidence": 0.0,
            "scores": {},
            "__error__": f"inference_failed:{exc}",
        }

    label = max(probs, key=probs.get)
    conf = float(probs[label])
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
        "model_type": model_type,
        "uncertain": uncertain,
        "appeal": appeal,
    }
