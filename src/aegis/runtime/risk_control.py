from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict
import math

from ..config import settings


TOOL_RISK_PROFILE: Dict[str, Dict[str, Any]] = {
    "json_transform": {"risk_weight": 0.1, "data_sensitivity_level": 0.1, "network_exposure_level": 0.0, "destructive_flag": False},
    "http_fetch": {"risk_weight": 0.6, "data_sensitivity_level": 0.4, "network_exposure_level": 0.8, "destructive_flag": False},
    "filesystem_read": {"risk_weight": 0.7, "data_sensitivity_level": 0.8, "network_exposure_level": 0.0, "destructive_flag": False},
    "shell": {"risk_weight": 1.0, "data_sensitivity_level": 0.9, "network_exposure_level": 0.9, "destructive_flag": True},
}

_HIGH_RISK_TOOLS = {"shell", "filesystem_read", "http_fetch"}


@dataclass
class DynamicThresholds:
    block: float
    warn: float
    ood_score: float
    ood_entropy: float
    ood_distance: float
    penalty: float


def _clip(v: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, v))


def tool_profile(tool_name: str) -> Dict[str, Any]:
    return dict(TOOL_RISK_PROFILE.get(tool_name, {"risk_weight": 0.5, "data_sensitivity_level": 0.5, "network_exposure_level": 0.5, "destructive_flag": False}))


def tool_risk_modifier(tool_name: str) -> float:
    p = tool_profile(tool_name)
    modifier = float(p["risk_weight"]) + 0.2 * float(p["data_sensitivity_level"]) + 0.2 * float(p["network_exposure_level"])
    if p.get("destructive_flag"):
        modifier += 0.2
    return _clip(modifier, 0.0, 1.5)


def is_sensitive_tool(tool_name: str) -> bool:
    return tool_name in _HIGH_RISK_TOOLS


def ood_metrics(local_cls: Dict[str, Any]) -> Dict[str, float]:
    scores = local_cls.get("scores") or {}
    if not scores:
        return {"ood_score": 0.0, "entropy": 0.0, "distance": 0.0}

    probs = [max(1e-12, float(v)) for v in scores.values()]
    total = sum(probs) or 1.0
    probs = [p / total for p in probs]
    n = len(probs)
    entropy = -sum(p * math.log(p) for p in probs) / (math.log(n) if n > 1 else 1.0)
    top = max(probs)
    distance = 1.0 - top
    ood = _clip(0.6 * entropy + 0.4 * distance, 0.0, 1.0)
    return {"ood_score": ood, "entropy": entropy, "distance": distance}


def dynamic_thresholds(local_cls: Dict[str, Any], risk_state: Dict[str, Any], profile: str, upcoming_tool: str | None = None) -> DynamicThresholds:
    base_block = float(settings.aegis_local_block_threshold)
    base_warn = float(settings.aegis_local_warn_threshold)
    ood = ood_metrics(local_cls)

    penalty = 0.0
    penalty += 0.18 * float(ood["ood_score"])
    if upcoming_tool:
        penalty += 0.12 * min(tool_risk_modifier(upcoming_tool), 1.0)
    if bool(risk_state.get("quarantined", False)):
        penalty += 0.08
    if profile == "strict":
        penalty += 0.04

    block = _clip(base_block - penalty, 0.45, 0.95)
    warn = _clip(base_warn - 0.7 * penalty, 0.35, block - 0.05)
    return DynamicThresholds(
        block=block,
        warn=warn,
        ood_score=float(ood["ood_score"]),
        ood_entropy=float(ood["entropy"]),
        ood_distance=float(ood["distance"]),
        penalty=float(penalty),
    )


def update_trajectory_risk(
    state: Dict[str, Any],
    base_classifier_score: float,
    injection_signal: bool,
    tool_misuse_signal: bool,
    goal_drift_signal: bool,
) -> Dict[str, Any]:
    st = dict(state or {})
    prev = float(st.get("cumulative_risk_score", 0.0) or 0.0)
    inj_count = int(st.get("injection_attempt_count", 0) or 0)
    sensitive_count = int(st.get("sensitive_tool_attempts", 0) or 0)
    drift = float(st.get("goal_drift_score", 0.0) or 0.0)

    if injection_signal:
        inj_count += 1
        drift += 0.2
    if tool_misuse_signal:
        sensitive_count += 1
    if goal_drift_signal:
        drift += 0.15

    risk_t = float(base_classifier_score)
    risk_t += 0.12 if injection_signal else 0.0
    risk_t += 0.15 if tool_misuse_signal else 0.0
    risk_t += 0.25 * prev  # historical decay carry-over
    risk_t += min(0.2, 0.04 * drift)
    cumulative = _clip(risk_t, 0.0, 1.6)

    st["cumulative_risk_score"] = cumulative
    st["goal_drift_score"] = _clip(drift, 0.0, 3.0)
    st["injection_attempt_count"] = inj_count
    st["sensitive_tool_attempts"] = sensitive_count
    return st


def should_quarantine(state: Dict[str, Any]) -> bool:
    cumulative = float(state.get("cumulative_risk_score", 0.0) or 0.0)
    inj_count = int(state.get("injection_attempt_count", 0) or 0)
    sensitive_count = int(state.get("sensitive_tool_attempts", 0) or 0)
    return cumulative >= float(settings.aegis_quarantine_threshold) or inj_count >= 3 or sensitive_count >= 3
