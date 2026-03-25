from __future__ import annotations

from copy import deepcopy
from typing import Any, Dict, List

from ..config import settings


_TENANT_PACKS: Dict[str, Dict[str, Any]] = {
    "default": {
        "name": "default",
        "description": "Balanced default pack.",
        "labels": [],
        "thresholds": {},
        "force_approval_tools": [],
    },
    "finance-prod": {
        "name": "finance-prod",
        "description": "Conservative controls for financial workflows.",
        "labels": ["CONFIDENTIAL", "FINANCE"],
        "thresholds": {
            "ood_warn_threshold": 0.62,
            "action_risk_approval_threshold": 0.6,
            "action_risk_block_threshold": 0.95,
        },
        "force_approval_tools": ["shell", "http_fetch"],
    },
    "healthcare": {
        "name": "healthcare",
        "description": "Elevated privacy posture for PII-heavy operations.",
        "labels": ["PHI", "CONFIDENTIAL"],
        "thresholds": {
            "ood_warn_threshold": 0.6,
            "action_risk_approval_threshold": 0.58,
        },
        "force_approval_tools": ["filesystem_read", "http_fetch"],
    },
    "research-open": {
        "name": "research-open",
        "description": "Looser pack for exploratory internal research.",
        "labels": ["RESEARCH"],
        "thresholds": {
            "ood_warn_threshold": 0.8,
            "action_risk_approval_threshold": 0.82,
            "action_risk_block_threshold": 1.2,
        },
        "force_approval_tools": [],
    },
}

_PACK_BINDINGS: Dict[str, str] = {
    "prod:finance": "finance-prod",
    "prod:healthcare": "healthcare",
    "dev:research": "research-open",
}

_CONTROL_STATE: Dict[str, Any] = {
    "guardrails_enabled": True,
    "consensus_enabled": True,
    "verifier_model": "",
    "consensus_disagreement_threshold": 1,
    "approval_default_ttl_seconds": 3600,
    "approval_default_scope": "exact",
    "redteam_dataset_path": "tests/data/guardrail_regression_cases.yaml",
}


def _clean_name(value: str) -> str:
    return (value or "").strip()


def get_control_settings() -> Dict[str, Any]:
    return {
        "guardrail_profile": settings.aegis_guardrail_profile,
        "active_model": settings.aegis_model_name,
        "classifier_model": settings.aegis_llm_model,
        "model_enabled": settings.aegis_model_enabled,
        "llm_enabled": settings.aegis_llm_enabled,
        "local_block_threshold": settings.aegis_local_block_threshold,
        "local_warn_threshold": settings.aegis_local_warn_threshold,
        "ood_warn_threshold": settings.aegis_ood_warn_threshold,
        "quarantine_threshold": settings.aegis_quarantine_threshold,
        "action_risk_approval_threshold": settings.aegis_action_risk_approval_threshold,
        "action_risk_block_threshold": settings.aegis_action_risk_block_threshold,
        "stage_disagreement_threshold": settings.aegis_stage_disagreement_threshold,
        **deepcopy(_CONTROL_STATE),
    }


def update_control_settings(patch: Dict[str, Any]) -> Dict[str, Any]:
    allowed_setting_fields = {
        "guardrail_profile": "aegis_guardrail_profile",
        "active_model": "aegis_model_name",
        "classifier_model": "aegis_llm_model",
        "model_enabled": "aegis_model_enabled",
        "llm_enabled": "aegis_llm_enabled",
        "local_block_threshold": "aegis_local_block_threshold",
        "local_warn_threshold": "aegis_local_warn_threshold",
        "ood_warn_threshold": "aegis_ood_warn_threshold",
        "quarantine_threshold": "aegis_quarantine_threshold",
        "action_risk_approval_threshold": "aegis_action_risk_approval_threshold",
        "action_risk_block_threshold": "aegis_action_risk_block_threshold",
        "stage_disagreement_threshold": "aegis_stage_disagreement_threshold",
    }
    for key, attr in allowed_setting_fields.items():
        if key not in patch:
            continue
        value = patch[key]
        if isinstance(getattr(settings, attr), bool):
            setattr(settings, attr, bool(value))
        elif isinstance(getattr(settings, attr), int):
            setattr(settings, attr, int(value))
        elif isinstance(getattr(settings, attr), float):
            setattr(settings, attr, float(value))
        else:
            setattr(settings, attr, _clean_name(str(value)))
    for key in list(_CONTROL_STATE.keys()):
        if key in patch:
            _CONTROL_STATE[key] = patch[key]
    return get_control_settings()


def get_tenant_packs() -> Dict[str, Any]:
    return {"packs": deepcopy(_TENANT_PACKS), "bindings": deepcopy(_PACK_BINDINGS)}


def update_tenant_packs(packs: Dict[str, Any], bindings: Dict[str, str] | None = None) -> Dict[str, Any]:
    if packs:
        _TENANT_PACKS.clear()
        _TENANT_PACKS.update(deepcopy(packs))
    if bindings is not None:
        _PACK_BINDINGS.clear()
        _PACK_BINDINGS.update({str(k): str(v) for k, v in bindings.items()})
    return get_tenant_packs()


def resolve_tenant_pack(tenant_id: str | None, environment: str | None, metadata: Dict[str, Any] | None = None) -> Dict[str, Any]:
    metadata = metadata or {}
    explicit = _clean_name(str(metadata.get("tenant_pack") or ""))
    if explicit and explicit in _TENANT_PACKS:
        return deepcopy(_TENANT_PACKS[explicit])
    env = _clean_name(environment or "")
    tenant = _clean_name(tenant_id or "")
    if env and tenant:
        bound = _PACK_BINDINGS.get(f"{env}:{tenant}")
        if bound and bound in _TENANT_PACKS:
            return deepcopy(_TENANT_PACKS[bound])
    return deepcopy(_TENANT_PACKS["default"])


def pack_threshold(pack: Dict[str, Any], key: str, fallback: float | int) -> float | int:
    thresholds = pack.get("thresholds") if isinstance(pack.get("thresholds"), dict) else {}
    return thresholds.get(key, fallback)


def force_approval_for_tool(pack: Dict[str, Any], tool_name: str) -> bool:
    return tool_name in (pack.get("force_approval_tools") or [])
