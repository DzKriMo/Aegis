import os
import yaml
from ..config import settings
from ..storage.registry import load_policies_from_db
from .validate import validate_policies_schema


def _resolve_path(path: str) -> str:
    if os.path.isabs(path):
        return path
    # project root = .../Aegis
    base = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
    return os.path.join(base, path)


def _validate_loaded_policies(policies):
    validate_policies_schema(policies)


def load_policies():
    strict = bool(settings.aegis_strict_policy_load)
    if settings.aegis_db_enabled:
        try:
            policies = load_policies_from_db()
            if policies:
                _validate_loaded_policies(policies)
                return policies
        except Exception:
            if settings.aegis_fail_closed or strict:
                raise RuntimeError("Policy load failed from DB while fail-closed is enabled")

    path = _resolve_path(settings.policy_path)
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        policies = data.get("policies", [])
        _validate_loaded_policies(policies)
        return policies
    except Exception as exc:
        if settings.aegis_fail_closed or strict:
            raise RuntimeError(f"Policy load failed from file: {exc}")
        return []


def save_policies(policies):
    _validate_loaded_policies(policies)
    path = _resolve_path(settings.policy_path)
    payload = {"policies": policies}
    with open(path, "w", encoding="utf-8") as f:
        yaml.safe_dump(payload, f, sort_keys=False)
