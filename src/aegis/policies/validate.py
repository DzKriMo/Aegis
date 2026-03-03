from __future__ import annotations

from typing import Any, Dict, List


_VALID_STAGES = {"prellm", "postllm", "tool_pre", "tool_post"}
_VALID_ACTIONS = {"block", "warn", "redact", "approve", "modify"}
_VALID_MATCH_KEYS = {"detector", "semantic", "regex", "label", "role", "environment", "tenant_id"}


def _is_number(v: Any) -> bool:
    return isinstance(v, (int, float))


def validate_policies_schema(policies: List[Dict[str, Any]]) -> None:
    if not isinstance(policies, list):
        raise ValueError("Policies payload must be a list.")
    if not policies:
        raise ValueError("Policies list is empty.")

    seen_ids: set[str] = set()
    for i, rule in enumerate(policies, start=1):
        if not isinstance(rule, dict):
            raise ValueError(f"Policy #{i}: rule must be an object.")

        rid = rule.get("id")
        if not isinstance(rid, str) or not rid.strip():
            raise ValueError(f"Policy #{i}: missing/invalid 'id'.")
        if rid in seen_ids:
            raise ValueError(f"Policy '{rid}': duplicate id.")
        seen_ids.add(rid)

        stage = rule.get("stage")
        if stage not in _VALID_STAGES:
            raise ValueError(f"Policy '{rid}': invalid stage '{stage}'.")

        action = rule.get("action")
        if action not in _VALID_ACTIONS:
            raise ValueError(f"Policy '{rid}': invalid action '{action}'.")

        if "risk" in rule and (not _is_number(rule["risk"]) or float(rule["risk"]) < 0.0):
            raise ValueError(f"Policy '{rid}': risk must be a non-negative number.")

        match = rule.get("match")
        if not isinstance(match, dict):
            raise ValueError(f"Policy '{rid}': missing/invalid 'match'.")
        any_list = match.get("any")
        if not isinstance(any_list, list) or not any_list:
            raise ValueError(f"Policy '{rid}': match.any must be a non-empty list.")

        for j, cond in enumerate(any_list, start=1):
            if not isinstance(cond, dict):
                raise ValueError(f"Policy '{rid}': match.any[{j}] must be an object.")
            unknown = set(cond.keys()) - _VALID_MATCH_KEYS
            if unknown:
                raise ValueError(f"Policy '{rid}': match.any[{j}] has unknown keys {sorted(unknown)}.")

            if "detector" in cond and not isinstance(cond["detector"], str):
                raise ValueError(f"Policy '{rid}': detector must be a string.")
            if "regex" in cond and not isinstance(cond["regex"], str):
                raise ValueError(f"Policy '{rid}': regex must be a string.")
            if "label" in cond and not isinstance(cond["label"], str):
                raise ValueError(f"Policy '{rid}': label must be a string.")
            if "role" in cond and not isinstance(cond["role"], str):
                raise ValueError(f"Policy '{rid}': role must be a string.")
            if "environment" in cond and not isinstance(cond["environment"], str):
                raise ValueError(f"Policy '{rid}': environment must be a string.")
            if "tenant_id" in cond and not isinstance(cond["tenant_id"], str):
                raise ValueError(f"Policy '{rid}': tenant_id must be a string.")

            if "semantic" in cond:
                semantic = cond["semantic"]
                if not isinstance(semantic, dict):
                    raise ValueError(f"Policy '{rid}': semantic must be an object.")
                category = semantic.get("category")
                threshold = semantic.get("threshold")
                if not isinstance(category, str) or not category.strip():
                    raise ValueError(f"Policy '{rid}': semantic.category must be a non-empty string.")
                if threshold is not None and (not _is_number(threshold) or not (0.0 <= float(threshold) <= 1.0)):
                    raise ValueError(f"Policy '{rid}': semantic.threshold must be in [0, 1].")
