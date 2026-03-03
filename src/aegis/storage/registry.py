import json
from typing import List, Dict, Any
from sqlalchemy import select, delete

from .db import get_session
from .models import PolicyRecord, ToolPolicyRecord
from ..policies.validate import validate_policies_schema


def load_policies_from_db() -> List[Dict[str, Any]]:
    s = get_session()
    if s is None:
        return []
    rows = s.execute(select(PolicyRecord).where(PolicyRecord.enabled == True)).scalars().all()
    s.close()
    policies = []
    for row in rows:
        policies.append({
            "id": row.name,
            "stage": row.stage,
            "action": row.action,
            "match": json.loads(row.match_json),
            "risk": float(row.risk) if row.risk else 0.0,
        })
    return policies


def load_tool_policies_from_db() -> Dict[str, Dict[str, Any]]:
    s = get_session()
    if s is None:
        return {}
    rows = s.execute(select(ToolPolicyRecord)).scalars().all()
    s.close()
    tools: Dict[str, Dict[str, Any]] = {}
    for row in rows:
        tools[row.name] = {
            "allowed_envs": json.loads(row.allowed_envs) if row.allowed_envs else [],
            "allowlist": json.loads(row.allowlist) if row.allowlist else [],
            "timeout_seconds": int(row.timeout_seconds),
            "max_bytes": int(row.max_bytes) if row.max_bytes else None,
        }
    return tools


def save_policies_to_db(policies: List[Dict[str, Any]]):
    validate_policies_schema(policies)
    s = get_session()
    if s is None:
        return
    s.execute(delete(PolicyRecord))
    for p in policies:
        s.add(PolicyRecord(
            name=p.get("id", "unnamed"),
            stage=p.get("stage", ""),
            action=p.get("action", ""),
            match_json=json.dumps(p.get("match", {})),
            risk=str(p.get("risk", "")) if p.get("risk") is not None else None,
            enabled=True,
        ))
    s.commit()
    s.close()


def save_tool_policies_to_db(policies: Dict[str, Dict[str, Any]]):
    s = get_session()
    if s is None:
        return
    s.execute(delete(ToolPolicyRecord))
    for name, p in policies.items():
        s.add(ToolPolicyRecord(
            name=name,
            allowed_envs=json.dumps(p.get("allowed_envs", [])),
            allowlist=json.dumps(p.get("allowlist", [])),
            timeout_seconds=int(p.get("timeout_seconds", 5)),
            max_bytes=p.get("max_bytes"),
        ))
    s.commit()
    s.close()
