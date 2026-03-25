from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Dict, List, Optional
from uuid import uuid4


def _snapshot_dir() -> Path:
    root = Path(__file__).resolve().parents[3]
    path = root / ".tmp" / "policy_snapshots"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _snapshot_path(snapshot_id: str) -> Path:
    return _snapshot_dir() / f"{snapshot_id}.json"


def list_policy_snapshots() -> List[Dict[str, Any]]:
    items: List[Dict[str, Any]] = []
    for path in sorted(_snapshot_dir().glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True):
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        items.append(
            {
                "id": payload.get("id") or path.stem,
                "name": payload.get("name") or path.stem,
                "created_at": payload.get("created_at"),
                "policy_count": len(payload.get("policies") or []),
                "source": payload.get("source") or "manual",
            }
        )
    return items


def load_policy_snapshot(snapshot_id: str) -> Optional[Dict[str, Any]]:
    path = _snapshot_path(snapshot_id)
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def create_policy_snapshot(name: str, policies: List[Dict[str, Any]], source: str = "manual") -> Dict[str, Any]:
    snapshot_id = str(uuid4())
    payload = {
        "id": snapshot_id,
        "name": (name or "Untitled snapshot").strip() or "Untitled snapshot",
        "created_at": int(time.time()),
        "source": source,
        "policies": policies,
    }
    _snapshot_path(snapshot_id).write_text(json.dumps(payload, indent=2, ensure_ascii=True), encoding="utf-8")
    return {
        "id": snapshot_id,
        "name": payload["name"],
        "created_at": payload["created_at"],
        "policy_count": len(policies or []),
        "source": source,
    }
