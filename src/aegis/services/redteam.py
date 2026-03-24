from __future__ import annotations

from pathlib import Path
from typing import Any, Dict
from uuid import uuid4

import yaml


def _resolve_path(path: str) -> Path:
    p = Path(path)
    if p.is_absolute():
        return p
    return Path(__file__).resolve().parents[3] / path


def run_redteam_suite(runtime, dataset_path: str) -> Dict[str, Any]:
    path = _resolve_path(dataset_path)
    payload = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    cases = payload.get("cases") or []
    results = []
    passed = 0
    failed = 0
    for case in cases:
        kind = case.get("kind")
        session_id = f"redteam-{uuid4()}"
        runtime.store.create_session(session_id)
        ok = True
        actual: Dict[str, Any] = {}
        try:
            if kind == "message":
                guarded = runtime.guard_user_input(session_id=session_id, content=case.get("content", ""), metadata={"source": "redteam"})
                actions = []
                if guarded.get("blocked"):
                    actions.append("block")
                if guarded.get("require_approval"):
                    actions.append("require_approval")
                if guarded.get("allowed") and guarded.get("risk_score", 0) > 0:
                    actions.append("warn")
                actual = {"actions": actions, "risk_score": guarded.get("risk_score", 0.0)}
                for expected in case.get("expected_actions") or []:
                    ok = ok and expected in actions
                for unexpected in case.get("expected_not_actions") or []:
                    ok = ok and unexpected not in actions
                if "expected_risk_min" in case:
                    ok = ok and float(actual["risk_score"]) >= float(case["expected_risk_min"])
            elif kind == "tool":
                result = runtime.handle_tool_call(
                    session_id=session_id,
                    tool_name=case.get("tool_name", ""),
                    payload=case.get("payload") or {},
                    environment=case.get("environment"),
                    allowlist=[],
                    denylist=[],
                    filesystem_root=None,
                )
                actual = result
                expected = case.get("expected") or {}
                for key, value in expected.items():
                    if key == "message_contains":
                        ok = ok and value.lower() in str(result.get("message", "")).lower()
                    else:
                        ok = ok and result.get(key) == value
            elif kind == "policy_eval":
                decision = runtime.policy_engine.evaluate(
                    text=case.get("content", ""),
                    stage=case.get("stage", "prellm"),
                    detectors=runtime.detectors,
                    context={"labels": [], "metadata": {"source": "redteam"}},
                )
                actual = decision.to_dict()
                expected = case.get("expected") or {}
                for key, value in expected.items():
                    ok = ok and actual.get(key) == value
        except Exception as exc:
            ok = False
            actual = {"error": str(exc)}
        if ok:
            passed += 1
        else:
            failed += 1
        results.append({"id": case.get("id"), "kind": kind, "passed": ok, "actual": actual})
    return {
        "dataset": str(path),
        "total": len(results),
        "passed": passed,
        "failed": failed,
        "pass_rate": (float(passed) / float(len(results))) if results else 0.0,
        "results": results,
    }
