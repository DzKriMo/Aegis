from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from uuid import uuid4
from typing import List, Dict, Any, Optional
from pathlib import Path
import json

from ..auth.api_key import require_api_key
from ..runtime.runner import GuardedRuntime
from ..storage.store import InMemoryStore
from ..storage.db_store import DbStore
from ..config import settings
from ..policies.loader import save_policies
from ..storage.registry import save_policies_to_db, save_tool_policies_to_db, load_tool_policies_from_db
from ..runtime.tool_registry import get_all_tool_policies

router = APIRouter()

store = DbStore() if settings.aegis_db_enabled else InMemoryStore()
runtime = GuardedRuntime(store=store)

class CreateSessionResponse(BaseModel):
    session_id: str

class MessageRequest(BaseModel):
    content: str
    metadata: Dict[str, Any] = {}

    # Multi-tenant context
    tenant_id: Optional[str] = None
    role: Optional[str] = None
    environment: Optional[str] = None  # dev/prod
    labels: List[str] = Field(default_factory=list)

    # Optional network policy hints
    url_allowlist: List[str] = Field(default_factory=list)
    url_denylist: List[str] = Field(default_factory=list)
    urls: List[str] = Field(default_factory=list)

class MessageResponse(BaseModel):
    content: str
    actions: List[str]
    risk_score: float = 0.0
    decision_message: Optional[str] = None
    approval_hash: Optional[str] = None

class ApprovalRequest(BaseModel):
    approval_hash: str

class ToolExecuteRequest(BaseModel):
    tool_name: str
    payload: Dict[str, Any] = {}
    environment: Optional[str] = None
    allowlist: List[str] = Field(default_factory=list)
    denylist: List[str] = Field(default_factory=list)
    filesystem_root: Optional[str] = None
    tenant_id: Optional[str] = None
    role: Optional[str] = None
    labels: List[str] = Field(default_factory=list)

class ToolExecuteResponse(BaseModel):
    allowed: bool
    message: Optional[str] = None
    result: Optional[Dict[str, Any]] = None
    approval_hash: Optional[str] = None

class PolicyUpdateRequest(BaseModel):
    policies: List[Dict[str, Any]]

class ToolPoliciesUpdateRequest(BaseModel):
    tools: Dict[str, Dict[str, Any]]

class ReplayRequest(BaseModel):
    policy_version: Optional[str] = None
    detector_version: Optional[str] = None
    model_hash: Optional[str] = None


def _decision_from_actions(actions: List[str]) -> str:
    s = set(actions or [])
    if "block" in s:
        return "BLOCK"
    if "require_approval" in s:
        return "APPROVAL"
    if "warn" in s:
        return "WARN"
    return "ALLOW"


def _latest_benchmark_payload() -> Dict[str, Any]:
    root = Path(__file__).resolve().parents[3]
    files = sorted((root / "research").glob("benchmark_*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
    for p in files:
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
            if isinstance(data, dict) and isinstance(data.get("metrics"), dict):
                data["_file"] = str(p)
                return data
        except Exception:
            continue
    return {}

@router.post("/sessions", response_model=CreateSessionResponse, dependencies=[Depends(require_api_key)])
def create_session():
    session_id = str(uuid4())
    store.create_session(session_id)
    return CreateSessionResponse(session_id=session_id)

@router.get("/sessions", dependencies=[Depends(require_api_key)])
def list_sessions():
    sessions = store.list_sessions()
    items = []
    for sid, data in sessions.items():
        items.append({"id": sid, "events": len(data.get("events", []))})
    return {"sessions": items}

@router.post("/sessions/{session_id}/messages", response_model=MessageResponse, dependencies=[Depends(require_api_key)])
def send_message(session_id: str, req: MessageRequest):
    if not store.session_exists(session_id):
        raise HTTPException(status_code=404, detail="Session not found")
    result = runtime.handle_user_message(
        session_id=session_id,
        content=req.content,
        metadata=req.metadata,
        tenant_id=req.tenant_id,
        role=req.role,
        environment=req.environment,
        labels=req.labels,
        url_allowlist=req.url_allowlist,
        url_denylist=req.url_denylist,
        urls=req.urls,
    )
    return MessageResponse(
        content=result.output,
        actions=result.actions,
        risk_score=result.risk_score,
        decision_message=result.message,
        approval_hash=result.approval_hash,
    )

@router.post("/sessions/{session_id}/approvals", dependencies=[Depends(require_api_key)])
def approve_action(session_id: str, req: ApprovalRequest):
    if not store.session_exists(session_id):
        raise HTTPException(status_code=404, detail="Session not found")
    ok = store.approve(session_id, req.approval_hash)
    if not ok:
        raise HTTPException(status_code=400, detail="Unknown or expired approval hash")
    return {"approved": True}

@router.post("/sessions/{session_id}/tools/execute", response_model=ToolExecuteResponse, dependencies=[Depends(require_api_key)])
def execute_tool(session_id: str, req: ToolExecuteRequest):
    if not store.session_exists(session_id):
        raise HTTPException(status_code=404, detail="Session not found")
    return runtime.handle_tool_call(
        session_id=session_id,
        tool_name=req.tool_name,
        payload=req.payload,
        environment=req.environment,
        allowlist=req.allowlist,
        denylist=req.denylist,
        filesystem_root=req.filesystem_root,
        tenant_id=req.tenant_id,
        role=req.role,
        labels=req.labels,
    )

@router.get("/sessions/{session_id}", dependencies=[Depends(require_api_key)])
def get_session(session_id: str):
    if not store.session_exists(session_id):
        raise HTTPException(status_code=404, detail="Session not found")
    return store.get_session(session_id)

@router.get("/sessions/{session_id}/risk", dependencies=[Depends(require_api_key)])
def get_session_risk(session_id: str):
    if not store.session_exists(session_id):
        raise HTTPException(status_code=404, detail="Session not found")
    getter = getattr(store, "get_risk_state", None)
    if callable(getter):
        return {"risk_state": getter(session_id)}
    return {"risk_state": {}}


@router.post("/replay/session/{session_id}", dependencies=[Depends(require_api_key)])
def replay_session(session_id: str, req: ReplayRequest):
    if not store.session_exists(session_id):
        raise HTTPException(status_code=404, detail="Session not found")
    original = store.get_session(session_id)
    events = list(original.get("events") or [])
    replay_session_id = f"replay-{uuid4()}"
    store.create_session(replay_session_id)

    replayed_messages = 0
    replayed_tools = 0
    mismatches = 0
    checks = 0

    for ev in events:
        stage = str(ev.get("stage", ""))
        if stage == "prellm" and isinstance(ev.get("decision"), dict) and isinstance(ev.get("content"), str):
            checks += 1
            result = runtime.handle_user_message(
                session_id=replay_session_id,
                content=ev.get("content", ""),
                metadata={"replay": True, "source_session": session_id},
            )
            replayed_messages += 1
            old_dec = ev["decision"]
            old_label = "BLOCK" if old_dec.get("blocked") else ("WARN" if old_dec.get("warn") else ("APPROVAL" if old_dec.get("require_approval") else "ALLOW"))
            new_label = _decision_from_actions(result.actions)
            if old_label != new_label:
                mismatches += 1
        elif stage == "tool_pre" and isinstance(ev.get("tool"), str):
            checks += 1
            result = runtime.handle_tool_call(
                session_id=replay_session_id,
                tool_name=ev.get("tool", ""),
                payload=ev.get("payload") or {},
                environment=None,
                allowlist=[],
                denylist=[],
                filesystem_root=None,
            )
            replayed_tools += 1
            old_decision = ev.get("decision") or {}
            old_label = "BLOCK" if old_decision.get("blocked") else "ALLOW"
            new_label = "ALLOW" if bool(result.get("allowed", False)) else "BLOCK"
            if old_label != new_label:
                mismatches += 1

    replay_risk = {}
    getter = getattr(store, "get_risk_state", None)
    if callable(getter):
        replay_risk = getter(replay_session_id)

    return {
        "source_session_id": session_id,
        "replay_session_id": replay_session_id,
        "replayed_messages": replayed_messages,
        "replayed_tools": replayed_tools,
        "checks": checks,
        "mismatches": mismatches,
        "drift_rate": (float(mismatches) / float(checks)) if checks else 0.0,
        "policy_version": req.policy_version or settings.aegis_policy_version,
        "detector_version": req.detector_version or settings.aegis_detector_version,
        "model_hash": req.model_hash or settings.aegis_model_hash,
        "replay_risk_state": replay_risk,
    }


@router.get("/metrics/cost-risk", dependencies=[Depends(require_api_key)])
def cost_risk_metrics():
    data = _latest_benchmark_payload()
    metrics = (data or {}).get("metrics") or {}
    confusion = metrics.get("confusion") or {}

    false_allow = int(((confusion.get("BLOCK") or {}).get("ALLOW", 0) or 0))
    false_warn = int(((confusion.get("ALLOW") or {}).get("WARN", 0) or 0) + ((confusion.get("BLOCK") or {}).get("WARN", 0) or 0))
    false_block = int(((confusion.get("ALLOW") or {}).get("BLOCK", 0) or 0))
    weighted_error = false_allow * 5 + false_warn * 2 + false_block * 1

    sessions = store.list_sessions()
    total_events = 0
    tool_events = 0
    abuse_blocks = 0
    quarantine_events = 0
    for sid in sessions.keys():
        sess = store.get_session(sid)
        evs = list(sess.get("events") or [])
        total_events += len(evs)
        for ev in evs:
            st = str(ev.get("stage", ""))
            if st.startswith("tool_") or st in {"tool_risk_fusion", "tool_output_sanitizer"}:
                tool_events += 1
            if st == "tool_risk_fusion" and str(ev.get("decision", "")).lower() == "block":
                abuse_blocks += 1
            if st == "risk.quarantine":
                quarantine_events += 1

    tool_abuse_probability = (float(abuse_blocks) / float(tool_events)) if tool_events else 0.0
    friction_estimate = false_block + false_warn

    return {
        "benchmark_file": data.get("_file"),
        "false_allow": false_allow,
        "false_warn": false_warn,
        "false_block": false_block,
        "risk_weighted_error": weighted_error,
        "false_allow_cost_estimate": false_allow * 5,
        "false_block_friction_estimate": friction_estimate,
        "tool_abuse_probability": tool_abuse_probability,
        "quarantine_events": quarantine_events,
        "policy_version": settings.aegis_policy_version,
        "detector_version": settings.aegis_detector_version,
        "model_hash": settings.aegis_model_hash,
    }

@router.get("/policies", dependencies=[Depends(require_api_key)])
def get_policies():
    return {"policies": runtime.policy_engine.policies}

@router.put("/policies", dependencies=[Depends(require_api_key)])
def update_policies(req: PolicyUpdateRequest):
    if settings.aegis_db_enabled:
        try:
            save_policies_to_db(req.policies)
        except Exception as exc:
            raise HTTPException(status_code=500, detail=f"DB save failed: {exc}")
    else:
        save_policies(req.policies)
    runtime.reload_policies()
    return {"ok": True, "count": len(req.policies)}

@router.get("/tool-policies", dependencies=[Depends(require_api_key)])
def get_tool_policies():
    if settings.aegis_db_enabled:
        try:
            tools = load_tool_policies_from_db()
            return {"tools": tools}
        except Exception as exc:
            raise HTTPException(status_code=500, detail=f"DB load failed: {exc}")
    tools = {}
    for name, t in get_all_tool_policies().items():
        tools[name] = {
            "allowed_envs": t.allowed_envs,
            "allowlist": t.allowlist,
            "timeout_seconds": t.timeout_seconds,
            "max_bytes": t.max_bytes,
        }
    return {"tools": tools}

@router.put("/tool-policies", dependencies=[Depends(require_api_key)])
def update_tool_policies(req: ToolPoliciesUpdateRequest):
    if not settings.aegis_db_enabled:
        raise HTTPException(status_code=501, detail="Tool policy editing requires DB")
    try:
        save_tool_policies_to_db(req.tools)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"DB save failed: {exc}")
    return {"ok": True, "count": len(req.tools)}
