from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from uuid import uuid4
from typing import List, Dict, Any, Optional
from pathlib import Path
import json
import re

from ..auth.api_key import require_api_key
from ..runtime.runner import GuardedRuntime
from ..storage.store import InMemoryStore
from ..storage.db_store import DbStore
from ..config import settings
from ..policies.loader import save_policies
from ..storage.registry import save_policies_to_db, save_tool_policies_to_db, load_tool_policies_from_db
from ..runtime.tool_registry import get_all_tool_policies
from ..services.ollama import list_ollama_models, ollama_base_url
from ..services.control_plane import get_control_settings, get_tenant_packs, update_control_settings, update_tenant_packs
from ..services.redteam import run_redteam_suite
from ..services.policy_snapshots import create_policy_snapshot, list_policy_snapshots, load_policy_snapshot
from ..policies.engine import PolicyEngine
from ..agent.krimo_service import AgentMemory, LocalAegisClient, run_turn

router = APIRouter()

store = DbStore() if settings.aegis_db_enabled else InMemoryStore()
runtime = GuardedRuntime(store=store)
agent_memories: Dict[str, AgentMemory] = {}

class CreateSessionResponse(BaseModel):
    session_id: str

class MessageRequest(BaseModel):
    content: str
    metadata: Dict[str, Any] = {}
    model: Optional[str] = None

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


class GuardInputResponse(BaseModel):
    allowed: bool
    blocked: bool
    require_approval: bool
    sanitized_content: Optional[str] = None
    risk_score: float = 0.0
    message: Optional[str] = None
    approval_hash: Optional[str] = None


class GuardOutputRequest(BaseModel):
    content: str
    metadata: Dict[str, Any] = {}
    tenant_id: Optional[str] = None
    role: Optional[str] = None
    environment: Optional[str] = None
    labels: List[str] = Field(default_factory=list)


class GuardOutputResponse(BaseModel):
    allowed: bool
    blocked: bool
    require_approval: bool
    sanitized_output: Optional[str] = None
    risk_score: float = 0.0
    message: Optional[str] = None
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


class ToolGuardPreRequest(BaseModel):
    tool_name: str
    payload: Dict[str, Any] = {}
    environment: Optional[str] = None
    tenant_id: Optional[str] = None
    role: Optional[str] = None
    labels: List[str] = Field(default_factory=list)


class ToolGuardPreResponse(BaseModel):
    allowed: bool
    blocked: bool
    require_approval: bool
    message: Optional[str] = None
    risk_score: float = 0.0
    approval_hash: Optional[str] = None
    sanitized_payload: Optional[Dict[str, Any]] = None


class ToolGuardPostRequest(BaseModel):
    tool_name: str
    result: Any = {}
    environment: Optional[str] = None
    tenant_id: Optional[str] = None
    role: Optional[str] = None
    labels: List[str] = Field(default_factory=list)


class ToolGuardPostResponse(BaseModel):
    allowed: bool
    blocked: bool
    require_approval: bool
    message: Optional[str] = None
    risk_score: float = 0.0
    approval_hash: Optional[str] = None
    sanitized_result: Optional[Any] = None

class PolicyUpdateRequest(BaseModel):
    policies: List[Dict[str, Any]]

class ToolPoliciesUpdateRequest(BaseModel):
    tools: Dict[str, Dict[str, Any]]

class ReplayRequest(BaseModel):
    policy_version: Optional[str] = None
    detector_version: Optional[str] = None
    model_hash: Optional[str] = None


class ActiveModelRequest(BaseModel):
    model: str
    update_classifier: bool = True


class ApprovalDecisionRequest(BaseModel):
    approval_hash: str
    actor: str = "dashboard"
    scope: str = "exact"
    expires_in_seconds: int = 3600
    reusable: bool = True
    reason: Optional[str] = None


class ControlSettingsRequest(BaseModel):
    patch: Dict[str, Any]


class TenantPackUpdateRequest(BaseModel):
    packs: Dict[str, Dict[str, Any]]
    bindings: Dict[str, str] = Field(default_factory=dict)


class PolicySimulateRequest(BaseModel):
    content: str
    stage: str
    candidate_policies: Optional[List[Dict[str, Any]]] = None
    tenant_id: Optional[str] = None
    role: Optional[str] = None
    environment: Optional[str] = None
    labels: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class RedTeamRunRequest(BaseModel):
    dataset_path: Optional[str] = None


class PolicySnapshotCreateRequest(BaseModel):
    name: str
    policies: Optional[List[Dict[str, Any]]] = None


class ReplayCompareRequest(BaseModel):
    snapshot_id: Optional[str] = None
    candidate_policies: Optional[List[Dict[str, Any]]] = None


class KrimoAgentRequest(BaseModel):
    content: str
    session_id: Optional[str] = None
    mode: str = "chat"
    remember: Optional[str] = None


class KrimoAgentResponse(BaseModel):
    ok: bool
    session_id: str
    mode: str
    model: Optional[str] = None
    content: Optional[str] = None
    blocked: bool = False
    require_approval: bool = False
    message: Optional[str] = None
    approval_hash: Optional[str] = None
    memory: Dict[str, Any] = Field(default_factory=dict)


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


def _derive_session_title(content: str) -> str:
    text = re.sub(r"\s+", " ", str(content or "")).strip()
    if not text:
        return "Untitled session"
    if len(text) > 72:
        text = text[:69].rstrip() + "..."
    return text


def _normalized_outcome(decision: Optional[Dict[str, Any]] = None, event: Optional[Dict[str, Any]] = None) -> str:
    d = decision or {}
    e = event or {}
    if d.get("blocked"):
        return "block"
    if d.get("require_approval"):
        return "approval"
    if d.get("redact"):
        return "redact"
    if d.get("warn"):
        return "warn"
    message = str(e.get("message") or "")
    stage = str(e.get("stage") or "")
    if message and any(token in message.lower() for token in ["failed", "error", "exception"]):
        return "runtime_error"
    if stage.endswith(".transform"):
        return "redact"
    return "allow"


def _request_input_excerpt(events: List[Dict[str, Any]]) -> str:
    for ev in events:
        for key in ("content", "input"):
            value = ev.get(key)
            if isinstance(value, str) and value.strip():
                return value[:220]
    return ""


def _collect_request_summaries(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    grouped: Dict[str, Dict[str, Any]] = {}
    ordered: List[Dict[str, Any]] = []
    for idx, event in enumerate(events):
        request_id = str(event.get("request_id") or f"legacy-{idx}")
        group = grouped.get(request_id)
        if group is None:
            group = {"id": request_id, "flow": event.get("flow") or "message", "events": []}
            grouped[request_id] = group
            ordered.append(group)
        group["events"].append(event)
        if event.get("flow"):
            group["flow"] = event.get("flow")

    summaries: List[Dict[str, Any]] = []
    severity = {"runtime_error": 5, "block": 4, "approval": 3, "redact": 2, "warn": 1, "allow": 0}
    for group in ordered:
        req_events = list(group["events"])
        stage_items: List[Dict[str, Any]] = []
        top_outcome = "allow"
        top_risk = 0.0
        primary_reason: Optional[str] = None
        transform_stages: List[str] = []
        signal_notes: List[str] = []
        matched_rules: List[str] = []

        for ev in req_events:
            decision = ev.get("decision") if isinstance(ev.get("decision"), dict) else None
            outcome = _normalized_outcome(decision, ev)
            risk_value = 0.0
            if isinstance(decision, dict):
                risk_value = float(decision.get("risk_score") or 0.0)
                matched_rules.extend(str(x) for x in (decision.get("matched_rules") or []) if str(x))
            if isinstance(ev.get("final_risk"), (int, float)):
                risk_value = max(risk_value, float(ev.get("final_risk") or 0.0))
            if isinstance(ev.get("message_risk"), (int, float)):
                risk_value = max(risk_value, float(ev.get("message_risk") or 0.0))
            top_risk = max(top_risk, risk_value)
            if severity[outcome] > severity[top_outcome]:
                top_outcome = outcome
            if primary_reason is None and outcome in {"block", "approval", "redact", "warn", "runtime_error"}:
                primary_reason = str((decision or {}).get("message") or ev.get("message") or ev.get("stage") or "").strip() or None
            if str(ev.get("stage") or "").endswith(".transform"):
                transform_stages.append(str(ev.get("stage")))
            if ev.get("stage") == "llm_classification" and isinstance(ev.get("classification"), dict):
                flags = [k for k, v in ev["classification"].items() if not str(k).startswith("__") and v is True]
                if flags:
                    signal_notes.append(f"LLM: {', '.join(flags)}")
                elif ev["classification"].get("__error__"):
                    signal_notes.append(f"LLM error: {ev['classification']['__error__']}")
            if ev.get("stage") == "local_classification" and isinstance(ev.get("classification"), dict):
                cls = ev["classification"]
                if cls.get("enabled") is False:
                    signal_notes.append("Local classifier disabled")
                else:
                    signal_notes.append(f"Local: {cls.get('label') or 'ALLOW'}")
            if ev.get("stage") == "llm_consensus":
                disagreements = ev.get("disagreements") or []
                signal_notes.append("Consensus disagreement" if disagreements else "Consensus matched")

            stage_items.append(
                {
                    "stage": ev.get("stage") or "event",
                    "outcome": outcome,
                    "message": str((decision or {}).get("message") or ev.get("message") or "").strip() or None,
                    "risk_score": risk_value,
                    "matched_rules": list((decision or {}).get("matched_rules") or []),
                    "timestamp": ev.get("ts"),
                    "timestamp_readable": ev.get("ts_readable"),
                }
            )

        summaries.append(
            {
                "id": group["id"],
                "flow": group["flow"],
                "input_excerpt": _request_input_excerpt(req_events),
                "outcome": top_outcome,
                "risk": top_risk,
                "event_count": len(req_events),
                "ts": (req_events[-1] or {}).get("ts") if req_events else 0,
                "inspector": {
                    "request_id": group["id"],
                    "flow": group["flow"],
                    "outcome": top_outcome,
                    "risk": round(top_risk, 4),
                    "input_excerpt": _request_input_excerpt(req_events),
                    "primary_reason": primary_reason,
                    "matched_rules": list(dict.fromkeys(matched_rules)),
                    "transform_stages": transform_stages,
                    "signal_notes": list(dict.fromkeys(signal_notes)),
                    "stages": stage_items,
                },
            }
        )
    summaries.sort(key=lambda item: float(item.get("ts") or 0), reverse=True)
    return summaries


def _evaluate_label_from_decision(decision: Any) -> str:
    if getattr(decision, "blocked", False):
        return "block"
    if getattr(decision, "require_approval", False):
        return "approval"
    if getattr(decision, "redact", False):
        return "redact"
    if getattr(decision, "warn", False):
        return "warn"
    return "allow"


def _candidate_policies_from_request(snapshot_id: Optional[str], candidate_policies: Optional[List[Dict[str, Any]]]) -> tuple[List[Dict[str, Any]], Dict[str, Any]]:
    if candidate_policies:
        return candidate_policies, {"mode": "candidate_inline", "snapshot_id": None}
    if snapshot_id:
        snapshot = load_policy_snapshot(snapshot_id)
        if not snapshot:
            raise HTTPException(status_code=404, detail="Policy snapshot not found")
        return list(snapshot.get("policies") or []), {
            "mode": "snapshot",
            "snapshot_id": snapshot.get("id"),
            "snapshot_name": snapshot.get("name"),
            "created_at": snapshot.get("created_at"),
        }
    return runtime.policy_engine.policies, {"mode": "current", "snapshot_id": None}


def _replay_compare_session(session: Dict[str, Any], candidate_policies: List[Dict[str, Any]], candidate_meta: Dict[str, Any]) -> Dict[str, Any]:
    events = list(session.get("events") or [])
    current_engine = runtime.policy_engine
    candidate_engine = PolicyEngine(candidate_policies)
    comparisons: List[Dict[str, Any]] = []

    for idx, ev in enumerate(events):
        stage = str(ev.get("stage") or "")
        if stage not in {"prellm", "postllm", "tool_pre", "tool_post"}:
            continue
        if not isinstance(ev.get("decision"), dict):
            continue
        content = ev.get("content")
        if stage in {"prellm", "postllm"} and not isinstance(content, str):
            continue
        if stage == "tool_pre":
            tool_name = str(ev.get("tool") or "")
            payload = ev.get("payload") or {}
            subject = f"{tool_name}: {json.dumps(payload, ensure_ascii=True)}"
        elif stage == "tool_post":
            tool_name = str(ev.get("tool") or "")
            result = ev.get("result") or ev.get("wrapped_result") or ev.get("safe_result") or {}
            subject = f"{tool_name}: {json.dumps(result, ensure_ascii=True)}"
        else:
            subject = str(content or "")

        context = {
            "tenant_id": ev.get("tenant_id"),
            "role": ev.get("role"),
            "environment": ev.get("environment"),
            "labels": list(ev.get("labels") or []),
            "metadata": ev.get("metadata") or {},
            "risk_state": {},
        }
        current_decision = current_engine.evaluate(subject, stage, runtime.detectors, dict(context))
        candidate_decision = candidate_engine.evaluate(subject, stage, runtime.detectors, dict(context))
        current_label = _evaluate_label_from_decision(current_decision)
        candidate_label = _evaluate_label_from_decision(candidate_decision)
        comparisons.append(
            {
                "request_id": str(ev.get("request_id") or f"legacy-{idx}"),
                "stage": stage,
                "current": current_decision.to_dict(),
                "candidate": candidate_decision.to_dict(),
                "current_outcome": current_label,
                "candidate_outcome": candidate_label,
                "changed": current_label != candidate_label,
                "input_excerpt": subject[:220],
            }
        )

    grouped: Dict[str, Dict[str, Any]] = {}
    ordered: List[Dict[str, Any]] = []
    for item in comparisons:
        request_id = item["request_id"]
        group = grouped.get(request_id)
        if group is None:
            group = {
                "request_id": request_id,
                "changes": [],
                "changed": False,
                "highest_current": "allow",
                "highest_candidate": "allow",
                "input_excerpt": item["input_excerpt"],
            }
            grouped[request_id] = group
            ordered.append(group)
        group["changes"].append(item)
        group["changed"] = group["changed"] or bool(item["changed"])
        severity = {"allow": 0, "warn": 1, "redact": 2, "approval": 3, "block": 4}
        if severity[item["current_outcome"]] > severity[group["highest_current"]]:
            group["highest_current"] = item["current_outcome"]
        if severity[item["candidate_outcome"]] > severity[group["highest_candidate"]]:
            group["highest_candidate"] = item["candidate_outcome"]

    changed_requests = sum(1 for item in ordered if item["changed"])
    return {
        "candidate": candidate_meta,
        "request_count": len(ordered),
        "changed_requests": changed_requests,
        "drift_rate": (float(changed_requests) / float(len(ordered))) if ordered else 0.0,
        "requests": ordered,
    }

@router.post("/sessions", response_model=CreateSessionResponse, dependencies=[Depends(require_api_key)])
def create_session():
    session_id = str(uuid4())
    store.create_session(session_id)
    return CreateSessionResponse(session_id=session_id)


@router.post("/agent/krimo", response_model=KrimoAgentResponse, dependencies=[Depends(require_api_key)])
def krimo_agent(req: KrimoAgentRequest):
    session_id = req.session_id or str(uuid4())
    if not store.session_exists(session_id):
        store.create_session(session_id)
    updater = getattr(store, "update_session_title", None)
    if callable(updater) and req.content:
        updater(session_id, _derive_session_title(req.content))

    memory = agent_memories.get(session_id) or AgentMemory()
    if req.remember:
        memory.remember_note(req.remember)

    client = LocalAegisClient(runtime)
    result = run_turn(client=client, session_id=session_id, content=req.content, memory=memory, mode=req.mode)
    agent_memories[session_id] = memory

    if result.get("ok"):
        return KrimoAgentResponse(
            ok=True,
            session_id=session_id,
            mode=str(result.get("mode") or req.mode),
            model=result.get("model"),
            content=result.get("content"),
            memory=result.get("memory") or memory.as_dict(),
        )
    return KrimoAgentResponse(
        ok=False,
        session_id=session_id,
        mode=req.mode,
        model=result.get("model"),
        blocked=bool(result.get("blocked", False)),
        require_approval=bool(result.get("require_approval", False)),
        message=result.get("message"),
        approval_hash=result.get("approval_hash"),
        memory=result.get("memory") or memory.as_dict(),
    )

@router.get("/sessions", dependencies=[Depends(require_api_key)])
def list_sessions():
    sessions = store.list_sessions()
    items = []
    for sid, data in sessions.items():
        events = list(data.get("events", []))
        items.append(
            {
                "id": sid,
                "events": len(events),
                "title": data.get("title") or "Untitled session",
                "created_at": data.get("created_at"),
                "last_event_at": ((events[-1] or {}).get("ts") if events and isinstance(events[-1], dict) else None),
                "quarantined": bool((data.get("risk_state") or {}).get("quarantined", False)),
            }
        )
    items.sort(key=lambda item: float(item.get("last_event_at") or item.get("created_at") or 0), reverse=True)
    return {"sessions": items}

@router.post("/sessions/{session_id}/messages", response_model=MessageResponse, dependencies=[Depends(require_api_key)])
def send_message(session_id: str, req: MessageRequest):
    if not store.session_exists(session_id):
        raise HTTPException(status_code=404, detail="Session not found")
    updater = getattr(store, "update_session_title", None)
    if callable(updater):
        updater(session_id, _derive_session_title(req.content))
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
        model_name=req.model,
    )
    return MessageResponse(
        content=result.output,
        actions=result.actions,
        risk_score=result.risk_score,
        decision_message=result.message,
        approval_hash=result.approval_hash,
    )


@router.post("/sessions/{session_id}/guard/input", response_model=GuardInputResponse, dependencies=[Depends(require_api_key)])
def guard_input(session_id: str, req: MessageRequest):
    if not store.session_exists(session_id):
        raise HTTPException(status_code=404, detail="Session not found")
    updater = getattr(store, "update_session_title", None)
    if callable(updater):
        updater(session_id, _derive_session_title(req.content))
    result = runtime.guard_user_input(
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
    return GuardInputResponse(**result)


@router.post("/sessions/{session_id}/guard/output", response_model=GuardOutputResponse, dependencies=[Depends(require_api_key)])
def guard_output(session_id: str, req: GuardOutputRequest):
    if not store.session_exists(session_id):
        raise HTTPException(status_code=404, detail="Session not found")
    result = runtime.guard_model_output(
        session_id=session_id,
        output_text=req.content,
        metadata=req.metadata,
        tenant_id=req.tenant_id,
        role=req.role,
        environment=req.environment,
        labels=req.labels,
    )
    return GuardOutputResponse(**result)

@router.post("/sessions/{session_id}/approvals", dependencies=[Depends(require_api_key)])
def approve_action(session_id: str, req: ApprovalRequest):
    if not store.session_exists(session_id):
        raise HTTPException(status_code=404, detail="Session not found")
    ok = store.approve(session_id, req.approval_hash)
    if not ok:
        raise HTTPException(status_code=400, detail="Unknown or expired approval hash")
    return {"approved": True}


@router.post("/sessions/{session_id}/approvals/decision", dependencies=[Depends(require_api_key)])
def approve_action_with_scope(session_id: str, req: ApprovalDecisionRequest):
    if not store.session_exists(session_id):
        raise HTTPException(status_code=404, detail="Session not found")
    ok = store.approve(
        session_id,
        req.approval_hash,
        actor=req.actor,
        scope=req.scope,
        expires_in_seconds=req.expires_in_seconds,
        reusable=req.reusable,
        reason=req.reason,
    )
    if not ok:
        raise HTTPException(status_code=400, detail="Unknown or expired approval hash")
    store.log_event(
        session_id,
        {
            "stage": "approval.granted",
            "approval_hash": req.approval_hash,
            "actor": req.actor,
            "scope": req.scope,
            "reusable": req.reusable,
            "reason": req.reason,
            "expires_in_seconds": req.expires_in_seconds,
        },
    )
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


@router.post("/sessions/{session_id}/guard/tool-pre", response_model=ToolGuardPreResponse, dependencies=[Depends(require_api_key)])
def guard_tool_pre(session_id: str, req: ToolGuardPreRequest):
    if not store.session_exists(session_id):
        raise HTTPException(status_code=404, detail="Session not found")
    result = runtime.guard_tool_call_pre(
        session_id=session_id,
        tool_name=req.tool_name,
        payload=req.payload,
        environment=req.environment,
        tenant_id=req.tenant_id,
        role=req.role,
        labels=req.labels,
    )
    return ToolGuardPreResponse(**result)


@router.post("/sessions/{session_id}/guard/tool-post", response_model=ToolGuardPostResponse, dependencies=[Depends(require_api_key)])
def guard_tool_post(session_id: str, req: ToolGuardPostRequest):
    if not store.session_exists(session_id):
        raise HTTPException(status_code=404, detail="Session not found")
    result = runtime.guard_tool_call_post(
        session_id=session_id,
        tool_name=req.tool_name,
        result=req.result,
        environment=req.environment,
        tenant_id=req.tenant_id,
        role=req.role,
        labels=req.labels,
    )
    return ToolGuardPostResponse(**result)

@router.get("/sessions/{session_id}", dependencies=[Depends(require_api_key)])
def get_session(session_id: str):
    if not store.session_exists(session_id):
        raise HTTPException(status_code=404, detail="Session not found")
    session = dict(store.get_session(session_id) or {})
    events = list(session.get("events") or [])
    session["request_summaries"] = _collect_request_summaries(events)
    return session

@router.delete("/sessions/{session_id}", dependencies=[Depends(require_api_key)])
def delete_session(session_id: str):
    deleter = getattr(store, "delete_session", None)
    if not callable(deleter) or not deleter(session_id):
        raise HTTPException(status_code=404, detail="Session not found")
    return {"deleted": True, "session_id": session_id}

@router.delete("/sessions", dependencies=[Depends(require_api_key)])
def clear_sessions():
    clearer = getattr(store, "clear_sessions", None)
    if not callable(clearer):
        raise HTTPException(status_code=501, detail="Session clearing not supported")
    deleted = int(clearer() or 0)
    return {"deleted": deleted}

@router.get("/sessions/{session_id}/risk", dependencies=[Depends(require_api_key)])
def get_session_risk(session_id: str):
    if not store.session_exists(session_id):
        raise HTTPException(status_code=404, detail="Session not found")
    getter = getattr(store, "get_risk_state", None)
    if callable(getter):
        return {"risk_state": getter(session_id)}
    return {"risk_state": {}}

@router.post("/sessions/{session_id}/risk/reset", dependencies=[Depends(require_api_key)])
def reset_session_risk(session_id: str):
    if not store.session_exists(session_id):
        raise HTTPException(status_code=404, detail="Session not found")
    resetter = getattr(store, "reset_risk_state", None)
    if not callable(resetter):
        raise HTTPException(status_code=501, detail="Risk reset not supported")
    risk_state = resetter(session_id)
    store.log_event(
        session_id,
        {"stage": "risk.reset", "message": "Session risk state reset", "risk_state": risk_state},
    )
    return {"ok": True, "risk_state": risk_state}


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


@router.get("/policy-snapshots", dependencies=[Depends(require_api_key)])
def get_policy_snapshots():
    return {"snapshots": list_policy_snapshots()}


@router.post("/policy-snapshots", dependencies=[Depends(require_api_key)])
def create_snapshot(req: PolicySnapshotCreateRequest):
    snapshot = create_policy_snapshot(req.name, req.policies or runtime.policy_engine.policies, source="dashboard")
    return {"snapshot": snapshot}

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


@router.post("/replay/session/{session_id}/compare-policy", dependencies=[Depends(require_api_key)])
def replay_compare_policy(session_id: str, req: ReplayCompareRequest):
    if not store.session_exists(session_id):
        raise HTTPException(status_code=404, detail="Session not found")
    session = store.get_session(session_id)
    candidate_policies, candidate_meta = _candidate_policies_from_request(req.snapshot_id, req.candidate_policies)
    return {
        "session_id": session_id,
        **_replay_compare_session(session, candidate_policies, candidate_meta),
    }

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


@router.get("/sessions/{session_id}/approvals", dependencies=[Depends(require_api_key)])
def list_session_approvals(session_id: str):
    if not store.session_exists(session_id):
        raise HTTPException(status_code=404, detail="Session not found")
    pending = getattr(store, "list_pending_approvals", lambda sid: [])(session_id)
    reusable = getattr(store, "list_reusable_approvals", lambda sid=None: [])(session_id)
    return {"pending": pending, "reusable": reusable}


@router.get("/control/settings", dependencies=[Depends(require_api_key)])
def get_runtime_control_settings():
    return get_control_settings()


@router.put("/control/settings", dependencies=[Depends(require_api_key)])
def put_runtime_control_settings(req: ControlSettingsRequest):
    updated = update_control_settings(req.patch)
    runtime.reload_policies()
    return updated


@router.get("/control/packs", dependencies=[Depends(require_api_key)])
def get_runtime_packs():
    return get_tenant_packs()


@router.put("/control/packs", dependencies=[Depends(require_api_key)])
def put_runtime_packs(req: TenantPackUpdateRequest):
    return update_tenant_packs(req.packs, bindings=req.bindings)


@router.post("/control/simulate-policy", dependencies=[Depends(require_api_key)])
def simulate_policy(req: PolicySimulateRequest):
    context = {
        "tenant_id": req.tenant_id,
        "role": req.role,
        "environment": req.environment,
        "labels": req.labels,
        "metadata": req.metadata,
        "risk_state": {},
    }
    current = runtime.policy_engine.evaluate(req.content, req.stage, runtime.detectors, context)
    candidate_engine = PolicyEngine(req.candidate_policies or runtime.policy_engine.policies)
    candidate = candidate_engine.evaluate(req.content, req.stage, runtime.detectors, context)
    return {
        "current": current.to_dict(),
        "candidate": candidate.to_dict(),
        "diff": {
            "blocked_changed": current.blocked != candidate.blocked,
            "approval_changed": current.require_approval != candidate.require_approval,
            "warn_changed": current.warn != candidate.warn,
            "risk_delta": float(candidate.risk_score) - float(current.risk_score),
            "matched_rules_added": sorted(set(candidate.matched_rules or []) - set(current.matched_rules or [])),
            "matched_rules_removed": sorted(set(current.matched_rules or []) - set(candidate.matched_rules or [])),
        },
    }


@router.post("/control/redteam/run", dependencies=[Depends(require_api_key)])
def run_redteam(req: RedTeamRunRequest):
    data = run_redteam_suite(runtime, req.dataset_path or get_control_settings()["redteam_dataset_path"])
    return data


@router.get("/models/ollama", dependencies=[Depends(require_api_key)])
def get_ollama_models():
    try:
        models = list_ollama_models()
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Failed to reach Ollama: {exc}")
    return {
        "base_url": ollama_base_url(),
        "endpoint": settings.aegis_model_endpoint,
        "active_model": settings.aegis_model_name,
        "classifier_model": settings.aegis_llm_model,
        "models": models,
    }


@router.put("/models/active", dependencies=[Depends(require_api_key)])
def update_active_model(req: ActiveModelRequest):
    model = (req.model or "").strip()
    if not model:
        raise HTTPException(status_code=400, detail="Model is required")
    settings.aegis_model_name = model
    if req.update_classifier:
        settings.aegis_llm_model = model
    return {
        "ok": True,
        "active_model": settings.aegis_model_name,
        "classifier_model": settings.aegis_llm_model,
        "endpoint": settings.aegis_model_endpoint,
    }

@router.put("/tool-policies", dependencies=[Depends(require_api_key)])
def update_tool_policies(req: ToolPoliciesUpdateRequest):
    if not settings.aegis_db_enabled:
        raise HTTPException(status_code=501, detail="Tool policy editing requires DB")
    try:
        save_tool_policies_to_db(req.tools)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"DB save failed: {exc}")
    return {"ok": True, "count": len(req.tools)}
