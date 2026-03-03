from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from uuid import uuid4
from typing import List, Dict, Any, Optional

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
