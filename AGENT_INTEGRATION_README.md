# Aegis Agent Integration Guide

This guide explains how to attach Aegis to a user-facing AI agent and run it in real environments, not just demos.

## 1. Integration Model

Put Aegis in front of your agent runtime as a policy decision point.

Flow:
1. User message arrives in your app.
2. Send message to `POST /v1/sessions/{session_id}/messages`.
3. If Aegis blocks, return Aegis message to user.
4. If Aegis requires approval, collect approval and call `POST /v1/sessions/{session_id}/approvals`.
5. If allowed, pass sanitized/approved text to your model runtime.
6. Route agent tool calls through `POST /v1/sessions/{session_id}/tools/execute`.
7. Return final output to user.

## 2. Minimum Setup

1. Start Aegis API:
```powershell
python -m uvicorn aegis.api.main:app --port 8000
```

2. Create a session:
```powershell
curl -X POST http://127.0.0.1:8000/v1/sessions -H "x-api-key: changeme"
```

3. Send a guarded message:
```powershell
curl -X POST http://127.0.0.1:8000/v1/sessions/<SESSION_ID>/messages `
  -H "Content-Type: application/json" `
  -H "x-api-key: changeme" `
  -d "{\"content\":\"User prompt here\",\"metadata\":{}}"
```

4. Inspect trajectory risk state:
```powershell
curl http://127.0.0.1:8000/v1/sessions/<SESSION_ID>/risk -H "x-api-key: changeme"
```

## 3. Reference Adapter (Python)

Use a thin client in your app that wraps all agent I/O.

```python
import requests

AEGIS_URL = "http://127.0.0.1:8000/v1"
API_KEY = "changeme"

def aegis_post(path: str, payload: dict):
    return requests.post(
        f"{AEGIS_URL}{path}",
        json=payload,
        headers={"x-api-key": API_KEY},
        timeout=10,
    ).json()

def guarded_user_message(session_id: str, content: str):
    res = aegis_post(
        f"/sessions/{session_id}/messages",
        {"content": content, "metadata": {}, "environment": "prod"},
    )
    if "block" in res.get("actions", []):
        return {"status": "blocked", "message": res.get("decision_message")}
    if "require_approval" in res.get("actions", []):
        return {"status": "approval_required", "approval_hash": res.get("approval_hash")}
    return {"status": "allowed", "content": res.get("content")}
```

## 4. Tooling Integration Pattern

Never execute tools directly from the agent. Always proxy through Aegis:

```powershell
curl -X POST http://127.0.0.1:8000/v1/sessions/<SESSION_ID>/tools/execute `
  -H "Content-Type: application/json" `
  -H "x-api-key: <API_KEY>" `
  -d "{\"tool_name\":\"http_fetch\",\"payload\":{\"url\":\"https://example.com\"},\"environment\":\"prod\"}"
```

If `allowed=false`, stop tool execution and surface `message` to the agent loop.

## 5. Approval Workflow

When Aegis returns `approval_hash`:
1. Show a clear operator prompt with reason.
2. Require explicit confirmation.
3. Send:

```powershell
curl -X POST http://127.0.0.1:8000/v1/sessions/<SESSION_ID>/approvals `
  -H "Content-Type: application/json" `
  -H "x-api-key: <API_KEY>" `
  -d "{\"approval_hash\":\"<HASH>\"}"
```

4. Retry the previously blocked operation once.

## 6. Real-Life Deployment Checklist

1. Set `AEGIS_ENV=prod`.
2. Set strong `AEGIS_API_KEY` and `AEGIS_JWT_SECRET`.
3. Enable `AEGIS_FAIL_CLOSED=true`.
4. Restrict `AEGIS_CORS_ORIGINS` to your app domains.
5. Use non-memory rate limiting (`AEGIS_RATE_LIMIT_BACKEND=sqlite` or external store in your fork).
6. Version-control your policy files and require PR review for policy changes.
7. Run regression suite on each commit:
```powershell
python -m unittest discover -s tests -p "test_*.py" -v
```
8. Alert on high-risk events (`blocked`, `require_approval`, `llm_classification.__error__`).
9. Stamp versions for replay/audit:
   - `AEGIS_POLICY_VERSION`
   - `AEGIS_DETECTOR_VERSION`
   - `AEGIS_MODEL_HASH`
10. Enable deterministic CI env flags:
   - `AEGIS_LLM_ENABLED=false`
   - `AEGIS_DB_ENABLED=false`
   - `AEGIS_SEMANTIC_ENABLED=false`
   - `HF_HUB_OFFLINE=1`

## 7. Multi-Tenant Usage

Pass tenant and role context in message/tool requests:
- `tenant_id`
- `role`
- `environment`
- `labels`

Use these fields in policy rules for tenant-specific controls.

## 8. Rollout Strategy

1. Shadow mode: log decisions but do not enforce blocks.
2. Soft enforce: enable warnings and approvals.
3. Hard enforce: block high-confidence attack classes.
4. Iterate from incident data and false positive review.

Use replay to validate changes before rollout:
```powershell
curl -X POST http://127.0.0.1:8000/v1/replay/session/<SESSION_ID> `
  -H "Content-Type: application/json" `
  -H "x-api-key: changeme" `
  -d "{\"policy_version\":\"candidate-v2\",\"detector_version\":\"candidate-det-v2\",\"model_hash\":\"qwen-3b-q4km\"}"
```

## 9. Common Pitfalls

1. Bypassing Aegis for tool calls.
2. Running with default API key/secret.
3. Missing fail-closed mode in production.
4. No regression corpus for prompt/tool attacks.
5. No human approval path for sensitive outputs.

## 10. Operational Reality

Aegis is a guardrail layer, not a complete security perimeter. Keep standard controls in place:
- network egress controls
- secret management
- endpoint authz
- audit logging
- incident response playbooks
