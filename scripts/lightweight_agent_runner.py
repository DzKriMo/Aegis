from __future__ import annotations

import json
import os
import sys
from typing import Any, Dict

import requests


AEGIS_BASE = os.getenv("AEGIS_BASE_URL", "http://127.0.0.1:8000/v1").rstrip("/")
AEGIS_API_KEY = os.getenv("AEGIS_API_KEY", "changeme")
MODEL_ENDPOINT = os.getenv("AGENT_MODEL_ENDPOINT", "http://127.0.0.1:11434/v1/chat/completions")
MODEL_NAME = os.getenv("AGENT_MODEL_NAME", "qwen2.5:3b-instruct")
ENVIRONMENT = os.getenv("AEGIS_AGENT_ENV", "dev")

TOOL_SPEC = (
    "Always return valid JSON in one of these forms only:\n"
    '{"action":"answer","content":"<final user-facing reply>"}\n'
    '{"action":"tool","tool_name":"<name>","payload":{...}}\n'
    "Available tools: shell, filesystem_read, directory_list, filesystem_write, http_fetch, json_transform."
)


def _aegis_headers() -> Dict[str, str]:
    return {"x-api-key": AEGIS_API_KEY, "content-type": "application/json"}


def aegis_post(path: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    resp = requests.post(f"{AEGIS_BASE}{path}", headers=_aegis_headers(), json=payload, timeout=45)
    resp.raise_for_status()
    return resp.json()


def model_chat(user_prompt: str, prior_tool_result: Dict[str, Any] | None = None) -> str:
    user_content = user_prompt
    if prior_tool_result is not None:
        user_content = f"{user_prompt}\n\nTOOL_RESULT_JSON:\n{json.dumps(prior_tool_result, ensure_ascii=True)}"
    payload = {
        "model": MODEL_NAME,
        "temperature": 0.1,
        "max_tokens": 500,
        "messages": [
            {"role": "system", "content": TOOL_SPEC},
            {"role": "user", "content": user_content},
        ],
    }
    resp = requests.post(MODEL_ENDPOINT, json=payload, timeout=60)
    resp.raise_for_status()
    data = resp.json()
    return data["choices"][0]["message"]["content"].strip()


def force_plain_answer(user_prompt: str) -> str:
    payload = {
        "model": MODEL_NAME,
        "temperature": 0.1,
        "max_tokens": 500,
        "messages": [
            {"role": "system", "content": "Reply with plain text only. Do not return JSON."},
            {"role": "user", "content": user_prompt},
        ],
    }
    resp = requests.post(MODEL_ENDPOINT, json=payload, timeout=60)
    resp.raise_for_status()
    return resp.json()["choices"][0]["message"]["content"].strip()


def maybe_approve_tool(session_id: str, tool_name: str, tool_res: Dict[str, Any]) -> bool:
    approval_hash = tool_res.get("approval_hash")
    if not approval_hash:
        return False
    print(f"aegis(tool-approval)> {tool_name} requires approval")
    print(f"aegis(approval_hash)> {approval_hash}")
    try:
        answer = input("approve this tool call? [y/N] ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        return False
    if answer not in {"y", "yes"}:
        return False
    aegis_post(
        f"/sessions/{session_id}/approvals/decision",
        {
            "approval_hash": approval_hash,
            "actor": "lightweight_agent_runner",
            "scope": "exact",
            "expires_in_seconds": 1800,
            "reusable": True,
            "reason": f"Interactive approval for tool {tool_name}",
        },
    )
    return True


def try_parse_tool_call(text: str) -> Dict[str, Any] | None:
    trimmed = text.strip()
    if not trimmed.startswith("{"):
        return None
    try:
        obj = json.loads(trimmed)
    except Exception:
        return None
    if not isinstance(obj, dict):
        return None
    if not isinstance(obj.get("tool_name"), str):
        return None
    payload = obj.get("payload", {})
    if not isinstance(payload, dict):
        payload = {}
    return {"tool_name": obj["tool_name"], "payload": payload}


def parse_agent_action(text: str) -> Dict[str, Any]:
    trimmed = text.strip()
    if trimmed.startswith("{"):
        try:
            obj = json.loads(trimmed)
        except Exception:
            return {"action": "answer", "content": trimmed}
        if not isinstance(obj, dict) or not obj:
            return {"action": "answer", "content": ""}
        action = str(obj.get("action") or "").strip().lower()
        known_tools = {
            "shell",
            "filesystem_read",
            "directory_list",
            "filesystem_write",
            "http_fetch",
            "json_transform",
        }
        if action == "tool" and isinstance(obj.get("tool_name"), str):
            payload = obj.get("payload", {})
            if not isinstance(payload, dict):
                payload = {}
            return {"action": "tool", "tool_name": obj["tool_name"], "payload": payload}
        if action in known_tools:
            payload = obj.get("payload", {})
            if not isinstance(payload, dict):
                payload = {}
            if action == "directory_list" and payload.get("path") is None:
                payload["path"] = "."
            return {"action": "tool", "tool_name": action, "payload": payload}
        if action == "answer":
            return {"action": "answer", "content": str(obj.get("content") or "")}
        if action == "return_keys":
            content = obj.get("content")
            if isinstance(content, list):
                return {"action": "answer", "content": ", ".join(str(x) for x in content)}
            return {"action": "answer", "content": str(content or "")}
        if isinstance(obj.get("tool_name"), str):
            payload = obj.get("payload", {})
            if not isinstance(payload, dict):
                payload = {}
            return {"action": "tool", "tool_name": obj["tool_name"], "payload": payload}
        if isinstance(obj.get("content"), (str, list, dict)):
            content = obj.get("content")
            if isinstance(content, list):
                return {"action": "answer", "content": ", ".join(str(x) for x in content)}
            if isinstance(content, dict):
                return {"action": "answer", "content": json.dumps(content)}
            return {"action": "answer", "content": content}
    tool_call = try_parse_tool_call(trimmed)
    if tool_call is not None:
        return {"action": "tool", **tool_call}
    return {"action": "answer", "content": trimmed}


def main() -> int:
    session = aegis_post("/sessions", {})
    session_id = session["session_id"]
    print(f"[aegis] session={session_id}")

    while True:
        try:
            user_text = input("you> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return 0
        if not user_text:
            continue
        if user_text.lower() in {"exit", "quit"}:
            return 0

        guarded = aegis_post(
            f"/sessions/{session_id}/guard/input",
            {
                "content": user_text,
                "metadata": {"source": "lightweight_agent_runner"},
                "environment": ENVIRONMENT,
            },
        )
        if guarded.get("blocked"):
            print(f"aegis(block)> {guarded.get('message') or 'Blocked'}")
            continue
        if guarded.get("require_approval"):
            print(f"aegis(approval)> {guarded.get('message') or 'Approval required'}")
            print(f"aegis(approval_hash)> {guarded.get('approval_hash')}")
            continue

        safe_input = guarded.get("sanitized_content") or user_text
        action = parse_agent_action(model_chat(safe_input))
        if action.get("action") == "answer" and not str(action.get("content") or "").strip():
            action = {"action": "answer", "content": force_plain_answer(safe_input)}

        if action.get("action") == "tool":
            tool_res = aegis_post(
                f"/sessions/{session_id}/tools/execute",
                {
                    "tool_name": action["tool_name"],
                    "payload": action["payload"],
                    "environment": ENVIRONMENT,
                },
            )
            if tool_res.get("approval_hash") and maybe_approve_tool(session_id, action["tool_name"], tool_res):
                tool_res = aegis_post(
                    f"/sessions/{session_id}/tools/execute",
                    {
                        "tool_name": action["tool_name"],
                        "payload": action["payload"],
                        "environment": ENVIRONMENT,
                    },
                )
            if not tool_res.get("allowed", False):
                final_text = f"Tool blocked: {tool_res.get('message') or 'blocked'}"
            else:
                second = parse_agent_action(model_chat(
                    f"{safe_input}\n\nUse the tool result to answer the user clearly.",
                    prior_tool_result=tool_res.get("result"),
                ))
                if second.get("action") == "answer" and not str(second.get("content") or "").strip():
                    second = {"action": "answer", "content": force_plain_answer(f"{safe_input}\n\nUse the tool result to answer clearly.")}
                final_text = second.get("content") or json.dumps(tool_res.get("result"))
        else:
            final_text = action.get("content") or ""

        guarded_out = aegis_post(
            f"/sessions/{session_id}/guard/output",
            {
                "content": final_text,
                "metadata": {"source": "lightweight_agent_runner"},
                "environment": ENVIRONMENT,
            },
        )
        if guarded_out.get("blocked"):
            print(f"aegis(post-block)> {guarded_out.get('message') or 'Blocked'}")
            continue
        if guarded_out.get("require_approval"):
            print(f"aegis(post-approval)> {guarded_out.get('message') or 'Approval required'}")
            print(f"aegis(approval_hash)> {guarded_out.get('approval_hash')}")
            continue

        safe_output = guarded_out.get("sanitized_output") or final_text
        print(f"agent> {safe_output}")


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except requests.HTTPError as exc:
        print(f"[error] HTTP failure: {exc}", file=sys.stderr)
        return_code = 2
    except Exception as exc:
        print(f"[error] {exc}", file=sys.stderr)
        return_code = 1
    raise SystemExit(return_code)
