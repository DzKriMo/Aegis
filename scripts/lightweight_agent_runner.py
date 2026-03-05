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
    "You may optionally call one tool by returning ONLY compact JSON:\n"
    '{"tool_name":"<name>","payload":{...}}\n'
    "Available tools: shell, filesystem_read, http_fetch, json_transform.\n"
    "If no tool is needed, return plain text answer."
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
        model_text = model_chat(safe_input)

        tool_call = try_parse_tool_call(model_text)
        if tool_call is not None:
            tool_res = aegis_post(
                f"/sessions/{session_id}/tools/execute",
                {
                    "tool_name": tool_call["tool_name"],
                    "payload": tool_call["payload"],
                    "environment": ENVIRONMENT,
                },
            )
            if not tool_res.get("allowed", False):
                final_text = f"Tool blocked: {tool_res.get('message') or 'blocked'}"
            else:
                final_text = model_chat(
                    f"{safe_input}\n\nUse the tool result to answer the user clearly.",
                    prior_tool_result=tool_res.get("result"),
                )
        else:
            final_text = model_text

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
