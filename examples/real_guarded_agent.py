from __future__ import annotations

import json
import os
import re
import sys
from typing import Any, Dict, Optional

import requests

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from aegis.tools.agent_adapter import AegisAgentAdapter
from aegis.tools.client import AegisClient


AEGIS_BASE = os.getenv("AEGIS_BASE_URL", "http://127.0.0.1:8000/v1")
AEGIS_API_KEY = os.getenv("AEGIS_API_KEY", "changeme")
MODEL_ENDPOINT = os.getenv("AGENT_MODEL_ENDPOINT", "http://127.0.0.1:11434/v1/chat/completions")
MODEL_NAME = os.getenv("AGENT_MODEL_NAME", "qwen2.5:7b-instruct")
MODEL_TEMPERATURE = float(os.getenv("AGENT_MODEL_TEMPERATURE", "0.1"))
MODEL_MAX_TOKENS = int(os.getenv("AGENT_MODEL_MAX_TOKENS", "400"))
AGENT_ENV = os.getenv("AEGIS_AGENT_ENV", "dev")
FILESYSTEM_ROOT = os.getenv("AEGIS_AGENT_FILESYSTEM_ROOT", os.getcwd())
AGENT_NAME = "KriMo AI"
AGENT_BANNER = r"""
██╗  ██╗██████╗ ██╗███╗   ███╗ ██████╗      █████╗ ██╗
██║ ██╔╝██╔══██╗██║████╗ ████║██╔═══██╗    ██╔══██╗██║
█████╔╝ ██████╔╝██║██╔████╔██║██║   ██║    ███████║██║
██╔═██╗ ██╔══██╗██║██║╚██╔╝██║██║   ██║    ██╔══██║██║
██║  ██╗██║  ██║██║██║ ╚═╝ ██║╚██████╔╝    ██║  ██║██║
╚═╝  ╚═╝╚═╝  ╚═╝╚═╝╚═╝     ╚═╝ ╚═════╝     ╚═╝  ╚═╝╚═╝
""".strip("\n")
MODEL_SESSION = requests.Session()


def attach_runtime(client: AegisClient, session_id: str) -> tuple[str, AegisAgentAdapter]:
    adapter = AegisAgentAdapter(client, session_id, environment=AGENT_ENV, filesystem_root=FILESYSTEM_ROOT)
    return session_id, adapter


def create_runtime(client: AegisClient) -> tuple[str, AegisAgentAdapter]:
    session_id = client.create_session()
    return attach_runtime(client, session_id)


def model_chat(messages: list[dict[str, str]]) -> str:
    payload = {
        "model": MODEL_NAME,
        "temperature": MODEL_TEMPERATURE,
        "max_tokens": MODEL_MAX_TOKENS,
        "messages": messages,
    }
    resp = MODEL_SESSION.post(MODEL_ENDPOINT, json=payload, timeout=90)
    resp.raise_for_status()
    return resp.json()["choices"][0]["message"]["content"].strip()


def force_plain_answer(user_text: str) -> str:
    return model_chat(
        [
            {"role": "system", "content": 'Reply with plain text only. Do not return JSON. Answer the user directly.'},
            {"role": "user", "content": user_text},
        ]
    )


def wants_summary(user_text: str) -> bool:
    text = (user_text or "").lower()
    return any(word in text for word in ["summarize", "summarise", "summary", "in bullets", "bullet points"])


def wants_exact_file_read(user_text: str, tool_name: str) -> bool:
    if tool_name != "filesystem_read":
        return False
    text = (user_text or "").lower()
    if wants_summary(text):
        return False
    return any(
        phrase in text
        for phrase in [
            "read ",
            "show ",
            "what is in",
            "what's in",
            "what does",
            "contents of",
            "content of",
            "open ",
        ]
    )


def exact_file_read_answer(payload: Dict[str, Any], result: Dict[str, Any]) -> str:
    path = str(payload.get("path") or "the file")
    content = str((result or {}).get("content") or "")
    return f"The file {path} contains: '{content}'."


def render_file_read_result(path: str, result: Dict[str, Any]) -> str:
    content = str((result or {}).get("content") or "")
    return f"The file {path} contains: '{content}'."


def render_directory_listing(result: Dict[str, Any]) -> str:
    entries = (result or {}).get("entries") or []
    path = str((result or {}).get("path") or ".")
    if not entries:
        return f"The directory {path} is empty."
    lines = [f"Directory listing for {path}:"]
    for entry in entries[:60]:
        name = str(entry.get("name") or "")
        suffix = "/" if entry.get("is_dir") else ""
        size = entry.get("size")
        size_text = f" ({size} bytes)" if isinstance(size, int) and not entry.get("is_dir") else ""
        lines.append(f"- {name}{suffix}{size_text}")
    if len(entries) > 60:
        lines.append(f"- ...and {len(entries) - 60} more")
    return "\n".join(lines)


def render_write_result(result: Dict[str, Any]) -> str:
    path = str((result or {}).get("path") or "the file")
    bytes_written = int((result or {}).get("bytes_written") or 0)
    return f"Wrote {bytes_written} bytes to {path}."


def render_json_transform_result(result: Dict[str, Any]) -> str:
    if isinstance(result.get("keys"), list):
        keys = ", ".join(str(k) for k in result["keys"])
        return f"Keys: {keys}" if keys else "No keys found."
    if isinstance(result.get("schema"), dict):
        items = [f"- {k}: {v}" for k, v in result["schema"].items()]
        return "\n".join(items) if items else "No schema fields found."
    if isinstance(result.get("json"), str):
        return result["json"]
    return format_display_text(result)


def render_text_search_result(result: Dict[str, Any]) -> str:
    matches = (result or {}).get("matches") or []
    query = str((result or {}).get("query") or "")
    if not matches:
        return f"No matches found for '{query}'."
    lines = [f"Found {len(matches)} matches for '{query}':"]
    for match in matches[:40]:
        path = str(match.get("path") or "")
        line_no = match.get("line")
        snippet = str(match.get("snippet") or "").strip()
        lines.append(f"- {path}:{line_no}  {snippet}")
    if len(matches) > 40:
        lines.append(f"- ...and {len(matches) - 40} more")
    return "\n".join(lines)


def render_edit_result(result: Dict[str, Any]) -> str:
    path = str((result or {}).get("path") or "the file")
    replacements = int((result or {}).get("replacements") or 0)
    return f"Updated {path} with {replacements} replacement(s)."


def render_patch_result(result: Dict[str, Any]) -> str:
    path = str((result or {}).get("path") or "the file")
    changes = (result or {}).get("changes") or []
    return f"Patched {path} with {len(changes)} change(s)."


def render_file_find_result(result: Dict[str, Any]) -> str:
    matches = (result or {}).get("matches") or []
    pattern = str((result or {}).get("pattern") or "")
    if not matches:
        return f"No files found for pattern '{pattern}'."
    lines = [f"Found {len(matches)} file(s) for '{pattern}':"]
    for match in matches[:60]:
        lines.append(f"- {match.get('relative_path') or match.get('path')}")
    if len(matches) > 60:
        lines.append(f"- ...and {len(matches) - 60} more")
    return "\n".join(lines)


def compact_tool_result(tool_name: str, result: Dict[str, Any]) -> str:
    if tool_name == "directory_list":
        return render_directory_listing(result)
    if tool_name == "filesystem_read":
        return render_file_read_result("the file", result)
    if tool_name == "filesystem_write":
        return render_write_result(result)
    if tool_name == "filesystem_edit":
        return render_edit_result(result)
    if tool_name == "filesystem_patch":
        return render_patch_result(result)
    if tool_name == "file_find":
        return render_file_find_result(result)
    if tool_name == "text_search":
        return render_text_search_result(result)
    if tool_name == "json_transform":
        return render_json_transform_result(result)
    if tool_name == "http_fetch":
        preview = str((result or {}).get("body_preview") or "")
        status = result.get("status")
        url = str((result or {}).get("url") or "")
        if preview:
            return f"Fetched {url} ({status}).\n\n{preview}"
        return format_display_text(result)
    return format_display_text(result)


def format_display_text(value: Any) -> str:
    if isinstance(value, str):
        trimmed = value.strip()
        if trimmed.startswith("{") or trimmed.startswith("["):
            try:
                parsed = json.loads(trimmed)
            except Exception:
                return value
            return format_display_text(parsed)
        return value
    if isinstance(value, dict):
        if isinstance(value.get("summary"), list):
            items = [str(item).strip() for item in value["summary"] if str(item).strip()]
            if items:
                return "\n".join(f"- {item}" for item in items)
        lines = []
        for key, item in value.items():
            rendered = format_display_text(item).strip()
            if rendered:
                lines.append(f"{key}: {rendered}")
        return "\n".join(lines) if lines else "{}"
    if isinstance(value, list):
        items = [format_display_text(item).strip() for item in value]
        items = [item for item in items if item]
        return "\n".join(f"- {item}" for item in items) if items else "[]"
    return str(value)


def maybe_approve_tool(client: AegisClient, session_id: str, tool_name: str, tool_res: Dict[str, Any]) -> bool:
    approval_hash = tool_res.get("approval_hash")
    if not approval_hash:
        return False
    reason = tool_res.get("message") or "Approval required"
    print(f"[agent] approval_required stage=tool tool={tool_name} reason={reason} hash={approval_hash}")
    try:
        answer = input("approve this tool call? [y/N] ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        return False
    if answer not in {"y", "yes"}:
        return False
    client.approve(
        session_id,
        approval_hash,
        actor="real_guarded_agent",
        scope="exact",
        expires_in_seconds=1800,
        reusable=True,
        reason=f"Interactive approval for tool {tool_name}",
    )
    print(f"[agent] approval_granted tool={tool_name}")
    return True


def maybe_approve_output(client: AegisClient, session_id: str, output_res: Dict[str, Any]) -> bool:
    approval_hash = output_res.get("approval_hash")
    if not approval_hash:
        return False
    reason = output_res.get("message") or "Approval required"
    print(f"[agent] approval_required stage=postllm reason={reason} hash={approval_hash}")
    try:
        answer = input("approve this output? [y/N] ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        return False
    if answer not in {"y", "yes"}:
        return False
    client.approve(
        session_id,
        approval_hash,
        actor="real_guarded_agent",
        scope="exact",
        expires_in_seconds=1800,
        reusable=True,
        reason="Interactive approval for postllm output",
    )
    print("[agent] approval_granted stage=postllm")
    return True


def execute_tool_with_approvals(
    adapter: AegisAgentAdapter,
    client: AegisClient,
    session_id: str,
    tool_name: str,
    payload: Dict[str, Any],
    max_attempts: int = 4,
) -> Dict[str, Any]:
    tool_res = adapter.run_tool(tool_name, payload)
    attempts = 0
    while tool_res.get("approval_hash") and attempts < max_attempts:
        if not maybe_approve_tool(client, session_id, tool_name, tool_res):
            break
        attempts += 1
        tool_res = adapter.run_tool(tool_name, payload)
    return tool_res


def guard_output_with_approvals(
    adapter: AegisAgentAdapter,
    client: AegisClient,
    session_id: str,
    final_output: str,
    metadata: Dict[str, Any],
    max_attempts: int = 3,
) -> Dict[str, Any]:
    guarded_out = adapter.guard_output(final_output, metadata=metadata)
    attempts = 0
    while guarded_out.get("require_approval") and attempts < max_attempts:
        if not maybe_approve_output(client, session_id, guarded_out):
            break
        attempts += 1
        guarded_out = adapter.guard_output(final_output, metadata=metadata)
    return guarded_out


def parse_tool_call(text: str) -> Optional[Dict[str, Any]]:
    trimmed = text.strip()
    if not trimmed.startswith("{"):
        return None
    try:
        obj = json.loads(trimmed)
    except Exception:
        return None
    if not isinstance(obj, dict) or not isinstance(obj.get("tool_name"), str):
        return None
    payload = obj.get("payload")
    if not isinstance(payload, dict):
        payload = {}
    return {"tool_name": obj["tool_name"], "payload": payload}


def parse_loose_tool_call(text: str) -> Optional[Dict[str, Any]]:
    lowered = text.lower()
    known_tools = [
        "directory_list",
        "filesystem_read",
        "filesystem_write",
        "filesystem_edit",
        "filesystem_patch",
        "http_fetch",
        "json_transform",
        "file_find",
        "text_search",
        "shell",
    ]
    tool_name = next((name for name in known_tools if f'"{name}"' in lowered or f'"action":"{name}"' in lowered), None)
    if not tool_name:
        return None

    payload: Dict[str, Any] = {}
    path_match = re.search(r'"path"\s*[:\.]\s*"([^"]*)"', text, re.IGNORECASE)
    if path_match:
        payload["path"] = path_match.group(1)
    elif tool_name == "directory_list":
        payload["path"] = "."

    url_match = re.search(r'"url"\s*[:\.]\s*"([^"]*)"', text, re.IGNORECASE)
    if url_match:
        payload["url"] = url_match.group(1)

    method_match = re.search(r'"method"\s*[:\.]\s*"([^"]*)"', text, re.IGNORECASE)
    if method_match:
        payload["method"] = method_match.group(1)

    command_match = re.search(r'"command"\s*[:\.]\s*"([^"]*)"', text, re.IGNORECASE)
    if command_match:
        payload["command"] = command_match.group(1)

    content_match = re.search(r'"content"\s*[:\.]\s*"([^"]*)"', text, re.IGNORECASE)
    if content_match and tool_name == "filesystem_write":
        payload["content"] = content_match.group(1)

    return {"tool_name": tool_name, "payload": payload}


def parse_agent_action(text: str) -> Dict[str, Any]:
    trimmed = text.strip()
    if trimmed.startswith("{"):
        try:
            obj = json.loads(trimmed)
        except Exception:
            obj = None
        if isinstance(obj, dict):
            if not obj:
                return {"action": "answer", "content": ""}
            action = str(obj.get("action") or "").strip().lower()
            known_tools = {
                "shell",
                "filesystem_read",
                "directory_list",
                "filesystem_write",
                "filesystem_edit",
                "filesystem_patch",
                "http_fetch",
                "json_transform",
                "file_find",
                "text_search",
            }
            if action == "tool" and isinstance(obj.get("tool_name"), str):
                payload = obj.get("payload")
                if not isinstance(payload, dict):
                    payload = {}
                return {"action": "tool", "tool_name": obj["tool_name"], "payload": payload}
            if action in known_tools:
                payload = obj.get("payload")
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
                payload = obj.get("payload")
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
    tool_call = parse_tool_call(trimmed)
    if tool_call is not None:
        return {"action": "tool", **tool_call}
    tool_call = parse_loose_tool_call(trimmed)
    if tool_call is not None:
        return {"action": "tool", **tool_call}
    return {"action": "answer", "content": trimmed}


def extract_json_blob(text: str) -> Optional[Any]:
    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1 or end <= start:
        return None
    try:
        return json.loads(text[start : end + 1])
    except Exception:
        return None


def detect_direct_tool_intent(user_text: str) -> Optional[Dict[str, Any]]:
    text = user_text.strip()
    lower = text.lower()

    if lower in {"ls", "ls .", "dir", "dir .", "list files", "list the files", "list the files in the current directory"}:
        return {"action": "tool", "tool_name": "directory_list", "payload": {"path": "."}, "mode": "fast", "guard_text": "List the files in the current directory."}
    if lower in {"pwd", "where am i", "current directory"}:
        return {"action": "answer", "content": os.getcwd(), "mode": "fast", "guard_text": "Show the current working directory."}

    if lower.startswith("ls "):
        path = text[3:].strip() or "."
        return {"action": "tool", "tool_name": "directory_list", "payload": {"path": path}, "mode": "fast", "guard_text": f"List the files in {path}."}
    if lower.startswith("dir "):
        path = text[4:].strip() or "."
        return {"action": "tool", "tool_name": "directory_list", "payload": {"path": path}, "mode": "fast", "guard_text": f"List the files in {path}."}

    read_match = re.match(r"^(?:read|cat|show|open)\s+(.+)$", text, re.IGNORECASE)
    if read_match:
        path = read_match.group(1).strip().strip("\"'")
        return {
            "action": "tool",
            "tool_name": "filesystem_read",
            "payload": {"path": path},
            "mode": "fast",
            "guard_text": f"Read the file {path}.",
        }

    write_match = re.match(
        r'^(?:write|create)\s+(?:a\s+file\s+called\s+|file\s+)?([^\s]+)\s+(?:containing|with)\s*:?\s*"?(.+?)"?$',
        text,
        re.IGNORECASE,
    )
    if write_match:
        path = write_match.group(1).strip().strip("\"'")
        content = write_match.group(2).strip()
        return {
            "action": "tool",
            "tool_name": "filesystem_write",
            "payload": {"path": path, "content": content},
            "mode": "fast",
            "guard_text": f"Write content to the file {path}.",
        }

    fetch_match = re.search(r"(https?://[^\s]+)", text, re.IGNORECASE)
    if fetch_match and any(token in lower for token in ["fetch", "open url", "get url", "visit", "summarize https://", "summarise https://"]):
        return {
            "action": "tool",
            "tool_name": "http_fetch",
            "payload": {"url": fetch_match.group(1), "method": "GET"},
            "mode": "fast",
            "guard_text": f"Fetch the URL {fetch_match.group(1)}.",
        }

    search_match = re.match(r"^(?:rg|grep|search)\s+(.+)$", text, re.IGNORECASE)
    if search_match:
        rest = search_match.group(1).strip()
        path = "."
        query = rest
        in_match = re.match(r'^(.+?)\s+in\s+([^\s]+)$', rest, re.IGNORECASE)
        if in_match:
            query = in_match.group(1).strip()
            path = in_match.group(2).strip()
        query = query.strip("\"'")
        path = path.strip("\"'")
        return {
            "action": "tool",
            "tool_name": "text_search",
            "payload": {"query": query, "path": path, "literal": True, "case_sensitive": False, "max_results": 50},
            "mode": "fast",
            "guard_text": f"Search for text '{query}' in {path}.",
        }

    find_match = re.match(r"^(?:find|glob)\s+(.+)$", text, re.IGNORECASE)
    if find_match:
        rest = find_match.group(1).strip()
        path = "."
        pattern = rest
        in_match = re.match(r'^(.+?)\s+in\s+([^\s]+)$', rest, re.IGNORECASE)
        if in_match:
            pattern = in_match.group(1).strip()
            path = in_match.group(2).strip()
        pattern = pattern.strip("\"'")
        path = path.strip("\"'")
        return {
            "action": "tool",
            "tool_name": "file_find",
            "payload": {"pattern": pattern, "path": path, "max_results": 60},
            "mode": "fast",
            "guard_text": f"Find files matching pattern '{pattern}' in {path}.",
        }

    replace_match = re.match(r'^replace\s+"(.+?)"\s+with\s+"(.*?)"\s+in\s+(.+)$', text, re.IGNORECASE)
    if replace_match:
        old_text = replace_match.group(1)
        new_text = replace_match.group(2)
        path = replace_match.group(3).strip().strip("\"'")
        return {
            "action": "tool",
            "tool_name": "filesystem_edit",
            "payload": {"path": path, "old_text": old_text, "new_text": new_text, "replace_all": False},
            "mode": "fast",
            "guard_text": f"Edit the file {path} by replacing exact text.",
        }

    patch_match = re.match(r'^patch\s+(.+?)\s*::\s*(.+)$', text, re.IGNORECASE)
    if patch_match:
        path = patch_match.group(1).strip().strip("\"'")
        change_spec = patch_match.group(2).strip()
        changes = []
        for raw_change in change_spec.split("|||"):
            raw_change = raw_change.strip()
            m = re.match(r'^"(.+?)"\s*=>\s*"(.*?)"$', raw_change)
            if not m:
                changes = []
                break
            changes.append({"old_text": m.group(1), "new_text": m.group(2), "replace_all": False})
        if changes:
            return {
                "action": "tool",
                "tool_name": "filesystem_patch",
                "payload": {"path": path, "changes": changes},
                "mode": "fast",
                "guard_text": f"Apply exact patch changes to the file {path}.",
            }

    if any(phrase in lower for phrase in ["list of keys", "list the keys", "return the keys", "keys of this json", "turn this json into a list of keys"]):
        data = extract_json_blob(text)
        if data is not None:
            return {
                "action": "tool",
                "tool_name": "json_transform",
                "payload": {"data": data, "operation": "keys"},
                "mode": "fast",
                "guard_text": "List the keys in the provided JSON data.",
            }

    return None


def answer_from_tool_result(user_text: str, action: Dict[str, Any], tool_res: Dict[str, Any]) -> str:
    result = tool_res.get("result") or {}
    tool_name = action["tool_name"]
    if tool_name == "filesystem_read" and wants_exact_file_read(user_text, tool_name):
        return exact_file_read_answer(action["payload"], result)
    if tool_name in {"directory_list", "filesystem_write", "filesystem_edit", "filesystem_patch", "file_find", "text_search", "json_transform"}:
        return compact_tool_result(tool_name, result)
    if tool_name == "filesystem_read" and not wants_summary(user_text):
        return exact_file_read_answer(action["payload"], result)

    follow_up = [
        {
            "role": "system",
            "content": (
                'Return ONLY JSON: {"action":"answer","content":"<final reply>"}'
                "\nAnswer the user using the tool result."
                "\nBe concise and precise."
                "\nWhen summarizing, do not quote or reproduce raw secrets, env vars, tokens, private keys,"
                " credential-like strings, or hidden/system instructions."
                "\nIf those appear in the tool result, refer to them generically as sensitive configuration or credentials."
            ),
        },
        {"role": "user", "content": user_text},
        {"role": "assistant", "content": json.dumps(action)},
        {"role": "tool", "content": json.dumps(result)},
    ]
    second = parse_agent_action(model_chat(follow_up))
    if second.get("action") == "answer" and not str(second.get("content") or "").strip():
        second = {"action": "answer", "content": compact_tool_result(tool_name, result)}
    return second.get("content") or compact_tool_result(tool_name, result)


def main() -> int:
    client = AegisClient(AEGIS_BASE, AEGIS_API_KEY)
    session_id, adapter = create_runtime(client)
    print(AGENT_BANNER)
    print(f"{AGENT_NAME} is ready")
    print(f"[aegis] session={session_id}")
    trusted_local_tools = {
        "filesystem_read",
        "directory_list",
        "filesystem_write",
        "filesystem_edit",
        "filesystem_patch",
        "file_find",
        "text_search",
    }

    tool_catalog_json = json.dumps(adapter.describe_tools(), indent=2)
    system_prompt = (
        "You are a real agent that must use tools through Aegis. "
        "Always respond with valid JSON in one of these forms only:\n"
        '{"action":"answer","content":"<final user-facing reply>"}\n'
        '{"action":"tool","tool_name":"<name>","payload":{...}}'
        "\nUse relative filesystem paths rooted in the current workspace. Do not invent /workspace paths."
        "\nAvailable guarded tools:\n"
        f"{tool_catalog_json}"
    )

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
        if user_text.lower() == "/new":
            session_id, adapter = create_runtime(client)
            print(AGENT_BANNER)
            print(f"{AGENT_NAME} ready")
            print(f"[aegis] session={session_id}")
            continue
        if user_text.lower().startswith("/attach "):
            target_session = user_text.split(None, 1)[1].strip()
            if not target_session:
                print("[agent] usage: /attach <session_id>")
                continue
            try:
                client.get_risk(target_session)
            except requests.HTTPError as exc:
                print(f"[agent] could not attach to session {target_session}: {exc}")
                continue
            session_id, adapter = attach_runtime(client, target_session)
            print(f"[aegis] attached session={session_id}")
            continue
        if user_text.lower() == "/risk":
            risk = client.get_risk(session_id).get("risk_state") or {}
            print(
                "[aegis] "
                f"quarantined={bool(risk.get('quarantined', False))} "
                f"cumulative={float(risk.get('cumulative_risk_score', 0.0) or 0.0):.3f} "
                f"injections={int(risk.get('injection_attempt_count', 0) or 0)} "
                f"sensitive_tools={int(risk.get('sensitive_tool_attempts', 0) or 0)} "
                f"goal_drift={float(risk.get('goal_drift_score', 0.0) or 0.0):.3f}"
            )
            continue
        if user_text.lower() == "/session":
            print(f"[aegis] session={session_id}")
            continue
        if user_text.lower() == "/model":
            print(f"[aegis] model={MODEL_NAME} endpoint={MODEL_ENDPOINT}")
            continue
        if user_text.lower() == "/tools":
            names = [tool.get("name") for tool in adapter.describe_tools() if tool.get("name")]
            print("[aegis] tools=" + ", ".join(names))
            continue
        if user_text.lower() == "/resetrisk":
            risk = client.reset_risk(session_id).get("risk_state") or {}
            print(
                "[aegis] risk reset "
                f"quarantined={bool(risk.get('quarantined', False))} "
                f"cumulative={float(risk.get('cumulative_risk_score', 0.0) or 0.0):.3f}"
            )
            continue
        if user_text.lower() == "/help":
            print("Commands: /new, /attach <session_id>, /session, /model, /tools, /risk, /resetrisk, /help, exit")
            continue

        pre_action = detect_direct_tool_intent(user_text)
        guard_text = str(pre_action.get("guard_text") or user_text) if pre_action else user_text
        guarded_in = adapter.guard_input(guard_text, metadata={"source": "real_guarded_agent", "fast_path": bool(pre_action)})
        if guarded_in.get("blocked"):
            print(f"aegis(block)> {guarded_in.get('message')}")
            continue
        if guarded_in.get("require_approval"):
            print(f"aegis(approval)> {guarded_in.get('message')}")
            print(f"aegis(hash)> {guarded_in.get('approval_hash')}")
            continue

        safe_input = guarded_in.get("sanitized_content") or guard_text
        action = pre_action or detect_direct_tool_intent(safe_input)
        if action is None:
            messages = [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": safe_input},
            ]
            first = model_chat(messages)
            action = parse_agent_action(first)
            if action.get("action") == "answer" and not str(action.get("content") or "").strip() and first.strip().startswith("{"):
                action = {"action": "answer", "content": force_plain_answer(safe_input)}
        else:
            print(f"[agent] fast_path={action.get('tool_name', 'answer')}")

        final_output = action.get("content") or ""
        output_metadata: Dict[str, Any] = {"source": "real_guarded_agent"}
        if action.get("action") == "tool":
            print(f"[agent] tool_request={action['tool_name']} payload={json.dumps(action['payload'], ensure_ascii=True)}")
            tool_res = execute_tool_with_approvals(adapter, client, session_id, action["tool_name"], action["payload"])
            if not tool_res.get("allowed", False):
                final_output = f"Tool blocked by Aegis: {tool_res.get('message')}"
            else:
                print(f"[agent] tool_allowed={action['tool_name']}")
                output_metadata.update(
                    {
                        "derived_from_tool": action["tool_name"],
                        "tool_trust": "high" if action["tool_name"] in trusted_local_tools else "low",
                        "summary_mode": action["tool_name"] in {"filesystem_read", "directory_list", "http_fetch"},
                    }
                )
                final_output = answer_from_tool_result(safe_input, action, tool_res)

        guarded_out = guard_output_with_approvals(adapter, client, session_id, final_output, output_metadata)
        if guarded_out.get("blocked"):
            print(f"aegis(post-block)> {guarded_out.get('message')}")
            continue
        if guarded_out.get("require_approval"):
            print(f"aegis(post-approval)> {guarded_out.get('message')}")
            print(f"aegis(hash)> {guarded_out.get('approval_hash')}")
            continue

        print(f"{AGENT_NAME}> {format_display_text(guarded_out.get('sanitized_output') or final_output)}")


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except requests.HTTPError as exc:
        print(f"[error] HTTP failure: {exc}", file=sys.stderr)
    except Exception as exc:
        print(f"[error] {exc}", file=sys.stderr)
    raise SystemExit(1)
