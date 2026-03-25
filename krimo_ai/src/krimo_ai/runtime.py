from __future__ import annotations

import json
import re
from typing import Any, Dict

from aegis.tools.agent_adapter import AegisAgentAdapter
from aegis.tools.client import AegisClient

from .actions import parse_agent_action
from .config import AGENT_ENV, FILESYSTEM_ROOT, MODEL_STREAM_ENABLED
from .memory import AgentMemory
from .modeling import add_line_references, model_chat
from .rendering import compact_tool_result, exact_file_read_answer, wants_exact_file_read, wants_summary
from .vision import VisionCapabilities


PII_INPUT_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b|\b(?:\d[ -]*?){13,19}\b", re.IGNORECASE)


def _normalize_web_url(value: str) -> str:
    candidate = str(value or "").strip().strip("\"'")
    if not candidate:
        return ""
    if re.match(r"^https?://", candidate, re.IGNORECASE):
        return candidate
    if re.match(r"^[A-Za-z0-9.-]+\.[A-Za-z]{2,}(/\S*)?$", candidate):
        return "https://" + candidate
    return candidate


def normalize_action_payload(action: Dict[str, Any]) -> Dict[str, Any]:
    if action.get("action") != "tool":
        return action
    tool_name = str(action.get("tool_name") or "")
    payload = action.get("payload")
    if not isinstance(payload, dict):
        payload = {}
        action["payload"] = payload
    if tool_name in {"browser_navigate", "web_open", "http_fetch"} and "url" in payload:
        payload["url"] = _normalize_web_url(str(payload.get("url") or ""))
    return action


def attach_runtime(client: AegisClient, session_id: str) -> tuple[str, AegisAgentAdapter]:
    adapter = AegisAgentAdapter(client, session_id, environment=AGENT_ENV, filesystem_root=FILESYSTEM_ROOT)
    return session_id, adapter


def create_runtime(client: AegisClient) -> tuple[str, AegisAgentAdapter]:
    session_id = client.create_session()
    return attach_runtime(client, session_id)


def build_memory_context(memory: AgentMemory) -> str:
    rendered = memory.render()
    return "" if rendered == "No working memory yet." else f"\nWorking memory:\n{rendered}\n"


def maybe_sensitive_input_notice(user_text: str, guarded_in: Dict[str, Any]) -> str | None:
    if guarded_in.get("blocked") or guarded_in.get("require_approval"):
        return None
    sanitized = str(guarded_in.get("sanitized_content") or "")
    if not sanitized or sanitized == user_text:
        return None
    if not PII_INPUT_RE.search(user_text or ""):
        return None
    return "Please don't send sensitive personal data here. Redact it first, then I can still help with the rest of your request."


def summarize_code_file(path: str, content: str, memory: AgentMemory) -> str:
    prompt = (
        f"Summarize the code in {path}.\n"
        "Focus on purpose, important functions/classes, data flow, and risks.\n"
        "Cite specific line numbers from the provided source.\n"
        "Return plain text bullets only."
        f"{build_memory_context(memory)}\n"
        "Source:\n"
        f"{add_line_references(content)}"
    )
    return model_chat(
        [
            {"role": "system", "content": "You are a concise senior engineer. Use the provided line numbers explicitly."},
            {"role": "user", "content": prompt},
        ],
        stream=MODEL_STREAM_ENABLED,
        stream_label=f"Summarizing code in {path}",
    )


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
    client.approve(session_id, approval_hash, actor="krimo_ai", scope="exact", expires_in_seconds=1800, reusable=True, reason=f"Interactive approval for tool {tool_name}")
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
    client.approve(session_id, approval_hash, actor="krimo_ai", scope="exact", expires_in_seconds=1800, reusable=True, reason="Interactive approval for postllm output")
    print("[agent] approval_granted stage=postllm")
    return True


def execute_tool_with_approvals(adapter: AegisAgentAdapter, client: AegisClient, session_id: str, tool_name: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    tool_res = adapter.run_tool(tool_name, payload)
    attempts = 0
    while tool_res.get("approval_hash") and attempts < 4:
        if not maybe_approve_tool(client, session_id, tool_name, tool_res):
            break
        attempts += 1
        tool_res = adapter.run_tool(tool_name, payload)
    return tool_res


def guard_output_with_approvals(adapter: AegisAgentAdapter, client: AegisClient, session_id: str, final_output: str, metadata: Dict[str, Any]) -> Dict[str, Any]:
    guarded_out = adapter.guard_output(final_output, metadata=metadata)
    attempts = 0
    while guarded_out.get("require_approval") and attempts < 3:
        if not maybe_approve_output(client, session_id, guarded_out):
            break
        attempts += 1
        guarded_out = adapter.guard_output(final_output, metadata=metadata)
    return guarded_out


def answer_from_tool_result(user_text: str, action: Dict[str, Any], tool_res: Dict[str, Any]) -> str:
    result = tool_res.get("result") or {}
    tool_name = action["tool_name"]
    if tool_name == "filesystem_read" and wants_exact_file_read(user_text, tool_name):
        return exact_file_read_answer(action["payload"], result)
    if tool_name in {"directory_list", "filesystem_write", "filesystem_edit", "filesystem_patch", "file_find", "repo_map", "text_search", "json_transform", "web_search", "web_open"}:
        return compact_tool_result(tool_name, result)
    if tool_name == "filesystem_read" and not wants_summary(user_text):
        return exact_file_read_answer(action["payload"], result)
    follow_up = [
        {"role": "system", "content": 'Return ONLY JSON: {"action":"answer","content":"<final reply>"}\nAnswer the user using the tool result.'},
        {"role": "user", "content": user_text},
        {"role": "assistant", "content": json.dumps(action)},
        {"role": "tool", "content": json.dumps(result)},
    ]
    second = parse_agent_action(model_chat(follow_up))
    return second.get("content") or compact_tool_result(tool_name, result)


def update_memory_from_tool(memory: AgentMemory, action: Dict[str, Any], result: Dict[str, Any]) -> None:
    tool_name = action.get("tool_name")
    payload = action.get("payload") or {}
    if tool_name in {"filesystem_read", "filesystem_write", "filesystem_edit", "filesystem_patch"}:
        memory.remember_file(str(payload.get("path") or ""))
    if tool_name == "text_search":
        memory.remember_search(str(payload.get("query") or ""))
    if tool_name == "file_find":
        memory.remember_search(f"find:{payload.get('pattern')}")
    if tool_name == "web_search":
        memory.remember_search(str(payload.get("query") or ""))
        memory.remember_web_results(list(result.get("results") or []))
    if tool_name == "web_open":
        memory.remember_page(str(result.get("url") or ""), list(result.get("links") or []))


def execute_agent_tool_action(adapter: AegisAgentAdapter, client: AegisClient, session_id: str, action: Dict[str, Any], user_text: str, memory: AgentMemory, trusted_local_tools: set[str]) -> tuple[str, Dict[str, Any]]:
    print(f"[agent] tool_request={action['tool_name']} payload={json.dumps(action['payload'], ensure_ascii=True)}")
    tool_res = execute_tool_with_approvals(adapter, client, session_id, action["tool_name"], action["payload"])
    output_metadata: Dict[str, Any] = {"source": "krimo_ai"}
    if (
        not tool_res.get("allowed", False)
        and action["tool_name"] == "browser_navigate"
        and "Browser automation unavailable" in str(tool_res.get("message") or "")
    ):
        fallback_action = {
            "action": "tool",
            "tool_name": "web_open",
            "payload": {"url": str(action["payload"].get("url") or ""), "max_links": 12},
        }
        print("[agent] browser_unavailable_fallback=web_open")
        tool_res = execute_tool_with_approvals(adapter, client, session_id, "web_open", fallback_action["payload"])
        action = fallback_action
    if not tool_res.get("allowed", False):
        message = str(tool_res.get("message") or "Tool failed")
        lowered = message.lower()
        if lowered == "unknown tool" or "unknown tool" in lowered:
            return f"Tool/runtime error: {message}", output_metadata
        if (
            "valid http/https url" in lowered
            or "browser automation unavailable" in lowered
            or "path does not exist" in lowered
            or "no such file" in lowered
            or "failed:" in lowered
            or "unavailable" in lowered
        ):
            return f"Tool/runtime error: {message}", output_metadata
        return f"Tool blocked by Aegis: {message}", output_metadata
    print(f"[agent] tool_allowed={action['tool_name']}")
    result = tool_res.get("result") or {}
    if action["tool_name"] == "browser_navigate" and action.get("mode") == "browser_explore":
        result = _explore_browser_state(adapter, client, session_id, result)
        tool_res["result"] = result
    update_memory_from_tool(memory, action, result)
    output_metadata.update({"derived_from_tool": action["tool_name"], "tool_trust": "high" if action["tool_name"] in trusted_local_tools else "low"})
    if action.get("mode") == "code_summary":
        path = str(action["payload"].get("path") or "the file")
        content = str(result.get("content") or "")
        return summarize_code_file(path, content, memory), output_metadata
    return answer_from_tool_result(user_text, action, tool_res), output_metadata


def _pick_primary_button(result: Dict[str, Any]) -> str:
    buttons = list(result.get("buttons") or [])
    priority = [r"authorize", r"unlock", r"enter", r"continue", r"launch", r"start", r"open", r"login", r"sign in"]
    for pattern in priority:
        for item in buttons:
            text = str(item.get("text") or "")
            selector = str(item.get("selector") or "")
            if selector and re.search(pattern, text, re.IGNORECASE):
                return selector
    for item in buttons:
        selector = str(item.get("selector") or "")
        text = str(item.get("text") or "")
        if selector and text:
            return selector
    return ""


def _looks_like_transitional_boot_screen(text_preview: str) -> bool:
    lowered = text_preview.lower()
    boot_tokens = [
        "bios version",
        "booting",
        "initializing",
        "storage devices",
        "virtual vfs",
        "boot process",
        "system ready",
        "guest",
    ]
    return sum(1 for token in boot_tokens if token in lowered) >= 2


def _looks_like_login_gate(result: Dict[str, Any]) -> bool:
    text_preview = str(result.get("text_preview") or "").lower()
    buttons = list(result.get("buttons") or [])
    inputs = list(result.get("inputs") or [])
    gate_tokens = [
        "authorize",
        "unlock",
        "login",
        "log in",
        "sign in",
        "guest",
        "system ready",
        "biometric",
        "ready",
    ]
    button_text = " ".join(str(item.get("text") or "").lower() for item in buttons)
    return bool(buttons) and (any(token in text_preview for token in gate_tokens) or any(token in button_text for token in gate_tokens) or bool(inputs))


def _looks_like_real_content_view(result: Dict[str, Any]) -> bool:
    text_preview = str(result.get("text_preview") or "")
    lowered = text_preview.lower()
    link_count = int(result.get("link_count") or 0)
    headings = list(result.get("headings") or [])
    buttons = list(result.get("buttons") or [])
    if _looks_like_transitional_boot_screen(text_preview):
        return False
    if _looks_like_login_gate(result):
        return False
    if any(token in lowered for token in ["portfolio", "about", "projects", "experience", "contact", "skills"]):
        return True
    if len(text_preview) >= 280 and (link_count >= 2 or len(headings) >= 2):
        return True
    if len(text_preview) >= 500 and len(buttons) <= 2:
        return True
    return False


def _describe_browser_screenshot(path: str) -> str:
    try:
        vision = VisionCapabilities()
        vision_result = vision.analyze_image_file(path)
    except Exception as exc:
        return f"visual analysis unavailable: {exc}"
    if not vision_result.success:
        return f"visual analysis unavailable: {vision_result.error or 'unknown error'}"
    description = (vision_result.description or "").strip()
    return description[:600] if description else "visual analysis produced no description"


def _explore_browser_state(adapter: AegisAgentAdapter, client: AegisClient, session_id: str, result: Dict[str, Any]) -> Dict[str, Any]:
    current = result
    for _ in range(5):
        text_preview = str(current.get("text_preview") or "")
        buttons = list(current.get("buttons") or [])
        inputs = list(current.get("inputs") or [])
        if _looks_like_real_content_view(current):
            current["auto_reached_content"] = True
            break
        if _looks_like_transitional_boot_screen(text_preview) and not buttons and not inputs:
            snapshot_res = execute_tool_with_approvals(adapter, client, session_id, "browser_snapshot", {"wait_ms": 2600})
            if snapshot_res.get("allowed") and isinstance(snapshot_res.get("result"), dict):
                current = snapshot_res["result"]
                current["auto_waited_for_transition"] = True
                continue
        selector = _pick_primary_button(current)
        if selector and _looks_like_login_gate(current):
            click_res = execute_tool_with_approvals(adapter, client, session_id, "browser_click", {"selector": selector})
            if click_res.get("allowed") and isinstance(click_res.get("result"), dict):
                current = click_res["result"]
                current["auto_interacted"] = True
                current["auto_selector"] = selector
                continue
        if not _looks_like_real_content_view(current) and len(text_preview) < 260:
            scroll_res = execute_tool_with_approvals(adapter, client, session_id, "browser_scroll", {"pixels": 1100})
            if scroll_res.get("allowed") and isinstance(scroll_res.get("result"), dict):
                current = scroll_res["result"]
                current["auto_scrolled"] = True
                continue
        snapshot_res = execute_tool_with_approvals(adapter, client, session_id, "browser_snapshot", {"wait_ms": 1800})
        if snapshot_res.get("allowed") and isinstance(snapshot_res.get("result"), dict):
            current = snapshot_res["result"]
            if _looks_like_real_content_view(current):
                current["auto_reached_content"] = True
                break
            if current.get("buttons") or current.get("inputs") or len(str(current.get("text_preview") or "")) > max(80, len(text_preview)):
                continue
        break
    if not _looks_like_real_content_view(current):
        screenshot_res = execute_tool_with_approvals(adapter, client, session_id, "browser_screenshot", {})
        if screenshot_res.get("allowed") and isinstance(screenshot_res.get("result"), dict):
            current.update(screenshot_res["result"])
            screenshot_path = str(current.get("screenshot_path") or "")
            if screenshot_path:
                current["vision_summary"] = _describe_browser_screenshot(screenshot_path)
    return current


def run_autocode_task(task: str, adapter: AegisAgentAdapter, client: AegisClient, session_id: str, tool_catalog_json: str, memory: AgentMemory, trusted_local_tools: set[str]) -> str:
    observations: list[str] = []
    for step in range(1, 5):
        plan_prompt = (
            "You are KriMo, a guarded local coding agent.\n"
            "Return only valid JSON in one of these forms:\n"
            '{"action":"answer","content":"..."}\n'
            '{"action":"tool","tool_name":"...","payload":{...}}\n'
            f"Available tools:\n{tool_catalog_json}\n"
            f"{build_memory_context(memory)}"
            f"Current task:\n{task}\n"
            f"Step {step} of 4.\n"
        )
        if observations:
            plan_prompt += "Observations so far:\n" + "\n".join(f"- {item}" for item in observations[-6:]) + "\n"
        action = parse_agent_action(
            model_chat(
                [
                    {"role": "system", "content": "Return only JSON. Prefer the smallest useful next action."},
                    {"role": "user", "content": plan_prompt},
                ],
                stream=MODEL_STREAM_ENABLED,
                stream_label=f"Autocode step {step}",
            )
        )
        if action.get("action") == "answer":
            content = str(action.get("content") or "").strip()
            if content:
                return content
            observations.append("empty answer")
            continue
        if action.get("action") != "tool":
            observations.append(f"unsupported action {action}")
            continue
        result_text, _ = execute_agent_tool_action(adapter, client, session_id, action, task, memory, trusted_local_tools)
        observations.append(f"{action['tool_name']}: {result_text[:600]}")
    synthesis_prompt = f"Finish this coding task based on the observations below.\nTask: {task}\n" + "\n".join(f"- {item}" for item in observations[-8:])
    return model_chat(
        [
            {"role": "system", "content": "Answer plainly and concisely based only on the provided observations."},
            {"role": "user", "content": synthesis_prompt},
        ],
        stream=MODEL_STREAM_ENABLED,
        stream_label="Synthesizing final coding answer",
    )
