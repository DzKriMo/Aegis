from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

import requests

from ..tools.agent_adapter import AegisAgentAdapter


MODEL_ENDPOINT = os.getenv("AGENT_MODEL_ENDPOINT", "http://127.0.0.1:11434/v1/chat/completions")
MODEL_NAME = os.getenv("AGENT_MODEL_NAME", "qwen2.5:7b-instruct")
MODEL_TEMPERATURE = float(os.getenv("AGENT_MODEL_TEMPERATURE", "0.1"))
MODEL_MAX_TOKENS = int(os.getenv("AGENT_MODEL_MAX_TOKENS", "400"))
MODEL_STREAM_ENABLED = os.getenv("AGENT_MODEL_STREAM", "true").lower() in {"1", "true", "yes", "on"}
AGENT_ENV = os.getenv("AEGIS_AGENT_ENV", "dev")
FILESYSTEM_ROOT = os.getenv("AEGIS_AGENT_FILESYSTEM_ROOT", os.getcwd())
MODEL_SESSION = requests.Session()
PII_INPUT_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b|\b(?:\d[ -]*?){13,19}\b", re.IGNORECASE)


@dataclass
class AgentMemory:
    recent_files: list[str] = field(default_factory=list)
    recent_searches: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    web_results: list[dict[str, str]] = field(default_factory=list)
    page_links: list[dict[str, str]] = field(default_factory=list)
    current_page: Optional[str] = None

    def remember_file(self, path: str) -> None:
        path = path.strip()
        if not path:
            return
        self.recent_files = [path] + [p for p in self.recent_files if p != path]
        self.recent_files = self.recent_files[:8]

    def remember_search(self, query: str) -> None:
        query = query.strip()
        if not query:
            return
        self.recent_searches = [query] + [q for q in self.recent_searches if q != query]
        self.recent_searches = self.recent_searches[:8]

    def remember_note(self, note: str) -> None:
        note = note.strip()
        if not note:
            return
        self.notes = [note] + self.notes[:11]

    def as_dict(self) -> Dict[str, Any]:
        return {
            "recent_files": list(self.recent_files),
            "recent_searches": list(self.recent_searches),
            "notes": list(self.notes),
            "web_results": list(self.web_results),
            "page_links": list(self.page_links),
            "current_page": self.current_page,
        }

    def render(self) -> str:
        parts = []
        if self.recent_files:
            parts.append("Recent files: " + ", ".join(self.recent_files))
        if self.recent_searches:
            parts.append("Recent searches: " + " | ".join(self.recent_searches))
        if self.notes:
            parts.append("Notes: " + " | ".join(self.notes[:5]))
        if self.current_page:
            parts.append(f"Current page: {self.current_page}")
        if self.web_results:
            parts.append("Web results: " + " | ".join(f"{idx + 1}:{item.get('title') or item.get('url')}" for idx, item in enumerate(self.web_results[:5])))
        if self.page_links:
            parts.append("Page links: " + " | ".join(f"{idx + 1}:{item.get('text') or item.get('url')}" for idx, item in enumerate(self.page_links[:5])))
        return "\n".join(parts) if parts else "No working memory yet."

    def remember_web_results(self, results: list[Dict[str, str]]) -> None:
        self.web_results = list(results[:10])

    def remember_page(self, url: str, links: list[Dict[str, str]]) -> None:
        self.current_page = url.strip() or None
        self.page_links = list(links[:20])


def build_memory_context(memory: AgentMemory) -> str:
    rendered = memory.render()
    return "" if rendered == "No working memory yet." else f"\nWorking memory:\n{rendered}\n"


def maybe_sensitive_input_notice(user_text: str, guarded_in: Dict[str, Any]) -> Optional[str]:
    if guarded_in.get("blocked") or guarded_in.get("require_approval"):
        return None
    sanitized = str(guarded_in.get("sanitized_content") or "")
    if not sanitized or sanitized == user_text:
        return None
    if not PII_INPUT_RE.search(user_text or ""):
        return None
    return "Please don't send sensitive personal data here. Redact it first, then I can still help with the rest of your request."


def model_chat(messages: list[dict[str, str]], stream: bool = False) -> str:
    payload = {
        "model": MODEL_NAME,
        "temperature": MODEL_TEMPERATURE,
        "max_tokens": MODEL_MAX_TOKENS,
        "messages": messages,
    }
    if stream:
        payload["stream"] = True
        resp = MODEL_SESSION.post(MODEL_ENDPOINT, json=payload, timeout=90, stream=True)
        resp.raise_for_status()
        parts: list[str] = []
        for raw in resp.iter_lines(decode_unicode=True):
            if not raw:
                continue
            line = raw.strip()
            if line == "data: [DONE]":
                break
            if not line.startswith("data: "):
                continue
            try:
                chunk = json.loads(line[6:])
            except Exception:
                continue
            delta = (((chunk.get("choices") or [{}])[0].get("delta") or {}).get("content")) or ""
            if delta:
                parts.append(delta)
        return "".join(parts).strip()
    resp = MODEL_SESSION.post(MODEL_ENDPOINT, json=payload, timeout=90)
    resp.raise_for_status()
    return resp.json()["choices"][0]["message"]["content"].strip()


def exact_file_read_answer(payload: Dict[str, Any], result: Dict[str, Any]) -> str:
    path = str(payload.get("path") or "the file")
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
    return "\n".join(lines)


def render_file_find_result(result: Dict[str, Any]) -> str:
    matches = (result or {}).get("matches") or []
    pattern = str((result or {}).get("pattern") or "")
    if not matches:
        return f"No files found for pattern '{pattern}'."
    lines = [f"Found {len(matches)} file(s) for '{pattern}':"]
    for match in matches[:60]:
        lines.append(f"- {match.get('relative_path') or match.get('path')}")
    return "\n".join(lines)


def render_repo_map_result(result: Dict[str, Any]) -> str:
    path = str((result or {}).get("path") or ".")
    tree = (result or {}).get("tree") or []
    files = int((result or {}).get("file_count") or 0)
    dirs = int((result or {}).get("dir_count") or 0)
    exts = (result or {}).get("top_extensions") or []
    lines = [f"Repository map for {path}:", f"- files: {files}", f"- directories: {dirs}"]
    if exts:
        ext_summary = ", ".join(f"{item.get('extension')}: {item.get('count')}" for item in exts[:8])
        lines.append(f"- top extensions: {ext_summary}")
    if tree:
        lines.append("Tree:")
        lines.extend(f"  {line}" for line in tree[:80])
    return "\n".join(lines)


def compact_tool_result(tool_name: str, result: Dict[str, Any]) -> str:
    if tool_name == "directory_list":
        return render_directory_listing(result)
    if tool_name == "filesystem_read":
        return exact_file_read_answer({}, result)
    if tool_name == "filesystem_write":
        path = str((result or {}).get("path") or "the file")
        bytes_written = int((result or {}).get("bytes_written") or 0)
        return f"Wrote {bytes_written} bytes to {path}."
    if tool_name == "filesystem_edit":
        path = str((result or {}).get("path") or "the file")
        replacements = int((result or {}).get("replacements") or 0)
        return f"Updated {path} with {replacements} replacement(s)."
    if tool_name == "filesystem_patch":
        path = str((result or {}).get("path") or "the file")
        changes = (result or {}).get("changes") or []
        return f"Patched {path} with {len(changes)} change(s)."
    if tool_name == "file_find":
        return render_file_find_result(result)
    if tool_name == "repo_map":
        return render_repo_map_result(result)
    if tool_name == "text_search":
        return render_text_search_result(result)
    if tool_name == "json_transform":
        if isinstance(result.get("keys"), list):
            return "Keys: " + ", ".join(str(k) for k in result["keys"])
    if tool_name == "http_fetch":
        preview = str((result or {}).get("body_preview") or "")
        url = str((result or {}).get("url") or "")
        return f"Fetched {url}.\n\n{preview}" if preview else json.dumps(result)
    if tool_name == "web_search":
        results = (result or {}).get("results") or []
        query = str((result or {}).get("query") or "")
        if not results:
            return f"No web results found for '{query}'."
        lines = [f"Web results for '{query}':"]
        for idx, item in enumerate(results[:8], start=1):
            title = str(item.get("title") or item.get("url") or "")
            url = str(item.get("url") or "")
            snippet = str(item.get("snippet") or "").strip()
            lines.append(f"{idx}. {title}")
            lines.append(f"   {url}")
            if snippet:
                lines.append(f"   {snippet}")
        return "\n".join(lines)
    if tool_name == "web_open":
        title = str((result or {}).get("title") or "Untitled page")
        url = str((result or {}).get("url") or "")
        preview = str((result or {}).get("text_preview") or "").strip()
        links = (result or {}).get("links") or []
        lines = [title, url]
        if preview:
            lines.append("")
            lines.append(preview)
        if links:
            lines.append("")
            lines.append("Links:")
            for idx, item in enumerate(links[:8], start=1):
                lines.append(f"{idx}. {item.get('text') or item.get('url')}")
                lines.append(f"   {item.get('url')}")
        return "\n".join(lines)
    if tool_name in {"browser_navigate", "browser_click", "browser_type", "browser_snapshot", "browser_screenshot"}:
        title = str((result or {}).get("title") or "Browser page")
        url = str((result or {}).get("url") or "")
        preview = str((result or {}).get("text_preview") or "").strip()
        lines = [title, url]
        if preview:
            lines.extend(["", preview])
        if result.get("screenshot_path"):
            lines.extend(["", f"Screenshot: {result.get('screenshot_path')}"])
        links = (result or {}).get("links") or []
        if links:
            lines.append("")
            lines.append("Links:")
            for idx, item in enumerate(links[:8], start=1):
                lines.append(f"{idx}. {item.get('text') or item.get('href')}")
                lines.append(f"   {item.get('href') or item.get('url')}")
        return "\n".join(lines)
    return json.dumps(result)


def parse_agent_action(text: str) -> Dict[str, Any]:
    trimmed = text.strip()
    if trimmed.startswith("{"):
        try:
            obj = json.loads(trimmed)
        except Exception:
            obj = None
        if isinstance(obj, dict):
            action = str(obj.get("action") or "").strip().lower()
            if action == "answer":
                return {"action": "answer", "content": str(obj.get("content") or "")}
            if action in {
                "shell",
                "filesystem_read",
                "directory_list",
                "filesystem_write",
                "filesystem_edit",
                "filesystem_patch",
                "http_fetch",
                "json_transform",
                "file_find",
                "repo_map",
                "text_search",
                "web_search",
                "web_open",
                "browser_navigate",
                "browser_click",
                "browser_type",
                "browser_snapshot",
                "browser_screenshot",
            }:
                payload = obj.get("payload") if isinstance(obj.get("payload"), dict) else {}
                return {"action": "tool", "tool_name": action, "payload": payload}
            if action == "tool" and isinstance(obj.get("tool_name"), str):
                payload = obj.get("payload") if isinstance(obj.get("payload"), dict) else {}
                return {"action": "tool", "tool_name": obj["tool_name"], "payload": payload}
    return {"action": "answer", "content": trimmed}


def add_line_references(text: str, max_lines: int = 80) -> str:
    lines = text.splitlines()
    rendered = [f"{idx + 1}: {line}" for idx, line in enumerate(lines[:max_lines])]
    if len(lines) > max_lines:
        rendered.append(f"... truncated after {max_lines} lines")
    return "\n".join(rendered)


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
    )


def detect_direct_tool_intent(user_text: str) -> Optional[Dict[str, Any]]:
    text = user_text.strip()
    lower = text.lower()
    if lower in {"tree", "repo map", "repomap", "map repo"}:
        return {"action": "tool", "tool_name": "repo_map", "payload": {"path": ".", "max_depth": 3, "max_entries": 200}, "mode": "fast", "guard_text": "Build a repository map for the current workspace."}
    google_match = re.match(r"^(?:google|search google for|search web for|web search|search the web for)\s+(.+)$", text, re.IGNORECASE)
    if google_match:
        query = google_match.group(1).strip().strip("\"'")
        return {"action": "tool", "tool_name": "web_search", "payload": {"query": query, "max_results": 6}, "mode": "fast", "guard_text": f"Search the web for {query}."}
    browse_match = re.match(r"^(?:browse|browser open|browser navigate|navigate browser to)\s+(https?://\S+)$", text, re.IGNORECASE)
    if browse_match:
        url = browse_match.group(1).strip()
        return {"action": "tool", "tool_name": "browser_navigate", "payload": {"url": url}, "mode": "fast", "guard_text": f"Navigate the browser to {url}."}
    open_result_match = re.match(r"^open result\s+(\d+)$", lower, re.IGNORECASE)
    if open_result_match:
        return {"action": "browser_result", "index": int(open_result_match.group(1))}
    follow_link_match = re.match(r"^(?:follow|open) link\s+(\d+)$", lower, re.IGNORECASE)
    if follow_link_match:
        return {"action": "browser_link", "index": int(follow_link_match.group(1))}
    click_match = re.match(r"^(?:click|browser click)\s+(.+)$", text, re.IGNORECASE)
    if click_match:
        selector = click_match.group(1).strip()
        return {"action": "tool", "tool_name": "browser_click", "payload": {"selector": selector}, "mode": "fast", "guard_text": f"Click browser element {selector}."}
    type_match = re.match(r'^(?:type|browser type)\s+"(.+?)"\s+into\s+(.+?)(?:\s+and submit)?$', text, re.IGNORECASE)
    if type_match:
        typed = type_match.group(1)
        selector = type_match.group(2).strip()
        submit = "and submit" in lower
        return {"action": "tool", "tool_name": "browser_type", "payload": {"selector": selector, "text": typed, "submit": submit}, "mode": "fast", "guard_text": f"Type text into browser element {selector}."}
    if lower in {"browser snapshot", "snapshot page", "page snapshot"}:
        return {"action": "tool", "tool_name": "browser_snapshot", "payload": {}, "mode": "fast", "guard_text": "Capture a browser page snapshot."}
    if lower in {"browser screenshot", "take screenshot", "screenshot page"}:
        return {"action": "tool", "tool_name": "browser_screenshot", "payload": {}, "mode": "fast", "guard_text": "Capture a browser page screenshot."}
    if lower in {"ls", "ls .", "dir", "dir ."}:
        return {"action": "tool", "tool_name": "directory_list", "payload": {"path": "."}, "mode": "fast", "guard_text": "List the files in the current directory."}
    if lower in {"pwd", "where am i", "current directory"}:
        return {"action": "answer", "content": os.getcwd(), "mode": "fast", "guard_text": "Show the current working directory."}
    tree_match = re.match(r"^(?:tree|repo map)\s+(.+)$", text, re.IGNORECASE)
    if tree_match:
        path = tree_match.group(1).strip().strip("\"'")
        return {"action": "tool", "tool_name": "repo_map", "payload": {"path": path, "max_depth": 3, "max_entries": 200}, "mode": "fast", "guard_text": f"Build a repository map for {path}."}
    url_match = re.match(r"^(?:open|visit|navigate to|go to)\s+(https?://\S+)$", text, re.IGNORECASE)
    if url_match:
        url = url_match.group(1).strip()
        return {"action": "tool", "tool_name": "web_open", "payload": {"url": url, "max_links": 12}, "mode": "fast", "guard_text": f"Open the web page {url}."}
    read_match = re.match(r"^(?:read|cat|show|open)\s+(.+)$", text, re.IGNORECASE)
    if read_match:
        path = read_match.group(1).strip().strip("\"'")
        return {"action": "tool", "tool_name": "filesystem_read", "payload": {"path": path}, "mode": "fast", "guard_text": f"Read the file {path}."}
    search_match = re.match(r"^(?:rg|grep|search)\s+(.+)$", text, re.IGNORECASE)
    if search_match:
        rest = search_match.group(1).strip()
        path = "."
        query = rest
        in_match = re.match(r'^(.+?)\s+in\s+([^\s]+)$', rest, re.IGNORECASE)
        if in_match:
            query = in_match.group(1).strip()
            path = in_match.group(2).strip()
        query_clean = query.strip("\"'")
        path_clean = path.strip("\"'")
        return {
            "action": "tool",
            "tool_name": "text_search",
            "payload": {"query": query_clean, "path": path_clean, "literal": True, "case_sensitive": False, "max_results": 50},
            "mode": "fast",
            "guard_text": f"Search for text '{query_clean}' in {path_clean}.",
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
        pattern_clean = pattern.strip("\"'")
        path_clean = path.strip("\"'")
        return {
            "action": "tool",
            "tool_name": "file_find",
            "payload": {"pattern": pattern_clean, "path": path_clean, "max_results": 60},
            "mode": "fast",
            "guard_text": f"Find files matching pattern '{pattern_clean}' in {path_clean}.",
        }
    code_summary_match = re.match(r"^(?:summarize code|summarise code|explain code)\s+(.+)$", text, re.IGNORECASE)
    if code_summary_match:
        path = code_summary_match.group(1).strip().strip("\"'")
        return {"action": "tool", "tool_name": "filesystem_read", "payload": {"path": path}, "mode": "code_summary", "guard_text": f"Read and summarize the code file {path}."}
    return None


def update_memory_from_tool(memory: AgentMemory, action: Dict[str, Any]) -> None:
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
    if tool_name in {"browser_navigate", "browser_snapshot", "browser_click", "browser_type", "browser_screenshot"}:
        if payload.get("url"):
            memory.remember_search(f"browse:{payload.get('url')}")


def run_turn(
    client: Any,
    session_id: str,
    content: str,
    memory: AgentMemory,
    mode: str = "chat",
) -> Dict[str, Any]:
    adapter = AegisAgentAdapter(client, session_id, environment=AGENT_ENV, filesystem_root=FILESYSTEM_ROOT)
    trusted_local_tools = {
        "filesystem_read",
        "directory_list",
        "filesystem_write",
        "filesystem_edit",
        "filesystem_patch",
        "file_find",
        "repo_map",
        "text_search",
    }
    pre_action = detect_direct_tool_intent(content)
    if pre_action and pre_action.get("action") == "browser_result":
        idx = int(pre_action.get("index") or 0) - 1
        if idx < 0 or idx >= len(memory.web_results):
            return {"ok": True, "content": "There is no search result with that number. Run a web search first.", "session_id": session_id, "memory": memory.as_dict(), "model": MODEL_NAME, "mode": mode}
        target = memory.web_results[idx]
        pre_action = {"action": "tool", "tool_name": "web_open", "payload": {"url": str(target.get("url") or ""), "max_links": 12}, "mode": "fast", "guard_text": f"Open web search result {idx + 1}: {target.get('url') or ''}"}
    if pre_action and pre_action.get("action") == "browser_link":
        idx = int(pre_action.get("index") or 0) - 1
        if idx < 0 or idx >= len(memory.page_links):
            return {"ok": True, "content": "There is no page link with that number. Open a page first.", "session_id": session_id, "memory": memory.as_dict(), "model": MODEL_NAME, "mode": mode}
        target = memory.page_links[idx]
        pre_action = {"action": "tool", "tool_name": "web_open", "payload": {"url": str(target.get("url") or ""), "max_links": 12}, "mode": "fast", "guard_text": f"Follow page link {idx + 1}: {target.get('url') or ''}"}
    guard_text = str(pre_action.get("guard_text") or content) if pre_action else content
    guarded_in = adapter.guard_input(guard_text, metadata={"source": "krimo_api", "mode": mode})
    if guarded_in.get("blocked") or guarded_in.get("require_approval"):
        return {"ok": False, **guarded_in, "memory": memory.as_dict()}
    sensitive_notice = maybe_sensitive_input_notice(guard_text, guarded_in)
    if sensitive_notice:
        guarded_out = adapter.guard_output(sensitive_notice, metadata={"source": "krimo_api", "mode": mode, "soft_reply": "pii_redaction"})
        if guarded_out.get("blocked") or guarded_out.get("require_approval"):
            return {"ok": False, **guarded_out, "memory": memory.as_dict()}
        return {
            "ok": True,
            "content": guarded_out.get("sanitized_output") or sensitive_notice,
            "session_id": session_id,
            "memory": memory.as_dict(),
            "model": MODEL_NAME,
            "mode": mode,
        }
    safe_input = guarded_in.get("sanitized_content") or content

    if mode == "autocode":
        # bounded simplified autocode loop
        tool_catalog_json = json.dumps(adapter.describe_tools(), indent=2)
        observations: list[str] = []
        final_output = ""
        for step in range(1, 6):
            plan_prompt = (
                "Return only JSON. Choose the smallest next action to solve the coding task.\n"
                f"Tools:\n{tool_catalog_json}\n"
                f"{build_memory_context(memory)}Task: {safe_input}\n"
                f"Observations:\n" + "\n".join(observations[-8:])
            )
            action = parse_agent_action(model_chat([{"role": "system", "content": "Return only JSON."}, {"role": "user", "content": plan_prompt}], stream=MODEL_STREAM_ENABLED))
            if action.get("action") == "answer":
                final_output = str(action.get("content") or "")
                if final_output:
                    break
                continue
            if action.get("action") != "tool":
                continue
            tool_res = adapter.run_tool(action["tool_name"], action["payload"])
            if not tool_res.get("allowed", False):
                final_output = f"Tool blocked by Aegis: {tool_res.get('message')}"
                break
            update_memory_from_tool(memory, action)
            result = tool_res.get("result") or {}
            if action["tool_name"] == "web_search":
                memory.remember_web_results(list(result.get("results") or []))
            if action["tool_name"] == "web_open":
                memory.remember_page(str(result.get("url") or ""), list(result.get("links") or []))
            if action["tool_name"] in {"browser_navigate", "browser_click", "browser_type", "browser_snapshot", "browser_screenshot"}:
                memory.remember_page(str(result.get("url") or ""), list(result.get("links") or []))
            if action.get("mode") == "code_summary":
                final_output = summarize_code_file(str(action["payload"].get("path") or "the file"), str(result.get("content") or ""), memory)
                break
            observations.append(f"{action['tool_name']}: {compact_tool_result(action['tool_name'], result)[:800]}")
        if not final_output:
            final_output = "\n".join(observations[-6:]) or "No result."
    else:
        action = pre_action
        if action is None:
            system_prompt = (
                "You are KriMo, a guarded local coding agent. Return only JSON.\n"
                '{"action":"answer","content":"..."} or {"action":"tool","tool_name":"...","payload":{...}}'
                f"{build_memory_context(memory)}"
            )
            action = parse_agent_action(
                model_chat(
                    [{"role": "system", "content": system_prompt}, {"role": "user", "content": safe_input}],
                    stream=MODEL_STREAM_ENABLED,
                )
            )
        if action.get("action") == "tool":
            tool_res = adapter.run_tool(action["tool_name"], action["payload"])
            if not tool_res.get("allowed", False):
                final_output = f"Tool blocked by Aegis: {tool_res.get('message')}"
            else:
                update_memory_from_tool(memory, action)
                result = tool_res.get("result") or {}
                if action.get("mode") == "code_summary":
                    final_output = summarize_code_file(str(action["payload"].get("path") or "the file"), str(result.get("content") or ""), memory)
                else:
                    final_output = compact_tool_result(action["tool_name"], result)
        else:
            final_output = str(action.get("content") or "")

    guarded_out = adapter.guard_output(final_output, metadata={"source": "krimo_api", "mode": mode})
    if guarded_out.get("blocked") or guarded_out.get("require_approval"):
        return {"ok": False, **guarded_out, "memory": memory.as_dict()}
    return {
        "ok": True,
        "content": guarded_out.get("sanitized_output") or final_output,
        "session_id": session_id,
        "memory": memory.as_dict(),
        "model": MODEL_NAME,
        "mode": mode,
    }
class LocalAegisClient:
    def __init__(self, runtime):
        self.runtime = runtime

    def guard_input(self, session_id: str, content: str, **kwargs) -> Dict[str, Any]:
        return self.runtime.guard_user_input(session_id, content, kwargs.pop("metadata", {}), **kwargs)

    def guard_output(self, session_id: str, content: str, **kwargs) -> Dict[str, Any]:
        return self.runtime.guard_model_output(session_id, content, kwargs.pop("metadata", {}), **kwargs)

    def execute_tool(self, session_id: str, tool_name: str, payload: Dict[str, Any], **kwargs) -> Dict[str, Any]:
        return self.runtime.handle_tool_call(
            session_id=session_id,
            tool_name=tool_name,
            payload=payload,
            environment=kwargs.get("environment"),
            allowlist=kwargs.get("allowlist"),
            denylist=kwargs.get("denylist"),
            filesystem_root=kwargs.get("filesystem_root"),
            tenant_id=kwargs.get("tenant_id"),
            role=kwargs.get("role"),
            labels=kwargs.get("labels"),
        )
