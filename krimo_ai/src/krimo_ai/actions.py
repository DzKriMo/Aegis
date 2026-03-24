from __future__ import annotations

import json
import os
import re
from typing import Any, Optional


def _normalize_web_url(value: str) -> str:
    candidate = str(value or "").strip().strip("\"'")
    if not candidate:
        return ""
    if re.match(r"^https?://", candidate, re.IGNORECASE):
        return candidate
    if re.match(r"^[A-Za-z0-9.-]+\.[A-Za-z]{2,}(/\S*)?$", candidate):
        return "https://" + candidate
    return candidate


def parse_tool_call(text: str) -> Optional[dict[str, Any]]:
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


def parse_loose_tool_call(text: str) -> Optional[dict[str, Any]]:
    lowered = text.lower()
    known_tools = [
        "directory_list",
        "filesystem_read",
        "filesystem_write",
        "filesystem_edit",
        "filesystem_patch",
        "http_fetch",
        "web_search",
        "web_open",
        "browser_navigate",
        "browser_click",
        "browser_type",
        "browser_snapshot",
        "browser_screenshot",
        "json_transform",
        "file_find",
        "repo_map",
        "text_search",
        "shell",
    ]
    tool_name = next((name for name in known_tools if f'"{name}"' in lowered or f'"action":"{name}"' in lowered), None)
    if not tool_name:
        return None
    payload: dict[str, Any] = {}
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


def parse_agent_action(text: str) -> dict[str, Any]:
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
                "web_search",
                "web_open",
                "browser_navigate",
                "browser_click",
                "browser_type",
                "browser_snapshot",
                "browser_screenshot",
                "json_transform",
                "file_find",
                "repo_map",
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


def detect_direct_tool_intent(user_text: str, web_results: list[dict[str, str]], page_links: list[dict[str, str]]) -> Optional[dict[str, Any]]:
    text = user_text.strip()
    lower = text.lower()
    interaction_requested = any(token in lower for token in ["interact", "click around", "explore the page", "inspect the page"])
    ocr_match = re.match(r"^(?:use your ocr to read the text in|ocr|read text from image|extract text from image)\s+(.+)$", text, re.IGNORECASE)
    if ocr_match:
        path = ocr_match.group(1).strip().strip("\"'")
        return {"action": "vision_ocr", "path": path}
    vision_match = re.match(r"^(?:analyze image|describe image|look at image)\s+(.+)$", text, re.IGNORECASE)
    if vision_match:
        path = vision_match.group(1).strip().strip("\"'")
        return {"action": "vision_analyze", "path": path}
    if lower in {"tree", "repo map", "repomap", "map repo"}:
        return {"action": "tool", "tool_name": "repo_map", "payload": {"path": ".", "max_depth": 3, "max_entries": 200}, "mode": "fast", "guard_text": "Build a repository map for the current workspace."}
    google_match = re.match(r"^(?:google|search google for|search web for|web search|search the web for)\s+(.+)$", text, re.IGNORECASE)
    if google_match:
        query = google_match.group(1).strip().strip("\"'")
        return {"action": "tool", "tool_name": "web_search", "payload": {"query": query, "max_results": 6}, "mode": "fast", "guard_text": f"Search the web for {query}."}
    browse_match = re.match(r"^(?:browse|browser open|browser navigate|navigate browser to|naviguate to)\s+(\S+)(?:\s+.*)?$", text, re.IGNORECASE)
    if browse_match:
        url = _normalize_web_url(browse_match.group(1))
        return {"action": "tool", "tool_name": "browser_navigate", "payload": {"url": url, "wait_ms": 2500 if interaction_requested else 1200}, "mode": "browser_explore" if interaction_requested else "fast", "guard_text": f"Navigate the browser to {url}."}
    open_result_match = re.match(r"^open result\s+(\d+)$", lower, re.IGNORECASE)
    if open_result_match:
        idx = int(open_result_match.group(1)) - 1
        if idx < 0 or idx >= len(web_results):
            return {"action": "browser_result", "index": idx + 1}
        target = web_results[idx]
        return {"action": "tool", "tool_name": "web_open", "payload": {"url": str(target.get("url") or ""), "max_links": 12}, "mode": "fast", "guard_text": f"Open web search result {idx + 1}: {target.get('url') or ''}"}
    follow_link_match = re.match(r"^(?:follow|open) link\s+(\d+)$", lower, re.IGNORECASE)
    if follow_link_match:
        idx = int(follow_link_match.group(1)) - 1
        if idx < 0 or idx >= len(page_links):
            return {"action": "browser_link", "index": idx + 1}
        target = page_links[idx]
        return {"action": "tool", "tool_name": "web_open", "payload": {"url": str(target.get("url") or ""), "max_links": 12}, "mode": "fast", "guard_text": f"Follow page link {idx + 1}: {target.get('url') or ''}"}
    if lower in {"ls", "ls .", "dir", "dir .", "list files", "list the files", "list the files in the current directory"}:
        return {"action": "tool", "tool_name": "directory_list", "payload": {"path": "."}, "mode": "fast", "guard_text": "List the files in the current directory."}
    if lower in {"pwd", "where am i", "current directory"}:
        return {"action": "answer", "content": os.getcwd(), "mode": "fast", "guard_text": "Show the current working directory."}
    url_match = re.match(r"^(?:open|visit|navigate to|go to)\s+(\S+)(?:\s+.*)?$", text, re.IGNORECASE)
    if url_match:
        url = _normalize_web_url(url_match.group(1))
        return {"action": "tool", "tool_name": "web_open", "payload": {"url": url, "max_links": 12}, "mode": "fast", "guard_text": f"Open the web page {url}."}
    tree_match = re.match(r"^(?:tree|repo map)\s+(.+)$", text, re.IGNORECASE)
    if tree_match:
        path = tree_match.group(1).strip().strip("\"'")
        return {"action": "tool", "tool_name": "repo_map", "payload": {"path": path, "max_depth": 3, "max_entries": 200}, "mode": "fast", "guard_text": f"Build a repository map for {path}."}
    if lower.startswith("ls "):
        path = text[3:].strip() or "."
        return {"action": "tool", "tool_name": "directory_list", "payload": {"path": path}, "mode": "fast", "guard_text": f"List the files in {path}."}
    read_match = re.match(r"^(?:read|cat|show|open)\s+(.+)$", text, re.IGNORECASE)
    if read_match:
        path = read_match.group(1).strip().strip("\"'")
        return {"action": "tool", "tool_name": "filesystem_read", "payload": {"path": path}, "mode": "fast", "guard_text": f"Read the file {path}."}
    return None
