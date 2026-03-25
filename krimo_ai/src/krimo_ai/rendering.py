from __future__ import annotations

import json
from typing import Any, Dict


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
        if len(tree) > 80:
            lines.append(f"  ...and {len(tree) - 80} more")
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
    if tool_name == "repo_map":
        return render_repo_map_result(result)
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
    if tool_name == "web_search":
        results = (result or {}).get("results") or []
        query = str((result or {}).get("query") or "")
        if not results:
            return f"No web results found for '{query}'."
        lines = [f"Web results for '{query}':"]
        for idx, item in enumerate(results[:8], start=1):
            lines.append(f"{idx}. {item.get('title') or item.get('url')}")
            lines.append(f"   {item.get('url')}")
            snippet = str(item.get("snippet") or "").strip()
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
            lines.extend(["", preview])
        if links:
            lines.extend(["", "Links:"])
            for idx, item in enumerate(links[:8], start=1):
                lines.append(f"{idx}. {item.get('text') or item.get('url')}")
                lines.append(f"   {item.get('url')}")
        return "\n".join(lines)
    if tool_name in {"browser_navigate", "browser_click", "browser_type", "browser_snapshot", "browser_scroll", "browser_screenshot"}:
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
            lines.extend(["", "Links:"])
            for idx, item in enumerate(links[:8], start=1):
                lines.append(f"{idx}. {item.get('text') or item.get('href')}")
                lines.append(f"   {item.get('href') or item.get('url')}")
        buttons = (result or {}).get("buttons") or []
        if buttons:
            lines.extend(["", "Buttons:"])
            for idx, item in enumerate(buttons[:8], start=1):
                lines.append(f"{idx}. {item.get('text') or '[unnamed button]'}")
        inputs = (result or {}).get("inputs") or []
        if inputs:
            lines.extend(["", "Inputs:"])
            for idx, item in enumerate(inputs[:6], start=1):
                label = item.get("placeholder") or item.get("name") or item.get("type") or "input"
                lines.append(f"{idx}. {label}")
        headings = (result or {}).get("headings") or []
        if headings:
            lines.extend(["", "Headings:"])
            for idx, item in enumerate(headings[:6], start=1):
                lines.append(f"{idx}. {item.get('text') or '[unnamed heading]'}")
        if result.get("auto_waited_for_transition"):
            lines.extend(["", "Auto interaction: waited for the page to transition from its boot/loading state"])
        if result.get("auto_scrolled"):
            lines.extend(["", "Auto interaction: scrolled to inspect content below the first viewport"])
        if result.get("auto_interacted"):
            lines.extend(["", f"Auto interaction: clicked {result.get('auto_selector')}"])
        if result.get("auto_reached_content"):
            lines.extend(["", "Auto interaction: reached a fuller content view"])
        if result.get("vision_summary"):
            lines.extend(["", f"Visual fallback: {result.get('vision_summary')}"])
        return "\n".join(lines)
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
