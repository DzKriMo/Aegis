from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional, List
import os
import subprocess
import json
import shutil
import re
import fnmatch
from pathlib import Path
from urllib.parse import urlparse

from .tools import guard_tool_call, guard_shell_command, guard_filesystem_path
from ..prellm.network import evaluate_urls
from .tool_registry import get_tool_policy


@dataclass
class ToolResult:
    allowed: bool
    message: Optional[str]
    result: Optional[Dict[str, Any]]


def _within_root(path: str, root: Optional[str]) -> tuple[bool, str]:
    target = os.path.abspath(path)
    if not root:
        return True, target
    root_abs = os.path.abspath(root)
    return target.startswith(root_abs), target


def _safe_json_size(value: Any) -> int:
    try:
        return len(json.dumps(value, ensure_ascii=True))
    except Exception:
        return 0


def _truncate_text(text: str, max_bytes: Optional[int]) -> str:
    if not max_bytes:
        return text
    encoded = text.encode("utf-8", errors="replace")
    return encoded[:max_bytes].decode("utf-8", errors="replace")


def _iter_text_files(root: str):
    for dirpath, _, filenames in os.walk(root):
        for filename in filenames:
            yield os.path.join(dirpath, filename)


def _iter_all_files(root: str):
    for dirpath, _, filenames in os.walk(root):
        for filename in filenames:
            yield os.path.join(dirpath, filename)


def execute_tool(
    tool_name: str,
    payload: Dict[str, Any],
    environment: Optional[str],
    allowlist: Optional[List[str]],
    denylist: Optional[List[str]],
    filesystem_root: Optional[str],
) -> ToolResult:
    decision = guard_tool_call(tool_name, environment, allowlist, denylist)
    if not decision.allowed:
        return ToolResult(False, decision.message, None)

    policy = get_tool_policy(tool_name)
    if policy is None:
        return ToolResult(False, "Unknown tool", None)
    if policy.allowed_envs and environment not in policy.allowed_envs:
        return ToolResult(False, "Tool not allowed in this environment", None)

    if tool_name == "shell":
        command = str(payload.get("command", ""))
        if policy.allowlist and command.split(" ", 1)[0] not in policy.allowlist:
            return ToolResult(False, "Command not allowlisted", None)
        cmd_decision = guard_shell_command(command)
        if not cmd_decision.allowed:
            return ToolResult(False, cmd_decision.message, None)
        # Safe execution: no shell, explicit timeout, capture output
        try:
            args = command.strip().split(" ")
            completed = subprocess.run(
                args,
                capture_output=True,
                text=True,
                timeout=policy.timeout_seconds,
                check=False,
            )
            return ToolResult(
                True,
                "Shell command executed",
                {"stdout": completed.stdout, "stderr": completed.stderr, "returncode": completed.returncode},
            )
        except Exception as exc:
            return ToolResult(False, f"Shell execution failed: {exc}", None)

    if tool_name == "filesystem_read":
        path = str(payload.get("path", ""))
        if filesystem_root:
            fs_decision = guard_filesystem_path(path, filesystem_root)
            if not fs_decision.allowed:
                return ToolResult(False, fs_decision.message, None)
        if not os.path.exists(path) or os.path.isdir(path):
            return ToolResult(False, "Path does not exist or is a directory", None)
        size = os.path.getsize(path)
        if policy.max_bytes and size > policy.max_bytes:
            return ToolResult(False, "File too large", None)
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read(policy.max_bytes or None)
        return ToolResult(True, "Filesystem read executed", {"content": content, "bytes": len(content)})

    if tool_name == "directory_list":
        path = str(payload.get("path", "."))
        if filesystem_root:
            fs_decision = guard_filesystem_path(path, filesystem_root)
            if not fs_decision.allowed:
                return ToolResult(False, fs_decision.message, None)
        if not os.path.isdir(path):
            return ToolResult(False, "Path is not a directory", None)
        entries = []
        for name in sorted(os.listdir(path))[:200]:
            full = os.path.join(path, name)
            try:
                stat = os.stat(full)
                entries.append(
                    {
                        "name": name,
                        "is_dir": os.path.isdir(full),
                        "size": stat.st_size,
                    }
                )
            except Exception:
                entries.append({"name": name, "is_dir": os.path.isdir(full), "size": None})
        return ToolResult(True, "Directory listing executed", {"path": os.path.abspath(path), "entries": entries})

    if tool_name == "filesystem_write":
        path = str(payload.get("path", ""))
        content = str(payload.get("content", ""))
        append = bool(payload.get("append", False))
        if not path:
            return ToolResult(False, "Path is required", None)
        if policy.max_bytes and len(content.encode("utf-8")) > policy.max_bytes:
            return ToolResult(False, "Content too large", None)
        allowed, abs_path = _within_root(path, filesystem_root)
        if filesystem_root and not allowed:
            return ToolResult(False, "Filesystem access outside root blocked", None)
        Path(abs_path).parent.mkdir(parents=True, exist_ok=True)
        mode = "a" if append else "w"
        with open(abs_path, mode, encoding="utf-8", errors="replace") as f:
            f.write(content)
        return ToolResult(True, "Filesystem write executed", {"path": abs_path, "bytes_written": len(content.encode('utf-8')), "append": append})

    if tool_name == "filesystem_edit":
        path = str(payload.get("path", ""))
        old_text = str(payload.get("old_text", ""))
        new_text = str(payload.get("new_text", ""))
        replace_all = bool(payload.get("replace_all", False))
        if not path or not old_text:
            return ToolResult(False, "Path and old_text are required", None)
        allowed, abs_path = _within_root(path, filesystem_root)
        if filesystem_root and not allowed:
            return ToolResult(False, "Filesystem access outside root blocked", None)
        if not os.path.exists(abs_path) or os.path.isdir(abs_path):
            return ToolResult(False, "Path does not exist or is a directory", None)
        with open(abs_path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read(policy.max_bytes or None)
        occurrences = content.count(old_text)
        if occurrences == 0:
            return ToolResult(False, "Target text not found", None)
        updated = content.replace(old_text, new_text) if replace_all else content.replace(old_text, new_text, 1)
        with open(abs_path, "w", encoding="utf-8", errors="replace") as f:
            f.write(updated)
        replaced = occurrences if replace_all else 1
        return ToolResult(
            True,
            "Filesystem edit executed",
            {"path": abs_path, "replacements": replaced, "replace_all": replace_all, "old_text_preview": _truncate_text(old_text, 120)},
        )

    if tool_name == "filesystem_patch":
        path = str(payload.get("path", ""))
        changes = payload.get("changes")
        if not path or not isinstance(changes, list) or not changes:
            return ToolResult(False, "Path and non-empty changes are required", None)
        allowed, abs_path = _within_root(path, filesystem_root)
        if filesystem_root and not allowed:
            return ToolResult(False, "Filesystem access outside root blocked", None)
        if not os.path.exists(abs_path) or os.path.isdir(abs_path):
            return ToolResult(False, "Path does not exist or is a directory", None)
        with open(abs_path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read(policy.max_bytes or None)

        applied: List[Dict[str, Any]] = []
        updated = content
        for idx, change in enumerate(changes):
            if not isinstance(change, dict):
                return ToolResult(False, f"Change #{idx + 1} is invalid", None)
            old_text = str(change.get("old_text", ""))
            new_text = str(change.get("new_text", ""))
            replace_all = bool(change.get("replace_all", False))
            if not old_text:
                return ToolResult(False, f"Change #{idx + 1} missing old_text", None)
            occurrences = updated.count(old_text)
            if occurrences == 0:
                return ToolResult(False, f"Patch target not found for change #{idx + 1}", None)
            updated = updated.replace(old_text, new_text) if replace_all else updated.replace(old_text, new_text, 1)
            applied.append(
                {
                    "index": idx + 1,
                    "replacements": occurrences if replace_all else 1,
                    "replace_all": replace_all,
                    "old_text_preview": _truncate_text(old_text, 120),
                }
            )
        with open(abs_path, "w", encoding="utf-8", errors="replace") as f:
            f.write(updated)
        return ToolResult(True, "Filesystem patch executed", {"path": abs_path, "changes": applied, "change_count": len(applied)})

    if tool_name == "file_find":
        pattern = str(payload.get("pattern", "")).strip()
        path = str(payload.get("path", ".") or ".")
        max_results = int(payload.get("max_results", 50) or 50)
        if not pattern:
            return ToolResult(False, "Pattern is required", None)
        allowed, abs_path = _within_root(path, filesystem_root)
        if filesystem_root and not allowed:
            return ToolResult(False, "Filesystem access outside root blocked", None)
        if not os.path.exists(abs_path):
            return ToolResult(False, "Search path does not exist", None)

        candidates = [abs_path] if os.path.isfile(abs_path) else list(_iter_all_files(abs_path))
        matches: List[Dict[str, Any]] = []
        normalized_pattern = pattern.replace("\\", "/")
        basename_mode = "/" not in normalized_pattern
        for candidate in candidates:
            rel = os.path.relpath(candidate, abs_path if os.path.isdir(abs_path) else os.path.dirname(abs_path) or abs_path)
            rel_norm = rel.replace("\\", "/")
            target = os.path.basename(candidate) if basename_mode else rel_norm
            if fnmatch.fnmatch(target, normalized_pattern):
                matches.append({"path": candidate, "relative_path": rel_norm})
                if len(matches) >= max_results:
                    break
        return ToolResult(True, "File find executed", {"pattern": pattern, "path": abs_path, "matches": matches, "count": len(matches)})

    if tool_name == "text_search":
        query = str(payload.get("query", ""))
        path = str(payload.get("path", ".") or ".")
        literal = bool(payload.get("literal", True))
        case_sensitive = bool(payload.get("case_sensitive", False))
        max_results = int(payload.get("max_results", 50) or 50)
        if not query:
            return ToolResult(False, "Query is required", None)
        allowed, abs_path = _within_root(path, filesystem_root)
        if filesystem_root and not allowed:
            return ToolResult(False, "Filesystem access outside root blocked", None)
        if not os.path.exists(abs_path):
            return ToolResult(False, "Search path does not exist", None)

        matches: List[Dict[str, Any]] = []
        rg_bin = shutil.which("rg")
        if rg_bin:
            cmd = [rg_bin, "--line-number", "--no-heading", "--color", "never"]
            if literal:
                cmd.append("--fixed-strings")
            if not case_sensitive:
                cmd.append("-i")
            cmd.extend(["--max-count", str(max_results), query, abs_path])
            completed = subprocess.run(cmd, capture_output=True, text=True, timeout=policy.timeout_seconds, check=False)
            if completed.returncode not in (0, 1):
                return ToolResult(False, f"text_search failed: {completed.stderr.strip() or 'unknown rg error'}", None)
            for line in completed.stdout.splitlines():
                match = re.match(r"^(.*?):(\d+):(.*)$", line)
                if not match:
                    continue
                file_path, line_no, snippet = match.groups()
                matches.append({"path": file_path, "line": int(line_no), "snippet": snippet})
                if len(matches) >= max_results:
                    break
        else:
            flags = 0 if case_sensitive else re.IGNORECASE
            pattern = re.escape(query) if literal else query
            compiled = re.compile(pattern, flags)
            roots = [abs_path] if os.path.isfile(abs_path) else list(_iter_text_files(abs_path))
            for candidate in roots:
                if len(matches) >= max_results:
                    break
                try:
                    with open(candidate, "r", encoding="utf-8", errors="replace") as f:
                        for idx, line in enumerate(f, start=1):
                            if compiled.search(line):
                                matches.append({"path": candidate, "line": idx, "snippet": line.rstrip()})
                                if len(matches) >= max_results:
                                    break
                except Exception:
                    continue
        return ToolResult(
            True,
            "Text search executed",
            {"query": query, "path": abs_path, "matches": matches, "count": len(matches), "literal": literal, "case_sensitive": case_sensitive},
        )

    if tool_name == "http_fetch":
        url = str(payload.get("url", ""))
        method = str(payload.get("method", "GET")).upper()
        net_decision = evaluate_urls([url], allowlist=allowlist or [], denylist=denylist or [])
        if net_decision.blocked:
            return ToolResult(False, net_decision.message, None)
        try:
            import urllib.request

            headers = payload.get("headers") if isinstance(payload.get("headers"), dict) else {}
            req = urllib.request.Request(url, method=method, headers={str(k): str(v) for k, v in headers.items()})
            with urllib.request.urlopen(req, timeout=policy.timeout_seconds) as resp:
                body = resp.read(policy.max_bytes or 64 * 1024)
                text_body = body.decode("utf-8", errors="replace")
                parsed = urlparse(url)
                return ToolResult(
                    True,
                    "HTTP fetch executed",
                    {
                        "status": resp.status,
                        "url": url,
                        "host": parsed.netloc,
                        "headers": dict(resp.headers),
                        "body": text_body,
                        "body_preview": _truncate_text(text_body, 1024),
                    },
                )
        except Exception as exc:
            return ToolResult(False, f"HTTP fetch failed: {exc}", None)

    if tool_name == "json_transform":
        data = payload.get("data")
        operation = str(payload.get("operation", "pretty")).lower()
        if operation == "keys":
            keys = sorted(list(data.keys())) if isinstance(data, dict) else []
            return ToolResult(True, "JSON transform executed", {"keys": keys, "count": len(keys)})
        if operation == "compact":
            return ToolResult(True, "JSON transform executed", {"json": json.dumps(data, separators=(",", ":"))})
        if operation == "schema":
            schema = {}
            if isinstance(data, dict):
                schema = {str(k): type(v).__name__ for k, v in data.items()}
            return ToolResult(True, "JSON transform executed", {"schema": schema})
        return ToolResult(True, "JSON transform executed", {"json": json.dumps(data, indent=2, sort_keys=True)})

    return ToolResult(False, "Unknown tool", None)
