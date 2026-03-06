from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional, List
import os
import subprocess
import json
import shlex

from .tools import guard_tool_call, guard_shell_command, guard_filesystem_path
from ..prellm.network import evaluate_urls
from .tool_registry import get_tool_policy


@dataclass
class ToolResult:
    allowed: bool
    message: Optional[str]
    result: Optional[Dict[str, Any]]


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
        cmd_decision = guard_shell_command(command)
        if not cmd_decision.allowed:
            return ToolResult(False, cmd_decision.message, None)
        # Safe execution: no shell, explicit timeout, capture output
        try:
            args = shlex.split(command.strip())
            if not args:
                return ToolResult(False, "Empty command", None)
            executable = os.path.basename(args[0])
            if policy.allowlist and executable not in policy.allowlist:
                return ToolResult(False, "Command not allowlisted", None)
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
        if environment == "prod" and not filesystem_root:
            return ToolResult(False, "filesystem_root is required in prod", None)
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

    if tool_name == "http_fetch":
        url = str(payload.get("url", ""))
        method = str(payload.get("method", "GET")).upper()
        if method not in {"GET", "HEAD"}:
            return ToolResult(False, "HTTP method blocked by firewall", None)
        net_decision = evaluate_urls([url], allowlist=allowlist or [], denylist=denylist or [])
        if net_decision.blocked:
            return ToolResult(False, net_decision.message, None)
        try:
            import urllib.request

            req = urllib.request.Request(url, method=method)
            with urllib.request.urlopen(req, timeout=policy.timeout_seconds) as resp:
                body = resp.read(policy.max_bytes or 64 * 1024)
                return ToolResult(
                    True,
                    "HTTP fetch executed",
                    {
                        "status": resp.status,
                        "headers": dict(resp.headers),
                        "body": body.decode("utf-8", errors="replace"),
                    },
                )
        except Exception as exc:
            return ToolResult(False, f"HTTP fetch failed: {exc}", None)

    if tool_name == "json_transform":
        data = payload.get("data")
        return ToolResult(True, "JSON transform executed", {"json": json.dumps(data)})

    return ToolResult(False, "Unknown tool", None)
