from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional

from ..config import settings
from ..storage.registry import load_tool_policies_from_db


@dataclass
class ToolPolicy:
    name: str
    allowed_envs: List[str]
    allowlist: List[str]
    timeout_seconds: int
    max_bytes: Optional[int] = None


_TOOLS: Dict[str, ToolPolicy] = {
    "shell": ToolPolicy(
        name="shell",
        allowed_envs=["dev"],
        allowlist=["python", "py", "pip", "dir", "ls", "echo", "pwd", "whoami", "git", "type"],
        timeout_seconds=5,
    ),
    "filesystem_read": ToolPolicy(
        name="filesystem_read",
        allowed_envs=["dev", "prod"],
        allowlist=[],
        timeout_seconds=2,
        max_bytes=64 * 1024,
    ),
    "http_fetch": ToolPolicy(
        name="http_fetch",
        allowed_envs=["dev"],
        allowlist=[],
        timeout_seconds=5,
        max_bytes=64 * 1024,
    ),
    "web_search": ToolPolicy(
        name="web_search",
        allowed_envs=["dev"],
        allowlist=[],
        timeout_seconds=8,
        max_bytes=96 * 1024,
    ),
    "web_open": ToolPolicy(
        name="web_open",
        allowed_envs=["dev"],
        allowlist=[],
        timeout_seconds=8,
        max_bytes=96 * 1024,
    ),
    "browser_navigate": ToolPolicy(
        name="browser_navigate",
        allowed_envs=["dev"],
        allowlist=[],
        timeout_seconds=15,
        max_bytes=96 * 1024,
    ),
    "browser_click": ToolPolicy(
        name="browser_click",
        allowed_envs=["dev"],
        allowlist=[],
        timeout_seconds=12,
        max_bytes=96 * 1024,
    ),
    "browser_type": ToolPolicy(
        name="browser_type",
        allowed_envs=["dev"],
        allowlist=[],
        timeout_seconds=12,
        max_bytes=96 * 1024,
    ),
    "browser_snapshot": ToolPolicy(
        name="browser_snapshot",
        allowed_envs=["dev"],
        allowlist=[],
        timeout_seconds=8,
        max_bytes=96 * 1024,
    ),
    "browser_scroll": ToolPolicy(
        name="browser_scroll",
        allowed_envs=["dev"],
        allowlist=[],
        timeout_seconds=8,
        max_bytes=96 * 1024,
    ),
    "browser_screenshot": ToolPolicy(
        name="browser_screenshot",
        allowed_envs=["dev"],
        allowlist=[],
        timeout_seconds=10,
        max_bytes=96 * 1024,
    ),
    "directory_list": ToolPolicy(
        name="directory_list",
        allowed_envs=["dev", "prod"],
        allowlist=[],
        timeout_seconds=2,
        max_bytes=64 * 1024,
    ),
    "filesystem_write": ToolPolicy(
        name="filesystem_write",
        allowed_envs=["dev"],
        allowlist=[],
        timeout_seconds=3,
        max_bytes=32 * 1024,
    ),
    "filesystem_edit": ToolPolicy(
        name="filesystem_edit",
        allowed_envs=["dev"],
        allowlist=[],
        timeout_seconds=3,
        max_bytes=64 * 1024,
    ),
    "filesystem_patch": ToolPolicy(
        name="filesystem_patch",
        allowed_envs=["dev"],
        allowlist=[],
        timeout_seconds=4,
        max_bytes=128 * 1024,
    ),
    "file_find": ToolPolicy(
        name="file_find",
        allowed_envs=["dev", "prod"],
        allowlist=[],
        timeout_seconds=4,
        max_bytes=64 * 1024,
    ),
    "repo_map": ToolPolicy(
        name="repo_map",
        allowed_envs=["dev", "prod"],
        allowlist=[],
        timeout_seconds=4,
        max_bytes=64 * 1024,
    ),
    "text_search": ToolPolicy(
        name="text_search",
        allowed_envs=["dev", "prod"],
        allowlist=[],
        timeout_seconds=4,
        max_bytes=64 * 1024,
    ),
    "json_transform": ToolPolicy(
        name="json_transform",
        allowed_envs=["dev", "prod"],
        allowlist=[],
        timeout_seconds=1,
    ),
}


def get_tool_policy(name: str) -> Optional[ToolPolicy]:
    if settings.aegis_db_enabled:
        try:
            db_tools = load_tool_policies_from_db()
            if name in db_tools:
                t = db_tools[name]
                return ToolPolicy(
                    name=name,
                    allowed_envs=t.get("allowed_envs", []),
                    allowlist=t.get("allowlist", []),
                    timeout_seconds=int(t.get("timeout_seconds", 5)),
                    max_bytes=t.get("max_bytes"),
                )
        except Exception:
            pass
    return _TOOLS.get(name)


def get_all_tool_policies() -> Dict[str, ToolPolicy]:
    return _TOOLS
