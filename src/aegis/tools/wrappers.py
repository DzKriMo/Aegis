from __future__ import annotations

from typing import Dict, Any, Optional

from .agent_adapter import AegisAgentAdapter
from .client import AegisClient


class GuardedTools:
    def __init__(self, client: AegisClient, session_id: str, environment: str = "dev", filesystem_root: Optional[str] = None):
        self.client = client
        self.session_id = session_id
        self.environment = environment
        self.filesystem_root = filesystem_root
        self.adapter = AegisAgentAdapter(client, session_id, environment=environment, filesystem_root=filesystem_root)

    def shell(self, command: str) -> Dict[str, Any]:
        return self.adapter.run_tool("shell", {"command": command})

    def filesystem_read(self, path: str) -> Dict[str, Any]:
        return self.adapter.run_tool("filesystem_read", {"path": path})

    def directory_list(self, path: str = ".") -> Dict[str, Any]:
        return self.adapter.run_tool("directory_list", {"path": path})

    def filesystem_write(self, path: str, content: str, append: bool = False) -> Dict[str, Any]:
        return self.adapter.run_tool("filesystem_write", {"path": path, "content": content, "append": append})

    def filesystem_edit(self, path: str, old_text: str, new_text: str, replace_all: bool = False) -> Dict[str, Any]:
        return self.adapter.run_tool(
            "filesystem_edit",
            {"path": path, "old_text": old_text, "new_text": new_text, "replace_all": replace_all},
        )

    def filesystem_patch(self, path: str, changes: list[Dict[str, Any]]) -> Dict[str, Any]:
        return self.adapter.run_tool("filesystem_patch", {"path": path, "changes": changes})

    def file_find(self, pattern: str, path: str = ".", max_results: int = 50) -> Dict[str, Any]:
        return self.adapter.run_tool("file_find", {"pattern": pattern, "path": path, "max_results": max_results})

    def repo_map(self, path: str = ".", max_depth: int = 3, max_entries: int = 200) -> Dict[str, Any]:
        return self.adapter.run_tool("repo_map", {"path": path, "max_depth": max_depth, "max_entries": max_entries})

    def text_search(self, query: str, path: str = ".", literal: bool = True, case_sensitive: bool = False, max_results: int = 50) -> Dict[str, Any]:
        return self.adapter.run_tool(
            "text_search",
            {"query": query, "path": path, "literal": literal, "case_sensitive": case_sensitive, "max_results": max_results},
        )

    def http_fetch(self, url: str, method: str = "GET") -> Dict[str, Any]:
        return self.adapter.run_tool("http_fetch", {"url": url, "method": method})

    def web_search(self, query: str, max_results: int = 5) -> Dict[str, Any]:
        return self.adapter.run_tool("web_search", {"query": query, "max_results": max_results})

    def web_open(self, url: str, max_links: int = 12) -> Dict[str, Any]:
        return self.adapter.run_tool("web_open", {"url": url, "max_links": max_links})

    def browser_navigate(self, url: str) -> Dict[str, Any]:
        return self.adapter.run_tool("browser_navigate", {"url": url})

    def browser_click(self, selector: str) -> Dict[str, Any]:
        return self.adapter.run_tool("browser_click", {"selector": selector})

    def browser_type(self, selector: str, text: str, submit: bool = False) -> Dict[str, Any]:
        return self.adapter.run_tool("browser_type", {"selector": selector, "text": text, "submit": submit})

    def browser_snapshot(self) -> Dict[str, Any]:
        return self.adapter.run_tool("browser_snapshot", {})

    def browser_scroll(self, pixels: int = 900) -> Dict[str, Any]:
        return self.adapter.run_tool("browser_scroll", {"pixels": pixels})

    def browser_screenshot(self) -> Dict[str, Any]:
        return self.adapter.run_tool("browser_screenshot", {})

    def json_transform(self, data: Any, operation: str = "pretty") -> Dict[str, Any]:
        return self.adapter.run_tool("json_transform", {"data": data, "operation": operation})
