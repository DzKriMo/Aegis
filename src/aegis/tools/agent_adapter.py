from __future__ import annotations

from typing import Any, Dict, List, Optional

from .client import AegisClient
from .catalog import tool_catalog


class AegisAgentAdapter:
    def __init__(self, client: AegisClient, session_id: str, environment: str = "dev", filesystem_root: Optional[str] = None):
        self.client = client
        self.session_id = session_id
        self.environment = environment
        self.filesystem_root = filesystem_root

    def describe_tools(self) -> List[Dict[str, Any]]:
        return tool_catalog()

    def guard_input(self, content: str, **kwargs) -> Dict[str, Any]:
        return self.client.guard_input(self.session_id, content, environment=self.environment, **kwargs)

    def guard_output(self, content: str, **kwargs) -> Dict[str, Any]:
        return self.client.guard_output(self.session_id, content, environment=self.environment, **kwargs)

    def run_tool(self, tool_name: str, payload: Dict[str, Any], **kwargs) -> Dict[str, Any]:
        return self.client.execute_tool(
            self.session_id,
            tool_name=tool_name,
            payload=payload,
            environment=self.environment,
            filesystem_root=self.filesystem_root,
            **kwargs,
        )
