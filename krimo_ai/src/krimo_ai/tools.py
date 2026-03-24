from __future__ import annotations

import json
import os
import re
import shlex
import subprocess
from pathlib import Path
from typing import Any, Dict, Optional
import sqlite3
from dataclasses import dataclass, field
import hashlib


@dataclass
class ToolResult:
    success: bool
    result: Any = None
    error: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "success": self.success,
            "result": self.result,
            "error": self.error,
            "metadata": self.metadata,
        }


class ShellTool:
    NAME = "shell"
    DESCRIPTION = "Execute shell commands. Supports any CLI command."

    def __init__(self, cwd: Optional[str] = None, timeout: int = 120):
        self.cwd = cwd or os.getcwd()
        self.timeout = timeout

    def execute(self, command: str, timeout: Optional[int] = None) -> ToolResult:
        try:
            timeout = timeout or self.timeout
            result = subprocess.run(
                command,
                shell=True,
                cwd=self.cwd,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            return ToolResult(
                success=result.returncode == 0,
                result={
                    "stdout": result.stdout,
                    "stderr": result.stderr,
                    "exit_code": result.returncode,
                },
                metadata={"command": command, "cwd": self.cwd},
            )
        except subprocess.TimeoutExpired:
            return ToolResult(success=False, error=f"Command timed out after {timeout}s")
        except Exception as e:
            return ToolResult(success=False, error=str(e))


class GitTool:
    NAME = "git"
    DESCRIPTION = "Execute git operations: status, log, diff, branch, checkout, commit, push, pull, merge, add, etc."

    def __init__(self, repo_path: str = "."):
        self.repo_path = repo_path
        self.shell = ShellTool(cwd=repo_path)

    def _run(self, *args: str) -> ToolResult:
        command = f"git {' '.join(args)}"
        return self.shell.execute(command)

    def status(self) -> ToolResult:
        return self._run("status", "--short")

    def log(self, n: int = 10, oneline: bool = True) -> ToolResult:
        flags = "--oneline" if oneline else ""
        return self._run("log", f"-{n}", flags)

    def diff(self, target: str = "") -> ToolResult:
        return self._run("diff", target)

    def branch_list(self) -> ToolResult:
        return self._run("branch", "-a")

    def checkout(self, branch: str, create: bool = False) -> ToolResult:
        flag = "-b" if create else ""
        return self._run("checkout", flag, branch)

    def commit(self, message: str, add_all: bool = False) -> ToolResult:
        if add_all:
            self._run("add", "-A")
        return self._run("commit", "-m", message)

    def push(self, remote: str = "origin", branch: str = "", force: bool = False) -> ToolResult:
        flags = "-f" if force else ""
        return self._run("push", flags, remote, branch)

    def pull(self, remote: str = "origin", branch: str = "") -> ToolResult:
        return self._run("pull", remote, branch)

    def merge(self, branch: str, no_ff: bool = False) -> ToolResult:
        flag = "--no-ff" if no_ff else ""
        return self._run("merge", flag, branch)

    def stash(self, action: str = "push") -> ToolResult:
        return self._run("stash", action)

    def remote_list(self) -> ToolResult:
        return self._run("remote", "-v")


class DockerTool:
    NAME = "docker"
    DESCRIPTION = "Docker container operations: list, run, stop, exec, logs, build, ps, images"

    def __init__(self):
        self.shell = ShellTool()

    def _run(self, *args: str) -> ToolResult:
        command = f"docker {' '.join(args)}"
        return self.shell.execute(command)

    def ps(self, all: bool = True) -> ToolResult:
        flag = "-a" if all else ""
        return self._run("ps", flag)

    def images(self) -> ToolResult:
        return self._run("images")

    def run(self, image: str, command: str = "", detach: bool = False, name: str = "", ports: str = "") -> ToolResult:
        flags = "-d" if detach else ""
        name_flag = f"--name {name}" if name else ""
        port_flag = f"-p {ports}" if ports else ""
        return self._run("run", flags, name_flag, port_flag, image, command)

    def stop(self, container: str) -> ToolResult:
        return self._run("stop", container)

    def exec(self, container: str, command: str) -> ToolResult:
        return self._run("exec", "-it", container, "sh", "-c", command)

    def logs(self, container: str, follow: bool = False, tail: int = 100) -> ToolResult:
        flags = "-f" if follow else ""
        return self._run("logs", flags, "--tail", str(tail), container)

    def build(self, tag: str, path: str = ".") -> ToolResult:
        return self._run("build", "-t", tag, path)


class DatabaseTool:
    NAME = "database"
    DESCRIPTION = "Execute SQL queries on SQLite databases. Supports query, execute, schema inspection."

    def __init__(self, db_path: str = ":memory:"):
        self.db_path = db_path
        self.conn: Optional[sqlite3.Connection] = None

    def connect(self) -> ToolResult:
        try:
            self.conn = sqlite3.connect(self.db_path)
            return ToolResult(success=True, result={"connected": True, "db_path": self.db_path})
        except Exception as e:
            return ToolResult(success=False, error=str(e))

    def execute(self, query: str, params: tuple = ()) -> ToolResult:
        if not self.conn:
            self.connect()
        if not self.conn:
            return ToolResult(success=False, error="Failed to connect to database")
        try:
            cursor = self.conn.cursor()
            cursor.execute(query, params)
            if query.strip().upper().startswith(("SELECT", "PRAGMA", "WITH")):
                columns = [desc[0] for desc in cursor.description] if cursor.description else []
                rows = cursor.fetchall()
                return ToolResult(
                    success=True,
                    result={"columns": columns, "rows": rows, "row_count": len(rows)},
                    metadata={"query_type": "select"},
                )
            else:
                self.conn.commit()
                return ToolResult(
                    success=True,
                    result={"affected_rows": cursor.rowcount, "lastrowid": cursor.lastrowid},
                    metadata={"query_type": "modify"},
                )
        except Exception as e:
            return ToolResult(success=False, error=str(e))

    def schema(self, table: str = "") -> ToolResult:
        if table:
            return self.execute(f"PRAGMA table_info({table})")
        return self.execute("SELECT name FROM sqlite_master WHERE type='table'")

    def close(self) -> ToolResult:
        if self.conn:
            self.conn.close()
            self.conn = None
        return ToolResult(success=True, result={"closed": True})


class APIClientTool:
    NAME = "api_client"
    DESCRIPTION = "Make HTTP API requests: GET, POST, PUT, DELETE with headers and body"

    def __init__(self):
        self.session = None

    def request(
        self,
        method: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        body: Any = None,
        params: Optional[Dict[str, str]] = None,
    ) -> ToolResult:
        try:
            import requests
            self.session = self.session or requests.Session()
            response = self.session.request(
                method=method.upper(),
                url=url,
                headers=headers,
                json=body if isinstance(body, (dict, list)) else None,
                params=params,
                timeout=30,
            )
            return ToolResult(
                success=True,
                result={
                    "status_code": response.status_code,
                    "headers": dict(response.headers),
                    "body": response.text[:5000],
                    "json": response.json() if response.headers.get("content-type", "").startswith("application/json") else None,
                },
                metadata={"url": url, "method": method},
            )
        except Exception as e:
            return ToolResult(success=False, error=str(e))


class FileSearchTool:
    NAME = "file_search"
    DESCRIPTION = "Advanced file search with content matching, regex support, and filtering"

    def __init__(self, root: str = "."):
        self.root = Path(root)

    def search(
        self,
        pattern: str,
        path: str = ".",
        regex: bool = False,
        file_types: Optional[list] = None,
        case_sensitive: bool = False,
        max_results: int = 100,
    ) -> ToolResult:
        try:
            search_path = Path(path)
            matches = []
            flags = 0 if case_sensitive else re.IGNORECASE

            for f in search_path.rglob("*"):
                if not f.is_file():
                    continue
                if file_types and f.suffix not in file_types:
                    continue
                try:
                    content = f.read_text(errors="ignore")
                    if regex:
                        found = re.search(pattern, content, flags)
                    else:
                        found = pattern.lower() in content.lower() if not case_sensitive else pattern in content

                    if found:
                        line_no = 0
                        snippet = ""
                        if not regex:
                            lines = content.split("\n")
                            for i, line in enumerate(lines):
                                if pattern.lower() in line.lower():
                                    line_no = i + 1
                                    snippet = line.strip()
                                    break
                        else:
                            match = re.search(pattern, content, flags)
                            if match:
                                start = max(0, match.start() - 50)
                                end = min(len(content), match.end() + 50)
                                snippet = content[start:end]
                                line_no = content[:match.start()].count("\n") + 1

                        matches.append({
                            "path": str(f.relative_to(self.root)),
                            "line": line_no,
                            "snippet": snippet,
                        })
                        if len(matches) >= max_results:
                            break
                except Exception:
                    continue

            return ToolResult(
                success=True,
                result={"matches": matches, "total": len(matches)},
                metadata={"pattern": pattern, "path": str(path)},
            )
        except Exception as e:
            return ToolResult(success=False, error=str(e))


class TaskRunnerTool:
    NAME = "task_runner"
    DESCRIPTION = "Run parallel tasks, manage task queues, and coordinate multi-step workflows"

    def __init__(self):
        self.tasks: Dict[str, Dict[str, Any]] = {}
        self.counter = 0

    def create_task(self, name: str, command: str, env: Optional[Dict[str, str]] = None) -> ToolResult:
        import uuid
        task_id = str(uuid.uuid4())[:8]
        self.tasks[task_id] = {
            "name": name,
            "command": command,
            "env": env or {},
            "status": "pending",
        }
        self.counter += 1
        return ToolResult(
            success=True,
            result={"task_id": task_id, "name": name},
            metadata={"total_tasks": self.counter},
        )

    def run_task(self, task_id: str, cwd: str = ".") -> ToolResult:
        if task_id not in self.tasks:
            return ToolResult(success=False, error=f"Task {task_id} not found")

        task = self.tasks[task_id]
        task["status"] = "running"
        shell = ShellTool(cwd=cwd)

        try:
            result = shell.execute(task["command"])
            task["status"] = "completed" if result.success else "failed"
            task["result"] = result.to_dict()
            return result
        except Exception as e:
            task["status"] = "failed"
            task["error"] = str(e)
            return ToolResult(success=False, error=str(e))

    def list_tasks(self) -> ToolResult:
        return ToolResult(
            success=True,
            result={"tasks": list(self.tasks.values()), "total": len(self.tasks)},
        )


TOOL_REGISTRY: Dict[str, type] = {
    "shell": ShellTool,
    "git": GitTool,
    "docker": DockerTool,
    "database": DatabaseTool,
    "api_client": APIClientTool,
    "file_search": FileSearchTool,
    "task_runner": TaskRunnerTool,
}


def get_tool(name: str, **kwargs: Any) -> Optional[Any]:
    tool_class = TOOL_REGISTRY.get(name)
    if tool_class:
        return tool_class(**kwargs)
    return None


def execute_tool(name: str, method: str, args: Dict[str, Any], **kwargs: Any) -> ToolResult:
    tool = get_tool(name, **kwargs)
    if not tool:
        return ToolResult(success=False, error=f"Unknown tool: {name}")

    if not hasattr(tool, method):
        return ToolResult(success=False, error=f"Tool {name} has no method {method}")

    try:
        return getattr(tool, method)(**args)
    except Exception as e:
        return ToolResult(success=False, error=str(e))
