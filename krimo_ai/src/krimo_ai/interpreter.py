from __future__ import annotations

import ast
import io
import sys
import os
import tempfile
import time
import traceback
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from pathlib import Path


@dataclass
class ExecutionResult:
    success: bool
    output: str = ""
    error: Optional[str] = None
    execution_time: float = 0.0
    stdout: str = ""
    stderr: str = ""
    return_value: Any = None
    plots: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "success": self.success,
            "output": self.output,
            "error": self.error,
            "execution_time": self.execution_time,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "return_value": str(self.return_value) if self.return_value is not None else None,
            "plots": self.plots,
        }


class SecurityAnalyzer(ast.NodeVisitor):
    DANGEROUS_PATTERNS = [
        "os.system", "subprocess", "eval", "exec", "compile",
        "open(", "__import__", "getattr", "setattr", "delattr",
        "input(", "exit(", "quit(", "breakpoint", "license",
        "rm -rf", "format(",
    ]

    def __init__(self):
        self.issues: List[str] = []
        self.dangerous_imports: List[str] = []

    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            if alias.name in ["os", "subprocess", "sys", "socket", "urllib", "http"]:
                self.dangerous_imports.append(alias.name)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        if node.module in ["os", "subprocess", "sys", "socket", "urllib", "http"]:
            self.dangerous_imports.append(node.module)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        if isinstance(node.func, ast.Name):
            if node.func.id in ["eval", "exec", "compile", "input"]:
                self.issues.append(f"Dangerous function call: {node.func.id}")
        elif isinstance(node.func, ast.Attribute):
            full_name = f"{node.func.value.id}.{node.func.attr}" if isinstance(node.func.value, ast.Name) else node.func.attr
            if full_name in ["os.system", "subprocess.run", "os.popen", "eval", "exec"]:
                self.issues.append(f"Dangerous call: {full_name}")
        self.generic_visit(node)


class SandboxContext:
    DANGEROUS_LIBS = {"os", "subprocess", "sys", "socket", "urllib", "http", "ctypes", "fcntl", "resource", "prctl"}

    def __init__(self, allowed_modules: Optional[List[str]] = None):
        self.allowed_modules = allowed_modules or [
            "math", "random", "datetime", "json", "re", " collections",
            "itertools", "functools", "operator", "string", "textwrap",
            "decimal", "fractions", "statistics", "copy", "pprint",
            "html", "xml", "csv", "io", "time", "hashlib", "base64",
            "binascii", "zlib", "gzip", "zipfile", "tarfile",
            "pathlib", "urllib.parse", "encodings", "codecs",
        ]

    def is_module_allowed(self, module_name: str) -> bool:
        base = module_name.split(".")[0]
        return base in self.allowed_modules or base in self.DANGEROUS_LIBS


class CodeInterpreter:
    MAX_EXECUTION_TIME = 30
    MAX_OUTPUT_SIZE = 100000
    MAX_MEMORY_MB = 256

    def __init__(self, sandbox: bool = True, working_dir: Optional[str] = None):
        self.sandbox = sandbox
        self.working_dir = working_dir or tempfile.gettempdir()
        self.sandbox_context = SandboxContext()
        self.execution_history: List[Dict[str, Any]] = []

    def analyze_security(self, code: str) -> Dict[str, Any]:
        issues: List[str] = []
        try:
            tree = ast.parse(code)
            analyzer = SecurityAnalyzer()
            analyzer.visit(tree)
            issues.extend(analyzer.issues)

            if analyzer.dangerous_imports and self.sandbox:
                issues.append(f"Blocked imports in sandbox mode: {analyzer.dangerous_imports}")
        except SyntaxError as e:
            return {"safe": False, "issues": [f"Syntax error: {e}"]}
        return {"safe": len(issues) == 0, "issues": issues}

    def execute_python(self, code: str, capture_plots: bool = True) -> ExecutionResult:
        start_time = time.time()
        stdout_capture = io.StringIO()
        stderr_capture = io.StringIO()

        if self.sandbox:
            security = self.analyze_security(code)
            if not security["safe"]:
                return ExecutionResult(
                    success=False,
                    error=f"Security check failed: {', '.join(security['issues'])}",
                    execution_time=time.time() - start_time,
                )

        old_stdout = sys.stdout
        old_stderr = sys.stderr
        sys.stdout = stdout_capture
        sys.stderr = stderr_capture

        return_value = None
        error = None

        try:
            exec_globals: Dict[str, Any] = {
                "__name__": "__main__",
                "__builtins__": self._get_safe_builtins(),
                "__file__": "<interactive>",
            }

            if capture_plots:
                exec_globals["__anthic_matplotlib_backend__"] = "Agg"

            code = code.replace("\\n", "\n")

            try:
                compiled = compile(code, "<interactive>", "exec")
            except SyntaxError as e:
                error = f"Syntax error: {e}"
                raise

            return_value = exec(compiled, exec_globals)

            output = stdout_capture.getvalue()
            if len(output) > self.MAX_OUTPUT_SIZE:
                output = output[:self.MAX_OUTPUT_SIZE] + f"\n... (truncated, {len(output) - self.MAX_OUTPUT_SIZE} bytes omitted)"

        except Exception as e:
            error = f"{type(e).__name__}: {e}\n{traceback.format_exc()}"

        finally:
            sys.stdout = old_stdout
            sys.stderr = old_stderr

        execution_time = time.time() - start_time
        result = ExecutionResult(
            success=error is None,
            output=stdout_capture.getvalue(),
            error=error,
            execution_time=execution_time,
            stdout=stdout_capture.getvalue(),
            stderr=stderr_capture.getvalue(),
            return_value=return_value,
        )

        self.execution_history.append({
            "code": code[:500],
            "result": result.to_dict(),
            "timestamp": time.time(),
        })

        return result

    def _get_safe_builtins(self) -> Dict[str, Any]:
        safe_builtins = {}
        for name in dir(__builtins__):
            if name not in ["open", "__import__", "eval", "exec", "compile", "input", "breakpoint"]:
                safe_builtins[name] = getattr(__builtins__, name)
        return safe_builtins

    def execute_javascript(self, code: str) -> ExecutionResult:
        return ExecutionResult(
            success=False,
            error="JavaScript execution requires Node.js. Install Node.js to enable JS execution.",
        )

    def execute_shell(self, command: str, timeout: int = 30) -> ExecutionResult:
        import subprocess
        start_time = time.time()

        try:
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=min(timeout, self.MAX_EXECUTION_TIME),
                cwd=self.working_dir,
            )

            return ExecutionResult(
                success=result.returncode == 0,
                output=result.stdout,
                error=result.stderr if result.returncode != 0 else None,
                execution_time=time.time() - start_time,
                stdout=result.stdout,
                stderr=result.stderr,
                return_value=result.returncode,
            )
        except subprocess.TimeoutExpired:
            return ExecutionResult(
                success=False,
                error=f"Command timed out after {timeout} seconds",
                execution_time=timeout,
            )
        except Exception as e:
            return ExecutionResult(
                success=False,
                error=str(e),
                execution_time=time.time() - start_time,
            )

    def run(self, code: str, language: str = "python", **kwargs: Any) -> ExecutionResult:
        language = language.lower()
        if language in ("python", "py", "python3"):
            return self.execute_python(code, **kwargs)
        elif language in ("javascript", "js", "node"):
            return self.execute_javascript(code)
        elif language in ("shell", "bash", "sh"):
            return self.execute_shell(code, **kwargs)
        else:
            return ExecutionResult(
                success=False,
                error=f"Unsupported language: {language}. Supported: python, javascript, shell",
            )

    def get_history(self) -> List[Dict[str, Any]]:
        return self.execution_history[-50:]

    def clear_history(self) -> None:
        self.execution_history.clear()


@dataclass
class Session:
    id: str
    code: str
    language: str
    result: ExecutionResult
    timestamp: float = field(default_factory=time.time)


class MultiLanguageInterpreter:
    def __init__(self, working_dir: Optional[str] = None):
        self.working_dir = working_dir or tempfile.gettempdir()
        self.python_interpreter = CodeInterpreter(sandbox=True, working_dir=self.working_dir)
        self.sessions: Dict[str, Session] = {}
        self.session_counter = 0

    def execute(self, code: str, language: str = "python", session_id: Optional[str] = None, **kwargs: Any) -> Dict[str, Any]:
        self.session_counter += 1
        sid = session_id or f"session_{self.session_counter}"

        result = self.python_interpreter.run(code, language, **kwargs)

        session = Session(
            id=sid,
            code=code,
            language=language,
            result=result,
        )
        self.sessions[sid] = session

        return {
            "session_id": sid,
            "result": result.to_dict(),
            "history": self.python_interpreter.get_history(),
        }

    def get_session(self, session_id: str) -> Optional[Session]:
        return self.sessions.get(session_id)

    def list_sessions(self) -> List[Dict[str, Any]]:
        return [
            {"id": s.id, "language": s.language, "timestamp": s.timestamp}
            for s in self.sessions.values()
        ]
