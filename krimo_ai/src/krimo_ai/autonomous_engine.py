from __future__ import annotations

import json
import time
import traceback
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Union
from pathlib import Path


class StepStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    SKIPPED = "skipped"
    RETRYING = "retrying"


@dataclass
class ExecutionStep:
    id: str
    description: str
    tool_name: str
    args: Dict[str, Any]
    status: StepStatus = StepStatus.PENDING
    result: Any = None
    error: Optional[str] = None
    attempts: int = 0
    max_attempts: int = 3
    retry_delay: float = 1.0
    timeout: int = 120
    created_at: float = field(default_factory=time.time)
    started_at: Optional[float] = None
    completed_at: Optional[float] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "description": self.description,
            "tool_name": self.tool_name,
            "args": self.args,
            "status": self.status.value,
            "result": str(self.result)[:500] if self.result else None,
            "error": self.error,
            "attempts": self.attempts,
        }


@dataclass
class Task:
    id: str
    goal: str
    steps: List[ExecutionStep] = field(default_factory=list)
    status: StepStatus = StepStatus.PENDING
    current_step: int = 0
    results: List[Dict[str, Any]] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)
    started_at: Optional[float] = None
    completed_at: Optional[float] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "goal": self.goal,
            "status": self.status.value,
            "current_step": self.current_step,
            "total_steps": len(self.steps),
            "completed_steps": sum(1 for s in self.steps if s.status == StepStatus.SUCCESS),
            "failed_steps": sum(1 for s in self.steps if s.status == StepStatus.FAILED),
        }


class ToolRegistry:
    _tools: Dict[str, Callable] = {}
    _metadata: Dict[str, Dict[str, Any]] = {}

    @classmethod
    def register(cls, name: str, func: Callable, description: str = "", args_schema: Optional[Dict] = None):
        cls._tools[name] = func
        cls._metadata[name] = {
            "description": description,
            "args_schema": args_schema or {},
            "registered_at": time.time(),
        }

    @classmethod
    def get(cls, name: str) -> Optional[Callable]:
        return cls._tools.get(name)

    @classmethod
    def list_tools(cls) -> List[Dict[str, Any]]:
        return [
            {"name": name, **meta}
            for name, meta in cls._metadata.items()
        ]

    @classmethod
    def has(cls, name: str) -> bool:
        return name in cls._tools


class AutonomousEngine:
    def __init__(
        self,
        model_func: Optional[Callable] = None,
        max_iterations: int = 20,
        step_timeout: int = 120,
        self_correct: bool = True,
        verbose: bool = True,
    ):
        self.model_func = model_func
        self.max_iterations = max_iterations
        self.step_timeout = step_timeout
        self.self_correct = self_correct
        self.verbose = verbose
        self.tasks: Dict[str, Task] = {}
        self.callbacks: List[Callable] = []

    def log(self, message: str, level: str = "info"):
        if self.verbose:
            prefix = {"info": "[*]", "success": "[+]", "error": "[!]", "warn": "[?]"}.get(level, "[*]")
            print(f"{prefix} {message}")

    def register_tool(self, name: str, func: Callable, description: str = ""):
        ToolRegistry.register(name, func, description)

    def execute_tool(self, tool_name: str, args: Dict[str, Any]) -> tuple[bool, Any]:
        tool = ToolRegistry.get(tool_name)
        if not tool:
            return False, f"Tool not found: {tool_name}"

        try:
            result = tool(**args)
            return True, result
        except Exception as e:
            return False, str(e)

    def plan_task(self, goal: str, context: Optional[Dict[str, Any]] = None) -> Task:
        import uuid
        task_id = str(uuid.uuid4())[:8]

        if self.model_func:
            planning_prompt = self._build_planning_prompt(goal, context)
            response = self.model_func(planning_prompt)
            steps = self._parse_planned_steps(response, goal)
        else:
            steps = [ExecutionStep(
                id=f"{task_id}_step_1",
                description=goal,
                tool_name="shell",
                args={"command": goal},
            )]

        task = Task(
            id=task_id,
            goal=goal,
            steps=steps,
            metadata={"context": context or {}},
        )
        self.tasks[task_id] = task
        return task

    def _build_planning_prompt(self, goal: str, context: Optional[Dict[str, Any]]) -> str:
        tools = ToolRegistry.list_tools()
        tools_str = "\n".join([f"- {t['name']}: {t['description']}" for t in tools]) if tools else "No tools registered"

        context_str = ""
        if context:
            context_str = f"\n\nContext:\n{json.dumps(context, indent=2)}"

        return f"""You are a task planning agent. Break down the goal into executable steps.

Available tools:
{tools_str}

Goal: {goal}{context_str}

Return ONLY valid JSON:
{{"steps": [
  {{"id": "step_1", "description": "...", "tool_name": "...", "args": {{}}}},
  ...
]}}
Only use tools that are in the available tools list."""

    def _parse_planned_steps(self, response: str, goal: str) -> List[ExecutionStep]:
        try:
            if "```json" in response:
                start = response.find("```json") + 7
                end = response.rfind("```")
                response = response[start:end]
            elif response.strip().startswith("{"):
                start = response.find("{")
                end = response.rfind("}") + 1
                response = response[start:end]

            data = json.loads(response)
            steps = []
            for i, step_data in enumerate(data.get("steps", [])):
                step = ExecutionStep(
                    id=step_data.get("id", f"step_{i+1}"),
                    description=step_data.get("description", ""),
                    tool_name=step_data.get("tool_name", "shell"),
                    args=step_data.get("args", {}),
                    timeout=step_data.get("timeout", self.step_timeout),
                )
                steps.append(step)
            return steps
        except json.JSONDecodeError:
            return [ExecutionStep(
                id="step_1",
                description=goal,
                tool_name="shell",
                args={"command": goal},
            )]

    def execute_step(self, step: ExecutionStep) -> tuple[bool, Any]:
        step.status = StepStatus.RUNNING
        step.started_at = time.time()
        step.attempts += 1

        self.log(f"Executing: {step.description}")

        success, result = self.execute_tool(step.tool_name, step.args)

        if success:
            step.status = StepStatus.SUCCESS
            step.result = result
            self.log(f"Step completed: {step.description}", "success")
        else:
            step.error = str(result)
            if step.attempts < step.max_attempts:
                step.status = StepStatus.RETRYING
                self.log(f"Retrying step ({step.attempts}/{step.max_attempts}): {step.error}", "warn")
                time.sleep(step.retry_delay * step.attempts)
            else:
                step.status = StepStatus.FAILED
                self.log(f"Step failed: {step.error}", "error")

        step.completed_at = time.time()
        return success, result

    def self_correct_step(self, failed_step: ExecutionStep, error: str, task: Task) -> Optional[ExecutionStep]:
        if not self.self_correct or not self.model_func:
            return None

        correction_prompt = f"""A step failed. Suggest a corrected approach.

Failed: {failed_step.description}
Error: {error}

Available tools: {', '.join(ToolRegistry.list_tools())}

Return ONLY valid JSON:
{{"description": "corrected step", "tool_name": "...", "args": {{}}}}
"""
        try:
            response = self.model_func(correction_prompt)
            data = json.loads(response.strip())
            return ExecutionStep(
                id=f"{failed_step.id}_retry",
                description=data.get("description", failed_step.description),
                tool_name=data.get("tool_name", "shell"),
                args=data.get("args", {"command": failed_step.description}),
            )
        except Exception:
            return None

    def execute_task(self, task: Task) -> Dict[str, Any]:
        task.status = StepStatus.RUNNING
        task.started_at = time.time()
        self.log(f"Starting task: {task.goal}")

        for i, step in enumerate(task.steps):
            task.current_step = i
            self._notify_callbacks("step_start", {"task": task, "step": step})

            success, result = self.execute_step(step)
            task.results.append({
                "step_id": step.id,
                "success": success,
                "result": str(result)[:200],
            })

            while step.status == StepStatus.RETRYING and step.attempts < step.max_attempts:
                new_step = self.self_correct_step(step, step.error, task)
                if new_step:
                    task.steps.insert(i + 1, new_step)
                success, result = self.execute_step(step)
                task.results[-1] = {"step_id": step.id, "success": success, "result": str(result)[:200]}

            if step.status == StepStatus.FAILED:
                task.status = StepStatus.FAILED
                task.completed_at = time.time()
                self.log(f"Task failed at step: {step.description}", "error")
                self._notify_callbacks("task_failed", {"task": task, "failed_step": step})
                return {
                    "success": False,
                    "error": step.error,
                    "failed_step": step.id,
                    "completed_steps": i,
                    "total_steps": len(task.steps),
                }

            self._notify_callbacks("step_complete", {"task": task, "step": step})

        task.status = StepStatus.SUCCESS
        task.completed_at = time.time()
        self.log(f"Task completed successfully!", "success")
        self._notify_callbacks("task_complete", {"task": task})

        return {
            "success": True,
            "completed_steps": len(task.steps),
            "total_steps": len(task.steps),
            "duration": task.completed_at - task.started_at,
            "results": task.results,
        }

    def run(self, goal: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        task = self.plan_task(goal, context)
        return self.execute_task(task)

    def add_callback(self, callback: Callable):
        self.callbacks.append(callback)

    def _notify_callbacks(self, event: str, data: Dict[str, Any]):
        for cb in self.callbacks:
            try:
                cb(event, data)
            except Exception:
                pass

    def get_task(self, task_id: str) -> Optional[Task]:
        return self.tasks.get(task_id)

    def list_tasks(self) -> List[Dict[str, Any]]:
        return [t.to_dict() for t in self.tasks.values()]


class StreamingCallback:
    def __init__(self):
        self.buffer = ""

    def on_step_start(self, step: ExecutionStep):
        print(f"\n>>> Executing: {step.description}")

    def on_step_complete(self, step: ExecutionStep, result: Any):
        if step.status == StepStatus.SUCCESS:
            preview = str(result)[:100]
            print(f"    [OK] {preview}...")
        else:
            print(f"    [FAIL] {step.error}")

    def on_task_complete(self, task: Task):
        print(f"\n{'='*50}")
        print(f"Task completed in {task.completed_at - task.started_at:.2f}s")
        print(f"Steps: {len([s for s in task.steps if s.status == StepStatus.SUCCESS])}/{len(task.steps)}")


def create_engine(
    model_func: Optional[Callable] = None,
    tools: Optional[Dict[str, Callable]] = None,
    verbose: bool = True,
) -> AutonomousEngine:
    engine = AutonomousEngine(model_func=model_func, verbose=verbose)

    if tools:
        for name, func in tools.items():
            engine.register_tool(name, func)

    callback = StreamingCallback()
    engine.add_callback(lambda e, d: callback.on_step_start(d.get("step", ExecutionStep("", "", "", {}))))
    engine.add_callback(lambda e, d: callback.on_step_complete(d.get("step", ExecutionStep("", "", "", {})), d.get("result")))
    engine.add_callback(lambda e, d: callback.on_task_complete(d.get("task", Task("", ""))) if e == "task_complete" else None)

    return engine
