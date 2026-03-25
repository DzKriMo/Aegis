from __future__ import annotations

import json
import re
import time
import threading
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple
from queue import Queue, Empty


class ExecutionMode(Enum):
    MANUAL = "manual"
    CONTINUOUS = "continuous"
    BATCH = "batch"
    SCHEDULED = "scheduled"


class TaskState(Enum):
    IDLE = "idle"
    PLANNING = "planning"
    EXECUTING = "executing"
    WAITING = "waiting"
    COMPLETED = "completed"
    FAILED = "failed"
    PAUSED = "paused"


@dataclass
class ExecutionStep:
    id: str
    description: str
    action: Dict[str, Any]
    status: TaskState = TaskState.IDLE
    result: Optional[Any] = None
    error: Optional[str] = None
    attempts: int = 0
    max_attempts: int = 3
    started_at: Optional[float] = None
    completed_at: Optional[float] = None


@dataclass
class AutonomousTask:
    id: str
    goal: str
    steps: List[ExecutionStep] = field(default_factory=list)
    state: TaskState = TaskState.IDLE
    current_step: int = 0
    results: List[Dict[str, Any]] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)
    started_at: Optional[float] = None
    completed_at: Optional[float] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


class AutonomousController:
    def __init__(
        self,
        model_func: Callable,
        execute_func: Callable,
        max_iterations: int = 50,
        step_timeout: int = 120,
        self_correct: bool = True,
    ):
        self.model_func = model_func
        self.execute_func = execute_func
        self.max_iterations = max_iterations
        self.step_timeout = step_timeout
        self.self_correct = self_correct
        self.tasks: Dict[str, AutonomousTask] = {}
        self.event_queue: Queue = Queue()
        self.is_running = False
        self.thread: Optional[threading.Thread] = None
        self.observers: List[Callable] = []

    def plan_task(self, goal: str, context: Optional[Dict[str, Any]] = None) -> AutonomousTask:
        import uuid
        task_id = str(uuid.uuid4())[:8]

        planning_prompt = (
            f"Break down this goal into specific execution steps:\n"
            f"Goal: {goal}\n\n"
            f"Return ONLY valid JSON with this structure:\n"
            f'{{"steps": [{{"description": "...", "action": {{"tool": "...", "args": {{}}}}}}]}}'
        )

        if context:
            planning_prompt += f"\n\nContext:\n{json.dumps(context)}"

        response = self.model_func([{"role": "user", "content": planning_prompt}])

        try:
            if response.strip().startswith("{"):
                start = response.find("{")
                end = response.rfind("}") + 1
                plan = json.loads(response[start:end])
            else:
                plan = {"steps": []}
        except json.JSONDecodeError:
            plan = {"steps": []}

        steps = []
        for i, step_data in enumerate(plan.get("steps", [])):
            step = ExecutionStep(
                id=f"step_{i + 1}",
                description=step_data.get("description", ""),
                action=step_data.get("action", {}),
            )
            steps.append(step)

        task = AutonomousTask(
            id=task_id,
            goal=goal,
            steps=steps,
            metadata={"context": context or {}},
        )
        self.tasks[task_id] = task
        return task

    def execute_step(self, task: AutonomousTask, step: ExecutionStep) -> Tuple[bool, Any]:
        step.status = TaskState.EXECUTING
        step.started_at = time.time()
        step.attempts += 1

        try:
            tool_name = step.action.get("tool", "")
            args = step.action.get("args", {})

            result = self.execute_func(tool_name, args)

            step.result = result
            step.status = TaskState.COMPLETED
            step.completed_at = time.time()

            self._notify_observers("step_completed", {"task": task, "step": step})

            return True, result

        except Exception as e:
            step.error = str(e)
            if step.attempts < step.max_attempts:
                step.status = TaskState.IDLE
                return False, f"Attempt {step.attempts} failed: {e}"
            else:
                step.status = TaskState.FAILED
                step.completed_at = time.time()
                return False, str(e)

    def self_correct_step(self, task: AutonomousTask, failed_step: ExecutionStep, error: str) -> Optional[ExecutionStep]:
        if not self.self_correct:
            return None

        correction_prompt = (
            f"A step failed while executing this task:\n"
            f"Goal: {task.goal}\n"
            f"Failed step: {failed_step.description}\n"
            f"Error: {error}\n\n"
            f"Return ONLY valid JSON with the corrected step:\n"
            f'{{"description": "...", "action": {{"tool": "...", "args": {{}}}}}}'
        )

        response = self.model_func([{"role": "user", "content": correction_prompt}])

        try:
            if response.strip().startswith("{"):
                start = response.find("{")
                end = response.rfind("}") + 1
                correction = json.loads(response[start:end])
            else:
                return None

            new_step = ExecutionStep(
                id=f"{failed_step.id}_retry_{failed_step.attempts}",
                description=correction.get("description", failed_step.description),
                action=correction.get("action", failed_step.action),
                max_attempts=failed_step.max_attempts,
            )
            return new_step

        except json.JSONDecodeError:
            return None

    def execute_task(self, task: AutonomousTask) -> Dict[str, Any]:
        task.state = TaskState.PLANNING
        task.started_at = time.time()

        if not task.steps:
            task.state = TaskState.FAILED
            task.errors.append("No steps to execute")
            return {"success": False, "error": "No steps planned"}

        task.state = TaskState.EXECUTING
        self._notify_observers("task_started", {"task": task})

        for i, step in enumerate(task.steps):
            task.current_step = i

            if step.status == TaskState.COMPLETED:
                continue

            success, result = self.execute_step(task, step)

            while not success and step.attempts < step.max_attempts:
                self._notify_observers("step_retried", {"task": task, "step": step, "error": result})
                correction = self.self_correct_step(task, step, str(result))
                if correction:
                    task.steps.insert(i + 1, correction)
                success, result = self.execute_step(task, step)

            if not success:
                task.state = TaskState.FAILED
                task.errors.append(str(result))
                self._notify_observers("task_failed", {"task": task, "step": step, "error": result})
                return {"success": False, "error": str(result), "failed_step": i}

            task.results.append({"step": i, "result": result})

        task.state = TaskState.COMPLETED
        task.completed_at = time.time()
        self._notify_observers("task_completed", {"task": task})

        return {
            "success": True,
            "results": task.results,
            "duration": task.completed_at - task.started_at,
        }

    def run_continuous(self, goals: List[str], context: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        results = []
        for goal in goals:
            task = self.plan_task(goal, context)
            result = self.execute_task(task)
            results.append({"goal": goal, "task": task, "result": result})
        return results

    def start_background(self, goals: List[str], context: Optional[Dict[str, Any]] = None) -> str:
        import uuid
        batch_id = str(uuid.uuid4())[:8]

        def run_batch():
            self.run_continuous(goals, context)

        self.is_running = True
        self.thread = threading.Thread(target=run_batch, daemon=True)
        self.thread.start()
        return batch_id

    def stop(self) -> None:
        self.is_running = False
        if self.thread:
            self.thread.join(timeout=5)

    def pause(self, task_id: str) -> bool:
        if task_id in self.tasks:
            self.tasks[task_id].state = TaskState.PAUSED
            return True
        return False

    def resume(self, task_id: str) -> bool:
        if task_id in self.tasks:
            task = self.tasks[task_id]
            if task.state == TaskState.PAUSED:
                task.state = TaskState.EXECUTING
                return True
        return False

    def get_task_status(self, task_id: str) -> Optional[Dict[str, Any]]:
        if task_id not in self.tasks:
            return None
        task = self.tasks[task_id]
        return {
            "id": task.id,
            "goal": task.goal,
            "state": task.state.value,
            "current_step": task.current_step,
            "total_steps": len(task.steps),
            "progress": task.current_step / len(task.steps) if task.steps else 0,
            "results_count": len(task.results),
            "errors": task.errors,
        }

    def add_observer(self, callback: Callable) -> None:
        self.observers.append(callback)

    def remove_observer(self, callback: Callable) -> None:
        if callback in self.observers:
            self.observers.remove(callback)

    def _notify_observers(self, event: str, data: Dict[str, Any]) -> None:
        for observer in self.observers:
            try:
                observer(event, data)
            except Exception:
                pass


class ReflexionAgent:
    def __init__(self, model_func: Callable):
        self.model_func = model_func
        self.reflection_history: List[Dict[str, Any]] = []

    def reflect(self, task: str, attempt_result: Any, attempt_number: int) -> Dict[str, Any]:
        reflection_prompt = (
            f"Reflect on this attempt to complete a task:\n"
            f"Task: {task}\n"
            f"Attempt {attempt_number} result: {attempt_result}\n\n"
            f"Return ONLY valid JSON with your reflection:\n"
            f'{{"analysis": "...", "lessons": ["..."], "improvements": ["..."]}}'
        )

        response = self.model_func([{"role": "user", "content": reflection_prompt}])

        try:
            if response.strip().startswith("{"):
                start = response.find("{")
                end = response.rfind("}") + 1
                reflection = json.loads(response[start:end])
            else:
                reflection = {"analysis": "", "lessons": [], "improvements": []}
        except json.JSONDecodeError:
            reflection = {"analysis": "", "lessons": [], "improvements": []}

        self.reflection_history.append({
            "task": task,
            "attempt": attempt_number,
            "reflection": reflection,
            "timestamp": time.time(),
        })

        return reflection

    def generate_improved_plan(self, task: str, reflections: List[Dict[str, Any]]) -> str:
        reflection_summary = "\n".join(
            f"Attempt {r['attempt']}: {r['reflection'].get('improvements', [])}"
            for r in reflections
        )

        improvement_prompt = (
            f"Based on these reflections, generate an improved plan:\n"
            f"Task: {task}\n"
            f"Previous reflections:\n{reflection_summary}\n\n"
            f"Return the improved plan as plain text."
        )

        return self.model_func([{"role": "user", "content": improvement_prompt}])


class EnhancedPlanner:
    def __init__(self, model_func: Callable):
        self.model_func = model_func
        self.plans: Dict[str, Dict[str, Any]] = {}

    def create_plan(
        self,
        goal: str,
        constraints: Optional[List[str]] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        constraints_text = "\n".join(f"- {c}" for c in constraints) if constraints else "None"

        planning_prompt = (
            f"Create a detailed execution plan for this goal:\n"
            f"Goal: {goal}\n"
            f"Constraints:\n{constraints_text}\n\n"
            f"Return ONLY valid JSON with this structure:\n"
            f'{{"plan_id": "...", "steps": [{{"id": "step_1", "description": "...", '
            f'"action": {{"tool": "...", "args": {{}}}}, "dependencies": [], "estimated_time": "..."}}], '
            f'"estimated_total_time": "...", "risks": ["..."], "alternatives": ["..."]}}'
        )

        if context:
            planning_prompt += f"\n\nContext:\n{json.dumps(context)}"

        response = self.model_func([{"role": "user", "content": planning_prompt}])

        try:
            if response.strip().startswith("{"):
                start = response.find("{")
                end = response.rfind("}") + 1
                plan = json.loads(response[start:end])
            else:
                plan = {"plan_id": "", "steps": [], "risks": [], "alternatives": []}
        except json.JSONDecodeError:
            plan = {"plan_id": "", "steps": [], "risks": [], "alternatives": []}

        plan["goal"] = goal
        plan["created_at"] = time.time()
        plan_id = plan.get("plan_id", str(hash(goal)))
        self.plans[plan_id] = plan

        return plan

    def estimate_time(self, plan: Dict[str, Any]) -> float:
        total_minutes = 0
        for step in plan.get("steps", []):
            est = step.get("estimated_time", "5 minutes")
            match = re.search(r"(\d+)", est)
            if match:
                total_minutes += int(match.group(1))
        return total_minutes * 60

    def identify_risks(self, plan: Dict[str, Any]) -> List[Dict[str, str]]:
        risks = []
        for step in plan.get("steps", []):
            for risk in plan.get("risks", []):
                risks.append({
                    "step": step.get("id", ""),
                    "risk": risk,
                    "mitigation": f"Monitor {step.get('description', '')} closely",
                })
        return risks

    def optimize_plan(self, plan: Dict[str, Any]) -> Dict[str, Any]:
        steps = plan.get("steps", [])
        dependencies = {}

        for i, step in enumerate(steps):
            deps = step.get("dependencies", [])
            dependencies[step.get("id", i)] = deps

        execution_order = []
        completed = set()

        while len(execution_order) < len(steps):
            for i, step in enumerate(steps):
                step_id = step.get("id", i)
                if step_id in completed:
                    continue
                deps = dependencies.get(step_id, [])
                if all(d in completed for d in deps):
                    execution_order.append(step)
                    completed.add(step_id)

        plan["optimized_steps"] = execution_order
        return plan
