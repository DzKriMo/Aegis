from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Awaitable
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading


class AgentRole(Enum):
    PLANNER = "planner"
    CODER = "coder"
    RESEARCHER = "researcher"
    REVIEWER = "reviewer"
    EXECUTOR = "executor"
    COORDINATOR = "coordinator"
    SPECIALIST = "specialist"


class TaskStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    WAITING = "waiting"


@dataclass
class Agent:
    id: str
    name: str
    role: AgentRole
    description: str
    capabilities: List[str] = field(default_factory=list)
    instructions: str = ""
    tools: List[str] = field(default_factory=list)
    model: str = "default"
    temperature: float = 0.1
    max_tokens: int = 2000

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "role": self.role.value,
            "description": self.description,
            "capabilities": self.capabilities,
            "instructions": self.instructions,
            "tools": self.tools,
        }


@dataclass
class Task:
    id: str
    description: str
    assigned_agent: Optional[str] = None
    status: TaskStatus = TaskStatus.PENDING
    priority: int = 0
    dependencies: List[str] = field(default_factory=list)
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    created_at: float = field(default_factory=time.time)
    started_at: Optional[float] = None
    completed_at: Optional[float] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "description": self.description,
            "assigned_agent": self.assigned_agent,
            "status": self.status.value,
            "priority": self.priority,
            "dependencies": self.dependencies,
            "result": self.result,
            "error": self.error,
            "created_at": self.created_at,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "metadata": self.metadata,
        }


@dataclass
class AgentMessage:
    from_agent: str
    to_agent: str
    content: Any
    task_id: Optional[str] = None
    timestamp: float = field(default_factory=time.time)
    message_type: str = "message"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "from": self.from_agent,
            "to": self.to_agent,
            "content": self.content,
            "task_id": self.task_id,
            "timestamp": self.timestamp,
            "type": self.message_type,
        }


class BaseAgentBackend:
    def __init__(self):
        self.messages: List[AgentMessage] = []

    def send_message(self, message: AgentMessage) -> None:
        self.messages.append(message)

    def get_messages(self, agent_id: Optional[str] = None) -> List[AgentMessage]:
        if agent_id:
            return [m for m in self.messages if m.to_agent == agent_id or m.from_agent == agent_id]
        return self.messages

    def clear_messages(self, agent_id: Optional[str] = None) -> None:
        if agent_id:
            self.messages = [m for m in self.messages if m.to_agent != agent_id and m.from_agent != agent_id]
        else:
            self.messages.clear()


class SubAgent:
    def __init__(
        self,
        agent: Agent,
        backend: Optional[BaseAgentBackend] = None,
        model_func: Optional[Callable] = None,
    ):
        self.agent = agent
        self.backend = backend or BaseAgentBackend()
        self.model_func = model_func
        self.task_history: List[Dict[str, Any]] = []
        self.state: Dict[str, Any] = {}

    def think(self, prompt: str, context: Optional[Dict[str, Any]] = None) -> str:
        if self.model_func:
            messages = [
                {"role": "system", "content": self.agent.instructions or f"You are {self.agent.name}, a {self.agent.role.value} agent."},
                {"role": "user", "content": prompt},
            ]
            if context:
                messages.insert(1, {"role": "system", "content": f"Context: {json.dumps(context)}"})
            return self.model_func(messages)
        return "Model function not configured"

    def execute_task(self, task: Task) -> Dict[str, Any]:
        task.started_at = time.time()
        result = {"task_id": task.id, "agent_id": self.agent.id, "success": True, "output": ""}

        try:
            output = self.think(
                f"Task: {task.description}\nPriority: {task.priority}\nMetadata: {json.dumps(task.metadata)}",
                context=task.metadata,
            )
            result["output"] = output
            task.result = result
            task.status = TaskStatus.COMPLETED
        except Exception as e:
            result["success"] = False
            result["error"] = str(e)
            task.error = str(e)
            task.status = TaskStatus.FAILED

        task.completed_at = time.time()
        self.task_history.append(result)
        return result

    def broadcast(self, message: str, target_role: Optional[AgentRole] = None) -> None:
        pass


class MultiAgentOrchestrator:
    def __init__(
        self,
        model_func: Optional[Callable] = None,
        max_concurrent: int = 5,
    ):
        self.agents: Dict[str, SubAgent] = {}
        self.tasks: Dict[str, Task] = {}
        self.model_func = model_func
        self.max_concurrent = max_concurrent
        self.backend = BaseAgentBackend()
        self.executor = ThreadPoolExecutor(max_workers=max_concurrent)
        self.coordinator: Optional[SubAgent] = None
        self._lock = threading.Lock()

    def register_agent(self, agent: Agent) -> str:
        sub_agent = SubAgent(agent, self.backend, self.model_func)
        with self._lock:
            self.agents[agent.id] = sub_agent
        if agent.role == AgentRole.COORDINATOR:
            self.coordinator = sub_agent
        return agent.id

    def create_agent(
        self,
        name: str,
        role: AgentRole,
        description: str,
        instructions: str = "",
        capabilities: Optional[List[str]] = None,
        tools: Optional[List[str]] = None,
    ) -> str:
        agent = Agent(
            id=str(uuid.uuid4())[:8],
            name=name,
            role=role,
            description=description,
            instructions=instructions,
            capabilities=capabilities or [],
            tools=tools or [],
        )
        return self.register_agent(agent)

    def create_task(
        self,
        description: str,
        priority: int = 0,
        dependencies: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> str:
        task = Task(
            id=str(uuid.uuid4())[:8],
            description=description,
            priority=priority,
            dependencies=dependencies or [],
            metadata=metadata or {},
        )
        with self._lock:
            self.tasks[task.id] = task
        return task.id

    def assign_task(self, task_id: str, agent_id: str) -> bool:
        with self._lock:
            if task_id in self.tasks and agent_id in self.agents:
                self.tasks[task_id].assigned_agent = agent_id
                return True
        return False

    def get_ready_tasks(self) -> List[Task]:
        ready = []
        with self._lock:
            for task in self.tasks.values():
                if task.status == TaskStatus.PENDING:
                    deps_met = all(
                        self.tasks.get(dep_id, Task("", "")).status == TaskStatus.COMPLETED
                        for dep_id in task.dependencies
                    )
                    if deps_met:
                        ready.append(task)
        return sorted(ready, key=lambda t: t.priority, reverse=True)

    def execute_task(self, task: Task) -> Dict[str, Any]:
        if not task.assigned_agent:
            if self.coordinator:
                task.assigned_agent = self.coordinator.agent.id
            elif self.agents:
                task.assigned_agent = next(iter(self.agents.keys()))
            else:
                return {"success": False, "error": "No agents available"}

        agent = self.agents.get(task.assigned_agent)
        if not agent:
            return {"success": False, "error": f"Agent {task.assigned_agent} not found"}

        return agent.execute_task(task)

    def run_workflow(
        self,
        tasks: List[Dict[str, Any]],
        parallel: bool = True,
        max_iterations: int = 50,
    ) -> Dict[str, Any]:
        task_ids = []
        for task_data in tasks:
            task_id = self.create_task(
                description=task_data.get("description", ""),
                priority=task_data.get("priority", 0),
                dependencies=task_data.get("dependencies", []),
                metadata=task_data.get("metadata", {}),
            )
            if "assigned_agent" in task_data:
                self.assign_task(task_id, task_data["assigned_agent"])
            task_ids.append(task_id)

        results = {}
        iterations = 0

        while iterations < max_iterations:
            iterations += 1
            ready_tasks = self.get_ready_tasks()

            if not ready_tasks:
                if all(t.status != TaskStatus.PENDING for t in self.tasks.values()):
                    break
                time.sleep(0.1)
                continue

            if parallel:
                futures = {}
                for task in ready_tasks[: self.max_concurrent]:
                    task.status = TaskStatus.RUNNING
                    future = self.executor.submit(self.execute_task, task)
                    futures[future] = task.id

                for future in as_completed(futures):
                    task_id = futures[future]
                    try:
                        result = future.result()
                        results[task_id] = result
                    except Exception as e:
                        results[task_id] = {"success": False, "error": str(e)}
            else:
                for task in ready_tasks:
                    task.status = TaskStatus.RUNNING
                    result = self.execute_task(task)
                    results[task.id] = result

        return {
            "completed": sum(1 for t in self.tasks.values() if t.status == TaskStatus.COMPLETED),
            "failed": sum(1 for t in self.tasks.values() if t.status == TaskStatus.FAILED),
            "results": results,
            "iterations": iterations,
        }

    def get_status(self) -> Dict[str, Any]:
        return {
            "agents": {aid: {"role": sa.agent.role.value, "tasks": len(sa.task_history)}
                      for aid, sa in self.agents.items()},
            "tasks": {
                "pending": sum(1 for t in self.tasks.values() if t.status == TaskStatus.PENDING),
                "running": sum(1 for t in self.tasks.values() if t.status == TaskStatus.RUNNING),
                "completed": sum(1 for t in self.tasks.values() if t.status == TaskStatus.COMPLETED),
                "failed": sum(1 for t in self.tasks.values() if t.status == TaskStatus.FAILED),
            },
            "messages": len(self.backend.messages),
        }

    def shutdown(self) -> None:
        self.executor.shutdown(wait=True)


@dataclass
class Team:
    id: str
    name: str
    mission: str
    agents: List[str] = field(default_factory=list)
    shared_state: Dict[str, Any] = field(default_factory=dict)


class AgentTeam:
    def __init__(self, orchestrator: MultiAgentOrchestrator):
        self.orchestrator = orchestrator
        self.teams: Dict[str, Team] = {}

    def create_team(
        self,
        name: str,
        mission: str,
        agent_definitions: List[Dict[str, Any]],
    ) -> str:
        team_id = str(uuid.uuid4())[:8]
        agent_ids = []

        for agent_def in agent_definitions:
            agent_id = self.orchestrator.create_agent(
                name=agent_def["name"],
                role=AgentRole(agent_def.get("role", "specialist")),
                description=agent_def.get("description", ""),
                instructions=agent_def.get("instructions", ""),
                capabilities=agent_def.get("capabilities", []),
                tools=agent_def.get("tools", []),
            )
            agent_ids.append(agent_id)

        team = Team(
            id=team_id,
            name=name,
            mission=mission,
            agents=agent_ids,
        )
        self.teams[team_id] = team
        return team_id

    def assign_team_task(self, team_id: str, task_description: str) -> str:
        if team_id not in self.teams:
            raise ValueError(f"Team {team_id} not found")

        task_id = self.orchestrator.create_task(
            description=task_description,
            metadata={"team_id": team_id},
        )
        return task_id

    def get_team_status(self, team_id: str) -> Optional[Dict[str, Any]]:
        if team_id not in self.teams:
            return None

        team = self.teams[team_id]
        agent_statuses = []
        for agent_id in team.agents:
            agent = self.orchestrator.agents.get(agent_id)
            if agent:
                agent_statuses.append({
                    "id": agent_id,
                    "name": agent.agent.name,
                    "role": agent.agent.role.value,
                    "tasks_completed": len(agent.task_history),
                })

        return {
            "id": team_id,
            "name": team.name,
            "mission": team.mission,
            "agents": agent_statuses,
            "shared_state": team.shared_state,
        }
