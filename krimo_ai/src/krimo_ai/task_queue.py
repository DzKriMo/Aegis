from __future__ import annotations

import json
import time
import uuid
from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional
from queue import PriorityQueue, Empty
import threading


class JobStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    PAUSED = "paused"


class JobPriority(Enum):
    LOW = 3
    NORMAL = 2
    HIGH = 1
    CRITICAL = 0


@dataclass
class Job:
    id: str
    name: str
    description: str
    func: Callable
    args: tuple = field(default_factory=tuple)
    kwargs: Dict[str, Any] = field(default_factory=dict)
    priority: JobPriority = JobPriority.NORMAL
    status: JobStatus = JobStatus.PENDING
    result: Any = None
    error: Optional[str] = None
    created_at: float = field(default_factory=time.time)
    started_at: Optional[float] = None
    completed_at: Optional[float] = None
    progress: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)
    dependencies: List[str] = field(default_factory=list)
    retry_count: int = 0
    max_retries: int = 3

    def __lt__(self, other: "Job") -> bool:
        return self.priority.value < other.priority.value

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "priority": self.priority.name,
            "status": self.status.value,
            "progress": self.progress,
            "created_at": self.created_at,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "duration": (self.completed_at or time.time()) - (self.started_at or self.created_at),
            "tags": self.tags,
            "error": self.error,
        }


class JobQueue:
    def __init__(self, max_workers: int = 4, max_queue_size: int = 100):
        self.max_workers = max_workers
        self.max_queue_size = max_queue_size
        self.queue: PriorityQueue[Job] = PriorityQueue(maxsize=max_queue_size)
        self.jobs: Dict[str, Job] = {}
        self.running: Dict[str, threading.Thread] = {}
        self.results: Dict[str, Any] = {}
        self.lock = threading.Lock()
        self.is_running = False
        self.worker_thread: Optional[threading.Thread] = None
        self.callbacks: Dict[str, List[Callable]] = {
            "job_start": [],
            "job_complete": [],
            "job_fail": [],
            "job_progress": [],
        }

    def add_job(
        self,
        name: str,
        func: Callable,
        args: tuple = (),
        kwargs: Optional[Dict[str, Any]] = None,
        priority: JobPriority = JobPriority.NORMAL,
        tags: Optional[List[str]] = None,
        dependencies: Optional[List[str]] = None,
        max_retries: int = 3,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> str:
        job_id = str(uuid.uuid4())[:8]
        job = Job(
            id=job_id,
            name=name,
            description=name,
            func=func,
            args=args,
            kwargs=kwargs or {},
            priority=priority,
            tags=tags or [],
            dependencies=dependencies or [],
            max_retries=max_retries,
            metadata=metadata or {},
        )

        with self.lock:
            self.jobs[job_id] = job

        try:
            self.queue.put_nowait(job)
        except:
            raise Exception("Queue is full")

        return job_id

    def get_job(self, job_id: str) -> Optional[Job]:
        return self.jobs.get(job_id)

    def cancel_job(self, job_id: str) -> bool:
        with self.lock:
            job = self.jobs.get(job_id)
            if not job:
                return False
            if job.status == JobStatus.RUNNING:
                return False
            job.status = JobStatus.CANCELLED
            return True

    def pause_job(self, job_id: str) -> bool:
        with self.lock:
            job = self.jobs.get(job_id)
            if job and job.status == JobStatus.RUNNING:
                job.status = JobStatus.PAUSED
                return True
        return False

    def resume_job(self, job_id: str) -> bool:
        with self.lock:
            job = self.jobs.get(job_id)
            if job and job.status == JobStatus.PAUSED:
                job.status = JobStatus.PENDING
                try:
                    self.queue.put_nowait(job)
                except:
                    return False
                return True
        return False

    def retry_job(self, job_id: str) -> bool:
        with self.lock:
            job = self.jobs.get(job_id)
            if job and job.status == JobStatus.FAILED and job.retry_count < job.max_retries:
                job.status = JobStatus.PENDING
                job.retry_count += 1
                job.error = None
                try:
                    self.queue.put_nowait(job)
                except:
                    return False
                return True
        return False

    def _execute_job(self, job: Job):
        job.status = JobStatus.RUNNING
        job.started_at = time.time()
        self._trigger_callback("job_start", job)

        try:
            result = job.func(*job.args, **job.kwargs)
            job.result = result
            job.status = JobStatus.COMPLETED
            job.completed_at = time.time()
            job.progress = 1.0
            self.results[job.id] = result
            self._trigger_callback("job_complete", job)
        except Exception as e:
            job.error = str(e)
            job.status = JobStatus.FAILED
            job.completed_at = time.time()
            self._trigger_callback("job_fail", job)

        with self.lock:
            if job.id in self.running:
                del self.running[job.id]

    def _worker(self):
        while self.is_running:
            try:
                job = self.queue.get(timeout=1.0)

                if job.status == JobStatus.CANCELLED:
                    continue

                if job.dependencies:
                    deps_met = all(
                        self.jobs.get(dep_id, Job("", "", "", lambda: None)).status == JobStatus.COMPLETED
                        for dep_id in job.dependencies
                    )
                    if not deps_met:
                        self.queue.put(job)
                        time.sleep(0.1)
                        continue

                with self.lock:
                    self.running[job.id] = threading.current_thread()

                thread = threading.Thread(target=self._execute_job, args=(job,))
                thread.daemon = True
                thread.start()

            except Empty:
                continue
            except Exception:
                pass

    def start(self):
        if self.is_running:
            return
        self.is_running = True
        self.worker_thread = threading.Thread(target=self._worker)
        self.worker_thread.daemon = True
        self.worker_thread.start()

    def stop(self, wait: bool = True):
        self.is_running = False
        if wait and self.worker_thread:
            self.worker_thread.join(timeout=5.0)

    def get_stats(self) -> Dict[str, Any]:
        with self.lock:
            return {
                "total_jobs": len(self.jobs),
                "pending": sum(1 for j in self.jobs.values() if j.status == JobStatus.PENDING),
                "running": len(self.running),
                "completed": sum(1 for j in self.jobs.values() if j.status == JobStatus.COMPLETED),
                "failed": sum(1 for j in self.jobs.values() if j.status == JobStatus.FAILED),
                "cancelled": sum(1 for j in self.jobs.values() if j.status == JobStatus.CANCELLED),
                "queue_size": self.queue.qsize(),
                "max_workers": self.max_workers,
            }

    def list_jobs(self, status: Optional[JobStatus] = None, tags: Optional[List[str]] = None, limit: int = 50) -> List[Dict[str, Any]]:
        jobs = list(self.jobs.values())
        if status:
            jobs = [j for j in jobs if j.status == status]
        if tags:
            jobs = [j for j in jobs if any(tag in j.tags for tag in tags)]
        jobs.sort(key=lambda j: j.created_at, reverse=True)
        return [j.to_dict() for j in jobs[:limit]]

    def on(self, event: str, callback: Callable):
        if event in self.callbacks:
            self.callbacks[event].append(callback)

    def _trigger_callback(self, event: str, job: Job):
        for callback in self.callbacks.get(event, []):
            try:
                callback(job)
            except Exception:
                pass

    def clear_completed(self, keep_results: bool = False):
        with self.lock:
            if not keep_results:
                self.results.clear()
            completed_ids = [jid for jid, j in self.jobs.items() if j.status in (JobStatus.COMPLETED, JobStatus.FAILED, JobStatus.CANCELLED)]
            for jid in completed_ids:
                del self.jobs[jid]


class TaskManager:
    def __init__(self, queue: Optional[JobQueue] = None):
        self.queue = queue or JobQueue()
        self.queue.start()
        self.task_templates: Dict[str, Dict[str, Any]] = {}

    def register_template(self, name: str, template: Dict[str, Any]):
        self.task_templates[name] = template

    def create_task(self, name: str, task_type: str, params: Dict[str, Any]) -> str:
        template = self.task_templates.get(task_type)
        if template:
            params = {**template, **params}

        func = self._get_task_func(task_type)
        if not func:
            raise ValueError(f"Unknown task type: {task_type}")

        return self.queue.add_job(
            name=name,
            func=func,
            kwargs=params,
        )

    def _get_task_func(self, task_type: str) -> Optional[Callable]:
        funcs = {
            "shell": lambda cmd, **kw: __import__("subprocess").run(cmd, shell=True, capture_output=True, text=True),
            "python": lambda code, **kw: __import__("exec").exec(code),
            "sleep": lambda seconds, **kw: __import__("time").sleep(seconds),
        }
        return funcs.get(task_type)

    def get_task_status(self, task_id: str) -> Optional[Dict[str, Any]]:
        job = self.queue.get_job(task_id)
        return job.to_dict() if job else None

    def wait_for_task(self, task_id: str, timeout: float = 60.0) -> Optional[Any]:
        start = time.time()
        while time.time() - start < timeout:
            job = self.queue.get_job(task_id)
            if not job:
                return None
            if job.status in (JobStatus.COMPLETED, JobStatus.FAILED, JobStatus.CANCELLED):
                return job.result if job.status == JobStatus.COMPLETED else job.error
            time.sleep(0.1)
        return None

    def cancel_all(self):
        for job_id in list(self.queue.jobs.keys()):
            self.queue.cancel_job(job_id)
