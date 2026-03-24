from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set
import threading
import hashlib


class EventType(Enum):
    CREATED = "created"
    MODIFIED = "modified"
    DELETED = "deleted"
    MOVED = "moved"
    ACCESSED = "accessed"


@dataclass
class FileEvent:
    path: str
    event_type: EventType
    timestamp: float = field(default_factory=time.time)
    size: Optional[int] = None
    is_directory: bool = False
    old_path: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "path": self.path,
            "event": self.event_type.value,
            "timestamp": self.timestamp,
            "size": self.size,
            "is_directory": self.is_directory,
            "old_path": self.old_path,
        }


class FileWatcher:
    def __init__(self, path: str, recursive: bool = True):
        self.path = Path(path)
        self.recursive = recursive
        self._file_hashes: Dict[str, str] = {}
        self._last_mtimes: Dict[str, float] = {}
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._callbacks: List[Callable[[FileEvent], None]] = []
        self._callbacks_lock = threading.Lock()
        self._stop_event = threading.Event()

    def _compute_hash(self, path: Path) -> str:
        try:
            with open(path, "rb") as f:
                return hashlib.md5(f.read(1024 * 1024)).hexdigest()
        except Exception:
            return ""

    def _check_file(self, path: Path) -> Optional[FileEvent]:
        try:
            if not path.exists():
                if str(path) in self._last_mtimes:
                    del self._last_mtimes[str(path)]
                    return FileEvent(path=str(path), event_type=EventType.DELETED)
                return None

            stat = path.stat()
            mtime = stat.st_mtime
            size = stat.st_size

            path_str = str(path)
            if path_str not in self._last_mtimes:
                self._last_mtimes[path_str] = mtime
                return FileEvent(
                    path=path_str,
                    event_type=EventType.CREATED,
                    size=size,
                    is_directory=path.is_dir(),
                )

            if mtime > self._last_mtimes[path_str]:
                self._last_mtimes[path_str] = mtime
                return FileEvent(
                    path=path_str,
                    event_type=EventType.MODIFIED,
                    size=size,
                    is_directory=path.is_dir(),
                )

        except Exception:
            pass
        return None

    def _scan_directory(self, directory: Path) -> Set[str]:
        files = set()
        try:
            if self.recursive:
                for item in directory.rglob("*"):
                    files.add(str(item))
            else:
                for item in directory.iterdir():
                    files.add(str(item))
        except Exception:
            pass
        return files

    def _watch_loop(self):
        while not self._stop_event.is_set():
            current_files = self._scan_directory(self.path)

            for file_path in list(self._last_mtimes.keys()):
                if file_path not in current_files and Path(file_path).exists() is False:
                    event = FileEvent(path=file_path, event_type=EventType.DELETED)
                    self._trigger_callbacks(event)
                    del self._last_mtimes[file_path]

            for file_path in current_files:
                path = Path(file_path)
                event = self._check_file(path)
                if event:
                    self._trigger_callbacks(event)

            time.sleep(1.0)

    def _trigger_callbacks(self, event: FileEvent):
        with self._callbacks_lock:
            for callback in self._callbacks:
                try:
                    callback(event)
                except Exception:
                    pass

    def start(self):
        if self._running:
            return
        self._running = True
        self._stop_event.clear()

        for item in self._scan_directory(self.path):
            try:
                self._last_mtimes[item] = Path(item).stat().st_mtime
            except Exception:
                pass

        self._thread = threading.Thread(target=self._watch_loop, daemon=True)
        self._thread.start()

    def stop(self):
        self._running = False
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=5.0)

    def on_change(self, callback: Callable[[FileEvent], None]):
        with self._callbacks_lock:
            self._callbacks.append(callback)

    def get_tracked_files(self) -> List[str]:
        return list(self._last_mtimes.keys())


class DirectoryMonitor:
    def __init__(self):
        self.watchers: Dict[str, FileWatcher] = {}
        self.event_history: List[FileEvent] = []
        self.max_history = 1000

    def watch(self, path: str, recursive: bool = True) -> str:
        path = str(Path(path).resolve())
        if path in self.watchers:
            return path

        watcher = FileWatcher(path, recursive)
        watcher.start()
        watcher.on_change(self._record_event)
        self.watchers[path] = watcher
        return path

    def unwatch(self, path: str):
        path = str(Path(path).resolve())
        if path in self.watchers:
            self.watchers[path].stop()
            del self.watchers[path]

    def _record_event(self, event: FileEvent):
        self.event_history.append(event)
        if len(self.event_history) > self.max_history:
            self.event_history = self.event_history[-self.max_history:]

    def get_events(self, path: Optional[str] = None, event_type: Optional[EventType] = None, since: Optional[float] = None) -> List[FileEvent]:
        events = self.event_history
        if path:
            events = [e for e in events if path in e.path]
        if event_type:
            events = [e for e in events if e.event_type == event_type]
        if since:
            events = [e for e in events if e.timestamp >= since]
        return events

    def get_stats(self) -> Dict[str, Any]:
        return {
            "watched_paths": list(self.watchers.keys()),
            "total_events": len(self.event_history),
            "tracked_files": sum(len(w.get_tracked_files()) for w in self.watchers.values()),
            "events_by_type": {
                etype.value: sum(1 for e in self.event_history if e.event_type.value == etype.value)
                for etype in EventType
            },
        }

    def stop_all(self):
        for watcher in self.watchers.values():
            watcher.stop()
        self.watchers.clear()


class WatcherCallback:
    def __init__(self, on_event: Optional[Callable] = None):
        self.events: List[FileEvent] = []
        self.on_event = on_event

    def __call__(self, event: FileEvent):
        self.events.append(event)
        if self.on_event:
            self.on_event(event)

    def get_events(self, event_type: Optional[EventType] = None) -> List[FileEvent]:
        if event_type:
            return [e for e in self.events if e.event_type == event_type]
        return self.events

    def clear(self):
        self.events.clear()


def create_watcher(path: str, recursive: bool = True) -> FileWatcher:
    return FileWatcher(path, recursive)


def create_monitor() -> DirectoryMonitor:
    return DirectoryMonitor()
