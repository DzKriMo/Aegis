from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Union
from enum import Enum


class ContextType(Enum):
    USER_MESSAGE = "user_message"
    ASSISTANT_RESPONSE = "assistant_response"
    TOOL_CALL = "tool_call"
    TOOL_RESULT = "tool_result"
    SYSTEM = "system"
    MEMORY = "memory"
    TASK = "task"
    ERROR = "error"


@dataclass
class ContextItem:
    id: str
    type: ContextType
    content: str
    metadata: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)
    importance: float = 1.0
    expires_at: Optional[float] = None
    tags: List[str] = field(default_factory=list)

    def is_expired(self) -> bool:
        if self.expires_at is None:
            return False
        return time.time() > self.expires_at

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "type": self.type.value,
            "content": self.content,
            "metadata": self.metadata,
            "timestamp": self.timestamp,
            "importance": self.importance,
            "tags": self.tags,
        }


class ContextManager:
    def __init__(
        self,
        max_items: int = 1000,
        default_ttl: float = 3600,
        auto_summarize: bool = True,
        summary_threshold: int = 100,
    ):
        self.max_items = max_items
        self.default_ttl = default_ttl
        self.auto_summarize = auto_summarize
        self.summary_threshold = summary_threshold
        self.items: Dict[str, ContextItem] = {}
        self.sessions: Dict[str, List[str]] = {}
        self.current_session: Optional[str] = None
        self.pinned_items: Set[str] = set()

    def _generate_id(self) -> str:
        return str(uuid.uuid4())[:12]

    def add(
        self,
        content: str,
        type: ContextType,
        metadata: Optional[Dict[str, Any]] = None,
        importance: float = 1.0,
        ttl: Optional[float] = None,
        tags: Optional[List[str]] = None,
        session: Optional[str] = None,
    ) -> str:
        item_id = self._generate_id()
        item = ContextItem(
            id=item_id,
            type=type,
            content=content,
            metadata=metadata or {},
            importance=importance,
            expires_at=time.time() + (ttl or self.default_ttl) if ttl or self.default_ttl > 0 else None,
            tags=tags or [],
        )
        self.items[item_id] = item

        if session or self.current_session:
            sess = session or self.current_session
            if sess not in self.sessions:
                self.sessions[sess] = []
            self.sessions[sess].append(item_id)

        self._cleanup_expired()
        self._enforce_max_items()

        return item_id

    def get(self, item_id: str) -> Optional[ContextItem]:
        item = self.items.get(item_id)
        if item and not item.is_expired():
            return item
        if item:
            del self.items[item_id]
        return None

    def update(self, item_id: str, content: Optional[str] = None, metadata: Optional[Dict[str, Any]] = None) -> bool:
        item = self.items.get(item_id)
        if not item:
            return False
        if content is not None:
            item.content = content
        if metadata is not None:
            item.metadata.update(metadata)
        return True

    def delete(self, item_id: str) -> bool:
        if item_id in self.items:
            del self.items[item_id]
            return True
        return False

    def pin(self, item_id: str) -> bool:
        if item_id in self.items:
            self.pinned_items.add(item_id)
            return True
        return False

    def unpin(self, item_id: str) -> bool:
        if item_id in self.pinned_items:
            self.pinned_items.discard(item_id)
            return True
        return False

    def get_recent(self, limit: int = 50, session: Optional[str] = None) -> List[ContextItem]:
        if session and session in self.sessions:
            ids = self.sessions[session][-limit:]
            return [self.items[i] for i in ids if i in self.items and not self.items[i].is_expired()]

        items = sorted(self.items.values(), key=lambda x: x.timestamp, reverse=True)
        return [i for i in items[:limit] if not i.is_expired()]

    def search(
        self,
        query: str,
        types: Optional[List[ContextType]] = None,
        tags: Optional[List[str]] = None,
        min_importance: float = 0.0,
        limit: int = 20,
    ) -> List[ContextItem]:
        results = []
        query_lower = query.lower()

        for item in self.items.values():
            if item.is_expired():
                continue
            if item.importance < min_importance:
                continue
            if types and item.type not in types:
                continue
            if tags and not any(tag in item.tags for tag in tags):
                continue
            if query_lower in item.content.lower():
                results.append(item)

        results.sort(key=lambda x: (x.importance, x.timestamp), reverse=True)
        return results[:limit]

    def get_context_window(self, before: Optional[str] = None, after: Optional[str] = None, limit: int = 20) -> List[ContextItem]:
        items = self.get_recent(limit=self.max_items)
        if not before and not after:
            return items[-limit:]

        if before:
            before_idx = next((i for i, item in enumerate(items) if item.id == before), -1)
            if before_idx > 0:
                return items[max(0, before_idx - limit):before_idx]

        if after:
            after_idx = next((i for i, item in enumerate(items) if item.id == after), len(items))
            if after_idx < len(items):
                return items[after_idx + 1:min(len(items), after_idx + 1 + limit)]

        return []

    def build_context_string(self, max_tokens: int = 2000, include_types: Optional[List[ContextType]] = None) -> str:
        recent = self.get_recent(limit=self.max_items)
        if include_types:
            recent = [i for i in recent if i.type in include_types]

        context_parts = []
        current_tokens = 0

        for item in reversed(recent):
            item_text = f"[{item.type.value}] {item.content}"
            item_tokens = len(item_text) // 4

            if current_tokens + item_tokens > max_tokens:
                break

            context_parts.append(item_text)
            current_tokens += item_tokens

        return "\n".join(reversed(context_parts))

    def summarize(self, items: Optional[List[ContextItem]] = None) -> str:
        if not items:
            items = self.get_recent(limit=self.summary_threshold)

        summary_parts = []
        for item in items:
            if item.type == ContextType.TOOL_CALL:
                summary_parts.append(f"Used tool: {item.metadata.get('tool_name', 'unknown')}")
            elif item.type == ContextType.ERROR:
                summary_parts.append(f"Error occurred: {item.content[:100]}")

        return "; ".join(summary_parts) if summary_parts else "No significant events"

    def _cleanup_expired(self):
        expired = [iid for iid, item in self.items.items() if item.is_expired()]
        for iid in expired:
            del self.items[iid]

    def _enforce_max_items(self):
        if len(self.items) <= self.max_items:
            return

        unpinned = [(iid, item) for iid, item in self.items.items() if iid not in self.pinned_items]
        unpinned.sort(key=lambda x: (x[1].importance, x[1].timestamp))

        to_remove = len(self.items) - self.max_items
        for iid, _ in unpinned[:to_remove]:
            del self.items[iid]

    def create_session(self) -> str:
        session_id = self._generate_id()
        self.sessions[session_id] = []
        self.current_session = session_id
        return session_id

    def switch_session(self, session_id: str) -> bool:
        if session_id in self.sessions:
            self.current_session = session_id
            return True
        return False

    def get_stats(self) -> Dict[str, Any]:
        self._cleanup_expired()
        return {
            "total_items": len(self.items),
            "pinned_items": len(self.pinned_items),
            "sessions": len(self.sessions),
            "current_session": self.current_session,
            "by_type": {
                t.value: sum(1 for i in self.items.values() if i.type == t)
                for t in ContextType
            },
        }

    def export(self) -> str:
        return json.dumps({
            "items": [i.to_dict() for i in self.items.values()],
            "pinned": list(self.pinned_items),
            "sessions": self.sessions,
        }, indent=2)

    def import_data(self, data: str) -> bool:
        try:
            parsed = json.loads(data)
            self.items = {
                i["id"]: ContextItem(
                    id=i["id"],
                    type=ContextType(i["type"]),
                    content=i["content"],
                    metadata=i.get("metadata", {}),
                    timestamp=i.get("timestamp", time.time()),
                    importance=i.get("importance", 1.0),
                    tags=i.get("tags", []),
                )
                for i in parsed.get("items", [])
            }
            self.pinned_items = set(parsed.get("pinned", []))
            self.sessions = parsed.get("sessions", {})
            return True
        except Exception:
            return False


from typing import Set
