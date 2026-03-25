from __future__ import annotations

import json
import hashlib
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
from pathlib import Path
import sqlite3
import struct
import math


@dataclass
class MemoryEntry:
    id: str
    content: str
    metadata: Dict[str, Any]
    embedding: Optional[List[float]] = None
    created_at: float = field(default_factory=time.time)
    access_count: int = 0
    last_accessed: float = field(default_factory=time.time)
    memory_type: str = "general"
    tags: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "content": self.content,
            "metadata": self.metadata,
            "created_at": self.created_at,
            "access_count": self.access_count,
            "last_accessed": self.last_accessed,
            "memory_type": self.memory_type,
            "tags": self.tags,
        }


class SimpleVectorDB:
    def __init__(self, db_path: str = ":memory:"):
        self.db_path = db_path
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self._init_db()

    def _init_db(self) -> None:
        cursor = self.conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS memories (
                id TEXT PRIMARY KEY,
                content TEXT NOT NULL,
                metadata TEXT,
                memory_type TEXT DEFAULT 'general',
                tags TEXT,
                created_at REAL,
                access_count INTEGER DEFAULT 0,
                last_accessed REAL,
                vector BLOB
            )
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_memory_type ON memories(memory_type)
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_created_at ON memories(created_at)
        """)
        self.conn.commit()

    def insert(self, entry: MemoryEntry) -> bool:
        try:
            cursor = self.conn.cursor()
            vector_blob = self._encode_vector(entry.embedding) if entry.embedding else None
            cursor.execute(
                """
                INSERT OR REPLACE INTO memories 
                (id, content, metadata, memory_type, tags, created_at, access_count, last_accessed, vector)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    entry.id,
                    entry.content,
                    json.dumps(entry.metadata),
                    entry.memory_type,
                    json.dumps(entry.tags),
                    entry.created_at,
                    entry.access_count,
                    entry.last_accessed,
                    vector_blob,
                ),
            )
            self.conn.commit()
            return True
        except Exception:
            return False

    def search(
        self,
        query: Optional[List[float]] = None,
        query_text: Optional[str] = None,
        memory_type: Optional[str] = None,
        tags: Optional[List[str]] = None,
        limit: int = 10,
        offset: int = 0,
    ) -> List[MemoryEntry]:
        cursor = self.conn.cursor()

        sql = "SELECT id, content, metadata, memory_type, tags, created_at, access_count, last_accessed FROM memories WHERE 1=1"
        params: List[Any] = []

        if memory_type:
            sql += " AND memory_type = ?"
            params.append(memory_type)

        if tags:
            for tag in tags:
                sql += " AND tags LIKE ?"
                params.append(f"%{tag}%")

        if query_text:
            sql += " AND content LIKE ?"
            params.append(f"%{query_text}%")

        sql += " ORDER BY access_count DESC, last_accessed DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        cursor.execute(sql, params)
        rows = cursor.fetchall()

        entries = []
        for row in rows:
            entries.append(MemoryEntry(
                id=row[0],
                content=row[1],
                metadata=json.loads(row[2]) if row[2] else {},
                memory_type=row[3],
                tags=json.loads(row[4]) if row[4] else [],
                created_at=row[5],
                access_count=row[6],
                last_accessed=row[7],
            ))

        return entries

    def get(self, memory_id: str) -> Optional[MemoryEntry]:
        cursor = self.conn.cursor()
        cursor.execute(
            "SELECT id, content, metadata, memory_type, tags, created_at, access_count, last_accessed FROM memories WHERE id = ?",
            (memory_id,),
        )
        row = cursor.fetchone()
        if row:
            return MemoryEntry(
                id=row[0],
                content=row[1],
                metadata=json.loads(row[2]) if row[2] else {},
                memory_type=row[3],
                tags=json.loads(row[4]) if row[4] else [],
                created_at=row[5],
                access_count=row[6],
                last_accessed=row[7],
            )
        return None

    def update_access(self, memory_id: str) -> None:
        cursor = self.conn.cursor()
        cursor.execute(
            "UPDATE memories SET access_count = access_count + 1, last_accessed = ? WHERE id = ?",
            (time.time(), memory_id),
        )
        self.conn.commit()

    def delete(self, memory_id: str) -> bool:
        try:
            cursor = self.conn.cursor()
            cursor.execute("DELETE FROM memories WHERE id = ?", (memory_id,))
            self.conn.commit()
            return cursor.rowcount > 0
        except Exception:
            return False

    def count(self, memory_type: Optional[str] = None) -> int:
        cursor = self.conn.cursor()
        if memory_type:
            cursor.execute("SELECT COUNT(*) FROM memories WHERE memory_type = ?", (memory_type,))
        else:
            cursor.execute("SELECT COUNT(*) FROM memories")
        return cursor.fetchone()[0]

    def clear(self, memory_type: Optional[str] = None) -> int:
        cursor = self.conn.cursor()
        if memory_type:
            cursor.execute("DELETE FROM memories WHERE memory_type = ?", (memory_type,))
        else:
            cursor.execute("DELETE FROM memories")
        self.conn.commit()
        return cursor.rowcount

    def _encode_vector(self, vector: List[float]) -> bytes:
        return struct.pack(f"{len(vector)}d", *vector)

    def _decode_vector(self, blob: bytes) -> List[float]:
        num_floats = len(blob) // 8
        return list(struct.unpack(f"{num_floats}d", blob))

    def close(self) -> None:
        self.conn.close()


class SemanticMemory:
    DIMENSION = 384

    def __init__(self, db_path: str = "memory.db"):
        self.db = SimpleVectorDB(db_path)
        self._initialized = False

    def _get_embedding(self, text: str) -> List[float]:
        import hashlib
        seed = int(hashlib.md5(text.encode()).hexdigest()[:8], 16)
        import random
        random.seed(seed)
        vec = [random.gauss(0, 1) for _ in range(self.DIMENSION)]
        norm = math.sqrt(sum(x * x for x in vec))
        return [x / norm for x in vec]

    def add(
        self,
        content: str,
        metadata: Optional[Dict[str, Any]] = None,
        memory_type: str = "general",
        tags: Optional[List[str]] = None,
    ) -> str:
        memory_id = hashlib.md5(f"{content}{time.time()}".encode()).hexdigest()[:16]
        embedding = self._get_embedding(content)

        entry = MemoryEntry(
            id=memory_id,
            content=content,
            metadata=metadata or {},
            embedding=embedding,
            memory_type=memory_type,
            tags=tags or [],
        )
        self.db.insert(entry)
        return memory_id

    def search(
        self,
        query: str,
        memory_type: Optional[str] = None,
        tags: Optional[List[str]] = None,
        limit: int = 5,
    ) -> List[MemoryEntry]:
        return self.db.search(
            query_text=query,
            memory_type=memory_type,
            tags=tags,
            limit=limit,
        )

    def recall(self, memory_id: str) -> Optional[MemoryEntry]:
        entry = self.db.get(memory_id)
        if entry:
            self.db.update_access(memory_id)
        return entry

    def forget(self, memory_id: str) -> bool:
        return self.db.delete(memory_id)

    def get_recent(self, memory_type: Optional[str] = None, limit: int = 10) -> List[MemoryEntry]:
        return self.db.search(memory_type=memory_type, limit=limit)

    def get_stats(self) -> Dict[str, Any]:
        return {
            "total_memories": self.db.count(),
            "by_type": {
                "general": self.db.count("general"),
                "fact": self.db.count("fact"),
                "preference": self.db.count("preference"),
                "knowledge": self.db.count("knowledge"),
            },
        }


class PersistentAgentMemory:
    def __init__(self, db_path: str = "agent_memory.db"):
        self.vector_db = SimpleVectorDB(db_path)
        self.semantic = SemanticMemory(db_path)
        self.conversation_history: List[Dict[str, Any]] = []
        self.max_history = 100

    def remember(
        self,
        content: str,
        memory_type: str = "general",
        tags: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> str:
        return self.semantic.add(
            content=content,
            memory_type=memory_type,
            tags=tags,
            metadata=metadata,
        )

    def recall(
        self,
        query: str,
        memory_type: Optional[str] = None,
        limit: int = 5,
    ) -> List[str]:
        entries = self.semantic.search(query, memory_type=memory_type, limit=limit)
        return [e.content for e in entries]

    def remember_fact(self, fact: str, source: Optional[str] = None) -> str:
        return self.remember(fact, memory_type="fact", tags=["fact"], metadata={"source": source})

    def remember_preference(self, preference: str, context: Optional[str] = None) -> str:
        return self.remember(
            preference,
            memory_type="preference",
            tags=["preference"],
            metadata={"context": context},
        )

    def remember_knowledge(self, knowledge: str, domain: Optional[str] = None) -> str:
        return self.remember(
            knowledge,
            memory_type="knowledge",
            tags=["knowledge", domain] if domain else ["knowledge"],
        )

    def add_conversation(
        self,
        role: str,
        content: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.conversation_history.append({
            "role": role,
            "content": content,
            "timestamp": time.time(),
            "metadata": metadata or {},
        })
        if len(self.conversation_history) > self.max_history:
            self.conversation_history = self.conversation_history[-self.max_history :]

    def get_conversation_context(self, last_n: int = 10) -> str:
        recent = self.conversation_history[-last_n:]
        return "\n".join(f"{msg['role']}: {msg['content']}" for msg in recent)

    def get_all_context(self, query: Optional[str] = None) -> str:
        parts = []

        if self.conversation_history:
            parts.append("Recent conversation:")
            parts.append(self.get_conversation_context(10))

        if query:
            memories = self.semantic.search(query, limit=5)
            if memories:
                parts.append("Relevant memories:")
                parts.extend(f"- {m.content}" for m in memories)

        return "\n\n".join(parts) if parts else ""

    def get_memories_by_type(self, memory_type: str, limit: int = 20) -> List[MemoryEntry]:
        return self.semantic.get_recent(memory_type=memory_type, limit=limit)

    def clear_memory(self, memory_type: Optional[str] = None) -> int:
        if memory_type:
            return self.vector_db.clear(memory_type)
        self.conversation_history.clear()
        return self.vector_db.clear()

    def get_stats(self) -> Dict[str, Any]:
        return {
            "vector_db": self.semantic.get_stats(),
            "conversation_history_size": len(self.conversation_history),
        }
