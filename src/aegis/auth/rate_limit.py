from collections import defaultdict, deque
import sqlite3
import threading
import time
from typing import Optional

from ..config import settings


class MemoryRateLimiter:
    def __init__(self, limit: int, window_seconds: int):
        self.limit = limit
        self.window = window_seconds
        self.hits = defaultdict(deque)

    def allow(self, key: str) -> bool:
        now = time.time()
        q = self.hits[key]
        while q and now - q[0] > self.window:
            q.popleft()
        if len(q) >= self.limit:
            return False
        q.append(now)
        return True


class SqliteRateLimiter:
    def __init__(self, db_path: str, limit: int, window_seconds: int):
        self.db_path = db_path
        self.limit = limit
        self.window = window_seconds
        self._lock = threading.Lock()
        self._init_db()

    def _connect(self):
        return sqlite3.connect(self.db_path, timeout=5)

    def _init_db(self):
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS rate_limit_hits (
                    key TEXT NOT NULL,
                    ts REAL NOT NULL
                )
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_rate_limit_key_ts ON rate_limit_hits (key, ts)")
            conn.commit()

    def allow(self, key: str) -> bool:
        now = time.time()
        cutoff = now - self.window
        with self._lock:
            with self._connect() as conn:
                conn.execute("DELETE FROM rate_limit_hits WHERE ts < ?", (cutoff,))
                cur = conn.execute("SELECT COUNT(*) FROM rate_limit_hits WHERE key = ?", (key,))
                count = int(cur.fetchone()[0])
                if count >= self.limit:
                    conn.commit()
                    return False
                conn.execute("INSERT INTO rate_limit_hits (key, ts) VALUES (?, ?)", (key, now))
                conn.commit()
                return True


class RedisRateLimiter:
    def __init__(self, redis_url: str, limit: int, window_seconds: int, key_prefix: str = "aegis:rl"):
        self.redis_url = redis_url
        self.limit = limit
        self.window = window_seconds
        self.key_prefix = key_prefix
        self._client: Optional[object] = None
        self._init_client()

    def _init_client(self):
        try:
            import redis  # type: ignore
        except Exception as exc:
            raise RuntimeError("Redis backend requested but 'redis' package is not installed") from exc
        self._client = redis.from_url(self.redis_url, decode_responses=True)

    def allow(self, key: str) -> bool:
        if self._client is None:
            return False
        now = int(time.time())
        window_start = now - self.window
        k = f"{self.key_prefix}:{key}"
        # Sliding-window approximation with sorted set.
        pipe = self._client.pipeline()
        pipe.zremrangebyscore(k, 0, window_start)
        pipe.zadd(k, {str(now): now})
        pipe.zcard(k)
        pipe.expire(k, self.window + 5)
        _, _, count, _ = pipe.execute()
        return int(count) <= self.limit


def build_rate_limiter():
    backend = (settings.aegis_rate_limit_backend or "memory").lower()
    if backend == "redis":
        return RedisRateLimiter(
            redis_url=settings.aegis_rate_limit_redis_url,
            limit=settings.aegis_rate_limit_limit,
            window_seconds=settings.aegis_rate_limit_window_seconds,
            key_prefix=settings.aegis_rate_limit_redis_prefix,
        )
    if backend == "sqlite":
        return SqliteRateLimiter(
            db_path=settings.aegis_rate_limit_sqlite_path,
            limit=settings.aegis_rate_limit_limit,
            window_seconds=settings.aegis_rate_limit_window_seconds,
        )
    return MemoryRateLimiter(
        limit=settings.aegis_rate_limit_limit,
        window_seconds=settings.aegis_rate_limit_window_seconds,
    )


limiter = build_rate_limiter()
