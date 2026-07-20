import json
import os
import sqlite3
import threading
import time
from typing import Any, Dict, Optional, Tuple


class MemoryCache:
    """Thread-safe L1 Memory Cache with TTL support."""

    def __init__(self, default_ttl: int = 86400):
        self.default_ttl = default_ttl
        self._cache: Dict[str, Tuple[float, Any]] = {}
        self._lock = threading.RLock()

    def get(self, key: str) -> Optional[Any]:
        with self._lock:
            if key not in self._cache:
                return None
            expiry, value = self._cache[key]
            if time.time() > expiry:
                del self._cache[key]
                return None
            return value

    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> None:
        effective_ttl = ttl if ttl is not None else self.default_ttl
        expiry = time.time() + effective_ttl
        with self._lock:
            self._cache[key] = (expiry, value)

    def invalidate(self, key: str) -> bool:
        with self._lock:
            if key in self._cache:
                del self._cache[key]
                return True
            return False

    def clear(self) -> None:
        with self._lock:
            self._cache.clear()

    def purge_expired(self) -> int:
        now = time.time()
        count = 0
        with self._lock:
            expired_keys = [k for k, (exp, _) in self._cache.items() if now > exp]
            for k in expired_keys:
                del self._cache[k]
                count += 1
        return count


class PersistentCache:
    """SQLite-backed L2 Persistent Cache with TTL and provider key isolation."""

    def __init__(self, db_path: str = "./cache/threat_intel/cache.db", default_ttl: int = 86400):
        self.db_path = db_path
        self.default_ttl = default_ttl
        self._lock = threading.RLock()

        os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10.0)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._lock, self._get_connection() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS cache_store (
                    cache_key TEXT PRIMARY KEY,
                    provider TEXT NOT NULL,
                    ioc_type TEXT NOT NULL,
                    ioc_value TEXT NOT NULL,
                    value_json TEXT NOT NULL,
                    is_negative INTEGER DEFAULT 0,
                    created_at REAL NOT NULL,
                    expires_at REAL NOT NULL
                )
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_expires_at ON cache_store(expires_at)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_provider_ioc ON cache_store(provider, ioc_type, ioc_value)")
            conn.commit()

    def get(self, key: str) -> Optional[Any]:
        now = time.time()
        with self._lock, self._get_connection() as conn:
            cursor = conn.execute(
                "SELECT value_json, expires_at FROM cache_store WHERE cache_key = ?",
                (key,),
            )
            row = cursor.fetchone()
            if not row:
                return None

            expires_at = row["expires_at"]
            if now > expires_at:
                conn.execute("DELETE FROM cache_store WHERE cache_key = ?", (key,))
                conn.commit()
                return None

            try:
                return json.loads(row["value_json"])
            except Exception:
                return None

    def set(
        self,
        key: str,
        value: Any,
        provider: str = "general",
        ioc_type: str = "generic",
        ioc_value: str = "",
        is_negative: bool = False,
        ttl: Optional[int] = None,
    ) -> None:
        effective_ttl = ttl if ttl is not None else self.default_ttl
        now = time.time()
        expires_at = now + effective_ttl
        value_json = json.dumps(value)

        with self._lock, self._get_connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO cache_store
                (cache_key, provider, ioc_type, ioc_value, value_json, is_negative, created_at, expires_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    key,
                    provider,
                    ioc_type,
                    ioc_value,
                    value_json,
                    1 if is_negative else 0,
                    now,
                    expires_at,
                ),
            )
            conn.commit()

    def invalidate(self, key: str) -> bool:
        with self._lock, self._get_connection() as conn:
            cursor = conn.execute("DELETE FROM cache_store WHERE cache_key = ?", (key,))
            conn.commit()
            return cursor.rowcount > 0

    def invalidate_provider(self, provider: str) -> int:
        with self._lock, self._get_connection() as conn:
            cursor = conn.execute("DELETE FROM cache_store WHERE provider = ?", (provider,))
            conn.commit()
            return cursor.rowcount

    def clear(self) -> None:
        with self._lock, self._get_connection() as conn:
            conn.execute("DELETE FROM cache_store")
            conn.commit()

    def purge_expired(self) -> int:
        now = time.time()
        with self._lock, self._get_connection() as conn:
            cursor = conn.execute("DELETE FROM cache_store WHERE expires_at < ?", (now,))
            conn.commit()
            return cursor.rowcount


class ThreatIntelCache:
    """Unified Two-Tier Threat Intelligence Cache with Negative Caching & Isolation."""

    def __init__(self, db_path: str = "./cache/threat_intel/cache.db", default_ttl: int = 86400, negative_ttl: int = 3600):
        self.memory_cache = MemoryCache(default_ttl=default_ttl)
        self.persistent_cache = PersistentCache(db_path=db_path, default_ttl=default_ttl)
        self.negative_ttl = negative_ttl
        self.hits = 0
        self.misses = 0

    @staticmethod
    def build_cache_key(provider: str, ioc_type: str, ioc_value: str) -> str:
        """Isolated key format: provider:ioc_type:ioc_value"""
        clean_provider = provider.strip().lower()
        clean_type = ioc_type.strip().lower()
        clean_val = ioc_value.strip().lower()
        return f"{clean_provider}:{clean_type}:{clean_val}"

    def get(self, provider: str, ioc_type: str, ioc_value: str) -> Optional[Any]:
        key = self.build_cache_key(provider, ioc_type, ioc_value)

        # L1 Memory check
        val = self.memory_cache.get(key)
        if val is not None:
            self.hits += 1
            return val

        # L2 Persistent check
        val = self.persistent_cache.get(key)
        if val is not None:
            # Promote to L1
            self.memory_cache.set(key, val)
            self.hits += 1
            return val

        self.misses += 1
        return None

    def set(
        self,
        provider: str,
        ioc_type: str,
        ioc_value: str,
        value: Any,
        is_negative: bool = False,
        ttl: Optional[int] = None,
    ) -> None:
        key = self.build_cache_key(provider, ioc_type, ioc_value)
        effective_ttl = self.negative_ttl if is_negative and ttl is None else ttl

        self.memory_cache.set(key, value, ttl=effective_ttl)
        self.persistent_cache.set(
            key=key,
            value=value,
            provider=provider,
            ioc_type=ioc_type,
            ioc_value=ioc_value,
            is_negative=is_negative,
            ttl=effective_ttl,
        )

    def invalidate(self, provider: str, ioc_type: str, ioc_value: str) -> bool:
        key = self.build_cache_key(provider, ioc_type, ioc_value)
        mem_res = self.memory_cache.invalidate(key)
        db_res = self.persistent_cache.invalidate(key)
        return mem_res or db_res

    def clear(self) -> None:
        self.memory_cache.clear()
        self.persistent_cache.clear()

    def hit_ratio(self) -> float:
        total = self.hits + self.misses
        return (self.hits / total) if total > 0 else 0.0
