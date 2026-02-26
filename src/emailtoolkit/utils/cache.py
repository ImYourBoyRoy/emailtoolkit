# ./src/emailtoolkit/utils/cache.py
"""Simple TTL cache utility used by DNS helper lookups.

Run path: imported by ``emailtoolkit.utils.dns`` only.
Inputs: string keys and arbitrary serializable/runtime values.
Outputs: cached values until TTL expiry, else ``None``.
Side effects: in-memory mutable store only.
Operational notes: process-local cache, not shared across workers or restarts.
"""

from __future__ import annotations

import time
from typing import Any, Dict, Optional, Tuple


class TTLCache:
    """Lightweight cache with per-entry time-to-live semantics."""

    def __init__(self, ttl_seconds: int):
        self.ttl = ttl_seconds
        self._store: Dict[str, Tuple[float, Any]] = {}

    def get(self, key: str) -> Optional[Any]:
        now = time.time()
        item = self._store.get(key)
        if not item:
            return None

        created_at, value = item
        if now - created_at > self.ttl:
            self._store.pop(key, None)
            return None

        return value

    def set(self, key: str, value: Any) -> None:
        self._store[key] = (time.time(), value)

    def clear(self) -> None:
        self._store.clear()
