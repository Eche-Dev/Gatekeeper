from __future__ import annotations

import time
from collections import deque
from collections.abc import Callable


class RateLimiter:
    """Ventana deslizante en memoria, por clave (IP). Un proceso, sin Redis (v0.1)."""

    def __init__(self, limit: int, window: float, clock: Callable[[], float] = time.monotonic):
        self.limit = limit
        self.window = window
        self.clock = clock
        self._hits: dict[str, deque[float]] = {}

    def allow(self, key: str) -> bool:
        now = self.clock()
        q = self._hits.setdefault(key, deque())
        while q and now - q[0] >= self.window:
            q.popleft()
        if len(q) >= self.limit:
            return False
        q.append(now)
        return True

    def retry_after(self, key: str) -> int:
        q = self._hits.get(key)
        if not q:
            return 0
        return max(1, int(self.window - (self.clock() - q[0])) + 1)
