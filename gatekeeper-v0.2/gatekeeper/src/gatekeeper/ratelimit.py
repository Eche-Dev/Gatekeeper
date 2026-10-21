from __future__ import annotations

import time
from collections import deque
from collections.abc import Callable


class RateLimiter:
    """Ventana deslizante en memoria, por clave (IP). Un proceso, sin Redis."""

    def __init__(
        self,
        limit: int,
        window: float,
        clock: Callable[[], float] = time.monotonic,
        prune_interval: int = 1000,
    ):
        self.limit = limit
        self.window = window
        self.clock = clock
        self.prune_interval = prune_interval
        self._calls = 0
        self._hits: dict[str, deque[float]] = {}

    def _prune(self, now: float) -> None:
        stale = [k for k, q in self._hits.items() if not q or now - q[-1] >= self.window]
        for key in stale:
            del self._hits[key]

    def allow(self, key: str) -> bool:
        now = self.clock()
        self._calls += 1
        if self._calls % self.prune_interval == 0:
            self._prune(now)  # evita crecimiento sin límite con muchas IPs distintas
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
