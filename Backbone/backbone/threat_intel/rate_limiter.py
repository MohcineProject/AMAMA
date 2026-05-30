"""Async sliding-window rate limiter."""

from __future__ import annotations

import asyncio
import time
from collections import deque


class RateLimiter:
    """Tracks call timestamps in a 60-second sliding window; blocks callers when the limit is reached."""

    def __init__(self, calls_per_minute: int) -> None:
        self._limit = calls_per_minute
        self._timestamps: deque[float] = deque()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        async with self._lock:
            now = time.monotonic()
            while self._timestamps and now - self._timestamps[0] >= 60.0:
                self._timestamps.popleft()

            if len(self._timestamps) >= self._limit:
                wait_secs = 60.0 - (now - self._timestamps[0]) + 0.05
                if wait_secs > 0:
                    await asyncio.sleep(wait_secs)
                now = time.monotonic()
                while self._timestamps and now - self._timestamps[0] >= 60.0:
                    self._timestamps.popleft()

            self._timestamps.append(time.monotonic())
