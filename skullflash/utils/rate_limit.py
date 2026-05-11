"""Async token-bucket rate limiter."""
from __future__ import annotations

import asyncio
import time


class RateLimiter:
    """Token bucket rate limiter for async I/O operations.

    Args:
        calls_per_second: Maximum number of calls allowed per second.
    """

    def __init__(self, calls_per_second: float) -> None:
        self._rate = calls_per_second
        self._tokens = calls_per_second
        self._last_check = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        """Block until a token is available."""
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self._last_check
            self._last_check = now
            self._tokens = min(self._rate, self._tokens + elapsed * self._rate)
            if self._tokens < 1:
                wait = (1 - self._tokens) / self._rate
                await asyncio.sleep(wait)
                self._tokens = 0
            else:
                self._tokens -= 1
