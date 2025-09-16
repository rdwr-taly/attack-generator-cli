from __future__ import annotations

import random
import time
from typing import Optional, Tuple

from anyio import Lock, sleep


class AsyncRateLimiter:
    """Token bucket limiter for async workflows."""

    def __init__(self, rate: float, *, burst: Optional[int] = None) -> None:
        if rate <= 0:
            raise ValueError("rate must be > 0")
        self._rate = rate
        self._capacity = burst or 1
        self._tokens = float(self._capacity)
        self._updated = time.monotonic()
        self._lock = Lock()

    def _refill(self) -> None:
        now = time.monotonic()
        elapsed = now - self._updated
        if elapsed <= 0:
            return
        self._updated = now
        self._tokens = min(self._capacity, self._tokens + elapsed * self._rate)

    async def acquire(self) -> None:
        while True:
            async with self._lock:
                self._refill()
                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    return
                needed = (1.0 - self._tokens) / self._rate
            await sleep(max(needed, 0.0))


def compute_jitter(bounds: Optional[Tuple[int, int]], *, rng: random.Random) -> float:
    """Return jitter in seconds from millisecond bounds."""

    if not bounds:
        return 0.0
    low, high = bounds
    if low == high:
        return low / 1000.0
    return rng.uniform(low / 1000.0, high / 1000.0)


__all__ = ["AsyncRateLimiter", "compute_jitter"]
