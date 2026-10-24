"""Request scheduling: inter-request delay, global + per-host budgets, and
polite back-off on HTTP 429 / Retry-After.

This is a small, deterministic helper (clock and sleeper are injectable so it
is unit-testable without real time). It never rotates identity or otherwise
tries to evade a server's throttling — on 429 it waits and respects
`Retry-After`.
"""

from __future__ import annotations

import time
from email.utils import parsedate_to_datetime
from datetime import datetime, timezone


def parse_retry_after(value: str | None, now: datetime | None = None) -> float | None:
    """Parse a Retry-After header (delta-seconds or HTTP-date) to seconds.

    Returns None when absent/unparseable, and never a negative number.
    """
    if not value:
        return None
    value = value.strip()
    if value.isdigit():
        return float(value)
    try:
        when = parsedate_to_datetime(value)
    except (TypeError, ValueError):
        return None
    if when is None:
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    ref = now or datetime.now(timezone.utc)
    return max(0.0, (when - ref).total_seconds())


class BudgetExceeded(Exception):
    def __init__(self, scope: str, host: str = ""):
        super().__init__(f"{scope} request budget exceeded")
        self.scope = scope
        self.host = host


class RequestScheduler:
    def __init__(
        self,
        min_delay: float = 0.0,
        global_max: int | None = None,
        per_host_max: int | None = None,
        respect_retry_after: bool = True,
        retry_after_cap: float = 30.0,
        sleeper=time.sleep,
        clock=time.monotonic,
    ) -> None:
        self.min_delay = max(0.0, min_delay)
        self.global_max = global_max
        self.per_host_max = per_host_max
        self.respect_retry_after = respect_retry_after
        self.retry_after_cap = retry_after_cap
        self._sleep = sleeper
        self._clock = clock
        self.total = 0
        self.host_counts: dict[str, int] = {}
        self._last = None  # time of last acquire
        self._paused_until = 0.0

    # ------------------------------------------------------------- budgets
    def check_budget(self, host: str) -> tuple[bool, str]:
        if self.global_max is not None and self.total >= self.global_max:
            return False, "global budget exceeded"
        if self.per_host_max is not None and self.host_counts.get(host, 0) >= self.per_host_max:
            return False, f"per-host budget exceeded for {host}"
        return True, "ok"

    # --------------------------------------------------------- before send
    def acquire(self, host: str) -> None:
        """Honour any pending back-off and the inter-request delay, then count."""
        now = self._clock()
        if self._paused_until > now:
            self._sleep(self._paused_until - now)
        if self.min_delay > 0 and self._last is not None:
            elapsed = self._clock() - self._last
            wait = self.min_delay - elapsed
            if wait > 0:
                self._sleep(wait)
        self._last = self._clock()
        self.total += 1
        self.host_counts[host] = self.host_counts.get(host, 0) + 1

    # ---------------------------------------------------------- after recv
    def on_response(self, status: int, headers: dict[str, str]) -> float:
        """On 429, wait for Retry-After (bounded) and arm a pause. Returns the
        number of seconds waited (0.0 if nothing to do)."""
        if not (self.respect_retry_after and status == 429):
            return 0.0
        ra = parse_retry_after(headers.get("retry-after"))
        delay = ra if ra is not None else max(self.min_delay, 1.0)
        delay = min(delay, self.retry_after_cap)
        self._paused_until = self._clock() + delay
        self._sleep(delay)
        return delay
