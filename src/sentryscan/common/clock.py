"""Injectable clock abstraction for reproducible time and freshness validation."""

from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Protocol


class Clock(Protocol):
    """Protocol for time retrieval and timing operations."""

    def now_utc(self) -> datetime:
        """Return current datetime in UTC timezone."""
        ...

    def now_iso(self) -> str:
        """Return current UTC time formatted as an ISO-8601 string."""
        ...

    def sleep(self, seconds: float) -> None:
        """Wait for the specified number of seconds."""
        ...


class SystemClock:
    """Standard system clock relying on actual wall-clock time."""

    def now_utc(self) -> datetime:
        return datetime.now(timezone.utc)

    def now_iso(self) -> str:
        return self.now_utc().isoformat().replace("+00:00", "Z")

    def sleep(self, seconds: float) -> None:
        time.sleep(seconds)


class FakeClock:
    """Deterministic, injectable mock clock for tests and repeatable simulations."""

    def __init__(self, initial_iso: str = "2026-10-21T00:00:00Z") -> None:
        clean_iso = initial_iso.replace("Z", "+00:00")
        self._current_time = datetime.fromisoformat(clean_iso).astimezone(timezone.utc)

    def now_utc(self) -> datetime:
        return self._current_time

    def now_iso(self) -> str:
        return self._current_time.isoformat().replace("+00:00", "Z")

    def advance(self, seconds: float) -> None:
        """Advance the simulated virtual clock without sleeping."""
        from datetime import timedelta
        self._current_time += timedelta(seconds=seconds)

    def sleep(self, seconds: float) -> None:
        """Simulate sleep by advancing virtual clock instantaneously."""
        self.advance(seconds)
