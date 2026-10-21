"""Shared fleet statistics with thread synchronization against lost updates."""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field


@dataclass
class FleetMetricsSnapshot:
    """Immutable snapshot of fleet statistics."""

    total_records: int
    valid_records: int
    malformed_records: int
    suspect_records: int
    findings_count: int


class SharedFleetStats:
    """Thread-safe counter repository with optional lockless mode for race condition proof."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.total_records: int = 0
        self.valid_records: int = 0
        self.malformed_records: int = 0
        self.suspect_records: int = 0
        self.findings_count: int = 0
        self.per_host_counts: dict[str, int] = field(default_factory=dict)

    def record_percept_locked(
        self,
        is_valid: bool = True,
        is_suspect: bool = False,
        findings_delta: int = 0,
        host_id: str | None = None,
    ) -> None:
        """Atomically update fleet statistics under mutex lock protection."""
        with self._lock:
            self.total_records += 1
            if is_valid:
                self.valid_records += 1
            else:
                self.malformed_records += 1

            if is_suspect:
                self.suspect_records += 1

            self.findings_count += findings_delta

            if host_id:
                current = getattr(self, "per_host_counts", None) or {}
                current[host_id] = current.get(host_id, 0) + 1
                self.per_host_counts = current

    def record_percept_unlocked(self) -> None:
        """Non-atomic update without lock, vulnerable to lost updates under high concurrency."""
        # Intentionally non-atomic read-modify-write with micro-yield
        current = self.total_records
        time.sleep(0.00001)  # Context switch window
        self.total_records = current + 1

    def snapshot(self) -> FleetMetricsSnapshot:
        """Return an immutable snapshot of current statistics."""
        with self._lock:
            return FleetMetricsSnapshot(
                total_records=self.total_records,
                valid_records=self.valid_records,
                malformed_records=self.malformed_records,
                suspect_records=self.suspect_records,
                findings_count=self.findings_count,
            )

    def reset(self) -> None:
        """Reset all counters to zero."""
        with self._lock:
            self.total_records = 0
            self.valid_records = 0
            self.malformed_records = 0
            self.suspect_records = 0
            self.findings_count = 0
            self.per_host_counts = {}


def demonstrate_lost_updates(
    num_threads: int = 10,
    increments_per_thread: int = 50,
) -> tuple[int, int, int]:
    """Execute concurrent increment experiment comparing locked vs unlocked counters.

    Returns:
        (expected_total, unlocked_actual, locked_actual)
    """
    expected = num_threads * increments_per_thread

    # 1. Unlocked experiment (demonstrates lost updates)
    unlocked_stats = SharedFleetStats()

    def worker_unlocked():
        for _ in range(increments_per_thread):
            unlocked_stats.record_percept_unlocked()

    threads_unlocked = [
        threading.Thread(target=worker_unlocked) for _ in range(num_threads)
    ]
    for t in threads_unlocked:
        t.start()
    for t in threads_unlocked:
        t.join()

    unlocked_actual = unlocked_stats.total_records

    # 2. Locked experiment (demonstrates race prevention)
    locked_stats = SharedFleetStats()

    def worker_locked():
        for _ in range(increments_per_thread):
            locked_stats.record_percept_locked(is_valid=True)

    threads_locked = [
        threading.Thread(target=worker_locked) for _ in range(num_threads)
    ]
    for t in threads_locked:
        t.start()
    for t in threads_locked:
        t.join()

    locked_actual = locked_stats.total_records

    return expected, unlocked_actual, locked_actual
