"""Thread-safe telemetry queue manager with latency tracking."""

from __future__ import annotations

import queue
import time
from dataclasses import dataclass

from sentryscan.contracts.telemetry import TelemetryRecord


@dataclass(frozen=True)
class QueuedItem:
    """Wrapper holding a telemetry record and its enqueue timestamp."""

    record: TelemetryRecord
    enqueued_at: float


class TelemetryQueueManager:
    """Thread-safe buffer connecting asynchronous fleet producers with analysis consumers."""

    def __init__(self, maxsize: int = 1000) -> None:
        self._queue: queue.Queue[QueuedItem | None] = queue.Queue(maxsize=maxsize)
        self._total_enqueued: int = 0
        self._total_dequeued: int = 0

    def enqueue(self, record: TelemetryRecord, timeout: float = 2.0) -> bool:
        """Enqueue a telemetry record with monotonic arrival timestamp."""
        try:
            item = QueuedItem(record=record, enqueued_at=time.perf_counter())
            self._queue.put(item, timeout=timeout)
            self._total_enqueued += 1
            return True
        except queue.Full:
            return False

    def dequeue(self, timeout: float = 0.5) -> tuple[TelemetryRecord | None, float]:
        """Dequeue a record and compute its queue residence duration in milliseconds.

        Returns:
            (record, wait_time_ms) or (None, 0.0) if queue was empty.
        """
        try:
            item = self._queue.get(timeout=timeout)
            if item is None:
                # Stop sentinel received
                self._queue.task_done()
                return None, 0.0

            wait_ms = (time.perf_counter() - item.enqueued_at) * 1000.0
            self._total_dequeued += 1
            self._queue.task_done()
            return item.record, wait_ms
        except queue.Empty:
            return None, 0.0

    def put_sentinel(self) -> None:
        """Send stop sentinel to wake up blocking consumers."""
        self._queue.put(None)

    def qsize(self) -> int:
        """Return approximate current depth of the queue."""
        return self._queue.qsize()

    @property
    def total_enqueued(self) -> int:
        return self._total_enqueued

    @property
    def total_dequeued(self) -> int:
        return self._total_dequeued
