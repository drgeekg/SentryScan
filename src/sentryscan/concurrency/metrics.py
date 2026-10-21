"""Queue latency and turnaround time performance metrics tracking."""

from __future__ import annotations

import csv
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class LatencyRecord:
    """Individual record latency measurement."""

    record_id: str
    queue_wait_ms: float
    processing_ms: float
    turnaround_ms: float


class LatencyTracker:
    """Calculates throughput, wait times, and percentiles (p50, p95)."""

    def __init__(self) -> None:
        self._records: list[LatencyRecord] = []

    def record_latency(
        self,
        record_id: str,
        queue_wait_ms: float,
        processing_ms: float,
    ) -> LatencyRecord:
        """Log latency datapoint for a processed record."""
        turnaround = queue_wait_ms + processing_ms
        item = LatencyRecord(
            record_id=record_id,
            queue_wait_ms=round(queue_wait_ms, 3),
            processing_ms=round(processing_ms, 3),
            turnaround_ms=round(turnaround, 3),
        )
        self._records.append(item)
        return item

    def _percentile(self, values: list[float], pct: float) -> float:
        if not values:
            return 0.0
        sorted_v = sorted(values)
        k = (len(sorted_v) - 1) * (pct / 100.0)
        f = int(k)
        c = f + 1
        if c < len(sorted_v):
            return sorted_v[f] + (k - f) * (sorted_v[c] - sorted_v[f])
        return sorted_v[f]

    def compute_summary(self) -> dict[str, Any]:
        """Compute mean, p50, p90, and p95 across wait and turnaround times."""
        if not self._records:
            return {
                "count": 0,
                "queue_wait_ms": {"mean": 0.0, "p50": 0.0, "p95": 0.0},
                "turnaround_ms": {"mean": 0.0, "p50": 0.0, "p95": 0.0},
            }

        waits = [r.queue_wait_ms for r in self._records]
        turnarounds = [r.turnaround_ms for r in self._records]

        return {
            "count": len(self._records),
            "queue_wait_ms": {
                "mean": round(sum(waits) / len(waits), 3),
                "p50": round(self._percentile(waits, 50.0), 3),
                "p90": round(self._percentile(waits, 90.0), 3),
                "p95": round(self._percentile(waits, 95.0), 3),
            },
            "turnaround_ms": {
                "mean": round(sum(turnarounds) / len(turnarounds), 3),
                "p50": round(self._percentile(turnarounds, 50.0), 3),
                "p90": round(self._percentile(turnarounds, 90.0), 3),
                "p95": round(self._percentile(turnarounds, 95.0), 3),
            },
        }

    def export_csv(self, file_path: Path | str) -> Path:
        """Export individual latency records to CSV file."""
        target = Path(file_path)
        target.parent.mkdir(parents=True, exist_ok=True)

        with open(target, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["record_id", "queue_wait_ms", "processing_ms", "turnaround_ms"])
            for r in self._records:
                writer.writerow([r.record_id, r.queue_wait_ms, r.processing_ms, r.turnaround_ms])

        return target
