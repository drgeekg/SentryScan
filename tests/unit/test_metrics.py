"""Unit tests for LatencyTracker and CSV export."""

from pathlib import Path

from sentryscan.concurrency.metrics import LatencyTracker


def test_latency_summary_and_percentiles(tmp_path: Path):
    """Verify p50, p95 calculation and CSV generation."""
    tracker = LatencyTracker()

    # Add 100 sample latencies
    for i in range(1, 101):
        tracker.record_latency(
            record_id=f"tel-{i:03d}",
            queue_wait_ms=float(i),
            processing_ms=1.5,
        )

    summary = tracker.compute_summary()
    assert summary["count"] == 100

    # For values 1..100: p50 ~ 50.5, p95 ~ 95.05
    assert 49.0 <= summary["queue_wait_ms"]["p50"] <= 52.0
    assert 94.0 <= summary["queue_wait_ms"]["p95"] <= 96.0

    # CSV export
    csv_file = tmp_path / "metrics.csv"
    tracker.export_csv(csv_file)
    assert csv_file.exists()

    lines = csv_file.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 101  # Header + 100 rows
    assert lines[0] == "record_id,queue_wait_ms,processing_ms,turnaround_ms"
    assert lines[1].startswith("tel-001,1.0,1.5,2.5")
