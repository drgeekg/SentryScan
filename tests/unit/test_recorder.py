"""Unit tests for EventRecorder and JSONL persistence."""

import json
from pathlib import Path

from sentryscan.common.clock import FakeClock
from sentryscan.contracts.events import EventStatus, EventType
from sentryscan.observability.recorder import EventRecorder


def test_recorder_monotonic_seq_and_jsonl(tmp_path: Path):
    """Verify EventRecorder assigns gap-free seq and writes valid JSONL."""
    trace_file = tmp_path / "trace.jsonl"
    clock = FakeClock("2026-10-21T00:00:00Z")

    with EventRecorder(run_id="run-000001", output_path=trace_file, clock=clock) as rec:
        e1 = rec.record(
            event_type=EventType.RUN_STARTED,
            component="test",
            status=EventStatus.OK,
        )
        assert e1.seq == 1
        assert e1.event_id == "evt-000001"

        clock.advance(5.0)
        e2 = rec.record(
            event_type=EventType.RECORD_RECEIVED,
            component="sensor",
            record_id="tel-000001",
            host_id="sim-host-001",
        )
        assert e2.seq == 2
        assert e2.timestamp_utc == "2026-10-21T00:00:05Z"

        e3 = rec.record(
            event_type=EventType.RECORD_REJECTED,
            component="sensor",
            record_id="tel-000019",
            status=EventStatus.REJECTED,
            reason_code="INVALID_PORT",
        )
        assert e3.seq == 3

    assert trace_file.exists()
    lines = trace_file.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 3

    parsed = [json.loads(line) for line in lines]
    seqs = [item["seq"] for item in parsed]
    assert seqs == [1, 2, 3]
    assert parsed[2]["reason_code"] == "INVALID_PORT"
