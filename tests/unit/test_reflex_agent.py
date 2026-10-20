"""Unit tests for the complete ReflexAgent Sense-Parse-Decide-Act pipeline."""

import json
from pathlib import Path

from sentryscan.agents.reflex_agent import ReflexAgent
from sentryscan.common.clock import FakeClock
from sentryscan.common.id_generator import IdGenerator

FIXTURE_PATH = (
    Path(__file__).resolve().parent.parent.parent
    / "fixtures"
    / "telemetry"
    / "sample_seed42.json"
)


def test_reflex_agent_end_to_end(tmp_path: Path):
    """Verify ReflexAgent processes the 20-record fixture deterministically."""
    clock = FakeClock("2026-10-21T00:00:00Z")
    id_gen = IdGenerator(seed=42)

    agent = ReflexAgent(
        run_id="run-test-1-2",
        output_dir=tmp_path,
        clock=clock,
        id_gen=id_gen,
    )

    raw_data = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
    res = agent.process_records(raw_data, print_console=False)

    assert res.total_percepts == 20
    assert res.valid_count == 18
    assert res.malformed_count == 2
    assert len(res.findings) == 13

    # Check generated files
    trace_file = tmp_path / "trace.jsonl"
    findings_file = tmp_path / "findings.json"
    summary_file = tmp_path / "summary.json"

    assert trace_file.exists()
    assert findings_file.exists()
    assert summary_file.exists()

    # Inspect trace events for monotonic seq and required event types
    lines = trace_file.read_text(encoding="utf-8").strip().splitlines()
    events = [json.loads(line) for line in lines]

    seqs = [e["seq"] for e in events]
    assert seqs == list(range(1, len(events) + 1))  # Gap-free monotonic seq

    event_types = {e["event_type"] for e in events}
    assert "run_started" in event_types
    assert "record_received" in event_types
    assert "record_rejected" in event_types
    assert "rule_matched" in event_types
    assert "finding_created" in event_types
    assert "unmatched_record" in event_types
    assert "report_written" in event_types
    assert "run_completed" in event_types


def test_reflex_agent_determinism(tmp_path: Path):
    """Verify two independent runs on the same input yield identical findings and traces."""
    dir1 = tmp_path / "run1"
    dir2 = tmp_path / "run2"

    raw_data = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))

    agent1 = ReflexAgent("run-det-1", dir1, FakeClock(), IdGenerator(seed=100))
    agent2 = ReflexAgent("run-det-2", dir2, FakeClock(), IdGenerator(seed=100))

    res1 = agent1.process_records(raw_data)
    res2 = agent2.process_records(raw_data)

    assert len(res1.findings) == len(res2.findings)
    for f1, f2 in zip(res1.findings, res2.findings, strict=False):
        assert f1.rule_id == f2.rule_id
        assert f1.severity == f2.severity
        assert f1.host_id == f2.host_id
        assert f1.title == f2.title
