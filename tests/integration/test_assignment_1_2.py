"""Integration tests for Assignment 1.2 — Rule-Based Reflex Reasoner."""

import json
from pathlib import Path

from sentryscan.agents.reflex_agent import ReflexAgent
from sentryscan.common.clock import FakeClock
from sentryscan.common.id_generator import IdGenerator
from sentryscan.contracts.finding import Severity

FIXTURE_PATH = (
    Path(__file__).resolve().parent.parent.parent
    / "fixtures"
    / "telemetry"
    / "sample_seed42.json"
)


def test_assignment_1_2_complete_rubric_pipeline(tmp_path: Path):
    """Integration test asserting full rubric compliance for Assignment 1.2.

    Checks:
    1. Ingestion of 20 seeded records.
    2. Exactly 2 malformed records rejected and quarantined with audit events.
    3. Exactly 18 valid records processed.
    4. Explicit triggers across all 6 production rules.
    5. Unmatched records explicitly audited with reason_code.
    6. Gap-free monotonic sequence numbers.
    """
    raw_data = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
    agent = ReflexAgent(
        run_id="run-rubric-1-2",
        output_dir=tmp_path,
        clock=FakeClock("2026-10-21T00:00:00Z"),
        id_gen=IdGenerator(seed=42),
    )

    result = agent.process_records(raw_data)

    # 1. Verification of record counts
    assert result.total_percepts == 20
    assert result.valid_count == 18
    assert result.malformed_count == 2

    # 2. Verification of rule triggers
    triggered_rules = {f.rule_id for f in result.findings}
    expected_rules = {
        "RULE-001",  # Telnet
        "RULE-002",  # Anonymous FTP
        "RULE-003",  # Deprecated TLS/SSL
        "RULE-004",  # Default credentials
        "RULE-005",  # Critical known vulnerability banner
        "RULE-006",  # Admin HTTP
    }
    missing = expected_rules - triggered_rules
    assert expected_rules.issubset(triggered_rules), f"Missing rules: {missing}"

    # 3. Verification of severities
    severities = {f.severity for f in result.findings}
    assert Severity.CRITICAL in severities
    assert Severity.HIGH in severities
    assert Severity.MEDIUM in severities

    # 4. Verification of trace events
    trace_file = tmp_path / "trace.jsonl"
    lines = trace_file.read_text(encoding="utf-8").strip().splitlines()
    events = [json.loads(line) for line in lines]

    # Monotonic seq verification
    seqs = [e["seq"] for e in events]
    assert seqs == list(range(1, len(events) + 1))

    # Malformed rejections
    rejected_events = [e for e in events if e["event_type"] == "record_rejected"]
    assert len(rejected_events) == 2
    for rev in rejected_events:
        assert rev["status"] == "REJECTED"
        assert rev["reason_code"] == "MALFORMED_TELEMETRY"

    # Unmatched records
    unmatched_events = [e for e in events if e["event_type"] == "unmatched_record"]
    assert len(unmatched_events) > 0
    for uev in unmatched_events:
        assert uev["reason_code"] == "NO_RULES_MATCHED"
