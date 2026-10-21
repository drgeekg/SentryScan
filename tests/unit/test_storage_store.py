"""Unit tests for SQLiteRunStore and dual-sink event parity."""

from __future__ import annotations

from pathlib import Path

from sentryscan.common.clock import FakeClock
from sentryscan.contracts.events import EventStatus, EventType
from sentryscan.contracts.finding import Finding, Severity
from sentryscan.contracts.message import Message, Performative
from sentryscan.contracts.telemetry import TelemetryRecord
from sentryscan.observability.recorder import EventRecorder
from sentryscan.storage.store import SQLiteRunStore


def test_sqlite_store_lifecycle(tmp_path: Path) -> None:
    db_file = tmp_path / "test_store.db"
    store = SQLiteRunStore(db_file)

    # 1. Run management
    store.save_run(
        run_id="run-001",
        seed=101,
        status="INITIALIZING",
        created_at="2026-10-21T10:00:00Z",
        manifest={"version": "0.1.0", "fleet_size": 4},
        metadata={"operator": "test-runner"},
    )
    r = store.get_run("run-001")
    assert r is not None
    assert r["run_id"] == "run-001"
    assert r["seed"] == 101
    assert r["manifest"]["fleet_size"] == 4

    store.update_run_status("run-001", "COMPLETED", metadata={"total_findings": 2})
    r_updated = store.get_run("run-001")
    assert r_updated is not None
    assert r_updated["status"] == "COMPLETED"
    assert r_updated["metadata"]["total_findings"] == 2

    # 2. Telemetry and Findings
    rec = TelemetryRecord(
        record_id="tel-001",
        host_id="sim-host-001",
        ip="192.0.2.10",
        port=22,
        service="ssh",
        banner="OpenSSH 7.2",
        auth_mode="required",
        tls_version=None,
        generated_at="2026-10-21T10:00:01Z",
    )
    store.save_telemetry_record(rec, run_id="run-001", is_poisoned=False)
    telemetry = store.get_telemetry_records("run-001")
    assert len(telemetry) == 1
    assert telemetry[0]["record_id"] == "tel-001"
    assert not telemetry[0]["is_poisoned"]

    finding = Finding(
        finding_id="fnd-001",
        run_id="run-001",
        record_id="tel-001",
        host_id="sim-host-001",
        rule_id="RULE-01-PORT",
        severity=Severity.HIGH,
        title="Insecure Port Detected",
        description="Port 22 exposed without compliant banner",
        confidence=0.95,
        evidence={"banner": "OpenSSH 7.2"},
        created_at="2026-10-21T10:00:02Z",
    )
    store.save_finding(finding, cve_id="CVE-2016-0777", cvss_score=7.5, quarantined=True)
    findings = store.get_findings("run-001")
    assert len(findings) == 1
    assert findings[0]["finding_id"] == "fnd-001"
    assert findings[0]["cve_id"] == "CVE-2016-0777"
    assert findings[0]["cvss_score"] == 7.5
    assert findings[0]["quarantined"] is True

    # 3. Messages
    msg = Message(
        message_id="msg-001",
        run_id="run-001",
        sender="supervisor-agent",
        receiver="analyst-agent",
        performative=Performative.ALERT,
        timestamp_utc="2026-10-21T10:00:03Z",
        nonce="nonce-test-1234",
        payload={"finding_id": "fnd-001"},
    )
    store.save_message(msg, seq=1, is_accepted=True, security_reason_code="OK")
    messages = store.get_messages("run-001")
    assert len(messages) == 1
    assert messages[0]["message_id"] == "msg-001"
    assert messages[0]["is_accepted"] is True
    assert messages[0]["payload"]["finding_id"] == "fnd-001"

    # 4. BDI Snapshots & LLM Calls
    store.save_bdi_snapshot(
        snapshot_id="snap-001",
        run_id="run-001",
        agent_id="analyst-agent",
        timestamp_utc="2026-10-21T10:00:04Z",
        intention_type="CONTAIN_COMPROMISED_HOSTS",
        desire_type="PREVENT_LATERAL_MOVEMENT",
        target_host="sim-host-001",
        reconsideration_count=1,
        beliefs={"sim-host-001": {"severity": "HIGH"}},
    )
    snapshots = store.get_bdi_snapshots("run-001")
    assert len(snapshots) == 1
    assert snapshots[0]["intention_type"] == "CONTAIN_COMPROMISED_HOSTS"
    assert snapshots[0]["reconsideration_count"] == 1

    store.save_llm_call(
        call_id="call-001",
        run_id="run-001",
        provider="deterministic",
        model="rule-synthesizer-v1",
        role="advisory",
        prompt_excerpt="Evaluate proposal risk",
        response_excerpt="Triage proposal selected",
        tokens=150,
        latency_ms=25.0,
        cached=False,
    )
    calls = store.get_llm_calls("run-001")
    assert len(calls) == 1
    assert calls[0]["provider"] == "deterministic"
    assert calls[0]["tokens"] == 150

    store.close()


def test_dual_sink_event_parity(tmp_path: Path) -> None:
    db_file = tmp_path / "parity_test.db"
    jsonl_file = tmp_path / "trace.jsonl"
    clock = FakeClock("2026-10-21T10:00:00Z")

    store = SQLiteRunStore(db_file)
    store.save_run(run_id="run-parity-01", seed=42, status="ACTIVE")

    recorder = EventRecorder(
        run_id="run-parity-01",
        output_path=jsonl_file,
        clock=clock,
        sqlite_store=store,
    )

    # Emit 15 diverse events
    for i in range(1, 16):
        recorder.record(
            event_type=EventType.RECORD_RECEIVED if i % 2 == 0 else EventType.RULE_MATCHED,
            component="test_worker",
            status=EventStatus.OK,
            host_id=f"host-{i}",
            details={"index": i},
        )
    recorder.close()

    # Verify parity using store's built-in verifier
    report = store.verify_parity(run_id="run-parity-01", jsonl_path=jsonl_file)
    assert report["parity_passed"] is True
    assert report["sqlite_event_count"] == 15
    assert report["jsonl_event_count"] == 15
    assert report["has_seq_gaps"] is False
    assert report["id_alignment"] is True

    # Test failure on artificial discrepancy
    tampered_jsonl = tmp_path / "tampered.jsonl"
    with (
        open(jsonl_file, "r", encoding="utf-8") as f_in,
        open(tampered_jsonl, "w", encoding="utf-8") as f_out,
    ):
        lines = f_in.readlines()
        # Drop one line to introduce a gap
        for line in lines[:-1]:
            f_out.write(line)

    tampered_report = store.verify_parity(run_id="run-parity-01", jsonl_path=tampered_jsonl)
    assert tampered_report["parity_passed"] is False
    assert tampered_report["jsonl_event_count"] == 14
    assert tampered_report["sqlite_event_count"] == 15

    store.close()
