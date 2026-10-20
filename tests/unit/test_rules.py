"""Unit tests for reflex condition-action rule engine."""

from sentryscan.common.id_generator import IdGenerator
from sentryscan.contracts.finding import Severity
from sentryscan.contracts.telemetry import AuthMode, TelemetryRecord
from sentryscan.rules.engine import RuleEngine


def test_rule_telnet_match():
    """Verify RULE-001 triggers on Telnet service."""
    engine = RuleEngine()
    gen = IdGenerator()
    rec = TelemetryRecord(
        record_id="tel-000001",
        host_id="sim-host-001",
        ip="192.0.2.1",
        port=23,
        service="telnet",
        banner="Linux telnetd",
        generated_at="2026-10-21T00:00:00Z",
    )
    findings = engine.evaluate_record(
        rec,
        run_id="run-000001",
        finding_id_generator=lambda: gen.next_id("finding"),
        timestamp_iso="2026-10-21T00:00:00Z",
    )
    assert len(findings) == 1
    assert findings[0].rule_id == "RULE-001"
    assert findings[0].severity == Severity.HIGH


def test_rule_default_credentials():
    """Verify RULE-004 triggers on default credentials banner or auth_mode."""
    engine = RuleEngine()
    gen = IdGenerator()
    rec = TelemetryRecord(
        record_id="tel-000005",
        host_id="sim-host-003",
        ip="192.0.2.13",
        port=8080,
        service="http",
        banner="Console (default credentials admin/admin)",
        auth_mode=AuthMode.DEFAULT,
        generated_at="2026-10-21T00:00:00Z",
    )
    findings = engine.evaluate_record(
        rec,
        run_id="run-000001",
        finding_id_generator=lambda: gen.next_id("finding"),
        timestamp_iso="2026-10-21T00:00:00Z",
    )
    # Triggers RULE-004 (Default Credentials) and RULE-006 (Admin HTTP)
    rule_ids = {f.rule_id for f in findings}
    assert "RULE-004" in rule_ids
    critical_findings = [f for f in findings if f.severity == Severity.CRITICAL]
    assert len(critical_findings) >= 1


def test_rule_unmatched_benign_record():
    """Verify benign record (modern SSH) yields zero findings."""
    engine = RuleEngine()
    gen = IdGenerator()
    rec = TelemetryRecord(
        record_id="tel-000002",
        host_id="sim-host-001",
        ip="192.0.2.11",
        port=22,
        service="ssh",
        banner="OpenSSH 9.2p1",
        auth_mode=AuthMode.REQUIRED,
        generated_at="2026-10-21T00:00:00Z",
    )
    findings = engine.evaluate_record(
        rec,
        run_id="run-000001",
        finding_id_generator=lambda: gen.next_id("finding"),
        timestamp_iso="2026-10-21T00:00:00Z",
    )
    assert len(findings) == 0
