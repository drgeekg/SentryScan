"""Unit tests for telemetry and finding data contracts."""

import pytest
from pydantic import ValidationError

from sentryscan.contracts.finding import Finding, Severity
from sentryscan.contracts.telemetry import AuthMode, TelemetryRecord, TelemetrySource


def test_telemetry_record_valid():
    """Verify valid telemetry record initializes correctly."""
    rec = TelemetryRecord(
        record_id="tel-000001",
        host_id="sim-host-001",
        ip="192.0.2.1",
        port=80,
        service="http",
        banner="nginx",
        tls_version=None,
        auth_mode=AuthMode.REQUIRED,
        generated_at="2026-10-21T00:00:00Z",
        source=TelemetrySource.SYNTHETIC_FIXTURE,
    )
    assert rec.port == 80
    assert rec.service == "http"
    assert rec.to_percept_dict()["record_id"] == "tel-000001"


def test_telemetry_record_invalid_port():
    """Verify port out of range raises ValidationError."""
    with pytest.raises(ValidationError):
        TelemetryRecord(
            record_id="tel-000002",
            host_id="sim-host-001",
            ip="192.0.2.1",
            port=99999,
            service="http",
            generated_at="2026-10-21T00:00:00Z",
        )


def test_telemetry_record_empty_host_id():
    """Verify empty host_id raises ValidationError."""
    with pytest.raises(ValidationError):
        TelemetryRecord(
            record_id="tel-000003",
            host_id="   ",
            ip="192.0.2.1",
            port=80,
            service="http",
            generated_at="2026-10-21T00:00:00Z",
        )


def test_finding_contract():
    """Verify finding record properties and serialization."""
    finding = Finding(
        finding_id="fnd-000001",
        run_id="run-000001",
        record_id="tel-000001",
        host_id="sim-host-001",
        rule_id="RULE-001",
        severity=Severity.HIGH,
        title="Unencrypted Telnet Exposed",
        description="Telnet protocol exposes credentials in cleartext.",
        evidence={"port": 23, "service": "telnet"},
        confidence=1.0,
        created_at="2026-10-21T00:00:00Z",
    )
    assert finding.severity == Severity.HIGH
    assert finding.confidence == 1.0
