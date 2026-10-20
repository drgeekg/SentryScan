"""Unit tests for telemetry parser and sensor ingestion."""

from pathlib import Path

from sentryscan.sensors.parser import TelemetryParser

FIXTURE_PATH = (
    Path(__file__).resolve().parent.parent.parent
    / "fixtures"
    / "telemetry"
    / "sample_seed42.json"
)


def test_parse_valid_dict():
    """Verify clean dictionary parses successfully."""
    parser = TelemetryParser()
    raw = {
        "record_id": "tel-000001",
        "host_id": "sim-host-001",
        "ip": "192.0.2.1",
        "port": 22,
        "service": "ssh",
        "banner": "OpenSSH",
        "generated_at": "2026-10-21T00:00:00Z",
    }
    res = parser.parse_dict(raw)
    assert res.is_valid is True
    assert res.record is not None
    assert res.record.service == "ssh"
    assert res.error_message is None


def test_parse_invalid_json_string():
    """Verify malformed JSON string is caught and flagged."""
    parser = TelemetryParser()
    res = parser.parse_json_string("{not valid json")
    assert res.is_valid is False
    assert "JSON decode failure" in (res.error_message or "")


def test_parse_fixture_sample_seed42():
    """Verify loading the 20-record fixture: exactly 18 valid and 2 malformed."""
    parser = TelemetryParser()
    results = parser.parse_file(FIXTURE_PATH)

    assert len(results) == 20
    valid_records = [r for r in results if r.is_valid]
    malformed_records = [r for r in results if not r.is_valid]

    assert len(valid_records) == 18
    assert len(malformed_records) == 2

    # Malformed 1: tel-000019 (port 99999 out of range)
    assert malformed_records[0].record_id == "tel-000019"
    assert "port" in (malformed_records[0].error_message or "").lower()
    assert "65535" in (malformed_records[0].error_message or "")

    # Malformed 2: tel-000020 (blank host_id)
    assert malformed_records[1].record_id == "tel-000020"
    assert "host_id" in (malformed_records[1].error_message or "")
