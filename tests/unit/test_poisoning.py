"""Unit tests for poisoning mutators and isolated ground-truth sidecar."""

from sentryscan.contracts.telemetry import AuthMode, TelemetryRecord, TelemetrySource
from sentryscan.simulation.poisoning import (
    GroundTruthSidecar,
    InjectionOperator,
    PoisoningMutator,
)


def _sample_record() -> TelemetryRecord:
    return TelemetryRecord(
        record_id="tel-000001",
        host_id="sim-host-001",
        ip="192.0.2.1",
        port=22,
        service="ssh",
        banner="OpenSSH 9.2",
        tls_version=None,
        auth_mode=AuthMode.REQUIRED,
        generated_at="2026-10-21T06:00:00Z",
        source=TelemetrySource.SYNTHETIC_SIMULATOR,
    )


def test_stale_timestamp_mutation():
    """Verify stale timestamp operator shifts time and logs ground truth."""
    sidecar = GroundTruthSidecar()
    mutator = PoisoningMutator(sidecar, seed=42)

    base = _sample_record()
    mutated = mutator.mutate(base, InjectionOperator.STALE_TIMESTAMP, "tel-000002")

    assert mutated.record_id == "tel-000002"
    assert mutated.generated_at == "2026-10-21T04:00:00Z"  # 2 hours earlier

    gt = sidecar.get_entry("tel-000002")
    assert gt is not None
    assert gt.is_poisoned is True
    assert gt.injection_type == "stale_timestamp"
    assert "generated_at" in gt.modified_fields


def test_service_banner_mismatch_mutation():
    """Verify service banner mismatch alters banner and logs ground truth."""
    sidecar = GroundTruthSidecar()
    mutator = PoisoningMutator(sidecar, seed=42)

    base = _sample_record()
    mutated = mutator.mutate(base, InjectionOperator.SERVICE_BANNER_MISMATCH, "tel-000003")

    assert "HTTP/1.1" in mutated.banner
    gt = sidecar.get_entry("tel-000003")
    assert gt is not None
    assert gt.expected_classification == "suspect"


def test_tls_contradiction_mutation():
    """Verify TLS claim contradiction asserts impossible TLS on plaintext service."""
    sidecar = GroundTruthSidecar()
    mutator = PoisoningMutator(sidecar, seed=42)

    base = _sample_record()
    mutated = mutator.mutate(base, InjectionOperator.TLS_CLAIM_CONTRADICTION, "tel-000004")

    assert mutated.service == "telnet"
    assert mutated.tls_version == "TLSv1.3"

    gt = sidecar.get_entry("tel-000004")
    assert gt is not None
    assert "tls_version" in gt.modified_fields
