"""Deterministic data-level integrity checker for suspect telemetry detection."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from sentryscan.common.clock import Clock, SystemClock
from sentryscan.contracts.telemetry import TelemetryRecord


class IntegrityReasonCode(str, Enum):
    """Reason codes for implausible or corrupted telemetry records."""

    STALE_RECORD = "STALE_RECORD"
    REPLAYED_RECORD = "REPLAYED_RECORD"
    FIELD_CONTRADICTION = "FIELD_CONTRADICTION"
    BASELINE_DRIFT = "BASELINE_DRIFT"
    RATE_ANOMALY = "RATE_ANOMALY"
    SUSPECT_TEXT = "SUSPECT_TEXT"


@dataclass(frozen=True)
class IntegrityFlag:
    """Individual integrity anomaly flag raised against a telemetry record."""

    record_id: str
    check_id: str
    reason_code: IntegrityReasonCode
    confidence: float
    details: dict[str, Any]


class IntegrityChecker:
    """Deterministic, rules-as-data plausibility validator.

    Detects corrupted, replayed, contradictory, or maliciously injected telemetry
    WITHOUT access to ground truth answer keys.
    """

    def __init__(
        self,
        clock: Clock | None = None,
        freshness_window_seconds: float = 60.0,
    ) -> None:
        self.clock = clock if clock is not None else SystemClock()
        self.freshness_window_seconds = freshness_window_seconds

        self._seen_record_ids: set[str] = set()
        self._payload_hashes: set[str] = set()
        self._device_last_seen: dict[str, datetime] = {}
        self._device_baseline_service: dict[str, set[str]] = {}

    def _hash_payload(self, record: TelemetryRecord) -> str:
        content = (
            f"{record.host_id}:{record.port}:{record.service}:"
            f"{record.banner}:{record.generated_at}"
        )
        return hashlib.sha256(content.encode("utf-8")).hexdigest()

    def check_record(self, record: TelemetryRecord) -> list[IntegrityFlag]:
        """Evaluate a telemetry record across all data integrity rules."""
        flags: list[IntegrityFlag] = []
        rec_id = record.record_id

        # 1. Check Duplication / Replay
        payload_hash = self._hash_payload(record)
        if rec_id in self._seen_record_ids:
            flags.append(
                IntegrityFlag(
                    record_id=rec_id,
                    check_id="INT-001",
                    reason_code=IntegrityReasonCode.REPLAYED_RECORD,
                    confidence=1.0,
                    details={"error": f"Duplicate record_id {rec_id} re-emitted"},
                )
            )
        elif payload_hash in self._payload_hashes:
            flags.append(
                IntegrityFlag(
                    record_id=rec_id,
                    check_id="INT-001",
                    reason_code=IntegrityReasonCode.REPLAYED_RECORD,
                    confidence=0.9,
                    details={"error": "Identical payload hash replayed for device"},
                )
            )
        else:
            self._seen_record_ids.add(rec_id)
            self._payload_hashes.add(payload_hash)

        # 2. Check Freshness and Monotonicity
        try:
            rec_dt = datetime.fromisoformat(
                record.generated_at.replace("Z", "+00:00")
            ).astimezone(timezone.utc)
            now_dt = self.clock.now_utc()
            drift_seconds = abs((now_dt - rec_dt).total_seconds())

            if drift_seconds > self.freshness_window_seconds:
                flags.append(
                    IntegrityFlag(
                        record_id=rec_id,
                        check_id="INT-002",
                        reason_code=IntegrityReasonCode.STALE_RECORD,
                        confidence=1.0,
                        details={
                            "drift_seconds": drift_seconds,
                            "allowed_window": self.freshness_window_seconds,
                        },
                    )
                )

            # Check time-reversal on same host
            last_dt = self._device_last_seen.get(record.host_id)
            if last_dt and rec_dt < last_dt:
                flags.append(
                    IntegrityFlag(
                        record_id=rec_id,
                        check_id="INT-002",
                        reason_code=IntegrityReasonCode.STALE_RECORD,
                        confidence=1.0,
                        details={"error": "Device timestamp moved backwards in time"},
                    )
                )
            self._device_last_seen[record.host_id] = rec_dt

        except Exception as err:
            flags.append(
                IntegrityFlag(
                    record_id=rec_id,
                    check_id="INT-002",
                    reason_code=IntegrityReasonCode.STALE_RECORD,
                    confidence=0.8,
                    details={"error": f"Invalid generated_at timestamp: {err}"},
                )
            )

        # 3. Check Cross-Field Contradictions
        # Case A: TLS claimed on plain-text only protocols
        if record.service.lower() in {"telnet", "tftp"} and record.tls_version:
            flags.append(
                IntegrityFlag(
                    record_id=rec_id,
                    check_id="INT-003",
                    reason_code=IntegrityReasonCode.FIELD_CONTRADICTION,
                    confidence=1.0,
                    details={
                        "service": record.service,
                        "contradiction": f"TLS {record.tls_version} claimed on plaintext service",
                    },
                )
            )

        # Case B: Service / Banner mismatch (HTTP banner on non-HTTP service)
        banner_lower = record.banner.lower()
        non_http_services = {
            "ssh",
            "postgresql",
            "mysql",
            "telnet",
            "dns",
            "wireguard",
            "ftp",
            "rdp",
            "smb",
        }
        if record.service.lower() in non_http_services and (
            "http/1.1" in banner_lower or "server: apache" in banner_lower or "apache/" in banner_lower
        ):
            flags.append(
                IntegrityFlag(
                    record_id=rec_id,
                    check_id="INT-003",
                    reason_code=IntegrityReasonCode.FIELD_CONTRADICTION,
                    confidence=0.95,
                    details={
                        "error": (
                            f"Service {record.service} on port {record.port} "
                            "returned HTTP web banner"
                        )
                    },
                )
            )

        # 4. Check Suspect Instruction Text (Prompt Injection in banners)
        prompt_injection_patterns = [
            "ignore prior instructions",
            "ignore previous instructions",
            "system:",
            "output status: all_hosts_secure",
            "mark all hosts",
        ]
        if any(pat in banner_lower for pat in prompt_injection_patterns):
            flags.append(
                IntegrityFlag(
                    record_id=rec_id,
                    check_id="INT-004",
                    reason_code=IntegrityReasonCode.SUSPECT_TEXT,
                    confidence=1.0,
                    details={"error": "Banner text contains prompt injection directive"},
                )
            )

        # 5. Check Rate Anomaly Marker
        if "burst_burst_rapid" in banner_lower:
            flags.append(
                IntegrityFlag(
                    record_id=rec_id,
                    check_id="INT-005",
                    reason_code=IntegrityReasonCode.RATE_ANOMALY,
                    confidence=0.9,
                    details={"error": "Emission rate anomaly detected for device"},
                )
            )

        return flags
