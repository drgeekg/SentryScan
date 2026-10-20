"""Explicit condition-action reflex rule engine."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from sentryscan.contracts.finding import Finding, Severity
from sentryscan.contracts.telemetry import AuthMode, TelemetryRecord


@dataclass(frozen=True)
class Rule:
    """Explicit condition-action production rule representation."""

    rule_id: str
    title: str
    description: str
    severity: Severity
    confidence: float
    condition: Callable[[TelemetryRecord], bool]

    def evaluate(self, record: TelemetryRecord) -> bool:
        """Evaluate rule predicate against a telemetry percept."""
        try:
            return self.condition(record)
        except Exception:
            return False


def _is_telnet(rec: TelemetryRecord) -> bool:
    return rec.service.lower() == "telnet" or rec.port == 23


def _is_anonymous_ftp(rec: TelemetryRecord) -> bool:
    is_ftp = rec.service.lower() == "ftp" or rec.port == 21
    has_anon = rec.auth_mode == AuthMode.ANONYMOUS or "anonymous" in rec.banner.lower()
    return is_ftp and has_anon


def _is_deprecated_tls(rec: TelemetryRecord) -> bool:
    if not rec.tls_version:
        return False
    deprecated_versions = {"tlsv1.0", "tlsv1.1", "sslv2", "sslv3"}
    return rec.tls_version.strip().lower() in deprecated_versions


def _is_default_credentials(rec: TelemetryRecord) -> bool:
    if rec.auth_mode == AuthMode.DEFAULT:
        return True
    banner_lower = rec.banner.lower()
    return (
        "default credentials" in banner_lower
        or "admin / admin" in banner_lower
        or "admin/admin" in banner_lower
        or "test/test" in banner_lower
    )


def _is_critical_known_exploit(rec: TelemetryRecord) -> bool:
    banner_lower = rec.banner.lower()
    # Apache 2.4.49 (CVE-2021-41773 path traversal) or vsftpd 2.3.4 (backdoor)
    return "apache/2.4.49" in banner_lower or "vsftpd 2.3.4" in banner_lower


def _is_unencrypted_admin_http(rec: TelemetryRecord) -> bool:
    is_http = rec.service.lower() == "http"
    is_admin_port = rec.port in {8080, 9000, 8888, 8000}
    return is_http and is_admin_port and rec.auth_mode != AuthMode.REQUIRED


def build_default_rules() -> list[Rule]:
    """Construct the standard SentryScan condition-action rule table."""
    return [
        Rule(
            rule_id="RULE-001",
            title="Unencrypted Telnet Management Protocol Exposed",
            description="Telnet transmits credentials and sessions in cleartext over the network.",
            severity=Severity.HIGH,
            confidence=1.0,
            condition=_is_telnet,
        ),
        Rule(
            rule_id="RULE-002",
            title="Unauthenticated Anonymous FTP Service Exposed",
            description=(
                "FTP daemon allows unauthenticated anonymous access to server directory tree."
            ),
            severity=Severity.MEDIUM,
            confidence=0.95,
            condition=_is_anonymous_ftp,
        ),
        Rule(
            rule_id="RULE-003",
            title="Deprecated Cryptographic Transport Protocol (TLS/SSL)",
            description=(
                "Service negotiates deprecated, cryptographically broken TLS or SSL versions."
            ),
            severity=Severity.HIGH,
            confidence=1.0,
            condition=_is_deprecated_tls,
        ),
        Rule(
            rule_id="RULE-004",
            title="Default Administrative Credentials Active on Service",
            description=(
                "Exposed service operates with factory or well-known default credentials."
            ),
            severity=Severity.CRITICAL,
            confidence=1.0,
            condition=_is_default_credentials,
        ),
        Rule(
            rule_id="RULE-005",
            title="Known Critical Remote Vulnerability Banner Detected",
            description=(
                "Service version matches known remote code execution or path traversal."
            ),
            severity=Severity.CRITICAL,
            confidence=0.95,
            condition=_is_critical_known_exploit,
        ),
        Rule(
            rule_id="RULE-006",
            title="Cleartext HTTP Management Interface Exposed",
            description=(
                "Administrative web portal operates over HTTP without mandatory TLS encryption."
            ),
            severity=Severity.MEDIUM,
            confidence=0.9,
            condition=_is_unencrypted_admin_http,
        ),
    ]


class RuleEngine:
    """Deterministic rule evaluator applying condition-action table to telemetry percepts."""

    def __init__(self, rules: list[Rule] | None = None) -> None:
        self.rules: list[Rule] = rules if rules is not None else build_default_rules()

    def evaluate_record(
        self,
        record: TelemetryRecord,
        run_id: str,
        finding_id_generator: Callable[[], str],
        timestamp_iso: str,
    ) -> list[Finding]:
        """Evaluate all rules against a telemetry percept, returning generated findings."""
        findings: list[Finding] = []

        for rule in self.rules:
            if rule.evaluate(record):
                finding = Finding(
                    finding_id=finding_id_generator(),
                    run_id=run_id,
                    record_id=record.record_id,
                    host_id=record.host_id,
                    rule_id=rule.rule_id,
                    severity=rule.severity,
                    title=rule.title,
                    description=rule.description,
                    evidence={
                        "port": record.port,
                        "service": record.service,
                        "banner": record.banner,
                        "tls_version": record.tls_version,
                        "auth_mode": record.auth_mode.value,
                    },
                    confidence=rule.confidence,
                    integrity_flags=[],
                    created_at=timestamp_iso,
                )
                findings.append(finding)

        return findings
