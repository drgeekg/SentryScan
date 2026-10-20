"""Simple reflex agent for deterministic security telemetry triage."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from sentryscan.actuators.report import ReportActuator
from sentryscan.common.clock import Clock, SystemClock
from sentryscan.common.id_generator import IdGenerator
from sentryscan.contracts.events import EventStatus, EventType
from sentryscan.contracts.finding import Finding, Severity
from sentryscan.observability.recorder import EventRecorder
from sentryscan.rules.engine import RuleEngine
from sentryscan.sensors.parser import ParseResult, TelemetryParser


@dataclass
class ReflexAgentRunResult:
    """Outcome metrics and findings produced by a reflex agent execution."""

    run_id: str
    total_percepts: int
    valid_count: int
    malformed_count: int
    findings: list[Finding] = field(default_factory=list)
    severity_counts: dict[str, int] = field(default_factory=dict)
    trace_path: str = ""
    findings_path: str = ""


class ReflexAgent:
    """Reflex reasoner executing Sense-Parse-Decide-Act over telemetry records."""

    def __init__(
        self,
        run_id: str,
        output_dir: Path | str,
        clock: Clock | None = None,
        id_gen: IdGenerator | None = None,
        rule_engine: RuleEngine | None = None,
    ) -> None:
        self.run_id = run_id
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.clock = clock if clock is not None else SystemClock()
        self.id_gen = id_gen if id_gen is not None else IdGenerator(seed=42)
        self.rule_engine = rule_engine if rule_engine is not None else RuleEngine()

        self.sensor = TelemetryParser()
        self.actuator = ReportActuator(output_dir=self.output_dir)

        trace_file = self.output_dir / "trace.jsonl"
        self.recorder = EventRecorder(run_id=self.run_id, output_path=trace_file, clock=self.clock)

    def process_records(
        self,
        records_raw: list[dict[str, Any]],
        print_console: bool = False,
    ) -> ReflexAgentRunResult:
        """Execute the Sense-Parse-Decide-Act loop across raw telemetry records."""
        self.recorder.record(
            event_type=EventType.RUN_STARTED,
            component="reflex_agent",
            status=EventStatus.OK,
            details={"run_id": self.run_id, "total_records": len(records_raw)},
        )

        all_findings: list[Finding] = []
        valid_count = 0
        malformed_count = 0

        for raw_item in records_raw:
            # 1. SENSE & PARSE
            parse_res: ParseResult = self.sensor.parse_dict(raw_item)

            if not parse_res.is_valid:
                # Quarantined malformed percept
                malformed_count += 1
                self.recorder.record(
                    event_type=EventType.RECORD_REJECTED,
                    component="sensor_parser",
                    status=EventStatus.REJECTED,
                    record_id=parse_res.record_id,
                    reason_code="MALFORMED_TELEMETRY",
                    details={"error": parse_res.error_message, "raw": parse_res.raw_payload},
                )
                continue

            # Valid percept accepted
            valid_count += 1
            record = parse_res.record
            assert record is not None

            self.recorder.record(
                event_type=EventType.RECORD_RECEIVED,
                component="sensor_parser",
                status=EventStatus.OK,
                record_id=record.record_id,
                host_id=record.host_id,
                details={"service": record.service, "port": record.port},
            )

            # 2. DECIDE: Evaluate Reflex Rules
            findings = self.rule_engine.evaluate_record(
                record=record,
                run_id=self.run_id,
                finding_id_generator=lambda: self.id_gen.next_id("finding"),
                timestamp_iso=self.clock.now_iso(),
            )

            if findings:
                for finding in findings:
                    all_findings.append(finding)
                    self.recorder.record(
                        event_type=EventType.RULE_MATCHED,
                        component="rule_engine",
                        status=EventStatus.OK,
                        record_id=record.record_id,
                        host_id=record.host_id,
                        rule_id=finding.rule_id,
                        finding_id=finding.finding_id,
                        details={"severity": finding.severity.value, "title": finding.title},
                    )
                    self.recorder.record(
                        event_type=EventType.FINDING_CREATED,
                        component="rule_engine",
                        status=EventStatus.OK,
                        record_id=record.record_id,
                        host_id=record.host_id,
                        rule_id=finding.rule_id,
                        finding_id=finding.finding_id,
                        details={
                            "severity": finding.severity.value,
                            "evidence": finding.evidence,
                        },
                    )
            else:
                # Explicit unmatched behavior recording
                self.recorder.record(
                    event_type=EventType.UNMATCHED_RECORD,
                    component="rule_engine",
                    status=EventStatus.OK,
                    record_id=record.record_id,
                    host_id=record.host_id,
                    reason_code="NO_RULES_MATCHED",
                    details={"service": record.service, "port": record.port},
                )

        # 3. ACT: Output Reports
        findings_file = self.output_dir / "findings.json"
        self.actuator.write_findings_json(all_findings, findings_file)

        severity_counts: dict[str, int] = {s.value: 0 for s in Severity}
        for f in all_findings:
            severity_counts[f.severity.value] += 1

        summary_data = {
            "run_id": self.run_id,
            "total_percepts": len(records_raw),
            "valid_records": valid_count,
            "malformed_records": malformed_count,
            "total_findings": len(all_findings),
            "severity_counts": severity_counts,
        }
        summary_file = self.output_dir / "summary.json"
        self.actuator.write_summary_json(summary_data, summary_file)

        self.recorder.record(
            event_type=EventType.REPORT_WRITTEN,
            component="actuator_report",
            status=EventStatus.OK,
            details={"findings_file": str(findings_file), "summary_file": str(summary_file)},
        )

        self.recorder.record(
            event_type=EventType.RUN_COMPLETED,
            component="reflex_agent",
            status=EventStatus.OK,
            details=summary_data,
        )

        self.recorder.close()

        if print_console:
            self.actuator.render_console_summary(
                run_id=self.run_id,
                total_records=len(records_raw),
                valid_records=valid_count,
                malformed_records=malformed_count,
                findings=all_findings,
            )

        return ReflexAgentRunResult(
            run_id=self.run_id,
            total_percepts=len(records_raw),
            valid_count=valid_count,
            malformed_count=malformed_count,
            findings=all_findings,
            severity_counts=severity_counts,
            trace_path=str(self.recorder.output_path),
            findings_path=str(findings_file),
        )
