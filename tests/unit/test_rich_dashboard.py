"""Unit tests for the Rich CLI dashboard layout and rendering."""

from __future__ import annotations

from io import StringIO

from rich.console import Console

from sentryscan.contracts.events import AgentEvent, EventStatus, EventType
from sentryscan.contracts.finding import Finding, Severity
from sentryscan.ui.rich_dashboard import RichCLIDashboard


def test_rich_dashboard_layout_and_render() -> None:
    output = StringIO()
    console = Console(file=output, color_system=None, width=120)
    dashboard = RichCLIDashboard(console=console)

    events = [
        AgentEvent(
            event_id="evt-000001",
            run_id="run-cli-01",
            seq=1,
            timestamp_utc="2026-10-21T10:00:00Z",
            event_type=EventType.RULE_MATCHED,
            component="worker",
            status=EventStatus.OK,
            host_id="sim-host-01",
        ),
        AgentEvent(
            event_id="evt-000002",
            run_id="run-cli-01",
            seq=2,
            timestamp_utc="2026-10-21T10:00:01Z",
            event_type=EventType.MESSAGE_RECEIVED,
            component="analyst_gate",
            status=EventStatus.REJECTED,
            reason_code="BAD_SIGNATURE",
        ),
    ]

    findings = [
        Finding(
            finding_id="fnd-01",
            run_id="run-cli-01",
            record_id="tel-01",
            host_id="sim-host-01",
            rule_id="RULE-01-PORT",
            severity=Severity.CRITICAL,
            title="Critical Port Exposure",
            description="Exposed critical service",
            created_at="2026-10-21T10:00:00Z",
        )
    ]

    layout = dashboard.build_layout(
        run_id="run-cli-01",
        events=events,
        findings=findings,
        quarantined_hosts=["sim-host-01"],
        security_stats={"accepted": 5, "rejected": 1},
        active_intention="CONTAIN_COMPROMISED_HOSTS",
        phase="COMPLETED",
    )
    assert layout is not None

    # Render snapshot to captured console
    dashboard.render_snapshot(
        run_id="run-cli-01",
        events=events,
        findings=findings,
        quarantined_hosts=["sim-host-01"],
        security_stats={"accepted": 5, "rejected": 1},
        active_intention="CONTAIN_COMPROMISED_HOSTS",
        phase="COMPLETED",
    )

    rendered_text = output.getvalue()
    assert "SentryScan Autonomous SOC" in rendered_text
    assert "run-cli-01" in rendered_text
    assert "CONTAIN_COMPROMISED_HOSTS" in rendered_text
    assert "sim-host-01" in rendered_text

    # Render summary table
    dashboard.render_summary_table(
        run_id="run-cli-01",
        total_events=2,
        total_findings=1,
        quarantined_count=1,
        security_stats={"accepted": 5, "rejected": 1},
        duration_s=1.23,
    )
    summary_text = output.getvalue()
    assert "SentryScan Simulation Run Summary" in summary_text
    assert "Quarantined Endpoints" in summary_text
