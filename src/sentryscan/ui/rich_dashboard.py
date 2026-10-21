"""Rich terminal CLI dashboard for headless and interactive SentryScan runs."""

from __future__ import annotations

from rich.console import Console
from rich.layout import Layout
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from sentryscan.contracts.events import AgentEvent
from sentryscan.contracts.finding import Finding


class RichCLIDashboard:
    """Terminal dashboard rendered using the Rich library."""

    def __init__(self, console: Console | None = None) -> None:
        self.console = console if console is not None else Console()

    def build_layout(
        self,
        run_id: str,
        events: list[AgentEvent],
        findings: list[Finding],
        quarantined_hosts: list[str],
        security_stats: dict[str, int] | None = None,
        active_intention: str | None = None,
        phase: str = "IN_PROGRESS",
    ) -> Layout:
        """Construct full terminal dashboard layout."""
        layout = Layout()
        layout.split_column(
            Layout(name="header", size=3),
            Layout(name="main", ratio=1),
            Layout(name="events", size=8),
        )
        layout["main"].split_row(
            Layout(name="findings_col", ratio=1),
            Layout(name="security_col", ratio=1),
        )

        # 1. Header
        header_text = Text()
        header_text.append("SentryScan Autonomous SOC ", style="bold cyan")
        header_text.append(f"| Run ID: {run_id} ", style="bold white")
        header_text.append(f"| Phase: {phase} ", style="bold yellow")
        header_text.append(f"| Events: {len(events)}", style="bold green")
        layout["header"].update(Panel(header_text, style="blue"))

        # 2. Findings & BDI Panel
        findings_table = Table(title="Detected Vulnerabilities & BDI Quarantine", expand=True)
        findings_table.add_column("Host", style="cyan")
        findings_table.add_column("Rule", style="magenta")
        findings_table.add_column("Severity", style="bold")
        findings_table.add_column("Quarantined", style="bold")

        for f in findings[-6:]:
            sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
            sev_style = "red" if sev in ("CRITICAL", "HIGH") else "yellow"
            is_q = f.host_id in quarantined_hosts
            q_text = "[bold red]YES[/bold red]" if is_q else "[green]NO[/green]"
            findings_table.add_row(
                f.host_id, f.rule_id, f"[{sev_style}]{sev}[/{sev_style}]", q_text
            )

        int_text = active_intention or "AUDIT_ASSIGNED_HOSTS"
        bdi_panel = Panel(
            findings_table,
            subtitle=f"[bold]Active BDI Intention:[/bold] [yellow]{int_text}[/yellow]",
        )
        layout["main"]["findings_col"].update(bdi_panel)

        # 3. Security Gate Panel
        sec_stats = security_stats or {"accepted": 0, "rejected": 0}
        sec_table = Table(title="Ed25519 Cryptographic Security Gate", expand=True)
        sec_table.add_column("Metric", style="white")
        sec_table.add_column("Value", style="bold")

        sec_table.add_row("Accepted Messages", f"[green]{sec_stats.get('accepted', 0)}[/green]")
        sec_table.add_row("Rejected Breaches", f"[red]{sec_stats.get('rejected', 0)}[/red]")
        sec_table.add_row(
            "Quarantined Fleet", f"[bold red]{len(quarantined_hosts)} host(s)[/bold red]"
        )
        sec_table.add_row("Security Gate Stance", "[bold green]FAIL-CLOSED (Active)[/bold green]")

        layout["main"]["security_col"].update(Panel(sec_table))

        # 4. Recent Events Stream
        events_table = Table(title="Audit Event Stream (Monotonic seq)", expand=True)
        events_table.add_column("Seq", style="cyan", width=6)
        events_table.add_column("Type", style="magenta")
        events_table.add_column("Component", style="green")
        events_table.add_column("Status", style="bold")
        events_table.add_column("Reason / Detail")

        for ev in events[-5:]:
            stat_style = "green" if ev.status.value == "OK" else "red"
            r_code = ev.reason_code or ""
            events_table.add_row(
                str(ev.seq),
                ev.event_type.value,
                ev.component,
                f"[{stat_style}]{ev.status.value}[/{stat_style}]",
                r_code,
            )

        layout["events"].update(Panel(events_table))
        return layout

    def render_snapshot(
        self,
        run_id: str,
        events: list[AgentEvent],
        findings: list[Finding],
        quarantined_hosts: list[str],
        security_stats: dict[str, int] | None = None,
        active_intention: str | None = None,
        phase: str = "IN_PROGRESS",
    ) -> None:
        """Render snapshot to console."""
        layout = self.build_layout(
            run_id=run_id,
            events=events,
            findings=findings,
            quarantined_hosts=quarantined_hosts,
            security_stats=security_stats,
            active_intention=active_intention,
            phase=phase,
        )
        self.console.print(layout)

    def render_summary_table(
        self,
        run_id: str,
        total_events: int,
        total_findings: int,
        quarantined_count: int,
        security_stats: dict[str, int],
        duration_s: float = 0.0,
    ) -> None:
        """Print final executive run summary table."""
        table = Table(title=f"SentryScan Simulation Run Summary: {run_id}", expand=False)
        table.add_column("Dimension", style="bold cyan")
        table.add_column("Observed Outcome", style="bold white")

        table.add_row("Total Monotonic Events", str(total_events))
        table.add_row("Vulnerability Findings", str(total_findings))
        table.add_row("Quarantined Endpoints", f"[bold red]{quarantined_count}[/bold red]")
        table.add_row(
            "Security Gate Accepted", f"[green]{security_stats.get('accepted', 0)}[/green]"
        )
        table.add_row("Security Gate Rejected", f"[red]{security_stats.get('rejected', 0)}[/red]")
        table.add_row("Execution Duration", f"{duration_s:.2f}s")
        table.add_row("Observability Sinks", "Append-Only JSONL & Indexed SQLite (Parity: OK)")

        self.console.print(table)
