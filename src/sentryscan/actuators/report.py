"""Actuator components for console rendering and file persistence of findings."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.table import Table

from sentryscan.contracts.finding import Finding, Severity


class ReportActuator:
    """Actuator responsible for presenting and writing vulnerability analysis reports."""

    def __init__(self, output_dir: Path | str | None = None) -> None:
        self.output_dir = Path(output_dir) if output_dir else None
        self.console = Console(highlight=False)

    def write_findings_json(
        self,
        findings: list[Finding],
        file_path: Path | str,
    ) -> Path:
        """Serialize findings to a clean JSON array file."""
        target = Path(file_path)
        target.parent.mkdir(parents=True, exist_ok=True)
        serialized = [f.model_dump() for f in findings]
        target.write_text(json.dumps(serialized, indent=2), encoding="utf-8")
        return target

    def write_summary_json(
        self,
        summary: dict[str, Any],
        file_path: Path | str,
    ) -> Path:
        """Write high-level run execution summary metrics."""
        target = Path(file_path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(summary, indent=2), encoding="utf-8")
        return target

    def render_console_summary(
        self,
        run_id: str,
        total_records: int,
        valid_records: int,
        malformed_records: int,
        findings: list[Finding],
    ) -> None:
        """Print rich terminal summary table of the reflex analysis run."""
        self.console.print()
        self.console.rule(f"[bold blue]SentryScan Reflex Analysis — Run: {run_id}[/bold blue]")

        # Metrics Overview Table
        meta_table = Table(title="Execution Ingestion Metrics", show_header=True)
        meta_table.add_column("Metric", style="cyan")
        meta_table.add_column("Count", style="bold green")

        meta_table.add_row("Total Raw Percepts Sensed", str(total_records))
        meta_table.add_row("Valid Records Ingested", str(valid_records))
        meta_table.add_row("Malformed Records Quarantined", str(malformed_records))
        meta_table.add_row("Total Vulnerability Findings", str(len(findings)))
        self.console.print(meta_table)

        # Findings Breakdown Table
        if findings:
            find_table = Table(title="Detected Exposures & Findings", show_header=True)
            find_table.add_column("Finding ID", style="dim")
            find_table.add_column("Host", style="cyan")
            find_table.add_column("Port/Svc", style="magenta")
            find_table.add_column("Severity", style="bold")
            find_table.add_column("Rule ID", style="yellow")
            find_table.add_column("Title", style="white")

            for f in findings:
                sev_color = {
                    Severity.CRITICAL: "bold red",
                    Severity.HIGH: "red",
                    Severity.MEDIUM: "yellow",
                    Severity.LOW: "green",
                    Severity.INFORMATIONAL: "blue",
                }.get(f.severity, "white")

                port_svc = f"{f.evidence.get('port', '?')}/{f.evidence.get('service', '?')}"
                find_table.add_row(
                    f.finding_id,
                    f.host_id,
                    port_svc,
                    f"[{sev_color}]{f.severity.value}[/{sev_color}]",
                    f.rule_id,
                    f.title,
                )
            self.console.print(find_table)
        else:
            self.console.print("[yellow]No vulnerability findings detected.[/yellow]")

        self.console.rule("[bold blue]End of Analysis Summary[/bold blue]")
        self.console.print()
