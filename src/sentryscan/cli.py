"""Command Line Interface for SentryScan."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from sentryscan import __version__
from sentryscan.agents.reflex_agent import ReflexAgent
from sentryscan.common.clock import SystemClock
from sentryscan.common.id_generator import IdGenerator


def main() -> None:
    """Main CLI entrypoint for SentryScan."""
    parser = argparse.ArgumentParser(
        prog="sentryscan",
        description="SentryScan: Autonomous Security Telemetry Analysis Platform",
    )
    parser.add_argument("--version", "-v", action="version", version=f"SentryScan {__version__}")

    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # run-reflex subcommand
    reflex_parser = subparsers.add_parser(
        "run-reflex",
        help="Execute deterministic reflex reasoner on telemetry fixtures",
    )
    reflex_parser.add_argument(
        "--fixture",
        "-f",
        default="fixtures/telemetry/sample_seed42.json",
        help="Path to JSON fixture array containing telemetry records",
    )
    reflex_parser.add_argument(
        "--output-dir",
        "-o",
        default="data/runs/cli_run",
        help="Directory to persist run trace and findings",
    )
    reflex_parser.add_argument(
        "--run-id",
        default="run-cli-001",
        help="Unique identifier for the execution run",
    )

    args = parser.parse_args()

    if args.command == "run-reflex":
        fixture_path = Path(args.fixture)
        if not fixture_path.exists():
            sys.stderr.write(f"Error: Fixture file not found: {fixture_path}\n")
            sys.exit(1)

        raw_records = json.loads(fixture_path.read_text(encoding="utf-8"))
        agent = ReflexAgent(
            run_id=args.run_id,
            output_dir=args.output_dir,
            clock=SystemClock(),
            id_gen=IdGenerator(seed=42),
        )
        res = agent.process_records(raw_records, print_console=True)
        print(f"[+] Run completed: {res.valid_count} valid, {res.malformed_count} malformed.")
        print(f"[+] Findings: {len(res.findings)} detected. Trace: {res.trace_path}")
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
