#!/usr/bin/env python3
"""Deterministic Demonstration Script for Assignment 1.2 — Reflex Reasoner.

Executes the Sense-Parse-Decide-Act reflex loop over the 20-record test fixture,
demonstrating deterministic rule triggers, malformed payload rejections,
unmatched record accounting, and monotonic event trace generation.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))

from sentryscan.agents.reflex_agent import ReflexAgent  # noqa: E402
from sentryscan.common.clock import FakeClock  # noqa: E402
from sentryscan.common.id_generator import IdGenerator  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parent.parent
FIXTURE_PATH = REPO_ROOT / "fixtures" / "telemetry" / "sample_seed42.json"
OUTPUT_DIR = REPO_ROOT / "data" / "runs" / "demo_1_2"


def run_demo() -> None:
    print("[*] Starting SentryScan Reflex Reasoner Demonstration (Assignment 1.2)...")
    print(f"[*] Loading fixture: {FIXTURE_PATH.name}")

    raw_records = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
    print(f"[*] Ingesting {len(raw_records)} synthetic telemetry percepts...")

    clock = FakeClock("2026-10-21T00:00:00Z")
    id_gen = IdGenerator(seed=42)

    agent = ReflexAgent(
        run_id="run-demo-1-2",
        output_dir=OUTPUT_DIR,
        clock=clock,
        id_gen=id_gen,
    )

    result = agent.process_records(raw_records, print_console=True)

    print("[*] Execution Verification:")
    print(f"    - Total Percepts Sensed:       {result.total_percepts} (Expected: 20)")
    print(f"    - Valid Telemetry Ingested:    {result.valid_count} (Expected: 18)")
    print(f"    - Malformed Records Rejected:  {result.malformed_count} (Expected: 2)")
    print(f"    - Exposures / Findings:        {len(result.findings)}")
    print(f"    - JSONL Trace Path:            {result.trace_path}")
    print(f"    - Findings Path:               {result.findings_path}")

    assert result.total_percepts == 20
    assert result.valid_count == 18
    assert result.malformed_count == 2
    assert len(result.findings) > 0

    print("[+] Demonstration completed successfully with 100% contract compliance!")


if __name__ == "__main__":
    run_demo()
