"""Unit tests for the end-to-end capstone simulation runner."""

from __future__ import annotations

from pathlib import Path

from sentryscan.capstone import run_capstone
from sentryscan.common.clock import FakeClock


def test_run_capstone_headless(tmp_path: Path) -> None:
    clock = FakeClock("2026-10-21T10:00:00Z")
    output_dir = tmp_path / "capstone_test"

    res = run_capstone(
        run_id="run-test-capstone-unit",
        seed=101,
        output_dir=output_dir,
        launch_gateway=False,
        clock=clock,
        quiet=True,
    )

    assert res["run_id"] == "run-test-capstone-unit"
    assert res["phase"] == "COMPLETED"
    assert res["parity_passed"] is True
    assert res["sqlite_event_count"] > 0
    assert res["sqlite_event_count"] == res["jsonl_event_count"]
    assert res["total_findings"] > 0
    assert len(res["quarantined_hosts"]) > 0

    # Ensure output files were written
    db_file = Path(res["db_path"])
    jsonl_file = Path(res["trace_path"])
    assert db_file.exists() and db_file.stat().st_size > 0
    assert jsonl_file.exists() and jsonl_file.stat().st_size > 0
