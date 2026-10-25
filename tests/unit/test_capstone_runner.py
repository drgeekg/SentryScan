"""Unit tests for the end-to-end capstone simulation runner."""

from __future__ import annotations

from pathlib import Path

from sentryscan.capstone import run_capstone, run_eval
from sentryscan.common.clock import FakeClock
from sentryscan.storage.store import SQLiteRunStore


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
    assert "eval_metrics" in res

    # Ensure output files were written
    db_file = Path(res["db_path"])
    jsonl_file = Path(res["trace_path"])
    assert db_file.exists() and db_file.stat().st_size > 0
    assert jsonl_file.exists() and jsonl_file.stat().st_size > 0


def test_run_eval_determinism_and_ground_truth(tmp_path: Path) -> None:
    r1 = run_eval(seed=42, cycles=3, output_dir=tmp_path / "eval1")
    r2 = run_eval(seed=42, cycles=3, output_dir=tmp_path / "eval2")

    assert r1["parity_passed"] is True
    assert r2["parity_passed"] is True
    assert r1["eval_metrics"] == r2["eval_metrics"]

    m = r1["eval_metrics"]
    assert 0.0 <= m["detection_precision"] <= 1.0
    assert 0.0 <= m["detection_recall"] <= 1.0
    assert 0.0 <= m["false_quarantine_rate"] <= 1.0
    assert m["time_to_contain_cycles"] >= 0.0
    assert m["cost_per_cycle"] > 0.0

    store = SQLiteRunStore(r1["db_path"])
    gt = store.get_ground_truth(r1["run_id"])
    assert len(gt) == 30  # 10 devices * 3 cycles
    assert any(row["is_vulnerable"] and row["expected_rules"] for row in gt)
    assert any(row["is_poisoned"] for row in gt)
    store.close()
