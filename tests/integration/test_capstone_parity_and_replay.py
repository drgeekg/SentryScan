"""Integration tests for capstone event parity, replay consistency, and reproducibility."""

from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from sentryscan.capstone import run_capstone
from sentryscan.common.clock import FakeClock
from sentryscan.dashboard_gateway.server import create_app
from sentryscan.storage.store import SQLiteRunStore


def test_end_to_end_event_parity_and_no_seq_gaps(tmp_path: Path) -> None:
    """Verify HLD §8.5: SQLite == JSONL, gap-free monotonic sequence."""
    clock = FakeClock("2026-10-21T10:00:00Z")
    out_dir = tmp_path / "parity_run"

    res = run_capstone(
        run_id="run-parity-check",
        seed=42,
        output_dir=out_dir,
        launch_gateway=False,
        clock=clock,
        quiet=True,
    )

    assert res["parity_passed"] is True
    store = SQLiteRunStore(res["db_path"])
    parity = store.verify_parity(run_id="run-parity-check", jsonl_path=res["trace_path"])

    assert parity["parity_passed"] is True
    assert parity["sqlite_event_count"] == parity["jsonl_event_count"]
    assert parity["has_seq_gaps"] is False
    assert parity["id_alignment"] is True
    store.close()


def test_trace_determinism_and_reproducibility(tmp_path: Path) -> None:
    """Verify that identical seed and clock produce identical findings and outcomes."""
    clock1 = FakeClock("2026-10-21T10:00:00Z")
    clock2 = FakeClock("2026-10-21T10:00:00Z")

    dir1 = tmp_path / "run_seed1"
    dir2 = tmp_path / "run_seed2"

    res1 = run_capstone(
        run_id="run-seed-42a",
        seed=42,
        output_dir=dir1,
        launch_gateway=False,
        clock=clock1,
        quiet=True,
    )
    res2 = run_capstone(
        run_id="run-seed-42b",
        seed=42,
        output_dir=dir2,
        launch_gateway=False,
        clock=clock2,
        quiet=True,
    )

    assert res1["awarded_proposer"] == res2["awarded_proposer"]
    assert res1["total_findings"] == res2["total_findings"]
    assert res1["quarantined_hosts"] == res2["quarantined_hosts"]
    assert res1["sqlite_event_count"] == res2["sqlite_event_count"]


def test_replay_consistency_without_mutation(tmp_path: Path) -> None:
    """Verify HLD §8.3: Replay reads recorded events and never reruns or mutates."""
    clock = FakeClock("2026-10-21T10:00:00Z")
    out_dir = tmp_path / "replay_run"

    res = run_capstone(
        run_id="run-replay-base",
        seed=99,
        output_dir=out_dir,
        launch_gateway=False,
        clock=clock,
        quiet=True,
    )

    store = SQLiteRunStore(res["db_path"])
    initial_event_count = store.get_event_count("run-replay-base")

    # Simulate replay reader
    replayed_events = store.get_events("run-replay-base", from_seq=1, limit=1000)
    assert len(replayed_events) == initial_event_count

    # Verify order is strictly monotonic by seq
    seqs = [e["seq"] for e in replayed_events]
    assert seqs == list(range(1, initial_event_count + 1))

    # Verify store was not mutated during replay
    assert store.get_event_count("run-replay-base") == initial_event_count
    store.close()


def test_gateway_resync_after_forced_disconnect(tmp_path: Path) -> None:
    """Verify HLD §8.1.6: Slow or reconnecting browser backfills from seq without loss."""
    clock = FakeClock("2026-10-21T10:00:00Z")
    out_dir = tmp_path / "resync_run"

    res = run_capstone(
        run_id="run-resync-test",
        seed=77,
        output_dir=out_dir,
        launch_gateway=False,
        clock=clock,
        quiet=True,
    )

    store = SQLiteRunStore(res["db_path"])
    app = create_app(store=store)
    client = TestClient(app)

    total_events = store.get_event_count("run-resync-test")
    half_seq = total_events // 2

    # Client reconnects after missing events up to half_seq
    with client.websocket_connect("/ws/run-resync-test") as ws:
        ws.send_json({"type": "subscribe", "from_seq": half_seq + 1})

        received_events = []
        for _ in range(total_events - half_seq):
            msg = ws.receive_json()
            received_events.append(msg)

        assert len(received_events) == (total_events - half_seq)
        assert received_events[0]["seq"] == half_seq + 1
        assert received_events[-1]["seq"] == total_events

    store.close()
