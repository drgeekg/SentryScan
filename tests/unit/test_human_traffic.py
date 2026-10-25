"""Unit tests for realistic human workstation simulation and traffic generator."""

from __future__ import annotations

from pathlib import Path

from sentryscan.common.clock import FakeClock
from sentryscan.common.id_generator import IdGenerator
from sentryscan.simulation.fleet import DeviceFleetSimulator
from sentryscan.simulation.human_tester import run_human_workstation_test
from sentryscan.simulation.human_traffic import (
    HUMAN_WORKSTATION_TEMPLATES,
    HumanTrafficGenerator,
)


def test_human_workstation_templates():
    """Verify built-in Windows and Linux human workstation templates."""
    assert len(HUMAN_WORKSTATION_TEMPLATES) >= 4
    families = {tpl.os_family for tpl in HUMAN_WORKSTATION_TEMPLATES}
    assert "windows" in families
    assert "linux" in families

    win_tpls = [t for t in HUMAN_WORKSTATION_TEMPLATES if t.os_family == "windows"]
    linux_tpls = [t for t in HUMAN_WORKSTATION_TEMPLATES if t.os_family == "linux"]

    assert any("smb" in [s.service for s in t.services] for t in win_tpls)
    assert any("ssh" in [s.service for s in t.services] for t in linux_tpls)


def test_human_traffic_generator_burst_planning():
    """Verify human burst planning generates authentic burst sizes and intra-delays."""
    clock = FakeClock("2026-10-21T08:00:00Z")
    id_gen = IdGenerator(seed=12)
    gen = HumanTrafficGenerator(
        device_count=4,
        seed=12,
        clock=clock,
        id_gen=id_gen,
        poison_ratio=0.2,
    )

    burst = gen.plan_next_human_burst()
    assert burst.host_id in [w.host_id for w in gen.workstations]
    assert burst.record_count >= 2
    assert burst.intra_event_delay_ms > 0
    assert burst.post_burst_pause_s > 0

    records = gen.generate_burst_records(burst)
    assert len(records) == burst.record_count

    for rec, truth, is_p, inj_type in records:
        assert rec.host_id == burst.host_id
        assert truth["host_id"] == burst.host_id
        assert "persona" in truth
        assert "os_family" in truth


def test_human_traffic_generator_determinism():
    """Verify identical seeds produce identical bursts and records."""
    clk1 = FakeClock("2026-10-21T08:00:00Z")
    clk2 = FakeClock("2026-10-21T08:00:00Z")
    gen1 = HumanTrafficGenerator(device_count=4, seed=999, clock=clk1)
    gen2 = HumanTrafficGenerator(device_count=4, seed=999, clock=clk2)

    b1 = gen1.plan_next_human_burst()
    b2 = gen2.plan_next_human_burst()

    assert b1.host_id == b2.host_id
    assert b1.action == b2.action
    assert b1.record_count == b2.record_count
    assert b1.intra_event_delay_ms == b2.intra_event_delay_ms

    recs1 = gen1.generate_burst_records(b1)
    recs2 = gen2.generate_burst_records(b2)

    assert len(recs1) == len(recs2)
    for (r1, t1, p1, _), (r2, t2, p2, _) in zip(recs1, recs2):
        assert r1.record_id == r2.record_id
        assert r1.host_id == r2.host_id
        assert r1.port == r2.port
        assert p1 == p2


def test_fleet_simulator_human_workstation_profile():
    """Verify DeviceFleetSimulator initializes human workstation profile correctly."""
    fleet = DeviceFleetSimulator(
        device_count=4,
        seed=42,
        profile="human_workstations",
    )
    assert len(fleet.devices) == 4
    host_ids = [d.host_id for d in fleet.devices]
    assert "win11-finance-01" in host_ids
    assert "ubuntu-dev-01" in host_ids

    cycle = fleet.generate_fleet_cycle()
    assert len(cycle) > 0
    assert all(r.host_id in host_ids for r in cycle)


def test_run_human_workstation_test_harness(tmp_path: Path):
    """Verify the automated human workstation test harness end-to-end."""
    clock = FakeClock("2026-10-21T09:00:00Z")
    metrics = run_human_workstation_test(
        seed=101,
        cycles=3,
        device_count=3,
        output_dir=tmp_path / "test_human_run",
        clock=clock,
        poison_ratio=0.2,
    )

    assert metrics["parity_passed"] is True
    assert metrics["total_records"] > 0
    assert metrics["total_bursts"] == 3
    assert metrics["device_count"] == 3
    assert metrics["sqlite_event_count"] == metrics["jsonl_event_count"]
    assert Path(metrics["db_path"]).exists()
    assert Path(metrics["trace_path"]).exists()
