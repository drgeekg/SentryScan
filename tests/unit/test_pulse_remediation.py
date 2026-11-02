"""Simulated remediation: controls recover, new findings re-fail them, reset restores state."""

from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from sentryscan.dashboard_gateway.server import create_app
from sentryscan.platform import core, pulse
from sentryscan.simulation.human_tester import run_human_workstation_test
from sentryscan.storage.store import SQLiteRunStore


def _store(tmp_path: Path):
    res = run_human_workstation_test(
        seed=42, cycles=4, output_dir=tmp_path / "r",
        fleet_spec="windows=1,cisco_router=1,aws=1,m365=1",
    )
    return SQLiteRunStore(res["db_path"]), res["run_id"], res


def test_remediate_all_reaches_full_compliance_and_reset_restores(tmp_path: Path):
    store, run_id, _ = _store(tmp_path)
    before = pulse.pulse_summary(store, run_id)["score"]
    assert before < 100
    out = pulse.remediate_all(store, run_id)
    assert out["after"] == 100
    assert all(c["status"] == "PASS" for c in out["controls"])
    assert all(0 <= c["freshness_pct"] <= 100 for c in out["controls"])
    core.reset_demo(store, run_id)
    assert pulse.pulse_summary(store, run_id)["score"] < 100
    store.close()


def test_breach_drops_score_again(tmp_path: Path):
    store, run_id, _ = _store(tmp_path)
    pulse.remediate_all(store, run_id)
    pulse.breach(store, run_id)
    ctl = {c["id"]: c for c in pulse.evaluate_controls(store, run_id, False)}
    assert ctl["CTL-06"]["status"] == "FAIL"
    store.close()


def test_control_endpoints_and_page(tmp_path: Path):
    store, run_id, _ = _store(tmp_path)
    app = create_app(store=store, static_dir=tmp_path / "nodist")
    with TestClient(app) as c:
        assert "Demo Control Center" in c.get("/control").text
        assert c.post(f"/api/runs/{run_id}/demo/hold", json={"hold": True}).json()["hold"] is True
        assert c.get(f"/api/runs/{run_id}/demo/state").json()["hold"] is True
        r = c.post(f"/api/runs/{run_id}/pulse/remediate-all").json()
        assert r["after"] == 100 and r["score"] == 100
        assert c.post(f"/api/runs/{run_id}/pulse/controls/CTL-99/remediate").status_code == 404
        assert c.post(f"/api/runs/{run_id}/demo/reset").json()["score"] < 100
