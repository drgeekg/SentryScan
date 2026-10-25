"""Unit tests for typed enterprise assets, simulated RADAR, Pulse controls, and Platform API v2."""

from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from sentryscan.dashboard_gateway.server import create_app
from sentryscan.platform import core, pulse
from sentryscan.simulation.asset_types import (
    ASSET_TYPES,
    build_templates,
    parse_fleet_spec,
    resolve_fleet,
)
from sentryscan.simulation.human_tester import run_human_workstation_test
from sentryscan.storage.store import SQLiteRunStore


def test_parse_and_resolve_fleet_determinism_and_guards():
    """Verify explicit per-type counts, prefix aliases, seeded random fill, and router guard."""
    assert len(ASSET_TYPES) == 11
    spec = parse_fleet_spec("windows=2,cisco_router=1,aws=1,m365=1")
    assert spec["windows_workstation"] == 2
    assert spec["cisco_router"] == 1
    assert spec["aws_account"] == 1
    assert spec["m365_tenant"] == 1

    # Explicit counts + random fill up to 8 must be deterministic for a fixed seed
    r1 = resolve_fleet("windows=2,linux_workstation=1", total=8, seed=101)
    r2 = resolve_fleet("windows=2,linux_workstation=1", total=8, seed=101)
    assert r1 == r2
    assert len(r1) == 8
    assert r1.count("windows_workstation") >= 2
    assert "cisco_router" in r1  # >=6 fleet gets at least one network device

    tpls = build_templates(r1)
    assert len(tpls) == 8
    assert len({t.host_id for t in tpls}) == 8


def test_radar_pulse_and_profile_inheritance(tmp_path: Path):
    """Verify generic vs healthcare profile loading, RADAR classification, and Pulse control evaluation."""
    res = run_human_workstation_test(
        seed=42,
        cycles=4,
        output_dir=tmp_path / "p_run",
        fleet_spec="windows=1,cisco_router=1,aws=1,m365=1",
    )
    store = SQLiteRunStore(res["db_path"])
    run_id = res["run_id"]

    rad = core.radar_summary(store, run_id)
    assert rad["synthetic"] is True
    assert len(rad["sources"]) > 0
    assert len(rad["scans"]) >= 1

    pul = pulse.pulse_summary(store, run_id)
    assert pul["profile"] == "generic"
    assert len(pul["controls"]) == 8
    assert any(c["status"] == "FAIL" for c in pul["controls"])

    # Switch to healthcare profile (extends generic with PHI + CTL-09)
    core.set_setting(store, run_id, "profile", "healthcare")
    core.scan(store, run_id, seed=99)
    pul_hc = pulse.pulse_summary(store, run_id)
    assert pul_hc["profile"] == "healthcare"
    assert any(c["id"] == "CTL-09" for c in pul_hc["controls"])
    store.close()


def test_platform_v2_api_endpoints_end_to_end(tmp_path: Path):
    """Verify Overview, Assets, Alerts, Incidents, RADAR, Pulse, Remediation, and Scenarios API."""
    res = run_human_workstation_test(
        seed=77,
        cycles=4,
        output_dir=tmp_path / "api_run",
        fleet_spec="windows=1,linux_server=1,cisco_router=1,aws=1",
    )
    store = SQLiteRunStore(res["db_path"])
    run_id = res["run_id"]
    client = TestClient(create_app(store=store))

    # 1. Asset types catalogue
    at_resp = client.get("/api/asset-types")
    assert at_resp.status_code == 200
    assert len(at_resp.json()) == 11

    # 2. Overview
    ov = client.get(f"/api/runs/{run_id}/overview").json()
    assert "security_score" in ov
    assert "compliance" in ov
    assert ov["assets"] == 4

    # 3. Assets & Asset Detail
    assets = client.get(f"/api/runs/{run_id}/assets").json()
    assert len(assets) == 4
    first_host = assets[0]["host_id"]
    ad = client.get(f"/api/runs/{run_id}/assets/{first_host}").json()
    assert ad["host_id"] == first_host
    assert "services" in ad and "data_sources" in ad

    # 4. Alerts & Incident Detail
    alerts = client.get(f"/api/runs/{run_id}/alerts").json()
    assert isinstance(alerts, list)
    incs = client.get(f"/api/runs/{run_id}/incidents").json()
    if incs:
        inc_det = client.get(f"/api/runs/{run_id}/incidents/{incs[0]['incident_id']}").json()
        assert inc_det["incident"]["incident_id"] == incs[0]["incident_id"]

    # 5. RADAR & Scan trigger
    rad = client.post(f"/api/runs/{run_id}/radar/scan").json()
    assert len(rad["scans"]) >= 2

    # 6. Pulse & Control detail + Framework switch
    pul = client.post(
        f"/api/runs/{run_id}/pulse/settings",
        json={"profile": "healthcare", "framework": "iso27001"},
    ).json()
    assert pul["profile"] == "healthcare"
    assert pul["framework"] == "iso27001"
    c1 = client.get(f"/api/runs/{run_id}/pulse/controls/CTL-01").json()
    assert c1["id"] == "CTL-01"
    assert c1["framework_ref"] == "A.8.20"

    # 7. Remediation lifecycle
    task = client.post(
        f"/api/runs/{run_id}/remediation",
        json={"kind": "pulse", "ref_id": "CTL-01", "host_id": first_host, "title": "Disable Telnet VTY", "owner": "netops"},
    ).json()
    done = client.post(
        f"/api/runs/{run_id}/remediation/{task['task_id']}",
        json={"status": "DONE", "owner": "netops"},
    ).json()
    assert done["status"] == "DONE"

    # 8. Fleet preview & Scenario execution
    prev = client.post("/api/simulation/resolve-fleet", json={"fleet_spec": "windows=2,cisco_router=1", "total": 5, "seed": 42}).json()
    assert prev["total"] == 5
    scen = client.post(
        "/api/simulation/scenarios",
        json={"name": "Hybrid Smoke Scenario", "fleet_spec": "windows=1,cisco_router=1", "total_devices": 2, "cycles": 2, "seed": 11},
    ).json()
    assert scen["status"] == "COMPLETED"
    assert scen["result"]["total_records"] > 0
    store.close()
