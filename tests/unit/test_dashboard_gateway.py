"""Unit tests for the FastAPI REST and WebSocket dashboard gateway."""

from __future__ import annotations

from fastapi.testclient import TestClient

from sentryscan.contracts.events import AgentEvent, EventStatus, EventType
from sentryscan.contracts.finding import Finding, Severity
from sentryscan.contracts.message import Message, Performative
from sentryscan.contracts.telemetry import TelemetryRecord
from sentryscan.dashboard_gateway.server import create_app
from sentryscan.storage.store import SQLiteRunStore


def _seed_test_store() -> tuple[SQLiteRunStore, str]:
    store = SQLiteRunStore(":memory:")
    run_id = "run-gw-test-01"
    store.save_run(
        run_id=run_id,
        seed=42,
        status="ACTIVE",
        created_at="2026-10-21T10:00:00Z",
        manifest={"test": True},
        metadata={"total_findings": 1},
    )

    # Add 3 events
    for seq in range(1, 4):
        store.save_event(
            AgentEvent(
                event_id=f"evt-{seq:06d}",
                run_id=run_id,
                seq=seq,
                timestamp_utc=f"2026-10-21T10:00:0{seq}Z",
                event_type=EventType.RULE_MATCHED,
                component="worker_node",
                status=EventStatus.OK,
                host_id="sim-host-01",
                details={"seq": seq},
            )
        )

    # Add finding
    store.save_finding(
        Finding(
            finding_id="fnd-gw-01",
            run_id=run_id,
            record_id="tel-gw-01",
            host_id="sim-host-01",
            rule_id="RULE-01-PORT",
            severity=Severity.HIGH,
            title="Open Port 22",
            description="SSH exposed",
            confidence=1.0,
            evidence={"port": 22},
            created_at="2026-10-21T10:00:01Z",
        ),
        cve_id="CVE-2023-38408",
        cvss_score=9.8,
        quarantined=True,
    )

    # Add telemetry
    store.save_telemetry_record(
        TelemetryRecord(
            record_id="tel-gw-01",
            host_id="sim-host-01",
            ip="192.0.2.10",
            port=22,
            service="ssh",
            banner="OpenSSH 7.2",
            auth_mode="required",
            tls_version=None,
            generated_at="2026-10-21T10:00:01Z",
        ),
        run_id=run_id,
    )

    # Add message
    store.save_message(
        Message(
            message_id="msg-gw-01",
            run_id=run_id,
            sender="supervisor-agent",
            receiver="analyst-agent",
            performative=Performative.ALERT,
            timestamp_utc="2026-10-21T10:00:01Z",
            nonce="nonce-gw-01",
            payload={"finding_id": "fnd-gw-01"},
        ),
        seq=1,
    )

    return store, run_id


def test_gateway_rest_api() -> None:
    store, run_id = _seed_test_store()
    app = create_app(store=store)
    client = TestClient(app)

    # Health check
    res_health = client.get("/api/health")
    assert res_health.status_code == 200
    assert res_health.json()["status"] == "ok"

    # List runs & get run
    res_runs = client.get("/api/runs")
    assert res_runs.status_code == 200
    runs = res_runs.json()
    assert len(runs) == 1
    assert runs[0]["run_id"] == run_id

    res_single = client.get(f"/api/runs/{run_id}")
    assert res_single.status_code == 200
    assert res_single.json()["status"] == "ACTIVE"

    # 404 for unknown run
    res_404 = client.get("/api/runs/non-existent-run")
    assert res_404.status_code == 404

    # Query events
    res_events = client.get(f"/api/runs/{run_id}/events?from_seq=2&limit=10")
    assert res_events.status_code == 200
    evts = res_events.json()
    assert len(evts) == 2
    assert evts[0]["seq"] == 2
    assert evts[1]["seq"] == 3

    # Query findings
    res_findings = client.get(f"/api/runs/{run_id}/findings")
    assert res_findings.status_code == 200
    findings = res_findings.json()
    assert len(findings) == 1
    assert findings[0]["cve_id"] == "CVE-2023-38408"
    assert findings[0]["quarantined"] is True

    # Query devices & messages
    res_devices = client.get(f"/api/runs/{run_id}/devices")
    assert res_devices.status_code == 200
    assert len(res_devices.json()) == 1

    res_msgs = client.get(f"/api/runs/{run_id}/messages")
    assert res_msgs.status_code == 200
    assert len(res_msgs.json()) == 1


def test_gateway_websocket_backfill_and_resync() -> None:
    store, run_id = _seed_test_store()
    app = create_app(store=store)
    client = TestClient(app)

    with client.websocket_connect(f"/ws/{run_id}") as websocket:
        # Subscribe requesting backfill from seq=2
        websocket.send_json({"type": "subscribe", "from_seq": 2})

        # Expect 2 backfilled events (seq 2 and seq 3)
        ev2 = websocket.receive_json()
        assert ev2["seq"] == 2
        assert ev2["event_id"] == "evt-000002"

        ev3 = websocket.receive_json()
        assert ev3["seq"] == 3
        assert ev3["event_id"] == "evt-000003"


def test_gateway_serves_html() -> None:
    store, _ = _seed_test_store()
    app = create_app(store=store)
    client = TestClient(app)

    res = client.get("/")
    assert res.status_code == 200
    assert "text/html" in res.headers["content-type"]
    assert "SentryScan" in res.text
