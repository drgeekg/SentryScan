"""Unit tests for background MonitorDaemon."""

import time

from sentryscan.common.clock import FakeClock
from sentryscan.concurrency.daemon import MonitorDaemon
from sentryscan.concurrency.queue_manager import TelemetryQueueManager
from sentryscan.simulation.fleet import DeviceFleetSimulator


def test_daemon_lifecycle_and_heartbeat():
    """Verify daemon starts, increments heartbeat, enqueues telemetry, and stops cleanly."""
    qm = TelemetryQueueManager(maxsize=500)
    sim = DeviceFleetSimulator(device_count=2, seed=42)
    clock = FakeClock("2026-10-21T06:00:00Z")

    heartbeats: list[int] = []

    def on_hb(count: int, ts: str):
        heartbeats.append(count)

    daemon = MonitorDaemon(
        queue_manager=qm,
        fleet_simulator=sim,
        clock=clock,
        heartbeat_interval=0.02,
        on_heartbeat=on_hb,
    )

    daemon.start()
    assert daemon.is_alive is True

    # Allow daemon to run for a few cycles
    time.sleep(0.1)

    assert daemon.heartbeat_count >= 2
    assert daemon.records_emitted > 0
    assert qm.qsize() > 0
    assert len(heartbeats) >= 2

    # Clean shutdown
    daemon.stop()
    daemon.join(timeout=1.0)
    assert daemon.is_alive is False
