"""Unit tests proving lost update race conditions and non-blocking concurrent progress."""

import time

from sentryscan.common.clock import FakeClock
from sentryscan.concurrency.daemon import MonitorDaemon
from sentryscan.concurrency.queue_manager import TelemetryQueueManager
from sentryscan.concurrency.stats import demonstrate_lost_updates
from sentryscan.simulation.fleet import DeviceFleetSimulator


def test_lost_updates_demonstration():
    """Verify lost updates occur without lock, and lock guarantees exact count."""
    expected, unlocked_actual, locked_actual = demonstrate_lost_updates(
        num_threads=10,
        increments_per_thread=30,
    )

    # 1. Unlocked must show lost updates due to race conditions
    assert unlocked_actual < expected, (
        f"Expected lost updates! actual: {unlocked_actual}, expected: {expected}"
    )

    # 2. Locked must be exact
    assert locked_actual == expected, (
        f"Locked counter failed! actual: {locked_actual}, expected: {expected}"
    )


def test_non_blocking_heartbeat():
    """Prove background monitor daemon heartbeat continues while consumer does work."""
    qm = TelemetryQueueManager(maxsize=100)
    sim = DeviceFleetSimulator(device_count=2, seed=42)
    clock = FakeClock("2026-10-21T06:00:00Z")

    daemon = MonitorDaemon(
        queue_manager=qm,
        fleet_simulator=sim,
        clock=clock,
        heartbeat_interval=0.01,
    )

    daemon.start()

    # Simulate slow consumer doing work in main thread
    time.sleep(0.06)
    hb_before = daemon.heartbeat_count

    time.sleep(0.06)
    hb_after = daemon.heartbeat_count

    daemon.stop()
    daemon.join(timeout=1.0)

    # Heartbeat continued ticking independently
    assert hb_after > hb_before >= 2
