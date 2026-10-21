"""Background monitor daemon with non-blocking heartbeat and clean shutdown."""

from __future__ import annotations

import threading
from typing import Callable

from sentryscan.common.clock import Clock, SystemClock
from sentryscan.concurrency.queue_manager import TelemetryQueueManager
from sentryscan.contracts.telemetry import TelemetryRecord
from sentryscan.simulation.fleet import DeviceFleetSimulator


class MonitorDaemon:
    """Concurrent monitor daemon generating telemetry and broadcasting heartbeat signals."""

    def __init__(
        self,
        queue_manager: TelemetryQueueManager,
        fleet_simulator: DeviceFleetSimulator,
        clock: Clock | None = None,
        heartbeat_interval: float = 0.05,
        on_heartbeat: Callable[[int, str], None] | None = None,
    ) -> None:
        self.queue_manager = queue_manager
        self.fleet_simulator = fleet_simulator
        self.clock = clock if clock is not None else SystemClock()
        self.heartbeat_interval = heartbeat_interval
        self.on_heartbeat = on_heartbeat

        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._heartbeat_count: int = 0
        self._last_heartbeat_iso: str = ""
        self._records_emitted: int = 0
        self._lock = threading.Lock()

    def start(self) -> None:
        """Start daemon loop in background thread."""
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run_loop,
            name="SentryScan-MonitorDaemon",
            daemon=True,
        )
        self._thread.start()

    def _run_loop(self) -> None:
        """Daemon execution loop: emits telemetry cycles and heartbeat signals."""
        while not self._stop_event.is_set():
            # 1. Update heartbeat
            with self._lock:
                self._heartbeat_count += 1
                self._last_heartbeat_iso = self.clock.now_iso()
                current_hb = self._heartbeat_count
                current_time = self._last_heartbeat_iso

            if self.on_heartbeat:
                self.on_heartbeat(current_hb, current_time)

            # 2. Produce telemetry cycle from fleet
            cycle_records: list[TelemetryRecord] = self.fleet_simulator.generate_fleet_cycle()
            for rec in cycle_records:
                if self._stop_event.is_set():
                    break
                enqueued = self.queue_manager.enqueue(rec, timeout=0.1)
                if enqueued:
                    with self._lock:
                        self._records_emitted += 1

            # 3. Wait for next interval or stop event
            self._stop_event.wait(timeout=self.heartbeat_interval)

    def stop(self) -> None:
        """Signal the daemon to cease execution."""
        self._stop_event.set()

    def join(self, timeout: float = 2.0) -> None:
        """Wait for the background daemon thread to terminate."""
        if self._thread is not None:
            self._thread.join(timeout=timeout)

    @property
    def is_alive(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    @property
    def heartbeat_count(self) -> int:
        with self._lock:
            return self._heartbeat_count

    @property
    def last_heartbeat_iso(self) -> str:
        with self._lock:
            return self._last_heartbeat_iso

    @property
    def records_emitted(self) -> int:
        with self._lock:
            return self._records_emitted
