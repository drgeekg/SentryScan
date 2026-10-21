"""Unit tests for thread-safe TelemetryQueueManager."""

import threading
import time

from sentryscan.concurrency.queue_manager import TelemetryQueueManager
from sentryscan.contracts.telemetry import AuthMode, TelemetryRecord, TelemetrySource


def _create_record(rec_id: str) -> TelemetryRecord:
    return TelemetryRecord(
        record_id=rec_id,
        host_id="sim-host-001",
        ip="192.0.2.1",
        port=80,
        service="http",
        banner="nginx",
        tls_version=None,
        auth_mode=AuthMode.REQUIRED,
        generated_at="2026-10-21T06:00:00Z",
        source=TelemetrySource.SYNTHETIC_SIMULATOR,
    )


def test_queue_enqueue_dequeue():
    """Verify FIFO ordering and wait duration tracking."""
    qm = TelemetryQueueManager(maxsize=10)
    rec1 = _create_record("tel-000001")
    rec2 = _create_record("tel-000002")

    assert qm.enqueue(rec1) is True
    assert qm.enqueue(rec2) is True
    assert qm.qsize() == 2

    r1, wait1 = qm.dequeue(timeout=0.1)
    assert r1 is not None
    assert r1.record_id == "tel-000001"
    assert wait1 >= 0.0

    r2, wait2 = qm.dequeue(timeout=0.1)
    assert r2 is not None
    assert r2.record_id == "tel-000002"

    assert qm.total_enqueued == 2
    assert qm.total_dequeued == 2


def test_queue_multithreaded_producer_consumer():
    """Verify concurrent thread safety between multiple producers and a consumer."""
    qm = TelemetryQueueManager(maxsize=100)
    num_items = 50
    consumed: list[str] = []

    def producer():
        for i in range(num_items):
            qm.enqueue(_create_record(f"tel-{i:04d}"))
            time.sleep(0.001)
        qm.put_sentinel()

    def consumer():
        while True:
            r, _ = qm.dequeue(timeout=1.0)
            if r is None:
                break
            consumed.append(r.record_id)

    t_prod = threading.Thread(target=producer)
    t_cons = threading.Thread(target=consumer)

    t_prod.start()
    t_cons.start()

    t_prod.join(timeout=3.0)
    t_cons.join(timeout=3.0)

    assert len(consumed) == num_items
    assert consumed[0] == "tel-0000"
    assert consumed[-1] == f"tel-{num_items - 1:04d}"
