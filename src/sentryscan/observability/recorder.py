"""Single-writer audit event recorder with monotonic sequence numbers and dual sinks."""

from __future__ import annotations

import threading
from pathlib import Path
from typing import TYPE_CHECKING, Any

from sentryscan.common.clock import Clock, SystemClock
from sentryscan.contracts.events import AgentEvent, EventStatus, EventType

if TYPE_CHECKING:
    from sentryscan.storage.store import SQLiteRunStore


class EventRecorder:
    """Thread-safe, single-writer event persistence component.

    Assigns gap-free monotonic sequence numbers (`seq`) and appends events
    to an authoritative JSONL trace file, with optional real-time persistence
    to a SQLite run store.
    """

    def __init__(
        self,
        run_id: str,
        output_path: Path | str,
        clock: Clock | None = None,
        sqlite_store: SQLiteRunStore | None = None,
    ) -> None:
        self.run_id = run_id
        self.output_path = Path(output_path)
        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        self.clock = clock if clock is not None else SystemClock()
        self.sqlite_store = sqlite_store

        self._lock = threading.Lock()
        self._seq_counter: int = 0
        self._events: list[AgentEvent] = []

        self._file = open(self.output_path, "a", encoding="utf-8")

    def record(
        self,
        event_type: EventType,
        component: str,
        status: EventStatus = EventStatus.OK,
        record_id: str | None = None,
        host_id: str | None = None,
        rule_id: str | None = None,
        finding_id: str | None = None,
        reason_code: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> AgentEvent:
        """Create, sequence, persist to dual sinks, and return a new AgentEvent."""
        with self._lock:
            self._seq_counter += 1
            seq = self._seq_counter
            event_id = f"evt-{seq:06d}"
            timestamp_utc = self.clock.now_iso()

            event = AgentEvent(
                event_id=event_id,
                run_id=self.run_id,
                seq=seq,
                timestamp_utc=timestamp_utc,
                event_type=event_type,
                component=component,
                record_id=record_id,
                host_id=host_id,
                rule_id=rule_id,
                finding_id=finding_id,
                status=status,
                reason_code=reason_code,
                details=details or {},
            )

            # 1. Sink: Append to authoritative JSONL trace
            json_line = event.model_dump_json()
            self._file.write(json_line + "\n")
            self._file.flush()

            # 2. Sink: Persist to SQLite run store if enabled
            if self.sqlite_store is not None:
                self.sqlite_store.save_event(event)
                self.sqlite_store._recorder = self  # type: ignore[attr-defined]

            self._events.append(event)
            return event

    def get_events(self) -> list[AgentEvent]:
        """Return in-memory copy of recorded events."""
        with self._lock:
            return list(self._events)

    def close(self) -> None:
        """Close trace file safely."""
        with self._lock:
            if not self._file.closed:
                self._file.close()

    def __enter__(self) -> EventRecorder:
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()
