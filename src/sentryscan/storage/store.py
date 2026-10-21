"""SQLite run store and persistence coordinator for SentryScan."""

from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import Any

from sentryscan.contracts.events import AgentEvent
from sentryscan.contracts.finding import Finding
from sentryscan.contracts.message import Message
from sentryscan.contracts.telemetry import TelemetryRecord


class SQLiteRunStore:
    """Thread-safe, indexed SQLite persistence store for simulation runs."""

    def __init__(self, db_path: Path | str = ":memory:") -> None:
        self.db_path = str(db_path)
        if self.db_path != ":memory:":
            Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)

        self._lock = threading.Lock()
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self.init_db()

    def init_db(self) -> None:
        """Create relational schema tables and indexes."""
        with self._lock, self._conn:
            self._conn.executescript("""
                CREATE TABLE IF NOT EXISTS runs (
                    run_id TEXT PRIMARY KEY,
                    created_at TEXT NOT NULL,
                    seed INTEGER NOT NULL,
                    status TEXT NOT NULL,
                    manifest_json TEXT NOT NULL DEFAULT '{}',
                    metadata_json TEXT NOT NULL DEFAULT '{}'
                );

                CREATE TABLE IF NOT EXISTS events (
                    event_id TEXT PRIMARY KEY,
                    run_id TEXT NOT NULL,
                    seq INTEGER NOT NULL,
                    timestamp_utc TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    component TEXT NOT NULL,
                    status TEXT NOT NULL,
                    record_id TEXT,
                    host_id TEXT,
                    rule_id TEXT,
                    finding_id TEXT,
                    reason_code TEXT,
                    details_json TEXT NOT NULL DEFAULT '{}',
                    FOREIGN KEY (run_id) REFERENCES runs (run_id)
                );
                CREATE INDEX IF NOT EXISTS idx_events_run_seq ON events (run_id, seq);

                CREATE TABLE IF NOT EXISTS messages (
                    message_id TEXT PRIMARY KEY,
                    run_id TEXT NOT NULL,
                    seq INTEGER NOT NULL DEFAULT 0,
                    sender TEXT NOT NULL,
                    receiver TEXT NOT NULL,
                    performative TEXT NOT NULL,
                    timestamp_utc TEXT NOT NULL,
                    nonce TEXT NOT NULL,
                    task_id TEXT,
                    payload_sha256 TEXT,
                    signature TEXT,
                    payload_json TEXT NOT NULL DEFAULT '{}',
                    is_accepted INTEGER NOT NULL DEFAULT 1,
                    security_reason_code TEXT NOT NULL DEFAULT 'OK',
                    FOREIGN KEY (run_id) REFERENCES runs (run_id)
                );
                CREATE INDEX IF NOT EXISTS idx_messages_run ON messages (run_id);

                CREATE TABLE IF NOT EXISTS telemetry_records (
                    record_id TEXT PRIMARY KEY,
                    run_id TEXT NOT NULL,
                    host_id TEXT NOT NULL,
                    ip TEXT NOT NULL,
                    port INTEGER NOT NULL,
                    service TEXT NOT NULL,
                    banner TEXT,
                    auth_mode TEXT,
                    tls_version TEXT,
                    is_poisoned INTEGER NOT NULL DEFAULT 0,
                    generated_at TEXT NOT NULL,
                    FOREIGN KEY (run_id) REFERENCES runs (run_id)
                );
                CREATE INDEX IF NOT EXISTS idx_telemetry_run_host
                ON telemetry_records (run_id, host_id);

                CREATE TABLE IF NOT EXISTS findings (
                    finding_id TEXT PRIMARY KEY,
                    run_id TEXT NOT NULL,
                    host_id TEXT NOT NULL,
                    rule_id TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    confidence REAL NOT NULL DEFAULT 1.0,
                    cve_id TEXT,
                    cvss_score REAL,
                    quarantined INTEGER NOT NULL DEFAULT 0,
                    timestamp_utc TEXT NOT NULL,
                    evidence_json TEXT NOT NULL DEFAULT '{}',
                    FOREIGN KEY (run_id) REFERENCES runs (run_id)
                );
                CREATE INDEX IF NOT EXISTS idx_findings_run_host ON findings (run_id, host_id);

                CREATE TABLE IF NOT EXISTS bdi_snapshots (
                    snapshot_id TEXT PRIMARY KEY,
                    run_id TEXT NOT NULL,
                    agent_id TEXT NOT NULL,
                    timestamp_utc TEXT NOT NULL,
                    intention_type TEXT NOT NULL,
                    desire_type TEXT NOT NULL,
                    target_host TEXT NOT NULL,
                    reconsideration_count INTEGER NOT NULL DEFAULT 0,
                    beliefs_json TEXT NOT NULL DEFAULT '{}',
                    FOREIGN KEY (run_id) REFERENCES runs (run_id)
                );
                CREATE INDEX IF NOT EXISTS idx_bdi_run ON bdi_snapshots (run_id);

                CREATE TABLE IF NOT EXISTS llm_calls (
                    call_id TEXT PRIMARY KEY,
                    run_id TEXT NOT NULL,
                    provider TEXT NOT NULL,
                    model TEXT NOT NULL,
                    role TEXT NOT NULL,
                    prompt_excerpt TEXT NOT NULL,
                    response_excerpt TEXT NOT NULL,
                    tokens INTEGER NOT NULL DEFAULT 0,
                    latency_ms REAL NOT NULL DEFAULT 0.0,
                    cached INTEGER NOT NULL DEFAULT 0,
                    timestamp_utc TEXT NOT NULL,
                    FOREIGN KEY (run_id) REFERENCES runs (run_id)
                );
                CREATE INDEX IF NOT EXISTS idx_llm_run ON llm_calls (run_id);
            """)

    def save_run(
        self,
        run_id: str,
        seed: int = 42,
        status: str = "IN_PROGRESS",
        created_at: str = "",
        manifest: dict[str, Any] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """Insert or replace a simulation run record."""
        ts = created_at or "2026-10-21T00:00:00Z"
        m_json = json.dumps(manifest or {})
        meta_json = json.dumps(metadata or {})
        with self._lock, self._conn:
            self._conn.execute(
                """
                INSERT OR REPLACE INTO runs (
                    run_id, created_at, seed, status, manifest_json, metadata_json
                )
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (run_id, ts, seed, status, m_json, meta_json),
            )

    def update_run_status(
        self,
        run_id: str,
        status: str,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """Update run status and metadata."""
        with self._lock, self._conn:
            if metadata is not None:
                meta_json = json.dumps(metadata)
                self._conn.execute(
                    "UPDATE runs SET status = ?, metadata_json = ? WHERE run_id = ?",
                    (status, meta_json, run_id),
                )
            else:
                self._conn.execute(
                    "UPDATE runs SET status = ? WHERE run_id = ?",
                    (status, run_id),
                )

    def save_event(self, event: AgentEvent) -> None:
        """Persist an observable AgentEvent."""
        det_json = json.dumps(event.details)
        stat = event.status.value if hasattr(event.status, "value") else str(event.status)
        etype = (
            event.event_type.value
            if hasattr(event.event_type, "value")
            else str(event.event_type)
        )
        with self._lock, self._conn:
            self._conn.execute(
                """
                INSERT OR REPLACE INTO events (
                    event_id, run_id, seq, timestamp_utc, event_type, component,
                    status, record_id, host_id, rule_id, finding_id, reason_code, details_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event.event_id,
                    event.run_id,
                    event.seq,
                    event.timestamp_utc,
                    etype,
                    event.component,
                    stat,
                    event.record_id,
                    event.host_id,
                    event.rule_id,
                    event.finding_id,
                    event.reason_code,
                    det_json,
                ),
            )

    def save_message(
        self,
        message: Message,
        seq: int = 0,
        is_accepted: bool = True,
        security_reason_code: str = "OK",
    ) -> None:
        """Persist an inter-agent message envelope."""
        p_json = json.dumps(message.payload)
        perf = (
            message.performative.value
            if hasattr(message.performative, "value")
            else str(message.performative)
        )
        with self._lock, self._conn:
            self._conn.execute(
                """
                INSERT OR REPLACE INTO messages (
                    message_id, run_id, seq, sender, receiver, performative,
                    timestamp_utc, nonce, task_id, payload_sha256, signature,
                    payload_json, is_accepted, security_reason_code
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    message.message_id,
                    message.run_id,
                    seq,
                    message.sender,
                    message.receiver,
                    perf,
                    message.timestamp_utc,
                    message.nonce,
                    message.task_id,
                    message.payload_sha256,
                    message.signature,
                    p_json,
                    1 if is_accepted else 0,
                    security_reason_code,
                ),
            )

    def save_telemetry_record(
        self,
        record: TelemetryRecord,
        run_id: str = "",
        is_poisoned: bool = False,
    ) -> None:
        """Persist a normalized telemetry record."""
        auth_val = (
            record.auth_mode.value
            if hasattr(record.auth_mode, "value")
            else str(record.auth_mode)
        )
        with self._lock, self._conn:
            self._conn.execute(
                """
                INSERT OR REPLACE INTO telemetry_records (
                    record_id, run_id, host_id, ip, port, service,
                    banner, auth_mode, tls_version, is_poisoned, generated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    record.record_id,
                    run_id,
                    record.host_id,
                    record.ip,
                    record.port,
                    record.service,
                    record.banner,
                    auth_val,
                    record.tls_version,
                    1 if is_poisoned else 0,
                    record.generated_at,
                ),
            )

    def save_finding(
        self,
        finding: Finding,
        cve_id: str | None = None,
        cvss_score: float | None = None,
        quarantined: bool = False,
    ) -> None:
        """Persist an identified vulnerability finding."""
        ev_json = json.dumps(finding.evidence)
        sev = (
            finding.severity.value
            if hasattr(finding.severity, "value")
            else str(finding.severity)
        )
        ts = (
            getattr(finding, "created_at", None)
            or getattr(finding, "timestamp_utc", None)
            or "2026-10-21T00:00:00Z"
        )
        with self._lock, self._conn:
            self._conn.execute(
                """
                INSERT OR REPLACE INTO findings (
                    finding_id, run_id, host_id, rule_id, severity, confidence,
                    cve_id, cvss_score, quarantined, timestamp_utc, evidence_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    finding.finding_id,
                    finding.run_id,
                    finding.host_id,
                    finding.rule_id,
                    sev,
                    finding.confidence,
                    cve_id,
                    cvss_score,
                    1 if quarantined else 0,
                    ts,
                    ev_json,
                ),
            )

    def save_bdi_snapshot(
        self,
        snapshot_id: str,
        run_id: str,
        agent_id: str,
        timestamp_utc: str,
        intention_type: str,
        desire_type: str,
        target_host: str,
        reconsideration_count: int = 0,
        beliefs: dict[str, Any] | None = None,
    ) -> None:
        """Persist a BDI deliberative state snapshot."""
        b_json = json.dumps(beliefs or {})
        with self._lock, self._conn:
            self._conn.execute(
                """
                INSERT OR REPLACE INTO bdi_snapshots (
                    snapshot_id, run_id, agent_id, timestamp_utc, intention_type,
                    desire_type, target_host, reconsideration_count, beliefs_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    snapshot_id,
                    run_id,
                    agent_id,
                    timestamp_utc,
                    intention_type,
                    desire_type,
                    target_host,
                    reconsideration_count,
                    b_json,
                ),
            )

    def save_llm_call(
        self,
        call_id: str,
        run_id: str,
        provider: str,
        model: str,
        role: str,
        prompt_excerpt: str,
        response_excerpt: str,
        tokens: int = 0,
        latency_ms: float = 0.0,
        cached: bool = False,
        timestamp_utc: str | None = None,
    ) -> None:
        """Persist an advisory LLM call record."""
        ts = timestamp_utc or "2026-10-21T00:00:00Z"
        with self._lock, self._conn:
            self._conn.execute(
                """
                INSERT OR REPLACE INTO llm_calls (
                    call_id, run_id, provider, model, role, prompt_excerpt,
                    response_excerpt, tokens, latency_ms, cached, timestamp_utc
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    call_id,
                    run_id,
                    provider,
                    model,
                    role,
                    prompt_excerpt,
                    response_excerpt,
                    tokens,
                    latency_ms,
                    1 if cached else 0,
                    ts,
                ),
            )

    # -------------------------------------------------------------------------
    # Retrieval Methods
    # -------------------------------------------------------------------------

    def get_run(self, run_id: str) -> dict[str, Any] | None:
        """Retrieve run metadata by run_id."""
        with self._lock:
            cur = self._conn.execute("SELECT * FROM runs WHERE run_id = ?", (run_id,))
            row = cur.fetchone()
            if not row:
                return None
            res = dict(row)
            res["manifest"] = json.loads(res.pop("manifest_json", "{}"))
            res["metadata"] = json.loads(res.pop("metadata_json", "{}"))
            return res

    def list_runs(self) -> list[dict[str, Any]]:
        """List all registered simulation runs."""
        with self._lock:
            cur = self._conn.execute("SELECT * FROM runs ORDER BY created_at DESC")
            runs = []
            for row in cur.fetchall():
                r = dict(row)
                r["manifest"] = json.loads(r.pop("manifest_json", "{}"))
                r["metadata"] = json.loads(r.pop("metadata_json", "{}"))
                runs.append(r)
            return runs

    def get_events(
        self,
        run_id: str,
        from_seq: int = 1,
        limit: int = 1000,
    ) -> list[dict[str, Any]]:
        """Query events by run_id starting from sequence number."""
        with self._lock:
            cur = self._conn.execute(
                """
                SELECT * FROM events
                WHERE run_id = ? AND seq >= ?
                ORDER BY seq ASC
                LIMIT ?
                """,
                (run_id, from_seq, limit),
            )
            events = []
            for row in cur.fetchall():
                e = dict(row)
                e["details"] = json.loads(e.pop("details_json", "{}"))
                events.append(e)
            return events

    def get_event_count(self, run_id: str) -> int:
        """Return total event count for a given run."""
        with self._lock:
            cur = self._conn.execute("SELECT COUNT(*) FROM events WHERE run_id = ?", (run_id,))
            return cur.fetchone()[0]

    def get_messages(self, run_id: str) -> list[dict[str, Any]]:
        """Query all messages for a run."""
        with self._lock:
            cur = self._conn.execute(
                "SELECT * FROM messages WHERE run_id = ? ORDER BY seq ASC, timestamp_utc ASC",
                (run_id,),
            )
            messages = []
            for row in cur.fetchall():
                m = dict(row)
                m["payload"] = json.loads(m.pop("payload_json", "{}"))
                m["is_accepted"] = bool(m["is_accepted"])
                messages.append(m)
            return messages

    def get_telemetry_records(self, run_id: str) -> list[dict[str, Any]]:
        """Query telemetry records for a run."""
        with self._lock:
            cur = self._conn.execute(
                "SELECT * FROM telemetry_records WHERE run_id = ? ORDER BY generated_at ASC",
                (run_id,),
            )
            records = []
            for row in cur.fetchall():
                r = dict(row)
                r["is_poisoned"] = bool(r["is_poisoned"])
                records.append(r)
            return records

    def get_findings(self, run_id: str) -> list[dict[str, Any]]:
        """Query findings for a run."""
        with self._lock:
            cur = self._conn.execute(
                "SELECT * FROM findings WHERE run_id = ? ORDER BY timestamp_utc ASC",
                (run_id,),
            )
            findings = []
            for row in cur.fetchall():
                f = dict(row)
                f["evidence"] = json.loads(f.pop("evidence_json", "{}"))
                f["quarantined"] = bool(f["quarantined"])
                findings.append(f)
            return findings

    def get_bdi_snapshots(self, run_id: str) -> list[dict[str, Any]]:
        """Query BDI deliberative snapshots for a run."""
        with self._lock:
            cur = self._conn.execute(
                "SELECT * FROM bdi_snapshots WHERE run_id = ? ORDER BY timestamp_utc ASC",
                (run_id,),
            )
            snapshots = []
            for row in cur.fetchall():
                s = dict(row)
                s["beliefs"] = json.loads(s.pop("beliefs_json", "{}"))
                snapshots.append(s)
            return snapshots

    def get_llm_calls(self, run_id: str) -> list[dict[str, Any]]:
        """Query advisory LLM calls for a run."""
        with self._lock:
            cur = self._conn.execute(
                "SELECT * FROM llm_calls WHERE run_id = ? ORDER BY timestamp_utc ASC",
                (run_id,),
            )
            calls = []
            for row in cur.fetchall():
                c = dict(row)
                c["cached"] = bool(c["cached"])
                calls.append(c)
            return calls

    # -------------------------------------------------------------------------
    # Parity Verification (HLD §8.5)
    # -------------------------------------------------------------------------

    def verify_parity(self, run_id: str, jsonl_path: Path | str) -> dict[str, Any]:
        """Verify strict parity between SQLite events and exported JSONL trace.

        Enforces HLD §8.5:
        1. count(SQLite events) == count(JSONL lines)
        2. seq sequence is strictly gap-free: [1, 2, ..., N]
        3. event_id and hash alignment across sinks.
        """
        p = Path(jsonl_path)
        jsonl_events: list[dict[str, Any]] = []
        if p.exists():
            with open(p, "r", encoding="utf-8") as f:
                for line in f:
                    stripped = line.strip()
                    if stripped:
                        jsonl_events.append(json.loads(stripped))

        sqlite_events = self.get_events(run_id=run_id, from_seq=1, limit=100000)

        jsonl_count = len(jsonl_events)
        sqlite_count = len(sqlite_events)

        # Check gap-free sequence in SQLite
        seqs = [e["seq"] for e in sqlite_events]
        expected_seqs = list(range(1, sqlite_count + 1))
        has_gaps = seqs != expected_seqs

        # Cross-sink ID alignment
        ids_match = True
        if jsonl_count == sqlite_count:
            for s_evt, j_evt in zip(sqlite_events, jsonl_events, strict=True):
                if s_evt["event_id"] != j_evt.get("event_id") or s_evt["seq"] != j_evt.get("seq"):
                    ids_match = False
                    break
        else:
            ids_match = False

        is_parity_ok = (jsonl_count == sqlite_count) and (not has_gaps) and ids_match

        return {
            "run_id": run_id,
            "parity_passed": is_parity_ok,
            "sqlite_event_count": sqlite_count,
            "jsonl_event_count": jsonl_count,
            "has_seq_gaps": has_gaps,
            "id_alignment": ids_match,
            "total_seqs": sqlite_count,
        }

    def close(self) -> None:
        """Close database connection."""
        with self._lock:
            self._conn.close()
