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
        self._recorder: Any = None
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

                CREATE TABLE IF NOT EXISTS reports (
                    report_id TEXT PRIMARY KEY,
                    run_id TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    window_name TEXT NOT NULL,
                    posture_score INTEGER NOT NULL DEFAULT 100,
                    threat_level TEXT NOT NULL,
                    summary_md TEXT NOT NULL,
                    data_json TEXT NOT NULL DEFAULT '{}',
                    FOREIGN KEY (run_id) REFERENCES runs (run_id)
                );
                CREATE INDEX IF NOT EXISTS idx_reports_run ON reports (run_id);

                CREATE TABLE IF NOT EXISTS ground_truth (
                    record_id TEXT PRIMARY KEY,
                    run_id TEXT NOT NULL,
                    host_id TEXT NOT NULL,
                    cycle INTEGER NOT NULL DEFAULT 1,
                    is_vulnerable INTEGER NOT NULL DEFAULT 0,
                    expected_rules_json TEXT NOT NULL DEFAULT '[]',
                    is_poisoned INTEGER NOT NULL DEFAULT 0,
                    injection_type TEXT,
                    FOREIGN KEY (run_id) REFERENCES runs (run_id)
                );
                CREATE INDEX IF NOT EXISTS idx_ground_truth_run_host
                ON ground_truth (run_id, host_id);

                CREATE TABLE IF NOT EXISTS pending_quarantine (
                    quarantine_id TEXT PRIMARY KEY,
                    run_id TEXT NOT NULL,
                    host_id TEXT NOT NULL,
                    finding_id TEXT NOT NULL,
                    rule_id TEXT NOT NULL,
                    confidence REAL NOT NULL DEFAULT 1.0,
                    remote_exploitable INTEGER NOT NULL DEFAULT 0,
                    status TEXT NOT NULL DEFAULT 'PENDING',
                    decided_by TEXT,
                    decided_at TEXT,
                    created_at TEXT NOT NULL,
                    rationale TEXT NOT NULL DEFAULT '',
                    FOREIGN KEY (run_id) REFERENCES runs (run_id)
                );
                CREATE INDEX IF NOT EXISTS idx_pending_quarantine_run
                ON pending_quarantine (run_id, status);

                CREATE TABLE IF NOT EXISTS bidder_weights (
                    weight_key TEXT PRIMARY KEY,
                    weight_val REAL NOT NULL,
                    updated_at TEXT NOT NULL
                );
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

    def save_report(
        self,
        report_id: str,
        run_id: str,
        created_at: str,
        window_name: str,
        posture_score: int,
        threat_level: str,
        summary_md: str,
        data_json: str = "{}",
    ) -> None:
        """Save a posture & incident analysis report."""
        with self._lock, self._conn:
            self._conn.execute(
                """
                INSERT OR REPLACE INTO reports (
                    report_id, run_id, created_at, window_name, posture_score,
                    threat_level, summary_md, data_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    report_id, run_id, created_at, window_name, posture_score,
                    threat_level, summary_md, data_json,
                ),
            )

    def get_reports(self, run_id: str) -> list[dict[str, Any]]:
        """Retrieve all generated reports for a run ordered newest first."""
        with self._lock:
            cursor = self._conn.execute(
                """
                SELECT report_id, run_id, created_at, window_name, posture_score,
                       threat_level, summary_md, data_json
                FROM reports WHERE run_id = ? ORDER BY created_at DESC
                """,
                (run_id,),
            )
            rows = cursor.fetchall()
            return [
                {
                    "report_id": r[0],
                    "run_id": r[1],
                    "created_at": r[2],
                    "window_name": r[3],
                    "posture_score": r[4],
                    "threat_level": r[5],
                    "summary_md": r[6],
                    "data": json.loads(r[7]) if r[7] else {},
                }
                for r in rows
            ]

    def save_ground_truth(
        self,
        record_id: str,
        run_id: str,
        host_id: str,
        cycle: int = 1,
        is_vulnerable: bool = False,
        expected_rules: list[str] | None = None,
        is_poisoned: bool = False,
        injection_type: str | None = None,
    ) -> None:
        """Persist evaluator-only ground truth for a telemetry record."""
        rules_json = json.dumps(expected_rules or [])
        with self._lock, self._conn:
            self._conn.execute(
                """
                INSERT OR REPLACE INTO ground_truth (
                    record_id, run_id, host_id, cycle,
                    is_vulnerable, expected_rules_json, is_poisoned, injection_type
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    record_id,
                    run_id,
                    host_id,
                    cycle,
                    1 if is_vulnerable else 0,
                    rules_json,
                    1 if is_poisoned else 0,
                    injection_type,
                ),
            )

    def get_ground_truth(self, run_id: str) -> list[dict[str, Any]]:
        """Retrieve evaluator-only ground truth rows for a run."""
        with self._lock:
            cur = self._conn.execute(
                "SELECT * FROM ground_truth WHERE run_id = ? ORDER BY cycle ASC, record_id ASC",
                (run_id,),
            )
            rows = []
            for row in cur.fetchall():
                d = dict(row)
                d["is_vulnerable"] = bool(d["is_vulnerable"])
                d["is_poisoned"] = bool(d["is_poisoned"])
                d["expected_rules"] = json.loads(d.pop("expected_rules_json", "[]"))
                rows.append(d)
            return rows

    def compute_eval_metrics(self, run_id: str) -> dict[str, Any]:
        """Compute detection precision/recall, false-quarantine rate, time-to-contain, and cost/cycle."""
        gt_rows = self.get_ground_truth(run_id)
        findings = self.get_findings(run_id)
        messages = self.get_messages(run_id)
        events = self.get_events(run_id, from_seq=1, limit=100000)

        # 1. Detection Precision & Recall over (host_id, rule_id) pairs
        expected_pairs: set[tuple[str, str]] = set()
        vulnerable_hosts: set[str] = set()
        first_vuln_cycle: dict[str, int] = {}
        all_hosts: set[str] = set()
        max_cycle = 1

        for g in gt_rows:
            hid = g["host_id"]
            cyc = int(g.get("cycle", 1))
            if cyc > max_cycle:
                max_cycle = cyc
            all_hosts.add(hid)
            if g["is_vulnerable"] and not g["is_poisoned"]:
                vulnerable_hosts.add(hid)
                if hid not in first_vuln_cycle or cyc < first_vuln_cycle[hid]:
                    first_vuln_cycle[hid] = cyc
                for r_id in g["expected_rules"]:
                    expected_pairs.add((hid, r_id))

        detected_pairs: set[tuple[str, str]] = {
            (f["host_id"], f["rule_id"]) for f in findings
        }
        tp = len(detected_pairs & expected_pairs)
        fp = len(detected_pairs - expected_pairs)
        fn = len(expected_pairs - detected_pairs)
        precision = tp / (tp + fp) if (tp + fp) > 0 else 1.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 1.0

        # 2. False-Quarantine Rate (quarantined non-vulnerable hosts / total quarantined hosts)
        quarantined_hosts: set[str] = {
            f["host_id"] for f in findings if f.get("quarantined")
        }
        for e in events:
            if e["event_type"] == "run_completed":
                q_list = e["details"].get("quarantined_hosts", [])
                quarantined_hosts.update(q_list)
        false_quarantined = quarantined_hosts - vulnerable_hosts
        false_quarantine_rate = (
            len(false_quarantined) / len(quarantined_hosts)
            if quarantined_hosts
            else 0.0
        )

        # 3. Time-to-Contain (in cycles) for quarantined vulnerable hosts
        contain_cycle: dict[str, int] = {}
        for f in findings:
            if f.get("quarantined"):
                hid = f["host_id"]
                f_cyc = int(f.get("evidence", {}).get("cycle", 1))
                if hid not in contain_cycle or f_cyc < contain_cycle[hid]:
                    contain_cycle[hid] = f_cyc
        ttc_values = [
            max(1, contain_cycle[h] - first_vuln_cycle.get(h, 1) + 1)
            for h in (quarantined_hosts & vulnerable_hosts)
            if h in contain_cycle
        ]
        time_to_contain_cycles = (
            sum(ttc_values) / len(ttc_values) if ttc_values else 0.0
        )

        # 4. Cost per cycle from ACCEPTED proposals
        proposals_by_id: dict[str, float] = {}
        for m in messages:
            if m["performative"] == "PROPOSE":
                prop = m["payload"].get("proposal", {})
                pid = prop.get("proposal_id")
                if pid:
                    proposals_by_id[pid] = float(prop.get("est_cost", 0.0))
        total_cost = 0.0
        accept_count = 0
        for m in messages:
            if m["performative"] == "ACCEPT":
                pid = m["payload"].get("proposal_id")
                total_cost += proposals_by_id.get(pid, 0.0)
                accept_count += 1
        cycles_count = max(max_cycle, accept_count, 1)
        cost_per_cycle = total_cost / cycles_count

        return {
            "detection_precision": round(precision, 4),
            "detection_recall": round(recall, 4),
            "false_quarantine_rate": round(false_quarantine_rate, 4),
            "time_to_contain_cycles": round(time_to_contain_cycles, 4),
            "cost_per_cycle": round(cost_per_cycle, 4),
            "true_positives": tp,
            "false_positives": fp,
            "false_negatives": fn,
            "quarantined_hosts": sorted(quarantined_hosts),
            "cycles": cycles_count,
        }

    def save_pending_quarantine(
        self,
        quarantine_id: str,
        run_id: str,
        host_id: str,
        finding_id: str,
        rule_id: str,
        confidence: float = 1.0,
        remote_exploitable: bool = False,
        status: str = "PENDING",
        decided_by: str | None = None,
        decided_at: str | None = None,
        created_at: str = "2026-10-21T00:00:00Z",
        rationale: str = "",
    ) -> dict[str, Any]:
        """Persist a pending or auto-approved quarantine request."""
        with self._lock, self._conn:
            self._conn.execute(
                """
                INSERT OR REPLACE INTO pending_quarantine (
                    quarantine_id, run_id, host_id, finding_id, rule_id,
                    confidence, remote_exploitable, status, decided_by, decided_at,
                    created_at, rationale
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    quarantine_id,
                    run_id,
                    host_id,
                    finding_id,
                    rule_id,
                    confidence,
                    1 if remote_exploitable else 0,
                    status,
                    decided_by,
                    decided_at,
                    created_at,
                    rationale,
                ),
            )
            if status in ("APPROVED", "AUTO_APPROVED"):
                self._conn.execute(
                    "UPDATE findings SET quarantined = 1 WHERE run_id = ? AND host_id = ?",
                    (run_id, host_id),
                )
        return {
            "quarantine_id": quarantine_id,
            "run_id": run_id,
            "host_id": host_id,
            "finding_id": finding_id,
            "rule_id": rule_id,
            "confidence": confidence,
            "remote_exploitable": remote_exploitable,
            "status": status,
            "decided_by": decided_by,
            "decided_at": decided_at,
            "created_at": created_at,
            "rationale": rationale,
        }

    def get_pending_quarantines(
        self, run_id: str, status: str | None = None
    ) -> list[dict[str, Any]]:
        """Retrieve pending_quarantine records for a run."""
        with self._lock:
            if status:
                cur = self._conn.execute(
                    "SELECT * FROM pending_quarantine WHERE run_id = ? AND status = ? "
                    "ORDER BY created_at DESC",
                    (run_id, status),
                )
            else:
                cur = self._conn.execute(
                    "SELECT * FROM pending_quarantine WHERE run_id = ? ORDER BY created_at DESC",
                    (run_id,),
                )
            rows = []
            for row in cur.fetchall():
                d = dict(row)
                d["remote_exploitable"] = bool(d["remote_exploitable"])
                rows.append(d)
            return rows

    def decide_pending_quarantine(
        self,
        quarantine_id: str,
        decision: str,
        decided_by: str = "human-operator",
        decided_at: str = "2026-10-21T00:00:00Z",
    ) -> dict[str, Any] | None:
        """Approve or reject a pending quarantine record, updating findings and logging an event."""
        norm_dec = decision.upper()
        if norm_dec not in ("APPROVED", "REJECTED", "APPROVE", "REJECT"):
            raise ValueError(f"Invalid quarantine decision: {decision}")
        final_status = "APPROVED" if norm_dec.startswith("APPROV") else "REJECTED"

        with self._lock, self._conn:
            cur = self._conn.execute(
                "SELECT * FROM pending_quarantine WHERE quarantine_id = ?",
                (quarantine_id,),
            )
            row = cur.fetchone()
            if not row:
                return None
            rec = dict(row)
            run_id = rec["run_id"]
            host_id = rec["host_id"]
            finding_id = rec["finding_id"]
            rule_id = rec["rule_id"]

            self._conn.execute(
                """
                UPDATE pending_quarantine
                SET status = ?, decided_by = ?, decided_at = ?
                WHERE quarantine_id = ?
                """,
                (final_status, decided_by, decided_at, quarantine_id),
            )
            if final_status == "APPROVED":
                self._conn.execute(
                    "UPDATE findings SET quarantined = 1 WHERE run_id = ? AND host_id = ?",
                    (run_id, host_id),
                )
            else:
                self._conn.execute(
                    "UPDATE findings SET quarantined = 0 WHERE run_id = ? AND host_id = ?",
                    (run_id, host_id),
                )

            rec["status"] = final_status
            rec["decided_by"] = decided_by
            rec["decided_at"] = decided_at
            rec["remote_exploitable"] = bool(rec["remote_exploitable"])

        evt_details = {
            "quarantine_id": quarantine_id,
            "who": decided_by,
            "what": final_status,
            "when": decided_at,
            "host_id": host_id,
            "finding_id": finding_id,
        }
        if self._recorder is not None and not getattr(self._recorder._file, "closed", True):
            from sentryscan.contracts.events import EventStatus, EventType

            self._recorder.record(
                event_type=EventType.STATE_TRANSITION,
                component=decided_by,
                status=EventStatus.OK if final_status == "APPROVED" else EventStatus.REJECTED,
                host_id=host_id,
                finding_id=finding_id,
                rule_id=rule_id,
                reason_code=f"QUARANTINE_{final_status}",
                details=evt_details,
            )
        else:
            with self._lock, self._conn:
                cur = self._conn.execute(
                    "SELECT COALESCE(MAX(seq), 0) FROM events WHERE run_id = ?", (run_id,)
                )
                next_seq = cur.fetchone()[0] + 1
                self._conn.execute(
                    """
                    INSERT OR REPLACE INTO events (
                        event_id, run_id, seq, timestamp_utc, event_type, component,
                        status, record_id, host_id, rule_id, finding_id, reason_code, details_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        f"evt-{next_seq:06d}",
                        run_id,
                        next_seq,
                        decided_at,
                        "state_transition",
                        decided_by,
                        "OK" if final_status == "APPROVED" else "REJECTED",
                        None,
                        host_id,
                        rule_id,
                        finding_id,
                        f"QUARANTINE_{final_status}",
                        json.dumps(evt_details),
                    ),
                )
        if final_status == "APPROVED":
            from sentryscan.agents.remediator import RemediatorAgent

            host_findings = [
                f for f in self.get_findings(run_id=run_id) if f.get("host_id") == host_id
            ]
            remediator = RemediatorAgent()
            plan = remediator.remediate_and_store(
                store=self,
                run_id=run_id,
                host_id=host_id,
                findings=host_findings,
                recorder=self._recorder,
            )
            rec["remediation_report_id"] = plan["report_id"]
        return rec

    def save_bidder_weights(
        self, weights: dict[str, float], updated_at: str = "2026-10-21T00:00:00Z"
    ) -> None:
        """Persist Triage port weights and Scout coverage weight in SQLite."""
        with self._lock, self._conn:
            for k, v in weights.items():
                self._conn.execute(
                    """
                    INSERT OR REPLACE INTO bidder_weights (weight_key, weight_val, updated_at)
                    VALUES (?, ?, ?)
                    """,
                    (str(k), float(v), updated_at),
                )

    def get_bidder_weights(self) -> dict[str, float]:
        """Retrieve persisted bidder weights from SQLite."""
        with self._lock:
            cur = self._conn.execute("SELECT weight_key, weight_val FROM bidder_weights")
            return {str(row["weight_key"]): float(row["weight_val"]) for row in cur.fetchall()}

    def close(self) -> None:
        """Close database connection."""
        with self._lock:
            self._conn.close()
