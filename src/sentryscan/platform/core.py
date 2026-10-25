"""Industry-agnostic platform layer: asset inventory, simulated RADAR discovery, remediation, settings.

All RADAR content is SYNTHETIC: seeded text is planted in simulated data sources and then classified
by the profile's regex policies. Nothing here touches real files or cloud accounts.
"""

from __future__ import annotations

import json
import random
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

PROFILE_DIR = Path("fixtures/profiles")

DDL = """
CREATE TABLE IF NOT EXISTS assets (run_id TEXT, host_id TEXT, asset_type TEXT, label TEXT, ip TEXT,
  os_family TEXT, provider TEXT, category TEXT, simulated INTEGER DEFAULT 1, PRIMARY KEY (run_id, host_id));
CREATE TABLE IF NOT EXISTS data_sources (source_id TEXT PRIMARY KEY, run_id TEXT, host_id TEXT, name TEXT,
  exposure TEXT, encrypted INTEGER, last_scan TEXT);
CREATE TABLE IF NOT EXISTS data_findings (df_id TEXT PRIMARY KEY, run_id TEXT, source_id TEXT, host_id TEXT,
  classification TEXT, severity TEXT, matches INTEGER, sample TEXT, exposure TEXT, encrypted INTEGER,
  detected_at TEXT, scan_id TEXT);
CREATE TABLE IF NOT EXISTS radar_scans (scan_id TEXT PRIMARY KEY, run_id TEXT, started_at TEXT, sources INTEGER,
  findings INTEGER);
CREATE TABLE IF NOT EXISTS remediation_tasks (task_id TEXT PRIMARY KEY, run_id TEXT, kind TEXT, ref_id TEXT,
  host_id TEXT, title TEXT, owner TEXT, status TEXT, created_at TEXT, updated_at TEXT);
CREATE TABLE IF NOT EXISTS pulse_history (run_id TEXT, ts TEXT, passing INTEGER, failing INTEGER, unknown INTEGER,
  evidence_required INTEGER, score INTEGER);
CREATE TABLE IF NOT EXISTS settings (run_id TEXT, key TEXT, value TEXT, PRIMARY KEY (run_id, key));
CREATE TABLE IF NOT EXISTS scenarios (scenario_id TEXT PRIMARY KEY, name TEXT, config_json TEXT, status TEXT,
  result_json TEXT, created_at TEXT);
"""

SEV_RANK = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def ensure_tables(store: Any) -> None:
    with store._lock, store._conn:
        store._conn.executescript(DDL)


def q(store: Any, sql: str, args: tuple = ()) -> list[dict[str, Any]]:
    with store._lock:
        return [dict(r) for r in store._conn.execute(sql, args).fetchall()]


def run(store: Any, sql: str, args: tuple = ()) -> None:
    with store._lock, store._conn:
        store._conn.execute(sql, args)


# ---------------------------------------------------------------- profiles
def _read(name: str) -> dict[str, Any]:
    path = PROFILE_DIR / f"{name}.json"
    if not path.exists():
        # Fall back to generic if custom or UI profile name is not found
        generic_path = PROFILE_DIR / "generic.json"
        if generic_path.exists():
            return json.loads(generic_path.read_text(encoding="utf-8"))
        raise FileNotFoundError(f"Profile '{name}' and fallback 'generic' not found in {PROFILE_DIR}")
    return json.loads(path.read_text(encoding="utf-8"))


def load_profile(name: str = "generic") -> dict[str, Any]:
    """Load a profile, merging 'extends' parents: lists are concatenated, framework mappings merged by id."""
    data = _read(name)
    if "extends" not in data:
        return data
    base = load_profile(data["extends"])
    base["profile"], base["name"] = data["profile"], data.get("name", base["name"])
    base["classifications"] = base["classifications"] + data.get("classifications", [])
    base["controls"] = base["controls"] + data.get("controls", [])
    for fw in data.get("frameworks", []):
        tgt = next((f for f in base["frameworks"] if f["id"] == fw["id"]), None)
        if tgt:
            tgt["mappings"].update(fw.get("mappings", {}))
        else:
            base["frameworks"].append(fw)
    return base


def list_profiles() -> list[str]:
    return sorted(p.stem for p in PROFILE_DIR.glob("*.json"))


def get_setting(store: Any, run_id: str, key: str, default: str = "") -> str:
    rows = q(store, "SELECT value FROM settings WHERE run_id=? AND key=?", (run_id, key))
    return rows[0]["value"] if rows else default


def set_setting(store: Any, run_id: str, key: str, value: str) -> None:
    run(store, "INSERT OR REPLACE INTO settings VALUES (?,?,?)", (run_id, key, value))


def active_profile(store: Any, run_id: str) -> dict[str, Any]:
    return load_profile(get_setting(store, run_id, "profile", "generic"))


# ---------------------------------------------------------------- RADAR
def classify(text: str, policies: list[dict[str, Any]]) -> dict[str, tuple[int, str]]:
    """Return {classification_id: (match_count, first_match)} for a text blob."""
    out: dict[str, tuple[int, str]] = {}
    for pol in policies:
        hits: list[str] = []
        for pat in pol["patterns"]:
            hits += [m.group(0) for m in re.finditer(pat, text)]
        if hits:
            out[pol["id"]] = (len(hits), hits[0])
    return out


def redact(s: str) -> str:
    return "*" * max(0, len(s) - 4) + s[-4:]


def _content(rng: random.Random, policies: list[dict[str, Any]]) -> str:
    """Synthetic document body: benign noise plus 0-3 planted sensitive snippets."""
    lines = [rng.choice(["Meeting notes", "Weekly status update", "Draft agenda", "Lunch menu"])
             for _ in range(rng.randint(1, 3))]
    for pol in rng.sample(policies, k=rng.choice([0, 0, 1, 1, 2, 3])):
        lines.append(rng.choice(pol["samples"]))
    rng.shuffle(lines)
    return "\n".join(lines)


def bootstrap(store: Any, run_id: str, templates: list[Any], seed: int = 42, profile: str = "generic") -> None:
    """Register assets, plant simulated data sources and run the first RADAR scan."""
    from sentryscan.simulation.asset_types import ASSET_TYPES

    ensure_tables(store)
    set_setting(store, run_id, "profile", profile)
    set_setting(store, run_id, "framework", "baseline")
    rng = random.Random(seed ^ 0xDA7A)
    for t in templates:
        at = ASSET_TYPES.get(t.persona)
        run(store, "INSERT OR REPLACE INTO assets VALUES (?,?,?,?,?,?,?,?,1)",
            (run_id, t.host_id, t.persona, t.label, t.ip, t.os_family,
             at.provider if at else "unknown", at.category if at else "endpoint"))
        for n, name in enumerate(at.data_sources if at else ()):
            run(store, "INSERT OR REPLACE INTO data_sources VALUES (?,?,?,?,?,?,?)",
                (f"src-{run_id}-{t.host_id}-{n}", run_id, t.host_id, name,
                 rng.choices(["private", "internal", "public"], [5, 3, 2])[0],
                 int(rng.random() < 0.7), None))
    scan(store, run_id, seed)


def ensure_bootstrapped(store: Any, run_id: str) -> None:
    """Auto-populate assets & simulated RADAR for legacy/capstone runs that only wrote telemetry_records."""
    from sentryscan.simulation.asset_types import ASSET_TYPES
    from sentryscan.simulation.human_traffic import HumanWorkstationTemplate

    ensure_tables(store)
    if q(store, "SELECT 1 FROM assets WHERE run_id=? LIMIT 1", (run_id,)):
        return
    recs = store.get_telemetry_records(run_id)
    if not recs:
        return
    hosts: dict[str, str] = {}
    for r in recs:
        hosts.setdefault(r["host_id"], r["ip"])
    keys = list(ASSET_TYPES.keys())
    templates = []
    for idx, (hid, ip) in enumerate(sorted(hosts.items())):
        matched = next((k for k in keys if hid.startswith(k.replace("_", "-"))), keys[idx % len(keys)])
        at = ASSET_TYPES[matched]
        ports = [s.port for s in at.services]
        templates.append(HumanWorkstationTemplate(
            host_id=hid, label=f"{at.label} ({hid})", os_family=at.os_family, persona=matched,
            ip=ip, services=list(at.services), primary_workflow=at.workflow,
            typical_active_ports=ports, typical_idle_ports=ports[:1],
        ))
    bootstrap(store, run_id, templates, seed=42, profile="generic")



def scan(store: Any, run_id: str, seed: int = 0) -> dict[str, Any]:
    """One simulated RADAR scan: re-draw content for every source, classify, replace its findings."""
    policies = active_profile(store, run_id)["classifications"]
    sev = {p["id"]: p["severity"] for p in policies}
    n_prev = q(store, "SELECT COUNT(*) AS n FROM radar_scans WHERE run_id=?", (run_id,))[0]["n"]
    rng = random.Random(seed * 7919 + n_prev)
    scan_id, ts = f"scan-{run_id}-{n_prev + 1:03d}", now_iso()
    sources = q(store, "SELECT * FROM data_sources WHERE run_id=?", (run_id,))
    total = 0
    for s in sources:
        run(store, "DELETE FROM data_findings WHERE source_id=?", (s["source_id"],))
        hit = classify(_content(rng, policies), policies)
        for cid, (count, sample) in hit.items():
            base = sev.get(cid, "MEDIUM")
            risk = "CRITICAL" if s["exposure"] == "public" and SEV_RANK[base] >= 3 else base
            run(store, "INSERT INTO data_findings VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (f"df-{uuid.uuid4().hex[:8]}", run_id, s["source_id"], s["host_id"], cid, risk, count,
                 redact(sample), s["exposure"], s["encrypted"], ts, scan_id))
            total += 1
        run(store, "UPDATE data_sources SET last_scan=? WHERE source_id=?", (ts, s["source_id"]))
    run(store, "INSERT INTO radar_scans VALUES (?,?,?,?,?)", (scan_id, run_id, ts, len(sources), total))
    return {"scan_id": scan_id, "sources": len(sources), "findings": total}


def radar_summary(store: Any, run_id: str) -> dict[str, Any]:
    ensure_bootstrapped(store, run_id)
    return {
        "sources": q(store, "SELECT s.*, a.label, a.asset_type FROM data_sources s LEFT JOIN assets a "
                            "ON a.run_id=s.run_id AND a.host_id=s.host_id WHERE s.run_id=?", (run_id,)),
        "findings": q(store, "SELECT * FROM data_findings WHERE run_id=? ORDER BY detected_at DESC", (run_id,)),
        "scans": q(store, "SELECT * FROM radar_scans WHERE run_id=? ORDER BY started_at DESC", (run_id,)),
        "policies": [{k: p[k] for k in ("id", "name", "severity", "patterns")}
                     for p in active_profile(store, run_id)["classifications"]],
        "synthetic": True,
    }


# ---------------------------------------------------------------- remediation
def ensure_task(store: Any, run_id: str, kind: str, ref_id: str, host_id: str, title: str) -> str:
    rows = q(store, "SELECT task_id FROM remediation_tasks WHERE run_id=? AND kind=? AND ref_id=? AND status!='DONE'",
             (run_id, kind, ref_id))
    if rows:
        return rows[0]["task_id"]
    tid, ts = f"task-{uuid.uuid4().hex[:8]}", now_iso()
    run(store, "INSERT INTO remediation_tasks VALUES (?,?,?,?,?,?,?,?,?,?)",
        (tid, run_id, kind, ref_id, host_id, title, "unassigned", "OPEN", ts, ts))
    return tid


def update_task(store: Any, run_id: str, task_id: str, status: str | None, owner: str | None) -> dict[str, Any]:
    rows = q(store, "SELECT * FROM remediation_tasks WHERE run_id=? AND task_id=?", (run_id, task_id))
    if not rows:
        raise KeyError(task_id)
    t = rows[0]
    status = (status or t["status"]).upper()
    if status not in ("OPEN", "IN_PROGRESS", "DONE"):
        raise ValueError("status must be OPEN, IN_PROGRESS or DONE")
    run(store, "UPDATE remediation_tasks SET status=?, owner=?, updated_at=? WHERE task_id=?",
        (status, owner or t["owner"], now_iso(), task_id))
    if status == "DONE" and t["kind"] == "radar":  # fixing the source: private + encrypted; rescan clears exposure
        run(store, "UPDATE data_sources SET exposure='private', encrypted=1 WHERE source_id=?", (t["ref_id"],))
        scan(store, run_id)
    return q(store, "SELECT * FROM remediation_tasks WHERE task_id=?", (task_id,))[0]


def list_scenarios(store: Any) -> list[dict[str, Any]]:
    ensure_tables(store)
    rows = q(store, "SELECT * FROM scenarios ORDER BY created_at DESC")
    for r in rows:
        r["config"] = json.loads(r.pop("config_json", "{}"))
        r["result"] = json.loads(r.pop("result_json", "{}"))
    return rows


def execute_scenario_in_store(
    store: Any,
    name: str,
    fleet_spec: str | None = None,
    total_devices: int = 6,
    cycles: int = 4,
    seed: int = 42,
    poison_ratio: float = 0.2,
    industry: str = "generic",
) -> dict[str, Any]:
    """Execute a deterministic typed-fleet scenario into the active SQLiteRunStore."""
    from sentryscan.agents.analyst import AnalystAgent
    from sentryscan.common.clock import SystemClock
    from sentryscan.common.id_generator import IdGenerator
    from sentryscan.contracts.events import EventStatus, EventType
    from sentryscan.graphs.supervisor import build_supervisor_graph
    from sentryscan.integrity.checker import IntegrityChecker
    from sentryscan.knowledge.enricher import KnowledgeEnricher
    from sentryscan.knowledge.ontology import VulnerabilityKnowledgeBase
    from sentryscan.llm.deterministic import DeterministicLLMProvider
    from sentryscan.observability.recorder import EventRecorder
    from sentryscan.security.gate import SecurityGate
    from sentryscan.security.identity import AgentIdentity
    from sentryscan.security.registry import TrustedAgentRegistry
    from sentryscan.simulation.asset_types import build_templates, resolve_fleet
    from sentryscan.simulation.fleet import DeviceFleetSimulator
    from sentryscan.simulation.human_traffic import HumanTrafficGenerator

    ensure_tables(store)
    sid = f"scen-{uuid.uuid4().hex[:6]}"
    run_id = f"run-{sid}"
    clk = SystemClock()
    id_gen = IdGenerator(seed=seed)
    base_off = (len(q(store, "SELECT run_id FROM runs")) + 1) * 100000
    id_gen._counters = {k: base_off for k in ("record", "finding", "event", "task", "proposal", "message", "snap")}
    types = resolve_fleet(fleet_spec, total_devices, seed)
    templates = build_templates(types)

    trace_dir = Path("data/scenarios")
    trace_dir.mkdir(parents=True, exist_ok=True)
    trace_path = trace_dir / f"{run_id}.jsonl"
    recorder = EventRecorder(run_id=run_id, output_path=trace_path, clock=clk, sqlite_store=store)

    cfg = {
        "name": name,
        "fleet_spec": fleet_spec or "",
        "resolved_types": types,
        "total_devices": len(templates),
        "cycles": cycles,
        "seed": seed,
        "poison_ratio": poison_ratio,
        "industry": industry,
    }
    store.save_run(run_id=run_id, seed=seed, status="RUNNING", created_at=clk.now_iso(), manifest=cfg)
    recorder.record(event_type=EventType.RUN_STARTED, component="supervisor", details={"manifest": cfg})
    bootstrap(store, run_id, templates, seed=seed, profile=industry)

    agent_names = ("supervisor-agent", "scout-agent", "triage-agent",
                   "analyst-l1-triage", "analyst-l2-incident", "analyst-l3-containment")
    ids = {n: AgentIdentity.generate(n) for n in agent_names}
    reg = TrustedAgentRegistry()
    for i in ids.values():
        reg.register(i.agent_id, i.public_key_hex, description=i.agent_id)
    kb = VulnerabilityKnowledgeBase.load_from_file()
    tiers = {
        t: AnalystAgent(
            agent_id=aid, tier=t, clock=clk, id_gen=id_gen,
            enricher=KnowledgeEnricher(ontology=kb, enable_online_nvd=False),
            security_gate=SecurityGate(agent_id=aid, registry=reg, clock=clk, freshness_window_seconds=30.0),
        )
        for t, aid in (("L1", "analyst-l1-triage"), ("L2", "analyst-l2-incident"), ("L3", "analyst-l3-containment"))
    }
    graph = build_supervisor_graph(
        clock=clk, id_gen=id_gen, llm_provider=DeterministicLLMProvider(),
        analyst_tiers=tiers, analyst_identities=ids, supervisor_identity=ids["supervisor-agent"], max_rounds=4,
    )
    fleet = DeviceFleetSimulator(device_count=len(templates), seed=seed, clock=clk, id_gen=id_gen, templates=templates)
    hgen = HumanTrafficGenerator(templates=templates, device_count=len(templates), seed=seed,
                                 clock=clk, id_gen=id_gen, poison_ratio=poison_ratio)
    checker = IntegrityChecker(clock=clk)
    for rec in fleet.generate_fleet_cycle():
        store.save_telemetry_record(rec, run_id=run_id, is_poisoned=False)
        checker.check_record(rec)

    quarantined: set[str] = set()
    total_records = 0
    rejected = 0
    for cycle in range(1, cycles + 1):
        burst = hgen.plan_next_human_burst()
        clean = []
        for rec, truth, is_p, inj_type in hgen.generate_burst_records(burst):
            total_records += 1
            store.save_ground_truth(
                record_id=rec.record_id, run_id=run_id, host_id=rec.host_id, cycle=cycle,
                is_vulnerable=truth["is_vulnerable"], expected_rules=truth["expected_rules"],
                is_poisoned=is_p, injection_type=inj_type,
            )
            recorder.record(event_type=EventType.RECORD_RECEIVED, component="fleet_sensor",
                            record_id=rec.record_id, host_id=rec.host_id,
                            details={"service": rec.service, "port": rec.port, "is_poisoned": is_p})
            flags = checker.check_record(rec)
            if flags:
                rejected += 1
                store.save_telemetry_record(rec, run_id=run_id, is_poisoned=True)
                recorder.record(event_type=EventType.RECORD_REJECTED, component="integrity_checker",
                                status=EventStatus.REJECTED, record_id=rec.record_id, host_id=rec.host_id,
                                reason_code=flags[0].reason_code.value)
            else:
                store.save_telemetry_record(rec, run_id=run_id, is_poisoned=False)
                clean.append(rec)
        if len(clean) < 2:
            continue
        half = len(clean) // 2
        st = graph.invoke({
            "run_id": run_id, "task_id": id_gen.next_id("task"),
            "batches": {"batch-alpha": [r.model_dump() for r in clean[:half]],
                        "batch-beta": [r.model_dump() for r in clean[half:]]},
            "constraints": {"max_cost": 150.0, "max_time": 600.0},
            "messages": [], "findings": [], "analyst_replies": [], "quarantined_hosts": [], "errors": [],
        })
        for msg in st.get("messages", []):
            store.save_message(msg)
            recorder.record(event_type=EventType.MESSAGE_SENT, component=msg.sender,
                            details={"receiver": msg.receiver, "performative": msg.performative.value,
                                     "message_id": msg.message_id, "payload": msg.payload})
        q_now = set(st.get("quarantined_hosts", []))
        quarantined |= q_now
        for f in st.get("findings", []):
            store.save_finding(f, cve_id=f.evidence.get("cve_id") if f.evidence else None, quarantined=f.host_id in q_now)
            recorder.record(event_type=EventType.FINDING_CREATED, component="scanner_worker",
                            host_id=f.host_id, finding_id=f.finding_id, rule_id=f.rule_id,
                            details={"severity": f.severity.value, "quarantined": f.host_id in q_now})
        for pq in st.get("pending_quarantines", []):
            store.save_pending_quarantine(**pq)

    recorder.record(event_type=EventType.RUN_COMPLETED, component="supervisor", status=EventStatus.OK)
    eval_metrics = store.compute_eval_metrics(run_id)
    res = {
        "run_id": run_id,
        "total_records": total_records,
        "rejected": rejected,
        "findings": len(store.get_findings(run_id)),
        "quarantined_hosts": sorted(quarantined),
        "eval_metrics": eval_metrics,
    }
    store.update_run_status(run_id=run_id, status="COMPLETED", metadata=res)
    run(store, "INSERT OR REPLACE INTO scenarios VALUES (?,?,?,?,?,?)",
        (sid, name, json.dumps(cfg), "COMPLETED", json.dumps(res), now_iso()))
    return {"scenario_id": sid, "name": name, "config": cfg, "status": "COMPLETED", "result": res}

