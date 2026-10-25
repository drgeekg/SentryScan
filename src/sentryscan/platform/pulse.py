"""Pulse control evaluation, overview aggregation, incident and asset drill-down."""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from sentryscan.analysis.report_generator import correlate_incidents
from sentryscan.platform import core
from sentryscan.platform.core import SEV_RANK, active_profile, ensure_task, get_setting, q, run

STATUSES = ("PASS", "FAIL", "UNKNOWN", "EVIDENCE_REQUIRED")


def _ts(s: str | None) -> datetime | None:
    try:
        return datetime.fromisoformat(str(s).replace("Z", "+00:00"))
    except Exception:
        return None


def _ref_time(store: Any, run_id: str) -> datetime:
    r = q(store, "SELECT MAX(timestamp_utc) AS t FROM events WHERE run_id=?", (run_id,))[0]["t"]
    return _ts(r) or datetime.now().astimezone()


def _distinct(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: dict[tuple[str, str], dict[str, Any]] = {}
    for f in findings:
        seen[(f["host_id"], f["rule_id"])] = f  # latest wins (rows are time-ordered)
    return list(seen.values())


def evaluate_controls(store: Any, run_id: str, record_history: bool = True) -> list[dict[str, Any]]:
    core.ensure_bootstrapped(store, run_id)
    prof = active_profile(store, run_id)
    fw_id = get_setting(store, run_id, "framework", "baseline")
    fw = next((f for f in prof["frameworks"] if f["id"] == fw_id), prof["frameworks"][0])
    window = int(prof.get("evidence_freshness_seconds", 3600))
    ref = _ref_time(store, run_id)
    findings = _distinct(store.get_findings(run_id))
    telem = q(store, "SELECT COUNT(*) AS n, MAX(generated_at) AS t FROM telemetry_records WHERE run_id=?", (run_id,))[0]
    ev = q(store, "SELECT SUM(event_type='record_received') AS rx, SUM(event_type='record_rejected') AS rj, "
                  "MAX(timestamp_utc) AS t FROM events WHERE run_id=?", (run_id,))[0]
    dfs = q(store, "SELECT * FROM data_findings WHERE run_id=?", (run_id,))
    sources = q(store, "SELECT * FROM data_sources WHERE run_id=?", (run_id,))
    scans = q(store, "SELECT * FROM radar_scans WHERE run_id=? ORDER BY started_at DESC", (run_id,))
    out: list[dict[str, Any]] = []

    def fresh(t: str | None) -> bool:
        d = _ts(t)
        return bool(d and abs((ref - d).total_seconds()) <= window)

    for c in prof["controls"]:
        chk, evid, hosts, fids, tasks_ref = c["check"], [], [], [], c["id"]
        status, reason = "UNKNOWN", "No evidence collected yet."
        if chk["type"] == "rules":
            bad = [f for f in findings if f["rule_id"] in chk["rules"]]
            hosts = sorted({f["host_id"] for f in bad})
            fids = [f["finding_id"] for f in bad]
            evid = [{"source": "VIGIL", "kind": "finding", "ref": f["finding_id"], "host_id": f["host_id"],
                     "timestamp": f["timestamp_utc"], "fresh": fresh(f["timestamp_utc"]),
                     "summary": f"{f['rule_id']} on {f['host_id']} ({f['severity']})"} for f in bad]
            if bad:
                status, reason = "FAIL", f"{len(bad)} open finding(s) on {len(hosts)} asset(s)."
            elif not telem["n"]:
                status, reason = "UNKNOWN", "No telemetry has been assessed."
            else:
                evid = [{"source": "VIGIL", "kind": "telemetry", "ref": f"{telem['n']} records", "host_id": None,
                         "timestamp": telem["t"], "fresh": fresh(telem["t"]),
                         "summary": f"{telem['n']} telemetry records assessed, no matching rule fired"}]
                status = "PASS" if evid[0]["fresh"] else "EVIDENCE_REQUIRED"
                reason = "No violations in assessed telemetry." if status == "PASS" else "Evidence is stale."
        elif chk["type"] in ("radar_exposure", "radar_unencrypted"):
            only = set(chk.get("classifications", []))
            rows = [d for d in dfs if not only or d["classification"] in only]
            if chk["type"] == "radar_exposure":
                bad = [d for d in rows if d["exposure"] == "public"]
            else:
                bad = [d for d in rows if not d["encrypted"] and SEV_RANK.get(d["severity"], 0) >= 3]
            hosts = sorted({d["host_id"] for d in bad})
            fids = [d["df_id"] for d in bad]
            evid = [{"source": "SENTRA", "kind": "data_finding", "ref": d["df_id"], "host_id": d["host_id"],
                     "timestamp": d["detected_at"], "fresh": fresh(d["detected_at"]),
                     "summary": f"{d['classification']} x{d['matches']} in {d['exposure']} source"} for d in bad]
            if not sources or not scans:
                status, reason = "EVIDENCE_REQUIRED", "No SENTRA scan has run."
            elif bad:
                status, reason = "FAIL", f"{len(bad)} classified finding(s) violate this control."
            else:
                evid = [{"source": "SENTRA", "kind": "scan", "ref": scans[0]["scan_id"], "host_id": None,
                         "timestamp": scans[0]["started_at"], "fresh": fresh(scans[0]["started_at"]),
                         "summary": f"Scan {scans[0]['scan_id']} covered {scans[0]['sources']} sources"}]
                status = "PASS" if evid[0]["fresh"] else "EVIDENCE_REQUIRED"
                reason = "No violations in latest scan." if status == "PASS" else "Last scan is stale: rescan."
        elif chk["type"] == "integrity":
            rx, rj = ev["rx"] or 0, ev["rj"] or 0
            if rx:
                ratio = rj / rx
                status = "PASS" if ratio <= chk.get("max_reject_ratio", 0.5) else "FAIL"
                reason = f"{rj}/{rx} records rejected ({ratio:.0%}), threshold {chk.get('max_reject_ratio', 0.5):.0%}."
                evid = [{"source": "VIGIL", "kind": "integrity", "ref": "integrity_checker", "host_id": None,
                         "timestamp": ev["t"], "fresh": fresh(ev["t"]), "summary": reason}]
        out.append({
            "id": c["id"], "name": c["name"], "category": c["category"], "description": c["description"],
            "status": status, "reason": reason, "evidence": evid[:50], "affected_hosts": hosts,
            "finding_refs": fids[:50], "framework_ref": fw["mappings"].get(c["id"]),
            "frameworks": {f["id"]: f["mappings"].get(c["id"]) for f in prof["frameworks"]},
        })
        if status == "FAIL":
            tid = ensure_task(store, run_id, "pulse", tasks_ref, hosts[0] if hosts else "", f"Remediate {c['id']}: {c['name']}")
            out[-1]["task_id"] = tid
            if chk["type"].startswith("radar"):  # one fixable task per offending data source
                for sid in sorted({d["source_id"] for d in bad}):
                    h = next(d["host_id"] for d in bad if d["source_id"] == sid)
                    ensure_task(store, run_id, "radar", sid, h, f"Secure data source {sid} (private + encrypted)")
    for c in out:
        c.setdefault("task_id", None)
    if record_history:
        _history(store, run_id, out)
    return out


def _score(controls: list[dict[str, Any]]) -> int:
    return round(100 * sum(c["status"] == "PASS" for c in controls) / max(1, len(controls)))


def _history(store: Any, run_id: str, controls: list[dict[str, Any]]) -> None:
    last = q(store, "SELECT ts FROM pulse_history WHERE run_id=? ORDER BY ts DESC LIMIT 1", (run_id,))
    now = core.now_iso()
    d_last, d_now = _ts(last[0]["ts"]) if last else None, _ts(now)
    if d_last and d_now and (d_now - d_last).total_seconds() < 20:
        return
    n = {s: sum(c["status"] == s for c in controls) for s in STATUSES}
    run(store, "INSERT INTO pulse_history VALUES (?,?,?,?,?,?,?)",
        (run_id, now, n["PASS"], n["FAIL"], n["UNKNOWN"], n["EVIDENCE_REQUIRED"], _score(controls)))


def pulse_summary(store: Any, run_id: str) -> dict[str, Any]:
    prof = active_profile(store, run_id)
    controls = evaluate_controls(store, run_id)
    tasks = q(store, "SELECT * FROM remediation_tasks WHERE run_id=? ORDER BY created_at DESC", (run_id,))
    return {
        "profile": prof["profile"], "profile_name": prof["name"],
        "available_profiles": core.list_profiles(),
        "framework": get_setting(store, run_id, "framework", "baseline"),
        "frameworks": [{"id": f["id"], "name": f["name"], "illustrative": f.get("illustrative", False)}
                       for f in prof["frameworks"]],
        "controls": controls, "tasks": tasks,
        "history": q(store, "SELECT * FROM pulse_history WHERE run_id=? ORDER BY ts ASC", (run_id,))[-60:],
        "score": _score(controls),
    }


def incidents(store: Any, run_id: str) -> list[dict[str, Any]]:
    fs = _distinct(store.get_findings(run_id))
    quarantined = {f["host_id"] for f in store.get_findings(run_id) if f.get("quarantined")}
    incs = correlate_incidents(fs, quarantined)
    for i in incs:
        i["incident_id"] = f"INC-{i['host_id']}"
    return incs


def overview(store: Any, run_id: str) -> dict[str, Any]:
    fs = _distinct(store.get_findings(run_id))
    sev = {s: sum(str(f["severity"]).upper() == s for f in fs) for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW")}
    controls = evaluate_controls(store, run_id)
    dfs = q(store, "SELECT * FROM data_findings WHERE run_id=?", (run_id,))
    incs = incidents(store, run_id)
    tasks = q(store, "SELECT * FROM remediation_tasks WHERE run_id=? AND status!='DONE'", (run_id,))
    penalty = 12 * sev["CRITICAL"] + 6 * sev["HIGH"] + 3 * sev["MEDIUM"] + sev["LOW"]
    ev = q(store, "SELECT * FROM events WHERE run_id=? ORDER BY seq DESC LIMIT 12", (run_id,))
    for e in ev:
        e["details"] = json.loads(e.pop("details_json", "{}"))
    fresh_n = sum(1 for c in controls for e in c["evidence"] if e["fresh"])
    all_n = sum(len(c["evidence"]) for c in controls)
    return {
        "security_score": max(0, 100 - min(100, penalty)),
        "severity": sev,
        "incidents": {"total": len(incs), "active": sum(not i["quarantined"] for i in incs),
                      "contained": sum(i["quarantined"] for i in incs), "top": incs[:5]},
        "compliance": {"score": _score(controls),
                       **{s.lower(): sum(c["status"] == s for c in controls) for s in STATUSES}},
        "evidence_freshness": round(100 * fresh_n / all_n) if all_n else 100,
        "exposure": {"findings": len(dfs), "public": sum(d["exposure"] == "public" for d in dfs),
                     "unencrypted": sum(not d["encrypted"] for d in dfs),
                     "by_class": {c: sum(d["classification"] == c for d in dfs) for c in sorted({d["classification"] for d in dfs})}},
        "assets": q(store, "SELECT COUNT(*) AS n FROM assets WHERE run_id=?", (run_id,))[0]["n"],
        "remediation": {"open": len(tasks), "in_progress": sum(t["status"] == "IN_PROGRESS" for t in tasks)},
        "recent_events": ev,
        "failing_controls": [c for c in controls if c["status"] == "FAIL"][:6],
    }


def asset_list(store: Any, run_id: str) -> list[dict[str, Any]]:
    core.ensure_bootstrapped(store, run_id)
    assets = q(store, "SELECT * FROM assets WHERE run_id=?", (run_id,))
    fs = _distinct(store.get_findings(run_id))
    quarantined = {f["host_id"] for f in store.get_findings(run_id) if f.get("quarantined")}
    dfs = q(store, "SELECT host_id, COUNT(*) AS n FROM data_findings WHERE run_id=? GROUP BY host_id", (run_id,))
    dmap = {d["host_id"]: d["n"] for d in dfs}

    crit_map = {
        "network": "CRITICAL",
        "server": "CRITICAL",
        "cloud": "HIGH",
        "saas": "HIGH",
        "endpoint": "MEDIUM",
        "iot": "LOW",
    }

    for a in assets:
        mine = [f for f in fs if f["host_id"] == a["host_id"]]
        a["findings"] = len(mine)
        a["max_severity"] = max((f["severity"] for f in mine), key=lambda s: SEV_RANK.get(s, 0), default=None)
        a["data_findings"] = dmap.get(a["host_id"], 0)
        a["quarantined"] = a["host_id"] in quarantined
        a["os"] = a.get("os_family") or "unknown"
        cat = (a.get("category") or "endpoint").lower()
        a["criticality"] = crit_map.get(cat, "MEDIUM")

        if a["quarantined"]:
            a["status"] = "QUARANTINED"
        elif any(f.get("severity") in ("CRITICAL", "HIGH") for f in mine):
            a["status"] = "VULNERABLE"
        elif mine:
            a["status"] = "SUSPECT"
        else:
            a["status"] = "NOMINAL"
    return assets


def asset_detail(store: Any, run_id: str, host_id: str) -> dict[str, Any] | None:
    a = next((x for x in asset_list(store, run_id) if x["host_id"] == host_id), None)
    if not a:
        return None
    controls = [c for c in evaluate_controls(store, run_id, False) if host_id in c["affected_hosts"]]
    return {
        **a,
        "services": q(store, "SELECT DISTINCT port, service, banner, tls_version, auth_mode FROM telemetry_records "
                             "WHERE run_id=? AND host_id=? AND is_poisoned=0", (run_id, host_id)),
        "findings": [f for f in store.get_findings(run_id) if f["host_id"] == host_id][-60:],
        "data_sources": q(store, "SELECT * FROM data_sources WHERE run_id=? AND host_id=?", (run_id, host_id)),
        "data_findings": q(store, "SELECT * FROM data_findings WHERE run_id=? AND host_id=?", (run_id, host_id)),
        "controls": controls,
        "incident": next((i for i in incidents(store, run_id) if i["host_id"] == host_id), None),
    }


def incident_detail(store: Any, run_id: str, incident_id: str) -> dict[str, Any] | None:
    inc = next((i for i in incidents(store, run_id) if i["incident_id"] == incident_id), None)
    if not inc:
        return None
    host = inc["host_id"]
    events = q(store, "SELECT * FROM events WHERE run_id=? AND host_id=? ORDER BY seq DESC LIMIT 80", (run_id, host))
    for e in events:
        e["details"] = json.loads(e.pop("details_json", "{}"))
    msgs = [m for m in store.get_messages(run_id) if host in json.dumps(m.get("payload", {}))][-40:]
    return {
        "incident": inc,
        "findings": [f for f in store.get_findings(run_id) if f["host_id"] == host][-60:],
        "events": list(reversed(events)),
        "messages": msgs,
        "approvals": [p for p in store.get_pending_quarantines(run_id) if p["host_id"] == host],
        "data_findings": q(store, "SELECT * FROM data_findings WHERE run_id=? AND host_id=?", (run_id, host)),
        "controls": [c for c in evaluate_controls(store, run_id, False) if host in c["affected_hosts"]],
        "asset": next((a for a in asset_list(store, run_id) if a["host_id"] == host), None),
    }


def alerts(store: Any, run_id: str, severity: str = "", asset: str = "", status: str = "") -> list[dict[str, Any]]:
    quarantined = {f["host_id"] for f in store.get_findings(run_id) if f.get("quarantined")}
    out = []
    for f in reversed(store.get_findings(run_id)):
        st = "CONTAINED" if f["host_id"] in quarantined else "OPEN"
        if (severity and f["severity"].upper() != severity.upper()) or (asset and f["host_id"] != asset) \
                or (status and st != status.upper()):
            continue
        out.append({**f, "status": st, "incident_id": f"INC-{f['host_id']}"})
    return out[:500]
