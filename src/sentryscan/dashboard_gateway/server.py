"""Loopback FastAPI REST and WebSocket gateway for SentryScan."""

from __future__ import annotations

import asyncio
import json
import logging
import random
import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import Body, FastAPI, HTTPException, Query, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, Response
from fastapi.staticfiles import StaticFiles

from sentryscan.analysis.report_generator import (
    ask_soc_copilot,
    build_pdf_report,
    correlate_incidents,
    generate_posture_report,
)
from sentryscan.common.clock import SystemClock
from sentryscan.contracts.events import AgentEvent, EventStatus, EventType
from sentryscan.contracts.finding import Severity
from sentryscan.contracts.message import Message, Performative
from sentryscan.contracts.telemetry import AuthMode, TelemetryRecord, TelemetrySource
from sentryscan.integrity.checker import IntegrityChecker
from sentryscan.rules.engine import RuleEngine
from sentryscan.simulation.poisoning import GroundTruthSidecar, InjectionOperator, PoisoningMutator
from sentryscan.storage.store import SQLiteRunStore

logger = logging.getLogger(__name__)


class ConnectionManager:
    """Manages active WebSocket subscribers per simulation run."""

    def __init__(self) -> None:
        self.active_connections: dict[str, list[WebSocket]] = {}
        self._lock = asyncio.Lock()

    async def connect(self, run_id: str, websocket: WebSocket) -> None:
        """Register a new active WebSocket subscriber."""
        await websocket.accept()
        async with self._lock:
            if run_id not in self.active_connections:
                self.active_connections[run_id] = []
            self.active_connections[run_id].append(websocket)
        logger.debug("Client connected to run_id=%s. Total: %d", run_id, len(self.active_connections[run_id]))

    async def disconnect(self, run_id: str, websocket: WebSocket) -> None:
        """Remove a disconnected WebSocket subscriber."""
        async with self._lock:
            if run_id in self.active_connections:
                if websocket in self.active_connections[run_id]:
                    self.active_connections[run_id].remove(websocket)
                if not self.active_connections[run_id]:
                    del self.active_connections[run_id]
        logger.debug("Client disconnected from run_id=%s", run_id)

    async def broadcast(self, run_id: str, message: dict[str, Any]) -> None:
        """Broadcast JSON payload to all active clients of a given run_id."""
        if run_id not in self.active_connections:
            return

        payload_str = json.dumps(message)
        dead: list[WebSocket] = []

        async with self._lock:
            connections = list(self.active_connections.get(run_id, []))

        for connection in connections:
            try:
                await connection.send_text(payload_str)
            except Exception:
                dead.append(connection)

        if dead:
            async with self._lock:
                for connection in dead:
                    if run_id in self.active_connections and connection in self.active_connections[run_id]:
                        self.active_connections[run_id].remove(connection)


def create_app(
    store: SQLiteRunStore | None = None,
    static_dir: Path | str | None = None,
) -> FastAPI:
    """FastAPI application factory for testing and production deployment."""

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        loop = asyncio.get_running_loop()
        default_handler = loop.get_exception_handler() or loop.default_exception_handler

        def proactor_exception_handler(l, ctx):
            exc = ctx.get("exception")
            msg = ctx.get("message", "")
            # Filter benign Windows socket teardown and h11 early disconnect noise
            if isinstance(exc, (ConnectionResetError, ConnectionAbortedError)):
                return
            if exc is not None and "can't handle event type Response when role=SERVER and state=CLOSED" in str(exc):
                return
            if "_call_connection_lost" in msg or "_loop_reading" in msg:
                if isinstance(exc, (ConnectionResetError, ConnectionAbortedError, OSError)) or exc is None:
                    return
            default_handler(l, ctx)

        loop.set_exception_handler(proactor_exception_handler)
        yield

    app = FastAPI(
        title="SentryScan Autonomous SOC Gateway",
        description="Loopback REST and WebSocket interfaces for multi-agent SOC telemetry and containment orchestration.",
        version="0.1.0",
        lifespan=lifespan,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.state.store = store if store is not None else SQLiteRunStore(":memory:")
    app.state.manager = ConnectionManager()

    # -------------------------------------------------------------------------
    # REST Endpoints (HLD §8.2)
    # -------------------------------------------------------------------------

    @app.get("/api/health")
    async def get_health() -> dict[str, str]:
        return {"status": "ok", "service": "sentryscan-gateway"}

    @app.get("/api/runs")
    async def list_runs() -> list[dict[str, Any]]:
        return app.state.store.list_runs()

    @app.get("/api/runs/{run_id}")
    async def get_run_manifest(run_id: str) -> dict[str, Any]:
        run = app.state.store.get_run(run_id=run_id)
        if not run:
            raise HTTPException(status_code=404, detail=f"Run {run_id} not found")
        return run

    @app.get("/api/runs/{run_id}/events")
    async def get_events(
        run_id: str,
        from_seq: int = Query(1, ge=1),
        limit: int = Query(1000, ge=1, le=5000),
    ) -> list[dict[str, Any]]:
        return app.state.store.get_events(run_id=run_id, from_seq=from_seq, limit=limit)

    @app.get("/api/runs/{run_id}/events/tail")
    async def get_events_tail(
        run_id: str,
        n: int = Query(20, ge=1, le=200),
    ) -> list[dict[str, Any]]:
        total = app.state.store.get_event_count(run_id=run_id)
        start_seq = max(1, total - n + 1)
        return app.state.store.get_events(run_id=run_id, from_seq=start_seq, limit=n)

    @app.get("/api/runs/{run_id}/summary")
    async def get_summary(run_id: str) -> dict[str, Any]:
        all_events = app.state.store.get_events(run_id=run_id, from_seq=1, limit=5000)
        messages = app.state.store.get_messages(run_id=run_id)
        findings = app.state.store.get_findings(run_id=run_id)
        quarantined = {f["host_id"] for f in findings if f.get("quarantined")}
        rejected = sum(1 for e in all_events if e.get("event_type") == "record_rejected")
        return {
            "run_id": run_id,
            "events": len(all_events),
            "messages": len(messages),
            "findings": len(findings),
            "quarantined": len(quarantined),
            "quarantined_hosts": sorted(quarantined),
            "rejected": rejected,
        }

    @app.get("/api/runs/{run_id}/messages")
    async def get_messages(run_id: str) -> list[dict[str, Any]]:
        return app.state.store.get_messages(run_id=run_id)

    @app.get("/api/runs/{run_id}/devices")
    async def get_devices(run_id: str) -> list[dict[str, Any]]:
        return app.state.store.get_telemetry_records(run_id=run_id)

    @app.get("/api/runs/{run_id}/findings")
    async def get_findings(run_id: str) -> list[dict[str, Any]]:
        return app.state.store.get_findings(run_id=run_id)

    @app.get("/api/runs/{run_id}/bdi")
    async def get_bdi(run_id: str) -> list[dict[str, Any]]:
        return app.state.store.get_bdi_snapshots(run_id=run_id)

    @app.get("/api/runs/{run_id}/llm")
    async def get_llm(run_id: str) -> list[dict[str, Any]]:
        return app.state.store.get_llm_calls(run_id=run_id)

    @app.get("/api/runs/{run_id}/reports")
    async def get_reports(run_id: str, type: str = "") -> list[dict[str, Any]]:
        reps = app.state.store.get_reports(run_id=run_id)
        if type == "posture":
            return [
                r for r in reps
                if "remediation_plan" not in json.dumps(r.get("data", {}))
                and not str(r.get("window_name", "")).startswith("Remediation Plan")
            ]
        elif type == "remediation":
            return [
                r for r in reps
                if "remediation_plan" in json.dumps(r.get("data", {}))
                or str(r.get("window_name", "")).startswith("Remediation Plan")
            ]
        return reps

    @app.get("/api/runs/{run_id}/reports/{report_id}/pdf")
    @app.get("/api/reports/{report_id}/pdf")
    async def get_report_pdf(report_id: str, run_id: str | None = None) -> Response:
        reps = app.state.store.get_reports(run_id=run_id) if run_id else []
        target = next((r for r in reps if r.get("report_id") == report_id), None)
        if not target:
            # Fallback across all runs in case run_id was omitted or mismatched
            all_reps = app.state.store.get_reports()
            target = next((r for r in all_reps if r.get("report_id") == report_id), None)
        if not target:
            raise HTTPException(status_code=404, detail=f"Report {report_id} not found")
        try:
            pdf_bytes = build_pdf_report(target)
        except Exception as e:
            logger.error("Failed to generate PDF for report %s: %s", report_id, e)
            raise HTTPException(status_code=500, detail=f"PDF generation error: {e}")
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={
                "Content-Disposition": f'inline; filename="{report_id}.pdf"',
                "Content-Length": str(len(pdf_bytes)),
                "Cache-Control": "no-cache",
                "Accept-Ranges": "bytes",
            },
        )

    @app.post("/api/runs/{run_id}/reports/generate")
    async def create_report(
        run_id: str,
        payload: dict[str, Any] = Body(default_factory=dict),
    ) -> dict[str, Any]:
        from sentryscan.llm.factory import get_llm_provider
        window = payload.get("window_name", "Last 30 Minutes")
        custom_provider = payload.get("provider")
        llm = (
            get_llm_provider(
                provider_name=custom_provider,
                purpose="report",
                model=payload.get("model"),
                api_key=payload.get("api_key"),
                base_url=payload.get("base_url"),
            )
            if custom_provider
            else None
        )
        rep = generate_posture_report(store=app.state.store, run_id=run_id, window_name=window, llm=llm)
        record_gateway_event(
            app.state.store,
            run_id,
            EventType.STATE_TRANSITION,
            component="analyst-l2-incident",
            details={"action": "posture_report_generated", "report_id": rep["report_id"], "score": rep["posture_score"]},
        )
        return rep

    @app.post("/api/runs/{run_id}/ask")
    async def copilot_ask(
        run_id: str,
        payload: dict[str, Any] = Body(...),
    ) -> dict[str, Any]:
        from sentryscan.llm.factory import get_llm_provider
        question = payload.get("question", "").strip()
        if not question:
            raise HTTPException(status_code=400, detail="Question cannot be empty.")
        custom_provider = payload.get("provider")
        llm = (
            get_llm_provider(
                provider_name=custom_provider,
                purpose="copilot",
                model=payload.get("model"),
                api_key=payload.get("api_key"),
                base_url=payload.get("base_url"),
            )
            if custom_provider
            else None
        )
        return ask_soc_copilot(store=app.state.store, run_id=run_id, question=question, llm=llm)

    @app.get("/api/runs/{run_id}/analysis")
    async def get_analysis(run_id: str) -> dict[str, Any]:
        findings = app.state.store.get_findings(run_id=run_id)
        quarantined = {f["host_id"] for f in findings if f.get("quarantined")}
        incidents = correlate_incidents(findings, quarantined)
        return {
            "incidents": incidents,
            "threat_breakdown": {
                "critical": sum(1 for f in findings if str(f.get("severity")).upper() == "CRITICAL"),
                "high": sum(1 for f in findings if str(f.get("severity")).upper() == "HIGH"),
                "medium": sum(1 for f in findings if str(f.get("severity")).upper() == "MEDIUM"),
                "low": sum(1 for f in findings if str(f.get("severity")).upper() == "LOW"),
            },
            "quarantined_hosts": list(quarantined),
        }

    @app.get("/api/runs/{run_id}/parity")
    async def get_parity(run_id: str, jsonl_path: str = "") -> dict[str, Any]:
        path = jsonl_path or f"runs/{run_id}/trace.jsonl"
        return app.state.store.verify_parity(run_id=run_id, jsonl_path=path)

    @app.get("/api/runs/{run_id}/quarantines")
    async def get_quarantines(run_id: str) -> list[dict[str, Any]]:
        return app.state.store.get_pending_quarantines(run_id=run_id)

    @app.post("/api/runs/{run_id}/quarantines/{quarantine_id}/decide")
    async def decide_quarantine(
        run_id: str,
        quarantine_id: str,
        payload: dict[str, Any] = Body(...),
    ) -> dict[str, Any]:
        from datetime import datetime, timezone
        decision = str(payload.get("decision", "")).upper()
        if decision not in ("APPROVED", "REJECTED"):
            raise HTTPException(status_code=400, detail="decision must be APPROVED or REJECTED")
        decided_by = str(payload.get("decided_by", "console-operator"))
        decided_at = payload.get("decided_at") or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        try:
            return app.state.store.decide_pending_quarantine(
                quarantine_id=quarantine_id,
                decision=decision,
                decided_by=decided_by,
                decided_at=decided_at,
            )
        except ValueError as err:
            raise HTTPException(status_code=404, detail=str(err)) from err

    # -------------------------------------------------------------------------
    # Platform v2 Endpoints (Overview, VIGIL, SENTRA, POLARIS, Assets, Simulation)
    # -------------------------------------------------------------------------

    @app.get("/api/asset-types")
    async def get_asset_types() -> list[dict[str, Any]]:
        from sentryscan.simulation.asset_types import ASSET_TYPES
        return [
            {
                "key": t.key,
                "label": t.label,
                "category": t.category,
                "os_family": t.os_family,
                "provider": t.provider,
                "weight": t.weight,
                "ports": [s.port for s in t.services],
                "services": [f"{s.service}:{s.port}" for s in t.services],
                "data_sources": list(t.data_sources),
            }
            for t in ASSET_TYPES.values()
        ]

    @app.get("/api/runs/{run_id}/overview")
    async def get_overview_v2(run_id: str) -> dict[str, Any]:
        from sentryscan.platform import pulse as platform_pulse
        return platform_pulse.overview(app.state.store, run_id)

    @app.get("/api/runs/{run_id}/assets")
    async def get_assets_v2(run_id: str) -> list[dict[str, Any]]:
        from sentryscan.platform import pulse as platform_pulse
        return platform_pulse.asset_list(app.state.store, run_id)

    @app.get("/api/runs/{run_id}/assets/{host_id}")
    async def get_asset_detail_v2(run_id: str, host_id: str) -> dict[str, Any]:
        from sentryscan.platform import pulse as platform_pulse
        detail = platform_pulse.asset_detail(app.state.store, run_id, host_id)
        if not detail:
            raise HTTPException(status_code=404, detail=f"Asset {host_id} not found")
        return detail

    @app.get("/api/runs/{run_id}/alerts")
    async def get_alerts_v2(
        run_id: str,
        severity: str = "",
        asset: str = "",
        status: str = "",
    ) -> list[dict[str, Any]]:
        from sentryscan.platform import pulse as platform_pulse
        return platform_pulse.alerts(app.state.store, run_id, severity=severity, asset=asset, status=status)

    @app.get("/api/runs/{run_id}/incidents")
    async def get_incidents_v2(run_id: str) -> list[dict[str, Any]]:
        from sentryscan.platform import pulse as platform_pulse
        return platform_pulse.incidents(app.state.store, run_id)

    @app.get("/api/runs/{run_id}/incidents/{incident_id}")
    async def get_incident_detail_v2(run_id: str, incident_id: str) -> dict[str, Any]:
        from sentryscan.platform import pulse as platform_pulse
        detail = platform_pulse.incident_detail(app.state.store, run_id, incident_id)
        if not detail:
            raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")
        return detail

    @app.get("/api/runs/{run_id}/radar")
    async def get_radar_v2(run_id: str) -> dict[str, Any]:
        from sentryscan.platform import core as platform_core
        return platform_core.radar_summary(app.state.store, run_id)

    @app.post("/api/runs/{run_id}/radar/scan")
    async def post_radar_scan_v2(run_id: str) -> dict[str, Any]:
        from sentryscan.platform import core as platform_core
        from sentryscan.platform import pulse as platform_pulse
        platform_core.ensure_bootstrapped(app.state.store, run_id)
        platform_core.scan(app.state.store, run_id)
        platform_pulse.evaluate_controls(app.state.store, run_id)
        return platform_core.radar_summary(app.state.store, run_id)

    @app.get("/api/runs/{run_id}/pulse")
    async def get_pulse_v2(run_id: str) -> dict[str, Any]:
        from sentryscan.platform import pulse as platform_pulse
        return platform_pulse.pulse_summary(app.state.store, run_id)

    @app.get("/api/runs/{run_id}/pulse/controls/{control_id}")
    async def get_pulse_control_detail_v2(run_id: str, control_id: str) -> dict[str, Any]:
        from sentryscan.platform import pulse as platform_pulse
        summary = platform_pulse.pulse_summary(app.state.store, run_id)
        ctrl = next((c for c in summary["controls"] if c["id"].upper() == control_id.upper()), None)
        if not ctrl:
            raise HTTPException(status_code=404, detail=f"Control {control_id} not found")
        tasks = [
            t for t in summary["tasks"]
            if t["ref_id"] == ctrl["id"] or (ctrl["affected_hosts"] and t["host_id"] in ctrl["affected_hosts"])
        ]
        return {**ctrl, "tasks": tasks, "framework": summary["framework"], "profile": summary["profile"]}

    @app.post("/api/runs/{run_id}/pulse/settings")
    async def post_pulse_settings_v2(
        run_id: str,
        payload: dict[str, Any] = Body(default_factory=dict),
    ) -> dict[str, Any]:
        from sentryscan.platform import core as platform_core
        from sentryscan.platform import pulse as platform_pulse
        platform_core.ensure_bootstrapped(app.state.store, run_id)
        if payload.get("profile"):
            prof = str(payload["profile"]).strip()
            if prof not in platform_core.list_profiles():
                raise HTTPException(status_code=400, detail=f"Unknown profile '{prof}'")
            platform_core.set_setting(app.state.store, run_id, "profile", prof)
            platform_core.scan(app.state.store, run_id)
        if payload.get("framework"):
            platform_core.set_setting(app.state.store, run_id, "framework", str(payload["framework"]).strip())
        platform_pulse.evaluate_controls(app.state.store, run_id)
        return platform_pulse.pulse_summary(app.state.store, run_id)

    @app.get("/api/runs/{run_id}/remediation")
    async def get_remediation_v2(run_id: str) -> list[dict[str, Any]]:
        from sentryscan.platform import core as platform_core
        from sentryscan.platform import pulse as platform_pulse
        platform_pulse.evaluate_controls(app.state.store, run_id, record_history=False)
        return platform_core.q(
            app.state.store,
            "SELECT * FROM remediation_tasks WHERE run_id=? ORDER BY created_at DESC",
            (run_id,),
        )

    @app.post("/api/runs/{run_id}/remediation")
    async def create_remediation_v2(
        run_id: str,
        payload: dict[str, Any] = Body(...),
    ) -> dict[str, Any]:
        from sentryscan.platform import core as platform_core
        platform_core.ensure_bootstrapped(app.state.store, run_id)
        tid = platform_core.ensure_task(
            app.state.store,
            run_id=run_id,
            kind=str(payload.get("kind", "manual")),
            ref_id=str(payload.get("ref_id", "manual")),
            host_id=str(payload.get("host_id", "")),
            title=str(payload.get("title", "Remediation task")),
        )
        if payload.get("owner"):
            return platform_core.update_task(app.state.store, run_id, tid, None, str(payload["owner"]))
        return platform_core.q(app.state.store, "SELECT * FROM remediation_tasks WHERE task_id=?", (tid,))[0]

    @app.post("/api/runs/{run_id}/remediation/{task_id}")
    async def update_remediation_v2(
        run_id: str,
        task_id: str,
        payload: dict[str, Any] = Body(...),
    ) -> dict[str, Any]:
        from sentryscan.platform import core as platform_core
        from sentryscan.platform import pulse as platform_pulse
        try:
            updated = platform_core.update_task(
                app.state.store,
                run_id=run_id,
                task_id=task_id,
                status=payload.get("status"),
                owner=payload.get("owner"),
            )
            platform_pulse.evaluate_controls(app.state.store, run_id)
            return updated
        except KeyError as err:
            raise HTTPException(status_code=404, detail=f"Task {task_id} not found") from err
        except ValueError as err:
            raise HTTPException(status_code=400, detail=str(err)) from err

    def record_gateway_event(
        store: SQLiteRunStore,
        run_id: str,
        event_type: EventType,
        component: str,
        status: EventStatus = EventStatus.OK,
        host_id: str | None = None,
        rule_id: str | None = None,
        finding_id: str | None = None,
        record_id: str | None = None,
        reason_code: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> AgentEvent:
        clk = SystemClock()
        with store._lock, store._conn:
            cur = store._conn.execute("SELECT COALESCE(MAX(seq), 0) + 1 FROM events WHERE run_id = ?", (run_id,))
            seq = int(cur.fetchone()[0])
        event = AgentEvent(
            event_id=f"evt-{seq:06d}",
            run_id=run_id,
            seq=seq,
            timestamp_utc=clk.now_iso(),
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
        store.save_event(event)
        return event

    @app.post("/api/runs/{run_id}/telemetry/inject")
    async def inject_telemetry(
        run_id: str,
        payload: dict[str, Any] = Body(default_factory=dict),
    ) -> dict[str, Any]:
        """Inject synthetic telemetry, attacks, or poisoned traffic directly into the run."""
        clk = SystemClock()
        chk = IntegrityChecker(clock=clk)
        engine = RuleEngine()
        mutator = PoisoningMutator(sidecar=GroundTruthSidecar(), seed=42)

        preset = str(payload.get("preset", "custom")).lower()
        target_host = payload.get("host_id") or "windows-workstation-03"
        if target_host in ("random", "any"):
            devices = app.state.store.get_devices(run_id)
            target_host = random.choice([d["host_id"] for d in devices]) if devices else "windows-workstation-03"

        count = max(1, min(50, int(payload.get("record_count", 5))))
        poison_rate = float(payload.get("poison_rate", 0.0))
        quarantine_imm = bool(payload.get("quarantine_immediate", False))

        service = str(payload.get("service") or "http")
        port = int(payload.get("port") or 80)
        banner = str(payload.get("banner") or "")
        auth_mode = AuthMode.UNKNOWN

        # Presets configuration
        if preset == "apache_cve":
            service, port, banner, auth_mode = "http", 80, "Apache/2.4.49 (Unix) OpenSSL/1.1.1d", AuthMode.UNKNOWN
            poison_rate = 0.0
        elif preset == "default_creds":
            service, port, banner, auth_mode = "http-admin", 8080, "Admin Web Console (default credentials admin / admin)", AuthMode.DEFAULT
            poison_rate = 0.0
        elif preset == "telnet_leak":
            service, port, banner, auth_mode = "telnet", 23, "Cisco IOS Telnet Terminal v15.2", AuthMode.UNKNOWN
            poison_rate = 0.0
        elif preset == "deprecated_tls":
            service, port, banner, auth_mode = "https", 443, "Legacy Web Portal", AuthMode.UNKNOWN
        elif preset == "poison_storm":
            poison_rate = 1.0
        elif preset == "normal_traffic":
            service, port, banner, auth_mode = "https", 443, "Enterprise Portal TLSv1.3", AuthMode.REQUIRED
            poison_rate = 0.0

        tls_ver = payload.get("tls_version") or ("SSLv3" if preset == "deprecated_tls" else None)

        record_gateway_event(
            app.state.store,
            run_id,
            EventType.STATE_TRANSITION,
            component="fleet_sensor",
            host_id=target_host,
            details={
                "action": "operator_burst_injected",
                "preset": preset,
                "count": count,
                "poison_rate": poison_rate,
                "target_host": target_host,
            },
        )

        injected_records = []
        clean_records = []
        rejected_records = []
        findings_created = []

        ops = [
            InjectionOperator.SERVICE_BANNER_MISMATCH,
            InjectionOperator.TLS_CLAIM_CONTRADICTION,
            InjectionOperator.STALE_TIMESTAMP,
            InjectionOperator.PROMPT_INJECTION_BANNER,
        ]

        for i in range(count):
            rid = f"rec-inj-{uuid.uuid4().hex[:8]}"
            base_rec = TelemetryRecord(
                record_id=rid,
                host_id=target_host,
                ip="192.168.10.50",
                port=port,
                service=service,
                banner=banner,
                tls_version=tls_ver,
                auth_mode=auth_mode,
                generated_at=clk.now_iso(),
                source=TelemetrySource.SYNTHETIC_SIMULATOR,
            )

            is_poisoned = False
            inj_type = None
            rec = base_rec
            if random.random() < poison_rate:
                op = random.choice(ops)
                rec = mutator.mutate(baseline=base_rec, operator=op, new_record_id=rid)
                is_poisoned = True
                inj_type = op.value

            app.state.store.save_ground_truth(
                record_id=rec.record_id,
                run_id=run_id,
                host_id=rec.host_id,
                cycle=999,
                is_vulnerable=bool(preset in ("apache_cve", "default_creds", "telnet_leak", "deprecated_tls")),
                expected_rules=[preset],
                is_poisoned=is_poisoned,
                injection_type=inj_type,
            )

            record_gateway_event(
                app.state.store,
                run_id,
                EventType.RECORD_RECEIVED,
                component="fleet_sensor",
                record_id=rec.record_id,
                host_id=rec.host_id,
                details={
                    "service": rec.service,
                    "port": rec.port,
                    "is_poisoned": is_poisoned,
                    "preset": preset,
                },
            )

            flags = chk.check_record(rec)
            if flags:
                app.state.store.save_telemetry_record(rec, run_id=run_id, is_poisoned=True)
                rejected_records.append(rec.record_id)
                record_gateway_event(
                    app.state.store,
                    run_id,
                    EventType.RECORD_REJECTED,
                    component="integrity_checker",
                    status=EventStatus.REJECTED,
                    record_id=rec.record_id,
                    host_id=rec.host_id,
                    reason_code=flags[0].reason_code.value,
                    details={"flags": len(flags)},
                )
            else:
                app.state.store.save_telemetry_record(rec, run_id=run_id, is_poisoned=False)
                clean_records.append(rec)

            injected_records.append(rec)

        # Scanner Worker processes clean records
        if clean_records:
            record_gateway_event(
                app.state.store,
                run_id,
                EventType.STATE_TRANSITION,
                component="scanner_worker",
                status=EventStatus.OK,
                details={
                    "action": "batch_scan_initiated",
                    "clean_records": len(clean_records),
                    "target_host": target_host,
                },
            )

            for rec in clean_records:
                eval_fnds = engine.evaluate_record(
                    rec,
                    run_id=run_id,
                    finding_id_generator=lambda: f"fnd-{uuid.uuid4().hex[:8]}",
                    timestamp_iso=clk.now_iso(),
                )
                for f in eval_fnds:
                    is_q = quarantine_imm or f.severity in (Severity.CRITICAL, Severity.HIGH)
                    cve = "CVE-2021-41773" if "apache" in rec.banner.lower() else None
                    app.state.store.save_finding(f, cve_id=cve, quarantined=is_q)
                    findings_created.append(f.finding_id)

                    record_gateway_event(
                        app.state.store,
                        run_id,
                        EventType.FINDING_CREATED,
                        component="scanner_worker",
                        host_id=f.host_id,
                        finding_id=f.finding_id,
                        rule_id=f.rule_id,
                        details={"severity": f.severity.value, "quarantined": is_q},
                    )

                    # Inter-agent escalation message cascade
                    msg_scan = Message(
                        message_id=f"msg-{uuid.uuid4().hex[:8]}",
                        run_id=run_id,
                        sender="scanner_worker",
                        receiver="supervisor-agent",
                        performative=Performative.TASK_RESULT,
                        timestamp_utc=clk.now_iso(),
                        nonce=uuid.uuid4().hex[:12],
                        payload={"finding_id": f.finding_id, "host_id": f.host_id, "severity": f.severity.value},
                    )
                    app.state.store.save_message(msg_scan)
                    record_gateway_event(
                        app.state.store,
                        run_id,
                        EventType.MESSAGE_SENT,
                        component="scanner_worker",
                        details={"receiver": "supervisor-agent", "performative": "TASK_RESULT", "payload": msg_scan.payload},
                    )

                    msg_l1 = Message(
                        message_id=f"msg-{uuid.uuid4().hex[:8]}",
                        run_id=run_id,
                        sender="supervisor-agent",
                        receiver="analyst-l1-triage",
                        performative=Performative.ALERT,
                        timestamp_utc=clk.now_iso(),
                        nonce=uuid.uuid4().hex[:12],
                        payload={"finding_id": f.finding_id, "host_id": f.host_id, "severity": f.severity.value},
                    )
                    app.state.store.save_message(msg_l1)
                    record_gateway_event(
                        app.state.store,
                        run_id,
                        EventType.MESSAGE_SENT,
                        component="supervisor-agent",
                        details={"receiver": "analyst-l1-triage", "performative": "ALERT", "payload": msg_l1.payload},
                    )

                    if f.severity in (Severity.CRITICAL, Severity.HIGH):
                        msg_l2 = Message(
                            message_id=f"msg-{uuid.uuid4().hex[:8]}",
                            run_id=run_id,
                            sender="analyst-l1-triage",
                            receiver="analyst-l2-incident",
                            performative=Performative.ALERT,
                            timestamp_utc=clk.now_iso(),
                            nonce=uuid.uuid4().hex[:12],
                            payload={"host_id": f.host_id, "severity": f.severity.value, "escalation": True},
                        )
                        app.state.store.save_message(msg_l2)
                        record_gateway_event(
                            app.state.store,
                            run_id,
                            EventType.MESSAGE_SENT,
                            component="analyst-l1-triage",
                            details={"receiver": "analyst-l2-incident", "performative": "ALERT", "payload": msg_l2.payload},
                        )

                    if is_q:
                        msg_l3 = Message(
                            message_id=f"msg-{uuid.uuid4().hex[:8]}",
                            run_id=run_id,
                            sender="analyst-l2-incident",
                            receiver="analyst-l3-containment",
                            performative=Performative.ALERT,
                            timestamp_utc=clk.now_iso(),
                            nonce=uuid.uuid4().hex[:12],
                            payload={"host_id": f.host_id, "action": "quarantine_request"},
                        )
                        app.state.store.save_message(msg_l3)
                        record_gateway_event(
                            app.state.store,
                            run_id,
                            EventType.MESSAGE_SENT,
                            component="analyst-l2-incident",
                            details={"receiver": "analyst-l3-containment", "performative": "ALERT", "payload": msg_l3.payload},
                        )

                        record_gateway_event(
                            app.state.store,
                            run_id,
                            EventType.STATE_TRANSITION,
                            component="analyst-l3-containment",
                            host_id=f.host_id,
                            details={"action": "quarantine_enforced", "host_id": f.host_id, "reason": "Operator injected exploit detected"},
                        )

        return {
            "status": "ok",
            "host_id": target_host,
            "records_injected": len(injected_records),
            "clean_verified": len(clean_records),
            "poisoned_rejected": len(rejected_records),
            "findings_created": len(findings_created),
            "quarantined": quarantine_imm or len(findings_created) > 0,
        }

    @app.post("/api/runs/{run_id}/simulation/tune")
    async def tune_simulation(
        run_id: str,
        payload: dict[str, Any] = Body(default_factory=dict),
    ) -> dict[str, Any]:
        """Tune live simulation pace, poison ratio, and active profile."""
        from sentryscan.platform import core as platform_core
        pace = float(payload.get("pace", 0.5))
        poison_ratio = float(payload.get("poison_ratio", 0.2))
        profile = str(payload.get("profile", "enterprise"))

        platform_core.set_setting(app.state.store, run_id, "simulation_pace", str(pace))
        platform_core.set_setting(app.state.store, run_id, "poison_ratio", str(poison_ratio))
        platform_core.set_setting(app.state.store, run_id, "profile", profile)

        record_gateway_event(
            app.state.store,
            run_id,
            EventType.STATE_TRANSITION,
            component="fleet_sensor",
            details={"action": "simulation_parameters_tuned", "pace": pace, "poison_ratio": poison_ratio, "profile": profile},
        )
        return {"status": "ok", "settings": {"pace": pace, "poison_ratio": poison_ratio, "profile": profile}}

    @app.post("/api/runs/{run_id}/hosts/{host_id}/quarantine")
    async def toggle_host_quarantine(
        run_id: str,
        host_id: str,
        payload: dict[str, Any] = Body(default_factory=dict),
    ) -> dict[str, Any]:
        """Manually quarantine or release an endpoint asset."""
        action = str(payload.get("action", "isolate")).lower()
        reason = str(payload.get("reason", "Operator manual containment action"))
        is_q = 1 if action == "isolate" else 0

        with app.state.store._lock, app.state.store._conn:
            app.state.store._conn.execute(
                "UPDATE findings SET quarantined = ? WHERE run_id = ? AND host_id = ?",
                (is_q, run_id, host_id),
            )

        action_name = "quarantine_enforced" if is_q else "quarantine_released"
        record_gateway_event(
            app.state.store,
            run_id,
            EventType.STATE_TRANSITION,
            component="analyst-l3-containment",
            host_id=host_id,
            details={"action": action_name, "reason": reason, "manual": True},
        )
        return {"status": "ok", "host_id": host_id, "quarantined": bool(is_q), "action": action_name}

    @app.get("/api/runs/{run_id}/simulation")
    async def get_simulation_v2(run_id: str) -> dict[str, Any]:
        from sentryscan.platform import core as platform_core
        from sentryscan.platform import pulse as platform_pulse
        platform_core.ensure_bootstrapped(app.state.store, run_id)
        run_row = app.state.store.get_run(run_id) or {}
        try:
            metrics = app.state.store.compute_eval_metrics(run_id)
        except Exception:
            metrics = {}
        gt = app.state.store.get_ground_truth(run_id)
        return {
            "run": run_row,
            "assets": platform_pulse.asset_list(app.state.store, run_id),
            "eval_metrics": metrics,
            "ground_truth_count": len(gt),
            "ground_truth_sample": gt[-40:],
            "scenarios": platform_core.list_scenarios(app.state.store),
        }

    @app.post("/api/simulation/resolve-fleet")
    async def resolve_fleet_preview(payload: dict[str, Any] = Body(default_factory=dict)) -> dict[str, Any]:
        from sentryscan.simulation.asset_types import resolve_fleet
        spec = payload.get("fleet_spec") or ""
        total = int(payload.get("total") or 0) or None
        seed = int(payload.get("seed") or 42)
        try:
            resolved = resolve_fleet(spec=spec, total=total, seed=seed)
        except ValueError as err:
            raise HTTPException(status_code=400, detail=str(err)) from err
        return {
            "total": len(resolved),
            "fleet": resolved,
            "counts": {t: resolved.count(t) for t in set(resolved)},
        }

    def record_gateway_event(
        store: SQLiteRunStore,
        run_id: str,
        event_type: EventType,
        component: str,
        status: EventStatus = EventStatus.OK,
        host_id: str | None = None,
        rule_id: str | None = None,
        finding_id: str | None = None,
        record_id: str | None = None,
        reason_code: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> AgentEvent:
        clk = SystemClock()
        with store._lock, store._conn:
            cur = store._conn.execute("SELECT COALESCE(MAX(seq), 0) + 1 FROM events WHERE run_id = ?", (run_id,))
            seq = int(cur.fetchone()[0])
        event = AgentEvent(
            event_id=f"evt-{seq:06d}",
            run_id=run_id,
            seq=seq,
            timestamp_utc=clk.now_iso(),
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
        store.save_event(event)
        return event

    @app.post("/api/runs/{run_id}/telemetry/inject")
    async def inject_telemetry(
        run_id: str,
        payload: dict[str, Any] = Body(default_factory=dict),
    ) -> dict[str, Any]:
        """Inject synthetic telemetry, attacks, or poisoned traffic directly into the run."""
        clk = SystemClock()
        chk = IntegrityChecker(clock=clk)
        engine = RuleEngine()
        mutator = PoisoningMutator(sidecar=GroundTruthSidecar(), seed=42)

        preset = str(payload.get("preset", "custom")).lower()
        target_host = payload.get("host_id") or "windows-workstation-03"
        if target_host in ("random", "any"):
            devices = app.state.store.get_devices(run_id)
            target_host = random.choice([d["host_id"] for d in devices]) if devices else "windows-workstation-03"

        count = max(1, min(50, int(payload.get("record_count", 5))))
        poison_rate = float(payload.get("poison_rate", 0.0))
        quarantine_imm = bool(payload.get("quarantine_immediate", False))

        service = str(payload.get("service") or "http")
        port = int(payload.get("port") or 80)
        banner = str(payload.get("banner") or "")
        auth_mode = AuthMode.UNKNOWN

        # Presets configuration
        if preset == "apache_cve":
            service, port, banner, auth_mode = "http", 80, "Apache/2.4.49 (Unix) OpenSSL/1.1.1d", AuthMode.UNKNOWN
            poison_rate = 0.0
        elif preset == "default_creds":
            service, port, banner, auth_mode = "http-admin", 8080, "Admin Web Console (default credentials admin / admin)", AuthMode.DEFAULT
            poison_rate = 0.0
        elif preset == "telnet_leak":
            service, port, banner, auth_mode = "telnet", 23, "Cisco IOS Telnet Terminal v15.2", AuthMode.UNKNOWN
            poison_rate = 0.0
        elif preset == "deprecated_tls":
            service, port, banner, auth_mode = "https", 443, "Legacy Web Portal", AuthMode.UNKNOWN
        elif preset == "poison_storm":
            poison_rate = 1.0
        elif preset == "normal_traffic":
            service, port, banner, auth_mode = "https", 443, "Enterprise Portal TLSv1.3", AuthMode.REQUIRED
            poison_rate = 0.0

        tls_ver = payload.get("tls_version") or ("SSLv3" if preset == "deprecated_tls" else None)

        record_gateway_event(
            app.state.store,
            run_id,
            EventType.STATE_TRANSITION,
            component="fleet_sensor",
            host_id=target_host,
            details={
                "action": "operator_burst_injected",
                "preset": preset,
                "count": count,
                "poison_rate": poison_rate,
                "target_host": target_host,
            },
        )

        injected_records = []
        clean_records = []
        rejected_records = []
        findings_created = []

        ops = [
            InjectionOperator.SERVICE_BANNER_MISMATCH,
            InjectionOperator.TLS_CLAIM_CONTRADICTION,
            InjectionOperator.STALE_TIMESTAMP,
            InjectionOperator.PROMPT_INJECTION_BANNER,
        ]

        for i in range(count):
            rid = f"rec-inj-{uuid.uuid4().hex[:8]}"
            base_rec = TelemetryRecord(
                record_id=rid,
                host_id=target_host,
                ip="192.168.10.50",
                port=port,
                service=service,
                banner=banner,
                tls_version=tls_ver,
                auth_mode=auth_mode,
                generated_at=clk.now_iso(),
                source=TelemetrySource.SYNTHETIC_SIMULATOR,
            )

            is_poisoned = False
            inj_type = None
            rec = base_rec
            if random.random() < poison_rate:
                op = random.choice(ops)
                rec = mutator.mutate(baseline=base_rec, operator=op, new_record_id=rid)
                is_poisoned = True
                inj_type = op.value

            app.state.store.save_ground_truth(
                record_id=rec.record_id,
                run_id=run_id,
                host_id=rec.host_id,
                cycle=999,
                is_vulnerable=bool(preset in ("apache_cve", "default_creds", "telnet_leak", "deprecated_tls")),
                expected_rules=[preset],
                is_poisoned=is_poisoned,
                injection_type=inj_type,
            )

            record_gateway_event(
                app.state.store,
                run_id,
                EventType.RECORD_RECEIVED,
                component="fleet_sensor",
                record_id=rec.record_id,
                host_id=rec.host_id,
                details={
                    "service": rec.service,
                    "port": rec.port,
                    "is_poisoned": is_poisoned,
                    "preset": preset,
                },
            )

            flags = chk.check_record(rec)
            if flags:
                app.state.store.save_telemetry_record(rec, run_id=run_id, is_poisoned=True)
                rejected_records.append(rec.record_id)
                record_gateway_event(
                    app.state.store,
                    run_id,
                    EventType.RECORD_REJECTED,
                    component="integrity_checker",
                    status=EventStatus.REJECTED,
                    record_id=rec.record_id,
                    host_id=rec.host_id,
                    reason_code=flags[0].reason_code.value,
                    details={"flags": len(flags)},
                )
            else:
                app.state.store.save_telemetry_record(rec, run_id=run_id, is_poisoned=False)
                clean_records.append(rec)

            injected_records.append(rec)

        # Scanner Worker processes clean records
        if clean_records:
            record_gateway_event(
                app.state.store,
                run_id,
                EventType.STATE_TRANSITION,
                component="scanner_worker",
                status=EventStatus.OK,
                details={
                    "action": "batch_scan_initiated",
                    "clean_records": len(clean_records),
                    "target_host": target_host,
                },
            )

            for rec in clean_records:
                eval_fnds = engine.evaluate_record(
                    rec,
                    run_id=run_id,
                    finding_id_generator=lambda: f"fnd-{uuid.uuid4().hex[:8]}",
                    timestamp_iso=clk.now_iso(),
                )
                for f in eval_fnds:
                    is_q = quarantine_imm or f.severity in (Severity.CRITICAL, Severity.HIGH)
                    cve = "CVE-2021-41773" if "apache" in rec.banner.lower() else None
                    app.state.store.save_finding(f, cve_id=cve, quarantined=is_q)
                    findings_created.append(f.finding_id)

                    record_gateway_event(
                        app.state.store,
                        run_id,
                        EventType.FINDING_CREATED,
                        component="scanner_worker",
                        host_id=f.host_id,
                        finding_id=f.finding_id,
                        rule_id=f.rule_id,
                        details={"severity": f.severity.value, "quarantined": is_q},
                    )

                    # Inter-agent escalation message cascade
                    msg_scan = Message(
                        message_id=f"msg-{uuid.uuid4().hex[:8]}",
                        run_id=run_id,
                        sender="scanner_worker",
                        receiver="supervisor-agent",
                        performative=Performative.TASK_RESULT,
                        timestamp_utc=clk.now_iso(),
                        nonce=uuid.uuid4().hex[:12],
                        payload={"finding_id": f.finding_id, "host_id": f.host_id, "severity": f.severity.value},
                    )
                    app.state.store.save_message(msg_scan)
                    record_gateway_event(
                        app.state.store,
                        run_id,
                        EventType.MESSAGE_SENT,
                        component="scanner_worker",
                        details={"receiver": "supervisor-agent", "performative": "TASK_RESULT", "payload": msg_scan.payload},
                    )

                    msg_l1 = Message(
                        message_id=f"msg-{uuid.uuid4().hex[:8]}",
                        run_id=run_id,
                        sender="supervisor-agent",
                        receiver="analyst-l1-triage",
                        performative=Performative.ALERT,
                        timestamp_utc=clk.now_iso(),
                        nonce=uuid.uuid4().hex[:12],
                        payload={"finding_id": f.finding_id, "host_id": f.host_id, "severity": f.severity.value},
                    )
                    app.state.store.save_message(msg_l1)
                    record_gateway_event(
                        app.state.store,
                        run_id,
                        EventType.MESSAGE_SENT,
                        component="supervisor-agent",
                        details={"receiver": "analyst-l1-triage", "performative": "ALERT", "payload": msg_l1.payload},
                    )

                    if f.severity in (Severity.CRITICAL, Severity.HIGH):
                        msg_l2 = Message(
                            message_id=f"msg-{uuid.uuid4().hex[:8]}",
                            run_id=run_id,
                            sender="analyst-l1-triage",
                            receiver="analyst-l2-incident",
                            performative=Performative.ALERT,
                            timestamp_utc=clk.now_iso(),
                            nonce=uuid.uuid4().hex[:12],
                            payload={"host_id": f.host_id, "severity": f.severity.value, "escalation": True},
                        )
                        app.state.store.save_message(msg_l2)
                        record_gateway_event(
                            app.state.store,
                            run_id,
                            EventType.MESSAGE_SENT,
                            component="analyst-l1-triage",
                            details={"receiver": "analyst-l2-incident", "performative": "ALERT", "payload": msg_l2.payload},
                        )

                    if is_q:
                        msg_l3 = Message(
                            message_id=f"msg-{uuid.uuid4().hex[:8]}",
                            run_id=run_id,
                            sender="analyst-l2-incident",
                            receiver="analyst-l3-containment",
                            performative=Performative.ALERT,
                            timestamp_utc=clk.now_iso(),
                            nonce=uuid.uuid4().hex[:12],
                            payload={"host_id": f.host_id, "action": "quarantine_request"},
                        )
                        app.state.store.save_message(msg_l3)
                        record_gateway_event(
                            app.state.store,
                            run_id,
                            EventType.MESSAGE_SENT,
                            component="analyst-l2-incident",
                            details={"receiver": "analyst-l3-containment", "performative": "ALERT", "payload": msg_l3.payload},
                        )

                        record_gateway_event(
                            app.state.store,
                            run_id,
                            EventType.STATE_TRANSITION,
                            component="analyst-l3-containment",
                            host_id=f.host_id,
                            details={"action": "quarantine_enforced", "host_id": f.host_id, "reason": "Operator injected exploit detected"},
                        )

        return {
            "status": "ok",
            "host_id": target_host,
            "records_injected": len(injected_records),
            "clean_verified": len(clean_records),
            "poisoned_rejected": len(rejected_records),
            "findings_created": len(findings_created),
            "quarantined": quarantine_imm or len(findings_created) > 0,
        }

    @app.post("/api/runs/{run_id}/simulation/tune")
    async def tune_simulation(
        run_id: str,
        payload: dict[str, Any] = Body(default_factory=dict),
    ) -> dict[str, Any]:
        """Tune live simulation pace, poison ratio, and active profile."""
        from sentryscan.platform import core as platform_core
        pace = float(payload.get("pace", 0.5))
        poison_ratio = float(payload.get("poison_ratio", 0.2))
        profile = str(payload.get("profile", "enterprise"))

        platform_core.set_setting(app.state.store, run_id, "simulation_pace", str(pace))
        platform_core.set_setting(app.state.store, run_id, "poison_ratio", str(poison_ratio))
        platform_core.set_setting(app.state.store, run_id, "profile", profile)

        record_gateway_event(
            app.state.store,
            run_id,
            EventType.STATE_TRANSITION,
            component="fleet_sensor",
            details={"action": "simulation_parameters_tuned", "pace": pace, "poison_ratio": poison_ratio, "profile": profile},
        )
        return {"status": "ok", "settings": {"pace": pace, "poison_ratio": poison_ratio, "profile": profile}}

    @app.post("/api/runs/{run_id}/hosts/{host_id}/quarantine")
    async def toggle_host_quarantine(
        run_id: str,
        host_id: str,
        payload: dict[str, Any] = Body(default_factory=dict),
    ) -> dict[str, Any]:
        """Manually quarantine or release an endpoint asset."""
        action = str(payload.get("action", "isolate")).lower()
        reason = str(payload.get("reason", "Operator manual containment action"))
        is_q = 1 if action == "isolate" else 0

        with app.state.store._lock, app.state.store._conn:
            app.state.store._conn.execute(
                "UPDATE findings SET quarantined = ? WHERE run_id = ? AND host_id = ?",
                (is_q, run_id, host_id),
            )

        action_name = "quarantine_enforced" if is_q else "quarantine_released"
        record_gateway_event(
            app.state.store,
            run_id,
            EventType.STATE_TRANSITION,
            component="analyst-l3-containment",
            host_id=host_id,
            details={"action": action_name, "reason": reason, "manual": True},
        )
        return {"status": "ok", "host_id": host_id, "quarantined": bool(is_q), "action": action_name}
        counts: dict[str, int] = {}
        for k in resolved:
            counts[k] = counts.get(k, 0) + 1
        tpls = build_templates(resolved)
        return {
            "total": len(resolved),
            "counts": counts,
            "hosts": [
                {"host_id": t.host_id, "label": t.label, "asset_type": t.persona,
                 "ip": t.ip, "category": ASSET_TYPES[t.persona].category}
                for t in tpls
            ],
        }

    @app.post("/api/simulation/scenarios")
    async def create_scenario_v2(payload: dict[str, Any] = Body(default_factory=dict)) -> dict[str, Any]:
        from sentryscan.platform import core as platform_core
        try:
            return platform_core.execute_scenario_in_store(
                store=app.state.store,
                name=str(payload.get("name") or "Custom Hybrid Scenario"),
                fleet_spec=payload.get("fleet_spec") or None,
                total_devices=int(payload.get("total_devices") or 6),
                cycles=max(1, min(20, int(payload.get("cycles") or 4))),
                seed=int(payload.get("seed") or 42),
                poison_ratio=float(payload.get("poison_ratio") if payload.get("poison_ratio") is not None else 0.2),
                industry=str(payload.get("industry") or "generic"),
            )
        except ValueError as err:
            raise HTTPException(status_code=400, detail=str(err)) from err

    def record_gateway_event(
        store: SQLiteRunStore,
        run_id: str,
        event_type: EventType,
        component: str,
        status: EventStatus = EventStatus.OK,
        host_id: str | None = None,
        rule_id: str | None = None,
        finding_id: str | None = None,
        record_id: str | None = None,
        reason_code: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> AgentEvent:
        clk = SystemClock()
        with store._lock, store._conn:
            cur = store._conn.execute("SELECT COALESCE(MAX(seq), 0) + 1 FROM events WHERE run_id = ?", (run_id,))
            seq = int(cur.fetchone()[0])
        event = AgentEvent(
            event_id=f"evt-{seq:06d}",
            run_id=run_id,
            seq=seq,
            timestamp_utc=clk.now_iso(),
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
        store.save_event(event)
        return event

    @app.post("/api/runs/{run_id}/telemetry/inject")
    async def inject_telemetry(
        run_id: str,
        payload: dict[str, Any] = Body(default_factory=dict),
    ) -> dict[str, Any]:
        """Inject synthetic telemetry, attacks, or poisoned traffic directly into the run."""
        clk = SystemClock()
        chk = IntegrityChecker(clock=clk)
        engine = RuleEngine()
        mutator = PoisoningMutator(sidecar=GroundTruthSidecar(), seed=42)

        preset = str(payload.get("preset", "custom")).lower()
        target_host = payload.get("host_id") or "windows-workstation-03"
        if target_host in ("random", "any"):
            devices = app.state.store.get_devices(run_id)
            target_host = random.choice([d["host_id"] for d in devices]) if devices else "windows-workstation-03"

        count = max(1, min(50, int(payload.get("record_count", 5))))
        poison_rate = float(payload.get("poison_rate", 0.0))
        quarantine_imm = bool(payload.get("quarantine_immediate", False))

        service = str(payload.get("service") or "http")
        port = int(payload.get("port") or 80)
        banner = str(payload.get("banner") or "")
        auth_mode = AuthMode.UNKNOWN

        # Presets configuration
        if preset == "apache_cve":
            service, port, banner, auth_mode = "http", 80, "Apache/2.4.49 (Unix) OpenSSL/1.1.1d", AuthMode.UNKNOWN
            poison_rate = 0.0
        elif preset == "default_creds":
            service, port, banner, auth_mode = "http-admin", 8080, "Admin Web Console (default credentials admin / admin)", AuthMode.DEFAULT
            poison_rate = 0.0
        elif preset == "telnet_leak":
            service, port, banner, auth_mode = "telnet", 23, "Cisco IOS Telnet Terminal v15.2", AuthMode.UNKNOWN
            poison_rate = 0.0
        elif preset == "deprecated_tls":
            service, port, banner, auth_mode = "https", 443, "Legacy Web Portal", AuthMode.UNKNOWN
        elif preset == "poison_storm":
            poison_rate = 1.0
        elif preset == "normal_traffic":
            service, port, banner, auth_mode = "https", 443, "Enterprise Portal TLSv1.3", AuthMode.REQUIRED
            poison_rate = 0.0

        tls_ver = payload.get("tls_version") or ("SSLv3" if preset == "deprecated_tls" else None)

        record_gateway_event(
            app.state.store,
            run_id,
            EventType.STATE_TRANSITION,
            component="fleet_sensor",
            host_id=target_host,
            details={
                "action": "operator_burst_injected",
                "preset": preset,
                "count": count,
                "poison_rate": poison_rate,
                "target_host": target_host,
            },
        )

        injected_records = []
        clean_records = []
        rejected_records = []
        findings_created = []

        ops = [
            InjectionOperator.SERVICE_BANNER_MISMATCH,
            InjectionOperator.TLS_CLAIM_CONTRADICTION,
            InjectionOperator.STALE_TIMESTAMP,
            InjectionOperator.PROMPT_INJECTION_BANNER,
        ]

        for i in range(count):
            rid = f"rec-inj-{uuid.uuid4().hex[:8]}"
            base_rec = TelemetryRecord(
                record_id=rid,
                host_id=target_host,
                ip="192.168.10.50",
                port=port,
                service=service,
                banner=banner,
                tls_version=tls_ver,
                auth_mode=auth_mode,
                generated_at=clk.now_iso(),
                source=TelemetrySource.SYNTHETIC_SIMULATOR,
            )

            is_poisoned = False
            inj_type = None
            rec = base_rec
            if random.random() < poison_rate:
                op = random.choice(ops)
                rec = mutator.mutate(baseline=base_rec, operator=op, new_record_id=rid)
                is_poisoned = True
                inj_type = op.value

            app.state.store.save_ground_truth(
                record_id=rec.record_id,
                run_id=run_id,
                host_id=rec.host_id,
                cycle=999,
                is_vulnerable=bool(preset in ("apache_cve", "default_creds", "telnet_leak", "deprecated_tls")),
                expected_rules=[preset],
                is_poisoned=is_poisoned,
                injection_type=inj_type,
            )

            record_gateway_event(
                app.state.store,
                run_id,
                EventType.RECORD_RECEIVED,
                component="fleet_sensor",
                record_id=rec.record_id,
                host_id=rec.host_id,
                details={
                    "service": rec.service,
                    "port": rec.port,
                    "is_poisoned": is_poisoned,
                    "preset": preset,
                },
            )

            flags = chk.check_record(rec)
            if flags:
                app.state.store.save_telemetry_record(rec, run_id=run_id, is_poisoned=True)
                rejected_records.append(rec.record_id)
                record_gateway_event(
                    app.state.store,
                    run_id,
                    EventType.RECORD_REJECTED,
                    component="integrity_checker",
                    status=EventStatus.REJECTED,
                    record_id=rec.record_id,
                    host_id=rec.host_id,
                    reason_code=flags[0].reason_code.value,
                    details={"flags": len(flags)},
                )
            else:
                app.state.store.save_telemetry_record(rec, run_id=run_id, is_poisoned=False)
                clean_records.append(rec)

            injected_records.append(rec)

        # Scanner Worker processes clean records
        if clean_records:
            record_gateway_event(
                app.state.store,
                run_id,
                EventType.STATE_TRANSITION,
                component="scanner_worker",
                status=EventStatus.OK,
                details={
                    "action": "batch_scan_initiated",
                    "clean_records": len(clean_records),
                    "target_host": target_host,
                },
            )

            for rec in clean_records:
                eval_fnds = engine.evaluate_record(
                    rec,
                    run_id=run_id,
                    finding_id_generator=lambda: f"fnd-{uuid.uuid4().hex[:8]}",
                    timestamp_iso=clk.now_iso(),
                )
                for f in eval_fnds:
                    is_q = quarantine_imm or f.severity in (Severity.CRITICAL, Severity.HIGH)
                    cve = "CVE-2021-41773" if "apache" in rec.banner.lower() else None
                    app.state.store.save_finding(f, cve_id=cve, quarantined=is_q)
                    findings_created.append(f.finding_id)

                    record_gateway_event(
                        app.state.store,
                        run_id,
                        EventType.FINDING_CREATED,
                        component="scanner_worker",
                        host_id=f.host_id,
                        finding_id=f.finding_id,
                        rule_id=f.rule_id,
                        details={"severity": f.severity.value, "quarantined": is_q},
                    )

                    # Inter-agent escalation message cascade
                    msg_scan = Message(
                        message_id=f"msg-{uuid.uuid4().hex[:8]}",
                        run_id=run_id,
                        sender="scanner_worker",
                        receiver="supervisor-agent",
                        performative=Performative.TASK_RESULT,
                        timestamp_utc=clk.now_iso(),
                        nonce=uuid.uuid4().hex[:12],
                        payload={"finding_id": f.finding_id, "host_id": f.host_id, "severity": f.severity.value},
                    )
                    app.state.store.save_message(msg_scan)
                    record_gateway_event(
                        app.state.store,
                        run_id,
                        EventType.MESSAGE_SENT,
                        component="scanner_worker",
                        details={"receiver": "supervisor-agent", "performative": "TASK_RESULT", "payload": msg_scan.payload},
                    )

                    msg_l1 = Message(
                        message_id=f"msg-{uuid.uuid4().hex[:8]}",
                        run_id=run_id,
                        sender="supervisor-agent",
                        receiver="analyst-l1-triage",
                        performative=Performative.ALERT,
                        timestamp_utc=clk.now_iso(),
                        nonce=uuid.uuid4().hex[:12],
                        payload={"finding_id": f.finding_id, "host_id": f.host_id, "severity": f.severity.value},
                    )
                    app.state.store.save_message(msg_l1)
                    record_gateway_event(
                        app.state.store,
                        run_id,
                        EventType.MESSAGE_SENT,
                        component="supervisor-agent",
                        details={"receiver": "analyst-l1-triage", "performative": "ALERT", "payload": msg_l1.payload},
                    )

                    if f.severity in (Severity.CRITICAL, Severity.HIGH):
                        msg_l2 = Message(
                            message_id=f"msg-{uuid.uuid4().hex[:8]}",
                            run_id=run_id,
                            sender="analyst-l1-triage",
                            receiver="analyst-l2-incident",
                            performative=Performative.ALERT,
                            timestamp_utc=clk.now_iso(),
                            nonce=uuid.uuid4().hex[:12],
                            payload={"host_id": f.host_id, "severity": f.severity.value, "escalation": True},
                        )
                        app.state.store.save_message(msg_l2)
                        record_gateway_event(
                            app.state.store,
                            run_id,
                            EventType.MESSAGE_SENT,
                            component="analyst-l1-triage",
                            details={"receiver": "analyst-l2-incident", "performative": "ALERT", "payload": msg_l2.payload},
                        )

                    if is_q:
                        msg_l3 = Message(
                            message_id=f"msg-{uuid.uuid4().hex[:8]}",
                            run_id=run_id,
                            sender="analyst-l2-incident",
                            receiver="analyst-l3-containment",
                            performative=Performative.ALERT,
                            timestamp_utc=clk.now_iso(),
                            nonce=uuid.uuid4().hex[:12],
                            payload={"host_id": f.host_id, "action": "quarantine_request"},
                        )
                        app.state.store.save_message(msg_l3)
                        record_gateway_event(
                            app.state.store,
                            run_id,
                            EventType.MESSAGE_SENT,
                            component="analyst-l2-incident",
                            details={"receiver": "analyst-l3-containment", "performative": "ALERT", "payload": msg_l3.payload},
                        )

                        record_gateway_event(
                            app.state.store,
                            run_id,
                            EventType.STATE_TRANSITION,
                            component="analyst-l3-containment",
                            host_id=f.host_id,
                            details={"action": "quarantine_enforced", "host_id": f.host_id, "reason": "Operator injected exploit detected"},
                        )

        return {
            "status": "ok",
            "host_id": target_host,
            "records_injected": len(injected_records),
            "clean_verified": len(clean_records),
            "poisoned_rejected": len(rejected_records),
            "findings_created": len(findings_created),
            "quarantined": quarantine_imm or len(findings_created) > 0,
        }

    @app.post("/api/runs/{run_id}/simulation/tune")
    async def tune_simulation(
        run_id: str,
        payload: dict[str, Any] = Body(default_factory=dict),
    ) -> dict[str, Any]:
        """Tune live simulation pace, poison ratio, and active profile."""
        from sentryscan.platform import core as platform_core
        pace = float(payload.get("pace", 0.5))
        poison_ratio = float(payload.get("poison_ratio", 0.2))
        profile = str(payload.get("profile", "enterprise"))

        platform_core.set_setting(app.state.store, run_id, "simulation_pace", str(pace))
        platform_core.set_setting(app.state.store, run_id, "poison_ratio", str(poison_ratio))
        platform_core.set_setting(app.state.store, run_id, "profile", profile)

        record_gateway_event(
            app.state.store,
            run_id,
            EventType.STATE_TRANSITION,
            component="fleet_sensor",
            details={"action": "simulation_parameters_tuned", "pace": pace, "poison_ratio": poison_ratio, "profile": profile},
        )
        return {"status": "ok", "settings": {"pace": pace, "poison_ratio": poison_ratio, "profile": profile}}

    @app.post("/api/runs/{run_id}/hosts/{host_id}/quarantine")
    async def toggle_host_quarantine(
        run_id: str,
        host_id: str,
        payload: dict[str, Any] = Body(default_factory=dict),
    ) -> dict[str, Any]:
        """Manually quarantine or release an endpoint asset."""
        action = str(payload.get("action", "isolate")).lower()
        reason = str(payload.get("reason", "Operator manual containment action"))
        is_q = 1 if action == "isolate" else 0

        with app.state.store._lock, app.state.store._conn:
            app.state.store._conn.execute(
                "UPDATE findings SET quarantined = ? WHERE run_id = ? AND host_id = ?",
                (is_q, run_id, host_id),
            )

        action_name = "quarantine_enforced" if is_q else "quarantine_released"
        record_gateway_event(
            app.state.store,
            run_id,
            EventType.STATE_TRANSITION,
            component="analyst-l3-containment",
            host_id=host_id,
            details={"action": action_name, "reason": reason, "manual": True},
        )
        return {"status": "ok", "host_id": host_id, "quarantined": bool(is_q), "action": action_name}

    # -------------------------------------------------------------------------
    # WebSocket Endpoint (HLD §8.3, §8.5)
    # -------------------------------------------------------------------------

    @app.websocket("/ws/{run_id}")
    async def websocket_endpoint(websocket: WebSocket, run_id: str) -> None:
        manager: ConnectionManager = app.state.manager
        await manager.connect(run_id, websocket)
        cursor = {"next": 1}

        async def pump() -> None:
            """Push events written after subscription point (live streaming)."""
            while True:
                await asyncio.sleep(0.2)
                if cursor["next"] is None:
                    continue
                try:
                    for ev in app.state.store.get_events(run_id=run_id, from_seq=cursor["next"], limit=200):
                        await websocket.send_text(json.dumps(ev))
                        cursor["next"] = ev["seq"] + 1
                except (WebSocketDisconnect, ConnectionResetError, Exception):
                    break

        pump_task = asyncio.create_task(pump())
        try:
            while True:
                data = await websocket.receive_text()
                try:
                    payload = json.loads(data)
                    if payload.get("type") == "subscribe":
                        from_seq = int(payload.get("from_seq", 1))
                        past_events = app.state.store.get_events(
                            run_id=run_id,
                            from_seq=from_seq,
                            limit=500,
                        )
                        for ev in past_events:
                            await websocket.send_text(json.dumps(ev))
                        if past_events:
                            cursor["next"] = past_events[-1]["seq"] + 1
                        else:
                            cursor["next"] = max(1, from_seq)
                except Exception as parse_err:
                    logger.debug("Non-critical WebSocket message parse error: %s", parse_err)
        except (WebSocketDisconnect, ConnectionResetError, Exception):
            pass
        finally:
            pump_task.cancel()
            await manager.disconnect(run_id, websocket)

    # -------------------------------------------------------------------------
    # Static Assets & Fallback HTML
    # -------------------------------------------------------------------------

    dist_path = Path(static_dir) if static_dir is not None else Path("frontend/dist")
    if dist_path.exists() and (dist_path / "index.html").exists():
        @app.get("/master", response_class=HTMLResponse)
        async def master_console_page() -> str:
            """Direct /master route serving the SentryScan single-page application focused on the Master Cyber Console."""
            html_content = (dist_path / "index.html").read_text(encoding="utf-8")
            script = "<script>if(!window.location.hash || window.location.hash === '#/'){window.location.hash='#/master';}</script>"
            return html_content.replace("</body>", f"{script}</body>")

        app.mount("/", StaticFiles(directory=str(dist_path), html=True), name="frontend")
    else:
        @app.get("/", response_class=HTMLResponse)
        async def index_fallback() -> str:
            return get_default_dashboard_html()

    return app


def get_default_dashboard_html() -> str:
    """Return fallback minimal dashboard HTML if frontend/dist is missing."""
    return """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>SentryScan SOC Gateway</title>
<style>
body { font-family: monospace; background: #070a09; color: #d9e6df; padding: 40px; }
h1 { color: #5dff9d; }
a { color: #4da3ff; }
</style>
</head>
<body>
<h1>SentryScan Autonomous SOC Gateway</h1>
<p>Gateway API is active. Frontend build missing at <code>frontend/dist</code>.</p>
<p>Run <code>cd frontend && npm run build</code> to compile the cyber console.</p>
<p>API endpoints available at <a href="/api/health">/api/health</a> and <a href="/api/runs">/api/runs</a>.</p>
</body>
</html>"""
