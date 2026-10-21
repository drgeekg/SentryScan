"""Loopback FastAPI REST and WebSocket gateway for SentryScan."""

from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Query, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles

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
        logger.info(
            "WebSocket connected for run_id=%s (total=%d)",
            run_id,
            len(self.active_connections[run_id]),
        )

    async def disconnect(self, run_id: str, websocket: WebSocket) -> None:
        """Unregister a disconnected WebSocket subscriber."""
        async with self._lock:
            if run_id in self.active_connections:
                if websocket in self.active_connections[run_id]:
                    self.active_connections[run_id].remove(websocket)
                if not self.active_connections[run_id]:
                    del self.active_connections[run_id]
        logger.info("WebSocket disconnected for run_id=%s", run_id)

    async def broadcast(self, run_id: str, message: dict[str, Any]) -> None:
        """Broadcast a message payload to all active subscribers for run_id."""
        async with self._lock:
            sockets = list(self.active_connections.get(run_id, []))

        text_data = json.dumps(message)
        for ws in sockets:
            try:
                await ws.send_text(text_data)
            except Exception as err:
                logger.warning("Failed to send WebSocket message: %s", err)


def get_default_dashboard_html() -> str:
    """Return dashboard HTML from frontend/dist/index.html or minimal fallback."""
    dist_file = Path("frontend/dist/index.html")
    if dist_file.exists():
        return dist_file.read_text(encoding="utf-8")
    return (
        "<!DOCTYPE html><html><head><title>SentryScan</title></head>"
        "<body><h1>SentryScan Dashboard</h1><p>Active</p></body></html>"
    )


def create_app(
    store: SQLiteRunStore | None = None,
    static_dir: Path | str | None = None,
) -> FastAPI:
    """Instantiate and configure the FastAPI application."""
    app = FastAPI(
        title="SentryScan Dashboard Gateway",
        description="REST and WebSocket API for live multi-agent security simulation",
        version="0.1.0",
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
    # REST Endpoints
    # -------------------------------------------------------------------------

    @app.get("/api/health")
    async def get_health() -> dict[str, str]:
        return {"status": "ok", "service": "SentryScan Dashboard Gateway"}

    @app.get("/api/runs")
    async def list_runs() -> list[dict[str, Any]]:
        return app.state.store.list_runs()

    @app.get("/api/runs/{run_id}")
    async def get_run(run_id: str) -> dict[str, Any]:
        run = app.state.store.get_run(run_id)
        if not run:
            raise HTTPException(status_code=404, detail=f"Run {run_id} not found")
        return run

    @app.get("/api/runs/{run_id}/events")
    async def get_events(
        run_id: str,
        from_seq: int = Query(default=1, ge=1),
        limit: int = Query(default=1000, ge=1, le=10000),
    ) -> list[dict[str, Any]]:
        return app.state.store.get_events(run_id=run_id, from_seq=from_seq, limit=limit)

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

    @app.get("/api/runs/{run_id}/parity")
    async def get_parity(run_id: str, jsonl_path: str = "") -> dict[str, Any]:
        path = jsonl_path or f"runs/{run_id}/trace.jsonl"
        return app.state.store.verify_parity(run_id=run_id, jsonl_path=path)

    # -------------------------------------------------------------------------
    # WebSocket Endpoint (HLD §8.3, §8.5)
    # -------------------------------------------------------------------------

    @app.websocket("/ws/{run_id}")
    async def websocket_endpoint(websocket: WebSocket, run_id: str) -> None:
        manager: ConnectionManager = app.state.manager
        await manager.connect(run_id, websocket)
        try:
            while True:
                data = await websocket.receive_text()
                try:
                    payload = json.loads(data)
                    # Handle sequence subscription and backfill
                    if payload.get("type") == "subscribe":
                        from_seq = int(payload.get("from_seq", 1))
                        past_events = app.state.store.get_events(
                            run_id=run_id,
                            from_seq=from_seq,
                            limit=1000,
                        )
                        for ev in past_events:
                            await websocket.send_text(json.dumps(ev))
                except Exception as parse_err:
                    logger.debug("Non-critical WebSocket message parse error: %s", parse_err)
        except WebSocketDisconnect:
            await manager.disconnect(run_id, websocket)

    # -------------------------------------------------------------------------
    # Static Assets & Fallback HTML
    # -------------------------------------------------------------------------

    dist_path = Path(static_dir) if static_dir is not None else Path("frontend/dist")
    if dist_path.exists() and (dist_path / "index.html").exists():
        app.mount("/", StaticFiles(directory=str(dist_path), html=True), name="frontend")
    else:
        @app.get("/", response_class=HTMLResponse)
        async def index_fallback() -> str:
            return get_default_dashboard_html()

    return app
