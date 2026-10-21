"""Dashboard gateway module providing loopback FastAPI REST and WebSocket endpoints."""

from sentryscan.dashboard_gateway.server import ConnectionManager, create_app

__all__ = ["ConnectionManager", "create_app"]
