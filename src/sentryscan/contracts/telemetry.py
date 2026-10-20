"""Strongly typed telemetry record contract and validation."""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, field_validator


class AuthMode(str, Enum):
    """Authentication requirement mode for an exposed service."""

    REQUIRED = "required"
    DEFAULT = "default"
    ANONYMOUS = "anonymous"
    UNKNOWN = "unknown"


class TelemetrySource(str, Enum):
    """Provenance source for synthetic telemetry."""

    SYNTHETIC_FIXTURE = "synthetic_fixture"
    SYNTHETIC_SIMULATOR = "synthetic_simulator"


class TelemetryRecord(BaseModel):
    """Canonical model for synthetic endpoint telemetry percepts."""

    record_id: str = Field(..., description="Unique record identifier within a run")
    host_id: str = Field(..., min_length=1, description="Synthetic host identity join key")
    ip: str = Field(..., description="RFC 5737/3849 display IP; never scanned")
    port: int = Field(..., ge=1, le=65535, description="Synthetic service port (1-65535)")
    service: str = Field(..., min_length=1, description="Service protocol name")
    banner: str = Field("", description="Service banner or response string; untrusted data")
    tls_version: str | None = Field(None, description="TLS/SSL protocol version if applicable")
    auth_mode: AuthMode = Field(AuthMode.UNKNOWN, description="Authentication posture")
    generated_at: str = Field(..., description="ISO-8601 UTC creation timestamp")
    source: TelemetrySource = Field(
        TelemetrySource.SYNTHETIC_FIXTURE,
        description="Declared provenance source",
    )

    @field_validator("port")
    @classmethod
    def validate_port_range(cls, v: int) -> int:
        if not (1 <= v <= 65535):
            raise ValueError(f"Port {v} is out of valid range (1-65535)")
        return v

    @field_validator("host_id")
    @classmethod
    def validate_host_id(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("host_id cannot be blank")
        return v.strip()

    def to_percept_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation for rule evaluation."""
        return self.model_dump()
