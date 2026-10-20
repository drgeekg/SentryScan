"""Audit event models and lifecycle performatives."""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class EventType(str, Enum):
    """Categorical classification of observable agent events."""

    RUN_STARTED = "run_started"
    RECORD_RECEIVED = "record_received"
    RECORD_REJECTED = "record_rejected"
    RULE_MATCHED = "rule_matched"
    UNMATCHED_RECORD = "unmatched_record"
    FINDING_CREATED = "finding_created"
    REPORT_WRITTEN = "report_written"
    RUN_COMPLETED = "run_completed"


class EventStatus(str, Enum):
    """Status outcome of a recorded agent action."""

    OK = "OK"
    REJECTED = "REJECTED"
    ERROR = "ERROR"
    UNRESOLVED = "UNRESOLVED"


class AgentEvent(BaseModel):
    """Canonical observable event model representing an action or decision."""

    event_id: str = Field(..., description="Unique event identifier")
    run_id: str = Field(..., description="Correlated simulation run ID")
    seq: int = Field(..., ge=1, description="Gap-free monotonic sequence number")
    timestamp_utc: str = Field(..., description="ISO-8601 UTC timestamp")
    event_type: EventType = Field(..., description="Classification of the event")
    component: str = Field(..., min_length=1, description="Originating component name")
    record_id: str | None = Field(None, description="Correlated telemetry record ID")
    host_id: str | None = Field(None, description="Correlated host ID")
    rule_id: str | None = Field(None, description="Correlated rule ID")
    finding_id: str | None = Field(None, description="Correlated finding ID")
    status: EventStatus = Field(EventStatus.OK, description="Execution status")
    reason_code: str | None = Field(None, description="Machine-readable outcome code")
    details: dict[str, Any] = Field(default_factory=dict, description="Contextual payload")
