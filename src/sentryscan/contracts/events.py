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
    MESSAGE_SENT = "message_sent"
    MESSAGE_RECEIVED = "message_received"
    STATE_TRANSITION = "state_transition"
    PARAMS_UPDATE = "params_update"
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
    component: str = Field(..., description="Originating agent, parser, or actuator")
    status: EventStatus = Field(default=EventStatus.OK, description="Resulting status")
    record_id: str | None = Field(default=None, description="Correlated telemetry record ID")
    host_id: str | None = Field(default=None, description="Correlated host ID")
    rule_id: str | None = Field(default=None, description="Correlated rule ID")
    finding_id: str | None = Field(default=None, description="Correlated finding ID")
    reason_code: str | None = Field(
        default=None, description="Machine-readable error/rejection reason"
    )
    details: dict[str, Any] = Field(default_factory=dict, description="Arbitrary typed metadata")
