"""State models and transition records for the deliberative Analyst graph."""

from __future__ import annotations

from typing import Any, TypedDict

from pydantic import BaseModel, Field

from sentryscan.bdi.beliefs import BeliefBase
from sentryscan.bdi.intentions import Intention


class ReconsiderationRecord(BaseModel):
    """Forensic record documenting why, when, and how an intention was reconsidered."""

    timestamp_utc: str
    trigger: str
    material_change: bool
    reconsidered: bool
    previous_intention_id: str | None = None
    previous_desire_type: str | None = None
    new_intention_id: str | None = None
    new_desire_type: str | None = None
    replan_reason: str
    details: dict[str, Any] = Field(default_factory=dict)


class AnalystGraphState(TypedDict, total=False):
    """Typed state for the deliberative Analyst LangGraph workflow."""

    beliefs: BeliefBase
    active_intention: Intention | None
    reconsideration_history: list[ReconsiderationRecord]
    incoming_percept: dict[str, Any] | None
    reconsideration_needed: bool
    replan_reason: str
    generated_action: dict[str, Any] | None
    status: str
