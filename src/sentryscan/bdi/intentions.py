"""BDI Intentions and operational plan models for SentryScan."""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field

from sentryscan.bdi.desires import DesireType


class IntentionStepStatus(str, Enum):
    """Execution status of an individual intention step."""

    PENDING = "PENDING"
    IN_PROGRESS = "IN_PROGRESS"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class IntentionStep(BaseModel):
    """An individual atomic action within an intention plan."""

    step_id: str
    action: str
    parameters: dict[str, Any] = Field(default_factory=dict)
    status: IntentionStepStatus = IntentionStepStatus.PENDING
    result: dict[str, Any] | None = None


class IntentionState(str, Enum):
    """Lifecycle status of a committed intention."""

    ACTIVE = "ACTIVE"
    COMPLETED = "COMPLETED"
    ABANDONED = "ABANDONED"
    SUSPENDED = "SUSPENDED"


class Intention(BaseModel):
    """Committed plan of action adopted by the agent pursuing an active desire."""

    intention_id: str
    desire_id: str
    desire_type: DesireType
    target_host: str | None = None
    state: IntentionState = IntentionState.ACTIVE
    steps: list[IntentionStep] = Field(default_factory=list)
    current_step_index: int = 0
    adopted_at_iso: str = ""
    rationale: str = ""
    reconsideration_reason: str | None = None

    def current_step(self) -> IntentionStep | None:
        """Return the current step to execute, or None if all completed."""
        if self.current_step_index < len(self.steps):
            return self.steps[self.current_step_index]
        return None

    def advance_step(self, step_result: dict[str, Any] | None = None) -> bool:
        """Mark current step completed and advance pointer. Returns True if more steps remain."""
        step = self.current_step()
        if step is not None:
            step.status = IntentionStepStatus.COMPLETED
            step.result = step_result
            self.current_step_index += 1

        if self.current_step_index >= len(self.steps):
            self.state = IntentionState.COMPLETED
            return False
        return True

    def abandon(self, reason: str) -> None:
        """Abandon the intention due to reconsideration or invalidation."""
        self.state = IntentionState.ABANDONED
        self.reconsideration_reason = reason
        step = self.current_step()
        if step and step.status == IntentionStepStatus.PENDING:
            step.status = IntentionStepStatus.FAILED

    def is_finished(self) -> bool:
        """Return True if intention has either completed or been abandoned."""
        return self.state in (IntentionState.COMPLETED, IntentionState.ABANDONED)
