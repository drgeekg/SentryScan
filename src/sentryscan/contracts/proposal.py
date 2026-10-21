"""Proposal contract for Contract-Net negotiation."""

from __future__ import annotations

from pydantic import BaseModel, Field


class Proposal(BaseModel):
    """Proposal model representing an agent's bid for analyzing telemetry batches."""

    proposal_id: str = Field(..., description="Unique proposal identifier")
    proposer: str = Field(
        ..., description="Proposing agent identifier (e.g. scout-agent, triage-agent)"
    )
    task_id: str = Field(..., description="Correlated task identifier")
    batch_ids: list[str] = Field(..., description="Ordered list of proposed batch IDs")
    est_cost: float = Field(..., ge=0.0, description="Estimated resource / execution cost")
    est_time: float = Field(..., ge=0.0, description="Estimated execution time in milliseconds")
    est_coverage: float = Field(
        ..., ge=0.0, le=1.0, description="Estimated host / severity coverage [0, 1]"
    )
    risk: float = Field(..., ge=0.0, le=1.0, description="Estimated risk score [0, 1]")
    round: int = Field(default=1, ge=1, description="Negotiation round number")
    rationale_ref: str | None = Field(default=None, description="Pointer to full rationale text")
    rationale: str | None = Field(default=None, description="Concise rationale for this proposal")
