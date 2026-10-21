"""Typed graph state for LangGraph supervisor orchestration."""

from __future__ import annotations

import operator
from typing import Annotated, Any, TypedDict

from sentryscan.contracts.finding import Finding
from sentryscan.contracts.message import Message
from sentryscan.contracts.proposal import Proposal


class SupervisorState(TypedDict, total=False):
    """Authoritative typed state dictionary for the multi-agent supervisor graph."""

    run_id: str
    task_id: str
    phase: str
    negotiation_round: int
    max_rounds: int
    constraints: dict[str, Any]
    batches: dict[str, list[dict[str, Any]]]
    proposals: dict[str, Proposal]
    winning_proposal: Proposal | None
    awarded_proposer: str | None
    awarded_batch_ids: list[str]

    # Reducer channels: accumulators across fan-out nodes and multi-turn negotiation
    messages: Annotated[list[Message], operator.add]
    findings: Annotated[list[Finding], operator.add]
    analyst_replies: Annotated[list[Message], operator.add]
    quarantined_hosts: Annotated[list[str], operator.add]
    errors: Annotated[list[str], operator.add]
    metadata: dict[str, Any]
