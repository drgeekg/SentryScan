"""Unit tests for LangGraph state definitions and Proposal contract."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from sentryscan.contracts.proposal import Proposal
from sentryscan.graphs.state import SupervisorState


def test_proposal_validation_success():
    p = Proposal(
        proposal_id="prop-001",
        proposer="scout-agent",
        task_id="task-01",
        batch_ids=["batch-01", "batch-02"],
        est_cost=15.0,
        est_time=120.0,
        est_coverage=0.85,
        risk=0.15,
        round=1,
        rationale="Maximizes broad endpoint coverage across subnet.",
    )
    assert p.proposal_id == "prop-001"
    assert p.proposer == "scout-agent"
    assert p.est_coverage == 0.85
    assert len(p.batch_ids) == 2


def test_proposal_validation_bounds():
    # est_coverage must be <= 1.0
    with pytest.raises(ValidationError):
        Proposal(
            proposal_id="prop-bad",
            proposer="scout-agent",
            task_id="task-01",
            batch_ids=["b-1"],
            est_cost=10.0,
            est_time=50.0,
            est_coverage=1.5,  # Exceeds 1.0 limit
            risk=0.2,
        )


def test_supervisor_state_structure():
    state: SupervisorState = {
        "run_id": "run-test-3-1",
        "task_id": "task-alloc-01",
        "phase": "CFP",
        "negotiation_round": 1,
        "max_rounds": 5,
        "constraints": {"max_cost": 50.0, "max_time": 200.0},
        "batches": {"batch-01": [{"host_id": "sim-host-001"}]},
        "proposals": {},
        "winning_proposal": None,
        "awarded_proposer": None,
        "awarded_batch_ids": [],
        "messages": [],
        "findings": [],
        "errors": [],
        "metadata": {},
    }
    assert state["phase"] == "CFP"
    assert state["max_rounds"] == 5
