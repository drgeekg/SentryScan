"""Unit tests for ScoutAgent and TriageAgent proposal generation."""

from __future__ import annotations

from sentryscan.agents.scout import ScoutAgent
from sentryscan.agents.triage import TriageAgent
from sentryscan.common.id_generator import IdGenerator
from sentryscan.llm.deterministic import DeterministicLLMProvider


def _sample_batches() -> dict[str, list[dict]]:
    return {
        "batch-01": [
            {
                "host_id": "192.0.2.10",
                "port": 22,
                "service": "ssh",
                "banner": "SSH-2.0-OpenSSH_7.2p2",
            },
            {
                "host_id": "192.0.2.11",
                "port": 80,
                "service": "http",
                "banner": "Apache/2.4.41",
            },
        ],
        "batch-02": [
            {
                "host_id": "192.0.2.12",
                "port": 23,
                "service": "telnet",
                "banner": "Linux Telnetd",
            },
            {
                "host_id": "192.0.2.13",
                "port": 443,
                "service": "https",
                "banner": "TLS 1.0 Enabled",
            },
        ],
        "batch-03": [
            {
                "host_id": "192.0.2.14",
                "port": 8080,
                "service": "http-alt",
                "banner": "Jetty 9.4",
            },
        ],
    }


def test_scout_agent_coverage_priority():
    llm = DeterministicLLMProvider()
    id_gen = IdGenerator(seed=101)
    scout = ScoutAgent(llm_provider=llm, id_gen=id_gen)

    batches = _sample_batches()
    proposal = scout.propose(
        task_id="task-01",
        batches=batches,
        constraints={"max_cost": 50.0, "max_time": 500.0},
    )

    assert proposal.proposer == "scout-agent"
    assert len(proposal.batch_ids) > 0
    assert proposal.est_cost > 0
    assert proposal.est_coverage > 0
    assert "coverage" in proposal.rationale.lower()


def test_triage_agent_risk_priority():
    llm = DeterministicLLMProvider()
    id_gen = IdGenerator(seed=102)
    triage = TriageAgent(llm_provider=llm, id_gen=id_gen)

    batches = _sample_batches()
    proposal = triage.propose(
        task_id="task-01",
        batches=batches,
        constraints={"max_cost": 50.0, "max_time": 500.0},
    )

    assert proposal.proposer == "triage-agent"
    # Batch-02 has Telnet (port 23) and TLS 1.0, so should be prioritized
    assert "batch-02" in proposal.batch_ids
    assert proposal.est_coverage > 0
    assert "triage" in proposal.rationale.lower() or "risk" in proposal.rationale.lower()
