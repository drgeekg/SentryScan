"""Unit tests for the LangGraph supervisor workflow and worker Send fan-out."""

from __future__ import annotationsfrom sentryscan.common.clock import FakeClockfrom sentryscan.common.id_generator import IdGeneratorfrom sentryscan.contracts.message import Performativefrom sentryscan.graphs.supervisor import build_supervisor_graphfrom sentryscan.llm.deterministic import DeterministicLLMProviderdef _build_test_batches():
    return {
        "batch-01": [
            {
                "record_id": "tel-000001",
                "host_id": "sim-host-001",
                "ip": "192.0.2.10",
                "port": 22,
                "service": "ssh",
                "banner": "SSH-2.0-OpenSSH_7.2p2",
                "auth_mode": "required",
                "tls_version": None,
                "generated_at": "2026-10-21T07:00:00Z",
            },
            {
                "record_id": "tel-000002",
                "host_id": "sim-host-002",
                "ip": "192.0.2.11",
                "port": 80,
                "service": "http",
                "banner": "Apache/2.4.49",  # Matches RULE-005 critical
                "auth_mode": "unknown",
                "tls_version": None,
                "generated_at": "2026-10-21T07:00:00Z",
            },
        ],
        "batch-02": [
            {
                "record_id": "tel-000003",
                "host_id": "sim-host-003",
                "ip": "192.0.2.12",
                "port": 23,
                "service": "telnet",
                "banner": "Linux telnetd",
                "auth_mode": "default",  # Matches RULE-001 & RULE-004
                "tls_version": None,
                "generated_at": "2026-10-21T07:00:00Z",
            },
            {
                "record_id": "tel-000004",
                "host_id": "sim-host-004",
                "ip": "192.0.2.13",
                "port": 443,
                "service": "https",
                "banner": "nginx/1.18.0",
                "auth_mode": "required",
                "tls_version": "TLSv1.0",  # Matches RULE-003
                "generated_at": "2026-10-21T07:00:00Z",
            },
        ],
    }


def test_supervisor_graph_awarded_and_fan_out():
    clock = FakeClock("2026-10-21T07:00:00Z")
    id_gen = IdGenerator(seed=42)
    llm = DeterministicLLMProvider()

    app = build_supervisor_graph(
        clock=clock,
        id_gen=id_gen,
        llm_provider=llm,
        max_rounds=3,
    )

    initial_state = {
        "run_id": "run-test-graph-01",
        "task_id": "task-alloc-01",
        "batches": _build_test_batches(),
        "constraints": {"max_cost": 100.0, "max_time": 500.0},
        "messages": [],
        "findings": [],
        "errors": [],
    }

    final_state = app.invoke(initial_state)

    assert final_state["phase"] == "COMPLETED"
    assert final_state["winning_proposal"] is not None
    assert final_state["awarded_proposer"] in ("scout-agent", "triage-agent")
    assert len(final_state["awarded_batch_ids"]) > 0

    # Ensure findings were discovered and aggregated across workers
    assert len(final_state["findings"]) > 0
    finding_rules = {f.rule_id for f in final_state["findings"]}
    # RULE-001 (Telnet) and/or RULE-003 (Deprecated TLS) should be triggered
    assert "RULE-001" in finding_rules or "RULE-003" in finding_rules

    # Check that worker TASK_RESULT messages are present in accumulated messages
    worker_messages = [
        m for m in final_state["messages"] if m.performative == Performative.TASK_RESULT
    ]
    assert len(worker_messages) == len(final_state["awarded_batch_ids"])


def test_supervisor_graph_unresolved_termination():
    clock = FakeClock("2026-10-21T07:00:00Z")
    id_gen = IdGenerator(seed=42)

    app = build_supervisor_graph(
        clock=clock,
        id_gen=id_gen,
        max_rounds=2,
    )

    # Impossible budget constraint
    initial_state = {
        "run_id": "run-test-graph-02",
        "task_id": "task-alloc-02",
        "batches": _build_test_batches(),
        "constraints": {"max_cost": 0.0001, "max_time": 0.0001},
        "messages": [],
        "findings": [],
        "errors": [],
    }

    final_state = app.invoke(initial_state)

    assert final_state["phase"] == "UNRESOLVED"
    assert final_state["winning_proposal"] is None
    assert len(final_state["findings"]) == 0  # No workers fanned out
    assert len(final_state["errors"]) > 0

def test_supervisor_graph_with_analyst_and_security_gate():
    from sentryscan.agents.analyst import AnalystAgent    from sentryscan.knowledge.enricher import KnowledgeEnricher    from sentryscan.knowledge.ontology import VulnerabilityKnowledgeBase    from sentryscan.security.gate import SecurityGate    from sentryscan.security.identity import AgentIdentity    from sentryscan.security.registry import TrustedAgentRegistry

    clock = FakeClock("2026-10-21T07:00:00Z")
    id_gen = IdGenerator(seed=101)
    llm = DeterministicLLMProvider()

    supervisor_id = AgentIdentity.generate("supervisor-agent")
    analyst_id = AgentIdentity.generate("analyst-agent-01")

    registry = TrustedAgentRegistry()
    registry.register(
        supervisor_id.agent_id, supervisor_id.public_key_hex, description="Supervisor"
    )
    registry.register(analyst_id.agent_id, analyst_id.public_key_hex, description="Analyst")

    gate = SecurityGate(
        agent_id="analyst-agent-01",
        registry=registry,
        clock=clock,
        freshness_window_seconds=30.0,
    )
    ontology = VulnerabilityKnowledgeBase.load_from_file()
    enricher = KnowledgeEnricher(ontology=ontology, enable_online_nvd=False)
    analyst = AnalystAgent(
        agent_id="analyst-agent-01",
        clock=clock,
        id_gen=id_gen,
        enricher=enricher,
        security_gate=gate,
    )

    app = build_supervisor_graph(
        clock=clock,
        id_gen=id_gen,
        llm_provider=llm,
        analyst_agent=analyst,
        supervisor_identity=supervisor_id,
        max_rounds=3,
    )

    initial_state = {
        "run_id": "run-test-graph-analyst",
        "task_id": "task-alloc-analyst",
        "batches": _build_test_batches(),
        "constraints": {"max_cost": 100.0, "max_time": 500.0},
        "messages": [],
        "findings": [],
        "analyst_replies": [],
        "quarantined_hosts": [],
        "errors": [],
    }

    final_state = app.invoke(initial_state)

    assert final_state["phase"] == "COMPLETED"
    assert len(final_state["findings"]) > 0
    assert len(final_state["analyst_replies"]) > 0
    assert len(final_state["quarantined_hosts"]) > 0
    # Host sim-host-002 with Apache 2.4.49 should be quarantined
    assert "sim-host-002" in final_state["quarantined_hosts"]
    assert final_state["metadata"]["quarantined_count"] > 0


def test_supervisor_graph_with_soc_tiers_l1_l2_l3():
    from sentryscan.agents.analyst import AnalystAgent
    from sentryscan.knowledge.enricher import KnowledgeEnricher
    from sentryscan.knowledge.ontology import VulnerabilityKnowledgeBase
    from sentryscan.security.gate import SecurityGate
    from sentryscan.security.identity import AgentIdentity
    from sentryscan.security.registry import TrustedAgentRegistry

    clock = FakeClock("2026-10-21T07:00:00Z")
    id_gen = IdGenerator(seed=202)
    llm = DeterministicLLMProvider()

    agent_names = (
        "supervisor-agent",
        "analyst-l1-triage",
        "analyst-l2-incident",
        "analyst-l3-containment",
    )
    ids = {n: AgentIdentity.generate(n) for n in agent_names}
    registry = TrustedAgentRegistry()
    for i in ids.values():
        registry.register(i.agent_id, i.public_key_hex, description=i.agent_id)

    ontology = VulnerabilityKnowledgeBase.load_from_file()
    analyst_tiers = {
        tier: AnalystAgent(
            agent_id=aid,
            tier=tier,
            clock=clock,
            id_gen=id_gen,
            enricher=KnowledgeEnricher(ontology=ontology, enable_online_nvd=False),
            security_gate=SecurityGate(
                agent_id=aid, registry=registry, clock=clock, freshness_window_seconds=30.0
            ),
        )
        for tier, aid in (
            ("L1", "analyst-l1-triage"),
            ("L2", "analyst-l2-incident"),
            ("L3", "analyst-l3-containment"),
        )
    }

    app = build_supervisor_graph(
        clock=clock,
        id_gen=id_gen,
        llm_provider=llm,
        analyst_tiers=analyst_tiers,
        analyst_identities=ids,
        supervisor_identity=ids["supervisor-agent"],
        max_rounds=3,
    )

    initial_state = {
        "run_id": "run-test-soc-tiers",
        "task_id": "task-soc-tiers",
        "batches": _build_test_batches(),
        "constraints": {"max_cost": 100.0, "max_time": 500.0},
        "messages": [],
        "findings": [],
        "analyst_replies": [],
        "quarantined_hosts": [],
        "errors": [],
    }

    final_state = app.invoke(initial_state)

    assert final_state["phase"] == "COMPLETED"
    assert len(final_state["quarantined_hosts"]) > 0

    # Verify full escalation chain in messages:
    # supervisor-agent -> analyst-l1-triage -> analyst-l2-incident -> analyst-l3-containment -> supervisor-agent
    pairs = {(m.sender, m.receiver, m.performative) for m in final_state["messages"]}
    assert ("supervisor-agent", "analyst-l1-triage", Performative.ALERT) in pairs
    assert ("analyst-l1-triage", "analyst-l2-incident", Performative.ALERT) in pairs
    assert ("analyst-l2-incident", "analyst-l3-containment", Performative.ALERT) in pairs
    assert ("analyst-l3-containment", "supervisor-agent", Performative.PARAMS_UPDATE) in pairs
