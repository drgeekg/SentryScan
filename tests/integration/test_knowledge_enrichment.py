"""Integration tests for Knowledge Enrichment, NVD API, and BDI Replanning."""

from typing import Any

from sentryscan.agents.analyst import AnalystAgent
from sentryscan.common.clock import FakeClock
from sentryscan.common.id_generator import IdGenerator
from sentryscan.contracts.message import Message, Performative
from sentryscan.knowledge.cache import VulnerabilityCache
from sentryscan.knowledge.enricher import KnowledgeEnricher
from sentryscan.knowledge.models import KnowledgeSource
from sentryscan.knowledge.nvd_adapter import NVDAdapter
from sentryscan.knowledge.ontology import VulnerabilityKnowledgeBase


class MockNVDClient:
    """Mock HTTP client returning canned NVD 2.0 payloads."""

    def __init__(self, cve_database: dict[str, dict[str, Any]]) -> None:
        self.cve_database = cve_database
        self.calls: list[str] = []

    def get(self, url: str, headers: dict[str, str], timeout: float) -> dict[str, Any]:
        self.calls.append(url)
        for cve_id, payload in self.cve_database.items():
            if f"cveId={cve_id}" in url:
                return payload
        return {"totalResults": 0, "vulnerabilities": []}


def test_offline_enrichment_escalates_and_triggers_quarantine() -> None:
    """Verify offline enrichment of Log4j finding escalates MEDIUM to CRITICAL and quarantines."""
    clock = FakeClock("2026-10-21T12:00:00Z")
    id_gen = IdGenerator(seed=42)

    ontology = VulnerabilityKnowledgeBase.load_from_file()
    cache = VulnerabilityCache(clock=clock)
    enricher = KnowledgeEnricher(ontology=ontology, cache=cache, enable_online_nvd=False)

    analyst = AnalystAgent(
        agent_id="analyst-agent-01",
        clock=clock,
        id_gen=id_gen,
        enricher=enricher,
    )

    # 1. Send routine LOW finding -> Adopts nominal audit
    msg1 = Message(
        message_id="msg-001",
        run_id="run-test",
        sender="supervisor-agent-01",
        receiver="analyst-agent-01",
        performative=Performative.ALERT,
        timestamp_utc=clock.now_iso(),
        nonce="nonce-001",
        payload={
            "target_host": "192.0.2.10",
            "finding_id": "fnd-001",
            "severity": "LOW",
            "service": "http",
        },
    )
    reply1 = analyst.process_message(msg1)
    assert reply1 is not None
    assert reply1.payload["action"] == "NOMINAL_MONITORING"
    assert reply1.payload["quarantine_flag"] is False
    assert analyst.active_intention is not None
    assert analyst.active_intention.desire_type.value == "AUDIT_ASSIGNED_HOSTS"

    # 2. Send MEDIUM finding with service='log4j' -> Enriched to CRITICAL via Log4Shell CVE
    msg2 = Message(
        message_id="msg-002",
        run_id="run-test",
        sender="supervisor-agent-01",
        receiver="analyst-agent-01",
        performative=Performative.ALERT,
        timestamp_utc=clock.now_iso(),
        nonce="nonce-002",
        payload={
            "target_host": "sim-host-007",
            "finding_id": "fnd-002",
            "severity": "MEDIUM",
            "service": "log4j",
            "banner": "Apache Log4j 2.14.1",
        },
    )
    reply2 = analyst.process_message(msg2)
    assert reply2 is not None

    # Verification of escalated parameters
    assert reply2.payload["target_host"] == "sim-host-007"
    assert reply2.payload["action"] == "DEEP_INSPECTION"
    assert reply2.payload["scan_interval_ms"] == 50
    assert reply2.payload["quarantine_flag"] is True
    assert reply2.payload["escalated"] is True
    assert reply2.payload["cve_id"] == "CVE-2021-44228"
    assert reply2.payload["cvss_score"] == 10.0

    # Verification of BDI intention shift
    assert analyst.active_intention is not None
    assert analyst.active_intention.desire_type.value == "CONTAIN_COMPROMISED_HOSTS"
    assert analyst.belief_base.hosts["sim-host-007"].quarantined is True
    assert analyst.belief_base.hosts["sim-host-007"].highest_severity == "CRITICAL"


def test_online_mocked_nvd_enrichment_and_caching() -> None:
    """Verify online NVD path fetches, validates, escalates, and caches response."""
    clock = FakeClock("2026-10-21T12:00:00Z")
    id_gen = IdGenerator(seed=99)

    mock_db = {
        "CVE-2024-3094": {
            "resultsPerPage": 1,
            "totalResults": 1,
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2024-3094",
                        "descriptions": [{"lang": "en", "value": "XZ liblzma backdoor"}],
                        "metrics": {
                            "cvssMetricV31": [
                                {
                                    "cvssData": {
                                        "version": "3.1",
                                        "baseScore": 10.0,
                                        "baseSeverity": "CRITICAL",
                                    }
                                }
                            ]
                        },
                        "weaknesses": [
                            {"description": [{"lang": "en", "value": "CWE-506"}]}
                        ],
                        "references": [{"url": "https://nvd.nist.gov/vuln/detail/CVE-2024-3094"}],
                    }
                }
            ],
        }
    }

    mock_client = MockNVDClient(cve_database=mock_db)
    adapter = NVDAdapter(http_client=mock_client)
    cache = VulnerabilityCache(clock=clock)
    enricher = KnowledgeEnricher(
        nvd_adapter=adapter,
        cache=cache,
        enable_online_nvd=True,
    )

    analyst = AnalystAgent(clock=clock, id_gen=id_gen, enricher=enricher)

    # First call: Fetches over NVD adapter
    msg1 = Message(
        message_id="msg-nvd-1",
        run_id="run-nvd",
        sender="supervisor-agent-01",
        receiver="analyst-agent-01",
        performative=Performative.ALERT,
        timestamp_utc=clock.now_iso(),
        nonce="nonce-nvd-1",
        payload={
            "target_host": "sim-host-009",
            "finding_id": "fnd-nvd-1",
            "severity": "LOW",
            "cve_id": "CVE-2024-3094",
        },
    )
    reply1 = analyst.process_message(msg1)
    assert reply1 is not None
    assert reply1.payload["escalated"] is True
    assert reply1.payload["knowledge_source"] == KnowledgeSource.NVD_API.value
    assert len(mock_client.calls) == 1

    # Second call: Served directly from cache with zero additional HTTP calls
    msg2 = Message(
        message_id="msg-nvd-2",
        run_id="run-nvd",
        sender="supervisor-agent-01",
        receiver="analyst-agent-01",
        performative=Performative.ALERT,
        timestamp_utc=clock.now_iso(),
        nonce="nonce-nvd-2",
        payload={
            "target_host": "sim-host-010",
            "finding_id": "fnd-nvd-2",
            "severity": "LOW",
            "cve_id": "CVE-2024-3094",
        },
    )
    reply2 = analyst.process_message(msg2)
    assert reply2 is not None
    assert reply2.payload["knowledge_source"] == KnowledgeSource.CACHE.value
    assert len(mock_client.calls) == 1  # No new network requests
    assert cache.stats()["hits"] == 1


def test_unenriched_alert_retains_nominal_posture() -> None:
    """Verify that alerts without matching vulnerability records preserve baseline policy."""
    clock = FakeClock()
    analyst = AnalystAgent(clock=clock)

    msg = Message(
        message_id="msg-clean",
        run_id="run-clean",
        sender="supervisor-agent-01",
        receiver="analyst-agent-01",
        performative=Performative.ALERT,
        timestamp_utc=clock.now_iso(),
        nonce="nonce-clean",
        payload={
            "target_host": "192.0.2.55",
            "finding_id": "fnd-clean",
            "severity": "LOW",
            "service": "custom-internal-service",
        },
    )
    reply = analyst.process_message(msg)
    assert reply is not None
    assert reply.payload["action"] == "NOMINAL_MONITORING"
    assert reply.payload["quarantine_flag"] is False
    assert reply.payload.get("escalated", False) is False
