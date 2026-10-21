"""Unit tests for Vulnerability Knowledge Base and Ontology."""

from pathlib import Path

import pytest

from sentryscan.knowledge.models import KnowledgeSource, VulnerabilityRecord
from sentryscan.knowledge.ontology import VulnerabilityKnowledgeBase


def test_vulnerability_record_validation() -> None:
    """Test valid creation and field bounds for VulnerabilityRecord."""
    rec = VulnerabilityRecord(
        cve_id="CVE-2021-44228",
        cwe_id="CWE-502",
        description="Log4j RCE vulnerability",
        cvss_score=10.0,
        severity="CRITICAL",
        affected_product="log4j-core",
        affected_versions=["2.0-beta9", "2.14.1"],
        service_match=["log4j"],
        remediation="Upgrade to 2.15.0+",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"],
        source=KnowledgeSource.LOCAL_ONTOLOGY,
    )
    assert rec.cve_id == "CVE-2021-44228"
    assert rec.cvss_score == 10.0
    assert rec.severity == "CRITICAL"


def test_vulnerability_record_invalid_cvss() -> None:
    """Ensure CVSS score must fall in range [0.0, 10.0]."""
    with pytest.raises(ValueError):
        VulnerabilityRecord(
            cve_id="CVE-INVALID",
            description="Invalid score test",
            cvss_score=11.5,
            severity="CRITICAL",
            affected_product="test",
            remediation="none",
        )


def test_knowledge_base_load_and_query() -> None:
    """Test loading ontology fixture and querying by CVE and service."""
    fixture_path = Path("fixtures/knowledge/vulnerability_ontology.json")
    assert fixture_path.exists()

    kb = VulnerabilityKnowledgeBase.load_from_file(fixture_path)
    assert kb.count() >= 5

    # Direct CVE lookup
    rec = kb.get_by_cve("cve-2021-44228")
    assert rec is not None
    assert rec.cve_id == "CVE-2021-44228"
    assert rec.cvss_score == 10.0

    # Service keyword matching
    matches = kb.query_by_service("apache", banner="Apache/2.4.49 (Unix)")
    assert len(matches) > 0
    cves = [m.cve_id for m in matches]
    assert "CVE-2021-41773" in cves


def test_knowledge_base_enrichment() -> None:
    """Test finding enrichment and severity escalation."""
    kb = VulnerabilityKnowledgeBase.load_from_file()

    # Original MEDIUM finding enriched to CRITICAL via Log4j CVE
    res = kb.enrich(
        finding_id="finding-001",
        target_host="192.0.2.10",
        original_severity="MEDIUM",
        service="log4j",
        cve_id="CVE-2021-44228",
    )
    assert res.cve_id == "CVE-2021-44228"
    assert res.original_severity == "MEDIUM"
    assert res.enriched_severity == "CRITICAL"
    assert res.escalated is True
    assert res.cvss_score == 10.0

    # Unmatched finding retains original severity and escalated is False
    res_unknown = kb.enrich(
        finding_id="finding-002",
        target_host="192.0.2.20",
        original_severity="LOW",
        service="unknown_custom_service",
    )
    assert res_unknown.cve_id is None
    assert res_unknown.enriched_severity == "LOW"
    assert res_unknown.escalated is False
