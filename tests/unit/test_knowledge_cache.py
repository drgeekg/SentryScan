"""Unit tests for Vulnerability Cache, Retry logic, and Offline Fallback."""

from pathlib import Path
from typing import Any

from sentryscan.common.clock import FakeClock
from sentryscan.knowledge.cache import VulnerabilityCache
from sentryscan.knowledge.enricher import KnowledgeEnricher
from sentryscan.knowledge.models import KnowledgeSource, VulnerabilityRecord
from sentryscan.knowledge.nvd_adapter import NVDAdapter
from sentryscan.knowledge.ontology import VulnerabilityKnowledgeBase


def test_vulnerability_cache_basic_ops(tmp_path: Path) -> None:
    """Verify cache store, retrieve, and disk persistence."""
    clock = FakeClock("2026-10-21T10:00:00Z")
    cache_file = tmp_path / "cache.json"

    cache = VulnerabilityCache(cache_path=cache_file, clock=clock, default_ttl_seconds=300.0)

    rec = VulnerabilityRecord(
        cve_id="CVE-2021-44228",
        cwe_id="CWE-502",
        description="Log4j RCE",
        cvss_score=10.0,
        severity="CRITICAL",
        affected_product="log4j",
        remediation="Upgrade to 2.15.0",
        source=KnowledgeSource.LOCAL_ONTOLOGY,
    )

    cache.set("CVE-2021-44228", rec)
    assert cache.stats()["size"] == 1

    # Fetch from cache
    cached = cache.get("CVE-2021-44228")
    assert cached is not None
    assert cached.cve_id == "CVE-2021-44228"
    assert cached.source == KnowledgeSource.CACHE
    assert cache.stats()["hits"] == 1

    # Re-instantiate from persisted file
    cache2 = VulnerabilityCache(cache_path=cache_file, clock=clock)
    assert cache2.get("CVE-2021-44228") is not None


def test_vulnerability_cache_ttl_expiration() -> None:
    """Verify that expired cache entries return None and are pruned."""
    clock = FakeClock("2026-10-21T10:00:00Z")
    cache = VulnerabilityCache(clock=clock, default_ttl_seconds=60.0)

    rec = VulnerabilityRecord(
        cve_id="CVE-2023-44487",
        description="Rapid Reset",
        cvss_score=7.5,
        severity="HIGH",
        affected_product="http2",
        remediation="Patch",
    )

    cache.set("CVE-2023-44487", rec, ttl_seconds=60.0)

    # Valid immediately
    assert cache.get("CVE-2023-44487") is not None

    # Advance clock by 61 seconds
    clock.advance(61.0)
    assert cache.get("CVE-2023-44487") is None
    assert cache.stats()["misses"] == 1


class FlakyMockHttpClient:
    """Mock client that fails N times before succeeding or always fails."""

    def __init__(self, fail_count: int, success_data: dict[str, Any] | None = None) -> None:
        self.fail_count = fail_count
        self.attempts = 0
        self.success_data = success_data or {}

    def get(self, url: str, headers: dict[str, str], timeout: float) -> dict[str, Any]:
        self.attempts += 1
        if self.attempts <= self.fail_count:
            raise ConnectionError(f"Simulated failure {self.attempts}")
        return self.success_data


def test_enricher_offline_fallback() -> None:
    """Verify that when online NVD is disabled, enricher safely falls back to local ontology."""
    ontology = VulnerabilityKnowledgeBase.load_from_file()
    cache = VulnerabilityCache()
    enricher = KnowledgeEnricher(
        ontology=ontology,
        cache=cache,
        enable_online_nvd=False,
    )

    res = enricher.enrich_finding(
        finding_id="finding-test-1",
        target_host="192.0.2.1",
        original_severity="MEDIUM",
        cve_id="CVE-2021-44228",
    )

    assert res.cve_id == "CVE-2021-44228"
    assert res.enriched_severity == "CRITICAL"
    assert res.escalated is True
    assert res.fallback_used is True
    assert res.cache_hit is False

    # Second query for same CVE should now be a cache hit
    res2 = enricher.enrich_finding(
        finding_id="finding-test-2",
        target_host="192.0.2.1",
        original_severity="MEDIUM",
        cve_id="CVE-2021-44228",
    )
    assert res2.cache_hit is True
    assert res2.source == KnowledgeSource.CACHE


def test_enricher_retry_and_fallback_on_nvd_failure() -> None:
    """Verify that transient NVD failures retry and fallback gracefully without crashing."""
    ontology = VulnerabilityKnowledgeBase.load_from_file()
    cache = VulnerabilityCache()

    # Client that always fails
    failing_client = FlakyMockHttpClient(fail_count=10)
    adapter = NVDAdapter(http_client=failing_client)

    enricher = KnowledgeEnricher(
        ontology=ontology,
        nvd_adapter=adapter,
        cache=cache,
        enable_online_nvd=True,
        max_retries=2,
        initial_backoff=0.01,
    )

    res = enricher.enrich_finding(
        finding_id="finding-test-3",
        target_host="192.0.2.2",
        original_severity="LOW",
        cve_id="CVE-2021-41773",
    )

    # Confirm retries occurred (attempt 1 + 2 retries = 3 attempts)
    assert failing_client.attempts == 3

    # Successfully fell back to local fixture
    assert res.cve_id == "CVE-2021-41773"
    assert res.enriched_severity == "HIGH"
    assert res.escalated is True
    assert res.fallback_used is True
