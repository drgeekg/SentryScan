"""Resilient Knowledge Enricher with Caching, Retry and Offline Fallback."""

from __future__ import annotations

import logging
import time
from typing import Any

from sentryscan.knowledge.cache import VulnerabilityCache
from sentryscan.knowledge.models import EnrichmentResult, KnowledgeSource, VulnerabilityRecord
from sentryscan.knowledge.nvd_adapter import NVDAdapter, NVDError
from sentryscan.knowledge.ontology import VulnerabilityKnowledgeBase

logger = logging.getLogger(__name__)


class KnowledgeEnricher:
    """Enriches vulnerability findings using cache, NVD API, and offline fallback."""

    def __init__(
        self,
        ontology: VulnerabilityKnowledgeBase | None = None,
        nvd_adapter: NVDAdapter | None = None,
        cache: VulnerabilityCache | None = None,
        enable_online_nvd: bool = False,
        max_retries: int = 2,
        initial_backoff: float = 0.1,
    ) -> None:
        self.ontology = (
            ontology if ontology is not None else VulnerabilityKnowledgeBase.load_from_file()
        )
        self.nvd_adapter = nvd_adapter
        self.cache = cache if cache is not None else VulnerabilityCache()
        self.enable_online_nvd = enable_online_nvd
        self.max_retries = max_retries
        self.initial_backoff = initial_backoff

    def enrich_finding(
        self,
        finding_id: str,
        target_host: str,
        original_severity: str,
        service: str | None = None,
        banner: str | None = None,
        cve_id: str | None = None,
        extra_details: dict[str, Any] | None = None,
    ) -> EnrichmentResult:
        """Enrich a finding through the tiered cache -> NVD -> fallback pipeline."""
        orig_norm = original_severity.upper()
        norm_cve = cve_id.strip().upper() if cve_id else None

        # 1. Infer CVE ID from service/banner if not provided
        if not norm_cve and service:
            matches = self.ontology.query_by_service(service, banner=banner)
            if matches:
                norm_cve = matches[0].cve_id

        # 2. Check Cache
        if norm_cve:
            cached_rec = self.cache.get(norm_cve)
            if cached_rec is not None:
                logger.debug("Cache hit for CVE %s", norm_cve)
                return self._build_result(
                    finding_id=finding_id,
                    target_host=target_host,
                    original_severity=orig_norm,
                    record=cached_rec,
                    cache_hit=True,
                    fallback_used=False,
                    extra_details=extra_details,
                )

        # 3. Check Online NVD Adapter if enabled
        nvd_rec: VulnerabilityRecord | None = None
        if self.enable_online_nvd and self.nvd_adapter and norm_cve:
            nvd_rec = self._fetch_with_retry(norm_cve)
            if nvd_rec:
                # Update cache
                self.cache.set(norm_cve, nvd_rec)
                return self._build_result(
                    finding_id=finding_id,
                    target_host=target_host,
                    original_severity=orig_norm,
                    record=nvd_rec,
                    cache_hit=False,
                    fallback_used=False,
                    extra_details=extra_details,
                )

        # 4. Fallback to Local Ontology Fixture
        if norm_cve:
            ontology_rec = self.ontology.get_by_cve(norm_cve)
            if ontology_rec:
                # Store in cache as well
                self.cache.set(norm_cve, ontology_rec)
                return self._build_result(
                    finding_id=finding_id,
                    target_host=target_host,
                    original_severity=orig_norm,
                    record=ontology_rec,
                    cache_hit=False,
                    fallback_used=True,
                    extra_details=extra_details,
                )

        # 5. Unenriched baseline
        return EnrichmentResult(
            finding_id=finding_id,
            target_host=target_host,
            cve_id=norm_cve,
            original_severity=orig_norm,
            enriched_severity=orig_norm,
            source=KnowledgeSource.FALLBACK_FIXTURE,
            cache_hit=False,
            fallback_used=True,
            escalated=False,
            details=extra_details or {},
        )

    def _fetch_with_retry(self, cve_id: str) -> VulnerabilityRecord | None:
        """Fetch from NVD adapter with bounded exponential backoff retry."""
        if not self.nvd_adapter:
            return None

        attempts = 0
        backoff = self.initial_backoff

        while attempts <= self.max_retries:
            try:
                return self.nvd_adapter.fetch_cve(cve_id)
            except NVDError as err:
                attempts += 1
                if attempts > self.max_retries:
                    logger.warning(
                        "NVD fetch failed for %s after %d retries: %s. "
                        "Falling back to offline fixture.",
                        cve_id,
                        self.max_retries,
                        err,
                    )
                    return None
                time.sleep(backoff)
                backoff *= 2.0
            except Exception as e:
                logger.warning("Unexpected error during NVD fetch for %s: %s", cve_id, e)
                return None

        return None

    def _build_result(
        self,
        finding_id: str,
        target_host: str,
        original_severity: str,
        record: VulnerabilityRecord,
        cache_hit: bool,
        fallback_used: bool,
        extra_details: dict[str, Any] | None = None,
    ) -> EnrichmentResult:
        """Construct structured EnrichmentResult evaluating severity escalation."""
        severity_ranks = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        orig_norm = original_severity.upper()
        enriched_sev = record.severity.upper()
        escalated = severity_ranks.get(enriched_sev, 0) > severity_ranks.get(orig_norm, 0)

        source = KnowledgeSource.CACHE if cache_hit else record.source
        if fallback_used and not cache_hit:
            source = KnowledgeSource.FALLBACK_FIXTURE

        return EnrichmentResult(
            finding_id=finding_id,
            target_host=target_host,
            cve_id=record.cve_id,
            cwe_id=record.cwe_id,
            original_severity=orig_norm,
            enriched_severity=enriched_sev,
            cvss_score=record.cvss_score,
            description=record.description,
            remediation=record.remediation,
            source=source,
            cache_hit=cache_hit,
            fallback_used=fallback_used,
            escalated=escalated,
            details=extra_details or {},
        )
