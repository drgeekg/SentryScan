"""Structured Vulnerability Knowledge Ontology for SentryScan."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from sentryscan.knowledge.models import EnrichmentResult, KnowledgeSource, VulnerabilityRecord

logger = logging.getLogger(__name__)

DEFAULT_ONTOLOGY_PATH = Path("fixtures/knowledge/vulnerability_ontology.json")


class VulnerabilityKnowledgeBase:
    """Local ontological repository of structured vulnerability specifications."""

    def __init__(self, records: list[VulnerabilityRecord] | None = None) -> None:
        self._records_by_cve: dict[str, VulnerabilityRecord] = {}
        self._records_by_service: dict[str, list[VulnerabilityRecord]] = {}

        if records:
            for record in records:
                self.add_record(record)

    @classmethod
    def load_from_file(cls, path: str | Path | None = None) -> VulnerabilityKnowledgeBase:
        """Load knowledge base from a JSON ontology fixture file."""
        target_path = Path(path) if path else DEFAULT_ONTOLOGY_PATH
        if not target_path.exists():
            logger.warning("Ontology file not found at %s. Initializing empty.", target_path)
            return cls([])

        try:
            with open(target_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            records = [VulnerabilityRecord(**item) for item in data]
            return cls(records)
        except Exception as e:
            logger.error("Failed to parse ontology file at %s: %s", target_path, e)
            return cls([])

    def add_record(self, record: VulnerabilityRecord) -> None:
        """Add a vulnerability record to internal indexes."""
        self._records_by_cve[record.cve_id.upper()] = record

        for service in record.service_match:
            svc_key = service.lower()
            if svc_key not in self._records_by_service:
                self._records_by_service[svc_key] = []
            if record not in self._records_by_service[svc_key]:
                self._records_by_service[svc_key].append(record)

    def get_by_cve(self, cve_id: str) -> VulnerabilityRecord | None:
        """Lookup vulnerability record by CVE identifier."""
        return self._records_by_cve.get(cve_id.strip().upper())

    def query_by_service(
        self, service: str, banner: str | None = None
    ) -> list[VulnerabilityRecord]:
        """Query vulnerability records matching a service name or banner keywords."""
        results: list[VulnerabilityRecord] = []
        seen_cves: set[str] = set()

        svc_norm = service.strip().lower()
        banner_norm = (banner or "").strip().lower()

        for svc_key, records in self._records_by_service.items():
            if svc_key in svc_norm or (banner_norm and svc_key in banner_norm):
                for rec in records:
                    if rec.cve_id in seen_cves:
                        continue
                    # When a banner is present and the record specifies affected_versions (excluding wildcard '*'),
                    # require that at least one affected version or specific product token appears in the banner.
                    version_restricted = [v for v in rec.affected_versions if v != '*']
                    if banner_norm and version_restricted:
                        if not any(v.lower() in banner_norm for v in version_restricted):
                            continue
                    results.append(rec)
                    seen_cves.add(rec.cve_id)

        # Sort matches by highest CVSS score descending
        results.sort(key=lambda r: r.cvss_score, reverse=True)
        return results

    def enrich(
        self,
        finding_id: str,
        target_host: str,
        original_severity: str,
        service: str | None = None,
        banner: str | None = None,
        cve_id: str | None = None,
        extra_details: dict[str, Any] | None = None,
    ) -> EnrichmentResult:
        """Enrich finding using local ontology knowledge."""
        record: VulnerabilityRecord | None = None

        if cve_id:
            record = self.get_by_cve(cve_id)

        if not record and service:
            matches = self.query_by_service(service, banner=banner)
            if matches:
                record = matches[0]

        severity_ranks = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        orig_norm = original_severity.upper()

        if record:
            enriched_sev = record.severity.upper()
            escalated = severity_ranks.get(enriched_sev, 0) > severity_ranks.get(orig_norm, 0)
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
                source=record.source,
                cache_hit=False,
                fallback_used=False,
                escalated=escalated,
                details=extra_details or {},
            )

        # Unenriched fallback
        return EnrichmentResult(
            finding_id=finding_id,
            target_host=target_host,
            original_severity=orig_norm,
            enriched_severity=orig_norm,
            source=KnowledgeSource.LOCAL_ONTOLOGY,
            cache_hit=False,
            fallback_used=False,
            escalated=False,
            details=extra_details or {},
        )

    def count(self) -> int:
        """Return total number of distinct indexed CVE records."""
        return len(self._records_by_cve)
