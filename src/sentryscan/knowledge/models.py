"""Data models for Vulnerability Knowledge Representation and Enrichment."""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class KnowledgeSource(str, Enum):
    """Origin of vulnerability contextual information."""

    LOCAL_ONTOLOGY = "LOCAL_ONTOLOGY"
    NVD_API = "NVD_API"
    CACHE = "CACHE"
    FALLBACK_FIXTURE = "FALLBACK_FIXTURE"


class VulnerabilityRecord(BaseModel):
    """Canonical representation of an external CVE vulnerability entry."""

    cve_id: str = Field(..., description="Common Vulnerabilities and Exposures identifier")
    cwe_id: str | None = Field(default=None, description="Common Weakness Enumeration ID")
    description: str = Field(..., description="Detailed vulnerability summary")
    cvss_score: float = Field(
        ..., ge=0.0, le=10.0, description="CVSS base metric score [0.0, 10.0]"
    )
    severity: str = Field(..., description="Normalized severity: LOW, MEDIUM, HIGH, CRITICAL")
    affected_product: str = Field(..., description="Component or software affected")
    affected_versions: list[str] = Field(default_factory=list, description="Version specs")
    service_match: list[str] = Field(default_factory=list, description="Associated services")
    remediation: str = Field(..., description="Actionable remediation guidance")
    references: list[str] = Field(default_factory=list, description="External reference URLs")
    source: KnowledgeSource = Field(default=KnowledgeSource.LOCAL_ONTOLOGY)


class EnrichmentResult(BaseModel):
    """Structured result of contextual knowledge enrichment for a security finding."""

    finding_id: str
    target_host: str
    cve_id: str | None = None
    cwe_id: str | None = None
    original_severity: str
    enriched_severity: str
    cvss_score: float | None = None
    description: str | None = None
    remediation: str | None = None
    source: KnowledgeSource
    cache_hit: bool = False
    fallback_used: bool = False
    escalated: bool = False
    details: dict[str, Any] = Field(default_factory=dict)
