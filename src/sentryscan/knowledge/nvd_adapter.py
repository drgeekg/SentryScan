"""Read-only National Vulnerability Database (NVD) CVE API adapter."""

from __future__ import annotations

import logging
from typing import Any

from pydantic import BaseModel, Field

from sentryscan.knowledge.models import KnowledgeSource, VulnerabilityRecord

logger = logging.getLogger(__name__)

DEFAULT_NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


class NVDError(Exception):
    """Base exception for NVD adapter failures."""


class NVDConnectionError(NVDError):
    """Raised when communication with NVD API fails or times out."""


class NVDValidationError(NVDError):
    """Raised when NVD API response fails schema validation."""


class NVDCvssData(BaseModel):
    """CVSS score details from NVD response."""

    version: str = "3.1"
    baseScore: float
    baseSeverity: str | None = None


class NVDCvssMetric(BaseModel):
    """Container for CVSS metric item."""

    cvssData: NVDCvssData


class NVDDescription(BaseModel):
    """Multi-language description item."""

    lang: str
    value: str


class NVDWeaknessDesc(BaseModel):
    """Weakness (CWE) description."""

    lang: str
    value: str


class NVDWeakness(BaseModel):
    """Weakness item container."""

    description: list[NVDWeaknessDesc] = Field(default_factory=list)


class NVDReference(BaseModel):
    """Reference URL entry."""

    url: str
    source: str | None = None


class NVDCveData(BaseModel):
    """Individual CVE data structure in NVD API 2.0."""

    id: str
    descriptions: list[NVDDescription] = Field(default_factory=list)
    metrics: dict[str, list[NVDCvssMetric]] = Field(default_factory=dict)
    weaknesses: list[NVDWeakness] = Field(default_factory=list)
    references: list[NVDReference] = Field(default_factory=list)


class NVDVulnerabilityItem(BaseModel):
    """Wrapper item for vulnerability in results."""

    cve: NVDCveData


class NVDResponse(BaseModel):
    """Top-level NVD API 2.0 response schema."""

    totalResults: int = 0
    vulnerabilities: list[NVDVulnerabilityItem] = Field(default_factory=list)


class NVDAdapter:
    """Read-only adapter for NIST National Vulnerability Database API 2.0.

    Adheres strictly to the SentryScan safety boundary: this adapter is solely
    used for read-only metadata enrichment and never probes, scans, or interacts
    with network hosts.
    """

    def __init__(
        self,
        base_url: str = DEFAULT_NVD_API_URL,
        api_key: str | None = None,
        timeout: float = 2.0,
        http_client: Any | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout
        self._http_client = http_client

    def fetch_cve(self, cve_id: str) -> VulnerabilityRecord | None:
        """Fetch CVE metadata from NVD API, validate schema, and return VulnerabilityRecord."""
        norm_cve = cve_id.strip().upper()
        url = f"{self.base_url}?cveId={norm_cve}"
        headers: dict[str, str] = {"Accept": "application/json"}
        if self.api_key:
            headers["apiKey"] = self.api_key

        try:
            raw_data = self._request(url, headers=headers)
        except Exception as e:
            logger.warning("NVD API request failed for %s: %s", norm_cve, e)
            raise NVDConnectionError(f"Failed to fetch {norm_cve} from NVD: {e}") from e

        return self.parse_response(raw_data, requested_cve=norm_cve)

    def parse_response(
        self, raw_data: dict[str, Any], requested_cve: str | None = None
    ) -> VulnerabilityRecord | None:
        """Validate raw response schema and convert to canonical VulnerabilityRecord."""
        try:
            validated = NVDResponse(**raw_data)
        except Exception as err:
            logger.error("NVD response validation error: %s", err)
            raise NVDValidationError(f"Invalid NVD response structure: {err}") from err

        if not validated.vulnerabilities:
            logger.info("No CVE records found in NVD response for %s", requested_cve)
            return None

        cve_data = validated.vulnerabilities[0].cve

        # Extract English description or first available
        desc = "No description provided."
        for d in cve_data.descriptions:
            if d.lang.lower() == "en":
                desc = d.value
                break
            desc = d.value

        # Extract CWE ID
        cwe_id: str | None = None
        for w in cve_data.weaknesses:
            for wd in w.description:
                if wd.value.startswith("CWE-"):
                    cwe_id = wd.value
                    break
            if cwe_id:
                break

        # Extract CVSS score and severity
        cvss_score = 0.0
        severity = "LOW"

        # Check CVSS v3.1, v3.0, then v2
        metrics_v31 = cve_data.metrics.get("cvssMetricV31", [])
        metrics_v30 = cve_data.metrics.get("cvssMetricV30", [])
        metrics_v2 = cve_data.metrics.get("cvssMetricV2", [])

        metric = None
        if metrics_v31:
            metric = metrics_v31[0].cvssData
        elif metrics_v30:
            metric = metrics_v30[0].cvssData
        elif metrics_v2:
            metric = metrics_v2[0].cvssData

        if metric:
            cvss_score = metric.baseScore
            if metric.baseSeverity:
                severity = metric.baseSeverity.upper()
            else:
                severity = self._score_to_severity(cvss_score)
        else:
            severity = self._score_to_severity(cvss_score)

        references = [r.url for r in cve_data.references]

        return VulnerabilityRecord(
            cve_id=cve_data.id,
            cwe_id=cwe_id,
            description=desc,
            cvss_score=cvss_score,
            severity=severity,
            affected_product=f"product_for_{cve_data.id}",
            affected_versions=["*"],
            service_match=[],
            remediation="Apply vendor patch or mitigate exposure.",
            references=references,
            source=KnowledgeSource.NVD_API,
        )

    def _score_to_severity(self, score: float) -> str:
        """Derive standard CVSS v3.1 categorical severity from numeric score."""
        if score >= 9.0:
            return "CRITICAL"
        if score >= 7.0:
            return "HIGH"
        if score >= 4.0:
            return "MEDIUM"
        if score > 0.0:
            return "LOW"
        return "INFO"

    def _request(self, url: str, headers: dict[str, str]) -> dict[str, Any]:
        """Perform HTTP GET request using provided client or default requests."""
        if self._http_client is not None:
            return self._http_client.get(url, headers=headers, timeout=self.timeout)

        # Standard urllib/requests fallback
        import requests

        response = requests.get(url, headers=headers, timeout=self.timeout)
        if response.status_code == 404:
            return {"totalResults": 0, "vulnerabilities": []}
        response.raise_for_status()
        return response.json()
