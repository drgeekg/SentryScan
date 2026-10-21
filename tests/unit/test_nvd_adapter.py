"""Unit tests for NVD API adapter and response validation."""

from typing import Any

import pytest

from sentryscan.knowledge.models import KnowledgeSource
from sentryscan.knowledge.nvd_adapter import (
    NVDAdapter,
    NVDConnectionError,
    NVDValidationError,
)


class MockHttpClient:
    """Mock client for simulating NVD HTTP responses."""

    def __init__(
        self, response_data: dict[str, Any] | None = None, should_fail: bool = False
    ) -> None:
        self.response_data = response_data or {}
        self.should_fail = should_fail
        self.last_url: str | None = None

    def get(self, url: str, headers: dict[str, str], timeout: float) -> dict[str, Any]:
        self.last_url = url
        if self.should_fail:
            raise ConnectionError("Simulated network timeout")
        return self.response_data


def test_nvd_adapter_valid_response() -> None:
    """Verify parsing and validation of standard NVD 2.0 API response."""
    sample_nvd_payload = {
        "resultsPerPage": 1,
        "startIndex": 0,
        "totalResults": 1,
        "format": "NVD_CVE",
        "version": "2.0",
        "timestamp": "2026-10-21T00:00:00.000",
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2021-44228",
                    "descriptions": [
                        {"lang": "en", "value": "Apache Log4j2 JNDI features flaw allows RCE."}
                    ],
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
                        {
                            "description": [{"lang": "en", "value": "CWE-502"}]
                        }
                    ],
                    "references": [
                        {"url": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"}
                    ],
                }
            }
        ],
    }

    mock_client = MockHttpClient(response_data=sample_nvd_payload)
    adapter = NVDAdapter(http_client=mock_client)

    record = adapter.fetch_cve("CVE-2021-44228")
    assert record is not None
    assert record.cve_id == "CVE-2021-44228"
    assert record.cwe_id == "CWE-502"
    assert record.cvss_score == 10.0
    assert record.severity == "CRITICAL"
    assert "Log4j2" in record.description
    assert record.source == KnowledgeSource.NVD_API
    assert "https://nvd.nist.gov/vuln/detail/CVE-2021-44228" in record.references


def test_nvd_adapter_not_found() -> None:
    """Verify that empty result set returns None without exception."""
    empty_payload = {
        "resultsPerPage": 0,
        "totalResults": 0,
        "vulnerabilities": [],
    }
    mock_client = MockHttpClient(response_data=empty_payload)
    adapter = NVDAdapter(http_client=mock_client)

    record = adapter.fetch_cve("CVE-2099-99999")
    assert record is None


def test_nvd_adapter_malformed_response() -> None:
    """Verify that corrupt schema triggers NVDValidationError."""
    corrupt_payload = {
        "vulnerabilities": "not_a_valid_list_structure"
    }
    mock_client = MockHttpClient(response_data=corrupt_payload)
    adapter = NVDAdapter(http_client=mock_client)

    with pytest.raises(NVDValidationError):
        adapter.fetch_cve("CVE-2021-44228")


def test_nvd_adapter_connection_error() -> None:
    """Verify that transport failure triggers NVDConnectionError."""
    mock_client = MockHttpClient(should_fail=True)
    adapter = NVDAdapter(http_client=mock_client)

    with pytest.raises(NVDConnectionError):
        adapter.fetch_cve("CVE-2021-44228")
