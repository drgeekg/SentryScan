"""Unit tests for the LLMProvider abstraction, deterministic, and fake providers."""

from __future__ import annotations

import pytest

from sentryscan.llm.deterministic import DeterministicLLMProvider
from sentryscan.llm.factory import get_llm_provider
from sentryscan.llm.fake import FakeLLMProvider
from sentryscan.llm.interface import LLMProvider, LLMRequest


def test_deterministic_provider_roles():
    provider = DeterministicLLMProvider()
    assert isinstance(provider, LLMProvider)

    # Test scout proposal rationale
    req_scout = LLMRequest(
        role="scout_proposal",
        system="You are ScoutAgent.",
        messages=[{"role": "user", "content": "Draft rationale for batch allocation"}],
        request_id="req-001",
        response_schema={"type": "object"},
    )
    resp_scout = provider.generate(req_scout)
    assert resp_scout.provider == "deterministic"
    assert "coverage" in resp_scout.text.lower()
    assert resp_scout.parsed is not None
    assert resp_scout.parsed["strategy"] == "MAX_COVERAGE"

    # Test triage proposal rationale
    req_triage = LLMRequest(
        role="triage_proposal",
        system="You are TriageAgent.",
        messages=[{"role": "user", "content": "Draft rationale for urgent triage"}],
        request_id="req-002",
        response_schema={"type": "object"},
    )
    resp_triage = provider.generate(req_triage)
    assert "critical" in resp_triage.text.lower() or "risk" in resp_triage.text.lower()
    assert resp_triage.parsed is not None
    assert resp_triage.parsed["strategy"] == "RISK_FIRST"


def test_fake_provider_recording_and_canned_queue():
    fake = FakeLLMProvider(default_text="Fallback text")

    req = LLMRequest(
        role="finding_explanation",
        system="Explain finding",
        messages=[{"role": "user", "content": "Explain CVE-2016-0777"}],
        request_id="req-003",
    )

    resp = fake.generate(req)
    assert len(fake.calls) == 1
    assert fake.calls[0].request_id == "req-003"
    assert resp.text == "Fallback text"

    # Test error simulation
    fake_err = FakeLLMProvider(raise_error=RuntimeError("API timeout"))
    with pytest.raises(RuntimeError):
        fake_err.generate(req)


def test_factory_resolution(monkeypatch):
    monkeypatch.delenv("SENTRYSCAN_LLM_PROVIDER", raising=False)
    p_default = get_llm_provider()
    assert isinstance(p_default, DeterministicLLMProvider)

    p_fake = get_llm_provider("fake")
    assert isinstance(p_fake, FakeLLMProvider)

    monkeypatch.setenv("SENTRYSCAN_LLM_PROVIDER", "fake")
    p_env = get_llm_provider()
    assert isinstance(p_env, FakeLLMProvider)
