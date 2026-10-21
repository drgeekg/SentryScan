"""Factory for resolving and instantiating configured LLM providers."""

from __future__ import annotations

import os
from typing import Any

from sentryscan.llm.deterministic import DeterministicLLMProvider
from sentryscan.llm.fake import FakeLLMProvider
from sentryscan.llm.interface import LLMProvider


def get_llm_provider(
    provider_name: str | None = None,
    **kwargs: Any,
) -> LLMProvider:
    """Resolve an LLM provider by name or environment variable SENTRYSCAN_LLM_PROVIDER."""
    name = (provider_name or os.environ.get("SENTRYSCAN_LLM_PROVIDER", "deterministic")).lower()

    if name == "deterministic":
        model_name = kwargs.get("model", "deterministic-rule-v1")
        return DeterministicLLMProvider(model_name=model_name)
    if name == "fake":
        return FakeLLMProvider(**kwargs)

    # For any unknown or unsupported provider, fail-safe to deterministic
    return DeterministicLLMProvider(model_name="deterministic-fallback-v1")
