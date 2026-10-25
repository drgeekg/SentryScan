"""Factory for resolving and instantiating configured LLM providers."""

from __future__ import annotations

import os
from typing import Any

from dotenv import load_dotenv

from sentryscan.llm.deterministic import DeterministicLLMProvider
from sentryscan.llm.fake import FakeLLMProvider
from sentryscan.llm.interface import LLMProvider
from sentryscan.llm.remote import RemoteLLMProvider

# Ensure .env is loaded on startup
load_dotenv()


def get_llm_provider(
    provider_name: str | None = None,
    purpose: str | None = None,
    **kwargs: Any,
) -> LLMProvider:
    """Resolve an LLM provider by purpose, name, or environment variables.

    Supports distinct providers and credentials for Report Generation vs Copilot vs Agent bidding:
    - Report: SENTRYSCAN_REPORT_LLM_PROVIDER, SENTRYSCAN_REPORT_LLM_MODEL, SENTRYSCAN_REPORT_LLM_API_KEY
    - Copilot: SENTRYSCAN_COPILOT_LLM_PROVIDER, SENTRYSCAN_COPILOT_LLM_MODEL, SENTRYSCAN_COPILOT_LLM_API_KEY
    - Agent: SENTRYSCAN_AGENT_LLM_PROVIDER, SENTRYSCAN_AGENT_LLM_MODEL, SENTRYSCAN_AGENT_LLM_API_KEY
    - Global Fallback: SENTRYSCAN_LLM_PROVIDER (defaults to 'deterministic')
    """
    prefix = ""
    if purpose:
        p_clean = purpose.strip().lower()
        if p_clean in ("report", "reporting", "posture_report"):
            prefix = "SENTRYSCAN_REPORT_"
        elif p_clean in ("copilot", "chat", "qa"):
            prefix = "SENTRYSCAN_COPILOT_"
        elif p_clean in ("agent", "bidding", "scout", "triage"):
            prefix = "SENTRYSCAN_AGENT_"

    resolved_provider = (
        provider_name
        or (os.environ.get(f"{prefix}LLM_PROVIDER") if prefix else None)
        or os.environ.get("SENTRYSCAN_LLM_PROVIDER", "deterministic")
    ).lower()

    resolved_model = (
        kwargs.get("model")
        or (os.environ.get(f"{prefix}LLM_MODEL") if prefix else None)
        or os.environ.get("SENTRYSCAN_LLM_MODEL")
    )
    resolved_api_key = (
        kwargs.get("api_key")
        or (os.environ.get(f"{prefix}LLM_API_KEY") if prefix else None)
        or os.environ.get("SENTRYSCAN_LLM_API_KEY")
    )
    resolved_base_url = (
        kwargs.get("base_url")
        or (os.environ.get(f"{prefix}LLM_BASE_URL") if prefix else None)
        or os.environ.get("SENTRYSCAN_LLM_BASE_URL")
    )

    if resolved_provider == "deterministic":
        model_name = resolved_model or "deterministic-rule-v1"
        return DeterministicLLMProvider(model_name=model_name)
    if resolved_provider == "fake":
        return FakeLLMProvider(**kwargs)

    remote_providers = ("gemini", "openai", "anthropic", "openrouter", "ollama", "nvidia", "nim", "custom", "local", "vllm", "lmstudio")
    if resolved_provider in remote_providers:
        return RemoteLLMProvider(
            provider=resolved_provider,
            model=resolved_model,
            base_url=resolved_base_url,
            api_key=resolved_api_key,
        )

    # For any unknown or unsupported provider, fail-safe to deterministic
    return DeterministicLLMProvider(model_name="deterministic-fallback-v1")
