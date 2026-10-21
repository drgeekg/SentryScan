"""Provider-neutral LLM request, response, and protocol abstractions."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable


@dataclass(frozen=True)
class LLMRequest:
    """Provider-neutral request object for advisory LLM invocations."""

    role: str
    system: str
    messages: list[dict[str, str]]
    request_id: str
    response_schema: dict[str, Any] | None = None
    max_tokens: int = 800
    temperature: float = 0.0


@dataclass(frozen=True)
class LLMResponse:
    """Canonical LLM response envelope with usage and telemetry metadata."""

    text: str
    parsed: dict[str, Any] | None
    provider: str
    model: str
    tokens_in: int
    tokens_out: int
    latency_ms: int
    cache_hit: bool
    finish_reason: str


@runtime_checkable
class LLMProvider(Protocol):
    """Protocol implemented by all LLM provider adapters."""

    def generate(self, request: LLMRequest) -> LLMResponse:
        """Execute or simulate an LLM generation call."""
        ...
