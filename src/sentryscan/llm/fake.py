"""Fake/scripted LLM provider for unit tests and failure mode simulation."""

from __future__ import annotations

from typing import Any

from sentryscan.llm.interface import LLMProvider, LLMRequest, LLMResponse


class FakeLLMProvider(LLMProvider):
    """Scriptable mock LLM provider recording invocations and returning canned responses."""

    def __init__(
        self,
        default_text: str = "Fake scripted response",
        default_parsed: dict[str, Any] | None = None,
        raise_error: Exception | None = None,
    ) -> None:
        self.default_text = default_text
        self.default_parsed = default_parsed
        self.raise_error = raise_error
        self.calls: list[LLMRequest] = []
        self._canned_queue: list[LLMResponse] = []

    def queue_response(self, response: LLMResponse) -> None:
        """Enqueue a canned response to be returned on subsequent generate calls."""
        self._canned_queue.append(response)

    def generate(self, request: LLMRequest) -> LLMResponse:
        """Record the request and return next canned or default response."""
        self.calls.append(request)

        if self.raise_error is not None:
            raise self.raise_error

        if self._canned_queue:
            return self._canned_queue.pop(0)

        return LLMResponse(
            text=self.default_text,
            parsed=self.default_parsed,
            provider="fake",
            model="fake-model",
            tokens_in=10,
            tokens_out=15,
            latency_ms=5,
            cache_hit=False,
            finish_reason="stop",
        )
