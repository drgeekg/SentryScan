"""Deterministic offline LLM provider for reproducible graded runs and CI."""

from __future__ import annotations

import json
from typing import Any

from sentryscan.llm.interface import LLMProvider, LLMRequest, LLMResponse


class DeterministicLLMProvider(LLMProvider):
    """Deterministic, zero-network LLM provider generating stable advisory rationales."""

    def __init__(self, model_name: str = "deterministic-rule-v1") -> None:
        self.model_name = model_name

    def generate(self, request: LLMRequest) -> LLMResponse:
        """Synthesize a deterministic response from request metadata and template rules."""
        # Calculate tokens
        input_text = " ".join(m.get("content", "") for m in request.messages)
        tokens_in = max(1, len(input_text.split()) * 4 // 3)

        role = request.role
        parsed: dict[str, Any] | None = None

        if role == "scout_proposal":
            text = (
                "Scout rationale: Prioritizing maximal host discovery and subnet coverage. "
                "Allocates telemetry batches to ensure balanced visibility across endpoints."
            )
            if request.response_schema:
                parsed = {
                    "strategy": "MAX_COVERAGE",
                    "priority": "HOST_BREADTH",
                    "rationale": text,
                }
        elif role == "triage_proposal":
            text = (
                "Triage rationale: Prioritizing high-risk and critical severity exposures. "
                "Allocates telemetry batches to urgent findings requiring immediate isolation."
            )
            if request.response_schema:
                parsed = {
                    "strategy": "RISK_FIRST",
                    "priority": "HIGH_SEVERITY",
                    "rationale": text,
                }
        elif role == "finding_explanation":
            text = (
                "Finding explanation: Telemetry banners matched deterministic security rule. "
                "Evidence demonstrates unencrypted protocol exposure in synthetic endpoint."
            )
            if request.response_schema:
                parsed = {
                    "summary": text,
                    "remediation": "Disable deprecated cleartext management ports.",
                }
        else:
            text = f"Deterministic advisory response for role '{role}'."
            if request.response_schema:
                parsed = {"role": role, "summary": text}

        # If parsed was produced, ensure text is synchronized if schema required
        if request.response_schema and parsed is not None:
            text = json.dumps(parsed)

        tokens_out = max(1, len(text.split()) * 4 // 3)

        return LLMResponse(
            text=text,
            parsed=parsed,
            provider="deterministic",
            model=self.model_name,
            tokens_in=tokens_in,
            tokens_out=tokens_out,
            latency_ms=2,
            cache_hit=False,
            finish_reason="stop",
        )
