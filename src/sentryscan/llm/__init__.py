"""LLM layer providing a swappable interface with deterministic default."""

from sentryscan.llm.deterministic import DeterministicLLMProvider
from sentryscan.llm.factory import get_llm_provider
from sentryscan.llm.fake import FakeLLMProvider
from sentryscan.llm.interface import LLMProvider, LLMRequest, LLMResponse

__all__ = [
    "LLMProvider",
    "LLMRequest",
    "LLMResponse",
    "DeterministicLLMProvider",
    "FakeLLMProvider",
    "get_llm_provider",
]
