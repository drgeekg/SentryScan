"""Remote HTTP LLM provider supporting OpenAI, OpenRouter, Gemini, Anthropic, Ollama, and Custom endpoints."""

from __future__ import annotations

import logging
import os
import time

import httpx

from sentryscan.llm.interface import LLMProvider, LLMRequest, LLMResponse

logger = logging.getLogger(__name__)


class RemoteLLMProvider(LLMProvider):
    """Universal HTTP LLM provider with per-provider Model, URL, and API Key configuration."""

    def __init__(
        self,
        provider: str = "openai",
        model: str | None = None,
        base_url: str | None = None,
        api_key: str | None = None,
    ) -> None:
        self.provider = provider.lower()
        self.client = httpx.Client(timeout=45.0)

        # Global overrides take precedence if supplied
        g_model = os.environ.get("SENTRYSCAN_LLM_MODEL")
        g_url = os.environ.get("SENTRYSCAN_LLM_BASE_URL")
        g_key = os.environ.get("SENTRYSCAN_LLM_API_KEY")

        if self.provider == "gemini":
            self.api_key = api_key or g_key or os.environ.get("GEMINI_API_KEY", "")
            self.model = model or g_model or os.environ.get("GEMINI_MODEL", "gemini-2.0-flash")
            self.base_url = (base_url or g_url or os.environ.get("GEMINI_BASE_URL", "https://generativelanguage.googleapis.com/v1beta")).rstrip("/")

        elif self.provider == "anthropic":
            self.api_key = api_key or g_key or os.environ.get("ANTHROPIC_API_KEY", "")
            self.model = model or g_model or os.environ.get("ANTHROPIC_MODEL", "claude-3-5-sonnet-20241022")
            self.base_url = (base_url or g_url or os.environ.get("ANTHROPIC_BASE_URL", "https://api.anthropic.com/v1")).rstrip("/")

        elif self.provider == "openrouter":
            self.api_key = api_key or g_key or os.environ.get("OPENROUTER_API_KEY", "")
            self.model = model or g_model or os.environ.get("OPENROUTER_MODEL", "google/gemini-2.0-flash-exp:free")
            self.base_url = (base_url or g_url or os.environ.get("OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1")).rstrip("/")

        elif self.provider == "ollama":
            self.api_key = api_key or g_key or os.environ.get("OLLAMA_API_KEY", "ollama")
            self.model = model or g_model or os.environ.get("OLLAMA_MODEL", "llama3.2")
            self.base_url = (base_url or g_url or os.environ.get("OLLAMA_BASE_URL", "http://127.0.0.1:11434")).rstrip("/")

        elif self.provider in ("nvidia", "nim"):
            self.api_key = api_key or g_key or os.environ.get("NVIDIA_API_KEY", os.environ.get("NIM_API_KEY", ""))
            self.model = model or g_model or os.environ.get("NVIDIA_MODEL", os.environ.get("NIM_MODEL", "meta/llama-3.3-70b-instruct"))
            self.base_url = (base_url or g_url or os.environ.get("NVIDIA_BASE_URL", os.environ.get("NIM_BASE_URL", "https://integrate.api.nvidia.com/v1"))).rstrip("/")

        elif self.provider in ("custom", "local", "vllm", "lmstudio"):
            self.api_key = api_key or g_key or os.environ.get("CUSTOM_API_KEY", "not-needed")
            self.model = model or g_model or os.environ.get("CUSTOM_MODEL", "default")
            self.base_url = (base_url or g_url or os.environ.get("CUSTOM_BASE_URL", "http://127.0.0.1:8000/v1")).rstrip("/")

        else:  # default openai
            self.api_key = api_key or g_key or os.environ.get("OPENAI_API_KEY", "")
            self.model = model or g_model or os.environ.get("OPENAI_MODEL", "gpt-4o-mini")
            self.base_url = (base_url or g_url or os.environ.get("OPENAI_BASE_URL", "https://api.openai.com/v1")).rstrip("/")

    def generate(self, request: LLMRequest) -> LLMResponse:
        t0 = time.perf_counter()
        prompt_text = " ".join(m.get("content", "") for m in request.messages)
        tokens_in = max(1, len(prompt_text.split()) * 4 // 3)

        try:
            if self.provider == "gemini":
                text = self._call_gemini(request)
            elif self.provider == "anthropic":
                text = self._call_anthropic(request)
            else:  # openai, openrouter, ollama, custom
                text = self._call_openai_compatible(request)

            latency_ms = round((time.perf_counter() - t0) * 1000, 1)
            tokens_out = max(1, len(text.split()) * 4 // 3)

            return LLMResponse(
                text=text,
                parsed=None,
                provider=self.provider,
                model=self.model,
                tokens_in=tokens_in,
                tokens_out=tokens_out,
                latency_ms=latency_ms,
                cache_hit=False,
                finish_reason="stop",
            )
        except Exception as err:
            logger.warning("Remote LLM call failed (%s at %s), falling back: %s", self.provider, self.base_url, err)
            latency_ms = round((time.perf_counter() - t0) * 1000, 1)
            fallback = f"Advisory fallback: {request.role} analysis completed. (Provider '{self.provider}' error: {err})"
            return LLMResponse(
                text=fallback,
                parsed=None,
                provider=f"{self.provider}-fallback",
                model=self.model,
                tokens_in=tokens_in,
                tokens_out=len(fallback.split()),
                latency_ms=latency_ms,
                cache_hit=False,
                finish_reason="fallback",
            )

    def _call_gemini(self, request: LLMRequest) -> str:
        # e.g. https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=...
        url = f"{self.base_url}/models/{self.model}:generateContent?key={self.api_key}"
        parts = []
        if request.system:
            parts.append({"text": f"System Instructions: {request.system}"})
        for m in request.messages:
            parts.append({"text": f"{m.get('role', 'user')}: {m.get('content', '')}"})

        payload = {"contents": [{"parts": parts}]}
        resp = self.client.post(url, json=payload)
        resp.raise_for_status()
        data = resp.json()
        return data["candidates"][0]["content"]["parts"][0]["text"]

    def _call_anthropic(self, request: LLMRequest) -> str:
        url = f"{self.base_url}/messages" if not self.base_url.endswith("/messages") else self.base_url
        headers = {
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        }
        messages = [{"role": m.get("role", "user"), "content": m.get("content", "")} for m in request.messages]
        payload = {
            "model": self.model,
            "max_tokens": 1024,
            "system": request.system or "",
            "messages": messages,
        }
        resp = self.client.post(url, json=payload, headers=headers)
        resp.raise_for_status()
        data = resp.json()
        return data["content"][0]["text"]

    def _call_openai_compatible(self, request: LLMRequest) -> str:
        # Resolve target URL
        b = self.base_url
        if b.endswith("/chat/completions"):
            url = b
        elif b.endswith("/v1"):
            url = f"{b}/chat/completions"
        else:
            url = f"{b}/v1/chat/completions"

        headers = {"Content-Type": "application/json"}
        if self.api_key and self.api_key != "not-needed":
            headers["Authorization"] = f"Bearer {self.api_key}"
        if self.provider == "openrouter":
            headers["HTTP-Referer"] = "https://github.com/sentryscan"

        messages = []
        if request.system:
            messages.append({"role": "system", "content": request.system})
        messages.extend(request.messages)

        payload = {"model": self.model, "messages": messages, "temperature": 0.2}
        resp = self.client.post(url, json=payload, headers=headers)
        resp.raise_for_status()
        data = resp.json()
        return data["choices"][0]["message"]["content"]
