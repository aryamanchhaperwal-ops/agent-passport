"""Ollama provider — local inference, no paid API, no cloud.

Talks to a local Ollama daemon at `OLLAMA_BASE_URL` (default
http://localhost:11434). Any connectivity problem raises `LLMUnavailable`,
which callers treat as "no proposal" (fail closed). No API key is involved.
"""

from __future__ import annotations

from app.llm.base import LLMConfig, LLMProvider, http_post_json


class OllamaProvider:
    name = "ollama"

    def __init__(self, config: LLMConfig) -> None:
        self._config = config

    def generate(self, system: str, prompt: str) -> str:
        payload = {
            "model": self._config.ollama_model,
            "prompt": prompt,
            "system": system,
            "stream": False,
            "options": {"temperature": 0},
        }
        data = http_post_json(
            f"{self._config.ollama_base_url.rstrip('/')}/api/generate",
            payload,
            timeout=self._config.timeout_seconds,
        )
        response = data.get("response")
        if not isinstance(response, str):
            raise LLMUnavailable("ollama returned no text response")
        return response


__all__ = ["OllamaProvider"]
