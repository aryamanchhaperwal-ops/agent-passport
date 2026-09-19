"""OpenRouter provider — OPTIONAL cloud fallback.

Enabled only when `LLM_PROVIDER=openrouter` AND `OPENROUTER_API_KEY` is
set in the environment; the key is read exclusively from the environment
and is never hard-coded, logged, or persisted. Any network failure raises
`LLMUnavailable` (fail closed upstream).
"""

from __future__ import annotations

from app.llm.base import LLMConfig, LLMProvider, LLMUnavailable, http_post_json

OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"


class OpenRouterProvider:
    name = "openrouter"

    def __init__(self, config: LLMConfig) -> None:
        if not config.openrouter_api_key:
            raise LLMUnavailable(
                "OPENROUTER_API_KEY is not configured in the environment"
            )
        if not config.openrouter_model:
            raise LLMUnavailable("OPENROUTER_MODEL is not configured")
        self._config = config

    def generate(self, system: str, prompt: str) -> str:
        payload = {
            "model": self._config.openrouter_model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": prompt},
            ],
            "temperature": 0,
        }
        data = http_post_json(
            OPENROUTER_URL,
            payload,
            headers={
                "Authorization": f"Bearer {self._config.openrouter_api_key}",
            },
            timeout=self._config.timeout_seconds,
        )
        try:
            content = data["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as exc:
            raise LLMUnavailable(f"unexpected OpenRouter response shape: {exc}") from exc
        if not isinstance(content, str):
            raise LLMUnavailable("OpenRouter returned no text content")
        return content


__all__ = ["OpenRouterProvider"]
