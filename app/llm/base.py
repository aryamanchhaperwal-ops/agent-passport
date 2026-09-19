"""LLM provider abstraction (Phase 2).

Security posture of this layer:

  * An LLM proposes; it NEVER authorizes. The strongest statement of this
    is structural: providers return raw text, and the only structured thing
    this layer can produce from it is an `AgentProposal` — which carries a
    tool NAME and ARGUMENTS, no authority. The SecurityGateway derives the
    required scope from the tool registry and re-derives authorization from
    the cryptographic chain, so whatever an LLM claims is inert.

  * Parsing fails closed: malformed, empty, fenced, or nonsensical output
    becomes `None` (no proposal), never a guessed default action.

  * Providers never embed API keys; configuration comes from environment
    variables (see `LLMConfig.from_env`). Network providers raise
    `LLMUnavailable` on any connectivity/timeout/HTTP problem; callers must
    treat that as "no proposal" — fail closed.
"""

from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Protocol

from pydantic import BaseModel, ConfigDict, Field


class LLMUnavailable(RuntimeError):
    """Raised when a network LLM provider cannot be reached or fails."""


class AgentProposal(BaseModel):
    """A parsed LLM proposal. Purely descriptive — no authority attached."""

    model_config = ConfigDict(frozen=True)

    tool_name: str = Field(min_length=1, max_length=128)
    arguments: dict = Field(default_factory=dict)
    rationale: str = Field(default="", max_length=2000)
    raw_text: str = Field(default="", max_length=8000)


_JSON_OBJECT_RE = re.compile(r"\{.*\}", re.DOTALL)


def parse_proposal(text: str | None) -> AgentProposal | None:
    """Parse raw LLM output into an AgentProposal, or None if unusable.

    Accepts a JSON object with `tool` (required), optional `arguments`,
    optional `rationale`. Tolerates markdown code fences and surrounding
    prose by extracting the first {...} block. Any failure -> None
    (fail closed).
    """
    if not text or not isinstance(text, str):
        return None
    candidate = text.strip()
    # Strip a fenced block if present.
    fence = re.search(r"```(?:json)?\s*(.*?)```", candidate, re.DOTALL)
    if fence:
        candidate = fence.group(1).strip()
    match = _JSON_OBJECT_RE.search(candidate)
    if not match:
        return None
    try:
        data = json.loads(match.group(0))
    except (json.JSONDecodeError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    tool = data.get("tool")
    if not isinstance(tool, str) or not tool.strip():
        return None
    arguments = data.get("arguments", {})
    if not isinstance(arguments, dict):
        return None
    rationale = data.get("rationale", "")
    if not isinstance(rationale, str):
        rationale = ""
    try:
        return AgentProposal(
            tool_name=tool.strip(),
            arguments=arguments,
            rationale=rationale,
            raw_text=text[:8000],
        )
    except Exception:
        return None


@dataclass(frozen=True)
class LLMConfig:
    """Environment-driven LLM configuration. No secrets in code."""

    provider: str = "mock"
    ollama_base_url: str = "http://localhost:11434"
    ollama_model: str = "llama3.1"
    openrouter_api_key: str = ""
    openrouter_model: str = ""
    timeout_seconds: float = 30.0

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None) -> "LLMConfig":
        source = env if env is not None else os.environ
        return cls(
            provider=source.get("LLM_PROVIDER", "mock").strip().lower() or "mock",
            ollama_base_url=source.get("OLLAMA_BASE_URL", "http://localhost:11434"),
            ollama_model=source.get("OLLAMA_MODEL", "llama3.1"),
            openrouter_api_key=source.get("OPENROUTER_API_KEY", ""),
            openrouter_model=source.get("OPENROUTER_MODEL", ""),
            timeout_seconds=float(source.get("LLM_TIMEOUT_SECONDS", "30")),
        )


def http_post_json(
    url: str,
    payload: dict[str, Any],
    headers: dict[str, str] | None = None,
    timeout: float = 30.0,
) -> dict[str, Any]:
    """Blocking JSON POST used by network providers. Module-level so tests
    can substitute it without any real network I/O."""
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", **(headers or {})},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read()
            return json.loads(body)
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError) as exc:
        raise LLMUnavailable(f"LLM request to {url} failed: {exc}") from exc


class LLMProvider(Protocol):
    """A provider turns a prompt into raw text. Nothing more."""

    name: str

    def generate(self, system: str, prompt: str) -> str: ...


def provider_from_config(config: LLMConfig) -> LLMProvider:
    """Build the configured provider. Fails closed on unknown names and on
    OpenRouter without a key (no silent fallback to a weaker provider)."""
    if config.provider == "mock":
        from app.llm.mock import MockProvider

        return MockProvider()
    if config.provider == "ollama":
        from app.llm.ollama import OllamaProvider

        return OllamaProvider(config)
    if config.provider == "openrouter":
        from app.llm.openrouter import OpenRouterProvider

        return OpenRouterProvider(config)
    raise ValueError(f"unknown LLM_PROVIDER {config.provider!r}")


__all__ = [
    "AgentProposal",
    "LLMConfig",
    "LLMProvider",
    "LLMUnavailable",
    "http_post_json",
    "parse_proposal",
    "provider_from_config",
]
