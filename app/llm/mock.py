"""Deterministic mock LLM provider — no network, no model, fully local.

Default behavior proposes `calendar.read`, which the demo chain is allowed
to execute. A queue of scripted replies lets tests drive arbitrary (and
malicious) LLM output without any real model.
"""

from __future__ import annotations

import json
from collections import deque


class MockProvider:
    name = "mock"

    def __init__(self, scripted_replies: list[str] | None = None) -> None:
        self._replies: deque[str] = deque(scripted_replies or [])

    def generate(self, system: str, prompt: str) -> str:
        if self._replies:
            return self._replies.popleft()
        return json.dumps(
            {
                "tool": "calendar.read",
                "arguments": {"days": 7},
                "rationale": "Default mock proposal: check calendar availability.",
            }
        )


__all__ = ["MockProvider"]
