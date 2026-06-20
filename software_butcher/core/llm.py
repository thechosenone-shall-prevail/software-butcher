"""Optional OpenRouter client factory — openai is not required at import time."""

from __future__ import annotations

import os
from typing import Any


def create_openrouter_client() -> Any | None:
    """Return an OpenAI-compatible OpenRouter client, or None if unavailable.

    This replaces the previous LLM client factory and only supports
    OpenRouter via `OPENROUTER_API_KEY` and `OPENROUTER_BASE_URL`.
    """
    try:
        import openai
    except ImportError:
        return None

    api_key = os.environ.get("OPENROUTER_API_KEY")
    if not api_key:
        return None

    base = os.environ.get("OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1")
    return openai.Client(api_key=api_key, base_url=base)
