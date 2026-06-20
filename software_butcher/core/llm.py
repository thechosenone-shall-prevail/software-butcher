"""Optional DeepSeek client factory — openai is not required at import time."""

from __future__ import annotations

import os
from typing import Any


def create_deepseek_client() -> Any | None:
    """Return an OpenAI-compatible DeepSeek client, or None if unavailable."""
    try:
        import openai
    except ImportError:
        return None

    api_key = os.environ.get("DEEPSEEK_API_KEY")
    if not api_key:
        return None

    return openai.Client(api_key=api_key, base_url="https://api.deepseek.com/v1")
