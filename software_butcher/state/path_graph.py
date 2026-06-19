"""Path hierarchy helpers for the known parent-path failure mode."""

from __future__ import annotations

from urllib.parse import urlsplit, urlunsplit


def parent_path(path: str) -> str | None:
    """Return the parent path for URLs or URL paths."""
    if not path or path in {"/", "."}:
        return None

    parsed = urlsplit(path)
    raw_path = parsed.path if parsed.scheme or parsed.netloc else path
    raw_path = raw_path.rstrip("/")

    if not raw_path or raw_path == "/":
        return None

    parts = raw_path.split("/")
    parent = "/".join(parts[:-1]) or "/"

    if parsed.scheme or parsed.netloc:
        return urlunsplit((parsed.scheme, parsed.netloc, parent, "", ""))
    return parent
