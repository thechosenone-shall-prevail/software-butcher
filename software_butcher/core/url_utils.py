"""URL normalization and target-path validation for web assessments."""

from __future__ import annotations

import re
from urllib.parse import urljoin, urlsplit, urlunsplit

DOMAIN_LIKE = re.compile(r"^[a-z0-9][a-z0-9.-]+\.[a-z]{2,}$", re.IGNORECASE)


def host_key(url: str) -> str:
    parsed = urlsplit(url.strip())
    if parsed.netloc:
        return parsed.netloc.lower().rstrip(".")
    segment = url.strip("/").split("/")[0].lower()
    if DOMAIN_LIKE.match(segment):
        return segment.rstrip(".")
    return url.strip().lower()


def engagement_entry_url(url: str) -> str:
    """Return the scoped assessment entry URL.

    When ``--target`` includes a path (e.g. ``/hall/``), recon and gates use that
    path — not the bare hostname root.
    """
    raw = (url or "").strip()
    if not raw:
        return raw
    parsed = urlsplit(raw)
    if parsed.scheme in {"http", "https"} and parsed.netloc:
        if (parsed.path or "").strip("/"):
            return raw.rstrip("/")
        return f"{parsed.scheme}://{parsed.netloc}"
    return base_web_url(raw).rstrip("/")


def base_web_url(url: str) -> str:
    """Return scheme://host for a URL or bare domain."""
    parsed = urlsplit(url.strip())
    if parsed.scheme in {"http", "https"} and parsed.netloc:
        return f"{parsed.scheme}://{parsed.netloc}"
    cleaned = url.strip().rstrip("/")
    if cleaned.startswith("//"):
        cleaned = f"https:{cleaned}"
    if "://" not in cleaned and DOMAIN_LIKE.match(cleaned.split("/")[0]):
        return f"https://{cleaned.split('/')[0]}"
    return cleaned


def canonical_web_url(path: str, base_target: str | None = None) -> str | None:
    """Normalize paths/hypotheses to absolute http(s) URLs when possible."""
    if not path or not path.strip():
        return None

    raw = path.strip()
    parsed = urlsplit(raw)

    if parsed.scheme in {"http", "https"} and parsed.netloc:
        normalized_path = parsed.path or "/"
        if normalized_path != "/":
            normalized_path = normalized_path.rstrip("/")
        port = f":{parsed.port}" if parsed.port else ""
        return f"{parsed.scheme}://{parsed.netloc}{port}{normalized_path}"

    if raw.startswith("//") and parsed.netloc:
        return f"https://{parsed.netloc}{parsed.path or ''}".rstrip("/")

    base = base_web_url(base_target) if base_target else None
    if not base:
        return None

    if raw.startswith("/"):
        joined = urljoin(base.rstrip("/") + "/", raw.lstrip("/"))
        return joined.rstrip("/") or base

    # Bare path segment like "hall" or "dashboard"
    if "/" not in raw and not DOMAIN_LIKE.match(raw):
        return urljoin(base.rstrip("/") + "/", raw).rstrip("/")

    return None


def same_origin(left: str, right: str) -> bool:
    return host_key(left) == host_key(right)


def is_plausible_target_path(path: str, base_target: str | None = None) -> bool:
    """Reject parent-path artifacts like '/' or '/evil.com/foo' off-target."""
    if not path or path in {"/", "."}:
        return False

    canonical = canonical_web_url(path, base_target) or path
    parsed = urlsplit(canonical if "://" in canonical else f"https://{canonical}")

    if parsed.scheme in {"http", "https"}:
        if base_target and not same_origin(canonical, base_target):
            return False
        return bool(parsed.netloc)

    # Path-only strings that embed a foreign domain as the first segment are invalid.
    segments = path.strip("/").split("/")
    if segments and DOMAIN_LIKE.match(segments[0]):
        if base_target and segments[0].lower() != host_key(base_target):
            return False
    return True


def resolve_tool_path(target: str, discovered_path: str) -> str | None:
    """Turn scanner output paths into in-scope absolute URLs."""
    cleaned = discovered_path.strip().rstrip(".,;")
    if not cleaned:
        return None

    base = base_web_url(target)
    base_host = host_key(base)

    if cleaned.startswith("/"):
        first_segment = cleaned.strip("/").split("/")[0]
        if first_segment and DOMAIN_LIKE.match(first_segment) and first_segment.lower() != base_host:
            return None
        candidate = urljoin(base.rstrip("/") + "/", cleaned.lstrip("/"))
    elif cleaned.startswith(("http://", "https://")):
        candidate = cleaned
        if not same_origin(candidate, base):
            return None
        return candidate.rstrip("/") if candidate.endswith("/") and urlsplit(candidate).path not in {"", "/"} else candidate
    else:
        if DOMAIN_LIKE.match(cleaned.split("/")[0]) and cleaned.split("/")[0].lower() != base_host:
            return None
        candidate = urljoin(base.rstrip("/") + "/", cleaned)

    if not same_origin(candidate, base):
        return None
    return candidate.rstrip("/") if candidate.endswith("/") and urlsplit(candidate).path not in {"", "/"} else candidate
