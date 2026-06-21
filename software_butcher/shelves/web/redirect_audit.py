"""Redirect-body analysis — detect "auth check ran after render" data leaks.

The pattern: the server returns a 3xx redirect (e.g. 302 -> /login.php) but the
response body delivered *with* that redirect still contains the full protected
page (booking tables, PII, reports). A naive client that only inspects the
status code follows the redirect and never sees the leaked data.

Everything here is signal-driven and generic — no target-specific paths or
wordlists. The only "location" heuristic is a structural notion of redirecting
to a lower-privilege surface (login/index/root), which is stack-agnostic.
"""

from __future__ import annotations

import re
from typing import Any

REDIRECT_CODES = frozenset({301, 302, 303, 307, 308})

# Generic PII / sensitive-data signals — not tied to any one application.
_PII_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),          # email
    re.compile(r"(?<!\d)(?:\+?\d[ -]?){10,13}(?!\d)"),                       # phone-ish
    re.compile(r"\b\d{4}[- ]?\d{4}[- ]?\d{4}(?:[- ]?\d{1,4})?\b"),           # card/id-ish
)
_ROW_RE = re.compile(r"<tr[\s>]", re.I)
_TABLE_RE = re.compile(r"<table[\s>]", re.I)
_TD_RE = re.compile(r"<td[\s>]", re.I)
# Body is "page-like" rather than a redirect stub if it has real document structure.
_PAGE_STRUCTURE_RE = re.compile(r"<(?:table|form|h[1-6]|ul|ol|article|section)[\s>]", re.I)
# A redirect Location pointing at a lower-privilege surface strengthens the signal.
_LOW_PRIV_LOCATION_RE = re.compile(r"(login|signin|sign-in|logout|index|home|auth|/$)", re.I)
# Stub redirect bodies (e.g. "Object moved", meta-refresh shims) are not leaks.
_STUB_MARKERS = ("object moved", "redirecting", "document has moved", "this page has moved")

# Below this size, a 3xx body is almost certainly a stub, not leaked content.
MIN_LEAK_BYTES = 1500


def _count_pii(body: str) -> int:
    return sum(len(p.findall(body or "")) for p in _PII_PATTERNS)


def _redact(body: str, *, limit: int = 240) -> str:
    snippet = (body or "")[:limit]
    for pattern in _PII_PATTERNS:
        snippet = pattern.sub("[REDACTED]", snippet)
    return re.sub(r"\s+", " ", snippet).strip()


def _is_stub_body(body: str) -> bool:
    sample = (body or "")[:512].lower()
    return any(marker in sample for marker in _STUB_MARKERS)


def _hop_status(hop: dict[str, Any]) -> int | None:
    try:
        return int(hop.get("status")) if hop.get("status") is not None else None
    except (TypeError, ValueError):
        return None


def evaluate_redirect_hop(hop: dict[str, Any], *, min_leak_bytes: int = MIN_LEAK_BYTES) -> dict[str, Any] | None:
    """Return a leak descriptor for one redirect hop, or None if it's benign."""
    status = _hop_status(hop)
    if status is None or status not in REDIRECT_CODES:
        return None

    body = str(hop.get("body") or "")
    body_len = int(hop.get("body_len") or len(body))
    if body_len < min_leak_bytes or _is_stub_body(body):
        return None

    rows = len(_ROW_RE.findall(body))
    has_structure = bool(_PAGE_STRUCTURE_RE.search(body))
    pii_hits = _count_pii(body)
    location = str(hop.get("location") or "")
    low_priv = bool(_LOW_PRIV_LOCATION_RE.search(location))

    # Leak = a substantial, structured body delivered alongside a redirect.
    if not (has_structure or rows >= 3 or pii_hits >= 2):
        return None

    return {
        "url": hop.get("url"),
        "status": status,
        "location": location,
        "body_len": body_len,
        "table_rows": rows,
        "pii_hits": pii_hits,
        "low_priv_redirect": low_priv,
        "has_page_structure": has_structure,
        "redacted_sample": _redact(body),
    }


def analyze_redirect_bodies(
    chain: list[dict[str, Any]],
    *,
    min_leak_bytes: int = MIN_LEAK_BYTES,
) -> list[dict[str, Any]]:
    """Scan a redirect chain and return descriptors for hops that leak data."""
    leaks: list[dict[str, Any]] = []
    seen: set[str] = set()
    for hop in chain or []:
        descriptor = evaluate_redirect_hop(hop, min_leak_bytes=min_leak_bytes)
        if not descriptor:
            continue
        key = f"{descriptor['url']}::{descriptor['status']}"
        if key in seen:
            continue
        seen.add(key)
        leaks.append(descriptor)
    return leaks


def summarize_redirect_chain(
    chain: list[dict[str, Any]],
    *,
    min_leak_bytes: int = MIN_LEAK_BYTES,
) -> list[dict[str, Any]]:
    """Compact, persistence-safe summary of redirect hops (NO raw bodies)."""
    summary: list[dict[str, Any]] = []
    for hop in chain or []:
        status = _hop_status(hop)
        if status is None:
            continue
        descriptor = evaluate_redirect_hop(hop, min_leak_bytes=min_leak_bytes)
        summary.append(
            {
                "url": hop.get("url"),
                "status": status,
                "location": hop.get("location"),
                "body_len": int(hop.get("body_len") or len(str(hop.get("body") or ""))),
                "leak_suspected": descriptor is not None,
            }
        )
    return summary


def chain_leak_suspected(chain: list[dict[str, Any]], *, min_leak_bytes: int = MIN_LEAK_BYTES) -> bool:
    return any(entry.get("leak_suspected") for entry in summarize_redirect_chain(chain, min_leak_bytes=min_leak_bytes))


def confidence_for_leak(descriptor: dict[str, Any]) -> float:
    """Map a leak descriptor to a confidence score in [0, 0.95]."""
    score = 0.55
    if descriptor.get("low_priv_redirect"):
        score += 0.2
    score += min(0.2, int(descriptor.get("pii_hits") or 0) * 0.02)
    if int(descriptor.get("table_rows") or 0) >= 3:
        score += 0.1
    return round(min(score, 0.95), 2)
