"""Score discovered URLs — deprioritize XAMPP boilerplate, elevate real application paths."""

from __future__ import annotations

import re
from urllib.parse import urlsplit

# XAMPP / default-hosting documentation — not the target application
NOISE_PATH_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"/dashboard/(faq|howto|index)\.html$", re.I),
    re.compile(r"/dashboard/(de|fr|es|pl|zh_|ja|tr|pt|ro|ru|it|hu|pt_br)/?$", re.I),
    re.compile(r"/dashboard/Images/?$", re.I),
    re.compile(r"/dashboard/docs/", re.I),
    re.compile(r"/dashboard/phpinfo\.php$", re.I),
    re.compile(r"privacy_policy\.html$", re.I),
    re.compile(r"/licenses/", re.I),
    re.compile(r"/webalizer/", re.I),
    re.compile(r"/icons/", re.I),
    re.compile(r"\.(png|jpe?g|gif|svg|ico|css|js|woff2?)$", re.I),
)

# Paths that likely belong to the actual engagement application
APP_PATH_SIGNALS: tuple[str, ...] = (
    "hall",
    "booking",
    "book",
    "portal",
    "login",
    "signin",
    "auth",
    "register",
    "student",
    "faculty",
    "reservation",
    "apply",
    "app",
)

XAMPP_TITLE_SIGNALS = ("xampp", "welcome to xampp", "apache friends")
XAMPP_BODY_SIGNALS = ("xampp for linux", "apache friends", "phpmyadmin", "dashboard/index.html")


def path_segment(url: str) -> str:
    parsed = urlsplit(url)
    return (parsed.path or "/").lower()


def is_noise_path(url: str) -> bool:
    path = path_segment(url)
    if path in {"/", ""}:
        return False
    return any(pattern.search(path) for pattern in NOISE_PATH_PATTERNS)


def score_path(url: str, *, title: str = "", page_context: str = "") -> float:
    """Return 0.0 (ignore) – 1.0 (investigate first)."""
    if is_noise_path(url):
        return 0.05

    path = path_segment(url)
    text = f"{path} {title} {page_context}".lower()

    score = 0.45
    if "/api" in path or "swagger" in text or "openapi" in text:
        score = max(score, 0.78)
    for signal in APP_PATH_SIGNALS:
        if signal in path or signal in text:
            score = max(score, 0.92 if signal == "hall" else 0.85)

    # phpMyAdmin: security-relevant but not the booking app — medium priority
    if "phpmyadmin" in path:
        return 0.55

    if path.rstrip("/") == "/dashboard":
        return 0.15

    if path.startswith("/dashboard/"):
        return 0.12

    if path.endswith(".html") and "/dashboard" not in path:
        score = max(score, 0.5)

    return min(score, 1.0)


def priority_for_score(score: float) -> float:
    return round(0.45 + score * 0.55, 2)


def should_queue_path(url: str, *, title: str = "", page_context: str = "", min_score: float = 0.4) -> bool:
    return score_path(url, title=title, page_context=page_context) >= min_score


def detect_default_stack_landing(
    *,
    title: str = "",
    body: str = "",
    headers: dict[str, str] | None = None,
    final_url: str = "",
) -> dict[str, str | bool]:
    """Detect when the mapped page is a default stack landing (e.g. XAMPP), not the real app."""
    title_l = (title or "").lower()
    body_l = (body or "")[:8000].lower()
    path = path_segment(final_url)

    is_xampp = any(s in title_l for s in XAMPP_TITLE_SIGNALS) or any(s in body_l for s in XAMPP_BODY_SIGNALS)
    is_dashboard_root = path.rstrip("/") == "/dashboard" or path.startswith("/dashboard/")

    if is_xampp or (is_dashboard_root and "apache" in body_l):
        return {
            "detected": True,
            "stack": "xampp_default",
            "conclusion": (
                "Root serves default XAMPP/dashboard content, not the primary application. "
                "Organic links from this page are stack documentation — not the booking portal. "
                "Use headless browser navigation and scoped directory discovery to find unlinked app paths."
            ),
        }
    return {"detected": False, "stack": "", "conclusion": ""}


def summarize_page_content(title: str, body: str, *, limit: int = 400) -> str:
    """Extract a short human-readable summary from HTML for Brain context."""
    if title:
        snippet = title.strip()
    else:
        stripped = re.sub(r"<[^>]+>", " ", body or "")
        stripped = re.sub(r"\s+", " ", stripped).strip()
        snippet = stripped[:limit]
    return snippet[:limit]
