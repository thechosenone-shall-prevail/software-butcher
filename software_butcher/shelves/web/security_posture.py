"""Security posture analysis — headers, cookie flags, and CSRF on POST forms.

Pure, deterministic analysis over an already-fetched response. No network, no
hardcoded application paths. Consumes headers + raw body, returns structured
conclusions the Brain/synthesis can cite.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

# Baseline response headers a hardened web app is expected to set.
BASELINE_SECURITY_HEADERS: dict[str, str] = {
    "content-security-policy": "No Content-Security-Policy — XSS/content-injection mitigation absent",
    "strict-transport-security": "No HSTS — transport downgrade not prevented",
    "x-frame-options": "No X-Frame-Options — clickjacking exposure",
    "x-content-type-options": "No X-Content-Type-Options (nosniff) — MIME-sniffing allowed",
    "referrer-policy": "No Referrer-Policy — referrer leakage not controlled",
    "permissions-policy": "No Permissions-Policy — browser feature scope not restricted",
}

_FORM_BLOCK_RE = re.compile(r"<form\b[^>]*>(.*?)</form>", re.I | re.S)
_FORM_OPEN_RE = re.compile(r"<form\b([^>]*)>", re.I)
_ATTR_METHOD_RE = re.compile(r"\bmethod\s*=\s*[\"']?([a-z]+)", re.I)
_ATTR_ACTION_RE = re.compile(r"\baction\s*=\s*[\"']([^\"']*)", re.I)
_INPUT_NAME_RE = re.compile(r"<input\b[^>]*\bname\s*=\s*[\"']([^\"']+)", re.I)
_HIDDEN_INPUT_RE = re.compile(r"<input\b[^>]*\btype\s*=\s*[\"']hidden[\"'][^>]*>", re.I)
# Generic token-naming convention — works across frameworks, not app-specific.
_CSRF_HINT_RE = re.compile(r"(csrf|xsrf|_token|authenticity|nonce|anti.?forgery|requestverification)", re.I)


@dataclass
class ParsedForm:
    method: str
    action: str
    input_names: list[str] = field(default_factory=list)
    has_token: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "method": self.method,
            "action": self.action,
            "input_names": self.input_names,
            "has_token": self.has_token,
        }


def parse_forms(body: str) -> list[ParsedForm]:
    """Extract forms with method/action/input-names and CSRF-token presence."""
    forms: list[ParsedForm] = []
    for match in _FORM_BLOCK_RE.finditer(body or ""):
        attrs = match.group(0)
        inner = match.group(1)
        open_attrs = _FORM_OPEN_RE.search(attrs)
        attr_str = open_attrs.group(1) if open_attrs else ""
        method = (_ATTR_METHOD_RE.search(attr_str).group(1).upper() if _ATTR_METHOD_RE.search(attr_str) else "GET")
        action = (_ATTR_ACTION_RE.search(attr_str).group(1) if _ATTR_ACTION_RE.search(attr_str) else "")
        names = _INPUT_NAME_RE.findall(inner)[:30]
        block_text = attrs
        has_token = bool(_CSRF_HINT_RE.search(block_text)) and bool(_HIDDEN_INPUT_RE.search(block_text))
        forms.append(ParsedForm(method=method, action=action, input_names=names, has_token=has_token))
    return forms


def _cookie_issues(headers: dict[str, str]) -> list[str]:
    """Flag Set-Cookie values missing HttpOnly / SameSite (Secure only on HTTPS)."""
    issues: list[str] = []
    for key, value in (headers or {}).items():
        if key.lower() != "set-cookie":
            continue
        low = value.lower()
        name = value.split("=", 1)[0].strip() or "cookie"
        if "httponly" not in low:
            issues.append(f"Cookie '{name}' missing HttpOnly — readable from JavaScript (XSS theft).")
        if "samesite" not in low:
            issues.append(f"Cookie '{name}' missing SameSite — CSRF/cross-site sending not restricted.")
    return issues


def analyze_security_posture(
    url: str,
    *,
    headers: dict[str, str],
    body: str = "",
    is_https: bool = False,
) -> dict[str, Any]:
    """Return missing-control conclusions, cookie issues, and CSRF findings."""
    normalized = {k.lower(): v for k, v in (headers or {}).items()}

    missing_headers = [msg for hdr, msg in BASELINE_SECURITY_HEADERS.items() if hdr not in normalized]
    if is_https and "strict-transport-security" not in normalized:
        pass  # already captured above; HSTS only meaningful on HTTPS but still reported

    cookie_issues = _cookie_issues(headers)

    forms = parse_forms(body)
    csrf_gaps: list[dict[str, Any]] = []
    for form in forms:
        if form.method == "POST" and not form.has_token:
            csrf_gaps.append(form.to_dict())

    conclusions: list[str] = []
    conclusions.extend(missing_headers)
    conclusions.extend(cookie_issues)
    for gap in csrf_gaps:
        conclusions.append(
            f"POST form (action={gap['action'] or url!r}) has no anti-CSRF token among "
            f"inputs {gap['input_names'][:8]} — state-changing request is CSRF-able."
        )

    return {
        "url": url,
        "missing_headers": missing_headers,
        "cookie_issues": cookie_issues,
        "csrf_gaps": csrf_gaps,
        "form_count": len(forms),
        "conclusions": conclusions,
        "has_baseline_controls": not missing_headers and not cookie_issues and not csrf_gaps,
    }
