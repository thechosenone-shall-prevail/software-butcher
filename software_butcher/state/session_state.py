"""Session persistence for authenticated probe chaining.

Cookies/tokens captured from successful auth bypass are stored here and
reused by subsequent adapter probes.  Sessions are keyed by origin
(scheme + host + port) to match browser scoping behaviour.

Stored alongside finding_state.json as session_state.json.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit


def get_origin(url: str) -> str:
    """Return the origin (scheme://host[:port]) of a URL.

    >>> get_origin("http://localhost/dvwa/login.php")
    'http://localhost'
    >>> get_origin("https://example.com:8443/api/v1")
    'https://example.com:8443'
    """
    parsed = urlsplit(url)
    if not parsed.scheme or not parsed.netloc:
        return url
    return f"{parsed.scheme}://{parsed.netloc}"


def parse_set_cookie(header: str) -> dict[str, str]:
    """Extract cookie name=value pairs from a Set-Cookie header value.

    Only captures the cookie name and value — ignores attributes like Path,
    Domain, Expires, HttpOnly, etc.

    >>> parse_set_cookie("PHPSESSID=abc123; path=/; HttpOnly")
    {'PHPSESSID': 'abc123'}
    >>> parse_set_cookie("token=xyz; Secure, session=999; path=/")
    {'token': 'xyz', 'session': '999'}
    """
    cookies: dict[str, str] = {}
    # Set-Cookie can contain multiple cookies separated by commas (rare but valid)
    # Each cookie's name=value is before the first semicolon
    for part in header.split(","):
        part = part.strip()
        if "=" not in part:
            continue
        # Take only the name=value segment (before any ;attributes)
        nv = part.split(";")[0].strip()
        if "=" in nv:
            name, _, value = nv.partition("=")
            name = name.strip()
            value = value.strip()
            if name and not name.lower() in {
                "path", "domain", "expires", "max-age",
                "samesite", "secure", "httponly",
            }:
                cookies[name] = value
    return cookies


class SessionStore:
    """Origin-scoped session cookie persistence.

    sessions = {origin → {cookie_name → cookie_value}}
    Example: {"http://localhost": {"PHPSESSID": "abc123"}}
    """

    def __init__(self) -> None:
        self.sessions: dict[str, dict[str, str]] = {}

    def store(self, origin: str, cookies: dict[str, str]) -> None:
        """Merge cookies into the session for the given origin."""
        existing = self.sessions.get(origin, {})
        existing.update(cookies)
        self.sessions[origin] = existing

    def get(self, origin: str) -> dict[str, str]:
        """Return cookies for the origin, or empty dict if none stored."""
        return self.sessions.get(origin, {})

    def has_session(self, origin: str) -> bool:
        """Return True if any cookies are stored for the origin."""
        return bool(self.sessions.get(origin))

    def cookie_header(self, origin: str) -> str | None:
        """Return a formatted Cookie header value, or None if no session."""
        cookies = self.get(origin)
        if not cookies:
            return None
        return "; ".join(f"{k}={v}" for k, v in cookies.items())

    def to_dict(self) -> dict[str, Any]:
        return {"sessions": self.sessions}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "SessionStore":
        store = cls()
        store.sessions = data.get("sessions", data)
        return store

    def save(self, path: str | Path) -> None:
        """Persist sessions to a JSON file."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.to_dict(), indent=2, sort_keys=True), encoding="utf-8")

    @classmethod
    def load(cls, path: str | Path) -> "SessionStore":
        """Load sessions from a JSON file, returning empty store if missing."""
        path = Path(path)
        if not path.exists():
            return cls()
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            return cls.from_dict(data)
        except (json.JSONDecodeError, KeyError):
            return cls()
