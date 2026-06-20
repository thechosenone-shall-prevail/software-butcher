"""Session persistence for authenticated probe chaining.

Cookies/tokens captured from successful auth bypass are stored here and
reused by subsequent adapter probes.  Sessions are keyed by origin
(scheme + host + port) to match browser scoping behaviour.

Shell sessions (SSH, Metasploit, Sliver, etc.) are also tracked to enable
post-exploit command chaining without re-establishing footholds.

Stored alongside finding_state.json as session_state.json.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit
from datetime import datetime, timezone


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


@dataclass
class ShellSession:
    """Represents an active shell session (SSH, Metasploit, Sliver, etc.)."""
    
    session_id: str  # Unique identifier for the session
    session_type: str  # "metasploit", "ssh", "sliver", "web_shell", etc.
    host: str  # Target host/IP
    port: int | None = None  # Port if applicable
    user: str | None = None  # Username if authenticated
    cwd: str = "/"  # Current working directory
    last_command: str = ""  # Last command executed
    last_output: str = ""  # Last command output
    active: bool = True  # Whether session is still active
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    last_used: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    metadata: dict[str, Any] = field(default_factory=dict)  # Additional session data
    
    def to_dict(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "session_type": self.session_type,
            "host": self.host,
            "port": self.port,
            "user": self.user,
            "cwd": self.cwd,
            "last_command": self.last_command,
            "last_output": self.last_output,
            "active": self.active,
            "created_at": self.created_at,
            "last_used": self.last_used,
            "metadata": self.metadata,
        }
    
    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ShellSession":
        return cls(
            session_id=data["session_id"],
            session_type=data["session_type"],
            host=data["host"],
            port=data.get("port"),
            user=data.get("user"),
            cwd=data.get("cwd", "/"),
            last_command=data.get("last_command", ""),
            last_output=data.get("last_output", ""),
            active=data.get("active", True),
            created_at=data.get("created_at", datetime.now(timezone.utc).isoformat()),
            last_used=data.get("last_used", datetime.now(timezone.utc).isoformat()),
            metadata=data.get("metadata", {}),
        )
    
    def update_usage(self, command: str, output: str) -> None:
        """Update session after running a command."""
        self.last_command = command
        self.last_output = output
        self.last_used = datetime.now(timezone.utc).isoformat()


class ShellSessionStore:
    """Manages active shell sessions for post-exploit chaining.
    
    Sessions are keyed by session_id and indexed by target for quick lookup.
    Enables the Brain to run commands in established shells without re-exploiting.
    """
    
    def __init__(self) -> None:
        self.sessions: dict[str, ShellSession] = {}  # session_id -> ShellSession
        self.target_index: dict[str, list[str]] = {}  # target -> list of session_ids
    
    def add_session(self, session: ShellSession) -> None:
        """Add a new shell session."""
        self.sessions[session.session_id] = session
        target_key = f"{session.host}:{session.port}" if session.port else session.host
        if target_key not in self.target_index:
            self.target_index[target_key] = []
        if session.session_id not in self.target_index[target_key]:
            self.target_index[target_key].append(session.session_id)
    def get_session(self, session_id: str) -> ShellSession | None:
        """Get a session by ID."""
        return self.sessions.get(session_id)
    def get_sessions_for_target(self, host: str, port: int | None = None) -> list[ShellSession]:
        """Get all active sessions for a target."""
        if port is not None:
            session_ids = self.target_index.get(f"{host}:{port}", [])
        else:
            session_ids = []
            for key, ids in self.target_index.items():
                if key == host or key.startswith(f"{host}:"):
                    session_ids.extend(ids)

        return [
            self.sessions[sid]
            for sid in session_ids
            if sid in self.sessions and self.sessions[sid].active
        ]


   


    def get_best_session_for_target(self, host: str, port: int | None = None) -> ShellSession | None:
        """Get the best (most recently used) active session for a target."""
        sessions = self.get_sessions_for_target(host, port)
        if not sessions:
            return None
        # Sort by last_used descending and return the most recent
        sessions.sort(key=lambda s: s.last_used, reverse=True)
        return sessions[0]
    
    def update_session(self, session_id: str, command: str, output: str, cwd: str | None = None) -> bool:
        """Update a session after running a command."""
        session = self.sessions.get(session_id)
        if not session:
            return False
        session.update_usage(command, output)
        if cwd:
            session.cwd = cwd
        return True
    
    def deactivate_session(self, session_id: str) -> bool:
        """Mark a session as inactive."""
        session = self.sessions.get(session_id)
        if not session:
            return False
        session.active = False
        return True
    
    def to_dict(self) -> dict[str, Any]:
        return {
            "sessions": {sid: sess.to_dict() for sid, sess in self.sessions.items()},
            "target_index": self.target_index,
        }
    
    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ShellSessionStore":
        store = cls()
        sessions_data = data.get("sessions", {})
        for session_id, session_dict in sessions_data.items():
            session = ShellSession.from_dict(session_dict)
            store.sessions[session_id] = session
        store.target_index = data.get("target_index", {})
        return store
    
    def save(self, path: str | Path) -> None:
        """Persist shell sessions to a JSON file."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.to_dict(), indent=2, sort_keys=True), encoding="utf-8")
    
    @classmethod
    def load(cls, path: str | Path) -> "ShellSessionStore":
        """Load shell sessions from a JSON file, returning empty store if missing."""
        path = Path(path)
        if not path.exists():
            return cls()
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            return cls.from_dict(data)
        except (json.JSONDecodeError, KeyError):
            return cls()


class SessionStore:
    """Origin-scoped session cookie persistence.

    sessions = {origin → {cookie_name → cookie_value}}
    Example: {"http://localhost": {"PHPSESSID": "abc123"}}
    """

    def __init__(self) -> None:
        self.sessions: dict[str, dict[str, str]] = {}
        self.shell_sessions = ShellSessionStore()  # New: shell session management

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
        return {
            "sessions": self.sessions,
            "shell_sessions": self.shell_sessions.to_dict(),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "SessionStore":
        store = cls()
        store.sessions = data.get("sessions", data)
        if "shell_sessions" in data:
            store.shell_sessions = ShellSessionStore.from_dict(data["shell_sessions"])
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

