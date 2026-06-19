"""Lightweight target classifier for first-pass routing."""

from __future__ import annotations

from pathlib import Path
from urllib.parse import urlsplit

from .assets import Asset


BINARY_SUFFIXES = {
    ".exe",
    ".dll",
    ".bin",
    ".elf",
    ".so",
    ".dylib",
    ".msi",
    ".apk",
    ".ipa",
    ".jar",
    ".war",
    ".firmware",
    ".img",
}


SOURCE_MARKERS = {
    "pyproject.toml",
    "package.json",
    "go.mod",
    "Cargo.toml",
    "pom.xml",
    "build.gradle",
    "CMakeLists.txt",
}


def classify_target(target: str) -> Asset:
    """Classify a user-provided target into an initial asset."""
    parsed = urlsplit(target)
    if parsed.scheme in {"http", "https"}:
        return Asset(locator=target, asset_type="web_endpoint")

    path = Path(target)
    if path.exists():
        if path.is_dir() and any((path / marker).exists() for marker in SOURCE_MARKERS):
            return Asset(locator=str(path), asset_type="source_repo")
        if path.is_file() and path.suffix.lower() in BINARY_SUFFIXES:
            return Asset(locator=str(path), asset_type="binary")
        return Asset(locator=str(path), asset_type="unknown")

    if target.startswith("aws:") or target.startswith("azure:") or target.startswith("gcp:"):
        return Asset(locator=target, asset_type="cloud_account")

    if _looks_like_ip(target):
        return Asset(locator=target, asset_type="ip")

    if "." in target and " " not in target:
        return Asset(locator=target, asset_type="domain")

    return Asset(locator=target, asset_type="unknown")


def _looks_like_ip(value: str) -> bool:
    parts = value.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(part) <= 255 for part in parts)
    except ValueError:
        return False
