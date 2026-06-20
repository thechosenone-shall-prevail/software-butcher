"""Map detected product/version strings to upstream source repositories."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable

VERSIONED_TECH_PATTERN = re.compile(
    r"(?P<name>[a-zA-Z][a-zA-Z0-9+\-\.]*)"
    r"(?:[/\s]+)?"
    r"(?P<version>\d+(?:\.\d+)*)",
    re.IGNORECASE,
)

UPSTREAM_SOURCES: dict[str, dict[str, str]] = {
    "php": {
        "repo": "https://github.com/php/php-src",
        "branch_prefix": "PHP-",
    },
    "apache": {
        "repo": "https://github.com/apache/httpd",
        "branch_prefix": "",
    },
    "httpd": {
        "repo": "https://github.com/apache/httpd",
        "branch_prefix": "",
    },
    "nginx": {
        "repo": "https://github.com/nginx/nginx",
        "branch_prefix": "release-",
    },
    "openssl": {
        "repo": "https://github.com/openssl/openssl",
        "branch_prefix": "OpenSSL_",
    },
    "tomcat": {
        "repo": "https://github.com/apache/tomcat",
        "branch_prefix": "",
    },
    "wordpress": {
        "repo": "https://github.com/WordPress/WordPress",
        "branch_prefix": "",
    },
}

# Major versions considered end-of-life for escalation heuristics.
EOL_MAJOR_VERSIONS: dict[str, tuple[int, ...]] = {
    "php": (5, 7),
    "apache": (2,),  # combined with minor check below
    "httpd": (2,),
    "nginx": (0, 1),
    "openssl": (1,),
}


@dataclass(frozen=True)
class SourceReference:
    technology: str
    product: str
    version: str
    repo_url: str
    branch: str | None
    local_dir_name: str
    is_eol: bool


def parse_versioned_technology(text: str) -> tuple[str, str] | None:
    """Parse strings like 'PHP 7.2.0' or 'Apache/2.4.49'."""
    cleaned = text.strip()
    match = VERSIONED_TECH_PATTERN.search(cleaned.replace("/", " "))
    if not match:
        return None
    name = match.group("name").lower()
    version = match.group("version")
    return name, version


def _major_minor(version: str) -> tuple[int, int]:
    parts = version.split(".")
    major = int(parts[0]) if parts else 0
    minor = int(parts[1]) if len(parts) > 1 else 0
    return major, minor


def is_eol_product(product: str, version: str) -> bool:
    product = product.lower()
    major, minor = _major_minor(version)

    if product == "php":
        return major in EOL_MAJOR_VERSIONS["php"]

    if product in {"apache", "httpd"}:
        # Apache 2.4.x below 2.4.50 historically had many issues; treat 2.2 as EOL.
        return major < 2 or (major == 2 and minor < 4)

    if product == "nginx":
        return major < 1 or (major == 1 and minor < 18)

    if product == "openssl":
        return major < 3

    eol_majors = EOL_MAJOR_VERSIONS.get(product, ())
    return major in eol_majors


def resolve_upstream_source(technology: str) -> SourceReference | None:
    """Resolve a technology string to a known upstream GitHub repository."""
    parsed = parse_versioned_technology(technology)
    if not parsed:
        return None

    product, version = parsed
    config = UPSTREAM_SOURCES.get(product)
    if not config:
        return None

    major, minor = _major_minor(version)
    branch: str | None = None
    branch_prefix = config.get("branch_prefix", "")
    if branch_prefix == "PHP-":
        branch = f"PHP-{major}.{minor}"
    elif branch_prefix:
        branch = f"{branch_prefix}{version.replace('.', '_')}"

    local_dir_name = f"{product}-{version.replace('.', '-')}"
    return SourceReference(
        technology=technology,
        product=product,
        version=version,
        repo_url=config["repo"],
        branch=branch,
        local_dir_name=local_dir_name,
        is_eol=is_eol_product(product, version),
    )


def collect_technologies(finding_text: str, metadata: dict | None) -> list[str]:
    """Gather technology strings from finding metadata and evidence."""
    found: list[str] = []
    metadata = metadata or {}

    if metadata.get("technology"):
        found.append(str(metadata["technology"]))

    for tech in metadata.get("technologies", []):
        found.append(str(tech))

    for item in metadata.get("target_profile", {}).get("technologies", []):
        found.append(str(item))

    for line in finding_text.splitlines():
        parsed = parse_versioned_technology(line)
        if parsed:
            name, version = parsed
            found.append(f"{name} {version}")

    # Dedupe preserving order
    seen: set[str] = set()
    ordered: list[str] = []
    for tech in found:
        key = tech.lower()
        if key not in seen:
            seen.add(key)
            ordered.append(tech)
    return ordered


def pick_escalation_candidate(technologies: Iterable[str]) -> SourceReference | None:
    """Prefer EOL products, then first resolvable upstream source."""
    resolved = [ref for tech in technologies if (ref := resolve_upstream_source(tech))]
    if not resolved:
        return None
    for ref in resolved:
        if ref.is_eol:
            return ref
    return resolved[0]
