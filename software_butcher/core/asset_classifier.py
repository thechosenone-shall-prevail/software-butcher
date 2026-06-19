"""URL and path asset-type classification.

Central source of truth for distinguishing static assets (CSS, JS, images,
fonts, archives) from interactive web endpoints.  Used by:

  - HexStrikeInterpreter  — assigns asset_type to discovered URLs/paths
  - HexstrikeAdapter      — classifies links from HTML crawl
  - PlaywrightCurlAdapter — guards auth-probe generation
  - HypothesisGenerator   — skips signal checks on static assets
  - BrainPolicy           — never escalates static assets to playwright

Rule rationale
--------------
We classify by file-extension only because that's all we have at discovery
time (before any HTTP request is sent).  This is a conservative first pass —
a path with no extension is assumed interactive, not static.
"""

from __future__ import annotations

from urllib.parse import urlsplit

# Extensions that definitively identify non-interactive, static resources.
# These paths will NEVER receive auth-bypass probes.
STATIC_EXTENSIONS: frozenset[str] = frozenset(
    {
        # Stylesheets & scripts
        ".css", ".scss", ".less", ".js", ".mjs", ".cjs", ".ts", ".map",
        # Images
        ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp",
        ".bmp", ".tiff", ".tif", ".avif", ".heic",
        # Fonts
        ".woff", ".woff2", ".ttf", ".eot", ".otf",
        # Documents & archives
        ".pdf", ".zip", ".tar", ".gz", ".bz2", ".rar", ".7z",
        # Video / audio
        ".mp4", ".webm", ".ogg", ".mp3", ".wav", ".flac",
        # Compiled / binary
        ".swf", ".class",
    }
)


def _path_from_url(url: str) -> str:
    """Return the path component of a URL or a raw path string."""
    parsed = urlsplit(url)
    return parsed.path if (parsed.scheme or parsed.netloc) else url


def file_extension(url: str) -> str:
    """Return the lowercase file extension of a URL path (e.g. '.css'), or ''."""
    path = _path_from_url(url).lower().rstrip("/")
    filename = path.split("/")[-1] if "/" in path else path
    if "." in filename:
        return "." + filename.rsplit(".", 1)[-1]
    return ""


def is_static_asset(url: str) -> bool:
    """Return True if the URL almost certainly refers to a static, non-interactive asset.

    Examples that return True:
        /login.css, /img/login_logo.png, http://host/js/app.min.js

    Examples that return False (treated as interactive):
        /login.php, /api/v1/auth, /admin, /setup, /dvwa/
    """
    return file_extension(url) in STATIC_EXTENSIONS


def classify_url_asset_type(url: str, default_interactive: str = "web_endpoint") -> str:
    """Return 'static_asset' or *default_interactive* based on URL extension.

    Args:
        url: A full URL or a path string.
        default_interactive: Asset type to use when the path is interactive.
            Usually 'web_endpoint' or 'api'.
    """
    return "static_asset" if is_static_asset(url) else default_interactive
