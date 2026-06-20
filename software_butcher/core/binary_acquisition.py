"""Download remote binaries into the assessment workspace."""

from __future__ import annotations

from pathlib import Path
from urllib.parse import unquote, urlsplit

import requests


class BinaryAcquisition:
    """Fetch executable assets referenced by HTTP(S) URLs."""

    def __init__(self, timeout: int = 60) -> None:
        self.timeout = timeout
        self.session = requests.Session()

    def download(self, url: str, workspace_root: str | Path) -> Path | None:
        """Download *url* to workspace/binaries/ and return the local path."""
        parsed = urlsplit(url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            return None

        filename = unquote(parsed.path.rsplit("/", 1)[-1]) or "download.bin"
        if "." not in filename:
            filename = f"{filename}.bin"

        dest_dir = Path(workspace_root) / "binaries"
        dest_dir.mkdir(parents=True, exist_ok=True)
        dest = dest_dir / filename

        if dest.exists() and dest.stat().st_size > 0:
            return dest

        try:
            response = self.session.get(url, timeout=self.timeout, stream=True)
            response.raise_for_status()
            dest.write_bytes(response.content)
            if dest.stat().st_size == 0:
                dest.unlink(missing_ok=True)
                return None
            return dest
        except requests.RequestException:
            return None
