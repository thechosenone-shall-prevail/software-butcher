"""Headless browser navigation — capture JS/meta redirects browsers see but curl misses."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urljoin, urlsplit

from software_butcher.core.url_utils import same_origin


@dataclass
class BrowserNavResult:
    success: bool
    requested_url: str
    final_url: str
    title: str
    redirect_chain: list[str] = field(default_factory=list)
    discovered_urls: list[str] = field(default_factory=list)
    error: str | None = None
    engine: str = "none"

    def to_dict(self) -> dict[str, Any]:
        return {
            "success": self.success,
            "requested_url": self.requested_url,
            "final_url": self.final_url,
            "title": self.title,
            "redirect_chain": self.redirect_chain,
            "discovered_urls": self.discovered_urls,
            "error": self.error,
            "engine": self.engine,
        }


def _extract_same_origin_links(base: str, html: str) -> list[str]:
    import re

    links: list[str] = []
    seen: set[str] = set()
    origin = f"{urlsplit(base).scheme}://{urlsplit(base).netloc}"
    for match in re.finditer(r"""(?:href|src|action)\s*=\s*["']([^"'#]+)["']""", html or "", re.I):
        href = match.group(1).strip()
        if href.startswith(("javascript:", "mailto:", "data:")):
            continue
        if href.startswith("/"):
            absolute = origin + href.rstrip("/")
        elif href.startswith(("http://", "https://")):
            absolute = href.rstrip("/")
        else:
            absolute = urljoin(base, href).rstrip("/")
        if same_origin(absolute, base) and absolute not in seen:
            seen.add(absolute)
            links.append(absolute)
    return links


def browser_navigate(url: str, *, timeout_s: int = 20, enabled: bool = True) -> BrowserNavResult:
    """Navigate with headless Chrome via Selenium; graceful fallback when unavailable."""
    if not enabled:
        return BrowserNavResult(
            success=False,
            requested_url=url,
            final_url=url,
            title="",
            error="browser navigation disabled",
        )

    try:
        from selenium import webdriver
        from selenium.webdriver.chrome.options import Options
        from selenium.webdriver.chrome.service import Service
        from selenium.webdriver.support.ui import WebDriverWait
        from webdriver_manager.chrome import ChromeDriverManager
    except ImportError:
        return BrowserNavResult(
            success=False,
            requested_url=url,
            final_url=url,
            title="",
            error="selenium/webdriver-manager not installed",
        )

    options = Options()
    options.add_argument("--headless=new")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument("--disable-gpu")
    options.add_argument("--window-size=1280,800")
    options.add_argument(
        "--user-agent=Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
    )

    driver = None
    try:
        service = Service(ChromeDriverManager().install())
        driver = webdriver.Chrome(service=service, options=options)
        driver.set_page_load_timeout(timeout_s)

        chain: list[str] = [url]
        driver.get(url)
        WebDriverWait(driver, timeout_s).until(lambda d: d.execute_script("return document.readyState") == "complete")

        final = driver.current_url.rstrip("/")
        if final not in chain:
            chain.append(final)

        # Detect late JS redirects (common SPA / window.location patterns)
        for _ in range(3):
            driver.implicitly_wait(1)
            new_url = driver.current_url.rstrip("/")
            if new_url != chain[-1]:
                chain.append(new_url)
            else:
                break

        html = driver.page_source or ""
        title = driver.title or ""
        discovered = _extract_same_origin_links(final, html)

        return BrowserNavResult(
            success=True,
            requested_url=url,
            final_url=chain[-1],
            title=title,
            redirect_chain=chain,
            discovered_urls=discovered,
            engine="selenium-chrome",
        )
    except Exception as exc:  # noqa: BLE001
        return BrowserNavResult(
            success=False,
            requested_url=url,
            final_url=url,
            title="",
            error=str(exc),
            engine="selenium-chrome",
        )
    finally:
        if driver is not None:
            try:
                driver.quit()
            except Exception:  # noqa: BLE001
                pass
