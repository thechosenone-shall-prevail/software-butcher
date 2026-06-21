"""Headless browser navigation — capture JS/meta redirects and redirect-hop bodies via CDP."""

from __future__ import annotations

import base64
import json
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urljoin, urlsplit

from software_butcher.core.url_utils import same_origin

REDIRECT_CODES = frozenset({301, 302, 303, 307, 308})


@dataclass
class BrowserNavResult:
    success: bool
    requested_url: str
    final_url: str
    title: str
    redirect_chain: list[str] = field(default_factory=list)
    redirect_hops: list[dict[str, Any]] = field(default_factory=list)
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
            "redirect_hops": [
                {
                    "url": h.get("url"),
                    "status": h.get("status"),
                    "location": h.get("location"),
                    "body_len": h.get("body_len"),
                    "profile": h.get("profile"),
                }
                for h in self.redirect_hops
            ],
            "discovered_urls": self.discovered_urls,
            "error": self.error,
            "engine": self.engine,
        }


def _extract_same_origin_links(base: str, html: str) -> list[str]:
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


def _capture_redirect_hops_cdp(driver) -> list[dict[str, Any]]:
    """Extract 3xx hop bodies from Chrome DevTools performance log."""
    responses: dict[str, dict[str, Any]] = {}
    finished: list[str] = []

    try:
        for entry in driver.get_log("performance"):
            try:
                msg = json.loads(entry["message"])["message"]
            except (KeyError, json.JSONDecodeError, TypeError):
                continue
            method = msg.get("method")
            params = msg.get("params") or {}
            if method == "Network.responseReceived":
                rid = params.get("requestId")
                resp = params.get("response") or {}
                headers = resp.get("headers") or {}
                responses[rid] = {
                    "url": resp.get("url", ""),
                    "status": resp.get("status"),
                    "location": headers.get("Location") or headers.get("location"),
                }
            elif method == "Network.loadingFinished":
                rid = params.get("requestId")
                if rid:
                    finished.append(rid)
    except Exception:  # noqa: BLE001
        return []

    hops: list[dict[str, Any]] = []
    for rid in finished:
        meta = responses.get(rid)
        if not meta or meta.get("status") not in REDIRECT_CODES:
            continue
        body = ""
        try:
            br = driver.execute_cdp_cmd("Network.getResponseBody", {"requestId": rid})
            raw = br.get("body") or ""
            if br.get("base64Encoded"):
                body = base64.b64decode(raw).decode("utf-8", errors="replace")
            else:
                body = raw
        except Exception:  # noqa: BLE001
            body = ""
        hops.append(
            {
                "url": meta.get("url"),
                "status": meta.get("status"),
                "location": meta.get("location"),
                "body": body,
                "body_len": len(body),
                "profile": "browser-cdp",
            }
        )
    return hops


def _capture_redirect_hops_transport(url: str) -> list[dict[str, Any]]:
    """Fallback: HTTP client redirect chain with per-hop bodies (browser UA)."""
    from software_butcher.shelves.web.http_transport import SmartHttpTransport

    transport = SmartHttpTransport()
    resp = transport.follow_redirects(url, "GET", profile="browser")
    hops: list[dict[str, Any]] = []
    for hop in resp.redirect_chain or []:
        if hop.get("status") in REDIRECT_CODES:
            hops.append({**hop, "profile": "browser-transport"})
    return hops


def browser_navigate(url: str, *, timeout_s: int = 20, enabled: bool = True) -> BrowserNavResult:
    """Navigate with headless Chrome; capture redirect-hop bodies when CDP is available."""
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
        hops = _capture_redirect_hops_transport(url)
        return BrowserNavResult(
            success=False,
            requested_url=url,
            final_url=url,
            title="",
            redirect_hops=hops,
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
    options.set_capability("goog:loggingPrefs", {"performance": "ALL"})

    driver = None
    try:
        service = Service(ChromeDriverManager().install())
        driver = webdriver.Chrome(service=service, options=options)
        driver.set_page_load_timeout(timeout_s)
        driver.execute_cdp_cmd("Network.enable", {})

        chain: list[str] = [url]
        driver.get(url)
        WebDriverWait(driver, timeout_s).until(lambda d: d.execute_script("return document.readyState") == "complete")

        final = driver.current_url.rstrip("/")
        if final not in chain:
            chain.append(final)

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
        redirect_hops = _capture_redirect_hops_cdp(driver)
        if not redirect_hops:
            redirect_hops = _capture_redirect_hops_transport(url)

        return BrowserNavResult(
            success=True,
            requested_url=url,
            final_url=chain[-1],
            title=title,
            redirect_chain=chain,
            redirect_hops=redirect_hops,
            discovered_urls=discovered,
            engine="selenium-chrome",
        )
    except Exception as exc:  # noqa: BLE001
        hops = _capture_redirect_hops_transport(url)
        return BrowserNavResult(
            success=False,
            requested_url=url,
            final_url=url,
            title="",
            redirect_hops=hops,
            error=str(exc),
            engine="selenium-chrome",
        )
    finally:
        if driver is not None:
            try:
                driver.quit()
            except Exception:  # noqa: BLE001
                pass
