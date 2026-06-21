"""Smart HTTP transport — cookies, profiles, backoff, proxy/VPN rotation."""

from __future__ import annotations

import http.cookiejar
import random
import ssl
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Callable

from software_butcher.shelves.web.infrastructure_intel import RateLimitSignal, detect_rate_limit

REDIRECT_CODES = frozenset({301, 302, 303, 307, 308})

BROWSER_USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
)
ASSESSMENT_USER_AGENT = "SoftwareButcher/1.0 (security-assessment)"

_SSL_CTX = ssl.create_default_context()
_SSL_CTX.check_hostname = True
_SSL_CTX.verify_mode = ssl.CERT_REQUIRED


@dataclass
class TransportConfig:
    proxies: list[str] = field(default_factory=list)
    vpn_rotate_commands: list[str] = field(default_factory=list)
    max_retries: int = 3
    base_backoff_s: float = 2.0
    profiles: tuple[str, ...] = ("browser", "assessment")

    @classmethod
    def from_scope(cls, scope: dict[str, Any] | None) -> "TransportConfig":
        if not scope:
            return cls()
        meta = scope.get("metadata") or {}
        egress = meta.get("egress") or {}
        if isinstance(egress, dict):
            return cls(
                proxies=list(egress.get("proxies") or []),
                vpn_rotate_commands=list(egress.get("vpn_rotate_commands") or []),
                max_retries=int(egress.get("max_retries") or 3),
            )
        return cls(
            proxies=list(meta.get("proxies") or []),
            vpn_rotate_commands=list(meta.get("vpn_rotate_commands") or []),
        )


@dataclass
class HttpResponse:
    success: bool
    status_code: int | None
    url: str
    final_url: str
    headers: dict[str, str]
    body: str
    elapsed_s: float
    error: str | None
    profile: str
    proxy: str | None
    rate_limit: RateLimitSignal | None = None
    redirect_chain: list[dict[str, Any]] = field(default_factory=list)


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ARG002
        return None


def _build_opener(proxy: str | None, cookie_jar: http.cookiejar.CookieJar | None = None) -> urllib.request.OpenerDirector:
    handlers: list[Any] = [_NoRedirectHandler(), urllib.request.HTTPSHandler(context=_SSL_CTX)]
    if cookie_jar is not None:
        handlers.append(urllib.request.HTTPCookieProcessor(cookie_jar))
    if proxy:
        handlers.insert(0, urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
    return urllib.request.build_opener(*handlers)


def _user_agent(profile: str) -> str:
    return BROWSER_USER_AGENT if profile == "browser" else ASSESSMENT_USER_AGENT


class SmartHttpTransport:
    """Cookie-aware HTTP client with rate-limit retry and egress rotation hooks."""

    def __init__(
        self,
        config: TransportConfig | None = None,
        *,
        on_rate_limit: Callable[[str, RateLimitSignal], None] | None = None,
        on_rotate: Callable[[str], None] | None = None,
        proxy_index: int = 0,
    ) -> None:
        self.config = config or TransportConfig()
        self.on_rate_limit = on_rate_limit
        self.on_rotate = on_rotate
        self.proxy_index = proxy_index
        self._cookie_jar = http.cookiejar.CookieJar()
        self._host_backoff_until: dict[str, float] = {}

    @property
    def current_proxy(self) -> str | None:
        if not self.config.proxies:
            return None
        return self.config.proxies[self.proxy_index % len(self.config.proxies)]

    def wait_if_needed(self, host: str) -> float:
        until = self._host_backoff_until.get(host.lower(), 0.0)
        now = time.monotonic()
        if until > now:
            delay = until - now
            time.sleep(delay)
            return delay
        return 0.0

    def rotate_egress(self, host: str) -> str | None:
        """Rotate proxy index and/or run configured VPN shell commands."""
        if self.config.proxies:
            self.proxy_index = (self.proxy_index + 1) % len(self.config.proxies)
        for command in self.config.vpn_rotate_commands:
            try:
                subprocess.run(
                    command,
                    shell=True,
                    check=False,
                    capture_output=True,
                    timeout=120,
                )
            except (OSError, subprocess.TimeoutExpired):
                continue
        if self.on_rotate:
            self.on_rotate(host)
        return self.current_proxy

    def _single_request(
        self,
        url: str,
        method: str,
        profile: str,
        *,
        timeout: int,
        max_body: int,
    ) -> HttpResponse:
        proxy = self.current_proxy
        opener = _build_opener(proxy, self._cookie_jar)
        urllib.request.install_opener(opener)

        req = urllib.request.Request(url, method=method)
        req.add_header("User-Agent", _user_agent(profile))
        req.add_header("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
        req.add_header("Accept-Language", "en-US,en;q=0.9")

        t0 = time.monotonic()
        try:
            with opener.open(req, timeout=timeout) as resp:
                body = resp.read(max_body)
                headers = {k: v for k, v in resp.headers.items()}
                elapsed = round(time.monotonic() - t0, 3)
                text = body.decode("utf-8", errors="replace")
                rl = detect_rate_limit(status_code=resp.status, headers=headers, body=text, elapsed_s=elapsed)
                return HttpResponse(
                    success=True,
                    status_code=resp.status,
                    url=url,
                    final_url=resp.url,
                    headers=headers,
                    body=text,
                    elapsed_s=elapsed,
                    error=None,
                    profile=profile,
                    proxy=proxy,
                    rate_limit=rl,
                )
        except urllib.error.HTTPError as exc:
            body = b""
            try:
                body = exc.read(max_body)
            except Exception:  # noqa: BLE001
                pass
            headers = {k: v for k, v in exc.headers.items()} if exc.headers else {}
            elapsed = round(time.monotonic() - t0, 3)
            text = body.decode("utf-8", errors="replace")
            rl = detect_rate_limit(status_code=exc.code, headers=headers, body=text, elapsed_s=elapsed)
            return HttpResponse(
                success=False,
                status_code=exc.code,
                url=url,
                final_url=url,
                headers=headers,
                body=text,
                elapsed_s=elapsed,
                error=f"HTTP {exc.code}: {exc.reason}",
                profile=profile,
                proxy=proxy,
                rate_limit=rl,
            )
        except Exception as exc:  # noqa: BLE001
            elapsed = round(time.monotonic() - t0, 3)
            return HttpResponse(
                success=False,
                status_code=None,
                url=url,
                final_url=url,
                headers={},
                body="",
                elapsed_s=elapsed,
                error=str(exc),
                profile=profile,
                proxy=proxy,
            )

    def follow_redirects(
        self,
        url: str,
        method: str = "GET",
        *,
        profile: str = "browser",
        timeout: int = 12,
        max_body: int = 65536,
        max_hops: int = 10,
        host: str = "",
    ) -> HttpResponse:
        """Follow redirects manually, storing cookies between hops."""
        host_key = (host or urllib.parse.urlsplit(url).netloc).lower()
        self.wait_if_needed(host_key)

        chain: list[dict[str, Any]] = []
        current = url.strip()
        if not current.endswith("/") and urllib.parse.urlsplit(current).path in ("", "/"):
            current = current.rstrip("/") + "/"

        last: HttpResponse | None = None
        for attempt in range(self.config.max_retries + 1):
            hops = 0
            current = url.strip()
            chain = []
            while hops <= max_hops:
                last = self._single_request(current, method, profile, timeout=timeout, max_body=max_body)
                chain.append(
                    {
                        "method": method,
                        "profile": profile,
                        "url": current,
                        "status": last.status_code,
                        "location": last.headers.get("Location"),
                        "proxy": last.proxy,
                    }
                )
                if last.rate_limit and last.rate_limit.detected:
                    if self.on_rate_limit:
                        self.on_rate_limit(host_key, last.rate_limit)
                    action = last.rate_limit.recommended_action
                    wait_s = last.rate_limit.retry_after_s or self.config.base_backoff_s
                    self._host_backoff_until[host_key] = time.monotonic() + wait_s
                    if action == "rotate_egress" and attempt < self.config.max_retries:
                        self.rotate_egress(host_key)
                        break
                    if attempt < self.config.max_retries:
                        jitter = random.uniform(0.5, 1.5)
                        time.sleep(wait_s * jitter)
                        break
                if last.status_code not in REDIRECT_CODES:
                    break
                location = last.headers.get("Location")
                if not location:
                    break
                current = urllib.parse.urljoin(current, location)
                hops += 1
            else:
                break
            if last and (not last.rate_limit or not last.rate_limit.detected or attempt >= self.config.max_retries):
                break

        assert last is not None
        last.redirect_chain = chain
        return last

    def probe_cache_behavior(self, url: str, *, prior_etag: str = "", prior_headers: dict[str, str] | None = None) -> dict[str, Any]:
        """Issue a conditional GET to detect caching semantics."""
        headers = dict(prior_headers or {})
        if prior_etag:
            headers["If-None-Match"] = prior_etag
        elif headers.get("ETag"):
            headers["If-None-Match"] = headers["ETag"]

        proxy = self.current_proxy
        opener = _build_opener(proxy, self._cookie_jar)
        req = urllib.request.Request(url, method="GET")
        req.add_header("User-Agent", BROWSER_USER_AGENT)
        for key, value in headers.items():
            if key.lower().startswith("if-"):
                req.add_header(key, value)

        try:
            with opener.open(req, timeout=10) as resp:
                return {
                    "status_code": resp.status,
                    "cache_hit": resp.status == 304,
                    "headers": {k: v for k, v in resp.headers.items()},
                }
        except urllib.error.HTTPError as exc:
            return {
                "status_code": exc.code,
                "cache_hit": exc.code == 304,
                "headers": {k: v for k, v in exc.headers.items()} if exc.headers else {},
            }
        except Exception as exc:  # noqa: BLE001
            return {"status_code": None, "cache_hit": False, "error": str(exc)}
