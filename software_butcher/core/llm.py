"""OpenRouter client factory and connectivity diagnostics."""

from __future__ import annotations

import os
import socket
from typing import Any
from urllib.parse import urlparse

DEFAULT_OPENROUTER_BASE = "https://openrouter.ai/api/v1"
DEFAULT_OPENROUTER_MODEL = "gpt-oss-120b"
DEFAULT_TIMEOUT = 30.0
DEFAULT_CONNECT_TIMEOUT = 5.0


def _masked_key(api_key: str) -> str:
    if len(api_key) <= 8:
        return "***"
    return f"{api_key[:6]}...{api_key[-4:]}"


def openrouter_config() -> dict[str, str]:
    """Return effective OpenRouter settings from the environment."""
    return {
        "api_key_set": bool(os.environ.get("OPENROUTER_API_KEY")),
        "api_key_preview": _masked_key(os.environ.get("OPENROUTER_API_KEY", "")),
        "base_url": os.environ.get("OPENROUTER_BASE_URL", DEFAULT_OPENROUTER_BASE),
        "model": os.environ.get("LLM_MODEL") or os.environ.get("OPENROUTER_MODEL") or DEFAULT_OPENROUTER_MODEL,
        "timeout_s": os.environ.get("OPENROUTER_TIMEOUT", str(int(DEFAULT_TIMEOUT))),
    }


def create_openrouter_client() -> Any | None:
    """Return an OpenAI-compatible OpenRouter client, or None if unavailable."""
    try:
        import openai
    except ImportError:
        return None

    api_key = os.environ.get("OPENROUTER_API_KEY")
    if not api_key:
        return None

    base = os.environ.get("OPENROUTER_BASE_URL", DEFAULT_OPENROUTER_BASE)
    timeout = float(os.environ.get("OPENROUTER_TIMEOUT", DEFAULT_TIMEOUT))
    return openai.OpenAI(api_key=api_key, base_url=base, timeout=timeout)


def diagnose_openrouter(*, probe_chat: bool = True) -> dict[str, Any]:
    """Run layered checks for OpenRouter setup and network reachability."""
    import requests

    cfg = openrouter_config()
    report: dict[str, Any] = {
        "config": cfg,
        "checks": [],
        "ok": False,
        "summary": "",
    }

    def add(name: str, ok: bool, detail: str) -> None:
        report["checks"].append({"name": name, "ok": ok, "detail": detail})

    try:
        import openai  # noqa: F401
        add("openai_package", True, "openai SDK installed")
    except ImportError:
        add("openai_package", False, "Install with: pip install openai")
        report["summary"] = "Missing openai package"
        return report

    if not cfg["api_key_set"]:
        add("api_key", False, "OPENROUTER_API_KEY is not set (add to .env in repo root)")
        report["summary"] = "OPENROUTER_API_KEY missing"
        return report
    add("api_key", True, f"OPENROUTER_API_KEY present ({cfg['api_key_preview']})")

    parsed = urlparse(cfg["base_url"])
    host = parsed.hostname or "openrouter.ai"
    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        add("dns", True, f"Resolved {host} -> {infos[0][4][0]}")
    except OSError as exc:
        add("dns", False, f"Cannot resolve {host}: {exc}")
        report["summary"] = f"DNS failure for {host} — check /etc/resolv.conf, VPN, or proxy"
        return report

    models_url = cfg["base_url"].rstrip("/") + "/models"
    connect_timeout = float(os.environ.get("OPENROUTER_CONNECT_TIMEOUT", DEFAULT_CONNECT_TIMEOUT))
    read_timeout = float(os.environ.get("OPENROUTER_TIMEOUT", DEFAULT_TIMEOUT))
    headers = {"Authorization": f"Bearer {os.environ['OPENROUTER_API_KEY']}"}

    try:
        response = requests.get(
            models_url,
            headers=headers,
            timeout=(connect_timeout, read_timeout),
        )
        if response.status_code == 401:
            add("auth", False, "HTTP 401 — invalid or expired OPENROUTER_API_KEY")
            report["summary"] = "OpenRouter rejected the API key"
            return report
        if response.status_code >= 400:
            add("http", False, f"GET {models_url} -> HTTP {response.status_code}: {response.text[:200]}")
            report["summary"] = f"OpenRouter HTTP {response.status_code}"
            return report
        add("http", True, f"GET /models -> HTTP {response.status_code}")
    except requests.RequestException as exc:
        add("http", False, f"Cannot reach OpenRouter API: {exc}")
        report["summary"] = "Network blocked or proxy required — test: curl -I https://openrouter.ai"
        return report

    if not probe_chat:
        report["ok"] = True
        report["summary"] = "OpenRouter reachable; chat probe skipped"
        return report

    client = create_openrouter_client()
    if client is None:
        add("chat", False, "Client factory returned None despite key being set")
        report["summary"] = "Client creation failed"
        return report

    try:
        response = client.chat.completions.create(
            model=cfg["model"],
            messages=[
                {"role": "system", "content": "Reply with JSON only."},
                {"role": "user", "content": '{"status":"ok"}'},
            ],
            response_format={"type": "json_object"},
            max_tokens=32,
        )
        content = (response.choices[0].message.content or "").strip()
        add("chat", True, f"Model {cfg['model']} replied: {content[:120]}")
        report["ok"] = True
        report["summary"] = "OpenRouter LLM is working"
    except Exception as exc:
        add("chat", False, f"Chat probe failed for model {cfg['model']}: {exc}")
        report["summary"] = (
            f"API reachable but model {cfg['model']} failed — try LLM_MODEL=openai/gpt-4o-mini "
            "or another model on your OpenRouter account"
        )
    return report


def format_diagnosis(report: dict[str, Any]) -> str:
    lines = [
        "OpenRouter LLM diagnostics",
        f"Summary: {report.get('summary', 'unknown')}",
        "",
    ]
    cfg = report.get("config", {})
    lines.append(f"  base_url: {cfg.get('base_url')}")
    lines.append(f"  model:    {cfg.get('model')}")
    lines.append(f"  timeout:  {cfg.get('timeout_s')}s")
    lines.append("")
    for check in report.get("checks", []):
        marker = "OK" if check["ok"] else "FAIL"
        lines.append(f"  [{marker}] {check['name']}: {check['detail']}")
    return "\n".join(lines)
