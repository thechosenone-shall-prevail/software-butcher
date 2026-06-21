"""Infer where the web application lives from crawl evidence — no fixed paths."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable
from urllib.parse import urlsplit

from software_butcher.core.meta_utils import as_dict, as_dict_list
from software_butcher.core.path_relevance import detect_default_stack_landing, is_noise_path
from software_butcher.core.url_utils import engagement_entry_url, host_key
from software_butcher.state.schema import Finding, Hypothesis

INFRA_PAGE_TYPES = frozenset({"phpinfo", "phpmyadmin"})


@dataclass(frozen=True)
class ApplicationRoot:
    url: str
    confidence: float
    rationale: str
    evidence_urls: tuple[str, ...]

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "confidence": self.confidence,
            "rationale": self.rationale,
            "evidence_urls": list(self.evidence_urls),
        }


def _normalize(url: str) -> str:
    return (url or "").rstrip("/").lower()


def _directory_root(url: str) -> str | None:
    """Scheme://host/first-segment — smallest directory prefix for an app URL."""
    parsed = urlsplit(url.strip())
    if not parsed.scheme or not parsed.netloc:
        return None
    parts = [p for p in (parsed.path or "").split("/") if p]
    if not parts:
        return f"{parsed.scheme}://{parsed.netloc}".rstrip("/")
    return f"{parsed.scheme}://{parsed.netloc}/{'/'.join(parts[:1])}".rstrip("/")


def _collect_app_signals(findings: Iterable[Finding]) -> dict[str, dict[str, float | int | set[str]]]:
    """Score each first-segment directory prefix from observed crawl evidence."""
    scores: dict[str, dict[str, float | int | set[str]]] = {}

    def bump(prefix: str, *, forms: int = 0, pages: int = 0, expanded: int = 0, entry: int = 0) -> None:
        if not prefix:
            return
        bucket = scores.setdefault(
            prefix,
            {"forms": 0, "pages": 0, "expanded": 0, "entry": 0, "urls": set()},
        )
        bucket["forms"] = int(bucket["forms"]) + forms
        bucket["pages"] = int(bucket["pages"]) + pages
        bucket["expanded"] = int(bucket["expanded"]) + expanded
        bucket["entry"] = int(bucket["entry"]) + entry
        bucket["urls"].add(prefix)

    for finding in findings:
        meta = finding.metadata or {}
        stack = as_dict(meta.get("stack_landing"))
        if stack.get("detected") and _normalize(finding.path) == _directory_root(finding.path):
            continue

        for page in meta.get("content_pages") or []:
            url = str(page.get("url") or "")
            prefix = _directory_root(url)
            if not prefix or is_noise_path(url):
                continue
            forms = int(page.get("form_count") or 0)
            bump(prefix, forms=1 if forms else 0, pages=1)
            if forms and prefix in scores:
                urls = scores[prefix].get("urls")
                if isinstance(urls, set):
                    urls.add(url)

        app_expand = meta.get("app_expand") or {}
        for url in app_expand.get("expanded_urls") or []:
            prefix = _directory_root(str(url))
            if prefix:
                bump(prefix, expanded=1, pages=1)

        for probe in meta.get("semantic_probes") or []:
            if not probe.get("reachable"):
                continue
            url = str(probe.get("url") or "")
            prefix = _directory_root(url)
            content = probe.get("content_analysis") or {}
            forms = int(content.get("form_count") or 0)
            if prefix:
                bump(prefix, forms=1 if forms else 0, pages=1)

        if meta.get("content_analysis"):
            url = finding.path
            prefix = _directory_root(url)
            forms = int(meta.get("form_count") or 0)
            if prefix and not stack.get("detected"):
                bump(prefix, forms=1 if forms else 0, pages=1)

    return scores


def infer_application_root(
    findings: Iterable[Finding],
    base_target: str = "",
) -> ApplicationRoot | None:
    """Pick the directory prefix with the strongest application signals."""
    findings_list = list(findings)
    if not findings_list:
        return None

    entry = engagement_entry_url(base_target).rstrip("/") if base_target else ""
    entry_prefix = _directory_root(entry) if entry else None
    scores = _collect_app_signals(findings_list)

    if entry_prefix:
        parsed_entry = urlsplit(entry)
        if (parsed_entry.path or "").strip("/"):
            bucket = scores.setdefault(
                entry_prefix,
                {"forms": 0, "pages": 0, "expanded": 0, "entry": 0, "urls": set()},
            )
            bucket["entry"] = int(bucket["entry"]) + 3
            for finding in findings_list:
                if _normalize(finding.path) == _normalize(entry) or _normalize(
                    str((finding.metadata or {}).get("mapped_target") or "")
                ) == _normalize(entry):
                    meta = finding.metadata or {}
                    if meta.get("content_analysis") or meta.get("content_pages"):
                        bucket["pages"] = int(bucket["pages"]) + 2
                    if int(meta.get("form_count") or 0) > 0:
                        bucket["forms"] = int(bucket["forms"]) + 2

    if not scores:
        return None

    ranked: list[tuple[str, float, str, tuple[str, ...]]] = []
    for prefix, bucket in scores.items():
        forms = int(bucket["forms"])
        pages = int(bucket["pages"])
        expanded = int(bucket["expanded"])
        entry_hit = int(bucket["entry"])
        urls = bucket.get("urls") or set()
        evidence = tuple(sorted(str(u) for u in urls if isinstance(u, str)))[:12]

        if pages < 1 and entry_hit < 1:
            continue

        raw = forms * 3.0 + pages * 1.5 + expanded * 2.0 + entry_hit * 4.0
        if entry_prefix and _normalize(prefix) == _normalize(entry_prefix):
            raw += 2.0

        if raw < 3.0:
            continue

        confidence = min(0.95, 0.35 + raw / 20.0)
        rationale = (
            f"Inferred application directory from crawl evidence: "
            f"{pages} mapped page(s), {forms} with forms, {expanded} organic expansion(s)"
            + (", matches scoped entry target" if entry_hit else "")
        )
        ranked.append((prefix, confidence, rationale, evidence))

    if not ranked:
        return None

    ranked.sort(key=lambda item: (-item[1], -len(item[3])))
    prefix, confidence, rationale, evidence = ranked[0]
    return ApplicationRoot(url=prefix, confidence=confidence, rationale=rationale, evidence_urls=evidence)


def infer_application_root_from_surface_map(
    surface_metadata: dict,
    base_target: str = "",
) -> ApplicationRoot | None:
    """Infer application root from one http_surface_map payload."""
    from software_butcher.state.schema import Finding

    target = str(surface_metadata.get("target") or base_target or "")
    if not target:
        return None
    finding = Finding(
        hypothesis="surface map",
        path=target,
        provenance="http_surface:map",
        metadata=surface_metadata,
    )
    return infer_application_root([finding], base_target)


def finding_drives_pcs_branching(
    finding: Finding,
    app_root: ApplicationRoot | None,
    *,
    engagement_type: str = "assessment",
    all_findings: Iterable[Finding] | None = None,
) -> bool:
    """Limit PCS branch spawning to app subtree + parallel stack infrastructure."""
    findings_list = list(all_findings) if all_findings is not None else [finding]
    if engagement_type != "assessment" or app_root is None or app_root.confidence < 0.55:
        return True

    pending = app_root_pending_urls(findings_list, app_root)
    if pending and not _finding_under_root(finding, app_root):
        if is_stack_host_surface(finding.path, findings_list):
            return False
        if as_dict((finding.metadata or {}).get("stack_landing")).get("detected"):
            return False

    if _finding_under_root(finding, app_root):
        return True
    if is_infrastructure_url(finding.path, findings_list):
        return True
    return False


def _content_mapped_urls(findings: Iterable[Finding], app_root: ApplicationRoot) -> set[str]:
    mapped: set[str] = set()
    for finding in findings:
        meta = finding.metadata or {}
        for page in meta.get("content_pages") or []:
            url = str(page.get("url") or "")
            if not url_under_application_root(url, app_root):
                continue
            if page.get("conclusions") or page.get("form_count") is not None or page.get("page_type"):
                mapped.add(_normalize(url))
        path = finding.path
        if url_under_application_root(path, app_root) and meta.get("content_analysis"):
            mapped.add(_normalize(path))
        mapped_target = str(meta.get("mapped_target") or "")
        if mapped_target and url_under_application_root(mapped_target, app_root) and meta.get("content_analysis"):
            mapped.add(_normalize(mapped_target))
    return mapped


def _discovered_app_urls(findings: Iterable[Finding], app_root: ApplicationRoot) -> set[str]:
    discovered: set[str] = set()
    for finding in findings:
        meta = finding.metadata or {}
        for page in meta.get("content_pages") or []:
            url = str(page.get("url") or "")
            if url_under_application_root(url, app_root):
                discovered.add(_normalize(url))
        for url in as_dict(meta.get("app_expand")).get("expanded_urls") or []:
            url_s = str(url)
            if url_under_application_root(url_s, app_root):
                discovered.add(_normalize(url_s))
        if url_under_application_root(finding.path, app_root):
            discovered.add(_normalize(finding.path))
        for url in meta.get("discovered_urls") or []:
            url_s = str(url)
            if url_under_application_root(url_s, app_root):
                discovered.add(_normalize(url_s))
        for item in meta.get("scored_urls") or []:
            if isinstance(item, dict):
                url_s = str(item.get("url") or "")
                if url_under_application_root(url_s, app_root):
                    discovered.add(_normalize(url_s))
    return discovered


def app_root_pending_urls(findings: Iterable[Finding], app_root: ApplicationRoot) -> list[str]:
    """App-subtree URLs seen organically but not yet content-mapped."""
    mapped = _content_mapped_urls(findings, app_root)
    pending = sorted(_discovered_app_urls(findings, app_root) - mapped)
    return [url for url in pending if url]


def is_stack_host_surface(url: str, findings: Iterable[Finding]) -> bool:
    """Default stack / XAMPP dashboard surface — not the engagement application."""
    if not any(as_dict((f.metadata or {}).get("stack_landing")).get("detected") for f in findings):
        return False
    target = _normalize(url)
    parsed = urlsplit(url)
    segments = [p for p in (parsed.path or "").split("/") if p]
    if not segments:
        return True
    if is_noise_path(url):
        return True
    if len(segments) == 1 and segments[0] == "dashboard":
        return True
    for finding in findings:
        if _normalize(finding.path) != target:
            continue
        if as_dict((finding.metadata or {}).get("stack_landing")).get("detected"):
            return True
    return False


def url_under_application_root(url: str, app_root: ApplicationRoot | str) -> bool:
    root = _normalize(app_root.url if isinstance(app_root, ApplicationRoot) else app_root)
    target = _normalize(url)
    if not root or not target:
        return False
    return target == root or target.startswith(root + "/")


def is_infrastructure_url(url: str, findings: Iterable[Finding]) -> bool:
    """Parallel stack surface (phpMyAdmin, phpinfo, default stack landing) — not the app."""
    target = _normalize(url)
    for finding in findings:
        meta = finding.metadata or {}
        path = _normalize(finding.path)
        mapped = _normalize(str(meta.get("mapped_target") or ""))
        if target not in {path, mapped}:
            for page in meta.get("content_pages") or []:
                if _normalize(str(page.get("url") or "")) != target:
                    continue
                page_type = str(page.get("page_type") or "")
                if page_type in INFRA_PAGE_TYPES:
                    return True
            continue

        page_type = str(meta.get("page_type") or "")
        if page_type in INFRA_PAGE_TYPES:
            return True

        stack = as_dict(meta.get("stack_landing"))
        if stack.get("detected"):
            title = str(meta.get("title") or "")
            body_hint = str(meta.get("page_summary") or "")
            if detect_default_stack_landing(
                title=title,
                body=body_hint,
                headers=meta.get("headers") or {},
                final_url=url,
            ).get("detected"):
                return True
    return False


def _finding_under_root(finding: Finding, app_root: ApplicationRoot) -> bool:
    if url_under_application_root(finding.path, app_root):
        return True
    meta = finding.metadata or {}
    mapped = str(meta.get("mapped_target") or "")
    if mapped and url_under_application_root(mapped, app_root):
        return True
    for page in meta.get("content_pages") or []:
        if url_under_application_root(str(page.get("url") or ""), app_root):
            return True
    return False


def _hypothesis_path_organically_discovered(
    hypothesis: Hypothesis,
    source: Finding,
    app_root: ApplicationRoot,
) -> bool:
    """True when this exact path was observed/linked from crawl data under the app root."""
    meta = source.metadata or {}
    hyp_norm = _normalize(hypothesis.path)

    for url in meta.get("discovered_urls") or []:
        if _normalize(str(url)) == hyp_norm and url_under_application_root(str(url), app_root):
            return True
    for url in meta.get("all_discovered_urls") or []:
        if _normalize(str(url)) == hyp_norm and url_under_application_root(str(url), app_root):
            return True
    for page in meta.get("content_pages") or []:
        page_url = str(page.get("url") or "")
        if _normalize(page_url) == hyp_norm:
            return True
    for url in (meta.get("app_expand") or {}).get("expanded_urls") or []:
        if _normalize(str(url)) == hyp_norm:
            return True
    for probe in meta.get("semantic_probes") or []:
        if not probe.get("reachable"):
            continue
        probe_url = str(probe.get("url") or "")
        if _normalize(probe_url) == hyp_norm:
            return True
    mapped = str(meta.get("mapped_target") or "")
    if mapped and _normalize(mapped) == hyp_norm and url_under_application_root(mapped, app_root):
        return True
    return False


def _hypothesis_traces_to_app(
    hypothesis: Hypothesis,
    app_root: ApplicationRoot,
    findings: dict[str, Finding],
    *,
    visited: set[str] | None = None,
) -> bool:
    if visited is None:
        visited = set()
    fid = hypothesis.source_finding_id
    if not fid or fid in visited:
        return False
    visited.add(fid)
    source = findings.get(fid)
    if not source:
        return False
    if _hypothesis_path_organically_discovered(hypothesis, source, app_root):
        return True
    if _finding_under_root(source, app_root) and _normalize(hypothesis.path) == _normalize(source.path):
        return True
    return False


def hypothesis_in_application_scope(
    hypothesis: Hypothesis,
    app_root: ApplicationRoot | None,
    findings: dict[str, Finding],
    *,
    base_target: str = "",
    engagement_type: str = "assessment",
) -> bool:
    """Assessment: once app root is known, focus work on that subtree (+ stack infra)."""
    if engagement_type != "assessment" or app_root is None or app_root.confidence < 0.55:
        return True

    path = hypothesis.path
    meta = hypothesis.metadata or {}

    if url_under_application_root(path, app_root):
        return True

    if is_infrastructure_url(path, findings.values()):
        return True

    entry = engagement_entry_url(base_target).rstrip("/") if base_target else ""
    if entry and _normalize(path) == _normalize(entry):
        return True

    if _hypothesis_traces_to_app(hypothesis, app_root, findings):
        return True

    if is_stack_host_surface(path, findings.values()) and not is_infrastructure_url(path, findings.values()):
        return False

    if str(meta.get("generated_by") or "") in {"redirect_audit", "security_posture", "phpmyadmin_assess", "dos_viability"}:
        if url_under_application_root(path, app_root) or is_infrastructure_url(path, findings.values()):
            return True

    parsed = urlsplit(path)
    root_parsed = urlsplit(app_root.url)
    app_segments = [p for p in (root_parsed.path or "").split("/") if p]
    path_segments = [p for p in (parsed.path or "").split("/") if p]

    if len(app_segments) >= 1 and len(path_segments) == 1:
        return False

    if len(app_segments) >= 1 and not path_segments:
        return False

    if len(app_segments) >= 1 and path_segments and not url_under_application_root(path, app_root):
        if len(path_segments) <= len(app_segments):
            return False

    return True


def app_root_redirect_audits_pending(
    findings: Iterable[Finding],
    app_root: ApplicationRoot,
) -> list[str]:
    """App pages with redirect-body leak signals but no redirect_body_audit yet."""
    pending: list[str] = []
    for finding in findings:
        meta = finding.metadata or {}
        for page in meta.get("content_pages") or []:
            page_url = str(page.get("url") or "")
            if not url_under_application_root(page_url, app_root):
                continue
            leak = bool(page.get("redirect_body_leak_suspected")) or any(
                entry.get("leak_suspected")
                for entry in as_dict_list(page.get("redirect_observations"))
            )
            if not leak:
                continue
            if not _capability_observed_on_url(findings, page_url, "redirect_body_audit"):
                pending.append(page_url)
    return sorted(set(pending))


def _capability_observed_on_url(
    findings: Iterable[Finding],
    url: str,
    capability: str,
) -> bool:
    target = _normalize(url)
    cap = capability.strip()
    for finding in findings:
        meta = finding.metadata or {}
        observed = str(meta.get("capability") or "")
        if observed != cap:
            continue
        if _normalize(finding.path) == target or _normalize(str(meta.get("mapped_target") or "")) == target:
            return True
    return False


def app_scope_work_pending(
    findings: Iterable[Finding],
    app_root: ApplicationRoot,
) -> tuple[list[str], list[str]]:
    """Return (unmapped_app_urls, redirect_audit_urls) still needing work."""
    maps = app_root_pending_urls(findings, app_root)
    redirects = app_root_redirect_audits_pending(findings, app_root)
    return maps, redirects


def assessment_serializes_branches(
    app_root: ApplicationRoot | None,
    findings: Iterable[Finding],
    *,
    engagement_type: str = "assessment",
) -> tuple[bool, str]:
    """Assessment runs single-branch once an application root is inferred."""
    if engagement_type != "assessment" or app_root is None or app_root.confidence < 0.55:
        return False, ""
    pending_maps, pending_redirects = app_scope_work_pending(findings, app_root)
    if pending_maps or pending_redirects:
        return (
            True,
            f"app_scope_serialize: {len(pending_maps)} unmapped app URL(s), "
            f"{len(pending_redirects)} redirect audit(s) pending",
        )
    return True, f"assessment_app_focus: app root {app_root.url} — single branch"


def filter_assessment_pending(
    pending: list[Hypothesis],
    app_root: ApplicationRoot,
    findings: dict[str, Finding],
) -> list[Hypothesis]:
    """Prefer app-subtree hypotheses; keep stack/dashboard/host-root out until app work is done."""
    findings_list = list(findings.values())
    app_hyps = [h for h in pending if url_under_application_root(h.path, app_root)]
    pending_maps, pending_redirects = app_scope_work_pending(findings_list, app_root)
    if pending_maps or pending_redirects:
        return app_hyps

    if app_hyps:
        return app_hyps

    infra = [
        h
        for h in pending
        if is_infrastructure_url(h.path, findings_list)
        and not is_stack_host_surface(h.path, findings_list)
    ]
    if infra:
        return infra

    return [h for h in pending if not is_stack_host_surface(h.path, findings_list)]


def application_scope_priority_boost(
    hypothesis: Hypothesis,
    app_root: ApplicationRoot | None,
    findings: dict[str, Finding],
) -> float:
    """Queue ordering: prefer app subtree, then infrastructure, deprioritize host noise."""
    if app_root is None or app_root.confidence < 0.55:
        return 0.0

    meta = hypothesis.metadata or {}
    generated_by = str(meta.get("generated_by") or "")
    pending = {_normalize(u) for u in app_root_pending_urls(findings.values(), app_root)}
    path_norm = _normalize(hypothesis.path)

    if url_under_application_root(hypothesis.path, app_root):
        boost = 0.35
        if generated_by in {"redirect_audit", "app_link_expand"}:
            boost += 0.2
        if path_norm in pending:
            boost += 0.25
        return boost

    if is_infrastructure_url(hypothesis.path, findings.values()):
        return -0.25 if pending else 0.0

    if is_stack_host_surface(hypothesis.path, findings.values()):
        return -0.65

    return -0.5
