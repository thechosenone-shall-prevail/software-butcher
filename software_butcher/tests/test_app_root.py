"""Evidence-driven application root inference and subtree scoping."""

from software_butcher.brain.context import build_brain_context
from software_butcher.core.app_root import (
    app_subtree_analysis_incomplete,
    filter_assessment_pending,
    hypothesis_in_application_scope,
    infer_application_root,
    is_infrastructure_url,
    url_under_application_root,
)
from software_butcher.state.engagement import EngagementState
from software_butcher.state.hypothesis_queue import HypothesisQueue
from software_butcher.state.pcs import ProgressiveConvergenceSearch
from software_butcher.state.schema import Finding, Hypothesis


def _surface_finding(**meta) -> Finding:
    defaults = {
        "capability": "http_surface_map",
        "stack_landing": {"detected": True, "stack": "xampp_default"},
        "content_pages": [
            {
                "url": "http://example.edu/hall/report.php",
                "form_count": 0,
                "conclusions": ["Report listing"],
            },
            {
                "url": "http://example.edu/hall/register.php",
                "form_count": 2,
                "conclusions": ["Registration form"],
            },
        ],
        "app_expand": {
            "expanded_urls": [
                "http://example.edu/hall/admin.php",
                "http://example.edu/hall/bookingdata.php",
            ],
        },
    }
    defaults.update(meta)
    return Finding(
        hypothesis="surface map",
        path="http://example.edu",
        provenance="http_surface:map",
        metadata=defaults,
    )


def test_infer_application_root_from_crawl_evidence():
    finding = _surface_finding()
    app_root = infer_application_root(
        [finding],
        base_target="http://example.edu/hall/",
    )
    assert app_root is not None
    assert app_root.url.rstrip("/").endswith("/hall")
    assert app_root.confidence >= 0.55


def test_rejects_host_root_admin_when_app_is_hall():
    finding = _surface_finding()
    findings = {finding.id: finding}
    app_root = infer_application_root([finding], base_target="http://example.edu/hall/")
    assert app_root is not None

    host_admin = Hypothesis(
        path="http://example.edu/admin",
        reason="hostname token guess",
        source_finding_id=finding.id,
        metadata={"generated_by": "domain_semantics"},
    )
    assert not hypothesis_in_application_scope(
        host_admin,
        app_root,
        findings,
        base_target="http://example.edu/hall/",
        engagement_type="assessment",
    )

    app_admin = Hypothesis(
        path="http://example.edu/hall/admin.php",
        reason="organic expansion",
        source_finding_id=finding.id,
        metadata={"generated_by": "app_link_expand"},
    )
    assert hypothesis_in_application_scope(
        app_admin,
        app_root,
        findings,
        base_target="http://example.edu/hall/",
        engagement_type="assessment",
    )


def test_infrastructure_url_allowed():
    finding = Finding(
        hypothesis="surface map",
        path="http://example.edu",
        provenance="http_surface:map",
        metadata={
            "content_pages": [
                {
                    "url": "http://example.edu/dashboard/phpinfo.php",
                    "page_type": "phpinfo",
                }
            ],
        },
    )
    assert is_infrastructure_url("http://example.edu/dashboard/phpinfo.php", [finding])


def test_queue_rejects_host_root_noise():
    finding = _surface_finding()
    queue = HypothesisQueue()
    base = "http://example.edu/hall/"
    queue.configure(
        findings={finding.id: finding},
        engagement_type="assessment",
        base_target=base,
    )
    queue.add(
        Hypothesis(
            path="http://example.edu/report",
            reason="hostname guess",
            source_finding_id=finding.id,
            metadata={"generated_by": "domain_semantics"},
        ),
        base_target=base,
    )
    queue.add(
        Hypothesis(
            path="http://example.edu/hall/report.php",
            reason="mapped application page",
            source_finding_id=finding.id,
            metadata={"generated_by": "content_intel"},
        ),
        base_target=base,
    )
    pending_paths = [h.path for h in queue.pending_list()]
    assert "http://example.edu/hall/report.php" in pending_paths
    assert "http://example.edu/report" not in pending_paths


def test_queue_prioritizes_app_subtree():
    finding = _surface_finding()
    queue = HypothesisQueue()
    base = "http://example.edu/hall/"
    queue.configure(
        findings={finding.id: finding},
        engagement_type="assessment",
        base_target=base,
    )
    queue.add(
        Hypothesis(
            path="http://example.edu/dashboard/phpinfo.php",
            reason="stack intel",
            source_finding_id=finding.id,
            priority=0.9,
            metadata={"generated_by": "content_intel"},
        ),
        base_target=base,
    )
    finding_infra = Finding(
        hypothesis="phpinfo",
        path="http://example.edu",
        provenance="http_surface:map",
        metadata={
            "content_pages": [
                {"url": "http://example.edu/dashboard/phpinfo.php", "page_type": "phpinfo"},
            ],
        },
    )
    queue.configure(
        findings={finding.id: finding, finding_infra.id: finding_infra},
        engagement_type="assessment",
        base_target=base,
    )
    queue.add(
        Hypothesis(
            path="http://example.edu/hall/admin.php",
            reason="app page",
            source_finding_id=finding.id,
            priority=0.7,
            metadata={"generated_by": "app_link_expand"},
        ),
        base_target=base,
    )
    first = queue.next()
    assert first is not None
    assert "/hall/" in first.path


def test_brain_context_includes_application_root():
    finding = _surface_finding()
    context = build_brain_context(
        [finding],
        EngagementState(),
        engagement_type="assessment",
        base_target="http://example.edu/hall/",
    )
    assert "Application root (inferred)" in context
    assert "/hall" in context


def test_pcs_skips_host_wide_branch_on_out_of_scope_finding():
    finding = _surface_finding()
    app_root = infer_application_root([finding], base_target="http://example.edu/hall/")
    assert app_root is not None

    host_noise = Finding(
        hypothesis="guess",
        path="http://example.edu/admin",
        provenance="domain_semantics",
        confidence=0.9,
        metadata={"generated_by": "domain_semantics"},
    )
    pcs = ProgressiveConvergenceSearch()
    count, _ = pcs.branches_for_step(
        {},
        [host_noise],
        app_root=app_root,
        engagement_type="assessment",
    )
    assert count == 1

    app_finding = Finding(
        hypothesis="admin page",
        path="http://example.edu/hall/admin.php",
        provenance="http_surface:map",
        confidence=0.9,
        metadata={"content_analysis": True},
    )
    count, reason = pcs.branches_for_step(
        {},
        [app_finding],
        app_root=app_root,
        engagement_type="assessment",
    )
    assert count == 1
    assert "assessment_app_focus" in reason or "app_scope_serialize" in reason


def test_url_under_application_root():
    assert url_under_application_root(
        "http://example.edu/hall/admin.php",
        "http://example.edu/hall",
    )
    assert not url_under_application_root(
        "http://example.edu/admin",
        "http://example.edu/hall",
    )


def _posture_finding(url: str, source_id: str = "") -> Finding:
    return Finding(
        hypothesis="security posture",
        path=url,
        provenance="web_audit:security_posture",
        metadata={"capability": "security_posture_audit", "mapped_target": url},
    )


def test_app_subtree_analysis_incomplete_without_security_posture():
    finding = _surface_finding(
        app_expand={"expanded_urls": []},
        content_pages=[
            {
                "url": "http://example.edu/hall/report.php",
                "form_count": 0,
                "conclusions": ["Report listing"],
            },
            {
                "url": "http://example.edu/hall/register.php",
                "form_count": 0,
                "conclusions": ["Registration form"],
            },
        ],
    )
    app_root = infer_application_root([finding], base_target="http://example.edu/hall/")
    assert app_root is not None
    assert app_subtree_analysis_incomplete([finding], app_root) is True

    findings = [finding, _posture_finding("http://example.edu/hall/report.php", finding.id)]
    assert app_subtree_analysis_incomplete(findings, app_root) is True

    complete_findings = findings + [
        _posture_finding("http://example.edu/hall/register.php", finding.id),
    ]
    assert app_subtree_analysis_incomplete(complete_findings, app_root) is False


def test_filter_assessment_pending_blocks_infra_when_analysis_incomplete():
    finding = _surface_finding(app_expand={"expanded_urls": []})
    app_root = infer_application_root([finding], base_target="http://example.edu/hall/")
    assert app_root is not None
    findings = {finding.id: finding}
    infra_hyp = Hypothesis(
        path="http://example.edu/dashboard/phpinfo.php",
        reason="stack intel",
        source_finding_id=finding.id,
        priority=0.95,
        metadata={"generated_by": "content_intel"},
    )
    app_hyp = Hypothesis(
        path="http://example.edu/hall/report.php",
        reason="posture audit",
        source_finding_id=finding.id,
        priority=0.7,
        metadata={"generated_by": "security_posture", "intent": "security_posture_audit"},
    )
    filtered = filter_assessment_pending([infra_hyp, app_hyp], app_root, findings)
    assert all("/hall/" in h.path for h in filtered)
    assert not any("phpinfo" in h.path for h in filtered)


def test_hypothesis_scope_blocks_infra_while_analysis_incomplete():
    finding = _surface_finding(
        app_expand={"expanded_urls": []},
        content_pages=[
            {
                "url": "http://example.edu/hall/report.php",
                "form_count": 0,
                "conclusions": ["Report listing"],
            },
            {
                "url": "http://example.edu/dashboard/phpinfo.php",
                "page_type": "phpinfo",
            },
        ],
    )
    app_root = infer_application_root([finding], base_target="http://example.edu/hall/")
    assert app_root is not None
    findings = {finding.id: finding}
    infra_hyp = Hypothesis(
        path="http://example.edu/dashboard/phpinfo.php",
        reason="stack intel",
        source_finding_id=finding.id,
        metadata={"generated_by": "content_intel"},
    )
    assert not hypothesis_in_application_scope(
        infra_hyp,
        app_root,
        findings,
        base_target="http://example.edu/hall/",
        engagement_type="assessment",
    )
