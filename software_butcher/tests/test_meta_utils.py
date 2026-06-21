"""Tests for safe metadata accessors and LLM context resilience."""

from software_butcher.brain.context import build_brain_context
from software_butcher.core.app_root import (
    app_root_pending_urls,
    app_scope_work_pending,
    application_scope_priority_boost,
    assessment_serializes_branches,
    infer_application_root,
    is_stack_host_surface,
)
from software_butcher.core.meta_utils import as_dict, as_dict_list
from software_butcher.state.engagement import EngagementState
from software_butcher.state.schema import Finding, Hypothesis


def test_as_dict_rejects_list():
    assert as_dict([]) == {}
    assert as_dict({"detected": True})["detected"] is True


def test_as_dict_list_filters_non_dicts():
    assert as_dict_list([{"leak_suspected": True}, "bad", None]) == [{"leak_suspected": True}]


def test_brain_context_survives_malformed_stack_landing():
    finding = Finding(
        hypothesis="surface map",
        path="http://example.edu/dashboard",
        provenance="http_surface:map",
        metadata={
            "stack_landing": ["unexpected", "list"],
            "infrastructure": ["waf=none"],
        },
    )
    text = build_brain_context([finding], EngagementState(), base_target="http://example.edu/hall/")
    assert "dashboard" in text


def test_stack_host_surface_when_stack_landing_known():
    finding = Finding(
        hypothesis="surface map",
        path="http://example.edu",
        provenance="http_surface:map",
        metadata={"stack_landing": {"detected": True, "stack": "xampp_default"}},
    )
    assert is_stack_host_surface("http://example.edu", [finding])
    assert is_stack_host_surface("http://example.edu/dashboard", [finding])
    assert not is_stack_host_surface("http://example.edu/hall/report.php", [finding])


def test_app_root_pending_urls_and_priority_boost():
    finding = Finding(
        hypothesis="surface map",
        path="http://example.edu/hall",
        provenance="http_surface:map",
        metadata={
            "content_pages": [
                {"url": "http://example.edu/hall/index.php", "form_count": 1},
            ],
            "app_expand": {
                "expanded_urls": [
                    "http://example.edu/hall/admin.php",
                    "http://example.edu/hall/report.php",
                ],
            },
        },
    )
    app_root = infer_application_root([finding], base_target="http://example.edu/hall/")
    assert app_root is not None
    pending = app_root_pending_urls([finding], app_root)
    assert "http://example.edu/hall/admin.php" in pending

    findings = {finding.id: finding}
    stack_hyp = Hypothesis(
        path="http://example.edu/dashboard",
        reason="stack",
        source_finding_id=finding.id,
        priority=0.9,
        metadata={"generated_by": "content_intel"},
    )
    app_hyp = Hypothesis(
        path="http://example.edu/hall/admin.php",
        reason="redirect audit",
        source_finding_id=finding.id,
        priority=0.7,
        metadata={"generated_by": "redirect_audit"},
    )
    assert application_scope_priority_boost(stack_hyp, app_root, findings) < 0
    assert application_scope_priority_boost(app_hyp, app_root, findings) > application_scope_priority_boost(
        stack_hyp, app_root, findings
    )


def test_assessment_serializes_while_app_work_pending():
    finding = Finding(
        hypothesis="surface map",
        path="http://example.edu/hall",
        provenance="http_surface:map",
        metadata={
            "content_pages": [{"url": "http://example.edu/hall/index.php", "form_count": 1}],
            "app_expand": {"expanded_urls": ["http://example.edu/hall/admin.php"]},
        },
    )
    app_root = infer_application_root([finding], base_target="http://example.edu/hall/")
    assert app_root is not None
    serial, reason = assessment_serializes_branches(app_root, [finding], engagement_type="assessment")
    assert serial is True
    assert "unmapped" in reason
    maps, redirects = app_scope_work_pending([finding], app_root)
    assert "http://example.edu/hall/admin.php" in maps
