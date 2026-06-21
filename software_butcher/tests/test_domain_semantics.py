"""Tests for hostname + engagement_context path hints (no fixed wordlists)."""

from software_butcher.core.domain_semantics import semantic_path_candidates, tokens_from_host


def test_hallbooking_without_context_only_yields_hostname_label():
    tokens = tokens_from_host("http://hallbooking.srmrmp.edu.in")
    assert tokens == ["hallbooking"]


def test_hallbooking_with_context_extracts_embedded_words():
    ctx = "faculty hall booking registration portal PHP MySQL"
    tokens = tokens_from_host("http://hallbooking.srmrmp.edu.in", ctx)
    assert "hallbooking" in tokens
    assert "hall" in tokens
    assert "booking" in tokens


def test_semantic_candidates_without_context_use_hostname_only():
    cands = semantic_path_candidates("http://hallbooking.srmrmp.edu.in")
    urls = [c["url"] for c in cands]
    assert len(cands) <= 2
    assert "http://hallbooking.srmrmp.edu.in/hallbooking" in urls
    assert "http://hallbooking.srmrmp.edu.in/hall" not in urls
    assert "http://hallbooking.srmrmp.edu.in/book" not in urls
    assert "http://hallbooking.srmrmp.edu.in/dashboard" not in urls


def test_semantic_candidates_with_context_can_include_embedded_tokens():
    ctx = "faculty hall booking registration"
    cands = semantic_path_candidates(
        "http://hallbooking.srmrmp.edu.in",
        engagement_context=ctx,
        max_paths=4,
    )
    tokens = {c["token"] for c in cands}
    assert "hall" in tokens or "booking" in tokens


def test_engagement_context_adds_tokens():
    without_ctx = semantic_path_candidates("http://portal.example.com")
    with_ctx = semantic_path_candidates(
        "http://portal.example.com",
        engagement_context="faculty hall booking registration",
    )
    assert len(with_ctx) <= 2
    assert any(c["source"] == "context" for c in with_ctx)
    ctx_urls = {c["url"] for c in with_ctx if c["source"] == "context"}
    baseline_urls = {c["url"] for c in without_ctx}
    assert ctx_urls - baseline_urls
