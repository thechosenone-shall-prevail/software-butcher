"""Tests for hostname-derived semantic path discovery."""

from software_butcher.core.domain_semantics import semantic_path_candidates, tokens_from_host


def test_hallbooking_host_yields_hall_token():
    tokens = tokens_from_host("http://hallbooking.srmrmp.edu.in")
    assert "hallbooking" in tokens
    assert "hall" in tokens
    assert "booking" not in tokens
    assert "book" not in tokens


def test_semantic_candidates_cap_substring_spray():
    cands = semantic_path_candidates("http://hallbooking.srmrmp.edu.in")
    urls = [c["url"] for c in cands]
    assert len(cands) <= 2
    assert "http://hallbooking.srmrmp.edu.in/hallbooking" in urls
    assert "http://hallbooking.srmrmp.edu.in/book" not in urls
    assert "http://hallbooking.srmrmp.edu.in/booking" not in urls
    assert "http://hallbooking.srmrmp.edu.in/dashboard" not in urls


def test_semantic_candidates_include_hall_path():
    cands = semantic_path_candidates("http://hallbooking.srmrmp.edu.in")
    urls = [c["url"] for c in cands]
    assert "http://hallbooking.srmrmp.edu.in/hall" in urls
    hall = next(c for c in cands if c["token"] == "hall")
    assert float(hall["score"]) >= 0.9


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
