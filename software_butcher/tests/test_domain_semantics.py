"""Tests for hostname-derived semantic path discovery."""

from software_butcher.core.domain_semantics import semantic_path_candidates, tokens_from_host


def test_hallbooking_host_yields_hall_token():
    tokens = tokens_from_host("http://hallbooking.srmrmp.edu.in")
    assert "hallbooking" in tokens
    assert "hall" in tokens
    assert "booking" in tokens


def test_semantic_candidates_include_hall_path():
    cands = semantic_path_candidates("http://hallbooking.srmrmp.edu.in")
    urls = [c["url"] for c in cands]
    assert "http://hallbooking.srmrmp.edu.in/hall" in urls
    hall = next(c for c in cands if c["token"] == "hall")
    assert float(hall["score"]) >= 0.9


def test_engagement_context_adds_tokens():
    cands = semantic_path_candidates(
        "http://portal.example.com",
        engagement_context="faculty hall booking registration",
    )
    urls = [c["url"] for c in cands]
    assert any("/hall" in u for u in urls)
