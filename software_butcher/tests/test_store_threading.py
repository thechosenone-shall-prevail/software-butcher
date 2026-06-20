"""Tests for thread-safe finding store."""

import threading

from software_butcher.state.schema import Finding, Hypothesis
from software_butcher.state.store import FindingStore


def test_concurrent_add_findings(tmp_path):
    store = FindingStore(tmp_path / "state.json")
    errors: list[Exception] = []

    def worker(idx: int) -> None:
        try:
            store.add_finding(
                Finding(
                    hypothesis=f"h-{idx}",
                    path=f"https://example.com/{idx}",
                    provenance="test",
                    status="hypothesis",
                    confidence=0.5,
                    evidence=[str(idx)],
                    asset_type="web_endpoint",
                )
            )
        except Exception as exc:
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(20)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert not errors
    assert len(store.findings) == 20


def test_record_tool_call_respects_limit(tmp_path):
    store = FindingStore(tmp_path / "state.json")
    assert store.record_tool_call(3)
    assert store.record_tool_call(3)
    assert store.record_tool_call(3)
    assert not store.record_tool_call(3)
    assert store.tool_calls == 3
