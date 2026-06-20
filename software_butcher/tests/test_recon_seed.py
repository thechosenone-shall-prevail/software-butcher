"""Tests for recon checklist re-queue and execution marking."""

from software_butcher.core.recon_seed import ensure_host_recon_hypothesis, next_recon_hypothesis
from software_butcher.state.recon_checklist import mark_host_recon
from software_butcher.state.store import FindingStore


def test_mark_host_recon_advances_checklist(tmp_path):
    store = FindingStore(tmp_path / "state.json")
    store.set_base_target("http://hallbooking.srmrmp.edu.in")
    mark_host_recon(store.recon_checklist, store.base_target, "web_behavior_analysis")
    assert store.recon_checklist.next_missing("hallbooking.srmrmp.edu.in") == "technology_fingerprint"


def test_ensure_host_recon_requeues_missing_step(tmp_path):
    store = FindingStore(tmp_path / "state.json")
    store.set_base_target("http://hallbooking.srmrmp.edu.in")
    assert ensure_host_recon_hypothesis(store) is True
    hyp = next_recon_hypothesis(store)
    assert hyp is not None
    assert hyp.metadata["intent"] == "web_behavior_analysis"


def test_ensure_host_recon_queues_fingerprint_after_behavior(tmp_path):
    store = FindingStore(tmp_path / "state.json")
    store.set_base_target("http://hallbooking.srmrmp.edu.in")
    mark_host_recon(store.recon_checklist, store.base_target, "web_behavior_analysis")
    assert ensure_host_recon_hypothesis(store) is True
    hyp = next_recon_hypothesis(store)
    assert hyp.metadata["intent"] == "technology_fingerprint"
