"""Tests for PCS adaptive branching."""

from software_butcher.state.pcs import ProgressiveConvergenceSearch
from software_butcher.state.schema import ConvergenceCluster, Finding


def test_pcs_starts_primary_path():
    pcs = ProgressiveConvergenceSearch()
    count, reason = pcs.branches_for_step({}, [])
    assert count == 1
    assert "primary" in reason


def test_pcs_spawns_on_high_value_evidence():
    pcs = ProgressiveConvergenceSearch()
    findings = [
        Finding(
            hypothesis="Confirmed RCE",
            path="https://t/",
            provenance="x",
            status="confirmed",
            evidence=["shell"],
            metadata={"capability": "rce"},
        )
    ]
    count, reason = pcs.branches_for_step({}, findings)
    assert count == 3
    assert "evidence" in reason


def test_pcs_validation_mode_on_convergence():
    pcs = ProgressiveConvergenceSearch()
    clusters = {
        "ssrf": ConvergenceCluster(
            theme="ssrf",
            supporting_paths=5,
            convergence_score=0.85,
            evidence_count=10,
        )
    }
    count, reason = pcs.branches_for_step(clusters, [])
    assert count == 1
    assert pcs.state.validation_mode is True
