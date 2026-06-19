"""Tests for ACE convergence clustering."""

from software_butcher.state.convergence import cluster_theme, detect_flags, recompute_clusters
from software_butcher.state.schema import Finding


def test_cluster_theme_auth():
    finding = Finding(
        hypothesis="Login bypass via SQL injection",
        path="https://target/login",
        provenance="playwright",
        evidence=["session created", "redirect to dashboard"],
        metadata={"capability": "auth_bypass_confirmed"},
    )
    assert cluster_theme(finding) == "auth_bypass"


def test_convergence_score_increases_with_branches():
    findings = [
        Finding(
            id="f1",
            hypothesis="Auth anomaly on login",
            path="https://t/login",
            provenance="b1",
            metadata={"branch_id": "branch-a"},
            evidence=["session"],
        ),
        Finding(
            id="f2",
            hypothesis="Auth bypass candidate",
            path="https://t/login",
            provenance="b2",
            metadata={"branch_id": "branch-b"},
            evidence=["redirect"],
        ),
        Finding(
            id="f3",
            hypothesis="Login behavior change",
            path="https://t/login",
            provenance="b3",
            metadata={"branch_id": "branch-c"},
            evidence=["cookie"],
        ),
    ]
    for f in findings:
        f.cluster_theme = "auth_bypass"

    clusters = recompute_clusters(findings)
    cluster = clusters["auth_bypass"]
    assert cluster.supporting_paths >= 2
    assert cluster.convergence_score > 0.5


def test_detect_htb_flag():
    flags = detect_flags("Got the flag HTB{4c4c3d3b1234abcd}")
    assert any("HTB{" in f for f in flags)
