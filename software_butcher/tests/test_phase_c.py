"""Tests for Phase C: lanes, fuzzy themes, binary download, shell chain."""

from pathlib import Path
from unittest.mock import MagicMock

from software_butcher.brain.loop import BrainLoop
from software_butcher.core.adapter import AdapterCapability, AdapterRequest, AdapterResult
from software_butcher.core.asset_expander import AssetExpander
from software_butcher.core.assets import Asset, AssetInventory
from software_butcher.core.binary_acquisition import BinaryAcquisition
from software_butcher.core.scope import Scope
from software_butcher.project import ButcherProject
from software_butcher.state.convergence import cluster_theme, recompute_clusters
from software_butcher.state.schema import Finding, Hypothesis
from software_butcher.state.session_state import SessionStore
from software_butcher.state.store import FindingStore
from software_butcher.shelves.hexstrike.adapter import HexstrikeAdapter
from software_butcher.synthesis.lanes import build_assessment_lanes
from software_butcher.synthesis.report import Synthesizer


def test_fuzzy_theme_merges_dashboard_and_hall():
    dashboard = Finding(
        id="f1",
        hypothesis="Dashboard requires auth",
        path="https://target.example.com/dashboard",
        provenance="hexstrike",
        evidence=["login redirect"],
        asset_type="web_endpoint",
    )
    hall = Finding(
        id="f2",
        hypothesis="Hall booking portal",
        path="https://target.example.com/hall",
        provenance="hexstrike",
        evidence=["session cookie set"],
        asset_type="web_endpoint",
    )
    assert cluster_theme(dashboard) == cluster_theme(hall) == "web_auth:target.example.com"


def test_fuzzy_theme_convergence_across_paths():
    findings = [
        Finding(
            id="f1",
            hypothesis="Dashboard auth",
            path="https://t.example/dashboard",
            provenance="b1",
            metadata={"branch_id": "branch-a"},
            evidence=["login"],
            asset_type="web_endpoint",
        ),
        Finding(
            id="f2",
            hypothesis="Hall auth",
            path="https://t.example/hall",
            provenance="b2",
            metadata={"branch_id": "branch-b"},
            evidence=["session"],
            asset_type="web_endpoint",
        ),
    ]
    clusters = recompute_clusters(findings)
    assert len(clusters) == 1
    assert list(clusters.keys())[0].startswith("web_auth:")


def test_binary_acquisition_downloads_file(tmp_path, monkeypatch):
    class FakeResponse:
        content = b"MZ\xfake-binary"

        @staticmethod
        def raise_for_status() -> None:
            return None

    monkeypatch.setattr(
        "software_butcher.core.binary_acquisition.requests.Session.get",
        lambda self, url, timeout, stream: FakeResponse(),
    )

    dest = BinaryAcquisition().download("https://corp.example.com/setup.exe", tmp_path)
    assert dest is not None
    assert dest.exists()
    assert dest.read_bytes().startswith(b"MZ")


def test_asset_expander_downloads_binary_url(tmp_path, monkeypatch):
    class FakeResponse:
        content = b"MZ\xfake"

        @staticmethod
        def raise_for_status() -> None:
            return None

    monkeypatch.setattr(
        "software_butcher.core.binary_acquisition.requests.Session.get",
        lambda self, url, timeout, stream: FakeResponse(),
    )

    scope = Scope(name="t", allowed_domains=["corp.example.com"])
    inventory = AssetInventory()
    store = FindingStore(tmp_path / "state.json")
    expander = AssetExpander()
    finding = Finding(
        id="f1",
        path="https://corp.example.com",
        hypothesis="Executable link found",
        provenance="hexstrike",
        evidence=["https://corp.example.com/bin/setup.exe"],
        asset_type="web_endpoint",
    )

    assets = expander.expand(
        finding,
        scope,
        inventory,
        hypothesis_queue=store.queue,
        workspace_root=tmp_path,
        binary_acquisition=BinaryAcquisition(),
    )
    assert len(assets) == 1
    assert assets[0].asset_type == "binary"
    assert Path(assets[0].locator).exists()
    assert assets[0].metadata.get("original_url", "").endswith("/setup.exe")


def test_multi_lane_synthesis_report():
    store = FindingStore("unused.json")
    inventory = AssetInventory()
    inventory.add(Asset(locator="https://app.example.com", asset_type="web_endpoint"))
    inventory.add(Asset(locator="/tmp/app.exe", asset_type="binary"))

    store.ingest_finding(
        Finding(
            path="https://app.example.com/admin",
            hypothesis="Admin login exposed",
            provenance="hexstrike",
            status="hypothesis",
            confidence=0.7,
            evidence=["login form"],
            asset_type="web_endpoint",
        )
    )
    store.ingest_finding(
        Finding(
            path="/tmp/app.exe",
            hypothesis="Binary contains strcpy",
            provenance="binary_triage",
            status="hypothesis",
            confidence=0.65,
            evidence=["strcpy"],
            asset_type="binary",
        )
    )

    report = Synthesizer().synthesize(store, inventory=inventory)
    assert len(report.lanes) == 5
    web_lane = next(lane for lane in report.lanes if lane["name"] == "web")
    binary_lane = next(lane for lane in report.lanes if lane["name"] == "binary")
    assert web_lane["status"] in {"exposed", "confirmed"}
    assert binary_lane["finding_count"] >= 1
    assert report.verdict.name == "partially_hardened"
    assert "web=" in report.verdict.summary


def test_synthesis_compromised_when_flags_present():
    store = FindingStore("unused.json")
    store.ingest_finding(
        Finding(
            path="http://10.10.11.5",
            hypothesis="Captured user flag",
            provenance="shell",
            status="confirmed",
            confidence=0.95,
            evidence=["HTB{deadbeef}"],
            asset_type="ip",
        )
    )
    store.engagement.flags_found.append("HTB{deadbeef}")
    report = Synthesizer().synthesize(store)
    assert report.verdict.name == "compromised"


def test_shell_exploit_to_command_chain_e2e(tmp_path):
    """Recorded chain: exploit output opens session -> shell_command reads flag."""
    workspace = tmp_path / "ws"
    scope = Scope(
        name="t",
        allowed_domains=["10.10.11.5"],
        max_tool_calls=5,
        metadata={"engagement_type": "ctf"},
    )
    project = ButcherProject(workspace, scope, resume=False)
    asset = project.add_asset(Asset(locator="http://10.10.11.5", asset_type="web_endpoint"))
    project.findings.set_base_target(asset.locator)

    session_store = project.findings.session_store
    adapter = HexstrikeAdapter(client=MagicMock())

    exploit_output = {
        "stdout": "[*] Meterpreter session 7 opened (10.10.11.5:4444 -> 10.10.14.2:44352)",
        "stderr": "",
        "success": True,
    }
    adapter._store_shell_if_detected(
        exploit_output,
        "10.10.11.5",
        {"session_store": session_store},
    )
    assert session_store.shell_sessions.get_session("7") is not None

    adapter.client.shell_execute.return_value = {
        "stdout": "HTB{user_flag_deadbeef}",
        "stderr": "",
        "success": True,
    }

    project.findings.add_hypothesis(
        Hypothesis(
            path="http://10.10.11.5",
            reason="Read user flag via established shell",
            source_finding_id="phase:foothold",
            priority=1.0,
            metadata={
                "intent": "shell_command_execution",
                "command": "cat user.txt",
                "asset_type": "ip",
            },
        )
    )

    from software_butcher.core.registry import AdapterRegistry

    registry = AdapterRegistry()
    registry.register(adapter)

    brain = BrainLoop(
        project.findings,
        scope=scope,
        registry=registry,
        max_steps=1,
        max_branches=1,
        adaptive_pcs=False,
        no_new_limit=99,
        on_finding_ingested=project.process_finding,
    )
    events = brain.run(asset)

    assert any(event.get("status") == "executed" for event in events)
    session = session_store.shell_sessions.get_session("7")
    assert session is not None
    assert "HTB{" in session.last_output
    adapter.client.shell_execute.assert_called_once()

    report = Synthesizer().synthesize(project.findings, inventory=project.inventory)
    post_exploit = next(lane for lane in report.lanes if lane["name"] == "post_exploit")
    assert post_exploit["status"] == "confirmed"
