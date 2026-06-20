"""Tests for CVE lookup capability dispatch."""

from unittest.mock import MagicMock

from software_butcher.core.adapter import AdapterRequest
from software_butcher.shelves.hexstrike.adapter import HexstrikeAdapter


def test_cve_lookup_dispatches_to_client():
    client = MagicMock()
    client.ensure_healthy = MagicMock()
    client.detect_technologies.return_value = {"success": True, "stdout": "Apache 2.4.49", "technologies": ["Apache 2.4.49"]}

    adapter = HexstrikeAdapter(client=client)
    request = AdapterRequest(
        objective="cve_lookup",
        target="https://example.com",
        asset_type="web_endpoint",
        scope={},
        options={"capability": "cve_lookup", "technology": "Apache 2.4.49"},
    )
    plan = adapter.plan(request)
    result = adapter.execute(plan)

    client.detect_technologies.assert_called()
    assert result.success or result.findings
