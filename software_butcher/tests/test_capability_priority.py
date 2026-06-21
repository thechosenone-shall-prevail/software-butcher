"""Tests for assessment capability priority ordering."""

from software_butcher.core.capability_priority import (
    assessment_capability_rank,
    is_assessment_deprioritized,
)
from software_butcher.core.registry import default_registry


def test_sql_injection_is_lowest_assessment_priority():
    assert assessment_capability_rank("http_surface_map") < assessment_capability_rank("sql_injection_probing")
    assert assessment_capability_rank("vulnerability_scanning") < assessment_capability_rank("sql_injection_probing")
    assert is_assessment_deprioritized("sql_injection_probing")
    assert is_assessment_deprioritized("directory_bruteforce")


def test_registry_lists_assessment_capabilities_with_sqlmap_last():
    registry = default_registry()
    ordered = registry.list_capabilities_for_engagement("assessment")
    names = [c["capability"] for c in ordered]
    assert names.index("http_surface_map") < names.index("vulnerability_scanning")
    assert names.index("vulnerability_scanning") < names.index("sql_injection_probing")
