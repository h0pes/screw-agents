"""Tests for reality-check C# ingest."""
from pathlib import Path

from benchmarks.scripts._active_cwes import ACTIVE_CWES
from benchmarks.scripts.ingest_reality_check_csharp import RealityCheckCsharpIngest


def test_phase1_filter_contains_expected_cwes():
    for cwe in ("CWE-79", "CWE-89", "CWE-78"):
        assert cwe in ACTIVE_CWES


def test_ingest_has_correct_metadata():
    ingest = RealityCheckCsharpIngest(root=Path("/tmp/test-root"))
    assert ingest.dataset_name == "reality-check-csharp"
    assert "reality-check" in ingest.source_url
