"""Tests for reality-check Java ingest."""
from pathlib import Path

from benchmarks.scripts._active_cwes import ACTIVE_CWES
from benchmarks.scripts.ingest_reality_check_java import RealityCheckJavaIngest


def test_phase1_filter_contains_expected_cwes():
    assert "CWE-79" in ACTIVE_CWES
    assert "CWE-78" in ACTIVE_CWES


def test_ingest_has_correct_metadata():
    ingest = RealityCheckJavaIngest(root=Path("/tmp/test-root"))
    assert ingest.dataset_name == "reality-check-java"
