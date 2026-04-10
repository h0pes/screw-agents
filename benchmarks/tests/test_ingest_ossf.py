"""Tests for the OpenSSF CVE Benchmark ingest script."""
from pathlib import Path

import pytest

from benchmarks.scripts._active_cwes import ACTIVE_CWES
from benchmarks.scripts.ingest_ossf import OssfCveBenchmarkIngest


def test_cwe_filter_covers_phase1_targets():
    """We must filter for the four Phase 1 CWEs plus CWE-94 (SSTI parent)."""
    for cwe in ("CWE-79", "CWE-78", "CWE-89", "CWE-94", "CWE-1336"):
        assert cwe in ACTIVE_CWES


def test_ingest_has_correct_dataset_name():
    ingest = OssfCveBenchmarkIngest(root=Path("/tmp/test-root"))
    assert ingest.dataset_name == "ossf-cve-benchmark"
    assert "ossf-cve-benchmark" in ingest.source_url
