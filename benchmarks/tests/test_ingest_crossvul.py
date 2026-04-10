"""Tests for CrossVul ingest."""
from pathlib import Path

from benchmarks.scripts._active_cwes import ACTIVE_CWE_DIGITS
from benchmarks.scripts.ingest_crossvul import _EXT_TO_LANG, CrossVulIngest


def test_targets_php_and_ruby():
    assert "php" in _EXT_TO_LANG
    assert "rb" in _EXT_TO_LANG


def test_filter_covers_phase1_cwe_digits():
    for digit in ("79", "78", "89", "1336"):
        assert digit in ACTIVE_CWE_DIGITS


def test_ingest_metadata():
    ingest = CrossVulIngest(root=Path("/tmp/test-root"))
    assert ingest.dataset_name == "crossvul"
    assert "zenodo.org" in ingest.source_url
