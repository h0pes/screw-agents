"""Tests for go-sec-code-mutated ingest."""
from pathlib import Path

from benchmarks.scripts._active_cwes import ACTIVE_CWES
from benchmarks.scripts.ingest_go_sec_code import GoSecCodeIngest


def test_covers_all_phase1_cwes():
    for cwe in ("CWE-78", "CWE-79", "CWE-89", "CWE-1336"):
        assert cwe in ACTIVE_CWES


def test_ingest_metadata():
    ingest = GoSecCodeIngest(root=Path("/tmp/test-root"))
    assert ingest.dataset_name == "go-sec-code-mutated"
    assert "go-sec-code-mutated" in ingest.source_url
