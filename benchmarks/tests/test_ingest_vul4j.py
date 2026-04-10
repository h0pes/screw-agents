"""Tests for Vul4J ingest."""
from pathlib import Path

from benchmarks.scripts._active_cwes import ACTIVE_CWES
from benchmarks.scripts.ingest_vul4j import Vul4JIngest


def test_filter_covers_phase1():
    for cwe in ("CWE-78", "CWE-79", "CWE-89"):
        assert cwe in ACTIVE_CWES


def test_ingest_metadata():
    ingest = Vul4JIngest(root=Path("/tmp/test-root"))
    assert ingest.dataset_name == "vul4j"
    assert "vul4j" in ingest.source_url.lower()
