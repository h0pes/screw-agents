"""Tests for skf-labs-mutated ingest."""
from pathlib import Path

from benchmarks.scripts._active_cwes import ACTIVE_CWES
from benchmarks.scripts.ingest_skf_labs import SkfLabsIngest


def test_covers_ssti():
    assert "CWE-1336" in ACTIVE_CWES


def test_ingest_metadata():
    ingest = SkfLabsIngest(root=Path("/tmp/test-root"))
    assert ingest.dataset_name == "skf-labs-mutated"
