"""Tests for benchmarks.scripts.ingest_base."""
from datetime import date
from pathlib import Path

import pytest

from benchmarks.runner.models import (
    BenchmarkCase,
    CodeLocation,
    Finding,
    FindingKind,
    Language,
)
from benchmarks.scripts.ingest_base import IngestBase


class _FakeIngest(IngestBase):
    dataset_name = "fake-dataset"
    source_url = "https://example.com/fake"

    def __init__(self, root: Path) -> None:
        super().__init__(root)
        self.downloaded = False

    def ensure_downloaded(self) -> None:
        self.downloaded = True

    def extract_cases(self) -> list[BenchmarkCase]:
        return [
            BenchmarkCase(
                case_id="fake-case-1",
                project="acme/thing",
                language=Language.PYTHON,
                vulnerable_version="1.0.0",
                patched_version="1.0.1",
                ground_truth=[
                    Finding(
                        cwe_id="CWE-89", kind=FindingKind.FAIL, cve_id="CVE-2024-0",
                        location=CodeLocation(file="src/a.py", start_line=10, end_line=15,
                                              function_name="query"),
                    ),
                    Finding(
                        cwe_id="CWE-89", kind=FindingKind.PASS, cve_id="CVE-2024-0",
                        location=CodeLocation(file="src/a.py", start_line=10, end_line=17,
                                              function_name="query"),
                    ),
                ],
                published_date=date(2024, 3, 1),
                source_dataset="fake-dataset",
            ),
        ]


def test_run_invokes_all_phases(tmp_path: Path):
    ingest = _FakeIngest(root=tmp_path)
    ingest.run()
    assert ingest.downloaded is True

    # Materialized SARIF file should exist
    sarif_path = tmp_path / "external" / "fake-dataset" / "fake-case-1" / "truth.sarif"
    assert sarif_path.exists()

    # Manifest should exist and list 1 case
    manifest_path = tmp_path / "external" / "manifests" / "fake-dataset.manifest.json"
    assert manifest_path.exists()
    import json
    data = json.loads(manifest_path.read_text())
    assert data["dataset_name"] == "fake-dataset"
    assert data["case_count"] == 1
    assert data["source_url"] == "https://example.com/fake"
