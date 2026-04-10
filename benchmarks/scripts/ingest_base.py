"""Base class for benchmark ingestion scripts.

Tasks 13-20 all subclass this and override `ensure_downloaded()` and
`extract_cases()`. The base handles "write bentoo-sarif truth files + manifest".

Usage:
    class MyIngest(IngestBase):
        dataset_name = "ossf-cve-benchmark"
        source_url = "https://github.com/ossf-cve-benchmark/ossf-cve-benchmark"

        def ensure_downloaded(self) -> None: ...
        def extract_cases(self) -> list[BenchmarkCase]: ...

    if __name__ == "__main__":
        MyIngest(root=Path("benchmarks")).run()
"""
from __future__ import annotations

import json
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from pathlib import Path

from benchmarks.runner.models import BenchmarkCase
from benchmarks.runner.sarif import write_bentoo_sarif


class IngestBase(ABC):
    """Abstract base for benchmark ingestion scripts."""

    dataset_name: str  # override in subclass
    source_url: str    # override in subclass

    def __init__(self, root: Path) -> None:
        self.root = Path(root)
        self.download_dir = self.root / "external" / self.dataset_name
        self.manifest_dir = self.root / "external" / "manifests"

    @abstractmethod
    def ensure_downloaded(self) -> None:
        """Download or clone the dataset into self.download_dir. Idempotent."""

    @abstractmethod
    def extract_cases(self) -> list[BenchmarkCase]:
        """Parse the downloaded dataset and return a list of BenchmarkCase."""

    def run(self) -> None:
        print(f"[{self.dataset_name}] Ensuring download ...")
        self.download_dir.mkdir(parents=True, exist_ok=True)
        self.manifest_dir.mkdir(parents=True, exist_ok=True)
        self.ensure_downloaded()

        print(f"[{self.dataset_name}] Extracting cases ...")
        cases = self.extract_cases()
        print(f"[{self.dataset_name}] Extracted {len(cases)} cases")

        self.materialize(cases)
        self.write_manifest(cases)
        print(f"[{self.dataset_name}] Done.")

    def materialize(self, cases: list[BenchmarkCase]) -> None:
        """Write one bentoo-sarif truth file per case."""
        for case in cases:
            case_dir = self.download_dir / case.case_id
            case_dir.mkdir(parents=True, exist_ok=True)
            truth_path = case_dir / "truth.sarif"
            write_bentoo_sarif(truth_path, case.ground_truth,
                               tool_name=f"{self.dataset_name}-{case.case_id}")

    def write_manifest(self, cases: list[BenchmarkCase]) -> None:
        """Write a provenance manifest JSON for this dataset."""
        manifest = {
            "dataset_name": self.dataset_name,
            "source_url": self.source_url,
            "case_count": len(cases),
            "ingested_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "cases": [
                {
                    "case_id": c.case_id,
                    "project": c.project,
                    "language": c.language.value,
                    "vulnerable_version": c.vulnerable_version,
                    "patched_version": c.patched_version,
                    "published_date": c.published_date.isoformat() if c.published_date else None,
                    "fail_count": sum(1 for f in c.ground_truth if f.kind.value == "fail"),
                    "pass_count": sum(1 for f in c.ground_truth if f.kind.value == "pass"),
                }
                for c in cases
            ],
        }
        out_path = self.manifest_dir / f"{self.dataset_name}.manifest.json"
        out_path.write_text(json.dumps(manifest, indent=2))
