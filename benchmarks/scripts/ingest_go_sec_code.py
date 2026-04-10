"""Ingest the flawgarden/go-sec-code-mutated benchmark.

Forks cokeBeer/go-sec-code (Beego educational vuln playground) and adds
bentoo-sarif truth files. Primary Phase 1 value: CWE-1336 SSTI via Sprig.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from benchmarks.runner.models import (
    BenchmarkCase,
    Finding,
    FindingKind,
    Language,
)
from benchmarks.runner.sarif import load_bentoo_sarif
from benchmarks.scripts._active_cwes import ACTIVE_CWES
from benchmarks.scripts.ingest_base import IngestBase


class GoSecCodeIngest(IngestBase):
    dataset_name = "go-sec-code-mutated"
    source_url = "https://github.com/flawgarden/go-sec-code-mutated"

    def ensure_downloaded(self) -> None:
        repo_dir = self.download_dir / "repo"
        if repo_dir.exists():
            print(f"  already cloned: {repo_dir}")
            return
        print(f"  cloning {self.source_url} ...")
        subprocess.run(
            ["git", "clone", "--depth", "1", self.source_url, str(repo_dir)],
            check=True,
        )

    def extract_cases(self) -> list[BenchmarkCase]:
        repo_dir = self.download_dir / "repo"
        cases: list[BenchmarkCase] = []
        for truth_path in sorted(repo_dir.rglob("truth.sarif")):
            case = self._build_case(truth_path, repo_dir)
            if case is not None:
                cases.append(case)
        return cases

    def _build_case(self, truth_path: Path, repo_dir: Path) -> BenchmarkCase | None:
        fail_findings = load_bentoo_sarif(truth_path)
        active = [f for f in fail_findings if f.cwe_id in ACTIVE_CWES]
        if not active:
            return None

        rel = truth_path.parent.relative_to(repo_dir)
        case_id = f"gosec-{str(rel).replace('/', '-')}"

        pass_findings = [
            Finding(cwe_id=f.cwe_id, kind=FindingKind.PASS, cve_id=f.cve_id,
                    location=f.location, message=f.message)
            for f in active
        ]

        return BenchmarkCase(
            case_id=case_id,
            project=str(rel.parts[0]) if rel.parts else "go-sec-code",
            language=Language.GO,
            vulnerable_version="HEAD",
            patched_version="HEAD-patched",
            ground_truth=active + pass_findings,
            published_date=None,
            source_dataset=self.dataset_name,
        )


def main() -> int:
    GoSecCodeIngest(root=Path("benchmarks")).run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
