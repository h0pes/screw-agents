"""Ingest the flawgarden/reality-check Python subset.

bentoo-sarif passthrough: reality-check already publishes truth.sarif files.
"""
from __future__ import annotations

import csv
import subprocess
import sys
from datetime import date
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


class RealityCheckPythonIngest(IngestBase):
    dataset_name = "reality-check-python"
    source_url = "https://github.com/flawgarden/reality-check"

    def ensure_downloaded(self) -> None:
        repo_dir = self.download_dir / "repo"
        if repo_dir.exists() and (repo_dir / "python").exists():
            print(f"  already cloned: {repo_dir}")
            return
        print(f"  cloning {self.source_url} ...")
        subprocess.run(
            ["git", "clone", "--depth", "1", self.source_url, str(repo_dir)],
            check=True,
        )

    def extract_cases(self) -> list[BenchmarkCase]:
        repo_dir = self.download_dir / "repo"
        csv_path = repo_dir / "python" / "cves_db.csv"
        if not csv_path.exists():
            raise RuntimeError(f"cves_db.csv not found at {csv_path}")

        cases: list[BenchmarkCase] = []
        with csv_path.open() as f:
            reader = csv.DictReader(f)
            for row in reader:
                case = self._build_case(row, repo_dir)
                if case is not None:
                    cases.append(case)
        return cases

    def _build_case(self, row: dict, repo_dir: Path) -> BenchmarkCase | None:
        cwe = _normalize_cwe(row.get("cwe", ""))
        if cwe not in ACTIVE_CWES:
            return None

        project = row.get("project", "unknown")
        cve = row.get("cve", "UNKNOWN")
        vul_version = row.get("vul_version", "")
        patch_version = row.get("patch_version", "")

        markup_path = (
            repo_dir / "python" / "markup"
            / project / f"{project}-{vul_version}" / "truth.sarif"
        )
        if not markup_path.exists():
            print(f"  WARN: missing truth.sarif for {project} {vul_version}: {markup_path}")
            return None

        fail_findings = load_bentoo_sarif(markup_path)
        pass_findings = [
            Finding(
                cwe_id=f.cwe_id, kind=FindingKind.PASS, cve_id=cve,
                location=f.location, message=cve,
            )
            for f in fail_findings
        ]

        return BenchmarkCase(
            case_id=f"rc-python-{project}-{cve}",
            project=project,
            language=Language.PYTHON,
            vulnerable_version=vul_version,
            patched_version=patch_version,
            ground_truth=fail_findings + pass_findings,
            published_date=None,
            source_dataset=self.dataset_name,
        )


def _normalize_cwe(raw: str) -> str:
    digits = "".join(ch for ch in raw if ch.isdigit())
    return f"CWE-{int(digits)}" if digits else raw


def main() -> int:
    RealityCheckPythonIngest(root=Path("benchmarks")).run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
