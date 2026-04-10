"""Ingest Vul4J — 79 Java CVEs with reproducible PoV test cases.

Source: https://github.com/tuhh-softsec/vul4j
"""
from __future__ import annotations

import csv
import subprocess
import sys
from pathlib import Path

from benchmarks.runner.models import (
    BenchmarkCase,
    CodeLocation,
    Finding,
    FindingKind,
    Language,
)
from benchmarks.scripts._active_cwes import ACTIVE_CWES
from benchmarks.scripts.ingest_base import IngestBase


class Vul4JIngest(IngestBase):
    dataset_name = "vul4j"
    source_url = "https://github.com/tuhh-softsec/vul4j"

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
        candidates = [
            repo_dir / "vul4j" / "data" / "vulnerability_list.csv",
            repo_dir / "data" / "vulnerability_list.csv",
            repo_dir / "vul4j" / "data" / "vulnerability_data.csv",
            repo_dir / "data" / "vulnerability_data.csv",
        ]
        csv_path = next((p for p in candidates if p.exists()), None)
        if csv_path is None:
            print(f"  WARN: vulnerability CSV not found; tried {candidates}")
            return []

        cases: list[BenchmarkCase] = []
        with csv_path.open() as f:
            reader = csv.DictReader(f)
            for row in reader:
                case = self._build_case(row, repo_dir)
                if case is not None:
                    cases.append(case)
        return cases

    def _build_case(self, row: dict, repo_dir: Path) -> BenchmarkCase | None:
        cwe_raw = row.get("cwe_id") or row.get("cwe") or row.get("CWE") or ""
        cwe_id = _normalize_cwe(cwe_raw)
        if cwe_id not in ACTIVE_CWES:
            return None

        cve = row.get("cve_id") or row.get("cve") or row.get("CVE") or "UNKNOWN"
        project = row.get("project_id") or row.get("project") or row.get("repo") or "unknown"
        files_raw = row.get("human_patch") or row.get("files") or row.get("modified_files") or ""

        files = [p.strip() for p in files_raw.replace(",", ";").split(";") if p.strip()]
        if not files:
            files = ["<unknown>"]

        fail_findings: list[Finding] = []
        pass_findings: list[Finding] = []
        for path in files:
            loc = CodeLocation(file=path, start_line=1, end_line=1)
            fail_findings.append(Finding(
                cwe_id=cwe_id, kind=FindingKind.FAIL, cve_id=cve,
                location=loc, message=cve,
            ))
            pass_findings.append(Finding(
                cwe_id=cwe_id, kind=FindingKind.PASS, cve_id=cve,
                location=loc, message=cve,
            ))

        return BenchmarkCase(
            case_id=f"vul4j-{cve}",
            project=project,
            language=Language.JAVA,
            vulnerable_version=row.get("buggy_commit") or "buggy",
            patched_version=row.get("fixed_commit") or "fixed",
            ground_truth=fail_findings + pass_findings,
            published_date=None,
            source_dataset=self.dataset_name,
        )


def _normalize_cwe(raw: str) -> str:
    digits = "".join(ch for ch in raw if ch.isdigit())
    return f"CWE-{int(digits)}" if digits else raw


def main() -> int:
    Vul4JIngest(root=Path("benchmarks")).run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
