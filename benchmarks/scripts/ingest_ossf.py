"""Ingest the OpenSSF CVE Benchmark for JavaScript/TypeScript.

Repo: https://github.com/ossf-cve-benchmark/ossf-cve-benchmark
Contains 218 real JS/TS CVEs with CWE tags and pre/post-patch commits.
"""
from __future__ import annotations

import json
import subprocess
import sys
from datetime import date, datetime
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


class OssfCveBenchmarkIngest(IngestBase):
    dataset_name = "ossf-cve-benchmark"
    source_url = "https://github.com/ossf-cve-benchmark/ossf-cve-benchmark"

    def ensure_downloaded(self) -> None:
        repo_dir = self.download_dir / "repo"
        if repo_dir.exists() and (repo_dir / "CVEs").exists():
            print(f"  already cloned: {repo_dir}")
            return
        print(f"  cloning {self.source_url} ...")
        subprocess.run(
            ["git", "clone", "--depth", "1", self.source_url, str(repo_dir)],
            check=True,
        )

    def extract_cases(self) -> list[BenchmarkCase]:
        repo_dir = self.download_dir / "repo"
        cves_dir = repo_dir / "CVEs"
        if not cves_dir.exists():
            for alt in ("cves", "data/CVEs", "data/cves"):
                if (repo_dir / alt).exists():
                    cves_dir = repo_dir / alt
                    break
            else:
                raise RuntimeError(f"Cannot locate CVEs dir under {repo_dir}")

        cases: list[BenchmarkCase] = []
        for json_file in sorted(cves_dir.glob("*.json")):
            case = self._build_case(json_file)
            if case is not None:
                cases.append(case)
        return cases

    def _build_case(self, json_file: Path) -> BenchmarkCase | None:
        try:
            meta = json.loads(json_file.read_text())
        except Exception:
            return None

        raw_cwes = meta.get("CWEs") or meta.get("cwe") or meta.get("cwes") or []
        if isinstance(raw_cwes, str):
            raw_cwes = [raw_cwes]
        cwes = {_normalize_cwe(c) for c in raw_cwes}
        active_cwes = cwes & ACTIVE_CWES
        if not active_cwes:
            return None

        canonical_cwe = sorted(active_cwes)[0]

        cve_id = meta.get("CVE") or meta.get("cve") or meta.get("cveId") or json_file.stem
        project = meta.get("repository") or meta.get("project") or meta.get("repo") or "unknown"

        # The OSSF format uses prePatch.weaknesses for vulnerable locations
        pre_patch = meta.get("prePatch") or {}
        weaknesses = pre_patch.get("weaknesses") or []
        vulnerable_files = meta.get("vulnerable_files") or meta.get("vulnerableFiles") or []
        if not vulnerable_files and weaknesses:
            vulnerable_files = [
                {"path": w.get("location", {}).get("file", "<unknown>"),
                 "start_line": w.get("location", {}).get("line", 1),
                 "end_line": w.get("location", {}).get("line", 1)}
                for w in weaknesses
            ]
        if not vulnerable_files:
            vulnerable_files = [{"path": meta.get("file", "<unknown>"),
                                 "start_line": meta.get("line", 1),
                                 "end_line": meta.get("line", 1)}]

        ground_truth: list[Finding] = []
        for vf in vulnerable_files:
            location = CodeLocation(
                file=vf.get("path", "<unknown>"),
                start_line=int(vf.get("start_line") or vf.get("startLine") or 1),
                end_line=int(vf.get("end_line") or vf.get("endLine") or 1),
                function_name=vf.get("function") or vf.get("method") or None,
            )
            ground_truth.append(Finding(
                cwe_id=canonical_cwe, kind=FindingKind.FAIL, cve_id=cve_id,
                location=location, message=cve_id,
            ))
            ground_truth.append(Finding(
                cwe_id=canonical_cwe, kind=FindingKind.PASS, cve_id=cve_id,
                location=location, message=cve_id,
            ))

        lang = Language.TYPESCRIPT if any(
            vf.get("path", "").endswith(".ts") for vf in vulnerable_files
        ) else Language.JAVASCRIPT

        published = _parse_date(meta.get("published") or meta.get("publishedDate"))

        return BenchmarkCase(
            case_id=f"ossf-{cve_id}",
            project=project,
            language=lang,
            vulnerable_version=meta.get("vulnerable_version")
                              or meta.get("vulnerableVersion")
                              or "pre-patch",
            patched_version=meta.get("patched_version")
                           or meta.get("patchedVersion")
                           or "post-patch",
            ground_truth=ground_truth,
            published_date=published,
            source_dataset=self.dataset_name,
        )


def _normalize_cwe(raw: str) -> str:
    """Normalize 'CWE-079' / '79' / 'cwe79' to 'CWE-79'."""
    digits = "".join(ch for ch in raw if ch.isdigit())
    if not digits:
        return raw
    return f"CWE-{int(digits)}"


def _parse_date(raw) -> date | None:
    if not raw:
        return None
    raw_str = str(raw).strip()
    # Try full ISO formats first, then fall back to YYYY-MM-DD prefix
    for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(raw_str, fmt).date()
        except ValueError:
            continue
    # Fall back: extract YYYY-MM-DD prefix from longer strings
    try:
        return datetime.strptime(raw_str[:10], "%Y-%m-%d").date()
    except ValueError:
        return None


def main() -> int:
    OssfCveBenchmarkIngest(root=Path("benchmarks")).run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
