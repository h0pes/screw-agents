"""Ingest CrossVul (ESEC/FSE 2021) — real PHP and Ruby CVEs.

Source: https://zenodo.org/record/4734050
Dataset structure: tarball with one directory per CWE, subdirectories per CVE
containing vuln/ and fix/ code snapshots.
"""
from __future__ import annotations

import sys
import tarfile
import urllib.request
import zipfile
from pathlib import Path

from benchmarks.runner.models import (
    BenchmarkCase,
    CodeLocation,
    Finding,
    FindingKind,
    Language,
)
from benchmarks.scripts._active_cwes import ACTIVE_CWE_DIGITS
from benchmarks.scripts.ingest_base import IngestBase


CROSSVUL_LANGUAGES = {"php", "ruby"}
ZENODO_RECORD = "4734050"
TARBALL_URL = f"https://zenodo.org/records/{ZENODO_RECORD}/files/dataset.zip"


class CrossVulIngest(IngestBase):
    dataset_name = "crossvul"
    source_url = f"https://zenodo.org/records/{ZENODO_RECORD}"

    def ensure_downloaded(self) -> None:
        # Check any of the possible extraction directory names.
        if self._find_crossvul_root() is not None:
            print(f"  already extracted: {self._find_crossvul_root()}")
            return

        archive = self.download_dir / "dataset.zip"
        if not archive.exists():
            print(f"  downloading {TARBALL_URL} ...")
            urllib.request.urlretrieve(TARBALL_URL, archive)

        print(f"  extracting {archive} ...")
        with zipfile.ZipFile(archive, "r") as zf:
            zf.extractall(self.download_dir)

    def _find_crossvul_root(self) -> Path | None:
        """Locate the CrossVul root directory after extraction.

        The zip may extract to CrossVul/, dataset/, or place CWE dirs directly.
        """
        for name in ("CrossVul", "dataset", "crossvul"):
            candidate = self.download_dir / name
            if candidate.is_dir():
                return candidate
        # Check if CWE dirs exist directly in download_dir
        for child in self.download_dir.iterdir():
            if child.is_dir() and child.name.upper().startswith("CWE"):
                return self.download_dir
        return None

    def extract_cases(self) -> list[BenchmarkCase]:
        crossvul_root = self._find_crossvul_root()
        if crossvul_root is None:
            raise RuntimeError(f"CrossVul not extracted under {self.download_dir}")

        cases: list[BenchmarkCase] = []
        for cwe_dir in crossvul_root.iterdir():
            if not cwe_dir.is_dir():
                continue
            cwe_id = _extract_cwe_id(cwe_dir.name)
            if cwe_id not in ACTIVE_CWE_DIGITS:
                continue
            for cve_dir in cwe_dir.iterdir():
                if not cve_dir.is_dir():
                    continue
                case = self._build_case(cve_dir, cwe_id)
                if case is not None:
                    cases.append(case)
        return cases

    def _build_case(self, cve_dir: Path, cwe_id: str) -> BenchmarkCase | None:
        vuln_dir = cve_dir / "vuln"
        fix_dir = cve_dir / "fix"
        if not vuln_dir.exists() or not fix_dir.exists():
            return None

        lang = _detect_language(vuln_dir)
        if lang is None:
            return None

        fail_findings: list[Finding] = []
        pass_findings: list[Finding] = []
        for vuln_file in sorted(vuln_dir.rglob("*")):
            if not vuln_file.is_file():
                continue
            rel = vuln_file.relative_to(vuln_dir)
            code = vuln_file.read_text(errors="replace")
            line_count = len(code.splitlines())
            loc = CodeLocation(
                file=str(rel), start_line=1, end_line=max(line_count, 1),
            )
            fail_findings.append(Finding(
                cwe_id=f"CWE-{cwe_id}", kind=FindingKind.FAIL,
                cve_id=cve_dir.name, location=loc, message=cve_dir.name,
            ))
            pass_findings.append(Finding(
                cwe_id=f"CWE-{cwe_id}", kind=FindingKind.PASS,
                cve_id=cve_dir.name, location=loc, message=cve_dir.name,
            ))

        if not fail_findings:
            return None

        return BenchmarkCase(
            case_id=f"crossvul-{cwe_id}-{cve_dir.name}",
            project=cve_dir.name,
            language=lang,
            vulnerable_version="vuln",
            patched_version="fix",
            ground_truth=fail_findings + pass_findings,
            published_date=None,
            source_dataset=self.dataset_name,
        )


def _extract_cwe_id(name: str) -> str:
    digits = "".join(ch for ch in name if ch.isdigit())
    return digits


def _detect_language(vuln_dir: Path) -> Language | None:
    for f in vuln_dir.rglob("*"):
        if not f.is_file():
            continue
        suffix = f.suffix.lower()
        if suffix in (".php",):
            return Language.PHP
        if suffix in (".rb",):
            return Language.RUBY
    return None


def main() -> int:
    CrossVulIngest(root=Path("benchmarks")).run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
