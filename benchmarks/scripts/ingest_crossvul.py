"""Ingest CrossVul (ESEC/FSE 2021) — real PHP and Ruby CVEs.

Source: https://zenodo.org/records/4734050
Dataset structure: CWE-XX/<lang_ext>/bad_<id> (vulnerable) + good_<id> (patched).
Files are plain source code, not directories. Each bad/good pair with the same
numeric ID forms a vulnerable/patched pair.
"""
from __future__ import annotations

import sys
import urllib.request
import zipfile
from collections import defaultdict
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


ZENODO_RECORD = "4734050"
TARBALL_URL = f"https://zenodo.org/records/{ZENODO_RECORD}/files/dataset.zip"

_EXT_TO_LANG: dict[str, Language] = {
    "php": Language.PHP,
    "rb": Language.RUBY,
}


class CrossVulIngest(IngestBase):
    dataset_name = "crossvul"
    source_url = f"https://zenodo.org/records/{ZENODO_RECORD}"

    def ensure_downloaded(self) -> None:
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
        """Locate the CrossVul root directory after extraction."""
        for name in ("CrossVul", "dataset", "crossvul", "dataset_final_sorted"):
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
        for cwe_dir in sorted(crossvul_root.iterdir()):
            if not cwe_dir.is_dir():
                continue
            cwe_id = _extract_cwe_id(cwe_dir.name)
            if cwe_id not in ACTIVE_CWE_DIGITS:
                continue

            # Under each CWE dir, language extension subdirs (php, rb, etc.)
            for lang_dir in sorted(cwe_dir.iterdir()):
                if not lang_dir.is_dir():
                    continue
                lang = _EXT_TO_LANG.get(lang_dir.name)
                if lang is None:
                    continue

                # Collect bad/good pairs by numeric ID
                bad_files: dict[str, Path] = {}
                good_files: dict[str, Path] = {}
                for f in sorted(lang_dir.iterdir()):
                    if not f.is_file():
                        continue
                    if f.name.startswith("bad_"):
                        pair_id = f.name[4:]  # strip "bad_" prefix
                        bad_files[pair_id] = f
                    elif f.name.startswith("good_"):
                        pair_id = f.name[5:]  # strip "good_" prefix
                        good_files[pair_id] = f

                # Build a case for each bad/good pair
                for pair_id, bad_path in bad_files.items():
                    good_path = good_files.get(pair_id)
                    if good_path is None:
                        continue

                    vuln_code = bad_path.read_text(errors="replace")
                    fix_code = good_path.read_text(errors="replace")
                    vuln_lines = len(vuln_code.splitlines())
                    fix_lines = len(fix_code.splitlines())

                    loc = CodeLocation(
                        file=bad_path.name,
                        start_line=1,
                        end_line=max(vuln_lines, 1),
                    )
                    fail_finding = Finding(
                        cwe_id=f"CWE-{cwe_id}",
                        kind=FindingKind.FAIL,
                        cve_id=f"crossvul-{pair_id}",
                        location=loc,
                        message=vuln_code,
                    )
                    pass_finding = Finding(
                        cwe_id=f"CWE-{cwe_id}",
                        kind=FindingKind.PASS,
                        cve_id=f"crossvul-{pair_id}",
                        location=CodeLocation(
                            file=good_path.name,
                            start_line=1,
                            end_line=max(fix_lines, 1),
                        ),
                        message=fix_code,
                    )

                    cases.append(BenchmarkCase(
                        case_id=f"crossvul-{cwe_id}-{lang_dir.name}-{pair_id}",
                        project=f"crossvul-{lang_dir.name}",
                        language=lang,
                        vulnerable_version="bad",
                        patched_version="good",
                        ground_truth=[fail_finding, pass_finding],
                        published_date=None,
                        source_dataset=self.dataset_name,
                    ))

        return cases


def _extract_cwe_id(name: str) -> str:
    """Extract numeric CWE ID from directory name like 'CWE-79'."""
    digits = "".join(ch for ch in name if ch.isdigit())
    return digits


def main() -> int:
    CrossVulIngest(root=Path("benchmarks")).run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
