"""Extract source code from benchmark datasets for evaluation.

Each dataset stores code differently. This module abstracts those differences
behind a single `extract_code_for_case()` interface.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from benchmarks.runner.models import BenchmarkCase, FindingKind

logger = logging.getLogger(__name__)


class CodeVariant(str, Enum):
    VULNERABLE = "vulnerable"
    PATCHED = "patched"


@dataclass
class ExtractedCode:
    """A piece of source code extracted from a benchmark dataset."""
    file_path: str
    content: str
    language: str


_RC_LANG_DIRS = {
    "reality-check-csharp": "csharp",
    "reality-check-python": "python",
    "reality-check-java": "java",
}


def extract_code_for_case(
    case: BenchmarkCase,
    variant: CodeVariant,
    benchmarks_external_dir: Path,
) -> list[ExtractedCode]:
    """Extract source code for a benchmark case."""
    ds = case.source_dataset

    if ds in _RC_LANG_DIRS:
        return _extract_reality_check(case, variant, benchmarks_external_dir)
    elif ds == "crossvul":
        return _extract_crossvul(case, variant, benchmarks_external_dir)
    elif ds in ("go-sec-code-mutated", "skf-labs-mutated"):
        return _extract_monolithic(case, variant, benchmarks_external_dir)
    elif ds == "ossf-cve-benchmark":
        return _extract_ossf(case, variant, benchmarks_external_dir)
    else:
        logger.warning("Unsupported dataset for code extraction: %s", ds)
        return []


def _extract_reality_check(
    case: BenchmarkCase, variant: CodeVariant, ext_dir: Path,
) -> list[ExtractedCode]:
    lang_subdir = _RC_LANG_DIRS[case.source_dataset]
    repo_dir = ext_dir / case.source_dataset / "repo"
    if not repo_dir.exists():
        raise FileNotFoundError(f"reality-check repo not found: {repo_dir}")

    version = case.vulnerable_version if variant == CodeVariant.VULNERABLE else case.patched_version
    projects_dir = repo_dir / lang_subdir / "projects" / case.project / version

    if not projects_dir.exists():
        logger.warning("Version dir not found: %s", projects_dir)
        return []

    kind = FindingKind.FAIL if variant == CodeVariant.VULNERABLE else FindingKind.PASS
    truth_files = {f.location.file for f in case.ground_truth if f.kind == kind}

    results = []
    for rel_file in truth_files:
        file_path = projects_dir / rel_file
        if not file_path.exists():
            matches = list(projects_dir.rglob(Path(rel_file).name))
            if matches:
                file_path = matches[0]
            else:
                logger.warning("File not found: %s", file_path)
                continue
        results.append(ExtractedCode(
            file_path=rel_file,
            content=file_path.read_text(errors="replace"),
            language=case.language.value,
        ))
    return results


def _extract_crossvul(
    case: BenchmarkCase, variant: CodeVariant, ext_dir: Path,
) -> list[ExtractedCode]:
    dataset_dir = ext_dir / "crossvul"
    if not dataset_dir.exists():
        raise FileNotFoundError(f"CrossVul dir not found: {dataset_dir}")

    kind = FindingKind.FAIL if variant == CodeVariant.VULNERABLE else FindingKind.PASS
    results = []
    for f in case.ground_truth:
        if f.kind != kind:
            continue
        if f.message:
            results.append(ExtractedCode(
                file_path=f.location.file,
                content=f.message,
                language=case.language.value,
            ))
            continue
        # Fallback: try to read from disk
        parts = case.case_id.split("-")
        if len(parts) >= 4:
            cwe_digits = parts[1]
            ext = parts[2]
            pair_id = "-".join(parts[3:])
            prefix = "bad_" if variant == CodeVariant.VULNERABLE else "good_"
            file_path = _find_crossvul_root(dataset_dir) / f"CWE-{cwe_digits}" / ext / f"{prefix}{pair_id}"
            if file_path.exists():
                results.append(ExtractedCode(
                    file_path=f.location.file,
                    content=file_path.read_text(errors="replace"),
                    language=case.language.value,
                ))
    return results


def _find_crossvul_root(dataset_dir: Path) -> Path:
    """Locate the CrossVul root after extraction (same logic as ingest)."""
    for name in ("CrossVul", "dataset", "crossvul", "dataset_final_sorted"):
        candidate = dataset_dir / name
        if candidate.is_dir():
            return candidate
    for child in dataset_dir.iterdir():
        if child.is_dir() and child.name.upper().startswith("CWE"):
            return dataset_dir
    return dataset_dir


def _extract_monolithic(
    case: BenchmarkCase, variant: CodeVariant, ext_dir: Path,
) -> list[ExtractedCode]:
    """Extract from monolithic repos (go-sec-code, skf-labs).
    No patched version available — return empty for PATCHED variant."""
    if variant == CodeVariant.PATCHED:
        return []

    repo_dir = ext_dir / case.source_dataset / "repo"
    if not repo_dir.exists():
        raise FileNotFoundError(f"Monolithic repo not found: {repo_dir}")

    fail_files = {f.location.file for f in case.ground_truth if f.kind == FindingKind.FAIL}

    results = []
    for rel_file in fail_files:
        file_path = repo_dir / rel_file
        if not file_path.exists():
            logger.warning("File not found in monolithic repo: %s", file_path)
            continue
        results.append(ExtractedCode(
            file_path=rel_file,
            content=file_path.read_text(errors="replace"),
            language=case.language.value,
        ))
    return results


def _extract_ossf(
    case: BenchmarkCase, variant: CodeVariant, ext_dir: Path,
) -> list[ExtractedCode]:
    """Extract from OSSF CVE benchmark."""
    repo_dir = ext_dir / "ossf-cve-benchmark" / "repo"
    if not repo_dir.exists():
        raise FileNotFoundError(f"OSSF repo not found: {repo_dir}")

    kind = FindingKind.FAIL if variant == CodeVariant.VULNERABLE else FindingKind.PASS
    truth_files = {f.location.file for f in case.ground_truth if f.kind == kind}

    results = []
    for rel_file in truth_files:
        file_path = repo_dir / rel_file
        if not file_path.exists():
            matches = list(repo_dir.rglob(Path(rel_file).name))
            if matches:
                file_path = matches[0]
            else:
                logger.warning("OSSF file not found: %s", rel_file)
                continue
        results.append(ExtractedCode(
            file_path=rel_file,
            content=file_path.read_text(errors="replace"),
            language=case.language.value,
        ))
    return results
