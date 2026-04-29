"""Extract source code from benchmark datasets for evaluation.

Each dataset stores code differently. This module abstracts those differences
behind a single `extract_code_for_case()` interface.
"""
from __future__ import annotations

import json
import logging
import subprocess
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from urllib.parse import quote

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
    context_files: list[ExtractedCode] = field(default_factory=list)


_RC_LANG_DIRS = {
    "reality-check-csharp": "csharp",
    "reality-check-python": "python",
    "reality-check-java": "java",
}

_MAX_FILES_PER_CASE = 10  # cap to avoid excessive Claude calls for large cases


def extract_code_for_case(
    case: BenchmarkCase,
    variant: CodeVariant,
    benchmarks_external_dir: Path,
    include_related_context: bool = False,
) -> list[ExtractedCode]:
    """Extract source code for a benchmark case."""
    ds = case.source_dataset

    if ds in _RC_LANG_DIRS:
        return _extract_reality_check(
            case,
            variant,
            benchmarks_external_dir,
            include_related_context=include_related_context,
        )
    elif ds == "crossvul":
        return _extract_crossvul(case, variant, benchmarks_external_dir)
    elif ds in ("go-sec-code-mutated", "skf-labs-mutated"):
        return _extract_monolithic(case, variant, benchmarks_external_dir)
    elif ds == "morefixes":
        return _extract_morefixes(case, variant, benchmarks_external_dir)
    elif ds == "ossf-cve-benchmark":
        return _extract_ossf(case, variant, benchmarks_external_dir)
    elif ds == "rust-d01-real-cves":
        return _extract_rust_d01(case, variant, benchmarks_external_dir)
    else:
        logger.warning("Unsupported dataset for code extraction: %s", ds)
        return []


def _extract_reality_check(
    case: BenchmarkCase,
    variant: CodeVariant,
    ext_dir: Path,
    *,
    include_related_context: bool = False,
) -> list[ExtractedCode]:
    lang_subdir = _RC_LANG_DIRS[case.source_dataset]
    repo_dir = ext_dir / case.source_dataset / "repo"
    if not repo_dir.exists():
        raise FileNotFoundError(f"reality-check repo not found: {repo_dir}")

    version = (
        case.vulnerable_version
        if variant == CodeVariant.VULNERABLE
        else case.patched_version
    )
    # Historical reality-check materialization used benchmark/ in fixtures,
    # while the restored upstream datasets use markup/.
    projects_dir = repo_dir / lang_subdir / "benchmark" / case.project / version
    if not projects_dir.exists():
        projects_dir = repo_dir / lang_subdir / "markup" / case.project / version

    if not projects_dir.exists():
        logger.warning(
            "Version dir not found: %s (run bootstrap.sh or download projects first)",
            projects_dir,
        )
        return []

    kind = FindingKind.FAIL if variant == CodeVariant.VULNERABLE else FindingKind.PASS
    truth_files = sorted(
        {f.location.file for f in case.ground_truth if f.kind == kind}
    )

    loaded_by_rel_path: dict[str, ExtractedCode] = {}
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
        piece = ExtractedCode(
            file_path=rel_file,
            content=file_path.read_text(errors="replace"),
            language=case.language.value,
        )
        loaded_by_rel_path[rel_file] = piece
        results.append(piece)
        if len(results) >= _MAX_FILES_PER_CASE:
            logger.info("Capped at %d files for reality-check case", _MAX_FILES_PER_CASE)
            break
    if include_related_context:
        _attach_related_context(results, loaded_by_rel_path)
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
        if f.message and len(f.message) >= 50:
            results.append(ExtractedCode(
                file_path=f.location.file,
                content=f.message,
                language=case.language.value,
            ))
            continue
        elif f.message:
            logger.debug("Skipping CrossVul case with short content: %s (%d chars)",
                         f.location.file, len(f.message))
            continue
        # Fallback: try to read from disk
        parts = case.case_id.split("-")
        if len(parts) >= 4:
            cwe_digits = parts[1]
            ext = parts[2]
            pair_id = "-".join(parts[3:])
            prefix = "bad_" if variant == CodeVariant.VULNERABLE else "good_"
            file_path = (
                _find_crossvul_root(dataset_dir)
                / f"CWE-{cwe_digits}"
                / ext
                / f"{prefix}{pair_id}"
            )
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


def _attach_related_context(
    results: list[ExtractedCode],
    loaded_by_rel_path: dict[str, ExtractedCode],
) -> None:
    """Attach same-variant truth files as context for multi-file cases."""
    for piece in results:
        piece.context_files = [
            context
            for rel_file, context in sorted(loaded_by_rel_path.items())
            if rel_file != piece.file_path
        ]


def _extract_monolithic(
    case: BenchmarkCase, variant: CodeVariant, ext_dir: Path,
) -> list[ExtractedCode]:
    """Extract from monolithic repos (go-sec-code, skf-labs).
    No patched version available — return empty for PATCHED variant.
    Caps at _MAX_FILES_PER_CASE to avoid excessive Claude calls.
    """
    if variant == CodeVariant.PATCHED:
        return []

    repo_dir = ext_dir / case.source_dataset / "repo"
    if not repo_dir.exists():
        raise FileNotFoundError(f"Monolithic repo not found: {repo_dir}")

    fail_files = sorted(
        {f.location.file for f in case.ground_truth if f.kind == FindingKind.FAIL}
    )

    results = []
    for rel_file in fail_files:
        file_path = repo_dir / rel_file
        # Fallback: some repos (skf-labs) have an extra subdirectory
        if not file_path.exists():
            for subdir in repo_dir.iterdir():
                if subdir.is_dir() and not subdir.name.startswith("."):
                    candidate = subdir / rel_file
                    if candidate.exists():
                        file_path = candidate
                        break
        if not file_path.exists():
            logger.warning("File not found in monolithic repo: %s", file_path)
            continue
        content = file_path.read_text(errors="replace")
        if len(content) < 50:
            logger.debug(
                "Skipping file with too-short content: %s (%d chars)",
                rel_file,
                len(content),
            )
            continue
        results.append(ExtractedCode(
            file_path=rel_file,
            content=content,
            language=case.language.value,
        ))
        if len(results) >= _MAX_FILES_PER_CASE:
            logger.info("Capped at %d files for case %s", _MAX_FILES_PER_CASE, case.case_id)
            break
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
    truth_by_file = {
        rel_file: [
            finding for finding in case.ground_truth
            if finding.kind == kind and finding.location.file == rel_file
        ]
        for rel_file in truth_files
    }

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
        content = file_path.read_text(errors="replace")
        line_count = len(content.splitlines())
        if not any(
            finding.location.end_line <= line_count
            for finding in truth_by_file[rel_file]
        ):
            logger.warning(
                "OSSF extracted file does not cover truth line range: "
                "%s resolved to %s with %d line(s)",
                rel_file,
                file_path.relative_to(repo_dir),
                line_count,
            )
            continue
        results.append(ExtractedCode(
            file_path=rel_file,
            content=content,
            language=case.language.value,
        ))
    return results


def _extract_morefixes(
    case: BenchmarkCase,
    variant: CodeVariant,
    ext_dir: Path,
) -> list[ExtractedCode]:
    """Extract MoreFixes code snapshots materialized beside truth.sarif."""
    case_dir = ext_dir / "morefixes" / case.case_id
    if not case_dir.exists():
        raise FileNotFoundError(f"MoreFixes case dir not found: {case_dir}")

    kind = FindingKind.FAIL if variant == CodeVariant.VULNERABLE else FindingKind.PASS
    snapshot_dir = case_dir / "code" / variant.value
    results: list[ExtractedCode] = []
    for rel_file in sorted({f.location.file for f in case.ground_truth if f.kind == kind}):
        snapshot_path = snapshot_dir / _snapshot_name(rel_file)
        if not snapshot_path.exists():
            logger.warning("MoreFixes snapshot not found: %s", snapshot_path)
            continue
        content = snapshot_path.read_text(errors="replace")
        if len(content) < 50:
            logger.debug(
                "Skipping MoreFixes snapshot with too-short content: %s (%d chars)",
                rel_file,
                len(content),
            )
            continue
        results.append(
            ExtractedCode(
                file_path=rel_file,
                content=content,
                language=case.language.value,
            )
        )
        if len(results) >= _MAX_FILES_PER_CASE:
            logger.info(
                "Capped at %d files for MoreFixes case %s",
                _MAX_FILES_PER_CASE,
                case.case_id,
            )
            break
    return results


def _extract_rust_d01(
    case: BenchmarkCase,
    variant: CodeVariant,
    ext_dir: Path,
) -> list[ExtractedCode]:
    """Extract Rust D-01 code from a local git clone described by provenance."""
    case_dir = ext_dir / "rust-d01-real-cves" / case.case_id
    provenance_path = case_dir / "provenance.json"
    if not provenance_path.exists():
        raise FileNotFoundError(f"Rust D-01 provenance not found: {provenance_path}")

    provenance = json.loads(provenance_path.read_text(encoding="utf-8"))
    repo_dir = _rust_d01_repo_dir(case, ext_dir, case_dir)
    if repo_dir is None:
        raise FileNotFoundError(
            "Rust D-01 local repo clone not found. Expected one of: "
            f"{case_dir / 'repo'}, "
            f"{ext_dir / 'rust-d01-real-cves' / 'repos' / case.project.replace('/', '__')}, "
            f"{ext_dir / 'rust-d01-real-cves' / 'repos' / case.project}"
        )

    kind = FindingKind.FAIL if variant == CodeVariant.VULNERABLE else FindingKind.PASS
    ref_key = "vulnerable_ref" if variant == CodeVariant.VULNERABLE else "patched_ref"
    ref = str(provenance[ref_key])
    results: list[ExtractedCode] = []
    for rel_file in sorted({f.location.file for f in case.ground_truth if f.kind == kind}):
        content = _git_show_file(repo_dir, ref, rel_file)
        if content is None:
            continue
        results.append(
            ExtractedCode(
                file_path=rel_file,
                content=content,
                language=case.language.value,
            )
        )
        if len(results) >= _MAX_FILES_PER_CASE:
            logger.info(
                "Capped at %d files for Rust D-01 case %s",
                _MAX_FILES_PER_CASE,
                case.case_id,
            )
            break
    return results


def _snapshot_name(rel_file: str) -> str:
    return quote(rel_file, safe="")


def _rust_d01_repo_dir(case: BenchmarkCase, ext_dir: Path, case_dir: Path) -> Path | None:
    dataset_dir = ext_dir / "rust-d01-real-cves"
    candidates = [
        case_dir / "repo",
        dataset_dir / "repos" / case.project.replace("/", "__"),
        dataset_dir / "repos" / case.project,
    ]
    return next((candidate for candidate in candidates if candidate.is_dir()), None)


def _git_show_file(repo_dir: Path, ref: str, rel_file: str) -> str | None:
    result = subprocess.run(  # noqa: S603
        ["git", "-C", str(repo_dir), "show", f"{ref}:{rel_file}"],  # noqa: S607
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        logger.warning(
            "Rust D-01 file not found at %s:%s: %s",
            ref,
            rel_file,
            result.stderr.strip(),
        )
        return None
    return result.stdout
