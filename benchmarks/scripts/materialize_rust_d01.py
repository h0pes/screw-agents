#!/usr/bin/env python3
"""Materialize reviewed D-01 Rust real-CVE seeds as benchmark truth files."""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import date
from datetime import datetime
from datetime import timezone
from pathlib import Path
from typing import Any

# Support direct invocation:
# `uv run python benchmarks/scripts/materialize_rust_d01.py`
_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from benchmarks.runner.models import (  # noqa: E402
    BenchmarkCase,
    CodeLocation,
    Finding,
    FindingKind,
    Language,
)
from benchmarks.scripts.ingest_base import IngestBase  # noqa: E402


DEFAULT_SEEDS_PATH = Path("benchmarks/data/rust-d01-reviewed-seeds.json")
DATASET_NAME = "rust-d01-real-cves"


class RustD01Materializer(IngestBase):
    """Turn reviewed Rust D-01 seeds into SARIF truth and manifest files."""

    dataset_name = DATASET_NAME
    source_url = "benchmarks/data/rust-d01-reviewed-seeds.json"

    def __init__(self, root: Path, seeds_path: Path = DEFAULT_SEEDS_PATH) -> None:
        super().__init__(root)
        self.seeds_path = Path(seeds_path)
        self._seeds_by_case_id: dict[str, dict[str, Any]] = {}

    def ensure_downloaded(self) -> None:
        self.download_dir.mkdir(parents=True, exist_ok=True)

    def extract_cases(self) -> list[BenchmarkCase]:
        payload = json.loads(self.seeds_path.read_text(encoding="utf-8"))
        cases = [_seed_to_case(seed) for seed in payload.get("seeds", [])]
        self._seeds_by_case_id = {
            case.case_id: seed
            for case, seed in zip(cases, payload.get("seeds", []), strict=True)
        }
        return cases

    def materialize(self, cases: list[BenchmarkCase]) -> None:
        super().materialize(cases)
        for case in cases:
            seed = self._seeds_by_case_id[case.case_id]
            provenance = {
                "schema_version": "rust-d01-case-provenance/v1",
                "case_id": case.case_id,
                "ghsa_id": seed["ghsa_id"],
                "cve_id": seed["cve_id"],
                "aliases": seed.get("aliases", []),
                "repo_url": seed["repo_url"],
                "vulnerable_ref": seed["vulnerable_ref"],
                "patched_ref": seed["patched_ref"],
                "source_urls": seed.get("source_urls", []),
                "trace_notes": seed.get("trace_notes"),
                "affected_files": seed.get("affected_files", []),
            }
            out = self.download_dir / case.case_id / "provenance.json"
            out.write_text(json.dumps(provenance, indent=2, sort_keys=True) + "\n")

    def write_manifest(self, cases: list[BenchmarkCase]) -> None:
        """Write manifest while avoiding timestamp-only churn on regeneration."""
        manifest_cases = [
            {
                "case_id": c.case_id,
                "project": c.project,
                "language": c.language.value,
                "vulnerable_version": c.vulnerable_version,
                "patched_version": c.patched_version,
                "published_date": (
                    c.published_date.isoformat() if c.published_date else None
                ),
                "fail_count": sum(
                    1 for finding in c.ground_truth if finding.kind.value == "fail"
                ),
                "pass_count": sum(
                    1 for finding in c.ground_truth if finding.kind.value == "pass"
                ),
            }
            for c in cases
        ]

        out_path = self.manifest_dir / f"{self.dataset_name}.manifest.json"
        previous = _read_existing_manifest(out_path)
        if previous and previous.get("cases") == manifest_cases:
            ingested_at = previous.get("ingested_at")
        else:
            ingested_at = datetime.now(timezone.utc).isoformat(timespec="seconds")

        manifest = {
            "dataset_name": self.dataset_name,
            "source_url": self.source_url,
            "case_count": len(cases),
            "ingested_at": ingested_at,
            "cases": manifest_cases,
        }
        out_path.write_text(json.dumps(manifest, indent=2) + "\n")


def _seed_to_case(seed: dict[str, Any]) -> BenchmarkCase:
    if seed.get("review_status") != "include_real_cve":
        raise ValueError(f"{seed.get('ghsa_id')} is not include_real_cve")
    if seed.get("training_contamination"):
        raise ValueError(f"{seed.get('ghsa_id')} is training-contaminated")

    findings: list[Finding] = []
    for affected_file in seed["affected_files"]:
        common = {
            "cwe_id": seed["cwe_id"],
            "cve_id": seed["cve_id"],
            "message": f"{seed['cve_id']} {seed['ghsa_id']}",
        }
        findings.append(
            Finding(
                **common,
                kind=FindingKind.FAIL,
                location=_location(affected_file, "vulnerable_lines"),
            )
        )
        findings.append(
            Finding(
                **common,
                kind=FindingKind.PASS,
                location=_location(affected_file, "patched_lines"),
            )
        )

    return BenchmarkCase(
        case_id=_case_id(seed),
        project=_project(seed["repo_url"]),
        language=Language.RUST,
        vulnerable_version=seed["vulnerable_ref"],
        patched_version=seed["patched_ref"],
        ground_truth=findings,
        published_date=_published_date(seed.get("published_at")),
        source_dataset=DATASET_NAME,
    )


def _location(affected_file: dict[str, Any], line_key: str) -> CodeLocation:
    lines = affected_file[line_key]
    return CodeLocation(
        file=affected_file["path"],
        start_line=int(lines["start"]),
        end_line=int(lines["end"]),
        function_name=affected_file.get("function_name"),
    )


def _case_id(seed: dict[str, Any]) -> str:
    package = seed["package_names"][0] if seed.get("package_names") else "rust"
    return f"rust-d01-{_slug(package)}-{seed['cve_id']}"


def _slug(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")


def _project(repo_url: str) -> str:
    return repo_url.removeprefix("https://github.com/").removesuffix(".git")


def _published_date(value: str | None) -> date | None:
    if not value:
        return None
    return date.fromisoformat(value.split("T", maxsplit=1)[0])


def _read_existing_manifest(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Materialize Phase 4 D-01 Rust real-CVE benchmark cases",
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=Path("benchmarks"),
        help="Benchmark root directory.",
    )
    parser.add_argument(
        "--seeds",
        type=Path,
        default=DEFAULT_SEEDS_PATH,
        help=f"Reviewed Rust D-01 seed JSON (default: {DEFAULT_SEEDS_PATH}).",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    RustD01Materializer(root=args.root, seeds_path=args.seeds).run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
