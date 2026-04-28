"""Tests for D-01 Rust real-CVE materialization."""

from __future__ import annotations

import json
from pathlib import Path

from benchmarks.runner.models import FindingKind, Language
from benchmarks.runner.sarif import load_bentoo_sarif
from benchmarks.scripts.materialize_rust_d01 import (
    DATASET_NAME,
    RustD01Materializer,
)


def test_extract_cases_builds_pair_based_rust_ground_truth() -> None:
    materializer = RustD01Materializer(
        root=Path("benchmarks"),
        seeds_path=Path("benchmarks/data/rust-d01-reviewed-seeds.json"),
    )

    cases = materializer.extract_cases()

    matrix = next(case for case in cases if case.case_id.endswith("CVE-2025-53549"))
    assert matrix.project == "matrix-org/matrix-rust-sdk"
    assert matrix.language == Language.RUST
    assert matrix.source_dataset == DATASET_NAME
    assert matrix.published_date and matrix.published_date.isoformat() == "2025-07-10"
    assert [finding.kind for finding in matrix.ground_truth] == [
        FindingKind.FAIL,
        FindingKind.PASS,
    ]
    assert matrix.ground_truth[0].location.function_name == "find_event_relations"


def test_run_materializes_truth_sarif_manifest_and_provenance(tmp_path: Path) -> None:
    materializer = RustD01Materializer(
        root=tmp_path,
        seeds_path=Path("benchmarks/data/rust-d01-reviewed-seeds.json"),
    )

    materializer.run()

    manifest_path = tmp_path / "external" / "manifests" / f"{DATASET_NAME}.manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest["dataset_name"] == DATASET_NAME
    assert manifest["case_count"] == 4

    expected_cwes = {
        "rust-d01-matrix-sdk-CVE-2025-53549": "CWE-89",
        "rust-d01-salvo-CVE-2026-22256": "CWE-79",
        "rust-d01-salvo-CVE-2026-22257": "CWE-79",
        "rust-d01-lettre-CVE-2020-28247": "CWE-77",
    }
    for case_id, cwe_id in expected_cwes.items():
        findings = load_bentoo_sarif(
            tmp_path / "external" / DATASET_NAME / case_id / "truth.sarif"
        )
        assert {finding.kind for finding in findings} == {
            FindingKind.FAIL,
            FindingKind.PASS,
        }
        assert {finding.cwe_id for finding in findings} == {cwe_id}

    case_id = "rust-d01-matrix-sdk-CVE-2025-53549"
    case_dir = tmp_path / "external" / DATASET_NAME / case_id
    provenance = json.loads((case_dir / "provenance.json").read_text(encoding="utf-8"))
    assert provenance["schema_version"] == "rust-d01-case-provenance/v1"
    assert provenance["ghsa_id"] == "GHSA-275g-g844-73jh"


def test_run_preserves_manifest_timestamp_when_cases_are_unchanged(
    tmp_path: Path,
) -> None:
    materializer = RustD01Materializer(
        root=tmp_path,
        seeds_path=Path("benchmarks/data/rust-d01-reviewed-seeds.json"),
    )

    materializer.run()
    manifest_path = tmp_path / "external" / "manifests" / f"{DATASET_NAME}.manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["ingested_at"] = "2026-04-28T00:00:00+00:00"
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")

    materializer.run()

    regenerated = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert regenerated["ingested_at"] == "2026-04-28T00:00:00+00:00"
