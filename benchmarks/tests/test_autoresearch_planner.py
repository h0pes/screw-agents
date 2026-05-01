"""Tests for Phase 4 autoresearch dry-run planning."""
# ruff: noqa: S101

from __future__ import annotations

import json
from pathlib import Path

from screw_agents.autoresearch.planner import (
    build_run_plan,
    render_run_plan_markdown,
    write_run_plan_json,
)


def _write_manifest(path: Path, dataset: str, cases: list[dict]) -> None:
    path.write_text(
        json.dumps(
            {
                "dataset_name": dataset,
                "source_url": "https://example.test",
                "case_count": len(cases),
                "cases": cases,
            }
        )
    )


def test_build_run_plan_inventory_and_gate_audit(tmp_path: Path) -> None:
    manifests_dir = tmp_path / "manifests"
    external_dir = tmp_path / "external"
    manifests_dir.mkdir()
    (external_dir / "ossf-cve-benchmark" / "case-1").mkdir(parents=True)
    (external_dir / "ossf-cve-benchmark" / "case-1" / "truth.sarif").write_text("{}")
    _write_manifest(
        manifests_dir / "ossf-cve-benchmark.manifest.json",
        "ossf-cve-benchmark",
        [
            {
                "case_id": "case-1",
                "fail_count": 2,
                "pass_count": 2,
            }
        ],
    )
    (manifests_dir / "morefixes-deployment.manifest.json").write_text(
        json.dumps({"dataset_name": "morefixes", "deployment": {"db_port": 54321}})
    )

    plan = build_run_plan(manifests_dir=manifests_dir, external_dir=external_dir)

    assert plan.schema_version == "phase4-autoresearch-run-plan/v1"
    assert {gate.gate_id for gate in plan.retired_gates} == {"G5.9", "G5.10"}
    assert plan.dataset_count == 1
    assert plan.total_cases == 1
    assert plan.estimated_min_invocations == 2
    dataset = plan.datasets[0]
    assert dataset.dataset_name == "ossf-cve-benchmark"
    assert dataset.truth_file_count == 1
    assert dataset.estimated_truth_locations == 4
    assert dataset.supported_by_extractor is True
    assert "G5.1" in dataset.g5_gate_ids

    g58 = next(gate for gate in plan.gate_audit if gate.gate_id == "G5.8")
    assert g58.dataset == "morefixes"
    assert g58.manifest_exists is False
    assert g58.extractor_supported is True
    assert g58.issue is None
    g511 = next(gate for gate in plan.gate_audit if gate.gate_id == "G5.11")
    assert g511.agent == "ssti"
    assert g511.dataset == "morefixes"
    assert g511.cwe_filter == "CWE-1336"
    assert g511.manifest_exists is False
    assert g511.extractor_supported is True


def test_build_run_plan_marks_rust_scope_and_missing_generated_data(
    tmp_path: Path,
) -> None:
    manifests_dir = tmp_path / "manifests"
    external_dir = tmp_path / "external"
    manifests_dir.mkdir()
    _write_manifest(
        manifests_dir / "rust-d01-real-cves.manifest.json",
        "rust-d01-real-cves",
        [{"case_id": "rust-case", "fail_count": 1, "pass_count": 1}],
    )

    plan = build_run_plan(manifests_dir=manifests_dir, external_dir=external_dir)

    dataset = plan.datasets[0]
    assert dataset.data_dir_exists is False
    assert dataset.supported_by_extractor is True
    assert any("Rust D-01 corpus is scoped" in note for note in dataset.notes)
    assert any("external dataset directory is missing" in note for note in dataset.notes)


def test_build_run_plan_counts_only_materialized_case_truth_files(
    tmp_path: Path,
) -> None:
    manifests_dir = tmp_path / "manifests"
    external_dir = tmp_path / "external"
    manifests_dir.mkdir()
    _write_manifest(
        manifests_dir / "reality-check-python.manifest.json",
        "reality-check-python",
        [{"case_id": "rc-case", "fail_count": 1, "pass_count": 1}],
    )
    (external_dir / "reality-check-python" / "repo" / "markup" / "extra").mkdir(
        parents=True
    )
    (
        external_dir
        / "reality-check-python"
        / "repo"
        / "markup"
        / "extra"
        / "truth.sarif"
    ).write_text("{}")
    (external_dir / "reality-check-python" / "rc-case").mkdir(parents=True)
    (
        external_dir / "reality-check-python" / "rc-case" / "truth.sarif"
    ).write_text("{}")

    plan = build_run_plan(manifests_dir=manifests_dir, external_dir=external_dir)

    assert plan.datasets[0].truth_file_count == 1


def test_render_and_write_run_plan(tmp_path: Path) -> None:
    manifests_dir = tmp_path / "manifests"
    external_dir = tmp_path / "external"
    manifests_dir.mkdir()
    _write_manifest(
        manifests_dir / "crossvul.manifest.json",
        "crossvul",
        [{"case_id": "c", "fail_count": 1, "pass_count": 1}],
    )
    plan = build_run_plan(manifests_dir=manifests_dir, external_dir=external_dir)

    markdown = render_run_plan_markdown(plan)
    assert "Phase 4 Autoresearch Run Plan" in markdown
    assert "crossvul" in markdown
    assert "Guardrails" in markdown
    assert "Retired Gates" in markdown

    out = tmp_path / "plan.json"
    write_run_plan_json(out, plan)
    written = json.loads(out.read_text())
    assert written["schema_version"] == "phase4-autoresearch-run-plan/v1"
    assert written["datasets"][0]["dataset_name"] == "crossvul"
    assert {gate["gate_id"] for gate in written["retired_gates"]} == {"G5.9", "G5.10"}
