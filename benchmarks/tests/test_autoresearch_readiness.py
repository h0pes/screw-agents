"""Tests for Phase 4 autoresearch dataset readiness reporting."""
# ruff: noqa: S101

from __future__ import annotations

import json
from pathlib import Path

from benchmarks.scripts.check_autoresearch_readiness import main as readiness_main
from screw_agents.autoresearch.readiness import (
    SCHEMA_VERSION,
    build_readiness_report,
    render_readiness_markdown,
    write_readiness_json,
)


def _dry_run_plan(*, ready: bool = False) -> dict:
    truth_file_count = 2 if ready else 0
    return {
        "schema_version": "phase4-autoresearch-run-plan/v1",
        "generated_at": "2026-04-28T00:00:00+00:00",
        "mode": "dry-run",
        "manifests_dir": "benchmarks/external/manifests",
        "external_dir": "benchmarks/external",
        "dataset_count": 2,
        "total_cases": 3,
        "estimated_min_invocations": 6,
        "datasets": [
            {
                "dataset_name": "morefixes",
                "manifest_path": "benchmarks/external/manifests/morefixes.manifest.json",
                "case_count": 2,
                "data_dir_exists": ready,
                "truth_file_count": truth_file_count,
                "supported_by_extractor": True,
                "g5_gate_ids": ["G5.8"],
                "estimated_min_invocations": 4,
                "estimated_truth_locations": 4,
                "notes": [],
            },
            {
                "dataset_name": "vul4j",
                "manifest_path": "benchmarks/external/manifests/vul4j.manifest.json",
                "case_count": 1,
                "data_dir_exists": False,
                "truth_file_count": 0,
                "supported_by_extractor": False,
                "g5_gate_ids": [],
                "estimated_min_invocations": 2,
                "estimated_truth_locations": 2,
                "notes": [],
            },
        ],
        "gate_audit": [
            {
                "gate_id": "G5.8",
                "agent": "sqli",
                "dataset": "morefixes",
                "metric": "tpr",
                "threshold": 0.5,
                "comparison": "gte",
                "cwe_filter": "CWE-89",
                "manifest_exists": True,
                "extractor_supported": True,
                "issue": None,
            }
        ],
        "retired_gates": [],
        "guardrails": [],
    }


def test_readiness_blocks_active_gate_dataset_missing_materialization() -> None:
    report = build_readiness_report(_dry_run_plan(ready=False))

    morefixes = next(dataset for dataset in report.datasets if dataset.dataset_name == "morefixes")
    vul4j = next(dataset for dataset in report.datasets if dataset.dataset_name == "vul4j")

    assert report.schema_version == SCHEMA_VERSION
    assert report.blocker_count == 2
    assert morefixes.status == "blocker"
    assert morefixes.required_for_controlled_run is True
    assert morefixes.blockers == [
        "external dataset directory is missing",
        "no truth.sarif files are materialized",
    ]
    assert morefixes.action.commands == [
        "bash benchmarks/scripts/deploy_morefixes.sh",
        "uv run python -m benchmarks.scripts.morefixes_extract",
    ]
    assert vul4j.status == "deferred"
    assert vul4j.required_for_controlled_run is False


def test_readiness_allows_ready_active_gate_dataset_while_tracking_deferral() -> None:
    report = build_readiness_report(_dry_run_plan(ready=True))

    morefixes = next(dataset for dataset in report.datasets if dataset.dataset_name == "morefixes")

    assert report.blocker_count == 0
    assert report.required_dataset_count == 1
    assert report.ready_required_dataset_count == 1
    assert report.deferred_count == 1
    assert morefixes.status == "ready"


def test_readiness_adds_missing_gate_inventory_blocker() -> None:
    plan = _dry_run_plan(ready=True)
    plan["datasets"] = [
        dataset
        for dataset in plan["datasets"]
        if dataset["dataset_name"] != "morefixes"
    ]

    report = build_readiness_report(plan)

    morefixes = next(dataset for dataset in report.datasets if dataset.dataset_name == "morefixes")
    assert morefixes.status == "blocker"
    assert morefixes.case_count == 0
    assert "tracked case manifest is absent" in morefixes.blockers[0]


def test_readiness_markdown_and_json_outputs(tmp_path: Path) -> None:
    report = build_readiness_report(_dry_run_plan(ready=False))

    markdown = render_readiness_markdown(report)
    assert "Phase 4 Autoresearch Readiness" in markdown
    assert "Materialization Checklist" in markdown
    assert "deploy_morefixes.sh" in markdown
    assert "Vul4J is intentionally deferred" in markdown

    out = tmp_path / "readiness_report.json"
    write_readiness_json(out, report)
    written = json.loads(out.read_text(encoding="utf-8"))
    assert written["schema_version"] == SCHEMA_VERSION
    assert written["blocker_count"] == 2


def test_readiness_cli_writes_report_and_returns_blocked_status(tmp_path: Path) -> None:
    dry_run_path = tmp_path / "run_plan.json"
    output_dir = tmp_path / "out"
    dry_run_path.write_text(json.dumps(_dry_run_plan(ready=False)), encoding="utf-8")

    exit_code = readiness_main(
        [
            "--dry-run-plan",
            str(dry_run_path),
            "--output-dir",
            str(output_dir),
        ]
    )

    assert exit_code == 2
    written = json.loads(
        (output_dir / "readiness_report.json").read_text(encoding="utf-8")
    )
    assert written["blocker_count"] == 2
    assert (output_dir / "readiness_report.md").exists()
