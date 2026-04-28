"""Tests for guarded Phase 4 controlled-run execution."""
# ruff: noqa: S101

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from benchmarks.runner.invoker import InvokeResult
from benchmarks.runner.models import CodeLocation, Finding, FindingKind
from benchmarks.runner.sarif import write_bentoo_sarif
from benchmarks.scripts.run_controlled_autoresearch import main as executor_main
from screw_agents.autoresearch.controlled_executor import (
    build_controlled_executor_report,
)
from screw_agents.autoresearch.controlled_run import (
    build_controlled_execution_plan,
    write_controlled_execution_plan_json,
)


def _write_morefixes_fixture(root: Path) -> Path:
    external_dir = root / "external"
    manifests_dir = root / "manifests"
    case_id = "morefixes-CVE-2024-0001-example"
    dataset_dir = external_dir / "morefixes"
    case_dir = dataset_dir / case_id
    truth_path = case_dir / "truth.sarif"
    truth_path.parent.mkdir(parents=True, exist_ok=True)
    write_bentoo_sarif(
        truth_path,
        [
            Finding(
                cwe_id="CWE-89",
                kind=FindingKind.FAIL,
                location=CodeLocation(file="src/db.php", start_line=1, end_line=4),
            ),
            Finding(
                cwe_id="CWE-89",
                kind=FindingKind.PASS,
                location=CodeLocation(file="src/db.php", start_line=1, end_line=4),
            ),
        ],
    )
    vuln = case_dir / "code" / "vulnerable" / "src%2Fdb.php"
    patched = case_dir / "code" / "patched" / "src%2Fdb.php"
    vuln.parent.mkdir(parents=True, exist_ok=True)
    patched.parent.mkdir(parents=True, exist_ok=True)
    vuln.write_text(
        "<?php\n"
        "function user($id) {\n"
        "  return query('SELECT * FROM users WHERE id=' . $id);\n"
        "}\n",
        encoding="utf-8",
    )
    patched.write_text(
        "<?php\n"
        "function user($db, $id) {\n"
        "  return prepared_query($db, 'SELECT * FROM users WHERE id=?', [$id]);\n"
        "}\n",
        encoding="utf-8",
    )
    manifest_path = manifests_dir / "morefixes.manifest.json"
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(
        json.dumps(
            {
                "dataset_name": "morefixes",
                "cases": [
                    {
                        "case_id": case_id,
                        "project": "https://github.com/example/app",
                        "language": "php",
                        "vulnerable_version": "pre-deadbeef",
                        "patched_version": "deadbeef",
                        "published_date": None,
                        "fail_count": 1,
                        "pass_count": 1,
                    }
                ],
            }
        )
        + "\n",
        encoding="utf-8",
    )
    dry_run_path = root / "run_plan.json"
    dry_run_path.write_text(
        json.dumps(
            {
                "schema_version": "phase4-autoresearch-run-plan/v1",
                "generated_at": "2026-04-28T00:00:00+00:00",
                "mode": "dry-run",
                "manifests_dir": str(manifests_dir),
                "external_dir": str(external_dir),
                "dataset_count": 1,
                "total_cases": 1,
                "estimated_min_invocations": 2,
                "datasets": [
                    {
                        "dataset_name": "morefixes",
                        "manifest_path": str(manifest_path),
                        "case_count": 1,
                        "data_dir_exists": True,
                        "truth_file_count": 1,
                        "supported_by_extractor": True,
                        "g5_gate_ids": ["G5.8"],
                        "estimated_min_invocations": 2,
                        "estimated_truth_locations": 1,
                        "notes": [],
                    }
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
        )
        + "\n",
        encoding="utf-8",
    )
    return dry_run_path


def _write_controlled_plan(root: Path, *, execution_allowed: bool = True) -> Path:
    dry_run_path = _write_morefixes_fixture(root)
    controlled_plan = build_controlled_execution_plan(
        dry_run_plan_path=dry_run_path,
        output_dir=root / "controlled",
        allow_claude_invocation=execution_allowed,
    )
    controlled_plan_path = root / "controlled_run_plan.json"
    write_controlled_execution_plan_json(controlled_plan_path, controlled_plan)
    return controlled_plan_path


def test_executor_validation_resolves_selected_case_without_invocation(
    tmp_path: Path,
) -> None:
    controlled_plan_path = _write_controlled_plan(tmp_path)

    report = build_controlled_executor_report(
        controlled_plan_path=controlled_plan_path,
        output_dir=tmp_path / "out",
    )

    assert report.execution_performed is False
    assert report.issues == []
    assert len(report.cases) == 1
    assert report.cases[0].case_id == "morefixes-CVE-2024-0001-example"
    assert report.cases[0].vulnerable_file_count == 1
    assert report.cases[0].patched_file_count == 1


def test_executor_execute_requires_executor_level_allowance(tmp_path: Path) -> None:
    controlled_plan_path = _write_controlled_plan(tmp_path)

    report = build_controlled_executor_report(
        controlled_plan_path=controlled_plan_path,
        output_dir=tmp_path / "out",
        execute=True,
    )

    assert report.execution_performed is False
    assert {issue.code for issue in report.issues} == {"executor_invocation_disabled"}


def test_executor_blocks_when_controlled_plan_is_not_executable(
    tmp_path: Path,
) -> None:
    controlled_plan_path = _write_controlled_plan(tmp_path, execution_allowed=False)

    report = build_controlled_executor_report(
        controlled_plan_path=controlled_plan_path,
        output_dir=tmp_path / "out",
        execute=True,
        allow_claude_invocation=True,
    )

    assert report.execution_performed is False
    assert any(issue.code == "controlled_plan_not_executable" for issue in report.issues)


def test_executor_can_run_selected_case_with_mocked_claude(tmp_path: Path) -> None:
    controlled_plan_path = _write_controlled_plan(tmp_path)
    calls = 0

    def invoke(prompt: str, _config: object) -> InvokeResult:
        nonlocal calls
        calls += 1
        if calls == 1:
            return InvokeResult(
                success=True,
                findings=[
                    {
                        "cwe_id": "CWE-89",
                        "file": "src/db.php",
                        "start_line": 2,
                        "end_line": 3,
                        "confidence": 0.9,
                        "message": "String concatenation in SQL query.",
                    }
                ],
            )
        return InvokeResult(success=True, findings=[])

    with patch("benchmarks.runner.evaluator.invoke_claude", side_effect=invoke):
        report = build_controlled_executor_report(
            controlled_plan_path=controlled_plan_path,
            output_dir=tmp_path / "out",
            execute=True,
            allow_claude_invocation=True,
            throttle_delay=0.0,
        )

    assert calls == 2
    assert report.execution_performed is True
    assert report.benchmark_run_id is not None
    assert len(report.summaries) == 1
    assert report.issues == []


def test_executor_cli_writes_validation_report(tmp_path: Path) -> None:
    controlled_plan_path = _write_controlled_plan(tmp_path)
    output_dir = tmp_path / "executor"

    exit_code = executor_main(
        [
            "--controlled-plan",
            str(controlled_plan_path),
            "--output-dir",
            str(output_dir),
        ]
    )

    assert exit_code == 0
    written = json.loads(
        (output_dir / "controlled_executor_report.json").read_text(encoding="utf-8")
    )
    assert written["execution_performed"] is False
    assert written["cases"][0]["case_id"] == "morefixes-CVE-2024-0001-example"
    assert (output_dir / "controlled_executor_report.md").exists()
