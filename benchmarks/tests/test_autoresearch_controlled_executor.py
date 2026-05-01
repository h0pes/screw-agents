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
    _append_invocation_progress_issues,
    build_controlled_executor_report,
    render_controlled_executor_report_markdown,
)
from screw_agents.autoresearch.controlled_run import (
    build_controlled_execution_plan,
    write_controlled_execution_plan_json,
)


def _write_morefixes_fixture(
    root: Path,
    *,
    extra_case: bool = False,
    multi_file_case: bool = False,
) -> Path:
    external_dir = root / "external"
    manifests_dir = root / "manifests"
    case_id = "morefixes-CVE-2024-0001-example"
    dataset_dir = external_dir / "morefixes"
    case_dir = dataset_dir / case_id
    truth_path = case_dir / "truth.sarif"
    truth_path.parent.mkdir(parents=True, exist_ok=True)
    findings = [
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
    ]
    if multi_file_case:
        findings.extend(
            [
                Finding(
                    cwe_id="CWE-89",
                    kind=FindingKind.FAIL,
                    location=CodeLocation(
                        file="src/orders.php",
                        start_line=1,
                        end_line=4,
                    ),
                ),
                Finding(
                    cwe_id="CWE-89",
                    kind=FindingKind.PASS,
                    location=CodeLocation(
                        file="src/orders.php",
                        start_line=1,
                        end_line=4,
                    ),
                ),
            ]
        )
    write_bentoo_sarif(truth_path, findings)
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
    if multi_file_case:
        orders_vuln = case_dir / "code" / "vulnerable" / "src%2Forders.php"
        orders_patched = case_dir / "code" / "patched" / "src%2Forders.php"
        orders_vuln.write_text(
            "<?php\n"
            "function orders($status) {\n"
            "  return query('SELECT * FROM orders WHERE status=' . $status);\n"
            "}\n",
            encoding="utf-8",
        )
        orders_patched.write_text(
            "<?php\n"
            "function orders($db, $status) {\n"
            "  return prepared_query($db, 'SELECT * FROM orders WHERE status=?', [$status]);\n"
            "}\n",
            encoding="utf-8",
        )
    manifest_cases = [
        {
            "case_id": case_id,
            "project": "https://github.com/example/app",
            "language": "php",
            "vulnerable_version": "pre-deadbeef",
            "patched_version": "deadbeef",
            "published_date": None,
            "fail_count": 2 if multi_file_case else 1,
            "pass_count": 2 if multi_file_case else 1,
        }
    ]
    if extra_case:
        second_case_id = "morefixes-CVE-2024-0002-example"
        second_case_dir = dataset_dir / second_case_id
        second_truth_path = second_case_dir / "truth.sarif"
        second_truth_path.parent.mkdir(parents=True, exist_ok=True)
        write_bentoo_sarif(
            second_truth_path,
            [
                Finding(
                    cwe_id="CWE-89",
                    kind=FindingKind.FAIL,
                    location=CodeLocation(
                        file="src/account.php", start_line=1, end_line=4
                    ),
                ),
                Finding(
                    cwe_id="CWE-89",
                    kind=FindingKind.PASS,
                    location=CodeLocation(
                        file="src/account.php", start_line=1, end_line=4
                    ),
                ),
            ],
        )
        second_vuln = second_case_dir / "code" / "vulnerable" / "src%2Faccount.php"
        second_patched = second_case_dir / "code" / "patched" / "src%2Faccount.php"
        second_vuln.parent.mkdir(parents=True, exist_ok=True)
        second_patched.parent.mkdir(parents=True, exist_ok=True)
        second_vuln.write_text(
            "<?php\n"
            "function account($name) {\n"
            "  return query(\"SELECT * FROM accounts WHERE name='$name'\");\n"
            "}\n",
            encoding="utf-8",
        )
        second_patched.write_text(
            "<?php\n"
            "function account($db, $name) {\n"
            "  return prepared_query($db, 'SELECT * FROM accounts WHERE name=?', [$name]);\n"
            "}\n",
            encoding="utf-8",
        )
        manifest_cases.append(
            {
                "case_id": second_case_id,
                "project": "https://github.com/example/app",
                "language": "php",
                "vulnerable_version": "pre-feedface",
                "patched_version": "feedface",
                "published_date": None,
                "fail_count": 1,
                "pass_count": 1,
            }
        )
    manifest_path = manifests_dir / "morefixes.manifest.json"
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(
        json.dumps(
            {
                "dataset_name": "morefixes",
                "cases": manifest_cases,
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
                        "case_count": len(manifest_cases),
                        "data_dir_exists": True,
                        "truth_file_count": len(manifest_cases),
                        "supported_by_extractor": True,
                        "g5_gate_ids": ["G5.8"],
                        "estimated_min_invocations": 2,
                        "estimated_truth_locations": len(manifest_cases),
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


def _write_reality_check_java_fixture(root: Path) -> Path:
    external_dir = root / "external"
    manifests_dir = root / "manifests"
    dataset_name = "reality-check-java"
    case_id = "rc-java-plexus-utils-CVE-2017-1000487"
    case_dir = external_dir / dataset_name / case_id
    truth_path = case_dir / "truth.sarif"
    truth_path.parent.mkdir(parents=True, exist_ok=True)
    write_bentoo_sarif(
        truth_path,
        [
            Finding(
                cwe_id="CWE-78",
                kind=FindingKind.FAIL,
                location=CodeLocation(file="Shell.java", start_line=1, end_line=3),
            ),
            Finding(
                cwe_id="CWE-78",
                kind=FindingKind.FAIL,
                location=CodeLocation(
                    file="BourneShell.java", start_line=1, end_line=3
                ),
            ),
            Finding(
                cwe_id="CWE-78",
                kind=FindingKind.PASS,
                location=CodeLocation(file="Shell.java", start_line=1, end_line=3),
            ),
            Finding(
                cwe_id="CWE-78",
                kind=FindingKind.PASS,
                location=CodeLocation(
                    file="BourneShell.java", start_line=1, end_line=3
                ),
            ),
        ],
    )
    for version, shell_content, bourne_content in (
        ("vuln", "class Shell { void run(String s) {} }\n", "class BourneShell {}\n"),
        (
            "patched",
            "class Shell { void run(String s) {} }\n",
            "class BourneShell { String quoteOneItem(String s) { return s; } }\n",
        ),
    ):
        version_dir = (
            external_dir
            / dataset_name
            / "repo"
            / "java"
            / "markup"
            / "plexus-utils"
            / version
        )
        version_dir.mkdir(parents=True, exist_ok=True)
        (version_dir / "Shell.java").write_text(shell_content, encoding="utf-8")
        (version_dir / "BourneShell.java").write_text(bourne_content, encoding="utf-8")

    manifest_path = manifests_dir / "reality-check-java.manifest.json"
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(
        json.dumps(
            {
                "dataset_name": dataset_name,
                "cases": [
                    {
                        "case_id": case_id,
                        "project": "plexus-utils",
                        "language": "java",
                        "vulnerable_version": "vuln",
                        "patched_version": "patched",
                        "published_date": None,
                        "fail_count": 2,
                        "pass_count": 2,
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
                        "dataset_name": dataset_name,
                        "manifest_path": str(manifest_path),
                        "case_count": 1,
                        "data_dir_exists": True,
                        "truth_file_count": 1,
                        "supported_by_extractor": True,
                        "g5_gate_ids": ["G5.6"],
                        "estimated_min_invocations": 2,
                        "estimated_truth_locations": 4,
                        "notes": [],
                    }
                ],
                "gate_audit": [
                    {
                        "gate_id": "G5.6",
                        "agent": "cmdi",
                        "dataset": dataset_name,
                        "metric": "tpr",
                        "threshold": 0.5,
                        "comparison": "gte",
                        "cwe_filter": "CWE-78",
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


def _write_controlled_plan(
    root: Path,
    *,
    execution_allowed: bool = True,
    extra_case: bool = False,
    multi_file_case: bool = False,
    max_cases_per_dataset: int = 1,
) -> Path:
    dry_run_path = _write_morefixes_fixture(
        root,
        extra_case=extra_case,
        multi_file_case=multi_file_case,
    )
    controlled_plan = build_controlled_execution_plan(
        dry_run_plan_path=dry_run_path,
        output_dir=root / "controlled",
        allow_claude_invocation=execution_allowed,
        max_cases_per_dataset=max_cases_per_dataset,
    )
    controlled_plan_path = root / "controlled_run_plan.json"
    write_controlled_execution_plan_json(controlled_plan_path, controlled_plan)
    return controlled_plan_path


def _write_reality_check_java_controlled_plan(root: Path) -> Path:
    dry_run_path = _write_reality_check_java_fixture(root)
    controlled_plan = build_controlled_execution_plan(
        dry_run_plan_path=dry_run_path,
        output_dir=root / "controlled",
        allow_claude_invocation=True,
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
    assert report.prompt_budget is not None
    assert report.prompt_budget.prompt_count == 2
    assert report.prompt_budget.total_prompt_chars > 0
    assert report.prompt_budget.retry_budgeted_prompt_chars == (
        report.prompt_budget.total_prompt_chars * report.config.max_retries
    )
    assert len(report.case_prompt_budgets) == 1
    assert report.case_prompt_budgets[0].case_id == "morefixes-CVE-2024-0001-example"
    assert report.case_prompt_budgets[0].prompt_count == 2
    assert report.case_prompt_budgets[0].total_prompt_chars == (
        report.prompt_budget.total_prompt_chars
    )
    assert report.case_prompt_budgets[0].retry_budgeted_prompt_chars == (
        report.case_prompt_budgets[0].total_prompt_chars * report.config.max_retries
    )
    assert {estimate.variant for estimate in report.prompt_estimates} == {
        "vulnerable",
        "patched",
    }


def test_executor_agent_filter_limits_reviewed_selection(tmp_path: Path) -> None:
    controlled_plan_path = _write_controlled_plan(tmp_path)

    report = build_controlled_executor_report(
        controlled_plan_path=controlled_plan_path,
        output_dir=tmp_path / "out",
        agents=["sqli"],
    )

    assert report.issues == []
    assert report.config.agents == ["sqli"]
    assert len(report.cases) == 1
    assert report.cases[0].agent == "sqli"


def test_executor_case_id_filter_limits_reviewed_selection(tmp_path: Path) -> None:
    controlled_plan_path = _write_controlled_plan(
        tmp_path,
        extra_case=True,
        max_cases_per_dataset=2,
    )

    report = build_controlled_executor_report(
        controlled_plan_path=controlled_plan_path,
        output_dir=tmp_path / "out",
        case_ids=["morefixes-CVE-2024-0002-example"],
    )

    assert report.issues == []
    assert report.config.case_ids == ["morefixes-CVE-2024-0002-example"]
    assert [case.case_id for case in report.cases] == [
        "morefixes-CVE-2024-0002-example"
    ]


def test_executor_max_files_per_variant_limits_validation_budget(
    tmp_path: Path,
) -> None:
    controlled_plan_path = _write_controlled_plan(tmp_path, multi_file_case=True)

    report = build_controlled_executor_report(
        controlled_plan_path=controlled_plan_path,
        output_dir=tmp_path / "out",
        max_files_per_variant=1,
    )

    assert report.issues == []
    assert report.config.max_files_per_variant == 1
    assert report.cases[0].vulnerable_file_count == 1
    assert report.cases[0].patched_file_count == 1
    assert report.prompt_budget is not None
    assert report.prompt_budget.prompt_count == 2
    assert report.case_prompt_budgets[0].prompt_count == 2
    rendered = render_controlled_executor_report_markdown(report)
    assert "**Max files per variant:** 1" in rendered


def test_executor_max_files_per_variant_limits_execution_calls(
    tmp_path: Path,
) -> None:
    controlled_plan_path = _write_controlled_plan(tmp_path, multi_file_case=True)
    calls = 0

    def invoke(
        prompt: str,
        _config: object,
        context: dict[str, object] | None = None,
    ) -> InvokeResult:
        nonlocal calls
        assert prompt
        assert context is not None
        assert context["file"] == "src/db.php"
        calls += 1
        return InvokeResult(success=True, findings=[])

    with patch("benchmarks.runner.evaluator.invoke_claude", side_effect=invoke):
        report = build_controlled_executor_report(
            controlled_plan_path=controlled_plan_path,
            output_dir=tmp_path / "out",
            execute=True,
            allow_claude_invocation=True,
            throttle_delay=0.0,
            max_files_per_variant=1,
        )

    assert calls == 2
    assert report.execution_performed is True
    assert report.config.max_files_per_variant == 1
    assert report.cases[0].vulnerable_file_count == 1
    assert report.cases[0].patched_file_count == 1


def test_invocation_progress_failures_become_executor_warnings(tmp_path: Path) -> None:
    progress_log = tmp_path / "invocation_progress.jsonl"
    progress_log.write_text(
        "\n".join(
            [
                json.dumps({"status": "started", "invocation_id": "one"}),
                json.dumps({"status": "failed", "invocation_id": "one"}),
                json.dumps({"status": "timeout", "invocation_id": "two"}),
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    issues = []
    issue_keys = set()

    _append_invocation_progress_issues(
        issues,
        issue_keys,
        progress_log_path=progress_log,
    )

    assert [issue.code for issue in issues] == [
        "claude_invocation_failures_detected",
        "claude_invocation_timeouts_detected",
    ]
    assert all(issue.severity == "warning" for issue in issues)


def test_executor_records_related_context_option(tmp_path: Path) -> None:
    controlled_plan_path = _write_controlled_plan(tmp_path)

    report = build_controlled_executor_report(
        controlled_plan_path=controlled_plan_path,
        output_dir=tmp_path / "out",
        include_related_context=True,
    )

    assert report.issues == []
    assert report.config.include_related_context is True
    assert "**Related context:** yes" in render_controlled_executor_report_markdown(report)


def test_executor_auto_marks_multifile_cases_for_related_context(
    tmp_path: Path,
) -> None:
    controlled_plan_path = _write_reality_check_java_controlled_plan(tmp_path)

    report = build_controlled_executor_report(
        controlled_plan_path=controlled_plan_path,
        output_dir=tmp_path / "out",
    )

    assert report.issues == []
    assert report.config.include_related_context is False
    assert len(report.cases) == 1
    assert report.cases[0].case_id == "rc-java-plexus-utils-CVE-2017-1000487"
    assert report.cases[0].include_related_context is True
    rendered = render_controlled_executor_report_markdown(report)
    assert "**Related context:** no" in rendered
    assert (
        "**Related context cases:** rc-java-plexus-utils-CVE-2017-1000487"
        in rendered
    )
    assert "| G5.6 | cmdi | reality-check-java |" in rendered
    assert "| 2 | 2 | yes | CWE-78 |" in rendered
    assert "## Prompt Budget By Case" in rendered
    assert "## Prompt Estimates" in rendered
    assert any(estimate.context_file_count == 1 for estimate in report.prompt_estimates)


def test_executor_filter_empty_blocks_execution(tmp_path: Path) -> None:
    controlled_plan_path = _write_controlled_plan(tmp_path)

    report = build_controlled_executor_report(
        controlled_plan_path=controlled_plan_path,
        output_dir=tmp_path / "out",
        execute=True,
        allow_claude_invocation=True,
        agents=["cmdi"],
    )

    assert report.execution_performed is False
    assert {issue.code for issue in report.issues} == {"selection_filter_empty"}


def test_executor_execute_requires_executor_level_allowance(tmp_path: Path) -> None:
    controlled_plan_path = _write_controlled_plan(tmp_path)

    report = build_controlled_executor_report(
        controlled_plan_path=controlled_plan_path,
        output_dir=tmp_path / "out",
        execute=True,
    )

    assert report.execution_performed is False
    assert {issue.code for issue in report.issues} == {"executor_invocation_disabled"}


def test_executor_blocks_execution_when_prompt_budget_is_exceeded(
    tmp_path: Path,
) -> None:
    controlled_plan_path = _write_controlled_plan(tmp_path)

    report = build_controlled_executor_report(
        controlled_plan_path=controlled_plan_path,
        output_dir=tmp_path / "out",
        execute=True,
        allow_claude_invocation=True,
        max_prompt_chars=1,
    )

    assert report.execution_performed is False
    assert "prompt_budget_exceeded" in {issue.code for issue in report.issues}
    assert report.prompt_budget is not None
    assert report.prompt_budget.max_prompt_chars == 1


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

    def invoke(
        prompt: str,
        _config: object,
        context: dict[str, object] | None = None,
    ) -> InvokeResult:
        nonlocal calls
        assert context is not None
        assert context["case_id"] == "morefixes-CVE-2024-0001-example"
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
    assert len(report.result_counts) == 1
    assert report.result_counts[0].vulnerable_finding_count == 1
    assert report.result_counts[0].patched_finding_count == 0
    assert report.issues == []

    rendered = render_controlled_executor_report_markdown(report)
    assert "## Metrics Summary" in rendered
    assert "## Finding Counts" in rendered
    assert (
        "| sqli | morefixes | 1 | 0 | 1 | 0 | 100.0% | "
        "0.0% | 100.0% | 100.0% | 100.0% |"
    ) in rendered
    assert "| sqli | morefixes | morefixes-CVE-2024-0001-example | 1 | 0 |" in rendered


def test_executor_cli_writes_validation_report(tmp_path: Path) -> None:
    controlled_plan_path = _write_controlled_plan(
        tmp_path,
        extra_case=True,
        max_cases_per_dataset=2,
    )
    output_dir = tmp_path / "executor"

    exit_code = executor_main(
        [
            "--controlled-plan",
            str(controlled_plan_path),
            "--output-dir",
            str(output_dir),
            "--case-id",
            "morefixes-CVE-2024-0002-example",
            "--include-related-context",
        ]
    )

    assert exit_code == 0
    written = json.loads(
        (output_dir / "controlled_executor_report.json").read_text(encoding="utf-8")
    )
    assert written["execution_performed"] is False
    assert written["config"]["case_ids"] == ["morefixes-CVE-2024-0002-example"]
    assert written["config"]["include_related_context"] is True
    assert written["config"]["max_prompt_chars"] == 250000
    assert written["config"]["max_files_per_variant"] == 0
    assert written["prompt_budget"]["prompt_count"] == 2
    assert written["case_prompt_budgets"][0]["case_id"] == (
        "morefixes-CVE-2024-0002-example"
    )
    assert written["case_prompt_budgets"][0]["prompt_count"] == 2
    assert written["prompt_estimates"]
    assert written["cases"][0]["case_id"] == "morefixes-CVE-2024-0002-example"
    assert (output_dir / "controlled_executor_report.md").exists()
