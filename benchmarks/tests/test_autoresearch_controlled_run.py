"""Tests for guarded Phase 4 autoresearch controlled-run preparation."""
# ruff: noqa: S101

from __future__ import annotations

import json
from pathlib import Path

from benchmarks.runner.models import CodeLocation, Finding, FindingKind
from benchmarks.runner.sarif import write_bentoo_sarif
from benchmarks.scripts.prepare_autoresearch_run import main as prepare_main
from screw_agents.autoresearch.controlled_run import (
    SCHEMA_VERSION,
    build_controlled_execution_plan,
    render_controlled_execution_plan_markdown,
    write_controlled_execution_plan_json,
)


def _write_manifest_and_truth(
    root: Path,
    *,
    dataset_name: str,
    cases: list[tuple[str, str]],
) -> Path:
    manifest_path = root / "manifests" / f"{dataset_name}.manifest.json"
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(
        json.dumps(
            {
                "dataset_name": dataset_name,
                "cases": [
                    {
                        "case_id": case_id,
                        "project": "example",
                        "language": "python",
                        "vulnerable_version": "vuln",
                        "patched_version": "patched",
                        "published_date": None,
                        "fail_count": 1,
                        "pass_count": 1,
                    }
                    for case_id, _cwe_id in cases
                ],
            }
        )
        + "\n",
        encoding="utf-8",
    )
    for case_id, cwe_id in cases:
        truth_path = root / "external" / dataset_name / case_id / "truth.sarif"
        truth_path.parent.mkdir(parents=True, exist_ok=True)
        write_bentoo_sarif(
            truth_path,
            [
                Finding(
                    cwe_id=cwe_id,
                    kind=FindingKind.FAIL,
                    location=CodeLocation(file="app.py", start_line=1, end_line=1),
                ),
                Finding(
                    cwe_id=cwe_id,
                    kind=FindingKind.PASS,
                    location=CodeLocation(file="app.py", start_line=1, end_line=1),
                ),
            ],
        )
        _write_extractable_code(root, dataset_name=dataset_name, case_id=case_id)
    return manifest_path


def _write_extractable_code(root: Path, *, dataset_name: str, case_id: str) -> None:
    external_dir = root / "external"
    if dataset_name == "morefixes":
        vulnerable = external_dir / dataset_name / case_id / "code" / "vulnerable" / "app.py"
        patched = external_dir / dataset_name / case_id / "code" / "patched" / "app.py"
        vulnerable.parent.mkdir(parents=True, exist_ok=True)
        patched.parent.mkdir(parents=True, exist_ok=True)
        vulnerable.write_text(
            "def handler(request):\n"
            "    query = request.args['q']\n"
            "    return database.execute('SELECT ' + query)\n"
        )
        patched.write_text(
            "def handler(request):\n"
            "    query = request.args['q']\n"
            "    return database.execute('SELECT ?', [query])\n"
        )
        return

    if dataset_name == "ossf-cve-benchmark":
        repo_file = external_dir / dataset_name / "repo" / "app.py"
        repo_file.parent.mkdir(parents=True, exist_ok=True)
        repo_file.write_text("def handler(request):\n    return request.args['q']\n")
        return

    lang_subdir = {
        "reality-check-csharp": "csharp",
        "reality-check-python": "python",
        "reality-check-java": "java",
    }.get(dataset_name)
    if lang_subdir is None:
        return
    for version in ("vuln", "patched"):
        version_file = (
            external_dir
            / dataset_name
            / "repo"
            / lang_subdir
            / "markup"
            / "example"
            / version
            / "app.py"
        )
        version_file.parent.mkdir(parents=True, exist_ok=True)
        version_file.write_text("def handler(request):\n    return request.args['q']\n")


def _write_dry_run_plan(path: Path, *, ready: bool = False) -> None:
    truth_file_count = 1 if ready else 0
    manifest_path = _write_manifest_and_truth(
        path.parent,
        dataset_name="morefixes",
        cases=[
            ("morefixes-sqli-1", "CWE-89"),
            ("morefixes-sqli-2", "CWE-89"),
        ],
    )
    path.write_text(
        json.dumps(
            {
                "schema_version": "phase4-autoresearch-run-plan/v1",
                "generated_at": "2026-04-28T00:00:00+00:00",
                "mode": "dry-run",
                "manifests_dir": "benchmarks/external/manifests",
                "external_dir": str(path.parent / "external"),
                "dataset_count": 1,
                "total_cases": 2,
                "estimated_min_invocations": 4,
                "datasets": [
                    {
                        "dataset_name": "morefixes",
                        "manifest_path": str(manifest_path),
                        "case_count": 2,
                        "data_dir_exists": ready,
                        "truth_file_count": truth_file_count,
                        "supported_by_extractor": True,
                        "g5_gate_ids": ["G5.8"],
                        "estimated_min_invocations": 4,
                        "estimated_truth_locations": 4,
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


def _write_multi_dataset_dry_run_plan(path: Path, *, ready: bool = True) -> None:
    truth_file_count = 1 if ready else 0
    manifest_paths = {
        "ossf-cve-benchmark": _write_manifest_and_truth(
            path.parent,
            dataset_name="ossf-cve-benchmark",
            cases=[
                ("ossf-xss-1", "CWE-79"),
                ("ossf-cmdi-1", "CWE-78"),
            ],
        ),
        "reality-check-csharp": _write_manifest_and_truth(
            path.parent,
            dataset_name="reality-check-csharp",
            cases=[
                ("rc-csharp-xss-1", "CWE-79"),
                ("rc-csharp-sqli-1", "CWE-89"),
            ],
        ),
        "reality-check-python": _write_manifest_and_truth(
            path.parent,
            dataset_name="reality-check-python",
            cases=[("rc-python-xss-1", "CWE-79")],
        ),
        "reality-check-java": _write_manifest_and_truth(
            path.parent,
            dataset_name="reality-check-java",
            cases=[("rc-java-cmdi-1", "CWE-78")],
        ),
        "morefixes": _write_manifest_and_truth(
            path.parent,
            dataset_name="morefixes",
            cases=[("morefixes-sqli-1", "CWE-89")],
        ),
    }
    datasets = [
        ("ossf-cve-benchmark", 2, ["G5.1", "G5.2", "G5.5"]),
        ("reality-check-csharp", 2, ["G5.3", "G5.7"]),
        ("reality-check-python", 1, ["G5.4"]),
        ("reality-check-java", 1, ["G5.6"]),
        ("morefixes", 1, ["G5.8"]),
    ]
    gates = [
        ("G5.1", "xss", "ossf-cve-benchmark", "tpr", 0.7, "CWE-79"),
        ("G5.2", "xss", "ossf-cve-benchmark", "fpr", 0.25, "CWE-79"),
        ("G5.5", "cmdi", "ossf-cve-benchmark", "tpr", 0.6, "CWE-78"),
        ("G5.3", "xss", "reality-check-csharp", "tpr", 0.6, "CWE-79"),
        ("G5.7", "sqli", "reality-check-csharp", "tpr", 0.5, "CWE-89"),
        ("G5.4", "xss", "reality-check-python", "tpr", 0.6, "CWE-79"),
        ("G5.6", "cmdi", "reality-check-java", "tpr", 0.5, "CWE-78"),
        ("G5.8", "sqli", "morefixes", "tpr", 0.5, "CWE-89"),
    ]
    path.write_text(
        json.dumps(
            {
                "schema_version": "phase4-autoresearch-run-plan/v1",
                "generated_at": "2026-04-28T00:00:00+00:00",
                "mode": "dry-run",
                "manifests_dir": "benchmarks/external/manifests",
                "external_dir": str(path.parent / "external"),
                "dataset_count": len(datasets),
                "total_cases": sum(case_count for _, case_count, _ in datasets),
                "estimated_min_invocations": 5472,
                "datasets": [
                    {
                        "dataset_name": dataset_name,
                        "manifest_path": str(manifest_paths[dataset_name]),
                        "case_count": case_count,
                        "data_dir_exists": ready,
                        "truth_file_count": truth_file_count,
                        "supported_by_extractor": True,
                        "g5_gate_ids": gate_ids,
                        "estimated_min_invocations": case_count * 2,
                        "estimated_truth_locations": case_count,
                        "notes": [],
                    }
                    for dataset_name, case_count, gate_ids in datasets
                ],
                "gate_audit": [
                    {
                        "gate_id": gate_id,
                        "agent": agent,
                        "dataset": dataset,
                        "metric": metric,
                        "threshold": threshold,
                        "comparison": "gte",
                        "cwe_filter": cwe_filter,
                        "manifest_exists": True,
                        "extractor_supported": True,
                        "issue": None,
                    }
                    for gate_id, agent, dataset, metric, threshold, cwe_filter in gates
                ],
                "retired_gates": [],
                "guardrails": [],
            }
        )
        + "\n",
        encoding="utf-8",
    )


def test_controlled_run_blocks_without_explicit_claude_allowance(tmp_path: Path) -> None:
    dry_run_path = tmp_path / "run_plan.json"
    _write_dry_run_plan(dry_run_path, ready=True)

    plan = build_controlled_execution_plan(
        dry_run_plan_path=dry_run_path,
        output_dir=tmp_path / "out",
    )

    assert plan.schema_version == SCHEMA_VERSION
    assert plan.execution_allowed is False
    assert any(issue.code == "claude_invocation_disabled" for issue in plan.issues)
    assert plan.config.yaml_mutation_allowed is False


def test_controlled_run_blocks_missing_dataset_readiness(tmp_path: Path) -> None:
    dry_run_path = tmp_path / "run_plan.json"
    _write_dry_run_plan(dry_run_path, ready=False)

    plan = build_controlled_execution_plan(
        dry_run_plan_path=dry_run_path,
        output_dir=tmp_path / "out",
        allow_claude_invocation=True,
    )

    assert plan.execution_allowed is False
    assert {issue.code for issue in plan.issues} == {
        "dataset_dir_missing",
        "truth_files_missing",
    }


def test_controlled_run_can_become_executable_when_ready_and_allowed(
    tmp_path: Path,
) -> None:
    dry_run_path = tmp_path / "run_plan.json"
    _write_dry_run_plan(dry_run_path, ready=True)

    plan = build_controlled_execution_plan(
        dry_run_plan_path=dry_run_path,
        output_dir=tmp_path / "out",
        allow_claude_invocation=True,
        max_cases_per_dataset=1,
        max_cases_per_agent=1,
    )

    assert plan.execution_allowed is True
    assert plan.issues == []
    assert len(plan.selections) == 1
    assert plan.selections[0].selected_case_count == 1
    assert plan.selections[0].selected_case_ids == ["morefixes-sqli-1"]
    assert plan.selections[0].estimated_invocations == 2


def test_expanded_stratified_allows_partial_executable_selection(
    tmp_path: Path,
) -> None:
    dry_run_path = tmp_path / "run_plan.json"
    _write_dry_run_plan(dry_run_path, ready=True)
    dry_run = json.loads(dry_run_path.read_text(encoding="utf-8"))
    dry_run["datasets"][0]["case_count"] = 3
    dry_run_path.write_text(json.dumps(dry_run) + "\n", encoding="utf-8")

    plan = build_controlled_execution_plan(
        dry_run_plan_path=dry_run_path,
        output_dir=tmp_path / "out",
        allow_claude_invocation=True,
        max_cases_per_dataset=3,
        selection_strategy="expanded-stratified",
    )

    assert plan.execution_allowed is True
    assert [(issue.severity, issue.code) for issue in plan.issues] == [
        ("warning", "case_selection_incomplete")
    ]
    assert plan.selections[0].selected_case_ids == [
        "morefixes-sqli-1",
        "morefixes-sqli-2",
    ]


def test_priority_stratified_ranks_higher_signal_cases_first(
    tmp_path: Path,
) -> None:
    dry_run_path = tmp_path / "run_plan.json"
    manifest_path = _write_manifest_and_truth(
        tmp_path,
        dataset_name="morefixes",
        cases=[
            ("morefixes-CVE-2024-0001-low-signal", "CWE-89"),
            ("morefixes-CVE-2021-0002-high-cvss", "CWE-89"),
            ("morefixes-CVE-2019-0003-explicit-priority", "CWE-89"),
        ],
    )
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["cases"][0]["fail_count"] = 1
    manifest["cases"][0]["pass_count"] = 1
    manifest["cases"][0]["published_date"] = "2024-01-01"
    manifest["cases"][1]["cvss_score"] = 9.8
    manifest["cases"][1]["published_date"] = "2021-01-01"
    manifest["cases"][2]["sample_priority"] = 50
    manifest["cases"][2]["published_date"] = "2019-01-01"
    manifest_path.write_text(json.dumps(manifest) + "\n", encoding="utf-8")
    dry_run_path.write_text(
        json.dumps(
            {
                "schema_version": "phase4-autoresearch-run-plan/v1",
                "generated_at": "2026-04-30T00:00:00+00:00",
                "mode": "dry-run",
                "external_dir": str(tmp_path / "external"),
                "dataset_count": 1,
                "total_cases": 3,
                "estimated_min_invocations": 6,
                "datasets": [
                    {
                        "dataset_name": "morefixes",
                        "manifest_path": str(manifest_path),
                        "case_count": 3,
                        "data_dir_exists": True,
                        "truth_file_count": 3,
                        "supported_by_extractor": True,
                        "g5_gate_ids": ["G5.8"],
                        "estimated_min_invocations": 6,
                        "estimated_truth_locations": 6,
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

    plan = build_controlled_execution_plan(
        dry_run_plan_path=dry_run_path,
        output_dir=tmp_path / "out",
        allow_claude_invocation=True,
        max_cases_per_dataset=2,
        selection_strategy="priority-stratified",
    )

    assert plan.execution_allowed is True
    assert plan.issues == []
    assert plan.selections[0].selected_case_ids == [
        "morefixes-CVE-2019-0003-explicit-priority",
        "morefixes-CVE-2021-0002-high-cvss",
    ]


def test_required_dataset_smoke_selects_each_dataset_agent_pair(
    tmp_path: Path,
) -> None:
    dry_run_path = tmp_path / "run_plan.json"
    _write_multi_dataset_dry_run_plan(dry_run_path, ready=True)

    plan = build_controlled_execution_plan(
        dry_run_plan_path=dry_run_path,
        output_dir=tmp_path / "out",
        allow_claude_invocation=True,
    )

    selected_pairs = {
        (selection.dataset, selection.agent) for selection in plan.selections
    }
    assert plan.execution_allowed is True
    assert selected_pairs == {
        ("ossf-cve-benchmark", "xss"),
        ("ossf-cve-benchmark", "cmdi"),
        ("reality-check-csharp", "xss"),
        ("reality-check-csharp", "sqli"),
        ("reality-check-python", "xss"),
        ("reality-check-java", "cmdi"),
        ("morefixes", "sqli"),
    }
    assert {selection.selected_case_count for selection in plan.selections} == {1}
    assert {
        selection.selected_case_ids[0] for selection in plan.selections
    } == {
        "ossf-xss-1",
        "ossf-cmdi-1",
        "rc-csharp-xss-1",
        "rc-csharp-sqli-1",
        "rc-python-xss-1",
        "rc-java-cmdi-1",
        "morefixes-sqli-1",
    }
    assert sum(selection.estimated_invocations for selection in plan.selections) == 14


def test_required_dataset_smoke_still_respects_agent_case_cap(
    tmp_path: Path,
) -> None:
    dry_run_path = tmp_path / "run_plan.json"
    _write_multi_dataset_dry_run_plan(dry_run_path, ready=True)

    plan = build_controlled_execution_plan(
        dry_run_plan_path=dry_run_path,
        output_dir=tmp_path / "out",
        allow_claude_invocation=True,
        max_cases_per_agent=1,
    )

    selected_pairs = {
        (selection.dataset, selection.agent) for selection in plan.selections
    }
    assert ("ossf-cve-benchmark", "xss") in selected_pairs
    assert ("ossf-cve-benchmark", "cmdi") in selected_pairs
    assert ("reality-check-csharp", "sqli") in selected_pairs
    assert ("reality-check-csharp", "xss") not in selected_pairs
    assert ("morefixes", "sqli") not in selected_pairs


def test_controlled_run_markdown_and_json_outputs(tmp_path: Path) -> None:
    dry_run_path = tmp_path / "run_plan.json"
    _write_dry_run_plan(dry_run_path, ready=True)
    plan = build_controlled_execution_plan(
        dry_run_plan_path=dry_run_path,
        output_dir=tmp_path / "out",
    )

    markdown = render_controlled_execution_plan_markdown(plan)
    assert "Controlled Run Plan" in markdown
    assert "claude_invocation_disabled" in markdown

    out = tmp_path / "controlled_run_plan.json"
    write_controlled_execution_plan_json(out, plan)
    written = json.loads(out.read_text(encoding="utf-8"))
    assert written["schema_version"] == SCHEMA_VERSION
    assert written["config"]["selection_strategy"] == "required-dataset-smoke"
    assert written["selections"][0]["selected_case_ids"] == ["morefixes-sqli-1"]
    assert written["config"]["yaml_mutation_allowed"] is False


def test_prepare_cli_writes_plan_and_returns_blocked_status(tmp_path: Path) -> None:
    dry_run_path = tmp_path / "run_plan.json"
    output_dir = tmp_path / "out"
    _write_dry_run_plan(dry_run_path, ready=True)

    exit_code = prepare_main(
        [
            "--dry-run-plan",
            str(dry_run_path),
            "--output-dir",
            str(output_dir),
        ]
    )

    assert exit_code == 2
    written = json.loads(
        (output_dir / "controlled_run_plan.json").read_text(encoding="utf-8")
    )
    assert written["execution_allowed"] is False
    assert (output_dir / "controlled_run_plan.md").exists()
