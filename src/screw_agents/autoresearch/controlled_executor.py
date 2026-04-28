"""Executor scaffold for reviewed Phase 4 controlled-run plans.

The default path validates a controlled plan without invoking Claude. Actual
invocation is available only when the reviewed plan is executable and the
caller also passes an explicit executor-level allowance.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict

from benchmarks.runner.code_extractor import CodeVariant, extract_code_for_case
from benchmarks.runner.evaluator import EvalConfig, Evaluator
from benchmarks.runner.invoker import InvokerConfig
from benchmarks.runner.models import BenchmarkCase, Language, Summary
from benchmarks.runner.sarif import load_bentoo_sarif
from screw_agents.autoresearch.controlled_run import ControlledExecutionPlan

SCHEMA_VERSION = "phase4-autoresearch-controlled-execution/v1"


class ControlledExecutorConfig(BaseModel):
    """Executor inputs and guardrails."""

    model_config = ConfigDict(extra="forbid")

    controlled_plan_path: str
    output_dir: str
    execute: bool = False
    allow_claude_invocation: bool = False
    throttle_delay: float = 2.0
    max_retries: int = 3
    timeout: int = 300


class ControlledExecutorIssue(BaseModel):
    """A blocker or warning from controlled execution preparation."""

    model_config = ConfigDict(extra="forbid")

    severity: Literal["blocker", "warning"]
    code: str
    message: str


class ControlledExecutorCase(BaseModel):
    """One selected case resolved from a controlled-run plan."""

    model_config = ConfigDict(extra="forbid")

    gate_id: str
    agent: str
    dataset: str
    case_id: str
    cwe_filter: str | None = None
    vulnerable_file_count: int
    patched_file_count: int
    vulnerable_files: list[str]
    patched_files: list[str]
    estimated_invocations: int = 2


class ControlledExecutorReport(BaseModel):
    """Validation/execution report for a controlled-run plan."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal[SCHEMA_VERSION] = SCHEMA_VERSION
    generated_at: str
    controlled_plan_schema_version: str
    config: ControlledExecutorConfig
    cases: list[ControlledExecutorCase]
    issues: list[ControlledExecutorIssue]
    execution_performed: bool
    benchmark_run_id: str | None = None
    summaries: list[dict[str, Any]]


def build_controlled_executor_report(
    *,
    controlled_plan_path: Path,
    output_dir: Path,
    execute: bool = False,
    allow_claude_invocation: bool = False,
    throttle_delay: float = 2.0,
    max_retries: int = 3,
    timeout: int = 300,
) -> ControlledExecutorReport:
    """Validate or execute a reviewed controlled-run plan."""
    plan = ControlledExecutionPlan.model_validate_json(
        controlled_plan_path.read_text(encoding="utf-8")
    )
    config = ControlledExecutorConfig(
        controlled_plan_path=str(controlled_plan_path),
        output_dir=str(output_dir),
        execute=execute,
        allow_claude_invocation=allow_claude_invocation,
        throttle_delay=throttle_delay,
        max_retries=max_retries,
        timeout=timeout,
    )
    issues: list[ControlledExecutorIssue] = []
    issue_keys: set[tuple[str, str]] = set()

    if not plan.execution_allowed:
        _append_issue(
            issues,
            issue_keys,
            "blocker",
            "controlled_plan_not_executable",
            "Controlled plan has execution_allowed=false.",
        )
    if execute and not allow_claude_invocation:
        _append_issue(
            issues,
            issue_keys,
            "blocker",
            "executor_invocation_disabled",
            "Execution requires explicit --allow-claude-invocation.",
        )

    dry_run_plan = json.loads(
        Path(plan.config.dry_run_plan_path).read_text(encoding="utf-8")
    )
    external_dir = Path(str(dry_run_plan.get("external_dir", "benchmarks/external")))
    datasets_by_name = {
        str(dataset["dataset_name"]): dataset
        for dataset in dry_run_plan.get("datasets", [])
    }

    resolved_cases: list[BenchmarkCase] = []
    report_cases: list[ControlledExecutorCase] = []
    for selection in plan.selections:
        dataset = datasets_by_name.get(selection.dataset)
        if dataset is None:
            _append_issue(
                issues,
                issue_keys,
                "blocker",
                "missing_dataset_inventory",
                f"Dataset {selection.dataset} is absent from the dry-run plan.",
            )
            continue
        manifest_cases = _load_manifest_cases(Path(str(dataset["manifest_path"])))
        for case_id in selection.selected_case_ids:
            raw_case = manifest_cases.get(case_id)
            if raw_case is None:
                _append_issue(
                    issues,
                    issue_keys,
                    "blocker",
                    "selected_case_missing",
                    f"Selected case {case_id} is absent from {selection.dataset}.",
                )
                continue
            case = _load_benchmark_case(
                raw_case=raw_case,
                dataset_name=selection.dataset,
                external_dir=external_dir,
                issues=issues,
                issue_keys=issue_keys,
            )
            if case is None:
                continue
            resolved_cases.append(case)
            report_case = _validate_case_extraction(
                case=case,
                gate_id=selection.gate_id,
                agent=selection.agent,
                cwe_filter=selection.cwe_filter,
                external_dir=external_dir,
                issues=issues,
                issue_keys=issue_keys,
            )
            if report_case is not None:
                report_cases.append(report_case)

    execution_performed = False
    benchmark_run_id: str | None = None
    summaries: list[dict[str, Any]] = []
    if execute and not any(issue.severity == "blocker" for issue in issues):
        eval_config = EvalConfig(
            mode="controlled-smoke",
            results_dir=output_dir / "benchmark-runs",
            benchmarks_external_dir=external_dir,
            invoker_config=InvokerConfig(
                throttle_delay=throttle_delay,
                max_retries=max_retries,
                timeout=timeout,
            ),
        )
        evaluator = Evaluator(eval_config)
        summary_models = _run_evaluation(resolved_cases, evaluator)
        execution_performed = True
        benchmark_run_id = evaluator.run_id
        summaries = [_summary_to_dict(summary) for summary in summary_models]

    return ControlledExecutorReport(
        generated_at=datetime.now(UTC).isoformat(timespec="seconds"),
        controlled_plan_schema_version=plan.schema_version,
        config=config,
        cases=report_cases,
        issues=issues,
        execution_performed=execution_performed,
        benchmark_run_id=benchmark_run_id,
        summaries=summaries,
    )


def render_controlled_executor_report_markdown(
    report: ControlledExecutorReport,
) -> str:
    """Render a human-readable executor validation/execution report."""
    estimated_calls = sum(case.estimated_invocations for case in report.cases)
    lines = [
        f"# Phase 4 Controlled Executor Report `{report.generated_at}`",
        "",
        f"- **Execute requested:** {_yes_no(report.config.execute)}",
        f"- **Claude invocation allowed:** {_yes_no(report.config.allow_claude_invocation)}",
        f"- **Execution performed:** {_yes_no(report.execution_performed)}",
        f"- **Cases:** {len(report.cases)}",
        f"- **Estimated calls:** {estimated_calls}",
        f"- **Benchmark run ID:** {report.benchmark_run_id or '-'}",
        "",
        "## Issues",
        "",
    ]
    if report.issues:
        lines.append("| Severity | Code | Message |")
        lines.append("|---|---|---|")
        for issue in report.issues:
            lines.append(f"| {issue.severity} | {issue.code} | {issue.message} |")
    else:
        lines.append("No executor issues detected.")

    lines.extend(["", "## Cases", ""])
    lines.append(
        "| Gate | Agent | Dataset | Case ID | Vulnerable Files | Patched Files | CWE |"
    )
    lines.append("|---|---|---|---|---:|---:|---|")
    for case in report.cases:
        lines.append(
            "| "
            f"{case.gate_id} | "
            f"{case.agent} | "
            f"{case.dataset} | "
            f"{case.case_id} | "
            f"{case.vulnerable_file_count} | "
            f"{case.patched_file_count} | "
            f"{case.cwe_filter or '-'} |"
        )
    lines.append("")
    return "\n".join(lines)


def write_controlled_executor_report_json(
    path: Path,
    report: ControlledExecutorReport,
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(report.model_dump(mode="json"), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def write_controlled_executor_report_markdown(
    path: Path,
    report: ControlledExecutorReport,
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_controlled_executor_report_markdown(report), encoding="utf-8")


def _load_manifest_cases(manifest_path: Path) -> dict[str, dict[str, Any]]:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    return {str(case["case_id"]): case for case in manifest.get("cases", [])}


def _load_benchmark_case(
    *,
    raw_case: dict[str, Any],
    dataset_name: str,
    external_dir: Path,
    issues: list[ControlledExecutorIssue],
    issue_keys: set[tuple[str, str]],
) -> BenchmarkCase | None:
    case_id = str(raw_case["case_id"])
    truth_path = external_dir / dataset_name / case_id / "truth.sarif"
    if not truth_path.exists():
        _append_issue(
            issues,
            issue_keys,
            "blocker",
            "truth_file_missing",
            f"Selected case {case_id} has no truth.sarif at {truth_path}.",
        )
        return None

    try:
        language = Language(str(raw_case["language"]))
    except ValueError:
        _append_issue(
            issues,
            issue_keys,
            "blocker",
            "unsupported_language",
            f"Selected case {case_id} has unsupported language {raw_case['language']}.",
        )
        return None

    return BenchmarkCase(
        case_id=case_id,
        project=str(raw_case["project"]),
        language=language,
        vulnerable_version=str(raw_case["vulnerable_version"]),
        patched_version=str(raw_case["patched_version"]),
        ground_truth=load_bentoo_sarif(truth_path),
        published_date=raw_case.get("published_date"),
        source_dataset=dataset_name,
    )


def _validate_case_extraction(
    *,
    case: BenchmarkCase,
    gate_id: str,
    agent: str,
    cwe_filter: str | None,
    external_dir: Path,
    issues: list[ControlledExecutorIssue],
    issue_keys: set[tuple[str, str]],
) -> ControlledExecutorCase | None:
    try:
        vulnerable = extract_code_for_case(case, CodeVariant.VULNERABLE, external_dir)
        patched = extract_code_for_case(case, CodeVariant.PATCHED, external_dir)
    except FileNotFoundError as exc:
        _append_issue(
            issues,
            issue_keys,
            "blocker",
            "code_extraction_failed",
            f"Could not extract selected case {case.case_id}: {exc}.",
        )
        return None

    if not vulnerable:
        _append_issue(
            issues,
            issue_keys,
            "blocker",
            "vulnerable_code_missing",
            f"Selected case {case.case_id} yielded no vulnerable code.",
        )
    if not patched:
        _append_issue(
            issues,
            issue_keys,
            "blocker",
            "patched_code_missing",
            f"Selected case {case.case_id} yielded no patched code.",
        )

    return ControlledExecutorCase(
        gate_id=gate_id,
        agent=agent,
        dataset=case.source_dataset,
        case_id=case.case_id,
        cwe_filter=cwe_filter,
        vulnerable_file_count=len(vulnerable),
        patched_file_count=len(patched),
        vulnerable_files=[piece.file_path for piece in vulnerable],
        patched_files=[piece.file_path for piece in patched],
    )


def _run_evaluation(
    cases: list[BenchmarkCase],
    evaluator: Evaluator,
) -> list[Summary]:
    from screw_agents.engine import ScanEngine
    from screw_agents.registry import AgentRegistry

    repo_root = Path(__file__).resolve().parents[3]
    engine = ScanEngine(AgentRegistry(repo_root / "domains"))
    return evaluator.run(cases, engine)


def _summary_to_dict(summary: Summary) -> dict[str, Any]:
    return summary.model_dump(mode="json")


def _append_issue(
    issues: list[ControlledExecutorIssue],
    issue_keys: set[tuple[str, str]],
    severity: Literal["blocker", "warning"],
    code: str,
    message: str,
) -> None:
    key = (code, message)
    if key in issue_keys:
        return
    issues.append(
        ControlledExecutorIssue(severity=severity, code=code, message=message)
    )
    issue_keys.add(key)


def _yes_no(value: bool) -> str:
    return "yes" if value else "no"
