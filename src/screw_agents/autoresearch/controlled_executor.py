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

from pydantic import BaseModel, ConfigDict, Field

from benchmarks.runner.code_extractor import CodeVariant, extract_code_for_case
from benchmarks.runner.evaluator import EvalConfig, Evaluator
from benchmarks.runner.invoker import InvokerConfig
from benchmarks.runner.models import BenchmarkCase, FindingKind, Language, Summary
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
    agents: list[str] = Field(default_factory=list)
    case_ids: list[str] = Field(default_factory=list)
    include_related_context: bool = False


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
    include_related_context: bool = False
    estimated_invocations: int = 2


class ControlledExecutorResultCounts(BaseModel):
    """Raw finding counts written by one executed vulnerable/patched pair."""

    model_config = ConfigDict(extra="forbid")

    case_id: str
    agent: str
    dataset: str
    vulnerable_finding_count: int
    patched_finding_count: int
    vulnerable_result_path: str
    patched_result_path: str


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
    result_counts: list[ControlledExecutorResultCounts] = Field(default_factory=list)


def build_controlled_executor_report(
    *,
    controlled_plan_path: Path,
    output_dir: Path,
    execute: bool = False,
    allow_claude_invocation: bool = False,
    throttle_delay: float = 2.0,
    max_retries: int = 3,
    timeout: int = 300,
    agents: list[str] | None = None,
    case_ids: list[str] | None = None,
    include_related_context: bool = False,
) -> ControlledExecutorReport:
    """Validate or execute a reviewed controlled-run plan."""
    agent_filter = _normalize_filter_values(agents)
    case_id_filter = _normalize_filter_values(case_ids)
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
        agents=agent_filter,
        case_ids=case_id_filter,
        include_related_context=include_related_context,
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
    related_context_case_ids: set[str] = set()
    for selection in plan.selections:
        if agent_filter and selection.agent not in agent_filter:
            continue
        planned_related_context_case_ids = set(selection.related_context_case_ids)
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
            if case_id_filter and case_id not in case_id_filter:
                continue
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
            case_include_related_context = (
                include_related_context
                or case.case_id in planned_related_context_case_ids
                or _case_needs_related_context(case, agent=selection.agent)
            )
            if case_include_related_context:
                related_context_case_ids.add(case.case_id)
            resolved_cases.append(case)
            report_case = _validate_case_extraction(
                case=case,
                gate_id=selection.gate_id,
                agent=selection.agent,
                cwe_filter=selection.cwe_filter,
                external_dir=external_dir,
                include_related_context=case_include_related_context,
                issues=issues,
                issue_keys=issue_keys,
            )
            if report_case is not None:
                report_cases.append(report_case)

    if (agent_filter or case_id_filter) and not report_cases:
        _append_issue(
            issues,
            issue_keys,
            "blocker",
            "selection_filter_empty",
            (
                "Controlled executor filters matched no reviewed cases "
                f"(agents={agent_filter or '-'}, case_ids={case_id_filter or '-'})."
            ),
        )

    execution_performed = False
    benchmark_run_id: str | None = None
    summaries: list[dict[str, Any]] = []
    result_counts: list[ControlledExecutorResultCounts] = []
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
            include_related_context=include_related_context,
            include_related_context_case_ids=related_context_case_ids,
        )
        evaluator = Evaluator(eval_config)
        summary_models = _run_evaluation(resolved_cases, evaluator)
        execution_performed = True
        benchmark_run_id = evaluator.run_id
        summaries = [_summary_to_dict(summary) for summary in summary_models]
        result_counts = _load_result_counts(report_cases, evaluator._cases_dir)

    return ControlledExecutorReport(
        generated_at=datetime.now(UTC).isoformat(timespec="seconds"),
        controlled_plan_schema_version=plan.schema_version,
        config=config,
        cases=report_cases,
        issues=issues,
        execution_performed=execution_performed,
        benchmark_run_id=benchmark_run_id,
        summaries=summaries,
        result_counts=result_counts,
    )


def render_controlled_executor_report_markdown(
    report: ControlledExecutorReport,
) -> str:
    """Render a human-readable executor validation/execution report."""
    estimated_calls = sum(case.estimated_invocations for case in report.cases)
    related_context_cases = [
        case.case_id for case in report.cases if case.include_related_context
    ]
    lines = [
        f"# Phase 4 Controlled Executor Report `{report.generated_at}`",
        "",
        f"- **Execute requested:** {_yes_no(report.config.execute)}",
        f"- **Claude invocation allowed:** {_yes_no(report.config.allow_claude_invocation)}",
        f"- **Execution performed:** {_yes_no(report.execution_performed)}",
        f"- **Cases:** {len(report.cases)}",
        f"- **Estimated calls:** {estimated_calls}",
        f"- **Benchmark run ID:** {report.benchmark_run_id or '-'}",
        f"- **Agent filter:** {_format_filter(report.config.agents)}",
        f"- **Case ID filter:** {_format_filter(report.config.case_ids)}",
        f"- **Related context:** {_yes_no(report.config.include_related_context)}",
        f"- **Related context cases:** {_format_filter(related_context_cases)}",
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
        "| Gate | Agent | Dataset | Case ID | Vulnerable Files | Patched Files | "
        "Related Context | CWE |"
    )
    lines.append("|---|---|---|---|---:|---:|---|---|")
    for case in report.cases:
        lines.append(
            "| "
            f"{case.gate_id} | "
            f"{case.agent} | "
            f"{case.dataset} | "
            f"{case.case_id} | "
            f"{case.vulnerable_file_count} | "
            f"{case.patched_file_count} | "
            f"{_yes_no(case.include_related_context)} | "
            f"{case.cwe_filter or '-'} |"
        )

    if report.summaries:
        lines.extend(["", "## Metrics Summary", ""])
        lines.append(
            "| Agent | Dataset | TP | FP | TN | FN | TPR | FPR | Precision | F1 | Accuracy |"
        )
        lines.append("|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|")
        for summary in report.summaries:
            metric = _overall_metric(summary)
            if metric is None:
                continue
            lines.append(
                "| "
                f"{summary['agent_name']} | "
                f"{summary['dataset']} | "
                f"{metric['true_positives']} | "
                f"{metric['false_positives']} | "
                f"{metric['true_negatives']} | "
                f"{metric['false_negatives']} | "
                f"{_pct(metric['tpr'])} | "
                f"{_pct(metric['fpr'])} | "
                f"{_pct(metric['precision'])} | "
                f"{_pct(metric['f1'])} | "
                f"{_pct(metric['accuracy'])} |"
            )

    if report.result_counts:
        lines.extend(["", "## Finding Counts", ""])
        lines.append("| Agent | Dataset | Case ID | Vulnerable Findings | Patched Findings |")
        lines.append("|---|---|---|---:|---:|")
        for result in report.result_counts:
            lines.append(
                "| "
                f"{result.agent} | "
                f"{result.dataset} | "
                f"{result.case_id} | "
                f"{result.vulnerable_finding_count} | "
                f"{result.patched_finding_count} |"
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
    include_related_context: bool,
    issues: list[ControlledExecutorIssue],
    issue_keys: set[tuple[str, str]],
) -> ControlledExecutorCase | None:
    try:
        vulnerable = extract_code_for_case(
            case,
            CodeVariant.VULNERABLE,
            external_dir,
            include_related_context=include_related_context,
        )
        patched = extract_code_for_case(
            case,
            CodeVariant.PATCHED,
            external_dir,
            include_related_context=include_related_context,
        )
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
        include_related_context=include_related_context,
    )


def _case_needs_related_context(case: BenchmarkCase, *, agent: str) -> bool:
    """Detect multi-file truth where same-variant context can affect evidence."""
    if agent != "cmdi":
        return False
    fail_files = {
        finding.location.file
        for finding in case.ground_truth
        if finding.kind == FindingKind.FAIL
    }
    pass_files = {
        finding.location.file
        for finding in case.ground_truth
        if finding.kind == FindingKind.PASS
    }
    return len(fail_files) > 1 or len(pass_files) > 1


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


def _load_result_counts(
    cases: list[ControlledExecutorCase],
    cases_dir: Path,
) -> list[ControlledExecutorResultCounts]:
    results: list[ControlledExecutorResultCounts] = []
    for case in cases:
        vuln_path = cases_dir / f"{case.case_id}_vuln.json"
        patched_path = cases_dir / f"{case.case_id}_patched.json"
        results.append(
            ControlledExecutorResultCounts(
                case_id=case.case_id,
                agent=case.agent,
                dataset=case.dataset,
                vulnerable_finding_count=_json_array_len(vuln_path),
                patched_finding_count=_json_array_len(patched_path),
                vulnerable_result_path=str(vuln_path),
                patched_result_path=str(patched_path),
            )
        )
    return results


def _json_array_len(path: Path) -> int:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise ValueError(f"Expected JSON array at {path}")
    return len(data)


def _overall_metric(summary: dict[str, Any]) -> dict[str, Any] | None:
    for metric in summary.get("metrics", []):
        if metric.get("cwe_id") is None and metric.get("language") is None:
            return metric
    return None


def _pct(value: float) -> str:
    return f"{value:.1%}"


def _normalize_filter_values(values: list[str] | None) -> list[str]:
    if not values:
        return []
    return [value for value in dict.fromkeys(item.strip() for item in values) if value]


def _format_filter(values: list[str]) -> str:
    if not values:
        return "-"
    return ", ".join(values)


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
