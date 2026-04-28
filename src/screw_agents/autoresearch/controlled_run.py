"""Controlled execution scaffold for Phase 4 autoresearch.

This module prepares a small benchmark execution plan from the dry-run
inventory. It does not invoke Claude and does not mutate YAML.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from benchmarks.runner.sarif import load_bentoo_sarif

SCHEMA_VERSION = "phase4-autoresearch-controlled-run/v1"

_AGENT_DEFAULT_CWE = {
    "xss": "CWE-79",
    "cmdi": "CWE-78",
    "sqli": "CWE-89",
    "ssti": "CWE-1336",
}


class ControlledRunConfig(BaseModel):
    """User-selected limits and safety switches for a controlled run."""

    model_config = ConfigDict(extra="forbid")

    mode: Literal["sample"] = "sample"
    selection_strategy: Literal["required-dataset-smoke", "gate-order"] = (
        "required-dataset-smoke"
    )
    dry_run_plan_path: str
    output_dir: str
    max_cases_per_dataset: int = Field(default=1, ge=1)
    max_cases_per_agent: int = Field(default=10, ge=1)
    allow_claude_invocation: bool = False
    yaml_mutation_allowed: Literal[False] = False


class ControlledRunSelection(BaseModel):
    """One planned agent/dataset sample slice."""

    model_config = ConfigDict(extra="forbid")

    gate_id: str
    agent: str
    dataset: str
    metric: str
    threshold: float
    cwe_filter: str | None = None
    selected_case_ids: list[str]
    selected_case_count: int
    estimated_invocations: int


class ReadinessIssue(BaseModel):
    """A blocker or warning discovered before any execution."""

    model_config = ConfigDict(extra="forbid")

    severity: Literal["blocker", "warning"]
    code: str
    message: str


class ControlledExecutionPlan(BaseModel):
    """Prepared controlled-run plan."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal[SCHEMA_VERSION] = SCHEMA_VERSION
    generated_at: str
    dry_run_schema_version: str
    config: ControlledRunConfig
    selections: list[ControlledRunSelection]
    issues: list[ReadinessIssue]
    execution_allowed: bool


def build_controlled_execution_plan(
    *,
    dry_run_plan_path: Path,
    output_dir: Path,
    allow_claude_invocation: bool = False,
    max_cases_per_dataset: int = 1,
    max_cases_per_agent: int = 10,
    mode: Literal["sample"] = "sample",
    selection_strategy: Literal["required-dataset-smoke", "gate-order"] = (
        "required-dataset-smoke"
    ),
) -> ControlledExecutionPlan:
    """Prepare a small sample execution plan from a dry-run plan JSON."""
    dry_run = json.loads(dry_run_plan_path.read_text(encoding="utf-8"))
    config = ControlledRunConfig(
        mode=mode,
        dry_run_plan_path=str(dry_run_plan_path),
        output_dir=str(output_dir),
        max_cases_per_dataset=max_cases_per_dataset,
        max_cases_per_agent=max_cases_per_agent,
        allow_claude_invocation=allow_claude_invocation,
        selection_strategy=selection_strategy,
    )
    datasets_by_name = {
        dataset["dataset_name"]: dataset
        for dataset in dry_run.get("datasets", [])
    }
    external_dir = Path(str(dry_run.get("external_dir", "benchmarks/external")))

    issues: list[ReadinessIssue] = []
    issue_keys: set[tuple[str, str]] = set()
    selections: list[ControlledRunSelection] = []
    if not allow_claude_invocation:
        _append_issue(
            issues,
            issue_keys,
            ReadinessIssue(
                severity="blocker",
                code="claude_invocation_disabled",
                message=(
                    "Controlled execution requires explicit "
                    "--allow-claude-invocation."
                ),
            ),
        )

    selected_by_agent: dict[str, int] = {}
    for gate in _select_candidate_gates(
        dry_run.get("gate_audit", []),
        strategy=selection_strategy,
    ):
        dataset_name = gate["dataset"]
        dataset = datasets_by_name.get(dataset_name)
        if dataset is None:
            _append_issue(
                issues,
                issue_keys,
                ReadinessIssue(
                    severity="blocker",
                    code="missing_dataset_inventory",
                    message=f"Gate {gate['gate_id']} dataset {dataset_name} is absent.",
                ),
            )
            continue
        _append_dataset_issues(
            issues,
            issue_keys,
            dataset=dataset,
        )
        dataset_has_blockers = _dataset_has_blockers(dataset=dataset)
        if selected_by_agent.get(gate["agent"], 0) >= max_cases_per_agent:
            continue
        selected_case_count = min(
            int(dataset["case_count"]),
            max_cases_per_dataset,
            max_cases_per_agent - selected_by_agent.get(gate["agent"], 0),
        )
        if selected_case_count <= 0:
            continue
        if dataset_has_blockers:
            continue
        selected_case_ids = _select_case_ids(
            dataset=dataset,
            gate=gate,
            external_dir=external_dir,
            limit=selected_case_count,
            issues=issues,
            issue_keys=issue_keys,
        )
        if not selected_case_ids:
            continue
        selected_case_count = len(selected_case_ids)
        selected_by_agent[gate["agent"]] = (
            selected_by_agent.get(gate["agent"], 0) + selected_case_count
        )
        selections.append(
            ControlledRunSelection(
                gate_id=gate["gate_id"],
                agent=gate["agent"],
                dataset=dataset_name,
                metric=gate["metric"],
                threshold=float(gate["threshold"]),
                cwe_filter=gate.get("cwe_filter"),
                selected_case_ids=selected_case_ids,
                selected_case_count=selected_case_count,
                estimated_invocations=selected_case_count * 2,
            )
        )
    if not selections and not any(issue.severity == "blocker" for issue in issues):
        _append_issue(
            issues,
            issue_keys,
            ReadinessIssue(
                severity="blocker",
                code="no_controlled_run_selections",
                message="No gate/dataset selections were available for the sample plan.",
            ),
        )

    execution_allowed = allow_claude_invocation and not any(
        issue.severity == "blocker" for issue in issues
    )
    return ControlledExecutionPlan(
        generated_at=datetime.now(UTC).isoformat(timespec="seconds"),
        dry_run_schema_version=dry_run.get("schema_version", "unknown"),
        config=config,
        selections=selections,
        issues=issues,
        execution_allowed=execution_allowed,
    )


def render_controlled_execution_plan_markdown(plan: ControlledExecutionPlan) -> str:
    """Render a human-readable controlled-run plan."""
    lines = [
        f"# Phase 4 Controlled Run Plan `{plan.generated_at}`",
        "",
        f"- **Mode:** `{plan.config.mode}`",
        f"- **Selection strategy:** `{plan.config.selection_strategy}`",
        f"- **Max cases per dataset:** {plan.config.max_cases_per_dataset}",
        f"- **Max cases per agent:** {plan.config.max_cases_per_agent}",
        f"- **Claude invocation allowed:** {_yes_no(plan.config.allow_claude_invocation)}",
        f"- **YAML mutation allowed:** {_yes_no(plan.config.yaml_mutation_allowed)}",
        f"- **Execution allowed:** {_yes_no(plan.execution_allowed)}",
        f"- **Selections:** {len(plan.selections)}",
        "",
        "## Issues",
        "",
    ]
    if plan.issues:
        lines.append("| Severity | Code | Message |")
        lines.append("|---|---|---|")
        for issue in plan.issues:
            lines.append(f"| {issue.severity} | {issue.code} | {issue.message} |")
    else:
        lines.append("No readiness issues detected.")
    lines.extend(["", "## Selections", ""])
    lines.append("| Gate | Agent | Dataset | Cases | Case IDs | Estimated Calls | CWE |")
    lines.append("|---|---|---|---:|---|---:|---|")
    for selection in plan.selections:
        lines.append(
            "| "
            f"{selection.gate_id} | "
            f"{selection.agent} | "
            f"{selection.dataset} | "
            f"{selection.selected_case_count} | "
            f"{', '.join(selection.selected_case_ids)} | "
            f"{selection.estimated_invocations} | "
            f"{selection.cwe_filter or '-'} |"
        )
    lines.append("")
    return "\n".join(lines)


def controlled_plan_to_dict(plan: ControlledExecutionPlan) -> dict[str, Any]:
    return plan.model_dump(mode="json")


def write_controlled_execution_plan_json(
    path: Path,
    plan: ControlledExecutionPlan,
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(controlled_plan_to_dict(plan), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def write_controlled_execution_plan_markdown(
    path: Path,
    plan: ControlledExecutionPlan,
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_controlled_execution_plan_markdown(plan), encoding="utf-8")


def _select_candidate_gates(
    gates: list[dict[str, Any]],
    *,
    strategy: Literal["required-dataset-smoke", "gate-order"],
) -> list[dict[str, Any]]:
    if strategy == "gate-order":
        return gates

    selected: list[dict[str, Any]] = []
    seen_dataset_agents: set[tuple[str, str]] = set()
    for gate in gates:
        key = (str(gate["dataset"]), str(gate["agent"]))
        if key in seen_dataset_agents:
            continue
        seen_dataset_agents.add(key)
        selected.append(gate)
    return selected


def _select_case_ids(
    *,
    dataset: dict[str, Any],
    gate: dict[str, Any],
    external_dir: Path,
    limit: int,
    issues: list[ReadinessIssue],
    issue_keys: set[tuple[str, str]],
) -> list[str]:
    dataset_name = str(dataset["dataset_name"])
    manifest_path = Path(str(dataset["manifest_path"]))
    if not manifest_path.exists():
        _append_issue(
            issues,
            issue_keys,
            ReadinessIssue(
                severity="blocker",
                code="manifest_missing",
                message=f"Dataset {dataset_name} manifest is missing: {manifest_path}.",
            ),
        )
        return []

    target_cwe = gate.get("cwe_filter") or _AGENT_DEFAULT_CWE.get(str(gate["agent"]))
    if target_cwe is None:
        _append_issue(
            issues,
            issue_keys,
            ReadinessIssue(
                severity="blocker",
                code="case_selection_cwe_unknown",
                message=(
                    f"Gate {gate['gate_id']} has no cwe_filter and agent "
                    f"{gate['agent']} has no default CWE mapping."
                ),
            ),
        )
        return []

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    selected: list[str] = []
    for case in manifest.get("cases", []):
        case_id = str(case["case_id"])
        truth_path = external_dir / dataset_name / case_id / "truth.sarif"
        if not truth_path.exists():
            continue
        try:
            findings = load_bentoo_sarif(truth_path)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            _append_issue(
                issues,
                issue_keys,
                ReadinessIssue(
                    severity="blocker",
                    code="truth_file_unreadable",
                    message=f"Could not read truth.sarif for {case_id}: {exc}.",
                ),
            )
            continue
        if any(finding.cwe_id == target_cwe for finding in findings):
            selected.append(case_id)
        if len(selected) >= limit:
            break

    if len(selected) < limit:
        _append_issue(
            issues,
            issue_keys,
            ReadinessIssue(
                severity="blocker",
                code="case_selection_incomplete",
                message=(
                    f"Gate {gate['gate_id']} requested {limit} {dataset_name} "
                    f"case(s) for {target_cwe}, but only selected {len(selected)}."
                ),
            ),
        )
    return selected


def _dataset_has_blockers(*, dataset: dict[str, Any]) -> bool:
    return (
        not dataset.get("data_dir_exists")
        or int(dataset.get("truth_file_count", 0)) == 0
        or not dataset.get("supported_by_extractor")
    )


def _append_dataset_issues(
    issues: list[ReadinessIssue],
    issue_keys: set[tuple[str, str]],
    *,
    dataset: dict[str, Any],
) -> None:
    dataset_name = dataset["dataset_name"]
    if not dataset.get("data_dir_exists"):
        _append_issue(
            issues,
            issue_keys,
            ReadinessIssue(
                severity="blocker",
                code="dataset_dir_missing",
                message=f"Dataset {dataset_name} external dir is missing.",
            ),
        )
    if int(dataset.get("truth_file_count", 0)) == 0:
        _append_issue(
            issues,
            issue_keys,
            ReadinessIssue(
                severity="blocker",
                code="truth_files_missing",
                message=f"Dataset {dataset_name} has no truth.sarif files.",
            ),
        )
    if not dataset.get("supported_by_extractor"):
        _append_issue(
            issues,
            issue_keys,
            ReadinessIssue(
                severity="blocker",
                code="extractor_missing",
                message=f"Dataset {dataset_name} has no extractor support.",
            ),
        )


def _append_issue(
    issues: list[ReadinessIssue],
    issue_keys: set[tuple[str, str]],
    issue: ReadinessIssue,
) -> None:
    key = (issue.code, issue.message)
    if key in issue_keys:
        return
    issues.append(issue)
    issue_keys.add(key)


def _yes_no(value: bool) -> str:
    return "yes" if value else "no"
