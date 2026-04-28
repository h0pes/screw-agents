"""Dry-run planning for Phase 4 autoresearch benchmark work.

This module intentionally does not run benchmarks, invoke Claude, edit agent
YAML, or sign adaptive scripts. Its job is to make the next expensive step
auditable before it happens.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from benchmarks.runner.gate_checker import G5_GATES, RETIRED_G5_GATES, GateDefinition

SUPPORTED_EXTRACTOR_DATASETS: frozenset[str] = frozenset(
    {
        "crossvul",
        "go-sec-code-mutated",
        "morefixes",
        "ossf-cve-benchmark",
        "reality-check-csharp",
        "reality-check-java",
        "reality-check-python",
        "rust-d01-real-cves",
        "skf-labs-mutated",
    }
)

@dataclass(frozen=True)
class DatasetPlan:
    dataset_name: str
    manifest_path: str
    case_count: int
    data_dir_exists: bool
    truth_file_count: int
    supported_by_extractor: bool
    g5_gate_ids: list[str]
    estimated_min_invocations: int
    estimated_truth_locations: int
    notes: list[str]


@dataclass(frozen=True)
class GateAudit:
    gate_id: str
    agent: str
    dataset: str
    metric: str
    threshold: float
    comparison: str
    cwe_filter: str | None
    manifest_exists: bool
    extractor_supported: bool
    issue: str | None


@dataclass(frozen=True)
class RetiredGate:
    gate_id: str
    reason: str


@dataclass(frozen=True)
class RunPlan:
    schema_version: str
    generated_at: str
    mode: str
    manifests_dir: str
    external_dir: str
    dataset_count: int
    total_cases: int
    estimated_min_invocations: int
    datasets: list[DatasetPlan]
    gate_audit: list[GateAudit]
    retired_gates: list[RetiredGate]
    guardrails: list[str]


def build_run_plan(
    *,
    manifests_dir: Path,
    external_dir: Path,
    mode: str = "dry-run",
) -> RunPlan:
    """Build a no-execution autoresearch plan from tracked manifests."""
    manifests = sorted(manifests_dir.glob("*.manifest.json"))
    gates_by_dataset = _gates_by_dataset(G5_GATES)
    manifest_names = {
        manifest.get("dataset_name", path.stem.replace(".manifest", ""))
        for path in manifests
        if not path.name.startswith("_")
        for manifest in [_read_json(path)]
        if _is_case_manifest(manifest)
    }

    datasets: list[DatasetPlan] = []
    for manifest_path in manifests:
        if manifest_path.name.startswith("_"):
            continue
        manifest = _read_json(manifest_path)
        if not _is_case_manifest(manifest):
            continue
        dataset_name = manifest.get(
            "dataset_name",
            manifest_path.stem.replace(".manifest", ""),
        )
        cases = manifest.get("cases", [])
        case_count = int(manifest.get("case_count", len(cases)))
        data_dir = external_dir / dataset_name
        gate_ids = [gate.gate_id for gate in gates_by_dataset.get(dataset_name, [])]
        truth_count = _count_truth_files(data_dir)
        estimated_truth_locations = _estimate_truth_locations(cases)
        notes = _dataset_notes(
            dataset_name=dataset_name,
            data_dir_exists=data_dir.exists(),
            supported_by_extractor=dataset_name in SUPPORTED_EXTRACTOR_DATASETS,
            gate_ids=gate_ids,
            truth_file_count=truth_count,
        )
        datasets.append(
            DatasetPlan(
                dataset_name=dataset_name,
                manifest_path=str(manifest_path),
                case_count=case_count,
                data_dir_exists=data_dir.exists(),
                truth_file_count=truth_count,
                supported_by_extractor=dataset_name in SUPPORTED_EXTRACTOR_DATASETS,
                g5_gate_ids=gate_ids,
                # Lower bound: vulnerable + patched scan per case. Real runs can
                # be much larger because code extraction may scan multiple files.
                estimated_min_invocations=case_count * 2,
                estimated_truth_locations=estimated_truth_locations,
                notes=notes,
            )
        )

    gate_audit = [
        _audit_gate(gate, manifest_names=manifest_names)
        for gate in G5_GATES
    ]

    return RunPlan(
        schema_version="phase4-autoresearch-run-plan/v1",
        generated_at=datetime.now(UTC).isoformat(timespec="seconds"),
        mode=mode,
        manifests_dir=str(manifests_dir),
        external_dir=str(external_dir),
        dataset_count=len(datasets),
        total_cases=sum(dataset.case_count for dataset in datasets),
        estimated_min_invocations=sum(
            dataset.estimated_min_invocations for dataset in datasets
        ),
        datasets=datasets,
        gate_audit=gate_audit,
        retired_gates=[
            RetiredGate(gate_id=gate_id, reason=reason)
            for gate_id, reason in sorted(RETIRED_G5_GATES.items(), key=_gate_sort_key)
        ],
        guardrails=[
            "Dry-run planning only: do not invoke Claude from this step.",
            "Do not mutate domains/**/*.yaml from aggregate metrics alone.",
            "Any YAML change must cite concrete missed/false-positive examples.",
            "Use stage_adaptive_script -> promote_staged_script for future generated code hooks.",
            "Keep Rust claims scoped: real-CVE SQLi/CmdI/XSS, synthetic-only SSTI.",
        ],
    )


def render_run_plan_markdown(plan: RunPlan) -> str:
    """Render a human-readable run plan."""
    lines = [
        f"# Phase 4 Autoresearch Run Plan `{plan.generated_at}`",
        "",
        f"- **Mode:** `{plan.mode}`",
        f"- **Datasets:** {plan.dataset_count}",
        f"- **Cases:** {plan.total_cases}",
        f"- **Estimated minimum invocations:** {plan.estimated_min_invocations}",
        "",
        "## Guardrails",
        "",
    ]
    lines.extend(f"- {guardrail}" for guardrail in plan.guardrails)
    lines.extend(["", "## Dataset Inventory", ""])
    lines.append(
        "| Dataset | Cases | Min Calls | Data Dir | Truth Files | Extractor | Gates | Notes |"
    )
    lines.append("|---|---:|---:|---|---:|---|---|---|")
    for dataset in sorted(plan.datasets, key=lambda item: item.dataset_name):
        notes = "<br>".join(dataset.notes) if dataset.notes else ""
        lines.append(
            "| "
            f"{dataset.dataset_name} | "
            f"{dataset.case_count} | "
            f"{dataset.estimated_min_invocations} | "
            f"{_yes_no(dataset.data_dir_exists)} | "
            f"{dataset.truth_file_count} | "
            f"{_yes_no(dataset.supported_by_extractor)} | "
            f"{', '.join(dataset.g5_gate_ids) or '-'} | "
            f"{notes} |"
        )
    lines.extend(["", "## Gate Audit", ""])
    lines.append("| Gate | Agent | Dataset | Metric | Threshold | Manifest | Extractor | Issue |")
    lines.append("|---|---|---|---|---:|---|---|---|")
    for gate in plan.gate_audit:
        op = ">=" if gate.comparison == "gte" else "<="
        issue = gate.issue or ""
        lines.append(
            "| "
            f"{gate.gate_id} | "
            f"{gate.agent} | "
            f"{gate.dataset} | "
            f"{gate.metric} | "
            f"{op} {gate.threshold:.0%} | "
            f"{_yes_no(gate.manifest_exists)} | "
            f"{_yes_no(gate.extractor_supported)} | "
            f"{issue} |"
        )
    if plan.retired_gates:
        lines.extend(["", "## Retired Gates", ""])
        lines.append("| Gate | Reason |")
        lines.append("|---|---|")
        for gate in plan.retired_gates:
            lines.append(f"| {gate.gate_id} | {gate.reason} |")
    lines.append("")
    return "\n".join(lines)


def plan_to_dict(plan: RunPlan) -> dict[str, Any]:
    return asdict(plan)


def write_run_plan_json(path: Path, plan: RunPlan) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(plan_to_dict(plan), indent=2, sort_keys=True) + "\n")


def write_run_plan_markdown(path: Path, plan: RunPlan) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_run_plan_markdown(plan))


def _audit_gate(gate: GateDefinition, *, manifest_names: set[str]) -> GateAudit:
    return GateAudit(
        gate_id=gate.gate_id,
        agent=gate.agent,
        dataset=gate.dataset,
        metric=gate.metric,
        threshold=gate.threshold,
        comparison=gate.comparison,
        cwe_filter=gate.cwe_filter,
        manifest_exists=gate.dataset in manifest_names,
        extractor_supported=gate.dataset in SUPPORTED_EXTRACTOR_DATASETS,
        issue=None,
    )


def _dataset_notes(
    *,
    dataset_name: str,
    data_dir_exists: bool,
    supported_by_extractor: bool,
    gate_ids: list[str],
    truth_file_count: int,
) -> list[str]:
    notes: list[str] = []
    if not data_dir_exists:
        notes.append("external dataset directory is missing; ingest/materialize first")
    if truth_file_count == 0:
        notes.append("no truth.sarif files found on disk")
    if not supported_by_extractor:
        notes.append("code extraction is not implemented for this dataset")
    if not gate_ids:
        notes.append("not referenced by current G5 gates")
    if dataset_name == "rust-d01-real-cves":
        notes.append("Rust D-01 corpus is scoped; do not use as SSTI real-CVE evidence")
    return notes


def _gates_by_dataset(gates: list[GateDefinition]) -> dict[str, list[GateDefinition]]:
    by_dataset: dict[str, list[GateDefinition]] = {}
    for gate in gates:
        by_dataset.setdefault(gate.dataset, []).append(gate)
    return by_dataset


def _gate_sort_key(item: tuple[str, str]) -> tuple[int, int | str]:
    gate_id = item[0]
    prefix, _, suffix = gate_id.partition(".")
    try:
        return (int(prefix.removeprefix("G")), int(suffix))
    except ValueError:
        return (999, gate_id)


def _read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _is_case_manifest(manifest: dict[str, Any]) -> bool:
    return isinstance(manifest.get("cases"), list)


def _count_truth_files(data_dir: Path) -> int:
    if not data_dir.exists():
        return 0
    return sum(1 for _ in data_dir.rglob("truth.sarif"))


def _estimate_truth_locations(cases: list[dict[str, Any]]) -> int:
    total = 0
    for case in cases:
        total += int(case.get("fail_count") or 0)
        total += int(case.get("pass_count") or 0)
    return total


def _yes_no(value: bool) -> str:
    return "yes" if value else "no"
