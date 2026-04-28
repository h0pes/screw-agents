"""Dataset readiness reporting for Phase 4 autoresearch.

The readiness report turns the dry-run inventory into an operator checklist. It
does not download datasets, invoke Claude, run benchmarks, or mutate agent YAML.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

SCHEMA_VERSION = "phase4-autoresearch-readiness/v1"

ReadinessStatus = Literal["ready", "blocker", "warning", "deferred"]

_INGEST_COMMANDS = {
    "crossvul": "uv run python -m benchmarks.scripts.ingest_crossvul",
    "go-sec-code-mutated": "uv run python -m benchmarks.scripts.ingest_go_sec_code",
    "ossf-cve-benchmark": "uv run python -m benchmarks.scripts.ingest_ossf",
    "reality-check-csharp": (
        "uv run python -m benchmarks.scripts.ingest_reality_check_csharp"
    ),
    "reality-check-java": "uv run python -m benchmarks.scripts.ingest_reality_check_java",
    "reality-check-python": (
        "uv run python -m benchmarks.scripts.ingest_reality_check_python"
    ),
    "skf-labs-mutated": "uv run python -m benchmarks.scripts.ingest_skf_labs",
}


@dataclass(frozen=True)
class ReadinessAction:
    title: str
    commands: list[str]
    notes: list[str]


@dataclass(frozen=True)
class DatasetReadiness:
    dataset_name: str
    status: ReadinessStatus
    required_for_controlled_run: bool
    gate_ids: list[str]
    case_count: int
    data_dir_exists: bool
    truth_file_count: int
    supported_by_extractor: bool
    blockers: list[str]
    warnings: list[str]
    action: ReadinessAction


@dataclass(frozen=True)
class ReadinessReport:
    schema_version: str
    generated_at: str
    dry_run_schema_version: str
    external_dir: str
    dataset_count: int
    required_dataset_count: int
    ready_required_dataset_count: int
    blocker_count: int
    deferred_count: int
    datasets: list[DatasetReadiness]
    guardrails: list[str]


def build_readiness_report(dry_run_plan: dict[str, Any]) -> ReadinessReport:
    """Build a reviewable dataset readiness report from a dry-run plan dict."""
    datasets_by_name: dict[str, dict[str, Any]] = {
        str(dataset["dataset_name"]): dataset
        for dataset in dry_run_plan.get("datasets", [])
    }
    gates_by_dataset: dict[str, list[str]] = {}
    for gate in dry_run_plan.get("gate_audit", []):
        gates_by_dataset.setdefault(str(gate["dataset"]), []).append(str(gate["gate_id"]))

    dataset_names = sorted(set(datasets_by_name) | set(gates_by_dataset))
    readiness = [
        _dataset_readiness(
            dataset_name=dataset_name,
            dataset=datasets_by_name.get(dataset_name),
            gate_ids=sorted(gates_by_dataset.get(dataset_name, []), key=_gate_sort_key),
        )
        for dataset_name in dataset_names
    ]
    required = [dataset for dataset in readiness if dataset.required_for_controlled_run]
    return ReadinessReport(
        schema_version=SCHEMA_VERSION,
        generated_at=datetime.now(UTC).isoformat(timespec="seconds"),
        dry_run_schema_version=dry_run_plan.get("schema_version", "unknown"),
        external_dir=str(dry_run_plan.get("external_dir", "")),
        dataset_count=len(readiness),
        required_dataset_count=len(required),
        ready_required_dataset_count=sum(1 for dataset in required if dataset.status == "ready"),
        blocker_count=sum(len(dataset.blockers) for dataset in readiness),
        deferred_count=sum(1 for dataset in readiness if dataset.status == "deferred"),
        datasets=readiness,
        guardrails=[
            "Readiness reporting only: do not invoke Claude from this step.",
            "Do not mutate domains/**/*.yaml from dataset readiness output.",
            "Generated benchmark datasets remain under ignored benchmarks/external paths.",
            "Controlled execution still requires prepare_autoresearch_run.py "
            "and explicit --allow-claude-invocation.",
        ],
    )


def render_readiness_markdown(report: ReadinessReport) -> str:
    """Render a human-readable dataset readiness report."""
    lines = [
        f"# Phase 4 Autoresearch Readiness `{report.generated_at}`",
        "",
        f"- **Dry-run schema:** `{report.dry_run_schema_version}`",
        f"- **External directory:** `{report.external_dir}`",
        f"- **Datasets:** {report.dataset_count}",
        f"- **Required for controlled run:** {report.required_dataset_count}",
        f"- **Ready required datasets:** {report.ready_required_dataset_count}",
        f"- **Blockers:** {report.blocker_count}",
        f"- **Deferred datasets:** {report.deferred_count}",
        "",
        "## Guardrails",
        "",
    ]
    lines.extend(f"- {guardrail}" for guardrail in report.guardrails)
    lines.extend(["", "## Dataset Status", ""])
    lines.append(
        "| Dataset | Status | Required | Cases | Data Dir | Truth Files | "
        "Extractor | Gates | Blockers | Warnings |"
    )
    lines.append("|---|---|---|---:|---|---:|---|---|---|---|")
    for dataset in report.datasets:
        lines.append(
            "| "
            f"{dataset.dataset_name} | "
            f"{dataset.status} | "
            f"{_yes_no(dataset.required_for_controlled_run)} | "
            f"{dataset.case_count} | "
            f"{_yes_no(dataset.data_dir_exists)} | "
            f"{dataset.truth_file_count} | "
            f"{_yes_no(dataset.supported_by_extractor)} | "
            f"{', '.join(dataset.gate_ids) or '-'} | "
            f"{_join_notes(dataset.blockers)} | "
            f"{_join_notes(dataset.warnings)} |"
        )
    lines.extend(["", "## Materialization Checklist", ""])
    for dataset in report.datasets:
        if dataset.status == "ready" and not dataset.warnings:
            continue
        lines.extend(
            [
                f"### {dataset.dataset_name}",
                "",
                f"**Status:** `{dataset.status}`",
                "",
                dataset.action.title,
                "",
            ]
        )
        if dataset.action.commands:
            lines.append("```bash")
            lines.extend(dataset.action.commands)
            lines.append("```")
            lines.append("")
        if dataset.action.notes:
            lines.extend(f"- {note}" for note in dataset.action.notes)
            lines.append("")
    return "\n".join(lines)


def readiness_to_dict(report: ReadinessReport) -> dict[str, Any]:
    return asdict(report)


def write_readiness_json(path: Path, report: ReadinessReport) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(readiness_to_dict(report), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def write_readiness_markdown(path: Path, report: ReadinessReport) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_readiness_markdown(report), encoding="utf-8")


def load_dry_run_plan(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _dataset_readiness(
    *,
    dataset_name: str,
    dataset: dict[str, Any] | None,
    gate_ids: list[str],
) -> DatasetReadiness:
    required = bool(gate_ids)
    case_count = int(dataset.get("case_count", 0)) if dataset else 0
    data_dir_exists = bool(dataset.get("data_dir_exists")) if dataset else False
    truth_file_count = int(dataset.get("truth_file_count", 0)) if dataset else 0
    supported_by_extractor = bool(dataset.get("supported_by_extractor")) if dataset else False

    blockers: list[str] = []
    warnings: list[str] = []
    if dataset is None:
        blockers.append("tracked case manifest is absent from the dry-run inventory")
    if required and not data_dir_exists:
        blockers.append("external dataset directory is missing")
    if required and truth_file_count == 0:
        blockers.append("no truth.sarif files are materialized")
    if required and not supported_by_extractor:
        blockers.append("code extractor support is missing")

    if not required and not data_dir_exists:
        warnings.append("not required by active G5 gates, but external data is not materialized")
    if not required and truth_file_count == 0:
        warnings.append("not required by active G5 gates, but no truth.sarif files are present")
    if not required and not supported_by_extractor:
        warnings.append("not required by active G5 gates, and code extraction is not implemented")

    if dataset_name == "vul4j":
        warnings = [
            "Vul4J is intentionally deferred until a vulnerable/patched "
            "checkout convention is defined"
        ]
        status: ReadinessStatus = "deferred"
    elif blockers:
        status = "blocker"
    elif warnings:
        status = "warning"
    else:
        status = "ready"

    return DatasetReadiness(
        dataset_name=dataset_name,
        status=status,
        required_for_controlled_run=required,
        gate_ids=gate_ids,
        case_count=case_count,
        data_dir_exists=data_dir_exists,
        truth_file_count=truth_file_count,
        supported_by_extractor=supported_by_extractor,
        blockers=blockers,
        warnings=warnings,
        action=_action_for_dataset(dataset_name),
    )


def _action_for_dataset(dataset_name: str) -> ReadinessAction:
    if dataset_name == "morefixes":
        return ReadinessAction(
            title="Regenerate MoreFixes from the local Postgres dump and write code snapshots.",
            commands=[
                "bash benchmarks/scripts/deploy_morefixes.sh",
                "uv run python -m benchmarks.scripts.morefixes_extract",
            ],
            notes=[
                "The extractor now writes truth.sarif plus code/vulnerable "
                "and code/patched snapshots.",
                "The Docker database and generated dataset contents remain ignored local material.",
            ],
        )
    if dataset_name == "rust-d01-real-cves":
        return ReadinessAction(
            title="Materialize reviewed Rust D-01 truth and provide local repository clones.",
            commands=[
                "uv run python benchmarks/scripts/materialize_rust_d01.py",
                "git clone <repo_url> benchmarks/external/rust-d01-real-cves/repos/<owner__repo>",
            ],
            notes=[
                "Each case writes provenance.json with vulnerable_ref and patched_ref.",
                "Code extraction accepts case_dir/repo, repos/<owner__repo>, "
                "or repos/<owner>/<repo>.",
                "Rust D-01 real-CVE coverage is scoped to SQLi/CmdI/XSS; "
                "SSTI remains synthetic-only.",
            ],
        )
    if dataset_name == "vul4j":
        return ReadinessAction(
            title="Keep Vul4J deferred for controlled execution.",
            commands=[],
            notes=[
                "The current ingest records metadata and rough file locations only.",
                "Before enabling Vul4J, define a reproducible vulnerable/patched "
                "checkout layout and extractor contract.",
            ],
        )
    return ReadinessAction(
        title=(
            "Re-run the dataset ingest/bootstrap command if the external "
            "directory or truth files are missing."
        ),
        commands=[_INGEST_COMMANDS.get(dataset_name, "<no known ingest command>")],
        notes=[
            "Some legacy datasets have custom bootstrap steps; consult "
            "docs/PROJECT_STATUS.md and the dataset ingest script before a paid run.",
            "Generated external data must stay under ignored benchmarks/external paths.",
        ],
    )


def _gate_sort_key(gate_id: str) -> tuple[int, int | str]:
    prefix, _, suffix = gate_id.partition(".")
    try:
        return (int(prefix.removeprefix("G")), int(suffix))
    except ValueError:
        return (999, gate_id)


def _join_notes(notes: list[str]) -> str:
    return "<br>".join(notes) if notes else "-"


def _yes_no(value: bool) -> str:
    return "yes" if value else "no"
