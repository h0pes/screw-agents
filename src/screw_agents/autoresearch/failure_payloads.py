"""Build Phase 4 failure-analysis payloads from controlled executor outputs.

This module is deliberately mechanical: it reads reviewed benchmark artifacts,
extracts concrete misses and false positives, and validates them against the
existing failure-input schema. It does not invoke Claude and it does not edit
agent YAML.
"""

from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from pathlib import Path
from typing import Any

import yaml

from benchmarks.runner.code_extractor import CodeVariant, extract_code_for_case
from benchmarks.runner.cwe import load_hierarchy
from benchmarks.runner.metrics import locations_match
from benchmarks.runner.models import (
    BenchmarkCase,
    CodeLocation,
    Finding,
    FindingKind,
    Language,
)
from benchmarks.runner.sarif import load_bentoo_sarif
from screw_agents.autoresearch.controlled_executor import (
    ControlledExecutorReport,
    ControlledExecutorResultCounts,
)
from screw_agents.autoresearch.controlled_run import ControlledExecutionPlan
from screw_agents.autoresearch.failure_input import (
    AgentSourceVersion,
    BenchmarkRunMetadata,
    CaseProvenance,
    FailureAnalysisInput,
    FailureExample,
    GuardrailState,
    MissDiagnosticsSummary,
    RelatedAgentFinding,
)


def build_failure_payloads_from_controlled_report(
    *,
    controlled_executor_report_path: Path,
    output_dir: Path,
    domains_dir: Path = Path("domains"),
    external_dir_override: Path | None = None,
    max_missed_per_agent: int = 5,
    max_false_positives_per_agent: int = 5,
    include_code_excerpt: bool = True,
) -> list[Path]:
    """Write one failure-analysis payload per agent and return output paths."""
    report = ControlledExecutorReport.model_validate_json(
        controlled_executor_report_path.read_text(encoding="utf-8")
    )
    if not report.execution_performed or report.benchmark_run_id is None:
        raise ValueError("controlled executor report must come from an executed run")

    controlled_plan_path = Path(report.config.controlled_plan_path)
    plan = ControlledExecutionPlan.model_validate_json(
        controlled_plan_path.read_text(encoding="utf-8")
    )
    dry_run_plan = json.loads(
        Path(plan.config.dry_run_plan_path).read_text(encoding="utf-8")
    )
    external_dir = external_dir_override or Path(
        str(dry_run_plan.get("external_dir", "benchmarks/external"))
    )
    datasets_by_name = {
        str(dataset["dataset_name"]): dataset
        for dataset in dry_run_plan.get("datasets", [])
    }
    raw_cases_by_dataset = {
        dataset_name: _load_manifest_cases(Path(str(dataset["manifest_path"])))
        for dataset_name, dataset in datasets_by_name.items()
    }

    cases_by_key: dict[tuple[str, str], ControlledCaseContext] = {}
    for report_case in report.cases:
        raw_case = raw_cases_by_dataset[report_case.dataset][report_case.case_id]
        manifest_path = Path(str(datasets_by_name[report_case.dataset]["manifest_path"]))
        case = _load_benchmark_case(
            raw_case=raw_case,
            dataset_name=report_case.dataset,
            external_dir=external_dir,
        )
        cases_by_key[(report_case.dataset, report_case.case_id)] = ControlledCaseContext(
            agent_name=report_case.agent,
            manifest_path=manifest_path,
            truth_path=external_dir
            / report_case.dataset
            / report_case.case_id
            / "truth.sarif",
            raw_case=raw_case,
            case=case,
            include_related_context=report_case.include_related_context,
        )

    grouped: dict[str, AgentPayloadParts] = defaultdict(AgentPayloadParts)
    for result in _result_counts(report, controlled_executor_report_path):
        context = cases_by_key[(result.dataset, result.case_id)]
        parts = grouped[result.agent]
        parts.case_provenance[(result.dataset, result.case_id)] = _case_provenance(
            context
        )
        parts.metrics.update(_summary_metrics_for(report, result.agent, result.dataset))

        vulnerable_findings = _load_agent_findings(
            Path(result.vulnerable_result_path),
            result.agent,
        )
        patched_findings = _load_agent_findings(
            Path(result.patched_result_path),
            result.agent,
        )
        if len(parts.missed_findings) < max_missed_per_agent:
            parts.missed_findings.extend(
                _missed_examples(
                    context=context,
                    agent_name=result.agent,
                    vulnerable_findings=vulnerable_findings,
                    max_count=max_missed_per_agent - len(parts.missed_findings),
                    include_code_excerpt=include_code_excerpt,
                    external_dir=external_dir,
                )
            )
        if len(parts.false_positive_findings) < max_false_positives_per_agent:
            parts.false_positive_findings.extend(
                _false_positive_examples(
                    context=context,
                    agent_name=result.agent,
                    patched_findings=patched_findings,
                    max_count=(
                        max_false_positives_per_agent
                        - len(parts.false_positive_findings)
                    ),
                    include_code_excerpt=include_code_excerpt,
                    external_dir=external_dir,
                )
            )

    output_dir.mkdir(parents=True, exist_ok=True)
    output_paths: list[Path] = []
    for agent_name in sorted(grouped):
        parts = grouped[agent_name]
        if not parts.missed_findings and not parts.false_positive_findings:
            continue
        payload = FailureAnalysisInput(
            run=BenchmarkRunMetadata(
                run_id=report.benchmark_run_id,
                generated_at=report.generated_at,
                mode="controlled-smoke",
                split_name="controlled-smoke",
                summary_paths=[str(controlled_executor_report_path)],
                metrics=parts.metrics,
            ),
            agent=_agent_source_version(agent_name, domains_dir),
            case_provenance=list(parts.case_provenance.values()),
            missed_findings=parts.missed_findings,
            false_positive_findings=parts.false_positive_findings,
            diagnostics=_miss_diagnostics_summary(
                missed_findings=parts.missed_findings,
                false_positive_findings=parts.false_positive_findings,
            ),
            guardrails=GuardrailState(
                yaml_mutation_allowed=False,
                aggregate_metrics_only=False,
                reason=(
                    "Payload was generated from concrete controlled-smoke "
                    "case examples. YAML mutation remains disabled until human "
                    "review approves a targeted change."
                ),
            ),
        )
        path = output_dir / f"{agent_name}_failure_input.json"
        path.write_text(
            json.dumps(payload.model_dump(mode="json"), indent=2, sort_keys=True)
            + "\n",
            encoding="utf-8",
        )
        output_paths.append(path)
    return output_paths


def _miss_diagnostics_summary(
    *,
    missed_findings: list[FailureExample],
    false_positive_findings: list[FailureExample],
) -> MissDiagnosticsSummary:
    nearby = 0
    same_file_only = 0
    related_file = 0
    pure = 0
    missing_code_excerpt = 0
    test_file_paths = 0
    for example in missed_findings:
        relationships = {
            finding.relationship for finding in example.related_agent_findings
        }
        if "nearby_same_file" in relationships:
            nearby += 1
        elif "same_file" in relationships:
            same_file_only += 1
        elif "related_file_same_case" in relationships:
            related_file += 1
        else:
            pure += 1
        flags = set(example.evidence_quality_flags)
        if "missing_code_excerpt" in flags:
            missing_code_excerpt += 1
        if "test_file_path" in flags:
            test_file_paths += 1
    return MissDiagnosticsSummary(
        total_missed=len(missed_findings),
        missed_with_related_findings=nearby + same_file_only + related_file,
        missed_with_nearby_same_file_findings=nearby,
        missed_with_same_file_only_findings=same_file_only,
        missed_with_related_file_findings=related_file,
        pure_misses=pure,
        exact_span_false_negatives=len(missed_findings),
        related_file_credit_candidates=related_file,
        false_negatives_after_related_file_credit=len(missed_findings)
        - related_file,
        false_positive_findings=len(false_positive_findings),
        missed_with_missing_code_excerpt=missing_code_excerpt,
        missed_in_test_file_paths=test_file_paths,
    )


class ControlledCaseContext:
    """Resolved selected case plus source artifact paths."""

    def __init__(
        self,
        *,
        agent_name: str,
        manifest_path: Path,
        truth_path: Path,
        raw_case: dict[str, Any],
        case: BenchmarkCase,
        include_related_context: bool,
    ) -> None:
        self.agent_name = agent_name
        self.manifest_path = manifest_path
        self.truth_path = truth_path
        self.raw_case = raw_case
        self.case = case
        self.include_related_context = include_related_context


class AgentPayloadParts:
    """Accumulated examples for one single-agent payload."""

    def __init__(self) -> None:
        self.case_provenance: dict[tuple[str, str], CaseProvenance] = {}
        self.missed_findings: list[FailureExample] = []
        self.false_positive_findings: list[FailureExample] = []
        self.metrics: dict[str, Any] = {}


def _load_manifest_cases(manifest_path: Path) -> dict[str, dict[str, Any]]:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    return {str(case["case_id"]): case for case in manifest.get("cases", [])}


def _result_counts(
    report: ControlledExecutorReport,
    controlled_executor_report_path: Path,
) -> list[ControlledExecutorResultCounts]:
    if report.result_counts:
        return report.result_counts
    if report.benchmark_run_id is None:
        return []
    cases_dir = (
        controlled_executor_report_path.parent
        / "benchmark-runs"
        / report.benchmark_run_id
        / "cases"
    )
    return [
        ControlledExecutorResultCounts(
            case_id=case.case_id,
            agent=case.agent,
            dataset=case.dataset,
            vulnerable_finding_count=_json_array_len(
                cases_dir / f"{case.case_id}_vuln.json"
            ),
            patched_finding_count=_json_array_len(
                cases_dir / f"{case.case_id}_patched.json"
            ),
            vulnerable_result_path=str(cases_dir / f"{case.case_id}_vuln.json"),
            patched_result_path=str(cases_dir / f"{case.case_id}_patched.json"),
        )
        for case in report.cases
    ]


def _load_benchmark_case(
    *,
    raw_case: dict[str, Any],
    dataset_name: str,
    external_dir: Path,
) -> BenchmarkCase:
    case_id = str(raw_case["case_id"])
    return BenchmarkCase(
        case_id=case_id,
        project=str(raw_case["project"]),
        language=Language(str(raw_case["language"])),
        vulnerable_version=str(raw_case["vulnerable_version"]),
        patched_version=str(raw_case["patched_version"]),
        ground_truth=load_bentoo_sarif(
            external_dir / dataset_name / case_id / "truth.sarif"
        ),
        published_date=raw_case.get("published_date"),
        source_dataset=dataset_name,
    )


def _json_array_len(path: Path) -> int:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise ValueError(f"Expected JSON array at {path}")
    return len(data)


def _case_provenance(context: ControlledCaseContext) -> CaseProvenance:
    raw = context.raw_case
    return CaseProvenance(
        dataset_name=context.case.source_dataset,
        case_id=context.case.case_id,
        project=context.case.project,
        language=context.case.language.value,
        vulnerable_version=context.case.vulnerable_version,
        patched_version=context.case.patched_version,
        manifest_path=str(context.manifest_path),
        truth_path=str(context.truth_path),
        source_url=raw.get("source_url") or raw.get("url"),
    )


def _load_agent_findings(path: Path, agent_name: str) -> list[Finding]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    findings: list[Finding] = []
    for item in raw:
        findings.append(
            Finding(
                cwe_id=str(item["cwe_id"]),
                kind=FindingKind.FAIL,
                location=CodeLocation(
                    file=str(item["file"]),
                    start_line=int(item["start_line"]),
                    end_line=int(item["end_line"]),
                ),
                agent_name=agent_name,
                confidence=float(item.get("confidence", 0.5)),
                message=item.get("message"),
            )
        )
    return findings


def _missed_examples(
    *,
    context: ControlledCaseContext,
    agent_name: str,
    vulnerable_findings: list[Finding],
    max_count: int,
    include_code_excerpt: bool,
    external_dir: Path,
) -> list[FailureExample]:
    if max_count <= 0:
        return []
    hierarchy = load_hierarchy()
    examples: list[FailureExample] = []
    for truth in _truths(context.case, FindingKind.FAIL):
        if _has_matching_finding(truth, vulnerable_findings, hierarchy):
            continue
        code_excerpt = (
            _excerpt(
                context.case,
                CodeVariant.VULNERABLE,
                truth.location.file,
                truth.location.start_line,
                truth.location.end_line,
                external_dir,
            )
            if include_code_excerpt
            else None
        )
        examples.append(
            FailureExample(
                kind="missed",
                dataset_name=context.case.source_dataset,
                case_id=context.case.case_id,
                source_variant="vulnerable",
                agent_name=agent_name,
                cwe_id=truth.cwe_id,
                file=truth.location.file,
                start_line=truth.location.start_line,
                end_line=truth.location.end_line,
                expected_behavior="Flag this ground-truth vulnerable location.",
                observed_behavior="No matching vulnerable-version finding was returned.",
                message=truth.message,
                code_excerpt=code_excerpt,
                related_agent_findings=_related_agent_findings(
                    truth=truth,
                    findings=vulnerable_findings,
                    hierarchy=hierarchy,
                    include_related_files=context.include_related_context,
                ),
                evidence_quality_flags=_evidence_quality_flags(
                    file_path=truth.location.file,
                    code_excerpt=code_excerpt,
                ),
            )
        )
        if len(examples) >= max_count:
            break
    return examples


def _false_positive_examples(
    *,
    context: ControlledCaseContext,
    agent_name: str,
    patched_findings: list[Finding],
    max_count: int,
    include_code_excerpt: bool,
    external_dir: Path,
) -> list[FailureExample]:
    if max_count <= 0:
        return []
    examples: list[FailureExample] = []
    for finding in patched_findings:
        code_excerpt = (
            _excerpt(
                context.case,
                CodeVariant.PATCHED,
                finding.location.file,
                finding.location.start_line,
                finding.location.end_line,
                external_dir,
            )
            if include_code_excerpt
            else None
        )
        examples.append(
            FailureExample(
                kind="false_positive",
                dataset_name=context.case.source_dataset,
                case_id=context.case.case_id,
                source_variant="patched",
                agent_name=agent_name,
                cwe_id=finding.cwe_id,
                file=finding.location.file,
                start_line=finding.location.start_line,
                end_line=finding.location.end_line,
                expected_behavior=(
                    "Do not flag the patched version unless a distinct "
                    "vulnerability remains."
                ),
                observed_behavior="Agent returned a finding on the patched version.",
                message=finding.message,
                code_excerpt=code_excerpt,
                evidence_quality_flags=_evidence_quality_flags(
                    file_path=finding.location.file,
                    code_excerpt=code_excerpt,
                ),
            )
        )
        if len(examples) >= max_count:
            break
    return examples


def _truths(case: BenchmarkCase, kind: FindingKind) -> list[Finding]:
    return [truth for truth in case.ground_truth if truth.kind == kind]


def _has_matching_finding(
    truth: Finding,
    findings: list[Finding],
    hierarchy: Any,
) -> bool:
    return any(
        locations_match(truth.location, finding.location)
        and hierarchy.broad_match(finding.cwe_id, truth.cwe_id)
        for finding in findings
    )


def _related_agent_findings(
    *,
    truth: Finding,
    findings: list[Finding],
    hierarchy: Any,
    include_related_files: bool = True,
    max_count: int = 3,
) -> list[RelatedAgentFinding]:
    same_file_candidates: list[tuple[int, Finding]] = []
    related_file_candidates: list[Finding] = []
    for finding in findings:
        if not hierarchy.broad_match(finding.cwe_id, truth.cwe_id):
            continue
        if finding.location.file == truth.location.file:
            if locations_match(truth.location, finding.location):
                continue
            same_file_candidates.append(
                (_line_distance(truth.location, finding.location), finding)
            )
        elif include_related_files:
            related_file_candidates.append(finding)

    related: list[RelatedAgentFinding] = []
    for distance, finding in sorted(
        same_file_candidates,
        key=lambda item: item[0],
    )[:max_count]:
        related.append(
            RelatedAgentFinding(
                file=finding.location.file,
                start_line=finding.location.start_line,
                end_line=finding.location.end_line,
                cwe_id=finding.cwe_id,
                line_distance=distance,
                relationship=(
                    "nearby_same_file" if distance <= 25 else "same_file"
                ),
                message=finding.message,
            )
        )
    remaining = max_count - len(related)
    for finding in sorted(
        related_file_candidates,
        key=lambda item: (item.location.file, item.location.start_line),
    )[:remaining]:
        related.append(
            RelatedAgentFinding(
                file=finding.location.file,
                start_line=finding.location.start_line,
                end_line=finding.location.end_line,
                cwe_id=finding.cwe_id,
                line_distance=0,
                relationship="related_file_same_case",
                message=finding.message,
            )
        )
    return related


def _line_distance(a: CodeLocation, b: CodeLocation) -> int:
    if locations_match(a, b):
        return 0
    if b.end_line < a.start_line:
        return a.start_line - b.end_line
    return b.start_line - a.end_line


def _evidence_quality_flags(
    *,
    file_path: str,
    code_excerpt: str | None,
) -> list[str]:
    flags: list[str] = []
    if not code_excerpt:
        flags.append("missing_code_excerpt")
    normalized = file_path.replace("\\", "/").lower()
    path_parts = normalized.split("/")
    file_name = path_parts[-1]
    if (
        "test" in path_parts
        or "tests" in path_parts
        or "test" in file_name
        or file_name.endswith("spec.js")
        or file_name.endswith("spec.ts")
    ):
        flags.append("test_file_path")
    return flags


def _excerpt(
    case: BenchmarkCase,
    variant: CodeVariant,
    file_path: str,
    start_line: int,
    end_line: int,
    external_dir: Path,
) -> str | None:
    try:
        pieces = extract_code_for_case(case, variant, external_dir)
    except FileNotFoundError:
        return None
    piece = next((item for item in pieces if item.file_path == file_path), None)
    if piece is None:
        return None
    lines = piece.content.splitlines()
    start = max(start_line - 2, 1)
    end = min(end_line + 2, len(lines))
    rendered = []
    for line_no in range(start, end + 1):
        rendered.append(f"{line_no}: {lines[line_no - 1]}")
    return "\n".join(rendered)


def _summary_metrics_for(
    report: ControlledExecutorReport,
    agent_name: str,
    dataset: str,
) -> dict[str, Any]:
    for summary in report.summaries:
        if summary.get("agent_name") == agent_name and summary.get("dataset") == dataset:
            metric = next(
                (
                    item
                    for item in summary.get("metrics", [])
                    if item.get("cwe_id") is None and item.get("language") is None
                ),
                None,
            )
            if metric is not None:
                return {dataset: metric}
    return {}


def _agent_source_version(agent_name: str, domains_dir: Path) -> AgentSourceVersion:
    domain_path = _agent_yaml_path(agent_name, domains_dir)
    content = domain_path.read_bytes()
    raw = yaml.safe_load(content)
    meta = raw["meta"]
    return AgentSourceVersion(
        agent_name=agent_name,
        domain_path=str(domain_path),
        yaml_sha256=hashlib.sha256(content).hexdigest(),
        yaml_version=str(meta.get("version")) if meta.get("version") is not None else None,
        yaml_last_updated=(
            str(meta.get("last_updated"))
            if meta.get("last_updated") is not None
            else None
        ),
    )


def _agent_yaml_path(agent_name: str, domains_dir: Path) -> Path:
    matches = sorted(domains_dir.rglob(f"{agent_name}.yaml"))
    if len(matches) != 1:
        raise ValueError(
            f"Expected exactly one YAML for agent {agent_name!r}, found {len(matches)}"
        )
    return matches[0]
