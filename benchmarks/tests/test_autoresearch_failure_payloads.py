"""Tests for generating Phase 4 failure-input payloads from executor outputs."""
# ruff: noqa: S101

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from benchmarks.runner.cwe import load_hierarchy
from benchmarks.runner.invoker import InvokeResult
from benchmarks.runner.models import CodeLocation, Finding, FindingKind
from benchmarks.scripts.generate_autoresearch_failure_inputs import main as cli_main
from benchmarks.tests.test_autoresearch_controlled_executor import (
    _write_controlled_plan,
)
from screw_agents.autoresearch.controlled_executor import (
    build_controlled_executor_report,
    write_controlled_executor_report_json,
)
from screw_agents.autoresearch.failure_input import FailureAnalysisInput
from screw_agents.autoresearch.failure_payloads import (
    _evidence_quality_flags,
    _miss_diagnostics_summary,
    _related_agent_findings,
    build_failure_payloads_from_controlled_report,
)


def _write_executed_report(
    tmp_path: Path,
    *,
    vulnerable_findings: list[dict[str, object]] | None = None,
) -> Path:
    controlled_plan_path = _write_controlled_plan(tmp_path)

    def invoke(prompt: str, _config: object) -> InvokeResult:
        if "prepared_query" in prompt:
            return InvokeResult(
                success=True,
                findings=[
                    {
                        "cwe_id": "CWE-89",
                        "file": "src/db.php",
                        "start_line": 2,
                        "end_line": 3,
                        "confidence": 0.7,
                        "message": "Incorrectly flags patched query helper.",
                    }
                ],
            )
        return InvokeResult(success=True, findings=vulnerable_findings or [])

    with patch("benchmarks.runner.evaluator.invoke_claude", side_effect=invoke):
        report = build_controlled_executor_report(
            controlled_plan_path=controlled_plan_path,
            output_dir=tmp_path / "executor",
            execute=True,
            allow_claude_invocation=True,
            throttle_delay=0.0,
        )

    report_path = tmp_path / "executor" / "controlled_executor_report.json"
    write_controlled_executor_report_json(report_path, report)
    return report_path


def test_build_failure_payloads_from_controlled_report(tmp_path: Path) -> None:
    report_path = _write_executed_report(tmp_path)

    paths = build_failure_payloads_from_controlled_report(
        controlled_executor_report_path=report_path,
        output_dir=tmp_path / "payloads",
        domains_dir=Path("domains"),
    )

    assert [path.name for path in paths] == ["sqli_failure_input.json"]
    payload = FailureAnalysisInput.model_validate_json(
        paths[0].read_text(encoding="utf-8")
    )
    assert payload.agent.agent_name == "sqli"
    assert payload.guardrails.yaml_mutation_allowed is False
    assert payload.guardrails.aggregate_metrics_only is False
    assert len(payload.case_provenance) == 1
    assert len(payload.missed_findings) == 1
    assert len(payload.false_positive_findings) == 1
    assert payload.diagnostics is not None
    assert payload.diagnostics.total_missed == 1
    assert payload.diagnostics.pure_misses == 1
    assert payload.diagnostics.exact_span_false_negatives == 1
    assert payload.diagnostics.related_file_credit_candidates == 0
    assert payload.diagnostics.false_negatives_after_related_file_credit == 1
    assert payload.diagnostics.false_positive_findings == 1
    assert payload.diagnostics.false_positive_fix_semantics_ambiguous == 0
    assert payload.diagnostics.false_positive_residual_risk_or_incomplete_fix == 0
    assert payload.missed_findings[0].source_variant == "vulnerable"
    assert payload.false_positive_findings[0].source_variant == "patched"
    assert payload.missed_findings[0].code_excerpt is not None
    assert payload.missed_findings[0].evidence_quality_flags == []


def test_failure_payload_cli_writes_payloads(tmp_path: Path) -> None:
    report_path = _write_executed_report(tmp_path)
    output_dir = tmp_path / "cli-payloads"

    exit_code = cli_main(
        [
            "--controlled-executor-report",
            str(report_path),
            "--output-dir",
            str(output_dir),
            "--external-dir",
            str(tmp_path / "external"),
            "--max-missed-per-agent",
            "1",
            "--max-false-positives-per-agent",
            "1",
        ]
    )

    assert exit_code == 0
    payload_path = output_dir / "sqli_failure_input.json"
    payload = json.loads(payload_path.read_text(encoding="utf-8"))
    assert payload["schema_version"] == "phase4-autoresearch-failure-input/v1"
    assert payload["agent"]["agent_name"] == "sqli"


def test_generator_supports_executor_reports_without_result_counts(
    tmp_path: Path,
) -> None:
    report_path = _write_executed_report(tmp_path)
    report = json.loads(report_path.read_text(encoding="utf-8"))
    report.pop("result_counts")
    report_path.write_text(json.dumps(report), encoding="utf-8")

    paths = build_failure_payloads_from_controlled_report(
        controlled_executor_report_path=report_path,
        output_dir=tmp_path / "payloads",
        domains_dir=Path("domains"),
    )

    payload = FailureAnalysisInput.model_validate_json(
        paths[0].read_text(encoding="utf-8")
    )
    assert len(payload.missed_findings) == 1
    assert len(payload.false_positive_findings) == 1


def test_missed_payload_includes_related_vulnerable_findings(tmp_path: Path) -> None:
    report_path = _write_executed_report(
        tmp_path,
        vulnerable_findings=[
            {
                "cwe_id": "CWE-89",
                "file": "src/db.php",
                "start_line": 8,
                "end_line": 10,
                "confidence": 0.7,
                "message": "Same file SQL construction but outside truth span.",
            }
        ],
    )

    paths = build_failure_payloads_from_controlled_report(
        controlled_executor_report_path=report_path,
        output_dir=tmp_path / "payloads",
        domains_dir=Path("domains"),
    )

    payload = FailureAnalysisInput.model_validate_json(
        paths[0].read_text(encoding="utf-8")
    )
    related = payload.missed_findings[0].related_agent_findings
    assert len(related) == 1
    assert related[0].relationship == "nearby_same_file"
    assert related[0].line_distance == 4
    assert payload.diagnostics is not None
    assert payload.diagnostics.total_missed == 1
    assert payload.diagnostics.missed_with_related_findings == 1
    assert payload.diagnostics.missed_with_nearby_same_file_findings == 1
    assert payload.diagnostics.missed_with_same_file_only_findings == 0
    assert payload.diagnostics.missed_with_related_file_findings == 0
    assert payload.diagnostics.pure_misses == 0
    assert payload.diagnostics.exact_span_false_negatives == 1
    assert payload.diagnostics.related_file_credit_candidates == 0
    assert payload.diagnostics.false_negatives_after_related_file_credit == 1


def test_related_agent_findings_include_same_case_related_files() -> None:
    truth = Finding(
        cwe_id="CWE-78",
        kind=FindingKind.FAIL,
        location=CodeLocation(file="Shell.java", start_line=266, end_line=285),
    )
    findings = [
        Finding(
            cwe_id="CWE-78",
            kind=FindingKind.FAIL,
            location=CodeLocation(
                file="BourneShell.java",
                start_line=112,
                end_line=127,
            ),
            message="Related Bourne shell quoting defect.",
        )
    ]

    related = _related_agent_findings(
        truth=truth,
        findings=findings,
        hierarchy=load_hierarchy(),
    )

    assert len(related) == 1
    assert related[0].file == "BourneShell.java"
    assert related[0].relationship == "related_file_same_case"
    assert related[0].line_distance == 0


def test_related_agent_findings_can_omit_related_files() -> None:
    truth = Finding(
        cwe_id="CWE-78",
        kind=FindingKind.FAIL,
        location=CodeLocation(file="Shell.java", start_line=266, end_line=285),
    )
    findings = [
        Finding(
            cwe_id="CWE-78",
            kind=FindingKind.FAIL,
            location=CodeLocation(
                file="BourneShell.java",
                start_line=112,
                end_line=127,
            ),
        )
    ]

    related = _related_agent_findings(
        truth=truth,
        findings=findings,
        hierarchy=load_hierarchy(),
        include_related_files=False,
    )

    assert related == []


def test_diagnostics_count_related_file_misses() -> None:
    payload = FailureAnalysisInput(
        run={
            "run_id": "run",
            "generated_at": "2026-04-30T00:00:00+00:00",
            "mode": "controlled-smoke",
        },
        agent={
            "agent_name": "cmdi",
            "domain_path": "domains/injection-input-handling/cmdi.yaml",
            "yaml_sha256": "0" * 64,
        },
        case_provenance=[
            {
                "dataset_name": "reality-check-java",
                "case_id": "case",
                "project": "plexus-utils",
                "language": "java",
                "vulnerable_version": "vuln",
                "patched_version": "patched",
                "manifest_path": "manifest.json",
                "truth_path": "truth.sarif",
            }
        ],
        missed_findings=[
            {
                "kind": "missed",
                "dataset_name": "reality-check-java",
                "case_id": "case",
                "source_variant": "vulnerable",
                "agent_name": "cmdi",
                "cwe_id": "CWE-78",
                "file": "Shell.java",
                "start_line": 266,
                "end_line": 285,
                "expected_behavior": "Flag this span.",
                "observed_behavior": "No exact match.",
                "related_agent_findings": [
                    {
                        "file": "BourneShell.java",
                        "start_line": 112,
                        "end_line": 127,
                        "cwe_id": "CWE-78",
                        "line_distance": 0,
                        "relationship": "related_file_same_case",
                    }
                ],
            }
        ],
        guardrails={
            "reason": "test",
            "aggregate_metrics_only": False,
        },
    )

    diagnostics = _miss_diagnostics_summary(
        missed_findings=payload.missed_findings,
        false_positive_findings=[],
    )

    assert diagnostics.missed_with_related_findings == 1
    assert diagnostics.missed_with_related_file_findings == 1
    assert diagnostics.pure_misses == 0
    assert diagnostics.exact_span_false_negatives == 1
    assert diagnostics.related_file_credit_candidates == 1
    assert diagnostics.false_negatives_after_related_file_credit == 0


def test_related_file_credit_keeps_exact_false_negative_visible() -> None:
    payload = FailureAnalysisInput(
        run={
            "run_id": "run",
            "generated_at": "2026-04-30T00:00:00+00:00",
            "mode": "controlled-smoke",
        },
        agent={
            "agent_name": "cmdi",
            "domain_path": "domains/injection-input-handling/cmdi.yaml",
            "yaml_sha256": "0" * 64,
        },
        case_provenance=[
            {
                "dataset_name": "reality-check-java",
                "case_id": "case",
                "project": "plexus-utils",
                "language": "java",
                "vulnerable_version": "vuln",
                "patched_version": "patched",
                "manifest_path": "manifest.json",
                "truth_path": "truth.sarif",
            }
        ],
        missed_findings=[
            {
                "kind": "missed",
                "dataset_name": "reality-check-java",
                "case_id": "case",
                "source_variant": "vulnerable",
                "agent_name": "cmdi",
                "cwe_id": "CWE-78",
                "file": "Shell.java",
                "start_line": 40,
                "end_line": 409,
                "expected_behavior": "Flag this span.",
                "observed_behavior": "No exact match.",
                "related_agent_findings": [
                    {
                        "file": "BourneShell.java",
                        "start_line": 72,
                        "end_line": 80,
                        "cwe_id": "CWE-78",
                        "line_distance": 0,
                        "relationship": "related_file_same_case",
                    }
                ],
            },
            {
                "kind": "missed",
                "dataset_name": "reality-check-java",
                "case_id": "case",
                "source_variant": "vulnerable",
                "agent_name": "cmdi",
                "cwe_id": "CWE-78",
                "file": "Shell.java",
                "start_line": 500,
                "end_line": 510,
                "expected_behavior": "Flag this span.",
                "observed_behavior": "No exact match.",
            },
        ],
        guardrails={
            "reason": "test",
            "aggregate_metrics_only": False,
        },
    )

    diagnostics = _miss_diagnostics_summary(
        missed_findings=payload.missed_findings,
        false_positive_findings=[],
    )

    assert diagnostics.total_missed == 2
    assert diagnostics.exact_span_false_negatives == 2
    assert diagnostics.related_file_credit_candidates == 1
    assert diagnostics.false_negatives_after_related_file_credit == 1


def test_payload_diagnostics_count_evidence_quality_flags(tmp_path: Path) -> None:
    report_path = _write_executed_report(tmp_path)
    vulnerable_file = (
        tmp_path
        / "external"
        / "morefixes"
        / "morefixes-CVE-2024-0001-example"
        / "code"
        / "vulnerable"
        / "src%2Fdb.php"
    )
    vulnerable_file.unlink()

    paths = build_failure_payloads_from_controlled_report(
        controlled_executor_report_path=report_path,
        output_dir=tmp_path / "payloads",
        domains_dir=Path("domains"),
    )

    payload = FailureAnalysisInput.model_validate_json(
        paths[0].read_text(encoding="utf-8")
    )
    assert payload.missed_findings[0].evidence_quality_flags == [
        "missing_code_excerpt"
    ]
    assert payload.diagnostics is not None
    assert payload.diagnostics.missed_with_missing_code_excerpt == 1
    assert payload.diagnostics.missed_in_test_file_paths == 0


def test_evidence_quality_flags_identify_test_file_paths() -> None:
    assert _evidence_quality_flags(
        file_path="OWASP.AntiSamyTests/Html/AntiSamyTest.cs",
        code_excerpt="public void TestSmuggledTagsInStyleContent() {}",
    ) == ["test_file_path"]


def test_diagnostics_count_fix_semantics_false_positive_flags() -> None:
    false_positive_findings = [
        FailureAnalysisInput.model_validate(
            {
                "run": {
                    "run_id": "run",
                    "generated_at": "2026-04-30T00:00:00+00:00",
                    "mode": "controlled-smoke",
                },
                "agent": {
                    "agent_name": "sqli",
                    "domain_path": "domains/injection-input-handling/sqli.yaml",
                    "yaml_sha256": "0" * 64,
                },
                "case_provenance": [
                    {
                        "dataset_name": "morefixes",
                        "case_id": "case",
                        "project": "app",
                        "language": "php",
                        "vulnerable_version": "vuln",
                        "patched_version": "patched",
                        "manifest_path": "manifest.json",
                        "truth_path": "truth.sarif",
                    }
                ],
                "false_positive_findings": [
                    {
                        "kind": "false_positive",
                        "dataset_name": "morefixes",
                        "case_id": "case",
                        "source_variant": "patched",
                        "agent_name": "sqli",
                        "cwe_id": "CWE-89",
                        "file": "plugin.php",
                        "start_line": 30,
                        "end_line": 33,
                        "expected_behavior": "Do not flag clean patched code.",
                        "observed_behavior": "Agent flagged patched code.",
                        "evidence_quality_flags": ["fix_semantics_ambiguous"],
                    },
                    {
                        "kind": "false_positive",
                        "dataset_name": "morefixes",
                        "case_id": "case",
                        "source_variant": "patched",
                        "agent_name": "sqli",
                        "cwe_id": "CWE-89",
                        "file": "action.php",
                        "start_line": 60,
                        "end_line": 64,
                        "expected_behavior": "Do not flag clean patched code.",
                        "observed_behavior": "Agent flagged patched code.",
                        "evidence_quality_flags": [
                            "residual_risk_or_incomplete_fix"
                        ],
                    },
                ],
                "guardrails": {
                    "reason": "test",
                    "aggregate_metrics_only": False,
                },
            }
        ).false_positive_findings
    ][0]

    diagnostics = _miss_diagnostics_summary(
        missed_findings=[],
        false_positive_findings=false_positive_findings,
    )

    assert diagnostics.false_positive_findings == 2
    assert diagnostics.false_positive_fix_semantics_ambiguous == 1
    assert diagnostics.false_positive_residual_risk_or_incomplete_fix == 1
