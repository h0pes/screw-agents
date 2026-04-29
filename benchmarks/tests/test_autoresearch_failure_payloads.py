"""Tests for generating Phase 4 failure-input payloads from executor outputs."""
# ruff: noqa: S101

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from benchmarks.runner.invoker import InvokeResult
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
    assert payload.missed_findings[0].source_variant == "vulnerable"
    assert payload.false_positive_findings[0].source_variant == "patched"
    assert payload.missed_findings[0].code_excerpt is not None


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
