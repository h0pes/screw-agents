"""Tests for the Phase 4 autoresearch failure-analysis input contract."""
# ruff: noqa: S101

from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from screw_agents.autoresearch.failure_input import (
    SCHEMA_VERSION,
    AgentSourceVersion,
    BenchmarkRunMetadata,
    CaseProvenance,
    FailureAnalysisInput,
    FailureExample,
    GuardrailState,
)


def _run() -> BenchmarkRunMetadata:
    return BenchmarkRunMetadata(
        run_id="20260428-000001",
        generated_at="2026-04-28T00:00:01+00:00",
        mode="sample",
        split_name="sample",
        summary_paths=["benchmarks/results/run/summary.json"],
        metrics={"tpr": 0.42},
    )


def _agent() -> AgentSourceVersion:
    return AgentSourceVersion(
        agent_name="sqli",
        domain_path="domains/injection-input-handling/sqli.yaml",
        yaml_sha256="a" * 64,
        yaml_version="1.0",
        yaml_last_updated="2026-04-28",
    )


def _case() -> CaseProvenance:
    return CaseProvenance(
        dataset_name="morefixes",
        case_id="morefixes-CVE-2024-0001-example",
        project="https://github.com/example/app",
        language="php",
        vulnerable_version="pre-deadbeef",
        patched_version="deadbeef",
        manifest_path="benchmarks/external/manifests/morefixes.manifest.json",
        truth_path=(
            "benchmarks/external/morefixes/"
            "morefixes-CVE-2024-0001-example/truth.sarif"
        ),
        source_url="https://doi.org/10.5281/zenodo.13983082",
    )


def _missed_example() -> FailureExample:
    return FailureExample(
        kind="missed",
        dataset_name="morefixes",
        case_id="morefixes-CVE-2024-0001-example",
        source_variant="vulnerable",
        agent_name="sqli",
        cwe_id="CWE-89",
        file="src/db.php",
        start_line=12,
        end_line=15,
        expected_behavior="Flag the string-concatenated SQL query.",
        observed_behavior="No finding was returned.",
        code_excerpt="$db->query('SELECT * FROM users WHERE id=' . $id);",
    )


def test_failure_analysis_input_defaults_to_no_yaml_mutation() -> None:
    payload = FailureAnalysisInput(
        run=_run(),
        agent=_agent(),
        case_provenance=[_case()],
        missed_findings=[_missed_example()],
        guardrails=GuardrailState(
            reason="Dry-run analysis only; human review has not approved YAML edits.",
        ),
    )

    assert payload.schema_version == SCHEMA_VERSION
    assert payload.guardrails.yaml_mutation_allowed is False
    assert payload.guardrails.aggregate_metrics_only is True


def test_failure_analysis_input_round_trips_via_json() -> None:
    payload = FailureAnalysisInput(
        run=_run(),
        agent=_agent(),
        case_provenance=[_case()],
        missed_findings=[_missed_example()],
        guardrails=GuardrailState(
            reason="Concrete examples are present, but mutation remains disabled.",
        ),
    )

    restored = FailureAnalysisInput.model_validate_json(payload.model_dump_json())

    assert restored == payload
    dumped = json.loads(restored.model_dump_json())
    assert dumped["schema_version"] == SCHEMA_VERSION


def test_yaml_mutation_requires_concrete_examples() -> None:
    with pytest.raises(ValidationError, match="at least one concrete example"):
        FailureAnalysisInput(
            run=_run(),
            agent=_agent(),
            case_provenance=[_case()],
            guardrails=GuardrailState(
                yaml_mutation_allowed=True,
                aggregate_metrics_only=False,
                reason="Human review approved a concrete change.",
            ),
        )


def test_yaml_mutation_requires_non_aggregate_payload() -> None:
    with pytest.raises(ValidationError, match="aggregate_metrics_only=False"):
        FailureAnalysisInput(
            run=_run(),
            agent=_agent(),
            case_provenance=[_case()],
            missed_findings=[_missed_example()],
            guardrails=GuardrailState(
                yaml_mutation_allowed=True,
                aggregate_metrics_only=True,
                reason="Aggregate metrics alone are insufficient.",
            ),
        )


def test_yaml_mutation_can_be_allowed_with_concrete_reviewable_examples() -> None:
    payload = FailureAnalysisInput(
        run=_run(),
        agent=_agent(),
        case_provenance=[_case()],
        missed_findings=[_missed_example()],
        guardrails=GuardrailState(
            yaml_mutation_allowed=True,
            aggregate_metrics_only=False,
            reason="Concrete missed finding reviewed by a human.",
        ),
    )

    assert payload.guardrails.yaml_mutation_allowed is True
    assert payload.guardrails.human_review_required is True


def test_examples_must_reference_case_provenance() -> None:
    example = _missed_example().model_copy(update={"case_id": "missing-case"})

    with pytest.raises(ValidationError, match="case_provenance"):
        FailureAnalysisInput(
            run=_run(),
            agent=_agent(),
            case_provenance=[_case()],
            missed_findings=[example],
            guardrails=GuardrailState(reason="Example provenance is incomplete."),
        )


def test_false_positive_bucket_requires_false_positive_kind() -> None:
    with pytest.raises(ValidationError, match="kind='false_positive'"):
        FailureAnalysisInput(
            run=_run(),
            agent=_agent(),
            case_provenance=[_case()],
            false_positive_findings=[_missed_example()],
            guardrails=GuardrailState(reason="Wrong example bucket."),
        )


def test_example_agent_must_match_payload_agent() -> None:
    example = _missed_example().model_copy(update={"agent_name": "xss"})

    with pytest.raises(ValidationError, match="agent_name"):
        FailureAnalysisInput(
            run=_run(),
            agent=_agent(),
            case_provenance=[_case()],
            missed_findings=[example],
            guardrails=GuardrailState(reason="Mixed-agent payloads are not allowed."),
        )


def test_example_line_order_is_validated() -> None:
    data = _missed_example().model_dump()
    data["start_line"] = 20
    data["end_line"] = 10

    with pytest.raises(ValidationError, match="start_line"):
        FailureExample.model_validate(data)
