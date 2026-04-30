"""Structured input contract for Phase 4 autoresearch failure analysis.

This module defines the payload future autoresearch steps consume after a
benchmark run. It is intentionally schema-only: it does not invoke LLMs and it
does not edit agent YAML.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

SCHEMA_VERSION = "phase4-autoresearch-failure-input/v1"


class BenchmarkRunMetadata(BaseModel):
    """Identifies the benchmark run and split that produced the examples."""

    model_config = ConfigDict(extra="forbid")

    run_id: str
    generated_at: str
    mode: str
    split_name: str | None = None
    summary_paths: list[str] = []
    metrics: dict[str, Any] = {}


class AgentSourceVersion(BaseModel):
    """Identifies the exact YAML source that was benchmarked."""

    model_config = ConfigDict(extra="forbid")

    agent_name: str
    domain_path: str
    yaml_sha256: str = Field(min_length=64, max_length=64)
    yaml_version: str | None = None
    yaml_last_updated: str | None = None


class CaseProvenance(BaseModel):
    """Links a failure example back to manifest and truth data."""

    model_config = ConfigDict(extra="forbid")

    dataset_name: str
    case_id: str
    project: str
    language: str
    vulnerable_version: str
    patched_version: str
    manifest_path: str
    truth_path: str
    source_url: str | None = None


class RelatedAgentFinding(BaseModel):
    """An agent finding that may explain a missed truth span."""

    model_config = ConfigDict(extra="forbid")

    file: str
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)
    cwe_id: str
    line_distance: int = Field(ge=0)
    relationship: Literal[
        "nearby_same_file",
        "same_file",
        "related_file_same_case",
    ]
    message: str | None = None

    @model_validator(mode="after")
    def check_line_order(self) -> RelatedAgentFinding:
        if self.start_line > self.end_line:
            raise ValueError("start_line must be <= end_line")
        return self


class FailureExample(BaseModel):
    """A concrete missed vulnerability or false-positive example."""

    model_config = ConfigDict(extra="forbid")

    kind: Literal["missed", "false_positive"]
    dataset_name: str
    case_id: str
    source_variant: Literal["vulnerable", "patched"]
    agent_name: str
    cwe_id: str
    file: str
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)
    expected_behavior: str
    observed_behavior: str
    message: str | None = None
    code_excerpt: str | None = None
    related_agent_findings: list[RelatedAgentFinding] = []
    evidence_quality_flags: list[
        Literal["missing_code_excerpt", "test_file_path"]
    ] = []

    @model_validator(mode="after")
    def check_line_order(self) -> FailureExample:
        if self.start_line > self.end_line:
            raise ValueError("start_line must be <= end_line")
        return self


class GuardrailState(BaseModel):
    """Controls whether a future step may propose YAML changes."""

    model_config = ConfigDict(extra="forbid")

    yaml_mutation_allowed: bool = False
    aggregate_metrics_only: bool = True
    concrete_examples_required: bool = True
    human_review_required: bool = True
    reason: str


class MissDiagnosticsSummary(BaseModel):
    """Counts that help separate true misses from truth-span granularity."""

    model_config = ConfigDict(extra="forbid")

    total_missed: int = Field(ge=0)
    missed_with_related_findings: int = Field(ge=0)
    missed_with_nearby_same_file_findings: int = Field(ge=0)
    missed_with_same_file_only_findings: int = Field(ge=0)
    missed_with_related_file_findings: int = Field(default=0, ge=0)
    pure_misses: int = Field(ge=0)
    exact_span_false_negatives: int = Field(default=0, ge=0)
    related_file_credit_candidates: int = Field(default=0, ge=0)
    false_negatives_after_related_file_credit: int = Field(default=0, ge=0)
    false_positive_findings: int = Field(ge=0)
    missed_with_missing_code_excerpt: int = Field(default=0, ge=0)
    missed_in_test_file_paths: int = Field(default=0, ge=0)


class FailureAnalysisInput(BaseModel):
    """Complete payload for autoresearch failure analysis."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal[SCHEMA_VERSION] = SCHEMA_VERSION
    run: BenchmarkRunMetadata
    agent: AgentSourceVersion
    case_provenance: list[CaseProvenance]
    missed_findings: list[FailureExample] = []
    false_positive_findings: list[FailureExample] = []
    diagnostics: MissDiagnosticsSummary | None = None
    guardrails: GuardrailState

    @model_validator(mode="after")
    def check_payload_consistency(self) -> FailureAnalysisInput:
        examples = [*self.missed_findings, *self.false_positive_findings]
        provenance_keys = {
            (case.dataset_name, case.case_id)
            for case in self.case_provenance
        }

        for example in self.missed_findings:
            if example.kind != "missed":
                raise ValueError("missed_findings entries must have kind='missed'")
        for example in self.false_positive_findings:
            if example.kind != "false_positive":
                raise ValueError(
                    "false_positive_findings entries must have kind='false_positive'"
                )
        for example in examples:
            if example.agent_name != self.agent.agent_name:
                raise ValueError("example agent_name must match payload agent")
            if (example.dataset_name, example.case_id) not in provenance_keys:
                raise ValueError(
                    "each example must cite a case present in case_provenance"
                )

        if self.guardrails.yaml_mutation_allowed:
            if not examples:
                raise ValueError(
                    "yaml_mutation_allowed requires at least one concrete example"
                )
            if self.guardrails.aggregate_metrics_only:
                raise ValueError(
                    "yaml_mutation_allowed requires aggregate_metrics_only=False"
                )
            if not self.guardrails.human_review_required:
                raise ValueError(
                    "yaml_mutation_allowed requires human_review_required=True"
                )
        return self
