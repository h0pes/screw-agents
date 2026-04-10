"""Typed domain objects for the screw-agents benchmark runner.

Every type the runner passes between modules is defined here. Keep this file
SMALL and authoritative — other modules import from here, they do not define
their own domain types.

See ADR-013 for design rationale.
"""
from __future__ import annotations

from datetime import date
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, model_validator


class Language(str, Enum):
    PYTHON = "python"
    JAVASCRIPT = "javascript"
    TYPESCRIPT = "typescript"
    JAVA = "java"
    GO = "go"
    RUBY = "ruby"
    PHP = "php"
    CSHARP = "csharp"
    RUST = "rust"
    C = "c"
    CPP = "cpp"


class FindingKind(str, Enum):
    """Whether a finding indicates a vulnerable code point (fail) or a safe
    one (pass).

    From bentoo-sarif: kind=fail marks the vulnerable method in the vulnerable
    version of a project. kind=pass marks the same location in the patched
    version — a true-positive agent MUST find kind=fail findings and MUST NOT
    flag kind=pass findings at the same location.
    """
    FAIL = "fail"
    PASS = "pass"


class CodeLocation(BaseModel):
    """A region of source code. Bentoo-sarif is method-granular."""
    file: str
    start_line: int
    end_line: int
    function_name: str | None = None

    @model_validator(mode="after")
    def check_line_order(self) -> "CodeLocation":
        if self.start_line > self.end_line:
            raise ValueError(f"start_line {self.start_line} > end_line {self.end_line}")
        return self


class Finding(BaseModel):
    """A single vulnerability finding — from ground truth OR from an agent."""
    cwe_id: str              # e.g., "CWE-89"
    kind: FindingKind
    location: CodeLocation
    cve_id: str | None = None          # e.g., "CVE-2024-12345"
    agent_name: str | None = None      # None for ground truth
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)    # None for ground truth; 0.0-1.0 otherwise
    message: str | None = None


class BenchmarkCase(BaseModel):
    """One entry in a benchmark — pairs a vulnerable and patched version."""
    case_id: str                       # stable across runs
    project: str                       # e.g., "lodash/lodash"
    language: Language
    vulnerable_version: str
    patched_version: str
    ground_truth: list[Finding]        # kind=fail for vuln, kind=pass for patched
    published_date: date | None = None  # For chronological splits
    source_dataset: str                # e.g., "ossf-cve-benchmark", "reality-check"


class AgentRun(BaseModel):
    """An agent's findings on one benchmark case."""
    case_id: str
    agent_name: str
    findings: list[Finding]
    runtime_seconds: float = Field(ge=0.0)


class MetricSet(BaseModel):
    """Per-(agent, dataset, CWE, language) metrics.

    Multiple MetricSet entries roll up a single Summary — one for the overall
    result, one per CWE, one per language, and optional cross-dimensions.
    """
    agent_name: str
    dataset: str
    cwe_id: str | None = None          # None = aggregate across all CWEs
    language: Language | None = None   # None = aggregate across all languages

    true_positives: int = Field(ge=0)
    false_positives: int = Field(ge=0)
    true_negatives: int = Field(ge=0)
    false_negatives: int = Field(ge=0)

    tpr: float                         # recall on vulnerable versions
    fpr: float                         # false positive rate on patched versions
    precision: float
    f1: float
    accuracy: float                    # TPR - FPR (standard SAST benchmark metric per ADR-013)


class Summary(BaseModel):
    """Top-level benchmark run output. Schema is bentoo-compatible."""
    run_id: str                        # e.g., "20260409-093215"
    agent_name: str
    dataset: str
    methodology: dict[str, Any]        # {"dedup": bool, "chrono_split": bool, "pair_based": bool, ...}
    metrics: list[MetricSet]
    generated_at: str                  # ISO 8601 UTC
