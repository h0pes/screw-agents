"""Pydantic models for agent YAML definitions and scan findings.

YAML schema follows PRD §4. The actual agent YAMLs have some field
variations (e.g., sans_top25 vs cwe_top25, flexible bypass_techniques
entries). Models are strict on required fields, flexible on optional
metadata.
"""

from __future__ import annotations

from typing import Any, ClassVar, Literal

from pydantic import BaseModel, ConfigDict, Field
from pydantic.main import IncEx


# ---------------------------------------------------------------------------
# YAML Agent Definition Schema (PRD §4)
# ---------------------------------------------------------------------------


class CWEs(BaseModel):
    primary: str
    related: list[str] = []


class OWASPMapping(BaseModel):
    model_config = ConfigDict(extra="allow")

    top10: str
    asvs: list[str] = []
    # Some agents (e.g., xss) reference multiple testing guide sections as a list.
    testing_guide: str | list[str] = ""


class Source(BaseModel):
    model_config = ConfigDict(extra="allow")

    url: str
    last_checked: str
    note: str = ""


class AgentMeta(BaseModel):
    """Agent metadata block — required fields plus flexible extras."""

    model_config = ConfigDict(extra="allow")

    name: str
    display_name: str
    domain: str
    version: str
    last_updated: str
    cwes: CWEs
    capec: list[str] = []
    owasp: OWASPMapping
    sources: list[Source] = []
    short_description: str | None = None
    # Optional — some agents use sans_top25, others cwe_top25
    sans_top25: dict[str, Any] | None = None
    cwe_top25: dict[str, Any] | None = None


class HeuristicEntry(BaseModel):
    """A structured heuristic entry with id, pattern, and language metadata."""

    model_config = ConfigDict(extra="allow")

    id: str
    pattern: str
    languages: list[str] = []


# Detection heuristic entries can be plain strings (minimal form) or structured
# objects with id/pattern/languages fields (the form used by the real agent YAMLs).
HeuristicItem = str | HeuristicEntry


class DetectionHeuristics(BaseModel):
    model_config = ConfigDict(extra="allow")

    high_confidence: list[HeuristicItem] = []
    medium_confidence: list[HeuristicItem] = []
    context_required: list[HeuristicItem] = []


class BypassTechnique(BaseModel):
    """A single bypass technique. Has required name/description + flexible extras."""

    model_config = ConfigDict(extra="allow")

    name: str
    description: str
    detection_hint: str = ""


class CommonMistake(BaseModel):
    mistake: str
    why_insufficient: str = ""


class Remediation(BaseModel):
    model_config = ConfigDict(extra="allow")

    preferred: str
    common_mistakes: list[CommonMistake] = []


class CodeExample(BaseModel):
    model_config = ConfigDict(extra="allow")

    language: str
    code: str
    explanation: str = ""
    label: str = ""


class FewShotExamples(BaseModel):
    vulnerable: list[CodeExample] = []
    safe: list[CodeExample] = []


class TargetStrategy(BaseModel):
    model_config = ConfigDict(extra="allow")

    scope: str = "function"
    include_imports: bool = True
    include_type_defs: bool = True
    file_patterns: list[str] = []
    relevance_signals: list[str] = []
    adaptive_depth: dict[str, str] | None = None


class AgentDefinition(BaseModel):
    """Complete agent YAML definition — validated at registry load time."""

    meta: AgentMeta
    core_prompt: str
    detection_heuristics: DetectionHeuristics
    bypass_techniques: list[BypassTechnique] = []
    remediation: Remediation
    few_shot_examples: FewShotExamples = FewShotExamples()
    target_strategy: TargetStrategy = TargetStrategy()


# ---------------------------------------------------------------------------
# Finding Output Schema (PRD §8 + data_flow extension)
# ---------------------------------------------------------------------------


class DataFlow(BaseModel):
    """Source-to-sink data flow tracing for injection findings."""

    source: str
    source_location: str = ""
    sink: str
    sink_location: str = ""


class FindingLocation(BaseModel):
    file: str
    line_start: int
    line_end: int | None = None
    function: str | None = None
    class_name: str | None = None
    code_snippet: str | None = None
    data_flow: DataFlow | None = None


class FindingClassification(BaseModel):
    cwe: str
    cwe_name: str
    capec: str | None = None
    owasp_top10: str | None = None
    severity: str  # critical, high, medium, low
    confidence: str  # high, medium, low


class FindingAnalysis(BaseModel):
    description: str
    impact: str | None = None
    exploitability: str | None = None
    false_positive_reasoning: str | None = None


class FindingRemediation(BaseModel):
    recommendation: str
    fix_code: str | None = None
    references: list[str] = []


class FindingTriage(BaseModel):
    status: str = "pending"
    triaged_by: str | None = None
    triaged_at: str | None = None
    notes: str | None = None
    excluded: bool = False
    exclusion_ref: str | None = None


# ---------------------------------------------------------------------------
# Exclusion Models (Phase 2 — persistent FP learning, spec §8)
# ---------------------------------------------------------------------------


class ExclusionScope(BaseModel):
    """Scope rule for an exclusion — determines how broadly it applies."""

    type: str  # "exact_line" | "pattern" | "function" | "file" | "directory"
    pattern: str | None = None  # for "pattern" scope
    path: str | None = None  # for "exact_line", "file", "directory", "function"
    name: str | None = None  # for "function" scope


class ExclusionFinding(BaseModel):
    """The original finding that was marked as a false positive."""

    file: str
    line: int
    code_pattern: str
    cwe: str


class ExclusionInput(BaseModel):
    """Input for recording a new exclusion (subagent sends this).

    Note on extras handling: this parent class is the write-side input shape
    with default Pydantic extras handling (silently ignored), while the
    `Exclusion` child has `extra="forbid"` for signing-integrity surface.
    The asymmetry is intentional — write-side callers may pass extra fields
    that should be ignored, but stored exclusions must reject extras so the
    canonical signing payload is not influenced by unknown keys.
    """

    agent: str
    finding: ExclusionFinding
    reason: str
    scope: ExclusionScope


class Exclusion(ExclusionInput):
    """A stored exclusion with generated metadata."""

    id: str
    created: str  # ISO8601
    times_suppressed: int = 0
    last_suppressed: str | None = None

    # new in Phase 3a — signing
    signed_by: str | None = None
    signature: str | None = None
    signature_version: int = 1

    # runtime flags (not persisted to YAML — dual-layer defense below)
    quarantined: bool = Field(default=False, exclude=True)
    trust_state: Literal["trusted", "warned", "quarantined", "allowed"] = Field(
        default="trusted", exclude=True
    )

    model_config = ConfigDict(extra="forbid")

    _RUNTIME_ONLY_FIELDS: ClassVar[set[str]] = {"quarantined", "trust_state"}

    def model_dump(
        self,
        *,
        mode: Literal["json", "python"] = "python",
        include: IncEx | None = None,
        exclude: IncEx | None = None,
        context: Any | None = None,
        by_alias: bool = False,
        exclude_unset: bool = False,
        exclude_defaults: bool = False,
        exclude_none: bool = False,
        round_trip: bool = False,
        warnings: bool | Literal["none", "warn", "error"] = True,
        serialize_as_any: bool = False,
    ) -> dict[str, Any]:
        """Strip runtime-only flags from Python-side serialization.

        Defense-in-depth: `quarantined` and `trust_state` are declared with
        `Field(exclude=True)` which handles the default case at the schema
        level for both `model_dump` and `model_dump_json`. This override is a
        second layer that catches edge cases the schema-level exclude does not
        cover:

        - Callers that pass `include={"quarantined"}` or `include={"trust_state"}`
          (Pydantic's include/exclude precedence can let include win over
          field-level exclude in some shapes)
        - Callers that pass `exclude=` as a list or tuple (unknown shape falls
          back to a safe set form)

        These fields are set at load time based on signature verification;
        persisting them would allow a tampered YAML file to self-mark as
        not-quarantined.
        """
        runtime = self._RUNTIME_ONLY_FIELDS
        if exclude is None:
            merged_exclude: IncEx = set(runtime)
        elif isinstance(exclude, set):
            merged_exclude = exclude | runtime
        elif isinstance(exclude, dict):
            merged_exclude = {**exclude, **{k: True for k in runtime}}
        else:
            # Unknown shape — fall back to a safe set form.
            merged_exclude = set(runtime)
        return super().model_dump(
            mode=mode,
            include=include,
            exclude=merged_exclude,
            context=context,
            by_alias=by_alias,
            exclude_unset=exclude_unset,
            exclude_defaults=exclude_defaults,
            exclude_none=exclude_none,
            round_trip=round_trip,
            warnings=warnings,
            serialize_as_any=serialize_as_any,
        )


# ---------------------------------------------------------------------------
# Project Configuration Models (Phase 3a — trust infrastructure)
# ---------------------------------------------------------------------------


class ReviewerKey(BaseModel):
    """A single trusted reviewer's identity and public key."""

    name: str
    email: str
    key: str  # SSH public key in OpenSSH format (e.g., "ssh-ed25519 AAAA... user@host")


class ScrewConfig(BaseModel):
    """Project-level screw-agents configuration stored in .screw/config.yaml."""

    version: int = 1
    exclusion_reviewers: list[ReviewerKey] = []
    script_reviewers: list[ReviewerKey] = []
    adaptive: bool = False
    legacy_unsigned_exclusions: Literal["reject", "warn", "allow"] = "reject"
    trusted_reviewers_file: str | None = None


class Finding(BaseModel):
    """A single scan finding — the core output unit."""

    id: str
    agent: str
    domain: str
    timestamp: str
    location: FindingLocation
    classification: FindingClassification
    analysis: FindingAnalysis
    remediation: FindingRemediation
    triage: FindingTriage = FindingTriage()


# ---------------------------------------------------------------------------
# Aggregation Models (Phase 3a PR#2 — learning reports)
# ---------------------------------------------------------------------------


class PatternSuggestion(BaseModel):
    """Feature 1 output: project-wide safe pattern candidates."""

    # Code-pattern string (e.g., "db.text_search(*)") being proposed
    # as a project-wide safe pattern based on repeated FP markings.
    pattern: str
    agent: str
    cwe: str
    evidence: dict[str, Any]
    suggestion: str
    confidence: Literal["low", "medium", "high"]


class DirectorySuggestion(BaseModel):
    """Feature 2 output: directory-scope exclusion candidates."""

    directory: str
    agent: str
    evidence: dict[str, Any]
    suggestion: str
    confidence: Literal["low", "medium", "high"]


class FPPattern(BaseModel):
    """A single false-positive pattern in the FP report."""

    agent: str
    cwe: str
    # Code-pattern string shared by multiple false-positive exclusions
    # within the same (agent, cwe) bucket. This is the signal Phase 4
    # autoresearch consumes to refine agent YAML heuristics.
    pattern: str
    fp_count: int = Field(ge=0)
    example_reasons: list[str]
    # Pre-rendered parallel field — each reason backtick-wrapped by aggregation
    # so the subagent does not have discretion on Markdown-injection defense.
    # See T21-m1 in docs/DEFERRED_BACKLOG.md for rationale. Default `[]` keeps
    # existing inline FPPattern constructions backward-compatible.
    example_reasons_rendered: list[str] = []
    candidate_heuristic_refinement: str


class FPReport(BaseModel):
    """Feature 4 output: false-positive signal for Phase 4 autoresearch."""

    generated_at: str
    scope: Literal["project", "global"]
    top_fp_patterns: list[FPPattern]


class AggregateReport(BaseModel):
    """Unified output of the three aggregation features."""

    pattern_confidence: list[PatternSuggestion]
    directory_suggestions: list[DirectorySuggestion]
    fp_report: FPReport


# ---------------------------------------------------------------------------
# Adaptive Analysis Models (Phase 3b — adaptive scripts)
# ---------------------------------------------------------------------------


class CoverageGap(BaseModel):
    """A detected gap in YAML agent coverage — the signal that adaptive mode could help."""

    type: Literal["context_required", "unresolved_sink"]
    agent: str
    file: str
    line: int
    evidence: dict[str, Any] = {}


class AdaptiveScriptMeta(BaseModel):
    """Metadata for an adaptive analysis script in .screw/custom-scripts/."""

    model_config = ConfigDict(extra="forbid")

    name: str
    created: str
    created_by: str  # signer email
    domain: str  # CWE-1400 domain (e.g., "injection-input-handling")
    description: str = ""
    target_patterns: list[str] = []
    validated: bool = False
    last_used: str | None = None
    findings_produced: int = 0
    false_positive_rate: float | None = None

    # signing (Phase 3a compatibility)
    sha256: str
    signed_by: str | None = None
    signature: str | None = None
    signature_version: int = 1


class SandboxResult(BaseModel):
    """Result of launching a script inside the OS sandbox."""

    stdout: bytes
    stderr: bytes
    returncode: int
    wall_clock_s: float
    killed_by_timeout: bool
    findings_json: str | None = None  # None if the script failed before emitting


class AdaptiveScriptResult(BaseModel):
    """Full result of an adaptive script execution, including findings."""

    script_name: str
    findings: list["Finding"]
    sandbox_result: SandboxResult
    stale: bool = False
    execution_time_ms: int


class SemanticReviewReport(BaseModel):
    """Output of the screw-script-reviewer subagent (Layer 0d)."""

    risk_score: Literal["low", "medium", "high"]
    flagged_patterns: list[str]
    unusual_imports: list[str]
    control_flow_summary: str
    estimated_runtime_ms: int
