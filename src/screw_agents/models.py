"""Pydantic models for agent YAML definitions and scan findings.

YAML schema follows PRD §4. The actual agent YAMLs have some field
variations (e.g., sans_top25 vs cwe_top25, flexible bypass_techniques
entries). Models are strict on required fields, flexible on optional
metadata.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict


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
    impact: str = ""
    exploitability: str = ""
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
