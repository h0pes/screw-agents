"""G5-G7 gate checking for Phase 1.7 validation.

G5: Detection rate thresholds per (agent, dataset) pair.
G6: Rust disclaimer must be present when no Rust cases are in the run.
G7: Failure dump for any gate below threshold.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

from benchmarks.runner.models import Finding, Language, MetricSet, Summary


@dataclass
class GateDefinition:
    gate_id: str
    agent: str
    dataset: str
    metric: str          # "tpr" or "fpr"
    threshold: float
    comparison: str      # "gte" (>=) or "lte" (<=)
    cwe_filter: str | None = None


G5_GATES: list[GateDefinition] = [
    GateDefinition("G5.1", "xss", "ossf-cve-benchmark", "tpr", 0.70, "gte"),
    GateDefinition("G5.2", "xss", "ossf-cve-benchmark", "fpr", 0.25, "lte"),
    GateDefinition("G5.3", "xss", "reality-check-csharp", "tpr", 0.60, "gte", "CWE-79"),
    GateDefinition("G5.4", "xss", "reality-check-python", "tpr", 0.60, "gte", "CWE-79"),
    GateDefinition("G5.5", "cmdi", "ossf-cve-benchmark", "tpr", 0.60, "gte"),
    GateDefinition("G5.6", "cmdi", "reality-check-java", "tpr", 0.50, "gte", "CWE-78"),
    GateDefinition("G5.7", "sqli", "reality-check-csharp", "tpr", 0.50, "gte", "CWE-89"),
    GateDefinition("G5.8", "sqli", "morefixes", "tpr", 0.50, "gte", "CWE-89"),
    GateDefinition("G5.9", "ssti", "go-sec-code-mutated", "tpr", 0.70, "gte", "CWE-1336"),
    GateDefinition("G5.10", "ssti", "skf-labs-mutated", "tpr", 0.70, "gte", "CWE-1336"),
]


@dataclass
class GateResult:
    gate_id: str
    passed: bool
    actual_value: float | None = None
    threshold: float = 0.0
    comparison: str = "gte"
    agent: str = ""
    dataset: str = ""
    note: str = ""


def check_g5_gates(summaries: list[Summary]) -> list[GateResult]:
    results: list[GateResult] = []
    for gate in G5_GATES:
        metric_set = _find_metric(summaries, gate)
        if metric_set is None:
            results.append(GateResult(
                gate_id=gate.gate_id, passed=False,
                threshold=gate.threshold, comparison=gate.comparison,
                agent=gate.agent, dataset=gate.dataset,
                note="Not run — no matching summary found",
            ))
            continue

        actual = getattr(metric_set, gate.metric)
        if gate.comparison == "gte":
            passed = actual >= gate.threshold
        else:
            passed = actual <= gate.threshold

        results.append(GateResult(
            gate_id=gate.gate_id, passed=passed,
            actual_value=actual, threshold=gate.threshold,
            comparison=gate.comparison,
            agent=gate.agent, dataset=gate.dataset,
        ))
    return results


def _find_metric(summaries: list[Summary], gate: GateDefinition) -> MetricSet | None:
    for s in summaries:
        if s.agent_name != gate.agent or s.dataset != gate.dataset:
            continue
        for m in s.metrics:
            if gate.cwe_filter:
                if m.cwe_id == gate.cwe_filter and m.language is None:
                    return m
            else:
                if m.cwe_id is None and m.language is None:
                    return m
    return None


def check_g6_rust_disclaimer(languages_in_run: Sequence[Language]) -> bool:
    return Language.RUST not in languages_in_run


def build_g7_failure_dump(
    missed_findings: list[Finding],
    false_flags: list[Finding],
    max_items: int = 10,
) -> dict:
    def _serialize(f: Finding) -> dict:
        return {
            "cwe_id": f.cwe_id,
            "cve_id": f.cve_id,
            "file": f.location.file,
            "start_line": f.location.start_line,
            "end_line": f.location.end_line,
            "message": f.message,
        }

    return {
        "missed": [_serialize(f) for f in missed_findings[:max_items]],
        "false_flags": [_serialize(f) for f in false_flags[:max_items]],
    }
