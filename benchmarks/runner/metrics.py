"""Pair-based TPR/FPR/precision/recall/F1/accuracy computation.

Scoring semantics per ADR-013 and PRD §11.3:

For each BenchmarkCase, the agent is run TWICE — once on the vulnerable
version, once on the patched version. A finding is only counted as a TRUE
POSITIVE if the agent flagged the vulnerable location AND did NOT flag the
same location on the patched version.
"""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
from typing import Iterable

from benchmarks.runner.cwe import Cwe1400Hierarchy
from benchmarks.runner.models import (
    AgentRun,
    BenchmarkCase,
    CodeLocation,
    Finding,
    FindingKind,
    Language,
    MetricSet,
    Summary,
)


def locations_match(a: CodeLocation, b: CodeLocation) -> bool:
    """True if both locations reference the same file and overlap on at least one line."""
    if a.file != b.file:
        return False
    return a.start_line <= b.end_line and a.end_line >= b.start_line


def _cwe_match(agent_cwe: str, truth_cwe: str, hierarchy: Cwe1400Hierarchy,
               mode: str) -> bool:
    if mode == "strict":
        return hierarchy.strict_match(agent_cwe, truth_cwe)
    elif mode == "broad":
        return hierarchy.broad_match(agent_cwe, truth_cwe)
    else:
        raise ValueError(f"Unknown match mode: {mode!r}")


def _score_case(
    case: BenchmarkCase,
    vuln_findings: list[Finding],
    patched_findings: list[Finding],
    hierarchy: Cwe1400Hierarchy,
    match_mode: str = "broad",
) -> tuple[int, int, int, int]:
    """Return (tp, fp, tn, fn) for a single case."""
    fail_truths = [f for f in case.ground_truth if f.kind == FindingKind.FAIL]
    pass_truths = [f for f in case.ground_truth if f.kind == FindingKind.PASS]

    tp = fp = tn = fn = 0
    consumed_vuln: set[int] = set()
    consumed_patched: set[int] = set()

    for truth in fail_truths:
        agent_vuln = _find_match(truth, vuln_findings, hierarchy, match_mode, consumed_vuln)
        agent_patched = _find_match(truth, patched_findings, hierarchy, match_mode, consumed_patched)
        if agent_vuln is not None and agent_patched is None:
            tp += 1
        elif agent_vuln is not None and agent_patched is not None:
            fn += 1
            fp += 1
        else:
            fn += 1

    for truth in pass_truths:
        agent_patched = _find_match(truth, patched_findings, hierarchy, match_mode, consumed_patched)
        if agent_patched is not None:
            pass  # already counted in fail_truths loop
        else:
            tn += 1

    for i, f in enumerate(vuln_findings):
        if i in consumed_vuln:
            continue
        fp += 1

    return tp, fp, tn, fn


def _find_match(
    truth: Finding,
    agent_findings: list[Finding],
    hierarchy: Cwe1400Hierarchy,
    match_mode: str,
    consumed: set[int],
) -> Finding | None:
    for i, af in enumerate(agent_findings):
        if i in consumed:
            continue
        if not locations_match(truth.location, af.location):
            continue
        if not _cwe_match(af.cwe_id, truth.cwe_id, hierarchy, match_mode):
            continue
        consumed.add(i)
        return af
    return None


def compute_metrics(
    cases: list[BenchmarkCase],
    runs_vulnerable: list[AgentRun],
    runs_patched: list[AgentRun],
    hierarchy: Cwe1400Hierarchy,
    *,
    agent_name: str,
    dataset: str,
    match_mode: str = "broad",
) -> Summary:
    """Compute a Summary with per-CWE, per-language, and overall MetricSets."""
    vuln_by_case = {r.case_id: r for r in runs_vulnerable}
    patched_by_case = {r.case_id: r for r in runs_patched}

    buckets: dict[tuple[str | None, Language | None], list[int]] = defaultdict(
        lambda: [0, 0, 0, 0]
    )

    for case in cases:
        vuln_run = vuln_by_case.get(case.case_id)
        patched_run = patched_by_case.get(case.case_id)
        vuln_findings = vuln_run.findings if vuln_run else []
        patched_findings = patched_run.findings if patched_run else []
        tp, fp, tn, fn = _score_case(case, vuln_findings, patched_findings, hierarchy, match_mode)

        fail_truths = [f for f in case.ground_truth if f.kind == FindingKind.FAIL]
        case_cwe = fail_truths[0].cwe_id if fail_truths else None

        for key in (
            (None, None),
            (case_cwe, None),
            (None, case.language),
            (case_cwe, case.language),
        ):
            buckets[key][0] += tp
            buckets[key][1] += fp
            buckets[key][2] += tn
            buckets[key][3] += fn

    metrics: list[MetricSet] = []
    for (cwe, lang), (tp, fp, tn, fn) in buckets.items():
        metrics.append(_build_metric_set(
            agent_name=agent_name, dataset=dataset,
            cwe_id=cwe, language=lang,
            tp=tp, fp=fp, tn=tn, fn=fn,
        ))

    return Summary(
        run_id=datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S"),
        agent_name=agent_name,
        dataset=dataset,
        methodology={
            "dedup": False,
            "chrono_split": False,
            "pair_based": True,
            "match_mode": match_mode,
        },
        metrics=metrics,
        generated_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
    )


def _build_metric_set(
    *, agent_name: str, dataset: str,
    cwe_id: str | None, language: Language | None,
    tp: int, fp: int, tn: int, fn: int,
) -> MetricSet:
    tpr = tp / (tp + fn) if (tp + fn) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tpr
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    accuracy = tpr - fpr
    return MetricSet(
        agent_name=agent_name, dataset=dataset,
        cwe_id=cwe_id, language=language,
        true_positives=tp, false_positives=fp,
        true_negatives=tn, false_negatives=fn,
        tpr=tpr, fpr=fpr, precision=precision, f1=f1, accuracy=accuracy,
    )
