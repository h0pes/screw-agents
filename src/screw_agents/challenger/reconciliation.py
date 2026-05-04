"""Deterministic provider-neutral reconciliation for Phase 5.

This module reconciles finding-shaped dictionaries with
``ChallengerAssessment`` records. It does not call providers, inspect prose, or
assume Claude/Codex semantics.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from screw_agents.challenger.models import (
    ChallengerAssessment,
    ChallengerReconciliation,
)

_CONFIDENCE_RANK = {"low": 0, "medium": 1, "high": 2}


def finding_key(finding: dict[str, Any]) -> str:
    """Return a stable reconciliation key for a finding-shaped dict.

    Prefer explicit finding IDs. When a fixture or future provider result lacks
    an ID, fall back to the output-schema location/classification shape:
    ``file:line_start:CWE``.
    """
    finding_id = finding.get("id")
    if isinstance(finding_id, str) and finding_id:
        return finding_id

    location = finding.get("location") or {}
    classification = finding.get("classification") or {}
    file_path = location.get("file")
    line_start = location.get("line_start")
    cwe = classification.get("cwe")
    if file_path is None or line_start is None or cwe is None:
        raise ValueError(
            "findings without id must include location.file, "
            "location.line_start, and classification.cwe"
        )
    return f"{file_path}:{line_start}:{cwe}"


def reconcile_findings(
    findings: list[dict[str, Any]],
    assessments: list[ChallengerAssessment],
    *,
    primary_provider: str | None = None,
) -> list[ChallengerReconciliation]:
    """Reconcile findings and challenger assessments into stable summaries.

    Status rules are deliberately simple and deterministic:

    - ``unique``: no assessment matches the finding.
    - ``unsupported``: any matching assessment reports an unsupported verdict.
    - ``disputed``: any matching assessment disagrees on exploitability,
      severity, or remediation.
    - ``uncertain``: any matching assessment is uncertain and none disagree or
      mark unsupported.
    - ``agreed``: all matching assessments agree.

    Args:
        findings: Finding-shaped dictionaries, usually ``Finding.model_dump``.
        assessments: Provider-neutral assessments keyed by ``finding_id``.
        primary_provider: Optional provider that produced the primary findings.

    Returns:
        One reconciliation per finding cluster, ordered by first finding
        appearance.
    """
    findings_by_key: dict[str, list[dict[str, Any]]] = {}
    key_order: list[str] = []
    for finding in findings:
        key = finding_key(finding)
        if key not in findings_by_key:
            findings_by_key[key] = []
            key_order.append(key)
        findings_by_key[key].append(finding)

    assessments_by_key: dict[str, list[ChallengerAssessment]] = defaultdict(list)
    for assessment in assessments:
        if assessment.finding_id:
            assessments_by_key[assessment.finding_id].append(assessment)

    reconciliations: list[ChallengerReconciliation] = []
    for key in key_order:
        cluster_findings = findings_by_key[key]
        cluster_assessments = assessments_by_key.get(key, [])
        participant_providers = _participant_providers(
            cluster_assessments,
            primary_provider=primary_provider,
        )
        status = _status_for(cluster_assessments)
        reconciliations.append(
            ChallengerReconciliation(
                finding_ids=_finding_ids(cluster_findings, fallback_key=key),
                status=status,
                primary_provider=primary_provider,
                participant_providers=participant_providers,
                agreed_severity=_agreed_severity(
                    cluster_findings,
                    cluster_assessments,
                    status=status,
                ),
                confidence=_aggregate_confidence(cluster_assessments),
                rationale=_rationale_for(status, cluster_assessments),
            )
        )

    return reconciliations


def _status_for(assessments: list[ChallengerAssessment]) -> str:
    if not assessments:
        return "unique"

    verdicts = [
        assessment.exploitability
        for assessment in assessments
    ] + [
        assessment.severity
        for assessment in assessments
    ] + [
        assessment.remediation
        for assessment in assessments
    ]
    if "unsupported" in verdicts:
        return "unsupported"
    if "disagree" in verdicts:
        return "disputed"
    if "uncertain" in verdicts:
        return "uncertain"
    return "agreed"


def _finding_ids(findings: list[dict[str, Any]], *, fallback_key: str) -> list[str]:
    ids: list[str] = []
    for finding in findings:
        finding_id = finding.get("id")
        ids.append(finding_id if isinstance(finding_id, str) and finding_id else fallback_key)
    return ids


def _participant_providers(
    assessments: list[ChallengerAssessment],
    *,
    primary_provider: str | None,
) -> list[str]:
    providers: list[str] = []
    if primary_provider:
        providers.append(primary_provider)
    for assessment in assessments:
        if assessment.provider not in providers:
            providers.append(assessment.provider)
    return providers


def _agreed_severity(
    findings: list[dict[str, Any]],
    assessments: list[ChallengerAssessment],
    *,
    status: str,
) -> str | None:
    if status not in {"agreed", "unique"}:
        return None
    first = findings[0]
    classification = first.get("classification") or {}
    severity = classification.get("severity")
    if status == "agreed" and any(
        assessment.severity != "agree" for assessment in assessments
    ):
        return None
    return severity if isinstance(severity, str) else None


def _aggregate_confidence(
    assessments: list[ChallengerAssessment],
) -> str | None:
    if not assessments:
        return None
    lowest = min(assessments, key=lambda item: _CONFIDENCE_RANK[item.confidence])
    return lowest.confidence


def _rationale_for(
    status: str,
    assessments: list[ChallengerAssessment],
) -> str:
    if status == "unique":
        return "No challenger assessment matched this finding."
    providers = ", ".join(assessment.provider for assessment in assessments)
    if status == "unsupported":
        return f"At least one assessment from {providers} was unsupported."
    if status == "disputed":
        return f"At least one assessment from {providers} disagreed."
    if status == "uncertain":
        return f"At least one assessment from {providers} was uncertain."
    return f"All assessments from {providers} agreed."
