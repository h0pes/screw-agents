from __future__ import annotations

import pytest

from screw_agents.challenger import (
    ChallengerAssessment,
    finding_key,
    reconcile_findings,
)


def _finding(
    finding_id: str | None = "sqli-001",
    *,
    file: str = "src/app.py",
    line: int = 42,
    cwe: str = "CWE-89",
    severity: str = "high",
) -> dict:
    finding = {
        "agent": "sqli",
        "location": {"file": file, "line_start": line},
        "classification": {"cwe": cwe, "severity": severity},
    }
    if finding_id is not None:
        finding["id"] = finding_id
    return finding


def _assessment(
    finding_id: str = "sqli-001",
    *,
    provider: str = "codex",
    exploitability: str = "agree",
    severity: str = "agree",
    remediation: str = "agree",
    confidence: str = "high",
) -> ChallengerAssessment:
    return ChallengerAssessment(
        provider=provider,
        transport="cli",
        role="challenger",
        finding_id=finding_id,
        exploitability=exploitability,  # type: ignore[arg-type]
        severity=severity,  # type: ignore[arg-type]
        remediation=remediation,  # type: ignore[arg-type]
        confidence=confidence,  # type: ignore[arg-type]
        reasoning="fixture assessment",
    )


def test_finding_key_prefers_explicit_id() -> None:
    assert finding_key(_finding("xss-123", file="other.py")) == "xss-123"


def test_finding_key_falls_back_to_location_and_cwe() -> None:
    assert finding_key(_finding(None, file="src/api.py", line=9, cwe="CWE-79")) == (
        "src/api.py:9:CWE-79"
    )


def test_finding_key_requires_location_shape_without_id() -> None:
    with pytest.raises(ValueError, match="findings without id"):
        finding_key({"classification": {"cwe": "CWE-89"}})


def test_reconcile_agreed_assessments() -> None:
    reconciled = reconcile_findings(
        [_finding()],
        [_assessment()],
        primary_provider="claude",
    )

    assert len(reconciled) == 1
    result = reconciled[0]
    assert result.status == "agreed"
    assert result.finding_ids == ["sqli-001"]
    assert result.primary_provider == "claude"
    assert result.participant_providers == ["claude", "codex"]
    assert result.agreed_severity == "high"
    assert result.confidence == "high"


def test_reconcile_disputed_when_any_dimension_disagrees() -> None:
    result = reconcile_findings(
        [_finding()],
        [_assessment(severity="disagree", confidence="medium")],
        primary_provider="claude",
    )[0]

    assert result.status == "disputed"
    assert result.agreed_severity is None
    assert result.confidence == "medium"
    assert "disagreed" in result.rationale


def test_reconcile_uncertain_when_no_disagreement() -> None:
    result = reconcile_findings(
        [_finding()],
        [_assessment(exploitability="uncertain", confidence="low")],
        primary_provider="claude",
    )[0]

    assert result.status == "uncertain"
    assert result.confidence == "low"
    assert "uncertain" in result.rationale


def test_reconcile_unsupported_has_priority_over_disagreement() -> None:
    result = reconcile_findings(
        [_finding()],
        [
            _assessment(provider="codex", exploitability="disagree"),
            _assessment(provider="gemini", remediation="unsupported"),
        ],
        primary_provider="claude",
    )[0]

    assert result.status == "unsupported"
    assert result.participant_providers == ["claude", "codex", "gemini"]


def test_reconcile_unique_without_matching_assessment() -> None:
    result = reconcile_findings(
        [_finding("cmdi-001", severity="medium")],
        [_assessment(finding_id="other-finding")],
        primary_provider="codex",
    )[0]

    assert result.status == "unique"
    assert result.finding_ids == ["cmdi-001"]
    assert result.participant_providers == ["codex"]
    assert result.agreed_severity == "medium"
    assert result.confidence is None


def test_reconcile_matches_fallback_key() -> None:
    finding = _finding(None, file="src/web.py", line=7, cwe="CWE-79")
    key = "src/web.py:7:CWE-79"

    result = reconcile_findings(
        [finding],
        [_assessment(finding_id=key)],
        primary_provider="claude",
    )[0]

    assert result.status == "agreed"
    assert result.finding_ids == [key]


def test_reconcile_preserves_first_finding_order() -> None:
    results = reconcile_findings(
        [
            _finding("second"),
            _finding("first"),
        ],
        [
            _assessment(finding_id="first"),
            _assessment(finding_id="second", exploitability="disagree"),
        ],
        primary_provider="claude",
    )

    assert [result.finding_ids[0] for result in results] == ["second", "first"]
    assert [result.status for result in results] == ["disputed", "agreed"]


def test_reconcile_uses_lowest_assessment_confidence() -> None:
    result = reconcile_findings(
        [_finding()],
        [
            _assessment(provider="codex", confidence="high"),
            _assessment(provider="gemini", confidence="low"),
        ],
        primary_provider="claude",
    )[0]

    assert result.status == "agreed"
    assert result.confidence == "low"
