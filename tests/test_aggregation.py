"""Unit tests for screw_agents.aggregation — learning reports."""

from __future__ import annotations

from screw_agents.aggregation import aggregate_pattern_confidence
from screw_agents.models import Exclusion, ExclusionFinding, ExclusionScope


def _excl(
    *, id: str, agent: str, pattern: str, file: str, line: int, reason: str
) -> Exclusion:
    return Exclusion(
        id=id,
        created="2026-04-14T10:00:00Z",
        agent=agent,
        finding=ExclusionFinding(file=file, line=line, code_pattern=pattern, cwe="CWE-89"),
        reason=reason,
        scope=ExclusionScope(type="pattern", pattern=pattern),
    )


def test_aggregate_pattern_confidence_groups_by_pattern():
    """12 exclusions matching the same pattern collapse to one PatternSuggestion."""
    exclusions = [
        _excl(id=f"fp-2026-04-14-{i:03d}", agent="sqli", pattern="db.text_search(*)",
              file=f"src/s{i}.py", line=10, reason="safe internal")
        for i in range(12)
    ]
    suggestions = aggregate_pattern_confidence(exclusions)
    assert len(suggestions) == 1
    assert suggestions[0].pattern == "db.text_search(*)"
    assert suggestions[0].agent == "sqli"
    assert suggestions[0].evidence["exclusion_count"] == 12
    assert suggestions[0].confidence == "high"  # 12 >= threshold for high


def test_aggregate_pattern_confidence_ignores_singletons():
    """A pattern seen only once is not a project-wide convention."""
    exclusions = [
        _excl(id="fp-2026-04-14-001", agent="sqli", pattern="one_off(*)",
              file="src/a.py", line=10, reason="special case")
    ]
    suggestions = aggregate_pattern_confidence(exclusions)
    assert len(suggestions) == 0


def test_aggregate_pattern_confidence_threshold_boundary():
    """At count == _PATTERN_MIN_COUNT (3), confidence is 'low' (below medium threshold)."""
    exclusions = [
        _excl(id=f"fp-2026-04-14-{i:03d}", agent="sqli", pattern="same(*)",
              file=f"src/s{i}.py", line=10, reason="safe")
        for i in range(3)
    ]
    suggestions = aggregate_pattern_confidence(exclusions)
    assert len(suggestions) == 1
    assert suggestions[0].confidence == "low"


def test_aggregate_pattern_confidence_skips_quarantined():
    """Quarantined exclusions are not included in the aggregation."""
    exclusions = [
        _excl(id=f"fp-2026-04-14-{i:03d}", agent="sqli", pattern="same(*)",
              file=f"src/s{i}.py", line=10, reason="safe")
        for i in range(5)
    ]
    exclusions[0].quarantined = True
    exclusions[1].quarantined = True
    suggestions = aggregate_pattern_confidence(exclusions)
    assert len(suggestions) == 1
    assert suggestions[0].evidence["exclusion_count"] == 3


def test_aggregate_pattern_confidence_empty_input():
    """Empty input returns empty suggestions — no crashes, no spurious output."""
    assert aggregate_pattern_confidence([]) == []


def test_aggregate_pattern_confidence_same_pattern_across_agents_doesnt_collapse():
    """Buckets include agent; identical pattern under different agents stays separate."""
    exclusions = [
        _excl(id=f"fp-2026-04-14-{i:03d}", agent="sqli", pattern="shared(*)",
              file=f"src/s{i}.py", line=10, reason="r")
        for i in range(5)
    ] + [
        _excl(id=f"fp-2026-04-14-{i + 100:03d}", agent="cmdi", pattern="shared(*)",
              file=f"src/c{i}.py", line=20, reason="r")
        for i in range(5)
    ]
    suggestions = aggregate_pattern_confidence(exclusions)
    agents = sorted(s.agent for s in suggestions)
    assert agents == ["cmdi", "sqli"]


def test_aggregate_pattern_confidence_same_pattern_different_cwes_doesnt_collapse():
    """Buckets include cwe; identical (agent, pattern) under different CWEs stays separate."""
    exclusions = [
        Exclusion(
            id=f"fp-2026-04-14-{i:03d}",
            created="2026-04-14T10:00:00Z",
            agent="sqli",
            finding=ExclusionFinding(
                file=f"src/s{i}.py", line=10, code_pattern="shared(*)", cwe="CWE-89"
            ),
            reason="r",
            scope=ExclusionScope(type="pattern", pattern="shared(*)"),
        )
        for i in range(4)
    ] + [
        Exclusion(
            id=f"fp-2026-04-14-{i + 100:03d}",
            created="2026-04-14T10:00:00Z",
            agent="sqli",
            finding=ExclusionFinding(
                file=f"src/s{i}.py", line=20, code_pattern="shared(*)", cwe="CWE-78"
            ),
            reason="r",
            scope=ExclusionScope(type="pattern", pattern="shared(*)"),
        )
        for i in range(4)
    ]
    suggestions = aggregate_pattern_confidence(exclusions)
    cwes = sorted(s.cwe for s in suggestions)
    assert cwes == ["CWE-78", "CWE-89"]


def test_aggregate_pattern_confidence_high_threshold_boundary():
    """At count == _PATTERN_HIGH_COUNT (10), confidence is 'high'."""
    exclusions = [
        _excl(id=f"fp-2026-04-14-{i:03d}", agent="sqli", pattern="boundary(*)",
              file=f"src/s{i}.py", line=10, reason="safe")
        for i in range(10)
    ]
    suggestions = aggregate_pattern_confidence(exclusions)
    assert len(suggestions) == 1
    assert suggestions[0].confidence == "high"


def test_aggregate_pattern_confidence_skips_empty_pattern():
    """Empty-string code_pattern is guarded — no bogus empty-pattern suggestion."""
    # ExclusionScope(type="pattern", pattern="") would fail Pydantic validation,
    # so construct manually with an exact_line scope instead.
    exclusions = [
        Exclusion(
            id=f"fp-2026-04-14-{i:03d}",
            created="2026-04-14T10:00:00Z",
            agent="sqli",
            finding=ExclusionFinding(
                file=f"src/s{i}.py", line=10, code_pattern="", cwe="CWE-89"
            ),
            reason="r",
            scope=ExclusionScope(type="exact_line", path=f"src/s{i}.py"),
        )
        for i in range(5)
    ]
    assert aggregate_pattern_confidence(exclusions) == []
