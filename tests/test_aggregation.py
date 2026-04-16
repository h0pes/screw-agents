"""Unit tests for screw_agents.aggregation — learning reports."""

from __future__ import annotations

import pytest

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
    """At least 3 occurrences required for a suggestion; threshold is inclusive."""
    exclusions = [
        _excl(id=f"fp-2026-04-14-{i:03d}", agent="sqli", pattern="same(*)",
              file=f"src/s{i}.py", line=10, reason="safe")
        for i in range(3)
    ]
    suggestions = aggregate_pattern_confidence(exclusions)
    assert len(suggestions) == 1
    assert suggestions[0].confidence in ("low", "medium")  # 3 is at the low end


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
