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


# --- Task 18: aggregate_directory_suggestions (Feature 2) ------------------


def test_aggregate_directory_suggestions_groups_by_common_prefix():
    """Exclusions concentrated in a single directory produce a suggestion."""
    from screw_agents.aggregation import aggregate_directory_suggestions

    exclusions = [
        _excl(id=f"fp-2026-04-14-{i:03d}", agent="sqli", pattern=f"p{i}",
              file=f"test/subdir/test_{i}.py", line=10, reason="test fixture")
        for i in range(8)
    ]
    suggestions = aggregate_directory_suggestions(exclusions)
    assert len(suggestions) >= 1
    dirs = {s.directory for s in suggestions}
    assert "test/" in dirs or "test/subdir/" in dirs


def test_aggregate_directory_suggestions_requires_min_count():
    from screw_agents.aggregation import aggregate_directory_suggestions

    exclusions = [
        _excl(id="fp-2026-04-14-001", agent="sqli", pattern="p", file="test/a.py", line=10, reason="r")
    ]
    suggestions = aggregate_directory_suggestions(exclusions)
    assert len(suggestions) == 0


def test_aggregate_directory_suggestions_empty_input():
    """Empty input returns empty suggestions."""
    from screw_agents.aggregation import aggregate_directory_suggestions
    assert aggregate_directory_suggestions([]) == []


def test_aggregate_directory_suggestions_skips_empty_file_path():
    """Empty file paths don't synthesize bogus directory suggestions."""
    from screw_agents.aggregation import aggregate_directory_suggestions
    exclusions = [
        Exclusion(
            id=f"fp-2026-04-14-{i:03d}",
            created="2026-04-14T10:00:00Z",
            agent="sqli",
            finding=ExclusionFinding(
                file="", line=10, code_pattern=f"p{i}", cwe="CWE-89"
            ),
            reason="r",
            scope=ExclusionScope(type="pattern", pattern=f"p{i}"),
        )
        for i in range(5)
    ]
    assert aggregate_directory_suggestions(exclusions) == []


def test_aggregate_directory_suggestions_threshold_low_at_min_count():
    """Exactly _DIR_MIN_COUNT exclusions yields 'low' confidence."""
    from screw_agents.aggregation import aggregate_directory_suggestions
    exclusions = [
        _excl(id=f"fp-2026-04-14-{i:03d}", agent="sqli", pattern=f"p{i}",
              file=f"test/sub/f{i}.py", line=10, reason="t")
        for i in range(3)
    ]
    suggestions = aggregate_directory_suggestions(exclusions)
    assert len(suggestions) == 1
    assert suggestions[0].confidence == "low"


def test_aggregate_directory_suggestions_high_threshold_boundary():
    """Exactly _DIR_HIGH_COUNT (10) exclusions yields 'high' confidence."""
    from screw_agents.aggregation import aggregate_directory_suggestions
    exclusions = [
        _excl(id=f"fp-2026-04-14-{i:03d}", agent="sqli", pattern=f"p{i}",
              file=f"test/f{i}.py", line=10, reason="t")
        for i in range(10)
    ]
    suggestions = aggregate_directory_suggestions(exclusions)
    assert len(suggestions) == 1
    assert suggestions[0].confidence == "high"


def test_aggregate_directory_suggestions_skips_quarantined():
    """Quarantined exclusions don't count toward the directory bucket."""
    from screw_agents.aggregation import aggregate_directory_suggestions
    exclusions = [
        _excl(id=f"fp-2026-04-14-{i:03d}", agent="sqli", pattern=f"p{i}",
              file=f"test/f{i}.py", line=10, reason="t")
        for i in range(5)
    ]
    exclusions[0].quarantined = True
    exclusions[1].quarantined = True
    # Only 3 remaining; still hits min threshold; produces "low" confidence
    suggestions = aggregate_directory_suggestions(exclusions)
    assert len(suggestions) == 1
    assert suggestions[0].confidence == "low"
    # Intent check: evidence reflects the filtered count, not the raw 5.
    assert suggestions[0].evidence["total_findings_in_directory"] == 3
    assert len(suggestions[0].evidence["files_affected"]) == 3


def test_aggregate_directory_suggestions_same_dir_across_agents_doesnt_collapse():
    """Identical directory under different agents stays separate."""
    from screw_agents.aggregation import aggregate_directory_suggestions
    exclusions = [
        _excl(id=f"fp-2026-04-14-{i:03d}", agent="sqli", pattern=f"p{i}",
              file=f"test/f{i}.py", line=10, reason="t")
        for i in range(5)
    ] + [
        _excl(id=f"fp-2026-04-14-{i + 100:03d}", agent="cmdi", pattern=f"p{i}",
              file=f"test/c{i}.py", line=10, reason="t")
        for i in range(5)
    ]
    suggestions = aggregate_directory_suggestions(exclusions)
    by_agent = {s.agent: s for s in suggestions}
    assert set(by_agent.keys()) == {"sqli", "cmdi"}
    # Each bucket has its own 5 findings — no cross-agent contamination
    assert by_agent["sqli"].evidence["total_findings_in_directory"] == 5
    assert by_agent["cmdi"].evidence["total_findings_in_directory"] == 5
    # Files are disjoint — the sqli bucket has no cmdi files and vice versa
    sqli_files = set(by_agent["sqli"].evidence["files_affected"])
    cmdi_files = set(by_agent["cmdi"].evidence["files_affected"])
    assert sqli_files.isdisjoint(cmdi_files)


def test_aggregate_directory_suggestions_skips_root_level_files():
    """Files with no directory component (e.g., README.md) don't produce suggestions."""
    from screw_agents.aggregation import aggregate_directory_suggestions
    exclusions = [
        _excl(id=f"fp-2026-04-14-{i:03d}", agent="sqli", pattern=f"p{i}",
              file=f"root_file_{i}.py", line=10, reason="t")
        for i in range(5)
    ]
    assert aggregate_directory_suggestions(exclusions) == []


def test_aggregate_directory_suggestions_tie_break_is_deterministic():
    """When two reasons tie in count, the top-reason in the suggestion string is deterministic."""
    from screw_agents.aggregation import aggregate_directory_suggestions
    # 4 exclusions: 2 with reason "alpha", 2 with reason "beta"
    exclusions = [
        _excl(id=f"fp-2026-04-14-{i:03d}", agent="sqli", pattern=f"p{i}",
              file=f"test/f{i}.py", line=10, reason="alpha")
        for i in range(2)
    ] + [
        _excl(id=f"fp-2026-04-14-{i + 100:03d}", agent="sqli", pattern=f"p{i}",
              file=f"test/g{i}.py", line=10, reason="beta")
        for i in range(2)
    ]
    # Add a third one with a different reason to avoid triggering
    # threshold-related logic — we need at least MIN=3 total entries
    exclusions.append(
        _excl(id="fp-2026-04-14-999", agent="sqli", pattern="p",
              file="test/h.py", line=10, reason="alpha")
    )
    # Now: alpha=3, beta=2 → top reason = alpha (unambiguous)
    suggestions = aggregate_directory_suggestions(exclusions)
    assert len(suggestions) == 1
    assert "'alpha'" in suggestions[0].suggestion

    # Now test tie-break: 2 alpha, 2 beta (equal count)
    exclusions_tied = [
        _excl(id=f"fp-2026-04-14-{i:03d}", agent="sqli", pattern=f"p{i}",
              file=f"test/f{i}.py", line=10, reason="alpha")
        for i in range(2)
    ] + [
        _excl(id=f"fp-2026-04-14-{i + 100:03d}", agent="sqli", pattern=f"p{i}",
              file=f"test/g{i}.py", line=10, reason="beta")
        for i in range(2)
    ]
    # Still need at least 3 total for the directory bucket to produce a suggestion
    exclusions_tied.append(
        _excl(id="fp-2026-04-14-555", agent="sqli", pattern="p",
              file="test/h.py", line=10, reason="gamma")
    )
    # Now: alpha=2, beta=2, gamma=1 → tie between alpha and beta
    # Tie-break rule: (count, reason_text) with max means larger string wins
    suggestions = aggregate_directory_suggestions(exclusions_tied)
    assert len(suggestions) == 1
    # With max((count, reason)) tie-break, "beta" > "alpha" lexicographically
    # so beta wins the tie
    assert "'beta'" in suggestions[0].suggestion
