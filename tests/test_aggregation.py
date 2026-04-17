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
    # Post-T21-m1 fix-up: suggestion wraps top_reason in backticks (same
    # rendering as evidence.reason_distribution_rendered, single source of truth).
    assert "`alpha`" in suggestions[0].suggestion

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
    # Post-T21-m1 fix-up: tie-break aligned with reason_distribution_rendered's
    # (count DESC, reason ASC) order — lexicographically SMALLEST reason wins.
    suggestions = aggregate_directory_suggestions(exclusions_tied)
    assert len(suggestions) == 1
    # alpha < beta lexicographically, so alpha wins the tie.
    assert "`alpha`" in suggestions[0].suggestion
    assert "`beta`" not in suggestions[0].suggestion


# ---------------------------------------------------------------------------
# Task 19 — aggregate_fp_report (Feature 4, Phase 4 autoresearch signal)
# ---------------------------------------------------------------------------


def test_aggregate_fp_report_surfaces_top_patterns():
    """The FP report sorts patterns by count and includes example reasons."""
    from screw_agents.aggregation import aggregate_fp_report

    exclusions = [
        _excl(id=f"fp-2026-04-14-{i:03d}", agent="sqli", pattern="execute(f\"",
              file=f"src/s{i}.py", line=10, reason="static query")
        for i in range(15)
    ] + [
        _excl(id=f"fp-2026-04-14-{i+100:03d}", agent="sqli", pattern="raw_sql(*)",
              file=f"src/s{i}.py", line=20, reason="test fixture")
        for i in range(5)
    ]

    report = aggregate_fp_report(exclusions)
    assert report.scope == "project"
    assert len(report.top_fp_patterns) >= 1
    # Top pattern should be execute(f" with count 15
    assert report.top_fp_patterns[0].fp_count == 15
    assert report.top_fp_patterns[0].pattern == "execute(f\""
    assert "static query" in report.top_fp_patterns[0].example_reasons


def test_aggregate_fp_report_empty_when_no_exclusions():
    from screw_agents.aggregation import aggregate_fp_report

    report = aggregate_fp_report([])
    assert report.top_fp_patterns == []


def test_aggregate_fp_report_generated_at_is_iso8601_utc():
    """The timestamp is strict ISO-8601 with trailing Z (UTC, no offset drift)."""
    from screw_agents.aggregation import aggregate_fp_report
    import re
    report = aggregate_fp_report([])
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", report.generated_at)


def test_aggregate_fp_report_skips_quarantined_and_empty_pattern():
    """Quarantined exclusions and empty code_patterns never reach the report."""
    from screw_agents.aggregation import aggregate_fp_report
    exclusions = [
        _excl(id=f"fp-2026-04-14-{i:03d}", agent="sqli", pattern="real_pattern",
              file=f"src/s{i}.py", line=10, reason=f"r{i}")
        for i in range(5)
    ]
    # Quarantine one of the "real_pattern" entries
    exclusions[0].quarantined = True
    # Add 3 empty-pattern entries — these should not form a bucket
    exclusions += [
        Exclusion(
            id=f"fp-2026-04-14-{i+900:03d}",
            created="2026-04-14T10:00:00Z",
            agent="sqli",
            finding=ExclusionFinding(
                file=f"src/s{i}.py", line=99, code_pattern="", cwe="CWE-89"
            ),
            reason="empty-pattern",
            scope=ExclusionScope(type="exact_line", path=f"src/s{i}.py"),
        )
        for i in range(3)
    ]
    report = aggregate_fp_report(exclusions)
    assert len(report.top_fp_patterns) == 1
    assert report.top_fp_patterns[0].pattern == "real_pattern"
    assert report.top_fp_patterns[0].fp_count == 4  # 5 - 1 quarantined


def test_aggregate_fp_report_top_n_cap():
    """The report caps at _FP_REPORT_TOP_N patterns even with more qualifying buckets."""
    from screw_agents.aggregation import aggregate_fp_report
    # Create 15 distinct patterns, each with 3 exclusions (at min threshold)
    exclusions = []
    for p in range(15):
        for i in range(3):
            exclusions.append(
                _excl(id=f"fp-2026-04-14-{p:03d}-{i}", agent="sqli",
                      pattern=f"pattern_{p}", file=f"src/s{p}_{i}.py",
                      line=10, reason="r")
            )
    report = aggregate_fp_report(exclusions)
    assert len(report.top_fp_patterns) == 10  # _FP_REPORT_TOP_N


def test_aggregate_fp_report_deterministic_ordering_across_ties():
    """Output is stable across insertion order — shuffled input yields the same report."""
    from screw_agents.aggregation import aggregate_fp_report
    import random
    exclusions = [
        _excl(id=f"fp-2026-04-14-{i:03d}", agent="sqli", pattern="bbb",
              file=f"src/s{i}.py", line=10, reason="r")
        for i in range(3)
    ] + [
        _excl(id=f"fp-2026-04-14-{i+100:03d}", agent="sqli", pattern="aaa",
              file=f"src/s{i}.py", line=10, reason="r")
        for i in range(3)
    ] + [
        _excl(id=f"fp-2026-04-14-{i+200:03d}", agent="cmdi", pattern="mmm",
              file=f"src/c{i}.py", line=10, reason="r")
        for i in range(3)
    ]
    baseline = aggregate_fp_report(list(exclusions))
    baseline_shape = [
        (p.agent, p.cwe, p.pattern, p.fp_count) for p in baseline.top_fp_patterns
    ]

    rng = random.Random(42)
    for _ in range(10):
        shuffled = list(exclusions)
        rng.shuffle(shuffled)
        report = aggregate_fp_report(shuffled)
        shape = [
            (p.agent, p.cwe, p.pattern, p.fp_count) for p in report.top_fp_patterns
        ]
        assert shape == baseline_shape

    # Also verify the specific tie-break outcome: sqli/CWE-89/aaa vs sqli/CWE-89/bbb
    # tie on count=3 — lexicographic pattern ascending puts aaa first.
    # cmdi/CWE-89/mmm also ties on count=3 — cross-agent tie-break: agent asc,
    # so cmdi before sqli.
    patterns_ordered = [(p.agent, p.pattern) for p in baseline.top_fp_patterns]
    assert patterns_ordered == [("cmdi", "mmm"), ("sqli", "aaa"), ("sqli", "bbb")]


def test_aggregate_fp_report_reason_cap_at_five():
    """example_reasons is capped at 5 unique reasons, ranked by frequency."""
    from screw_agents.aggregation import aggregate_fp_report
    # Construct exclusions where reason frequencies are clearly ordered:
    # "most_common" x 10, "second" x 5, "third" x 3, "fourth" x 2, "fifth" x 1, "sixth" x 1
    # Total = 22 exclusions; one bucket of 22.
    exclusions = []
    reason_counts = [
        ("most_common", 10),
        ("second", 5),
        ("third", 3),
        ("fourth", 2),
        ("fifth", 1),
        ("sixth", 1),
    ]
    idx = 0
    for reason, count in reason_counts:
        for _ in range(count):
            exclusions.append(
                _excl(id=f"fp-2026-04-14-{idx:03d}", agent="sqli", pattern="p",
                      file=f"src/s{idx}.py", line=10, reason=reason)
            )
            idx += 1
    report = aggregate_fp_report(exclusions)
    assert len(report.top_fp_patterns) == 1
    reasons = report.top_fp_patterns[0].example_reasons
    # Top-5 by frequency, tie-break lexicographic ascending on reason string
    # frequency ranking: most_common (10), second (5), third (3), fourth (2), then fifth (1) vs sixth (1)
    # fifth < sixth lexicographically, so fifth wins the tie
    assert reasons == ["most_common", "second", "third", "fourth", "fifth"]


def test_aggregate_fp_report_same_pattern_cross_agent_stays_separate():
    """Identical pattern under different agents produces two FPPattern entries."""
    from screw_agents.aggregation import aggregate_fp_report
    exclusions = [
        _excl(id=f"fp-2026-04-14-{i:03d}", agent="sqli", pattern="shared",
              file=f"src/s{i}.py", line=10, reason="r")
        for i in range(3)
    ] + [
        _excl(id=f"fp-2026-04-14-{i+100:03d}", agent="cmdi", pattern="shared",
              file=f"src/c{i}.py", line=10, reason="r")
        for i in range(3)
    ]
    report = aggregate_fp_report(exclusions)
    agents = sorted(p.agent for p in report.top_fp_patterns)
    assert agents == ["cmdi", "sqli"]


# ---------------------------------------------------------------------------
# T21-m1 — Server-side reason backtick-wrapping (rendered parallel fields)
# ---------------------------------------------------------------------------


def test_directory_suggestions_emit_rendered_reasons():
    """evidence.reason_distribution_rendered is a pre-formatted Markdown string
    with each reason wrapped in backticks."""
    from screw_agents.aggregation import aggregate_directory_suggestions

    # Seed exclusions reproducing a realistic test-fixture concentration:
    # three "test fixture" + two "one-shot migration" in the same directory.
    reasons = [
        "test fixture",
        "test fixture",
        "test fixture",
        "one-shot migration",
        "one-shot migration",
    ]
    exclusions = [
        _excl(
            id=f"fp-2026-04-14-{i:03d}",
            agent="sqli",
            pattern=f"p{i}",
            file=f"test/f{i}.py",
            line=10,
            reason=reason,
        )
        for i, reason in enumerate(reasons)
    ]
    suggestions = aggregate_directory_suggestions(exclusions)
    assert len(suggestions) == 1
    evidence = suggestions[0].evidence
    # Keep the machine-readable dict for programmatic consumers
    assert evidence["reason_distribution"] == {"test fixture": 3, "one-shot migration": 2}
    # NEW: pre-rendered string with backticks around each reason
    rendered = evidence["reason_distribution_rendered"]
    assert "`test fixture`" in rendered
    assert "`one-shot migration`" in rendered
    assert rendered.count("`") % 2 == 0  # balanced pairs
    # Determinism: (count DESC, reason ASC) ordering — "test fixture" (3)
    # precedes "one-shot migration" (2).
    assert rendered.index("`test fixture`") < rendered.index("`one-shot migration`")


def test_fp_report_emits_rendered_example_reasons():
    """FPPattern.example_reasons_rendered is a list of backtick-wrapped reasons."""
    from screw_agents.aggregation import aggregate_fp_report

    # Three "safe helper" + two "validated input" sharing the same pattern.
    reasons = [
        "safe helper",
        "safe helper",
        "safe helper",
        "validated input",
        "validated input",
    ]
    exclusions = [
        _excl(
            id=f"fp-2026-04-14-{i:03d}",
            agent="sqli",
            pattern="db.text_search(*)",
            file=f"src/s{i}.py",
            line=10,
            reason=reason,
        )
        for i, reason in enumerate(reasons)
    ]
    report = aggregate_fp_report(exclusions)
    assert len(report.top_fp_patterns) == 1
    pattern = report.top_fp_patterns[0]
    # Keep raw list for machine consumers (Phase 4 autoresearch)
    assert pattern.example_reasons == ["safe helper", "validated input"]
    # NEW: each element pre-wrapped in backticks, same order as example_reasons
    assert pattern.example_reasons_rendered == ["`safe helper`", "`validated input`"]


def test_aggregate_fp_report_mixed_fixture_quarantine_empty_below_above_threshold():
    """Quarantined + empty-pattern + below-threshold + above-threshold all in one fixture."""
    from screw_agents.aggregation import aggregate_fp_report
    exclusions = []

    # Bucket A: 5 entries, 1 quarantined -> 4 counted (above threshold)
    for i in range(5):
        exclusions.append(
            _excl(id=f"fp-2026-04-14-a{i:03d}", agent="sqli",
                  pattern="bucket_a", file=f"src/a{i}.py", line=10,
                  reason="r")
        )
    exclusions[0].quarantined = True

    # Bucket B: 2 entries (below threshold — should not appear)
    for i in range(2):
        exclusions.append(
            _excl(id=f"fp-2026-04-14-b{i:03d}", agent="sqli",
                  pattern="bucket_b", file=f"src/b{i}.py", line=10,
                  reason="r")
        )

    # Bucket C: 3 entries all with empty code_pattern -> should not bucket
    for i in range(3):
        exclusions.append(
            Exclusion(
                id=f"fp-2026-04-14-c{i:03d}",
                created="2026-04-14T10:00:00Z",
                agent="sqli",
                finding=ExclusionFinding(
                    file=f"src/c{i}.py", line=10, code_pattern="", cwe="CWE-89"
                ),
                reason="r",
                scope=ExclusionScope(type="exact_line", path=f"src/c{i}.py"),
            )
        )

    # Bucket D: 4 entries (above threshold)
    for i in range(4):
        exclusions.append(
            _excl(id=f"fp-2026-04-14-d{i:03d}", agent="cmdi",
                  pattern="bucket_d", file=f"src/d{i}.py", line=10,
                  reason="r")
        )

    report = aggregate_fp_report(exclusions)
    # Expect only buckets A (count=4) and D (count=4) — both tied, so
    # deterministic tie-break by (agent, cwe, pattern) applies:
    # cmdi/CWE-89/bucket_d vs sqli/CWE-89/bucket_a -> cmdi wins
    patterns = [(p.agent, p.pattern, p.fp_count) for p in report.top_fp_patterns]
    assert patterns == [("cmdi", "bucket_d", 4), ("sqli", "bucket_a", 4)]


# ---------------------------------------------------------------------------
# T21-m1 fix-up — Backtick-escape + tie-break + suggestion parity
# ---------------------------------------------------------------------------


def test_directory_suggestions_escape_backticks_in_reasons():
    """A reason containing a backtick does NOT break the Markdown code span."""
    # Seed a bucket where reason contains a backtick
    exclusions = [
        _excl(id=f"fp-2026-04-16-{i:03d}", agent="sqli",
              pattern="q(*)", file=f"test/t{i}.py", line=10,
              reason="safe `wrapped` helper")
        for i in range(3)
    ]
    # Force into the directory-suggestion path by using a directory-grouped file path
    # (already satisfied — all files under test/)
    # Note: must meet _DIR_MIN_COUNT (3) for suggestion to be emitted
    from screw_agents.aggregation import aggregate_directory_suggestions
    suggestions = aggregate_directory_suggestions(exclusions)
    assert len(suggestions) == 1
    rendered = suggestions[0].evidence["reason_distribution_rendered"]
    # Original backticks are replaced, preserving balanced code-span pairs
    assert "`" in rendered  # the wrapping backticks remain
    # Count of un-escaped backticks should be EVEN (the wrappers)
    assert rendered.count("`") == 2  # one open, one close — single reason bucket
    # The suggestion string's top_reason is also backtick-wrapped and escaped
    assert "top reason: `safe " in suggestions[0].suggestion
    # U+02BC is present in place of the raw backtick
    assert "\u02bc" in rendered


def test_directory_suggestions_tie_break_alignment():
    """top_reason in `suggestion` must agree with the first entry of
    reason_distribution_rendered. Equal-count reasons pick lex-smallest."""
    # 3× "alpha" + 3× "bravo" → both count=3, tie → should pick "alpha"
    exclusions = [
        _excl(id=f"fp-2026-04-16-1{i:02d}", agent="sqli",
              pattern="q(*)", file=f"test/t{i}.py", line=10, reason="alpha")
        for i in range(3)
    ] + [
        _excl(id=f"fp-2026-04-16-2{i:02d}", agent="sqli",
              pattern="q(*)", file=f"test/t{i+3}.py", line=10, reason="bravo")
        for i in range(3)
    ]
    from screw_agents.aggregation import aggregate_directory_suggestions
    suggestions = aggregate_directory_suggestions(exclusions)
    assert len(suggestions) == 1
    # suggestion.top_reason → "alpha" (lex smallest on tied count)
    assert "top reason: `alpha`" in suggestions[0].suggestion
    # rendered order: alpha first, then bravo
    rendered = suggestions[0].evidence["reason_distribution_rendered"]
    assert rendered.index("`alpha`") < rendered.index("`bravo`")


def test_fp_report_escapes_backticks_in_example_reasons():
    """example_reasons_rendered sanitizes backticks in raw reason strings."""
    from screw_agents.aggregation import aggregate_fp_report
    exclusions = [
        _excl(id=f"fp-2026-04-16-3{i:02d}", agent="sqli",
              pattern="db.text_search(*)", file=f"src/s{i}.py",
              line=10, reason="safe `helper` call")
        for i in range(3)
    ]
    report = aggregate_fp_report(exclusions)
    assert len(report.top_fp_patterns) == 1
    pattern = report.top_fp_patterns[0]
    assert len(pattern.example_reasons_rendered) == 1
    rendered = pattern.example_reasons_rendered[0]
    # Outer wrapping backticks preserved
    assert rendered.startswith("`") and rendered.endswith("`")
    # Internal raw backticks replaced with U+02BC
    assert "\u02bc" in rendered
    # Total backtick count is exactly 2 (the wrappers)
    assert rendered.count("`") == 2


def test_fp_report_rendered_parallels_example_reasons():
    """example_reasons_rendered is index-aligned with example_reasons."""
    from screw_agents.aggregation import aggregate_fp_report
    exclusions = [
        _excl(id=f"fp-2026-04-16-4{i:02d}", agent="sqli",
              pattern="q(*)", file=f"src/s{i}.py", line=10,
              reason=reason)
        for i, reason in enumerate(["zeta"] * 3 + ["alpha"] * 5)
    ]
    report = aggregate_fp_report(exclusions)
    pattern = report.top_fp_patterns[0]
    # Length invariant
    assert len(pattern.example_reasons_rendered) == len(pattern.example_reasons)
    # Element-wise alignment (modulo backtick wrapping + escape)
    for raw, rendered in zip(pattern.example_reasons, pattern.example_reasons_rendered):
        expected = raw.replace("`", "\u02bc")
        assert rendered == f"`{expected}`"


def test_directory_suggestions_benign_markdown_chars_still_wrapped():
    """Non-backtick Markdown-structural chars (*, _, [, ]) are safely contained
    by the code-span wrapping — the escape helper does NOT need to touch them."""
    exclusions = [
        _excl(id=f"fp-2026-04-16-5{i:02d}", agent="sqli",
              pattern="q(*)", file=f"test/t{i}.py", line=10,
              reason=reason)
        for i, reason in enumerate(["*star* _under_ [link]"] * 3)
    ]
    from screw_agents.aggregation import aggregate_directory_suggestions
    suggestions = aggregate_directory_suggestions(exclusions)
    rendered = suggestions[0].evidence["reason_distribution_rendered"]
    # Wrapping backticks render the whole reason as code — structural chars neutralized
    assert "`*star* _under_ [link]`" in rendered
