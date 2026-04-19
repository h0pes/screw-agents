"""Unit tests for src/screw_agents/gap_signal.py — adaptive coverage-gap detection.

T14 covers the D1 signal (context-required pattern matched but no finding emitted).
T15 will add D2 (unresolved sink reachability) tests in this same file.

Security property under test: D1 has zero false positives by construction. The
YAML agent itself declared the gap by tagging a pattern as `severity:
context-required` and choosing not to emit a finding. No LLM reasoning involved.
"""

from __future__ import annotations

from screw_agents.gap_signal import detect_d1_context_required_gaps
from screw_agents.models import CoverageGap


def test_d1_fires_on_dropped_context_required_match() -> None:
    """A context-required match with no emitted finding yields exactly one gap.

    Also asserts the evidence dict shape — locks the `pattern` key so a rename
    (e.g., `pattern` -> `match_pattern`) cannot regress silently.
    """
    matches = [
        {
            "agent": "sqli",
            "file": "app.py",
            "line": 42,
            "pattern": "ambiguous(*)",
        },
    ]
    emitted: dict[tuple[str, str, int, str], object] = {}

    gaps = list(detect_d1_context_required_gaps(
        context_required_matches=matches,
        emitted_findings_by_match=emitted,
    ))

    assert len(gaps) == 1
    assert isinstance(gaps[0], CoverageGap)
    assert gaps[0].type == "context_required"
    assert gaps[0].agent == "sqli"
    assert gaps[0].file == "app.py"
    assert gaps[0].line == 42
    assert gaps[0].evidence == {"pattern": "ambiguous(*)"}


def test_d1_does_not_fire_when_finding_was_emitted() -> None:
    """A context-required match that produced a finding must NOT yield a gap."""
    matches = [
        {
            "agent": "xss",
            "file": "view.py",
            "line": 7,
            "pattern": "render_template_string(*)",
        },
    ]
    emitted: dict[tuple[str, str, int, str], object] = {
        ("xss", "view.py", 7, "render_template_string(*)"): "finding-id-001",
    }

    gaps = list(detect_d1_context_required_gaps(
        context_required_matches=matches,
        emitted_findings_by_match=emitted,
    ))

    assert gaps == []


def test_d1_returns_empty_for_empty_input() -> None:
    """No matches in, no gaps out."""
    gaps = list(detect_d1_context_required_gaps(
        context_required_matches=[],
        emitted_findings_by_match={},
    ))

    assert gaps == []


def test_d1_partial_emission_yields_only_dropped() -> None:
    """3 matches, 2 emitted findings, 1 dropped — exactly 1 gap, matching the dropped one."""
    matches = [
        {
            "agent": "sqli",
            "file": "a.py",
            "line": 1,
            "pattern": "p1",
        },
        {
            "agent": "sqli",
            "file": "b.py",
            "line": 2,
            "pattern": "p2",
        },
        {
            "agent": "ssti",
            "file": "c.py",
            "line": 3,
            "pattern": "p3",
        },
    ]
    emitted: dict[tuple[str, str, int, str], object] = {
        ("sqli", "a.py", 1, "p1"): "fid-1",
        ("ssti", "c.py", 3, "p3"): "fid-3",
    }

    gaps = list(detect_d1_context_required_gaps(
        context_required_matches=matches,
        emitted_findings_by_match=emitted,
    ))

    assert len(gaps) == 1
    assert gaps[0].agent == "sqli"
    assert gaps[0].file == "b.py"
    assert gaps[0].line == 2
    assert gaps[0].evidence == {"pattern": "p2"}


def test_d1_evidence_locks_pattern_key() -> None:
    """Independent assertion that evidence is exactly {"pattern": ...}.

    Deliberately redundant with the evidence assertion in
    `test_d1_fires_on_dropped_context_required_match` — two independent tests
    asserting the same invariant make a regression unambiguous.
    """
    matches = [
        {
            "agent": "cmdi",
            "file": "shell.py",
            "line": 99,
            "pattern": "subprocess.run(shell=True)",
        },
    ]
    emitted: dict[tuple[str, str, int, str], object] = {}

    gaps = list(detect_d1_context_required_gaps(
        context_required_matches=matches,
        emitted_findings_by_match=emitted,
    ))

    assert len(gaps) == 1
    assert gaps[0].evidence == {"pattern": "subprocess.run(shell=True)"}
