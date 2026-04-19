"""Unit tests for src/screw_agents/gap_signal.py — adaptive coverage-gap detection.

T14 covers the D1 signal (context-required pattern matched but no finding emitted).
T15 covers the D2 signal (taint-verified unresolved sink) via real intraprocedural
dataflow through `adaptive.dataflow.match_pattern`, NOT file-level substring
co-occurrence.

Security properties under test:
- D1: zero false positives by construction. The YAML agent itself declared the
  gap by tagging a pattern as `severity: context-required` and choosing not to
  emit a finding. No LLM reasoning involved.
- D2: real taint path required — sink-shape match + unknown receiver alone are
  NOT sufficient. The argument must trace back to a known source via bounded
  intraprocedural dataflow. Cross-file and cross-function cases must not fire.
"""

from __future__ import annotations

from pathlib import Path

from screw_agents.gap_signal import (
    detect_d1_context_required_gaps,
    detect_d2_unresolved_sink_gaps,
)
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
    """A context-required match that produced a finding must NOT yield a gap.

    Asserts the dual side of the zero-FP-by-construction property: if the YAML
    agent DID emit a finding, no gap is reported. Combined with
    `test_d1_fires_on_dropped_context_required_match`, these two tests pin the
    iff condition that D1's security claim rests on.
    """
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
            "pattern": "$X.execute($Y)",
        },
        {
            "agent": "cmdi",
            "file": "b.py",
            "line": 2,
            "pattern": "subprocess.run(...)",
        },
        {
            "agent": "ssti",
            "file": "c.py",
            "line": 3,
            "pattern": "render_template_string(...)",
        },
    ]
    emitted: dict[tuple[str, str, int, str], object] = {
        ("sqli", "a.py", 1, "$X.execute($Y)"): "fid-1",
        ("ssti", "c.py", 3, "render_template_string(...)"): "fid-3",
    }

    gaps = list(detect_d1_context_required_gaps(
        context_required_matches=matches,
        emitted_findings_by_match=emitted,
    ))

    assert len(gaps) == 1
    assert gaps[0].agent == "cmdi"
    assert gaps[0].file == "b.py"
    assert gaps[0].line == 2
    assert gaps[0].evidence == {"pattern": "subprocess.run(...)"}


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


def test_d1_same_location_different_pattern_yields_two_gaps() -> None:
    """Two context-required patterns matching the same line are two distinct
    gaps. The tuple-key includes `pattern` by design — a future refactor that
    keys only by (agent, file, line) would silently lose findings.

    Real-world case: `eval(eval(x))` can match an eval-based pattern twice on
    the same line (outer and inner call). Both are legitimate gaps.
    """
    matches = [
        {"agent": "sqli", "file": "src/app.py", "line": 42, "pattern": "eval_outer"},
        {"agent": "sqli", "file": "src/app.py", "line": 42, "pattern": "eval_inner"},
    ]
    gaps = list(detect_d1_context_required_gaps(
        context_required_matches=matches,
        emitted_findings_by_match={},
    ))
    assert len(gaps) == 2
    patterns = {g.evidence["pattern"] for g in gaps}
    assert patterns == {"eval_outer", "eval_inner"}


def test_d1_duplicate_match_entries_yield_duplicate_gaps() -> None:
    """Duplicate match events in the input produce duplicate gap events in
    the output. Deduplication, if desired, is the caller's responsibility —
    gap_signal does not assume its caller has already deduped.

    Locks the contract so a future "optimization" that adds internal dedup
    doesn't silently change semantics for a caller that depends on one
    gap-event per match-event.
    """
    matches = [
        {"agent": "sqli", "file": "src/app.py", "line": 42, "pattern": "ambiguous(*)"},
        {"agent": "sqli", "file": "src/app.py", "line": 42, "pattern": "ambiguous(*)"},
    ]
    gaps = list(detect_d1_context_required_gaps(
        context_required_matches=matches,
        emitted_findings_by_match={},
    ))
    assert len(gaps) == 2


# ---------------------------------------------------------------------------
# D2 — taint-verified unresolved sink
#
# All six tests below exercise the three conjoint conditions (sink regex match,
# receiver not in known_receivers, argument taints back to a known source via
# bounded intraprocedural dataflow) plus the two design-choice limits
# (cross-file isolation, cross-function isolation).
# ---------------------------------------------------------------------------


def test_d2_fires_on_unresolved_sink_with_tainted_arg(tmp_path: Path) -> None:
    """Source -> identifier binding -> sink call: should fire D2."""
    (tmp_path / "handler.py").write_text(
        "def handle(request):\n"
        "    q = request.args.get('q')\n"
        "    self.db.execute_raw(q)\n"
    )

    gaps = list(detect_d2_unresolved_sink_gaps(
        project_root=tmp_path,
        agent="sqli",
        sink_regex=r"execute|execute_raw|query",
        known_receivers={"cursor", "connection", "Session"},
        known_sources=["request.args"],
    ))
    assert len(gaps) == 1
    assert isinstance(gaps[0], CoverageGap)
    assert gaps[0].type == "unresolved_sink"
    assert gaps[0].agent == "sqli"
    assert gaps[0].file == "handler.py"
    assert gaps[0].line == 3
    assert gaps[0].evidence["receiver"] == "db"
    assert gaps[0].evidence["method"] == "execute_raw"


def test_d2_does_not_fire_without_tainted_arg(tmp_path: Path) -> None:
    """Unresolved receiver + sink method name, but all args are literals
    with no source taint: should NOT fire (real taint required, not just
    sink-shape match).

    The `_hint` binding exists so the file-level prefilter passes — this test
    specifically locks condition-3 (taint trace), not the prefilter.
    """
    (tmp_path / "handler.py").write_text(
        "def handle(request):\n"
        "    # File contains source pattern so prefilter passes\n"
        "    _hint = request.args.get('unused')\n"
        "    self.db.execute_raw('SELECT 1')\n"
    )

    gaps = list(detect_d2_unresolved_sink_gaps(
        project_root=tmp_path,
        agent="sqli",
        sink_regex=r"execute|execute_raw",
        known_receivers={"cursor"},
        known_sources=["request.args"],
    ))
    assert gaps == []


def test_d2_does_not_fire_for_known_receiver(tmp_path: Path) -> None:
    """Receiver IS in known_receivers: YAML agent already handles this,
    not a coverage gap."""
    (tmp_path / "handler.py").write_text(
        "def handle(request):\n"
        "    q = request.args.get('q')\n"
        "    cursor.execute_raw(q)\n"
    )

    gaps = list(detect_d2_unresolved_sink_gaps(
        project_root=tmp_path,
        agent="sqli",
        sink_regex=r"execute|execute_raw",
        known_receivers={"cursor"},
        known_sources=["request.args"],
    ))
    assert gaps == []


def test_d2_fires_on_direct_source_in_arg(tmp_path: Path) -> None:
    """Argument is a direct source expression, no intermediate variable:
    match_pattern should still detect the source pattern in the arg's text."""
    (tmp_path / "handler.py").write_text(
        "def handle(request):\n"
        "    self.db.execute_raw(request.args.get('q'))\n"
    )

    gaps = list(detect_d2_unresolved_sink_gaps(
        project_root=tmp_path,
        agent="sqli",
        sink_regex=r"execute|execute_raw",
        known_receivers={"cursor"},
        known_sources=["request.args"],
    ))
    assert len(gaps) == 1
    assert gaps[0].line == 2
    assert gaps[0].evidence["receiver"] == "db"
    assert gaps[0].evidence["method"] == "execute_raw"


def test_d2_does_not_fire_when_source_in_different_file(tmp_path: Path) -> None:
    """Source appears in file A, sink in file B: should NOT fire. Verifies
    the file-level prefilter correctly scopes taint-tracking per file.

    This locks cross-file isolation: even though both files exist in the
    same project, the taint trace is per-file and the prefilter short-
    circuits the sink file (which has no source reference) before AST parse.
    """
    (tmp_path / "a_source.py").write_text(
        "def load(request):\n"
        "    return request.args.get('q')\n"
    )
    (tmp_path / "b_sink.py").write_text(
        "def save(q):\n"
        "    self.db.execute_raw(q)\n"
    )

    gaps = list(detect_d2_unresolved_sink_gaps(
        project_root=tmp_path,
        agent="sqli",
        sink_regex=r"execute|execute_raw",
        known_receivers={"cursor"},
        known_sources=["request.args"],
    ))
    assert gaps == []


def test_d2_does_not_fire_across_function_boundaries(tmp_path: Path) -> None:
    """Source binding in function A, sink in function B, same file: should
    NOT fire. The dataflow trace is intraprocedural (scope-bounded to
    enclosing function_definition); this test locks that design choice.

    Interprocedural analysis is explicitly out of scope for the signal —
    it belongs downstream in the adaptive script the signal triggers.
    """
    (tmp_path / "split.py").write_text(
        "def load(request):\n"
        "    q = request.args.get('q')\n"
        "    return q\n"
        "\n"
        "def save(q):\n"
        "    self.db.execute_raw(q)\n"
    )

    gaps = list(detect_d2_unresolved_sink_gaps(
        project_root=tmp_path,
        agent="sqli",
        sink_regex=r"execute|execute_raw",
        known_receivers={"cursor"},
        known_sources=["request.args"],
    ))
    assert gaps == []
