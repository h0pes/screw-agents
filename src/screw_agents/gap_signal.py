"""Coverage-gap signals for adaptive analysis (Phase 3b).

This module detects places where the YAML scan engine had reason to believe a
vulnerability *might* be present but could not (or did not) emit a finding on
its own. Adaptive analysis scripts target these gaps; the signal is what tells
the orchestrator "here is where additional analysis would help."

Two signals are planned:

D1 — "context-required dropped"
    A pattern declared in a YAML agent with `severity: context-required` matched
    a source location, but the agent did not emit a finding for that match.
    `severity: context-required` is the YAML author's explicit declaration that
    the pattern is suspicious but cannot be classified by static rules alone.
    A dropped match is therefore a self-declared gap: zero false positives by
    construction, because the YAML agent literally tagged the gap itself. No
    LLM reasoning enters the decision. Producers emit one match record per
    occurrence using the `ContextRequiredMatch` TypedDict declared below.

D2 — "unresolved sink reachability"
    A known dangerous sink was reached via dataflow whose source could not be
    classified by the engine (e.g., interprocedural call boundary, dynamic
    dispatch, missing type information). The engine had partial evidence of a
    flow but could not complete the trust analysis.

NOTE: T14 ships D1 only. D2 lands in T15 as `detect_d2_unresolved_sink_gaps`,
which will be added to `__all__` at that time.

Both detectors are pure functions over data the scan engine has already
collected. They yield `CoverageGap` records lazily so the caller can stream
results into a generator pipeline without materializing a list.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from typing import TypedDict

from screw_agents.models import CoverageGap

__all__ = [
    "ContextRequiredMatch",
    "detect_d1_context_required_gaps",
]
# T15: append "detect_d2_unresolved_sink_gaps" to __all__.


class ContextRequiredMatch(TypedDict):
    """Shape of a single context-required pattern match recorded by the YAML
    scan engine. T16 (ScanEngine.detect_coverage_gaps) produces these at scan
    time; gap_signal.py consumes them here.

    All four fields are required and structural. Producers MUST emit all four
    keys with the declared types; a malformed dict is a producer bug, not a
    condition this module handles.
    """

    agent: str
    file: str
    line: int
    pattern: str


def detect_d1_context_required_gaps(
    *,
    context_required_matches: list[ContextRequiredMatch],
    emitted_findings_by_match: Mapping[tuple[str, str, int, str], object],
) -> Iterator[CoverageGap]:
    """D1: yield a CoverageGap for every context-required pattern match that
    did not produce a finding.

    The YAML scan engine records every match of a `severity: context-required`
    pattern in `context_required_matches`, then records which matches actually
    produced a finding in `emitted_findings_by_match` (keyed by
    `(agent, file, line, pattern)`). Any match whose key is *absent* from
    `emitted_findings_by_match` is, by the YAML author's own declaration, a
    coverage gap that adaptive analysis could fill.

    Deduplication is the caller's responsibility. Duplicate match entries in
    `context_required_matches` yield duplicate `CoverageGap` events — gap_signal
    preserves the 1:1 match-event to gap-event correspondence.

    Args:
        context_required_matches: Records of every context-required pattern
            match seen during the scan. See `ContextRequiredMatch` for shape.
        emitted_findings_by_match: Membership-only mapping from match key
            `(agent, file, line, pattern)` to caller-defined value (typically
            a finding id). Presence of the key means a finding was emitted;
            absence means the match was dropped. The value is never read.

    Yields:
        `CoverageGap(type="context_required", agent=..., file=..., line=...,
        evidence={"pattern": ...})` for every dropped match.

    Security:
        Zero false positives by construction. The YAML agent declared the gap
        itself by tagging the pattern `severity: context-required` and choosing
        not to emit a finding. No LLM reasoning is involved in the signal.
    """
    for match in context_required_matches:
        key = (match["agent"], match["file"], match["line"], match["pattern"])
        if key in emitted_findings_by_match:
            continue
        yield CoverageGap(
            type="context_required",
            agent=match["agent"],
            file=match["file"],
            line=match["line"],
            evidence={"pattern": match["pattern"]},
        )
