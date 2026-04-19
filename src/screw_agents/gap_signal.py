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
    LLM reasoning enters the decision.

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

from collections.abc import Iterator
from typing import Any

from screw_agents.models import CoverageGap

__all__ = ["detect_d1_context_required_gaps"]


def detect_d1_context_required_gaps(
    *,
    context_required_matches: list[dict[str, Any]],
    emitted_findings_by_match: dict[tuple[str, str, int, str], Any],
) -> Iterator[CoverageGap]:
    """D1: yield a CoverageGap for every context-required pattern match that
    did not produce a finding.

    The YAML scan engine records every match of a `severity: context-required`
    pattern in `context_required_matches`, then records which matches actually
    produced a finding in `emitted_findings_by_match` (keyed by
    `(agent, file, line, pattern)`). Any match whose key is *absent* from
    `emitted_findings_by_match` is, by the YAML author's own declaration, a
    coverage gap that adaptive analysis could fill.

    Args:
        context_required_matches: Records of every context-required pattern
            match seen during the scan. Each dict has keys `agent` (str),
            `file` (str), `line` (int), `pattern` (str).
        emitted_findings_by_match: Mapping from match key
            `(agent, file, line, pattern)` to caller-defined value (typically
            a finding id). Presence of the key means a finding was emitted;
            absence means the match was dropped.

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
