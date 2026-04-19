"""Coverage-gap signals for adaptive analysis (Phase 3b).

This module detects places where the YAML scan engine had reason to believe a
vulnerability *might* be present but could not (or did not) emit a finding on
its own. Adaptive analysis scripts target these gaps; the signal is what tells
the orchestrator "here is where additional analysis would help."

Two signals ship here:

D1 — "context-required dropped"
    A pattern declared in a YAML agent with `severity: context-required` matched
    a source location, but the agent did not emit a finding for that match.
    `severity: context-required` is the YAML author's explicit declaration that
    the pattern is suspicious but cannot be classified by static rules alone.
    A dropped match is therefore a self-declared gap: zero false positives by
    construction, because the YAML agent literally tagged the gap itself. No
    LLM reasoning enters the decision. Producers emit one match record per
    occurrence using the `ContextRequiredMatch` TypedDict declared below.

D2 — "taint-verified unresolved sink"
    A sink-shaped call (method name matching `sink_regex`) is invoked on a
    receiver that is NOT in the YAML agent's `known_receivers` set, AND at
    least one argument taints back to a known source via bounded
    intraprocedural dataflow trace. The taint check uses
    `screw_agents.adaptive.dataflow.match_pattern` — the same depth-bounded,
    scope-bounded, cycle-detected identifier-binding trace used by the
    adaptive scripts themselves. This is real SAST taint propagation, NOT
    file-level substring co-occurrence.

    Design choice — intraprocedural only: the taint trace is scope-bounded to
    the enclosing `function_definition` and does NOT follow returns, globals,
    module-level bindings, or cross-function flows. A source assigned in
    function A and consumed in function B of the same file will NOT fire D2.
    This is intentional: interprocedural analysis lives downstream in the
    adaptive script the signal triggers, not in the signal itself.

    A pure-performance file-level prefilter skips files with zero source
    references at all so we don't parse them. The prefilter is NOT a signal
    condition — every fired gap has a verified per-call taint path.

Both detectors are pure functions over data the scan engine has already
collected. They yield `CoverageGap` records lazily so the caller can stream
results into a generator pipeline without materializing a list.
"""

from __future__ import annotations

import re
from collections.abc import Iterator, Mapping
from pathlib import Path
from typing import TypedDict

from screw_agents.adaptive.ast_walker import (
    _CALL_PARENS_RE,
    _call_callee_text,
    parse_ast,
    walk_ast,
)
from screw_agents.adaptive.dataflow import get_call_args, match_pattern
from screw_agents.adaptive.project import ProjectRoot
from screw_agents.models import CoverageGap

__all__ = [
    "ContextRequiredMatch",
    "detect_d1_context_required_gaps",
    "detect_d2_unresolved_sink_gaps",
]


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


def detect_d2_unresolved_sink_gaps(
    *,
    project_root: Path,
    agent: str,
    sink_regex: str,
    known_receivers: set[str],
    known_sources: list[str],
) -> Iterator[CoverageGap]:
    """D2: Yield a CoverageGap for every sink-shaped call where:
      1. Method name matches `sink_regex`
      2. Receiver is NOT in `known_receivers`
      3. At least one argument taints back to a known source via bounded
         intraprocedural dataflow (NOT file-level substring co-occurrence).

    Uses `screw_agents.adaptive.dataflow.match_pattern` for condition 3 —
    real SAST taint propagation with depth-bounded, scope-bounded, cycle-
    detected trace. Intraprocedural only: cross-function flows, returns,
    globals, and module-level bindings are NOT followed.

    The file-level substring presence check is a pure performance prefilter
    (skip parsing files with zero source references) and does NOT itself
    signal a gap — every fired gap has a verified per-call taint path.

    Args:
        project_root: Absolute path to the project root. All files scanned
            via `ProjectRoot`, which enforces no-escape semantics.
        agent: YAML agent identifier (e.g., "sqli") attached to every gap.
        sink_regex: Python regex matched against the callee method name (the
            trailing dotted token). `re.search` semantics — anchor explicitly
            if you need an exact match.
        known_receivers: Set of receiver identifiers the YAML agent already
            handles. Calls on these receivers are NOT gaps — they're coverage.
        known_sources: List of source substring patterns (e.g.,
            `["request.args", "request.form"]`). Passed to `match_pattern` as
            the pattern list; semantics match the adaptive dataflow helpers.

    Yields:
        `CoverageGap(type="unresolved_sink", agent=..., file=..., line=...,
        evidence={"sink_regex": ..., "receiver": ..., "method": ...,
        "callee_text": ...})` for every call where all three conditions hold.

    Security:
        Not zero-FP by construction (unlike D1). The signal is "there is a
        taint path to a sink-shaped call on an unknown receiver" — the
        downstream adaptive script is what classifies true/false positive.
        Intraprocedural-only is a deliberate precision choice: cross-function
        analysis belongs in the adaptive script triggered by the gap, not in
        the gap signal itself.
    """
    project = ProjectRoot(project_root)
    pattern = re.compile(sink_regex)

    for rel_path in project.list_files("**/*.py"):
        try:
            source = project.read_file(rel_path)
        except (UnicodeDecodeError, OSError):
            # Narrow exception per DEFERRED_BACKLOG T3-M1 discipline. Non-UTF-8
            # or unreadable files are silently skipped; real bugs (e.g.,
            # programmer errors in ProjectRoot) still propagate.
            continue

        # Pure perf prefilter: skip files with zero source references at all.
        # This does NOT itself signal a gap — each call still has to produce
        # a verified per-call taint path for D2 to fire.
        if not any(src in source for src in known_sources):
            continue

        tree = parse_ast(source, language="python")
        for call in walk_ast(tree, node_types=["call"]):
            callee_text = _call_callee_text(call, source)
            if not callee_text:
                continue

            # Strip parenthesized subexpressions iteratively so chained calls
            # like `get_db().execute` yield tokens `["get_db", "execute"]`
            # rather than `["get_db()", "execute"]`. Reuses ast_walker's
            # regex to match how find_calls already handles chains.
            cleaned = callee_text
            while True:
                new_cleaned = _CALL_PARENS_RE.sub("", cleaned)
                if new_cleaned == cleaned:
                    break
                cleaned = new_cleaned
            tokens = [t for t in cleaned.split(".") if t]
            if len(tokens) < 2:
                # Bare calls (e.g., `execute(q)`) have no receiver we can
                # classify as known/unknown; skip.
                continue

            method = tokens[-1]
            receiver = tokens[-2]

            # Condition 1: method regex match
            if not pattern.search(method):
                continue

            # Condition 2: receiver NOT in known set
            if receiver in known_receivers:
                continue

            # Condition 3: at least one argument taints back to a known source
            # via bounded intraprocedural dataflow. THIS is the real SAST
            # signal — the file-level prefilter above was just a perf guard.
            args = get_call_args(call)
            tainted = any(
                match_pattern(arg, source=source, patterns=known_sources)
                for arg in args
            )
            if not tainted:
                continue

            yield CoverageGap(
                type="unresolved_sink",
                agent=agent,
                file=rel_path,
                line=call.start_point[0] + 1,
                evidence={
                    "sink_regex": sink_regex,
                    "receiver": receiver,
                    "method": method,
                    "callee_text": callee_text,
                },
            )
