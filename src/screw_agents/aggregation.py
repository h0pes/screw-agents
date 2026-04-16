"""Learning aggregation — cross-scan pattern reports from the exclusions database.

Phase 3a ships Features 1, 2, 4 from PRD §11.2 layer 3. Feature 3 (high-value
target suggestions) is deferred to Phase 6 because it requires a new data source
(confirmed findings, not just rejections).

All three features share the same data pipeline — they're different projections
of the same signed exclusions database.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
from typing import Literal

from screw_agents.models import (
    DirectorySuggestion,
    Exclusion,
    FPPattern,
    FPReport,
    PatternSuggestion,
)

# Thresholds for confidence levels on pattern-confidence suggestions.
_PATTERN_MIN_COUNT = 3
_PATTERN_MEDIUM_COUNT = 5
_PATTERN_HIGH_COUNT = 10


def aggregate_pattern_confidence(exclusions: list[Exclusion]) -> list[PatternSuggestion]:
    """Group exclusions by (agent, code_pattern, cwe) into safe-pattern suggestions.

    Only trusted (non-quarantined) exclusions with a non-empty code_pattern are considered.
    A bucket must contain at least _PATTERN_MIN_COUNT exclusions to generate a suggestion.

    The bucket key is the full triple (agent, code_pattern, cwe) — identical patterns
    under different agents or different CWEs are NOT collapsed, because a safe pattern
    for one vulnerability class is not automatically safe for another.
    """
    buckets: dict[tuple[str, str, str], list[Exclusion]] = defaultdict(list)
    for excl in exclusions:
        if excl.quarantined:
            continue
        # Skip exclusions with no identifiable code-pattern — these are
        # either schema-evolution artifacts or test fixtures and must not
        # synthesize a bogus empty-pattern suggestion.
        if not excl.finding.code_pattern.strip():
            continue
        key = (excl.agent, excl.finding.code_pattern, excl.finding.cwe)
        buckets[key].append(excl)

    suggestions: list[PatternSuggestion] = []
    for (agent, pattern, cwe), group in buckets.items():
        if len(group) < _PATTERN_MIN_COUNT:
            continue

        files_affected = sorted({e.finding.file for e in group})
        confidence: Literal["low", "medium", "high"]
        if len(group) >= _PATTERN_HIGH_COUNT:
            confidence = "high"
        elif len(group) >= _PATTERN_MEDIUM_COUNT:
            confidence = "medium"
        else:
            confidence = "low"

        # NOTE: min/max on ISO-8601 strings relies on strict YYYY-MM-DDTHH:MM:SSZ form
        # (see Exclusion.created). Tracked by T16-M2 (datetime migration in
        # docs/DEFERRED_BACKLOG.md) which will replace this with datetime comparisons.
        suggestions.append(
            PatternSuggestion(
                pattern=pattern,
                agent=agent,
                cwe=cwe,
                evidence={
                    "exclusion_count": len(group),
                    "files_affected": files_affected,
                    "first_seen": min(e.created for e in group),
                    "last_seen": max(e.created for e in group),
                },
                suggestion=(
                    f"Consider adding `{pattern}` to the project-wide safe patterns list "
                    f"for {agent}."
                ),
                confidence=confidence,
            )
        )
    return suggestions


# Thresholds for confidence levels on directory-scope suggestions.
_DIR_MIN_COUNT = 3
_DIR_MEDIUM_COUNT = 5
_DIR_HIGH_COUNT = 10


def aggregate_directory_suggestions(exclusions: list[Exclusion]) -> list[DirectorySuggestion]:
    """Detect directories where exclusions concentrate, suggesting directory-scope exclusions.

    Groups exclusions by (agent, top_dir) where top_dir is the FIRST path component
    of finding.file plus a trailing slash. This is an intentional coarse granularity:
    a concentration in `src/` surfaces as one bucket, not split by sub-paths. Deeper
    granularity is tracked by T18-M1 in docs/DEFERRED_BACKLOG.md.

    Exclusions are skipped when:
    - quarantined (trust-policy decision)
    - file path is empty/whitespace (malformed data)
    - file path has no directory component (root-level files like README.md)

    Only buckets meeting _DIR_MIN_COUNT produce a suggestion. The "top reason" in
    the suggestion string is deterministically tie-broken by (count, reason_text)
    to prevent order-dependent output across exclusion insertion order.
    """
    buckets: dict[tuple[str, str], list[Exclusion]] = defaultdict(list)
    for excl in exclusions:
        if excl.quarantined:
            continue
        # Skip exclusions with no identifiable file path — these are schema-
        # evolution artifacts or test fixtures and must not synthesize a bogus
        # directory suggestion.
        file_path = excl.finding.file.strip()
        if not file_path:
            continue
        # Skip root-level files (no slash) — they don't represent directory
        # concentration and would produce nonsense suggestions like `README.md/**`.
        if "/" not in file_path:
            continue
        top_dir = file_path.split("/", 1)[0] + "/"
        key = (excl.agent, top_dir)
        buckets[key].append(excl)

    suggestions: list[DirectorySuggestion] = []
    for (agent, directory), group in buckets.items():
        if len(group) < _DIR_MIN_COUNT:
            continue

        reason_counts: dict[str, int] = defaultdict(int)
        for e in group:
            reason_counts[e.reason] += 1

        confidence: Literal["low", "medium", "high"]
        if len(group) >= _DIR_HIGH_COUNT:
            confidence = "high"
        elif len(group) >= _DIR_MEDIUM_COUNT:
            confidence = "medium"
        else:
            confidence = "low"

        # Deterministic tie-break: when two reasons share the same count,
        # the lexicographically larger reason wins. Stable across exclusion
        # insertion order.
        top_reason = max(reason_counts.items(), key=lambda kv: (kv[1], kv[0]))[0]

        # T21-m1: pre-render the reason distribution with backticks server-side
        # so the subagent can surface it verbatim instead of applying its own
        # Markdown-wrapping rule. Order: (count DESC, reason ASC) — matches
        # the deterministic tie-break convention used elsewhere in this module.
        rendered_pairs = sorted(
            reason_counts.items(), key=lambda kv: (-kv[1], kv[0])
        )
        reason_distribution_rendered = ", ".join(
            f"`{reason}` ({count})" for reason, count in rendered_pairs
        )

        suggestions.append(
            DirectorySuggestion(
                directory=directory,
                agent=agent,
                evidence={
                    "total_findings_in_directory": len(group),
                    # Invariant: every Exclusion in the database represents a user-confirmed
                    # false positive (that's the only way entries land in exclusions.yaml).
                    # The literal True encodes this invariant; do NOT compute it from group
                    # contents — the model guarantees it.
                    "all_marked_false_positive": True,
                    "reason_distribution": dict(reason_counts),
                    "reason_distribution_rendered": reason_distribution_rendered,
                    "files_affected": sorted({e.finding.file for e in group}),
                },
                suggestion=(
                    f"Add directory-scope exclusion for `{directory}**` "
                    f"(top reason: '{top_reason}')."
                ),
                confidence=confidence,
            )
        )
    return suggestions


# Thresholds for the FP report (Feature 4 — Phase 4 autoresearch signal).
# _FP_REPORT_TOP_N caps the number of pattern buckets returned. Rationale:
# Phase 4 autoresearch iterates the FP report per-agent; with ~18 domains
# × 10 patterns × N scans, the aggregate signal volume is manageable. If
# a project has deeper heterogeneity and 10 feels too few, this is the
# knob to tune. Tracked by T19-N1 (parameterization) in DEFERRED_BACKLOG.md.
_FP_REPORT_TOP_N = 10
_FP_REPORT_MIN_COUNT = 3
_FP_REPORT_MAX_REASONS = 5  # Number of example_reasons to include per FPPattern


def aggregate_fp_report(exclusions: list[Exclusion]) -> FPReport:
    """Produce a ranked list of FP patterns suitable for Phase 4 autoresearch.

    Groups by (agent, cwe, code_pattern) — same triple as aggregate_pattern_confidence
    so the two signals are directly comparable. Returns the top _FP_REPORT_TOP_N
    buckets (ranked by fp_count descending, with deterministic tie-break on
    (count, agent, cwe, pattern)), filtered to bucket size >= _FP_REPORT_MIN_COUNT.

    Only trusted (non-quarantined) exclusions with a non-empty code_pattern are
    counted.

    Field-role separation (important for Phase 4 autoresearch consumers):
    - Structured fields (`agent`, `cwe`, `pattern`, `fp_count`, `example_reasons`)
      are the MACHINE-READABLE signal. Phase 4 refinement logic MUST read these
      directly rather than parsing prose.
    - `candidate_heuristic_refinement` is a HUMAN-READABLE display string for the
      screw-learning-analyst subagent's report. Treat it as prose, not as a
      stable contract — wording may evolve.

    The output is consumed by:
    - Task 21 subagent (human-readable report via candidate_heuristic_refinement)
    - Phase 4 autoresearch loop (machine-readable YAML-refinement signal via
      structured fields — Phase 3b Task 18 references this contract in
      docs/PHASE_3B_PLAN.md lines 56-61).
    """
    buckets: dict[tuple[str, str, str], list[Exclusion]] = defaultdict(list)
    for excl in exclusions:
        if excl.quarantined:
            continue
        if not excl.finding.code_pattern.strip():
            continue
        key = (excl.agent, excl.finding.cwe, excl.finding.code_pattern)
        buckets[key].append(excl)

    # Sort with deterministic tie-break: primary by count desc, then by
    # (agent, cwe, pattern) ascending for stability across exclusion reorderings.
    ranked = sorted(
        (
            (key, group)
            for key, group in buckets.items()
            if len(group) >= _FP_REPORT_MIN_COUNT
        ),
        key=lambda item: (-len(item[1]), item[0]),
    )[:_FP_REPORT_TOP_N]

    patterns: list[FPPattern] = []
    for (agent, cwe, pattern), group in ranked:
        # Frequency-weighted reason selection: count occurrences, sort by
        # (count desc, reason asc) for deterministic tie-break, take top N.
        # Lexicographic-only selection would drop "test fixture" (95 occurrences)
        # in favor of "aborted" (5 occurrences) purely because "a" < "t".
        reason_counts: dict[str, int] = defaultdict(int)
        for e in group:
            reason_counts[e.reason] += 1
        ranked_reasons = sorted(
            reason_counts.items(),
            key=lambda kv: (-kv[1], kv[0]),
        )
        reasons = [r for r, _count in ranked_reasons[:_FP_REPORT_MAX_REASONS]]
        # T21-m1: pre-render each reason backtick-wrapped so the subagent can
        # surface it verbatim without applying its own Markdown-wrapping rule.
        # Same order as `reasons` for parallel indexing by consumers.
        reasons_rendered = [f"`{r}`" for r in reasons]

        # The suggestion text embeds the pattern as inline code so user-controlled
        # content doesn't inject into Markdown structure.
        # Include all (up to 5) example reasons in the prose so the human-readable
        # refinement string preserves the distribution, not just the top one.
        reasons_inline = ", ".join(f"'{r}'" for r in reasons) if reasons else "n/a"
        patterns.append(
            FPPattern(
                agent=agent,
                cwe=cwe,
                pattern=pattern,
                fp_count=len(group),
                example_reasons=reasons,
                example_reasons_rendered=reasons_rendered,
                candidate_heuristic_refinement=(
                    f"{agent} agent may benefit from lower confidence on pattern "
                    f"`{pattern}` (seen in {len(group)} exclusions with reasons: "
                    f"{reasons_inline})"
                ),
            )
        )

    return FPReport(
        generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        scope="project",
        top_fp_patterns=patterns,
    )
