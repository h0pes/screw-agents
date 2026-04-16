"""Learning aggregation — cross-scan pattern reports from the exclusions database.

Phase 3a ships Features 1, 2, 4 from PRD §11.2 layer 3. Feature 3 (high-value
target suggestions) is deferred to Phase 6 because it requires a new data source
(confirmed findings, not just rejections).

All three features share the same data pipeline — they're different projections
of the same signed exclusions database.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Literal

from screw_agents.models import (
    DirectorySuggestion,
    Exclusion,
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

    Groups by (agent, top_dir) where top_dir is the first path component of
    finding.file plus a trailing slash. Only trusted (non-quarantined) exclusions
    with a non-empty file path are considered. Buckets meeting _DIR_MIN_COUNT
    produce a suggestion.
    """
    buckets: dict[tuple[str, str], list[Exclusion]] = defaultdict(list)
    for excl in exclusions:
        if excl.quarantined:
            continue
        # Skip exclusions with no identifiable file path — these are schema-
        # evolution artifacts or test fixtures and must not synthesize a bogus
        # directory suggestion.
        if not excl.finding.file.strip():
            continue
        top_dir = excl.finding.file.split("/", 1)[0] + "/"
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

        suggestions.append(
            DirectorySuggestion(
                directory=directory,
                agent=agent,
                evidence={
                    "total_findings_in_directory": len(group),
                    "all_marked_false_positive": True,
                    "reason_distribution": dict(reason_counts),
                    "files_affected": sorted({e.finding.file for e in group}),
                },
                suggestion=(
                    f"Add directory-scope exclusion for `{directory}**` "
                    f"(top reason: '{max(reason_counts, key=reason_counts.get)}')."
                ),
                confidence=confidence,
            )
        )
    return suggestions
