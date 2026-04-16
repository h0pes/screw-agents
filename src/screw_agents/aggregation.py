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
