---
name: screw:learn-report
description: "Surface cross-scan learning insights from .screw/learning/exclusions.yaml — pattern-confidence suggestions, directory-scope exclusion candidates, and a false-positive report for future agent tuning."
---

# /screw:learn-report

Delegate to the `screw-learning-analyst` subagent:

"Present the learning report for this project by calling `aggregate_learning` on the current project root. Show pattern-confidence suggestions, directory-scope exclusion candidates, and the false-positive report. Offer to act on any actionable suggestions by calling `record_exclusion` (with confirmation)."

## Notes

- This command is on-demand only. It does NOT run automatically after scans because learning insights are about *meta-patterns across history* — a different concern from per-scan findings — and computing them on every scan would waste cycles on stable data.
- The subagent will lead its response with a trust-notice block if any exclusions are quarantined. This is mandatory and not configurable — quarantined entries are silently skipped from the report computation, so the notice is the only way you'll know.
- The report is computed from signed exclusions only. Quarantined entries are excluded; run `screw-agents validate-exclusion <id>` to re-validate them.
- The subagent resolves the project root by walking up to the nearest `.git/` directory. If your current working directory is ambiguous, specify the project root explicitly.
- If there are fewer than 3 exclusions matching a pattern or directory, no suggestion is produced — the thresholds are conservative to avoid noise.
