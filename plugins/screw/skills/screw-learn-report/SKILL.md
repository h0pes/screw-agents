---
name: screw-learn-report
description: >
  Use when the user asks for screw-agents learning, trust, exclusion,
  false-positive, or adaptive-script reports.
---

# screw-agents Learning Report Skill

This skill is the Codex-supported entry point for the learning-report workflow
described by `plugins/screw/commands/learn-report.md`.

## What To Do

Use the `screw-agents` MCP server to inspect and summarize learning state. Do
not parse `.screw/` files directly unless an MCP tool response explicitly points
to a report file that needs to be read.

Prefer these MCP tools:

- `aggregate_learning`
- `verify_trust`
- `check_exclusions`
- `list_adaptive_scripts`

## Output

Report:

- active exclusions and quarantine counts;
- adaptive script active/quarantine counts;
- trust status;
- notable learning or false-positive trends;
- suggested next action when stale, quarantined, or inconsistent state exists.

Do not promote, reject, remove, or execute adaptive scripts from this skill.
