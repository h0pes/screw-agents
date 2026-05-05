---
name: screw-adaptive-cleanup
description: >
  Use when the user asks to review, clean up, remove, reject, quarantine, or
  sweep screw-agents adaptive scripts and staged learning artifacts.
---

# screw-agents Adaptive Cleanup Skill

This skill is the Codex-supported entry point for the adaptive-cleanup workflow
described by `plugins/screw/commands/adaptive-cleanup.md`.

## Safety Rules

- Use only the `screw-agents` MCP server for adaptive state changes.
- List state before changing it.
- Require explicit user confirmation before removal, rejection, promotion, or
  sweeping.
- Never execute adaptive scripts from cleanup unless the user explicitly asks
  and the trust checks pass.

## MCP Tools

Use the relevant tools:

- `list_adaptive_scripts`
- `remove_adaptive_script`
- `reject_staged_script`
- `promote_staged_script`
- `sweep_stale_staging`
- `verify_trust`

## Output

Summarize:

- what was inspected;
- what changed;
- what remains active or quarantined;
- whether trust state is clean after the operation.
