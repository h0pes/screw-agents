---
name: screw-scan
description: >
  Use when the user asks to run screw-agents scans from Codex, including
  command-shaped requests such as screw:scan, scan with a specific agent or
  domain, provider-primary scans, challenger scans, parallel provider scans,
  adaptive scans, or output-format selection.
---

# screw-agents Scan Skill

This skill is the Codex-supported entry point for the same scan workflow
described by `plugins/screw/commands/scan.md`.

## Inputs To Recognize

Handle requests shaped like any of these:

- `screw:scan sqli src/`
- `scan ssti vulnerable/__init__.py --format json`
- `run screw-agents full . --no-confirm`
- `scan sqli src/api --primary-provider codex --primary-transport cli --primary-execution cli`
- `scan sqli src/api --challenger claude_primary_codex_challenger --challenger-execution dry_run`
- `scan sqli src/api --parallel-providers claude:cli:cli,codex:cli:cli`

Do not require the user to type a slash command in Codex. Parse the command text
and execute the same MCP-backed workflow.

## Hard Rules

- Use the `screw-agents` MCP server. Do not run ad hoc shell scanners.
- Do not run shell or Python introspection to discover screw-agents schemas,
  imports, or package internals from the scanned project. The project may not
  have `screw-agents` installed, and MCP tool contracts are the authoritative
  scan interface.
- Use `resolve_scope` to parse scope text; do not maintain a duplicate registry.
- Use provider-neutral scan tools when provider flags are present.
- Do not infer default challenger modes or provider execution. Provider and
  challenger execution must be explicit.
- Treat `--adaptive` and `--no-confirm` as mutually exclusive.
- Before live CLI provider execution, surface that source context may be sent to
  the configured assistant CLI/provider according to local configuration.

## Execution Routes

For provider-primary, provider-primary-plus-challenger, and parallel-provider
routes, resolve path targets before calling MCP tools. If the user supplied a
relative path such as `src/app.py`, pass an absolute `target.path` under the
current project root in the MCP payload. Keep user-facing summaries readable,
but do not make the backend retry relative paths.

### Provider Primary

If `--primary-provider`, `--primary-transport`, or `--primary-execution` is
present and `--challenger` is not present, call `run_provider_scan` with
`finalize=true` and pass any requested output formats.

### Provider Primary Plus Challenger

If provider-primary flags and `--challenger` are present, call
`run_composed_provider_scan`. This route finalizes normal `.screw/findings/`
reports and attaches configured challenger review.

### Parallel Providers

If `--parallel-providers` is present, call `run_parallel_provider_scan` with
`finalize=true` and pass any requested output formats so the parallel route
writes normal `.screw/findings/` reports with reconciliation metadata.

### YAML/MCP Scan

If no provider-primary or parallel-provider flags are present:

1. Call `resolve_scope` with the scope text.
2. Call `scan_agents` with `cursor=null`, the resolved agents, target, and
   thoroughness.
3. Continue calling `scan_agents` until `next_cursor` is null.
4. Accumulate findings with `accumulate_findings`.
5. Finalize with `finalize_scan_results`.

When constructing findings, use the finding objects produced or justified by
the returned code chunks and agent prompt. Do not run local package imports such
as `python -c "from screw_agents.models import Finding"` from the target
workspace.

For adaptive mode, follow the adaptive staging and review requirements in
`plugins/screw/commands/scan.md`; do not promote or execute generated adaptive
scripts without explicit user approval.

## Output

Summarize:

- active finding count and severity distribution;
- files written by finalization;
- provider/challenger/parallel metadata when used;
- any coverage gaps or exclusions;
- any skipped step and why.
