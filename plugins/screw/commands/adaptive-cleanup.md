---
name: screw:adaptive-cleanup
description: "Inspect and clean up adaptive analysis scripts. Usage: /screw:adaptive-cleanup [list|remove <name>|stale [--max-age-days N] [--preview]]"
---

# /screw:adaptive-cleanup — Adaptive Script Cleanup

Inspect and clean up adaptive analysis scripts stored under
`.screw/custom-scripts/` **and** orphaned staging directories under
`.screw/staging/`. The two storage locations have independent lifecycles
and the word "stale" means different things in each:

- **Per-script stale** (surfaced by `list`) — a signed script under
  `.screw/custom-scripts/` whose `target_patterns` no longer match any
  call sites in the project AST. The script is cryptographically intact;
  its target code is gone. Retire it with `remove`.
- **Orphan-staging stale** (swept by `stale`) — an unpromoted and
  unrejected staging directory under `.screw/staging/{session_id}/`
  older than the configured threshold (default 14 days). Residue from a
  review cycle the user walked away from. Nothing was ever signed.

## Syntax

```
/screw:adaptive-cleanup [list|remove <script-name>|stale [--max-age-days N] [--preview]]
```

## Default action: `list` — show all adaptive scripts

When invoked without args (or with `list`), call:

```
mcp__screw-agents__list_adaptive_scripts({
  "project_root": "<absolute path to current project root>"
})
```

Render each entry in the returned `scripts` array as a compact block
(one block per script, matching the existing UX):

```
<name> — <description>
  created: <created> by <created_by>
  domain: <domain>
  signing: <✓ signed | ⚠ unsigned>   (from `validated`: True → signed)
  findings produced: <findings_produced>   last used: <last_used or "never">
  target patterns: <comma-separated list>
  <if stale:> ⚠ stale — <stale_reason>
```

If `scripts` is empty, render: "No adaptive scripts present in
`.screw/custom-scripts/`."

If the listing contains ANY stale scripts, surface a discoverability prompt:

> Stale scripts found: `<name1>, <name2>`.
> Run `/screw:adaptive-cleanup remove <name>` to retire them.

### List action — per-script stale detection (AST pattern-based)

A script is **stale** when NONE of its declared `target_patterns` have
matching call sites in the current project AST. This matches the
executor's `_check_stale` semantic in
`src/screw_agents/adaptive/executor.py` exactly (same `find_calls`
helper, same semantics) so staleness here aligns with what would happen
if you tried to run the script via `--adaptive`.

Edge cases:

- `target_patterns: []` → NOT flagged as stale (we can't judge without
  patterns). `stale_reason` becomes `"no target_patterns declared"` —
  surfaced informationally, not as a ⚠ warning.
- Any `target_pattern` has at least one matching call site → NOT stale.
- ALL `target_patterns` have zero call sites → stale; `stale_reason`
  names the dead patterns.

Stale scripts still pass Layer 3 signature verification (they're
cryptographically intact; they just have no code left to analyze).
`remove` is the safe way to retire them.

## Remove action: `remove <script-name>`

Deletion is **destructive** — the `.py` and `.meta.yaml` files are
unlinked from disk. Historical `.screw/findings/` and
`.screw/learning/` artifacts produced by the script survive (they're
audit records, not live state).

### Confirmation gate (MANDATORY)

Before calling the backend, you MUST prompt the user:

> About to delete `.screw/custom-scripts/<name>.py` +
> `<name>.meta.yaml`. Confirm with `yes` or `cancel`.

- If the user responds with anything other than `yes`
  (case-insensitive), treat as cancel and report
  "Removal cancelled by user."
- Only after explicit `yes` do you invoke the backend:

```
mcp__screw-agents__remove_adaptive_script({
  "project_root": "<absolute path>",
  "script_name": "<name>",
  "confirmed": true
})
```

Show the returned `status`, `script_name`, and (on error) `message`
to the user.

### Backend return statuses

| Status | Meaning |
|---|---|
| `removed` | Both `.py` and `.meta.yaml` existed and were deleted (or at least one of the pair existed and its present companion was cleaned up). |
| `error` + `confirmation_required` | Slash command bug — `confirmed=true` was not sent. User must re-invoke. |
| `error` + `not_found` | Neither file existed. |
| `error` + `delete_failed` | A filesystem error prevented deletion; `message` explains. |

## Stale-sweep action: `stale [--max-age-days N] [--preview]`

Sweeps orphaned staging directories under `.screw/staging/`. These
accumulate when a reviewer starts an adaptive cycle, a script is staged
via `stage_adaptive_script`, but the reviewer neither approves nor
rejects it before walking away (or the process crashes). The
staging directory sits there indefinitely unless cleaned up.

### Arguments

- `--max-age-days N` (optional): override the threshold in days.
  Omitted → the backend reads `staging_max_age_days` from
  `.screw/config.yaml` (default `14` when the config key is absent).
  Clamped to `[1, 365]` server-side.
- `--preview` (optional): dry-run. Report what would be removed
  without touching the filesystem and without appending `swept`
  audit events to the registry.

### Call

```
mcp__screw-agents__sweep_stale_staging({
  "project_root": "<absolute path>",
  "max_age_days": <N if --max-age-days N provided; else omit (engine falls back to config)>,
  "dry_run": <true if --preview provided; else false>
})
```

### Response shape + rendering

The tool returns:

- `status`: `"ok"` on success; error otherwise.
- `max_age_days`: the effective threshold used (post-clamp, post-fallback).
- `dry_run`: echoes the request flag.
- `sessions_scanned`: count of session directories examined.
- `sessions_removed`: count of session directories removed (0 on dry-run).
- `scripts_removed`: list of `{session_id, script_name, age_days, reason}`.
- `tampered_preserved`: list of `{session_id, script_name, evidence_path}` —
  staging dirs where sha256-mismatch was detected and the dir was KEPT
  for forensic review (never swept even when old).

Render as:

```
Swept .screw/staging/ at threshold <max_age_days> days
  <if dry_run:> (--preview: no filesystem changes made)

  sessions scanned: <sessions_scanned>
  sessions removed: <sessions_removed>
  scripts removed:
    - <session_id>/<script_name> — <reason> (age <age_days>d)
    ... (one line per entry)
  tampered (preserved for review):
    - <session_id>/<script_name> — evidence at <evidence_path>
    ... (one line per entry; section omitted if list is empty)
```

### Security note

The `tampered_preserved` list is never empty silently — when it has
entries, flag it prominently in the output (e.g., a ⚠ warning line
above the block). A tampered staging directory means someone wrote to
`.screw/staging/` after `stage_adaptive_script` produced the sha256;
that is a tamper signal, not noise. Do NOT offer to re-sweep with a
shorter threshold or otherwise suggest the operator bypass the
preservation.

## Examples

```
/screw:adaptive-cleanup
/screw:adaptive-cleanup list
/screw:adaptive-cleanup remove qb-check
/screw:adaptive-cleanup stale
/screw:adaptive-cleanup stale --preview
/screw:adaptive-cleanup stale --max-age-days 30
/screw:adaptive-cleanup stale --max-age-days 7 --preview
```

## Notes

- This command is on-demand. `list` walks the project AST once per
  script (O(project_files × patterns)) — acceptable for interactive
  cleanup, but NOT cheap enough to call on every scan. If you need
  scan-time stale filtering, the executor already handles that via
  `_check_stale` during `execute_script`.
- The three MCP tools (`list_adaptive_scripts`, `remove_adaptive_script`,
  `sweep_stale_staging`) are registered at `src/screw_agents/server.py`
  lines 188-209 and dispatched to engine methods at
  `src/screw_agents/engine.py` lines 1061-1436. This slash command is
  the only consumer of `sweep_stale_staging` in the plugin today; the
  other two tools are also consumed by future tooling.
