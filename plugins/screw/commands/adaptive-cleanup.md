---
name: screw:adaptive-cleanup
description: "List and remove adaptive analysis scripts in .screw/custom-scripts/. Shows per-script stale status, signing status, and findings-produced count. Usage: /screw:adaptive-cleanup [list|remove <script-name>]"
---

# /screw:adaptive-cleanup — Adaptive Script Cleanup

Inspect and clean up adaptive analysis scripts stored under
`.screw/custom-scripts/`. These are user-approved Python scripts generated
by the `--adaptive` flow (see `/screw:scan ... --adaptive`) — they persist
across scans and keep analyzing the same code patterns until retired.

Over time, some of these scripts become **stale** (the code patterns they
target no longer exist in the project), **unused** (never produced a
finding), or **experimental** (you approved them to test an idea and want
to remove them now). This command surfaces that state and helps you retire
scripts safely.

## Syntax

```
/screw:adaptive-cleanup [list|remove <script-name>]
```

## Arguments

**action** (optional, defaults to `list`):

- `list` — show every adaptive script with metadata + stale status.
- `remove <script-name>` — delete a script's `.py` + `.meta.yaml` pair
  (with confirmation).

## Default action: `list`

When invoked without args (or with `list`), enumerate `.screw/custom-scripts/`
via the backend:

```bash
uv run python -c "
from pathlib import Path
import json
from screw_agents.cli.adaptive_cleanup import list_adaptive_scripts
print(json.dumps(list_adaptive_scripts(Path('.').resolve()), indent=2))
"
```

Render each script in a compact block:

```
<name> — <description>
  created: <created> by <created_by>
  domain: <domain>
  signing: <✓ signed | ⚠ unsigned>   (from `validated`: True → signed)
  findings produced: <findings_produced>   last used: <last_used or "never">
  target patterns: <comma-separated list>
  <if stale:> ⚠ stale — <stale_reason>
```

If the listing contains ANY stale scripts, surface a discoverability prompt:

> Stale scripts found: `<name1>, <name2>`.
> Run `/screw:adaptive-cleanup remove <name>` to clean them up.

## Remove action: `remove <script-name>`

Deletion is **destructive** — the `.py` and `.meta.yaml` files are unlinked
from disk. Historical `.screw/findings/` and `.screw/learning/` artifacts
produced by the script survive (they're audit records, not live state).

### Confirmation gate (MANDATORY)

Before calling the backend, you MUST prompt the user:

> About to delete `.screw/custom-scripts/<name>.py` + `<name>.meta.yaml`.
> Confirm with `yes` or `cancel`.

- If the user responds with anything other than `yes` (case-insensitive),
  treat as cancel and report "Removal cancelled by user."
- Only after explicit `yes` do you invoke the backend:

```bash
uv run python -c "
from pathlib import Path
import json
from screw_agents.cli.adaptive_cleanup import remove_adaptive_script
print(json.dumps(remove_adaptive_script(Path('.').resolve(), script_name='<name>'), indent=2))
"
```

Show the returned `status`, `message`, and `removed_files` to the user.

### Backend return statuses

| Status | Meaning |
|---|---|
| `removed` | Both `.py` and `.meta.yaml` existed and were deleted. |
| `not_found` | Neither file existed. |
| `partial` | Only one of the pair existed; the present file was deleted and the recovery is complete. |
| `error` | A filesystem error prevented deletion; the message explains. |

## Stale-detection semantic

A script is **stale** when NONE of its declared `target_patterns` have
matching call sites in the current project AST. This matches the executor's
`_is_stale` semantic in `src/screw_agents/adaptive/executor.py` exactly
(same `find_calls` helper, same semantics) so staleness here aligns with
what would happen if you tried to run the script via `--adaptive`.

Edge cases:

- `target_patterns: []` → NOT flagged as stale (we can't judge without
  patterns). `stale_reason` becomes `"no target_patterns declared"` —
  surfaced informationally, not as a ⚠ warning.
- Any `target_pattern` has at least one matching call site → NOT stale.
- ALL `target_patterns` have zero call sites → stale; `stale_reason`
  names the dead patterns.

Stale scripts still pass Layer 3 signature verification (they're
cryptographically intact; they just have no code left to analyze). This
command is the safe way to retire them.

## Examples

```
/screw:adaptive-cleanup
/screw:adaptive-cleanup list
/screw:adaptive-cleanup remove qb-check
```

## Notes

- This command is on-demand. Listing walks the project AST once per
  script (O(project_files × patterns)) — acceptable for interactive
  cleanup, but NOT cheap enough to call on every scan. If you need
  scan-time stale filtering, the executor already handles that via
  `_is_stale` during `execute_script`.
- The subagent does NOT need to do anything beyond parsing `<action>`
  and `<script-name>`, running the backend shell calls above, and
  rendering output. No MCP tools are required for this command.
