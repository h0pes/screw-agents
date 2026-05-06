# Command Reference

This document lists the user-facing commands, MCP tools, benchmark scripts, and
common development commands currently available in `screw-agents`.

For architecture and roadmap context, start with the top-level
[README.md](../README.md).

## Package CLI

Run commands through `uv` during development:

```bash
uv run screw-agents <command> [options]
```

### `screw-agents serve`

Run the MCP server.

```bash
uv run screw-agents serve [--transport stdio|http] [--host 127.0.0.1] [--port 8080] [--domains-dir PATH] [--log-level LEVEL]
```

Options:

| Option | Values | Default | Description |
|---|---|---:|---|
| `--transport` | `stdio`, `http` | `stdio` | MCP transport protocol |
| `--host` | host/IP | `127.0.0.1` | HTTP bind host; use `0.0.0.0` only for intentional network exposure |
| `--port` | integer | `8080` | HTTP port when `--transport http` is used |
| `--domains-dir` | path | auto-detect | Alternate agent YAML domains directory |
| `--log-level` | `DEBUG`, `INFO`, `WARNING`, `ERROR` | `INFO` | Server logging level |

Examples:

```bash
uv run screw-agents serve --transport stdio
uv run screw-agents serve --transport http --port 8080
uv run screw-agents serve --transport http --host 0.0.0.0 --port 8080
```

### `screw-agents challenger-dry-run`

Run one configured Phase 5 challenger mode with fixture transports only and
print the structured result JSON. This command is intentionally non-live: it
refuses CLI, API, or local transports so users can validate mode wiring and
output shape without invoking external assistants or spending API credits.

```bash
uv run screw-agents challenger-dry-run MODE --finding-json FINDING_JSON [--project-root PATH] [--prompt TEXT] [--target-path PATH] [--run-id ID] [--session-id ID]
```

Options:

| Argument/Option | Required | Default | Description |
|---|---|---:|---|
| `MODE` | yes | n/a | Configured challenger mode name |
| `--finding-json` | yes | n/a | Finding object JSON used as dry-run input |
| `--project-root` | no | `.` | Project root containing `.screw/config.yaml` |
| `--prompt` | no | `Phase 5 challenger dry-run.` | Prompt text passed to fixture runners |
| `--target-path` | no | `.` | Target path recorded in dry-run metadata |
| `--run-id` | no | `dry-run-001` | Run identifier recorded in output |
| `--session-id` | no | `dry-run-session` | Session identifier recorded in output |

Example:

```bash
uv run screw-agents challenger-dry-run claude_primary_codex_challenger \
  --finding-json '{"id":"sqli-001","agent":"sqli","location":{"file":"src/app.py","line_start":42},"classification":{"cwe":"CWE-89","severity":"high"}}'
```

### `screw-agents challenger-run`

Run one configured Phase 5 challenger mode through live CLI transports and
print the structured result JSON. This command is opt-in and only supports
enabled `cli` transports. Fixture modes must use `challenger-dry-run`; API and
local transports are rejected until their adapters are implemented.

Configured Claude and Codex CLI runners remove `ANTHROPIC_API_KEY` and
`OPENAI_API_KEY`, respectively, before invocation so subscription-backed CLI
use does not accidentally switch to API-key billing.
CLI challenger prompts include the supplied findings payload as authoritative
JSON context. In primary/challenger modes, only participants with
`role: challenger` are invoked during this review step; the primary provider is
recorded as provenance, not re-run as a reviewer.

```bash
uv run screw-agents challenger-run MODE --finding-json FINDING_JSON [--project-root PATH] [--prompt TEXT] [--target-path PATH] [--run-id ID] [--session-id ID] [--timeout-seconds N]
```

Options:

| Argument/Option | Required | Default | Description |
|---|---|---:|---|
| `MODE` | yes | n/a | Configured challenger mode name |
| `--finding-json` | yes | n/a | Finding object JSON used as run input |
| `--project-root` | no | `.` | Project root containing `.screw/config.yaml` |
| `--prompt` | no | `Phase 5 challenger CLI run.` | Prompt text passed to CLI runners |
| `--target-path` | no | `.` | Target path recorded in run metadata |
| `--run-id` | no | `run-001` | Run identifier recorded in output |
| `--session-id` | no | `run-session` | Session identifier recorded in output |
| `--timeout-seconds` | no | `120` | Per-provider CLI timeout in seconds |

Example:

```bash
uv run screw-agents challenger-run claude_primary_codex_challenger \
  --finding-json '{"id":"sqli-001","agent":"sqli","location":{"file":"src/app.py","line_start":42},"classification":{"cwe":"CWE-89","severity":"high"}}' \
  --prompt "Review this finding and return challenger assessment JSON."
```

### `screw-agents provider-scan`

Run one provider-neutral primary scan through fixture or opt-in CLI execution
and print the structured `PrimaryScanResult` JSON. This command assembles
selected YAML agent knowledge, resolves the target, sends a structured
`PrimaryScanInput` to the selected runner, and validates returned findings with
the shared `Finding` schema.

API and local transports are rejected until adapters exist. Claude and Codex
CLI runners remove `ANTHROPIC_API_KEY` and `OPENAI_API_KEY`, respectively, for
subscription-backed CLI use.

Configured CLI transports may set execution-specific command overrides:
`primary_command` is used for provider-neutral first-pass scanning, while
`challenger_command` is used for challenger review. The fallback `command` is
used when no execution-specific override is present. This is useful when the
same assistant CLI needs different structured-output schemas for finding
generation and finding review.

```bash
uv run screw-agents provider-scan --provider PROVIDER --transport TRANSPORT --execution fixture|cli --agents AGENTS_CSV --target-json TARGET_JSON [--project-root PATH] [--run-id ID] [--session-id ID] [--thoroughness quick|standard|deep] [--timeout-seconds N] [--fixture-findings-json FINDINGS_JSON] [--finalize] [--format json|markdown|csv|sarif]
```

Options:

| Option | Required | Default | Description |
|---|---|---:|---|
| `--provider` | yes | n/a | Configured provider name, e.g. `codex` |
| `--transport` | yes | n/a | Configured transport name, e.g. `cli` or `fixture` |
| `--execution` | yes | n/a | `fixture` or opt-in live `cli` |
| `--agents` | yes | n/a | Comma-separated registered agent names |
| `--target-json` | yes | n/a | Target spec JSON object |
| `--project-root` | no | `.` | Project root containing `.screw/config.yaml` |
| `--run-id` | no | `provider-scan-001` | Run identifier recorded in output |
| `--session-id` | no | `provider-scan-session` | Session identifier recorded in output |
| `--thoroughness` | no | `standard` | Prompt depth |
| `--timeout-seconds` | no | `120` | Per-provider CLI timeout |
| `--fixture-findings-json` | no | none | Fixture finding array for `--execution fixture` |
| `--finalize` | no | false | Accumulate returned findings and write normal `.screw/findings/` reports |
| `--format` | no | JSON + Markdown + CSV | Output format used with `--finalize`; repeat for multiple formats |

Example:

```bash
uv run screw-agents provider-scan \
  --provider codex \
  --transport fixture \
  --execution fixture \
  --agents sqli \
  --target-json '{"type":"file","path":"src/app.py"}' \
  --fixture-findings-json '[]'
```

With `--finalize`, output changes from a raw `PrimaryScanResult` to an object
containing `primary_scan_result`, `accumulate_result`, and `finalize_result`.

### `screw-agents init-trust`

Register the local SSH key as a trusted reviewer for a project.

```bash
uv run screw-agents init-trust --name NAME --email EMAIL [--project-root PATH]
```

Options:

| Option | Required | Default | Description |
|---|---|---:|---|
| `--name` | yes | n/a | Reviewer display name |
| `--email` | yes | n/a | Reviewer email |
| `--project-root` | no | `.` | Project root containing `.screw/` state |

### `screw-agents migrate-exclusions`

Sign legacy unsigned false-positive exclusions.

```bash
uv run screw-agents migrate-exclusions [--project-root PATH] [--yes]
```

Options:

| Option | Default | Description |
|---|---:|---|
| `--project-root` | `.` | Project root |
| `--yes` | false | Skip per-entry confirmation |

### `screw-agents validate-exclusion`

Re-sign one quarantined exclusion after manual review.

```bash
uv run screw-agents validate-exclusion EXCLUSION_ID [--project-root PATH]
```

Options:

| Argument/Option | Required | Default | Description |
|---|---|---:|---|
| `EXCLUSION_ID` | yes | n/a | Exclusion ID to validate |
| `--project-root` | no | `.` | Project root |

### `screw-agents validate-script`

Re-sign one quarantined adaptive script after manual review.

```bash
uv run screw-agents validate-script SCRIPT_NAME [--project-root PATH]
```

Options:

| Argument/Option | Required | Default | Description |
|---|---|---:|---|
| `SCRIPT_NAME` | yes | n/a | Script name without `.py` suffix |
| `--project-root` | no | `.` | Project root |

## Assistant Plugin Commands

These command names, agent roles, skills, and tool workflows are the
assistant-facing command contract for `screw-agents`. The shared plugin
implementation lives under `plugins/screw/` and carries both Claude Code and
Codex metadata, but each host has different UX primitives. The semantics are
intended to stay portable across Claude Code, Codex, Gemini, local assistants,
editor integrations, web workers, or future plugin hosts that can call the same
MCP/backend tools. This portability applies to all scan, learning, adaptive,
trust/exclusion, challenger/provider, and future workflows: equivalent inputs,
options, and result shapes should exist wherever the host can support them.

### Host Surface Map

The names are intentionally similar but not interchangeable:

| Surface | Host | Path | User-visible form | Purpose |
|---|---|---|---|---|
| Slash commands | Claude-compatible plugin hosts | `plugins/screw/commands/` | `/screw:scan`, `/screw:learn-report`, `/screw:adaptive-cleanup` | Explicit user commands |
| Claude skills | Claude-compatible plugin hosts | `plugins/screw/skills/` | `screw-review`, `screw-research`; Claude may show these as `/screw-review`, `/screw-research` in autocomplete | Auto-invocation helpers for review/research intents |
| Claude agents/subagents | Claude-compatible plugin hosts | `plugins/screw/agents/` | `screw-scan`, `screw-script-reviewer`, `screw-learning-analyst` | Internal worker roles dispatched by commands/skills |
| Codex skills | Codex plugin hosts | `plugins/screw/codex-skills/` | `screw:screw-scan`, `screw:screw-learn-report`, `screw:screw-adaptive-cleanup`, `screw:screw-review`, `screw:screw-research` | Codex-supported reusable workflows |
| MCP tools | Any MCP-capable host | Python server | `scan_agents`, `run_provider_scan`, `finalize_scan_results`, etc. | Shared backend operations |
| Package CLI | Any shell/CI | `screw-agents ...` | `screw-agents provider-scan`, `screw-agents challenger-run`, etc. | Scriptable backend entry points |

`/screw:scan` and `screw-scan` are different things. `/screw:scan` is the
Claude user-facing slash command. `screw-scan` is the internal Claude
agent/subagent that the command can dispatch for normal YAML/MCP scans. Codex
also has a `screw:screw-scan` skill that implements the same scan workflow
through Codex's supported skill mechanism.

Codex-only scan, learning-report, and adaptive-cleanup workflow skills live
under `codex-skills/` instead of Claude's top-level `skills/` directory so
Claude does not show duplicate slash completions such as `/screw-scan` beside
`/screw:scan`. Claude's historical `screw-review` and `screw-research` skills
remain in `plugins/screw/skills/`.

Load the plugin locally in Claude Code:

```bash
claude --plugin-dir ./plugins/screw
```

Register the repo-local Codex marketplace entry and MCP server:

```bash
codex plugin marketplace add /path/to/screw-agents
codex mcp add screw-agents -- uv run --directory /path/to/screw-agents screw-agents serve --transport stdio
```

Use `codex mcp list` and `codex mcp get screw-agents` to verify the backend
registration. Run the `codex mcp add` command from a screw-agents checkout or
worktree during local development; current Codex CLI versions may fail to load
configuration when run from an arbitrary `/tmp` project. Current Codex releases
use skills, not custom prompts, for reusable workflows; the repo-local plugin
packages Codex skills for scan, learning-report, adaptive-cleanup, review, and
research workflows. Those skills use the same MCP tools and command grammar as
the slash-command files.
After adding the marketplace, open `/plugins` in Codex and enable the
`screw-agents` plugin so Codex loads the packaged skills and MCP server config.

### Which Surface Should I Use?

Use the highest-level surface your host supports:

| You are... | Use this | Why |
|---|---|---|
| In Claude Code and you want to scan | `/screw:scan` | User-facing command that orchestrates scope parsing, MCP calls, subagent dispatch, finalization, adaptive mode, provider-primary mode, challenger mode, and parallel mode |
| In Claude Code and you want learning summaries | `/screw:learn-report` | User-facing command for false-positive learning/exclusion insights |
| In Claude Code and you want to inspect/remove adaptive artifacts | `/screw:adaptive-cleanup` | User-facing command for adaptive script/staging hygiene |
| In Claude Code and you ask generally for a security review | `screw-review` skill, usually auto-invoked | Intent router that decides whether to dispatch scan workflows or explain available agents |
| In Claude Code and you are authoring/researching new agent knowledge | `screw-research` skill, usually auto-invoked | Guides the research -> synthesize -> validate process for YAML agent definitions |
| In Codex and you want any screw-agents workflow | Codex skills, e.g. `screw:screw-scan` or command-shaped text such as `screw:scan ssti src/` | Codex currently supports reusable workflows through skills rather than Claude-style custom slash commands |
| In CI, scripts, or a shell | `screw-agents ...` package CLI | Stable scriptable entry points without assistant UX |
| You are building another client or web app | MCP tools | Lowest-level integration boundary for orchestration, background workers, or custom UIs |
| You are inside Claude internals/skill prompt authoring | Claude agents/subagents such as `screw-scan` | Worker roles dispatched by commands/skills; users normally do not invoke these directly |

### Claude Agents/Subagents

Claude agents/subagents are specialized worker prompts packaged under
`plugins/screw/agents/`. They exist because a single user-facing command often
needs delegated work with a narrower role and tool set. For example,
`/screw:scan` is a main-session orchestrator: it parses flags, resolves scope,
handles provider routes, controls adaptive review, and finalizes reports. For
normal YAML/MCP scans, it can dispatch the `screw-scan` agent/subagent to walk
paginated `scan_agents` results, fetch agent prompts, analyze code chunks, and
accumulate findings. The user should choose `/screw:scan`; the command chooses
when to use `screw-scan`.

Current Claude agents/subagents:

| Agent/subagent | Invoked by | Use case |
|---|---|---|
| `screw-scan` | `/screw:scan` and `screw-review` | Internal scan worker for normal YAML/MCP scans; not the same as `/screw:scan` |
| `screw-script-reviewer` | `/screw:scan --adaptive` | Reviews proposed adaptive analysis scripts before promotion/execution |
| `screw-learning-analyst` | `/screw:learn-report` | Analyzes project learning/exclusion evidence for reporting |

### Claude Skills

Claude skills are auto-invocation helpers. They are useful when the user asks
in natural language rather than typing a slash command. Claude may also expose
installed skills in slash autocomplete as `/screw-review` and
`/screw-research`; those are skill entry points, not the same class of
workflow as the explicit `/screw:*` command files.

| Skill | Use case | Prefer instead |
|---|---|---|
| `screw-review` | User asks for a security review, vulnerability scan, audit, SQLi/XSS/CmdI/SSTI check, or broad secure-code review | Use `/screw:scan` directly when you already know the exact scope/flags |
| `screw-research` | User is researching or authoring new vulnerability agent knowledge | Use package/docs workflows directly when doing scripted benchmark or registry work |

### Codex Skills

Codex skills are the Codex-host equivalent of reusable workflows. They live
under `plugins/screw/codex-skills/` and route to the same MCP backend.

| Codex skill | Use case | Equivalent Claude/user command |
|---|---|---|
| `screw:screw-scan` | Run command-shaped scan requests, provider-primary scans, challenger scans, parallel scans, adaptive scans, and output-format selection | `/screw:scan` |
| `screw:screw-learn-report` | Summarize false-positive learning and exclusions | `/screw:learn-report` |
| `screw:screw-adaptive-cleanup` | Inspect/remove adaptive scripts and staging artifacts | `/screw:adaptive-cleanup` |
| `screw:screw-review` | Natural-language security review routing | Claude `screw-review` skill |
| `screw:screw-research` | Vulnerability-agent research and authoring workflow | Claude `screw-research` skill |

### MCP Tools Versus Commands

MCP tools are lower-level operations. Assistant commands and skills call them
for you. Use MCP tools directly when building another integration, debugging a
route, writing tests, or needing precise orchestration. Prefer assistant
commands/skills for normal interactive use because they handle validation,
target normalization, finalization, trust summaries, and user-facing reporting.

### `/screw:scan`

Run security review with one or more agents.

```text
/screw:scan <scope-spec> [target] [--adaptive | --no-confirm] [--thoroughness standard|deep] [--format json|sarif|markdown|csv] [--primary-provider PROVIDER --primary-transport TRANSPORT --primary-execution fixture|cli] [--parallel-providers provider:transport:execution,...] [--challenger MODE --challenger-execution dry_run|cli]
```

Scope forms:

| Form | Example | Meaning |
|---|---|---|
| Agent bare token | `/screw:scan sqli src/` | Run one agent |
| Domain bare token | `/screw:scan injection-input-handling src/` | Run all agents in one domain |
| Full keyword | `/screw:scan full .` | Run all registered agents after relevance filtering |
| Agents prefix | `/screw:scan agents:sqli,xss src/` | Run explicit agent list |
| Domains prefix | `/screw:scan domains:injection-input-handling src/` | Run one or more domains |
| Mixed prefix | `/screw:scan domains:foo agents:bar src/` | Run selected agents within selected domains |

Options:

| Option | Values | Default | Description |
|---|---|---:|---|
| `--adaptive` | flag | false | Enable interactive adaptive-analysis flow |
| `--no-confirm` | flag | false | Skip pre-execution confirmation for CI/non-interactive use |
| `--thoroughness` | `standard`, `deep` | `standard` | Scan depth passed to agent prompts |
| `--format` | `json`, `markdown`, `csv`, `sarif` | JSON + Markdown + CSV | Restrict output to one format |
| `--primary-provider` | configured provider name | disabled | Explicitly choose a provider-neutral first-pass scanner |
| `--primary-transport` | configured transport name | n/a | Required with `--primary-provider` |
| `--primary-execution` | `fixture`, `cli` | n/a | Required with `--primary-provider`; selects fixture dry-run or opt-in live CLI primary execution |
| `--parallel-providers` | `provider:transport:execution,...` | disabled | Run two or more independent provider-neutral primary scans and reconcile results |
| `--challenger` | configured mode name | disabled | Explicitly attach Phase 5 challenger review during finalization |
| `--challenger-execution` | `dry_run`, `cli` | n/a | Required with `--challenger`; selects fixture dry-run or opt-in live CLI execution |
| `--help` | flag | n/a | Print command help without scanning |

`--adaptive` and `--no-confirm` are mutually exclusive.
`--primary-provider`, `--primary-transport`, and `--primary-execution` must be
supplied together. Primary-provider mode is currently mutually exclusive with
`--adaptive`; it routes through provider scan tools rather than the legacy
subagent scan path.
`--parallel-providers` is mutually exclusive with primary-provider flags,
challenger flags, and `--adaptive`.
`--challenger` and `--challenger-execution` must be supplied together. The
slash command does not infer a default challenger mode, does not default to
live CLI execution, and does not expose API/local challenger transports.
Provider-primary execution likewise does not infer a default provider or
transport, and does not expose API/local primary transports until adapters
exist.

Target forms include paths, globs, git diffs, commit ranges, pull requests,
classes, functions, and line ranges as supported by the MCP target resolver.

Examples:

```text
/screw:scan sqli src/api/
/screw:scan injection-input-handling src/
/screw:scan full . --no-confirm
/screw:scan agents:sqli,xss src/api/ --format sarif
/screw:scan sqli src/api/ --adaptive
/screw:scan sqli src/api/ --primary-provider codex --primary-transport cli --primary-execution cli
/screw:scan sqli src/api/ --challenger claude_primary_codex_challenger --challenger-execution dry_run
/screw:scan sqli src/api/ --primary-provider codex --primary-transport cli --primary-execution cli --challenger codex_primary_claude_challenger --challenger-execution cli
/screw:scan sqli src/api/ --parallel-providers claude:cli:cli,codex:cli:cli
```

### `/screw:learn-report`

Produce a learning aggregation report from project exclusions.

The command uses the `aggregate_learning` MCP tool and summarizes patterns,
directory suggestions, and false-positive clusters that may inform future
agent refinement.

### `/screw:adaptive-cleanup`

Inspect and clean adaptive analysis scripts.

The command uses adaptive script MCP tools such as `list_adaptive_scripts` and
`remove_adaptive_script`.

## MCP Tools

The MCP server exposes these tools to clients.

### Discovery

| Tool | Purpose | Key inputs |
|---|---|---|
| `list_domains` | List vulnerability domains and agent counts | none |
| `list_agents` | List registered agents, optionally by domain | `domain?` |
| `get_agent_prompt` | Fetch one agent prompt lazily | `agent_name`, `thoroughness?` |
| `resolve_scope` | Convert slash-command scope text to agent list | `scope_text` |

### Scanning

| Tool | Purpose | Key inputs |
|---|---|---|
| `scan_agents` | Primary paginated scan primitive for explicit agents | `agents`, `target`, `project_root?`, `cursor?`, `page_size?`, `thoroughness?` |
| `scan_domain` | Convenience wrapper for all agents in one domain | `domain`, `target`, `project_root?`, `cursor?`, `page_size?`, `thoroughness?` |
| `run_provider_scan` | Provider-neutral first-pass scan execution through fixture or opt-in CLI transports | `project_root`, `provider`, `transport`, `execution`, `run_id`, `session_id`, `agents`, `target`, `thoroughness?`, `timeout_seconds?`, `fixture_findings?`, `finalize?`, `formats?` |
| `run_composed_provider_scan` | Provider-neutral primary scan followed by configured challenger review/finalization | `project_root`, `primary_provider`, `primary_transport`, `primary_execution`, `challenger_mode`, `challenger_execution`, `run_id`, `session_id`, `agents`, `target`, `thoroughness?`, `primary_timeout_seconds?`, `challenger_timeout_seconds?`, `fixture_findings?`, `formats?` |
| `run_parallel_provider_scan` | Independent provider-neutral primary scans with agreed/disputed/unique reconciliation | `project_root`, `participants`, `run_id`, `session_id`, `agents`, `target`, `thoroughness?`, `timeout_seconds?`, `fixture_findings_by_provider?`, `finalize?`, `formats?` |

Retired scan tools:

- `scan_full`
- `scan_sqli`
- `scan_cmdi`
- `scan_ssti`
- `scan_xss`

Use `scan_agents` instead.

### Output And Learning

| Tool | Purpose | Key inputs |
|---|---|---|
| `accumulate_findings` | Append findings to a scan session | `project_root`, `findings_chunk`, `session_id?` |
| `finalize_scan_results` | Render reports, optionally attach challenger review, and clean scan staging | `project_root`, `session_id`, `agent_names`, `formats?`, `scan_metadata?`, `challenger_mode?`, `challenger_execution?` |
| `format_output` | Format supplied findings without writing project reports | `findings`, `format`, `scan_metadata?` |
| `record_exclusion` | Record a false-positive exclusion | `project_root`, `exclusion` |
| `check_exclusions` | Read project exclusions | `project_root`, `agent?` |
| `aggregate_learning` | Build learning reports from exclusions | `project_root`, `report_type?` |

`finalize_scan_results` leaves challenger execution disabled unless both
`challenger_mode` and `challenger_execution` are provided. `challenger_execution`
accepts `dry_run` for fixture transports or `cli` for opt-in live CLI transports.
When enabled, the challenger reviews finalized active findings after merge and
exclusion filtering, before JSON/Markdown/SARIF reports are written.

When `scan_metadata.challenger_results` is provided, JSON, Markdown, and SARIF
outputs include the challenger run envelope and finding-level reconciliation
summaries. When `scan_metadata.report` or other Phase 5 provider metadata is
provided, report filenames include the mode/provider label and JSON,
Markdown, and SARIF include the scan metadata. Examples include
`sqli-codex-primary-*`, `sqli-codex-primary-claude-challenger-*`, and
`sqli-parallel-claude-codex-*`. Existing JSON array output is preserved when
no challenger or Phase 5 provider metadata is supplied. CSV remains
finding-only.

### Challenger Execution

| Tool | Purpose | Key inputs |
|---|---|---|
| `challenger_dry_run` | Run a fixture-only configured challenger mode and return JSON | `project_root`, `mode`, `run_id`, `session_id`, `agents`, `target`, `prompt`, `findings` |
| `challenger_run` | Run an opt-in CLI-backed challenger mode and return JSON | `project_root`, `mode`, `run_id`, `session_id`, `agents`, `target`, `prompt`, `findings`, `timeout_seconds?` |

`challenger_dry_run` refuses CLI, API, and local transports. `challenger_run`
requires all selected-mode participants to use enabled `cli` transports and
refuses fixture, API, and local transports. Both tools use the same structured
result envelope as the package CLI commands.

### Provider Scan Execution

| Tool | Purpose | Key inputs |
|---|---|---|
| `run_provider_scan` | Run a provider-neutral primary scan and return `PrimaryScanResult` JSON | `project_root`, `provider`, `transport`, `execution`, `run_id`, `session_id`, `agents`, `target` |
| `run_composed_provider_scan` | Run provider-neutral primary scanning, accumulate/finalize findings, and attach challenger review | `project_root`, `primary_provider`, `primary_transport`, `primary_execution`, `challenger_mode`, `challenger_execution`, `run_id`, `session_id`, `agents`, `target` |
| `run_parallel_provider_scan` | Run multiple provider-neutral primary scans and optionally finalize mode-aware reports | `project_root`, `participants`, `run_id`, `session_id`, `agents`, `target`, `finalize?`, `formats?` |

`run_provider_scan` supports `execution: "fixture"` and opt-in
`execution: "cli"` only. It rejects API/local transports until adapters exist.
By default it returns validated findings for callers to inspect, accumulate,
challenge, or reconcile. When `finalize: true`, it also accumulates the returned
findings and writes normal `.screw/findings/` reports through
`finalize_scan_results`.

`run_composed_provider_scan` supports the two required primary/challenger
directions through configured modes, for example Codex primary with Claude
challenger and Claude primary with Codex challenger. `run_parallel_provider_scan`
requires at least two participants, runs them independently from the same
YAML-derived scan input, and reports agreed, disputed, and unique findings.
When `finalize: true`, parallel mode also writes normal `.screw/findings/`
reports with the parallel provider list and reconciliation metadata embedded
in JSON/Markdown/SARIF output.

Manual live validation has passed for Codex and Claude CLI primary scans on one
MLflow MoreFixes SSTI vulnerable/patched benchmark pair. Codex can satisfy the
contract through strict structured output from `codex exec`; Claude CLI can
produce the required structured findings under `structured_output.findings`,
which the production Claude CLI primary runner now extracts from Claude's JSON
envelope.

`provider-scan` is the backend/package CLI surface for provider-neutral primary
scanning. `/screw:scan` is the universal assistant-facing scan command and
now exposes provider-neutral primary selection, primary-plus-challenger
composition, and parallel provider scan reconciliation through explicit flags.

### Trust And Adaptive Analysis

| Tool | Purpose | Key inputs |
|---|---|---|
| `verify_trust` | Summarize trust state for exclusions and adaptive scripts | `project_root` |
| `record_context_required_match` | Record investigated-but-dropped context-required matches | `project_root`, `match`, `session_id?` |
| `detect_coverage_gaps` | Compute adaptive coverage gaps for a scan session | `agent_name`, `project_root`, `session_id` |
| `lint_adaptive_script` | Lint proposed adaptive script source without executing it | `source` |
| `stage_adaptive_script` | Stage an unsigned adaptive script for review | `project_root`, `script_name`, `source`, `meta`, `session_id`, `target_gap?` |
| `promote_staged_script` | Sign and promote staged script bytes after review | `project_root`, `script_name`, `session_id`, `confirm_sha_prefix?`, `confirm_stale?` |
| `reject_staged_script` | Reject and delete staged adaptive script files | `project_root`, `script_name`, `session_id`, `reason?` |
| `execute_adaptive_script` | Execute a validated adaptive script in the sandbox | `project_root`, `script_name`, `wall_clock_s?` |
| `list_adaptive_scripts` | List installed adaptive scripts and validation status | `project_root` |
| `remove_adaptive_script` | Delete an adaptive script pair with confirmation | `project_root`, `script_name`, `confirmed` |
| `sweep_stale_staging` | Clean stale `.screw/staging/` entries | `project_root`, `max_age_days?`, `dry_run?` |

## Benchmark Commands

The benchmark stack is primarily for development, validation, and Phase 4-style
controlled evidence gathering.

### Benchmark runner

```bash
uv run python -m benchmarks.runner list
uv run python -m benchmarks.runner validate path/to/truth.sarif
uv run python -m benchmarks.runner run --agent sqli --dataset morefixes --match-mode broad --dedup
```

Subcommands:

| Command | Purpose |
|---|---|
| `list` | List benchmark manifests and registered agents |
| `validate PATH` | Validate a bentoo-SARIF file |
| `run` | Stub evaluation command retained for runner CLI compatibility |

### Autoresearch planning and controlled execution

No-Claude planning:

```bash
uv run python benchmarks/scripts/plan_autoresearch.py \
  --output-dir /tmp/screw-plan
```

Planning options:

| Option | Default | Description |
|---|---:|---|
| `--manifests-dir` | `benchmarks/external/manifests` | Benchmark manifest directory |
| `--external-dir` | `benchmarks/external` | Materialized benchmark data directory |
| `--output-dir` | timestamped result dir | Directory for `run_plan.json` and `run_plan.md` |

Readiness check:

```bash
uv run python benchmarks/scripts/check_autoresearch_readiness.py \
  --dry-run-plan /tmp/screw-plan/run_plan.json \
  --output-dir /tmp/screw-readiness
```

Readiness options:

| Option | Default | Description |
|---|---:|---|
| `--dry-run-plan` | none | Existing `run_plan.json`; omitted means build one from manifests |
| `--manifests-dir` | `benchmarks/external/manifests` | Used when `--dry-run-plan` is omitted |
| `--external-dir` | `benchmarks/external` | Used when `--dry-run-plan` is omitted |
| `--output-dir` | timestamped result dir | Directory for readiness JSON and Markdown |

Prepare controlled run:

```bash
uv run python benchmarks/scripts/prepare_autoresearch_run.py \
  --dry-run-plan /tmp/screw-plan/run_plan.json \
  --output-dir /tmp/screw-controlled
```

Controlled-plan options:

| Option | Default | Description |
|---|---:|---|
| `--dry-run-plan` | required | Path to `run_plan.json` from planning |
| `--output-dir` | timestamped result dir | Directory for `controlled_run_plan.json` and Markdown |
| `--max-cases-per-dataset` | `1` | Per-dataset sample cap |
| `--max-cases-per-agent` | `10` | Per-agent sample cap |
| `--selection-strategy` | `required-dataset-smoke` | Case selection strategy: `required-dataset-smoke`, `gate-order`, `expanded-stratified`, or `priority-stratified` |
| `--allow-claude-invocation` | false | Required before the generated plan can be executable |

Validate controlled executor without Claude:

```bash
uv run python benchmarks/scripts/run_controlled_autoresearch.py \
  --controlled-plan /tmp/screw-controlled/controlled_run_plan.json \
  --output-dir /tmp/screw-controlled-validation
```

Execute a reviewed controlled slice:

```bash
uv run python benchmarks/scripts/run_controlled_autoresearch.py \
  --controlled-plan /tmp/screw-controlled/controlled_run_plan.json \
  --output-dir /tmp/screw-controlled-run \
  --agent sqli \
  --case-id <case-id> \
  --max-retries 1 \
  --timeout 600 \
  --max-prompt-chars 600000 \
  --execute \
  --allow-claude-invocation
```

Controlled executor options:

| Option | Default | Description |
|---|---:|---|
| `--controlled-plan` | required | Path to `controlled_run_plan.json` |
| `--output-dir` | timestamped result dir | Output directory |
| `--execute` | false | Actually invoke Claude |
| `--allow-claude-invocation` | false | Required with `--execute` |
| `--throttle` | `2.0` | Seconds between Claude calls |
| `--max-retries` | `3` | Retry budget per Claude call |
| `--timeout` | `300` | Timeout in seconds per Claude call |
| `--agent` | none | Restrict to one or more agents; repeatable |
| `--case-id` | none | Restrict to one or more benchmark cases; repeatable |
| `--include-related-context` | false | Add related truth files to prompt context |
| `--include-helper-context` | true | Add directly referenced helper files as bounded context |
| `--no-helper-context` | false | Disable helper context |
| `--max-prompt-chars` | `250000` | Retry-budgeted prompt character guard; `0` disables |
| `--max-files-per-variant` | `0` | Optional selected-file cap per vulnerable/patched variant |

Generate failure payloads:

```bash
uv run python benchmarks/scripts/generate_autoresearch_failure_inputs.py \
  --controlled-executor-report /tmp/screw-controlled-run/controlled_executor_report.json \
  --output-dir /tmp/screw-failure-inputs
```

Failure-payload options:

| Option | Default | Description |
|---|---:|---|
| `--controlled-executor-report` | required | Controlled executor report JSON |
| `--output-dir` | timestamped result dir | Directory for generated payloads |
| `--domains-dir` | `domains` | Agent YAML directory |
| `--external-dir` | none | Override external benchmark data directory |
| `--max-missed-per-agent` | `5` | Missed-vulnerability examples per agent payload |
| `--max-false-positives-per-agent` | `5` | False-positive examples per agent payload |
| `--no-code-excerpts` | false | Omit code excerpts from generated examples |

Inspect live invocation progress:

```bash
uv run python benchmarks/scripts/show_invocation_progress.py \
  /tmp/screw-controlled-run/invocation_progress.jsonl
```

### Dataset and materialization helpers

Common scripts:

| Script | Purpose |
|---|---|
| `benchmarks/scripts/extract_cwe_1400.py` | Extract CWE-1400 hierarchy data |
| `benchmarks/scripts/ingest_*.py` | Ingest benchmark manifests/datasets |
| `benchmarks/scripts/deploy_morefixes.sh` | Start MoreFixes Docker/Postgres materialization support |
| `benchmarks/scripts/morefixes_extract.py` | Extract MoreFixes truth and code snapshots |
| `benchmarks/scripts/materialize_ossf_targets.py` | Clone/materialize selected OSSF target repositories |
| `benchmarks/scripts/refresh_rust_advisories.py` | Refresh Rust advisory candidates |
| `benchmarks/scripts/review_rust_advisory_candidates.py` | Review Rust advisory candidates |
| `benchmarks/scripts/materialize_rust_d01.py` | Materialize D-01 Rust benchmark cases |
| `benchmarks/scripts/run_gates.py` | Run benchmark gate checks |

Generated benchmark material under `benchmarks/external/` is intentionally
ignored unless it is a tracked manifest or small support file.

## Development Commands

```bash
uv sync
uv run pytest
uv run pytest tests/test_registry_invariants.py -v
uv run pytest benchmarks/tests/test_autoresearch_controlled_executor.py -v
uv run ruff check src/screw_agents
uv run ruff check .
```

`uv run ruff check src/screw_agents` is the production-source lint baseline.
Repo-wide lint also traverses tests and benchmark material, including
assert-heavy pytest files and intentionally vulnerable benchmark fixtures.

Current Claude Code plugin development:

```bash
claude --plugin-dir ./plugins/screw
claude --debug --plugin-dir ./plugins/screw
claude plugin validate ./plugins/screw
```

After editing plugin commands, agents, or skills, run `/reload-plugins` inside
Claude Code.

Current Codex plugin development:

```bash
codex plugin marketplace add /path/to/screw-agents
codex mcp list
codex mcp get screw-agents
```

The repo-local Codex plugin manifest is
`plugins/screw/.codex-plugin/plugin.json`; its local marketplace entry is
`.agents/plugins/marketplace.json`. Local marketplace entries are read from
their configured root path; enable the plugin from `/plugins` after adding the
marketplace. `codex plugin marketplace upgrade` is for Git-backed marketplaces,
not this repo-local path.
