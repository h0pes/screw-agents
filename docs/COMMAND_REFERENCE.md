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
uv run screw-agents serve [--transport stdio|http] [--port 8080] [--domains-dir PATH] [--log-level LEVEL]
```

Options:

| Option | Values | Default | Description |
|---|---|---:|---|
| `--transport` | `stdio`, `http` | `stdio` | MCP transport protocol |
| `--port` | integer | `8080` | HTTP port when `--transport http` is used |
| `--domains-dir` | path | auto-detect | Alternate agent YAML domains directory |
| `--log-level` | `DEBUG`, `INFO`, `WARNING`, `ERROR` | `INFO` | Server logging level |

Examples:

```bash
uv run screw-agents serve --transport stdio
uv run screw-agents serve --transport http --port 8080
```

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

## Claude Code Plugin Commands

Load the plugin locally:

```bash
claude --plugin-dir ./plugins/screw
```

### `/screw:scan`

Run security review with one or more agents.

```text
/screw:scan <scope-spec> [target] [--adaptive | --no-confirm] [--thoroughness standard|deep] [--format json|sarif|markdown|csv]
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
| `--help` | flag | n/a | Print command help without scanning |

`--adaptive` and `--no-confirm` are mutually exclusive.

Target forms include paths, globs, git diffs, commit ranges, pull requests,
classes, functions, and line ranges as supported by the MCP target resolver.

Examples:

```text
/screw:scan sqli src/api/
/screw:scan injection-input-handling src/
/screw:scan full . --no-confirm
/screw:scan agents:sqli,xss src/api/ --format sarif
/screw:scan sqli src/api/ --adaptive
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
| `finalize_scan_results` | Render reports and clean scan staging | `project_root`, `session_id`, `agent_names`, `formats?`, `scan_metadata?` |
| `format_output` | Format supplied findings without writing project reports | `findings`, `format`, `scan_metadata?` |
| `record_exclusion` | Record a false-positive exclusion | `project_root`, `exclusion` |
| `check_exclusions` | Read project exclusions | `project_root`, `agent?` |
| `aggregate_learning` | Build learning reports from exclusions | `project_root`, `report_type?` |

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
uv run ruff check .
```

Claude plugin development:

```bash
claude --plugin-dir ./plugins/screw
claude --debug --plugin-dir ./plugins/screw
claude plugin validate ./plugins/screw
```

After editing plugin commands, agents, or skills, run `/reload-plugins` inside
Claude Code.
