# Phase 5 Manual Validation

> Status: in progress. Fixture-mode provider-neutral primary scan validation is
> recorded. Live Codex and Claude CLI primary scan validation passed on one
> vulnerable/patched benchmark round trip; the Claude structured-output
> adapter behavior discovered during that run is now implemented in the
> production runner. Backend composed primary-plus-challenger workflow has
> fixture coverage and live Claude/Codex validation in both directions;
> backend parallel primary reconciliation has fixture
> coverage for agreed, unique, and severity-disputed findings. The universal
> `/screw:scan` provider-primary command contract is implemented and
> route-equivalent fixture validation passed for single provider-primary,
> primary-plus-challenger, and parallel-provider paths. Live parallel mode
> validation remains pending. Codex plugin skill
> validation has passed for the MCP-backed YAML scan route.
> Last updated: 2026-05-05.

## Scope

This document records manual round-trip validation for Phase 5 public provider
surfaces. These checks simulate an end user running `screw-agents` from a
separate project directory, not from repository internals.

## Environment

- Repository worktree: `.worktrees/phase5-provider-scan-validation`
- Temporary end-user project:
  `/tmp/screw-agents-phase5-provider-scan-fixture`
- Vulnerable target:
  `/tmp/screw-agents-phase5-provider-scan-fixture/src/app.py`
- Project config:
  `/tmp/screw-agents-phase5-provider-scan-fixture/.screw/config.yaml`
- Live provider invocation: none
- API keys required: none

The temporary project contained a configured `codex` provider with:

- enabled `fixture` transport;
- enabled `api` transport used only to verify rejection behavior;
- `api_billing_allowed: false`;
- no configured CLI transport for this fixture-only validation.

## `/screw:scan` Provider Route Fixture Validation

The universal `/screw:scan` provider-primary flags route to MCP provider scan
tools after scope resolution. This validation exercised the same resolved
scope, target, provider, transport, execution, session, finalization, and
reconciliation arguments that the command contract now maps to those tools,
without invoking live providers.

Environment:

- Repository worktree: `.worktrees/phase5-scan-ux-validation`
- Temporary end-user project:
  `/tmp/screw-agents-phase5-scan-ux-fixture`
- Target:
  `/tmp/screw-agents-phase5-scan-ux-fixture/src/app.py`
- Project config:
  `/tmp/screw-agents-phase5-scan-ux-fixture/.screw/config.yaml`
- Configured providers: `claude` and `codex`
- Configured transports: fixture only
- Live provider invocation: none
- API keys required: none

The project config enabled these fixture modes:

- `codex_primary_claude_challenger`
- `claude_primary_codex_challenger`

Command:

```bash
uv run python /tmp/screw-agents-phase5-scan-ux-fixture/validate_scan_routes.py
```

Result:

```json
{
  "composed": {
    "active": 1,
    "challenger_count": 1,
    "mode_type": "primary_challenger",
    "primary_provider": "codex"
  },
  "parallel": {
    "mode_type": "parallel",
    "provider_count": 2,
    "reconciliation_statuses": ["disputed"]
  },
  "scope_agents": ["sqli"],
  "single_provider": {
    "active": 1,
    "provider": "codex"
  }
}
```

Validated route mappings:

- `/screw:scan sqli ... --primary-provider codex --primary-transport fixture
  --primary-execution fixture` maps to `run_provider_scan` with
  `finalize=true`; result finalized one active finding and wrote JSON/Markdown
  reports.
- `/screw:scan sqli ... --primary-provider codex --primary-transport fixture
  --primary-execution fixture --challenger codex_primary_claude_challenger
  --challenger-execution dry_run` maps to `run_composed_provider_scan`; result
  produced one primary finding, one challenger result, and one active finalized
  finding.
- `/screw:scan sqli ... --parallel-providers
  claude:fixture:fixture,codex:fixture:fixture` maps to
  `run_parallel_provider_scan`; result ran two independent fixture primary
  scans and returned one severity-disputed reconciliation.

Conclusion: passed for route-equivalent fixture validation. This proves the
new command contract can reach all three provider-primary MCP workflows without
provider/API execution. Live provider validation for composed and parallel
paths remains pending.

## Live Benchmark Round Trip

The live provider-neutral primary scan validation used a separate temporary
end-user project:

- Temporary end-user project:
  `/tmp/screw-agents-phase5-live-mlflow`
- Benchmark case:
  `benchmarks/external/morefixes/morefixes-CVE-2023-6709-https_____github.com__mlflow__mlflow`
- Vulnerable target:
  `/tmp/screw-agents-phase5-live-mlflow/vulnerable/__init__.py`
- Patched target:
  `/tmp/screw-agents-phase5-live-mlflow/patched/__init__.py`
- Truth evidence:
  `/tmp/screw-agents-phase5-live-mlflow/truth.sarif`
- Agent:
  `ssti`
- CWE:
  `CWE-1336`

The benchmark truth identifies the vulnerable `CardTab.to_html` path where a
caller-controlled Jinja2 template string is rendered with a non-sandboxed
`Environment(...).from_string(...)`; the patched target uses
`SandboxedEnvironment`.

The temporary project configured:

- `codex` CLI transport using `codex exec --skip-git-repo-check --sandbox
  read-only --output-schema ... -`;
- `claude` CLI transport through a temporary wrapper that invokes `claude -p
  --output-format json --json-schema ...` and normalizes
  `structured_output.findings` into the provider-scan contract;
- `api_billing_allowed: false`;
- no API transport invocation.

The Codex primary runner strips `OPENAI_API_KEY`; the Claude primary runner and
temporary wrapper strip `ANTHROPIC_API_KEY`. Both live paths therefore exercised
subscription-backed CLI transports rather than an explicit API-key transport.
Claude Code's JSON envelope reported usage/cost accounting, which is provider
CLI metadata and should be documented separately from screw-agents API billing
consent.

### Codex CLI Primary Scan - Vulnerable Target

Command shape:

```bash
uv run screw-agents provider-scan \
  --project-root /tmp/screw-agents-phase5-live-mlflow \
  --provider codex \
  --transport cli \
  --execution cli \
  --agents ssti \
  --target-json '{"type":"file","path":"/tmp/screw-agents-phase5-live-mlflow/vulnerable/__init__.py"}' \
  --run-id codex-mlflow-live-004 \
  --session-id codex-mlflow-live-session-004 \
  --thoroughness standard \
  --timeout-seconds 300 \
  --finalize \
  --format json \
  --format markdown
```

Result:

- Exit code: `0`
- Returned provider/transport: `codex` / `cli`
- Returned finding count: `1`
- Finalized active finding count: `1`
- Severity: `high`
- CWE: `CWE-1336`
- Finding location: `CardTab.to_html` in the vulnerable MLflow file.

Conclusion: passed.

### Codex CLI Primary Scan - Patched Target

Command shape matched the vulnerable run, with target
`/tmp/screw-agents-phase5-live-mlflow/patched/__init__.py` and run id
`codex-mlflow-patched-live-001`.

Result:

- Exit code: `0`
- Returned provider/transport: `codex` / `cli`
- Returned finding count: `0`
- Finalized active finding count: `0`

Conclusion: passed.

### Claude CLI Primary Scan - Vulnerable Target

The first direct Claude command returned a Claude JSON envelope whose `result`
field was prose rather than the raw `{"findings": [...]}` object expected by
the generic primary runner. A temporary adapter was used during this validation
to extract `structured_output.findings`; the production Claude CLI primary
runner now implements that same output-normalization behavior.

Command shape:

```bash
uv run screw-agents provider-scan \
  --project-root /tmp/screw-agents-phase5-live-mlflow \
  --provider claude \
  --transport cli \
  --execution cli \
  --agents ssti \
  --target-json '{"type":"file","path":"/tmp/screw-agents-phase5-live-mlflow/vulnerable/__init__.py"}' \
  --run-id claude-mlflow-live-004 \
  --session-id claude-mlflow-live-session-004 \
  --thoroughness standard \
  --timeout-seconds 360 \
  --finalize \
  --format json \
  --format markdown
```

Result:

- Exit code: `0`
- Returned provider/transport: `claude` / `cli`
- Returned finding count: `1`
- Finalized active finding count: `1`
- Severity: `high`
- CWE: `CWE-1336`
- Finding location: `CardTab.to_html` in the vulnerable MLflow file.

Conclusion: passed; this temporary validation adapter was later promoted into
the production Claude CLI primary runner.

### Claude CLI Primary Scan - Patched Target

Command shape matched the vulnerable run, with target
`/tmp/screw-agents-phase5-live-mlflow/patched/__init__.py` and run id
`claude-mlflow-patched-live-001`.

Result:

- Exit code: `0`
- Returned provider/transport: `claude` / `cli`
- Returned finding count: `0`
- Finalized active finding count: `0`

Conclusion: passed; this temporary validation adapter was later promoted into
the production Claude CLI primary runner.

## Live Validation Lessons

- Codex CLI can satisfy the primary scan contract through structured output
  when configured with a strict schema accepted by `codex exec`.
- Claude CLI can produce the required structured finding payload, but provider
  adapters must read `structured_output.findings` from the Claude JSON envelope
  rather than expecting the top-level `result` field to be raw JSON. The
  production Claude CLI primary runner now does this.
- `provider-scan --finalize` correctly accumulates and writes normal
  `.screw/findings/` JSON/Markdown reports for live provider output.
- The benchmark vulnerable/patched pair gives a useful acceptance shape:
  vulnerable finding count `1`, patched finding count `0`, same CWE/location
  signal as truth evidence.
- The package CLI and MCP/backend surface are validated for primary provider
  execution. `/screw:scan` now exposes provider-neutral primary selection as
  the universal scan command contract that should be exposed consistently by
  Claude Code, Codex, Gemini, local assistants, or future plugin hosts. The new
  Codex skill route is validated for normal YAML/MCP scanning. Provider-mode
  assistant routes still need live round-trip validation before Phase 5 closure.

## Codex Plugin Skill Round Trip

The Codex plugin validation used a separate temporary project:

- Temporary end-user project:
  `/tmp/screw-agents-phase5-live-modes`
- Plugin marketplace:
  `.worktrees/phase5-codex-command-discovery`
- Installed Codex plugin cache version:
  `0.1.4`
- MCP server:
  `uv run --directory .worktrees/phase5-codex-command-discovery screw-agents serve --transport stdio`
- Agent:
  `ssti`

Codex v0.128.0 did not expose plugin `commands/` files as literal
`/screw:*` slash-completion entries during validation. It did load packaged
skills and MCP tools. OpenAI Codex docs mark custom prompts as deprecated in
favor of skills, so this validation exercised the Codex-supported skill path.

Setup checks:

- `/plugins` showed the installed `screw-agents` plugin with skills:
  `screw:screw-adaptive-cleanup`, `screw:screw-learn-report`,
  `screw:screw-research`, `screw:screw-review`, and `screw:screw-scan`.
- `/mcp` showed `screw-agents` connected to the worktree server.
- A no-scan registry check called only `list_domains` and `list_agents`,
  returning domain `injection-input-handling` and agents `cmdi`, `sqli`,
  `ssti`, and `xss`.

Dry explanation prompt:

```text
Use the screw:screw-scan skill to explain how it would handle this request,
but do not call any MCP tools and do not run a scan: screw:scan ssti
/tmp/screw-agents-phase5-live-modes --format json
```

Result: passed. Codex read the `screw:screw-scan` skill and described the
`resolve_scope` -> `scan_agents` -> `accumulate_findings` ->
`finalize_scan_results` route without calling MCP tools.

Live skill prompt:

```text
Use screw:screw-scan to run: screw:scan ssti
/tmp/screw-agents-phase5-live-modes --format json
```

Result:

- Scope resolved to `["ssti"]`.
- `scan_agents` paginated the target and completed.
- Codex accumulated one high-confidence `CWE-1336` finding for
  `vulnerable/__init__.py:125`.
- `finalize_scan_results` wrote JSON:
  `/tmp/screw-agents-phase5-live-modes/.screw/findings/ssti-2026-05-05T13-50-59.json`
- Final summary: `1` active finding, severity `high`, no suppressions, no
  exclusions, clean trust status, no coverage gaps.

Validation note: Codex attempted an unnecessary local
`uv run python -c "from screw_agents.models import Finding; ..."` schema
inspection from the temporary project and received
`ModuleNotFoundError: No module named 'screw_agents'`. This did not affect MCP
scan/finalization. The Codex scan skill now explicitly instructs Codex not to
run shell/Python introspection for screw-agents schemas from the scanned
project; MCP tool contracts are the authoritative interface.

## Fixture Provider-Scan CLI Round Trip

Command:

```bash
uv run screw-agents provider-scan \
  --project-root /tmp/screw-agents-phase5-provider-scan-fixture \
  --provider codex \
  --transport fixture \
  --execution fixture \
  --agents sqli \
  --target-json '{"type":"file","path":"/tmp/screw-agents-phase5-provider-scan-fixture/src/app.py"}' \
  --run-id fixture-cli-001 \
  --session-id fixture-cli-session \
  --fixture-findings-json '[{"id":"sqli-manual-001","agent":"sqli","domain":"injection-input-handling","timestamp":"2026-05-04T12:00:00Z","location":{"file":"/tmp/screw-agents-phase5-provider-scan-fixture/src/app.py","line_start":5},"classification":{"cwe":"CWE-89","cwe_name":"SQL Injection","severity":"high","confidence":"high"},"analysis":{"description":"String interpolation is used to construct a SQL query."},"remediation":{"recommendation":"Use parameterized SQL queries."}}]'
```

Result:

- Exit code: `0`
- Returned `PrimaryScanResult.run_id`: `fixture-cli-001`
- Returned provider/transport: `codex` / `fixture`
- Returned `transport_kind`: `fixture`
- Returned finding id: `sqli-manual-001`
- Finding was normalized through the shared `Finding` model, including default
  triage and optional fields.
- Guardrails: `{"fixture_runner": true}`

Conclusion: passed.

## Fixture MCP `run_provider_scan` Round Trip

Command:

```bash
uv run python -c 'import json; from screw_agents.engine import ScanEngine; from screw_agents.server import _dispatch_tool; engine=ScanEngine.from_defaults(); result=_dispatch_tool(engine,"run_provider_scan",{"project_root":"/tmp/screw-agents-phase5-provider-scan-fixture","provider":"codex","transport":"fixture","execution":"fixture","run_id":"fixture-mcp-001","session_id":"fixture-mcp-session","agents":["sqli"],"target":{"type":"file","path":"/tmp/screw-agents-phase5-provider-scan-fixture/src/app.py"},"fixture_findings":[{"id":"sqli-mcp-001","agent":"sqli","domain":"injection-input-handling","timestamp":"2026-05-04T12:05:00Z","location":{"file":"/tmp/screw-agents-phase5-provider-scan-fixture/src/app.py","line_start":5},"classification":{"cwe":"CWE-89","cwe_name":"SQL Injection","severity":"high","confidence":"high"},"analysis":{"description":"String interpolation is used to construct a SQL query."},"remediation":{"recommendation":"Use parameterized SQL queries."}}]}); print(json.dumps({"run_id":result["run_id"],"provider":result["provider"],"transport_kind":result["transport_kind"],"finding_id":result["findings"][0]["id"],"guardrails":result["guardrails"]}, sort_keys=True))'
```

Result:

```json
{"finding_id": "sqli-mcp-001", "guardrails": {"fixture_runner": true}, "provider": "codex", "run_id": "fixture-mcp-001", "transport_kind": "fixture"}
```

Conclusion: passed.

## API/Local Rejection Guardrail

Command:

```bash
uv run screw-agents provider-scan \
  --project-root /tmp/screw-agents-phase5-provider-scan-fixture \
  --provider codex \
  --transport api \
  --execution cli \
  --agents sqli \
  --target-json '{"type":"file","path":"/tmp/screw-agents-phase5-provider-scan-fixture/src/app.py"}'
```

Result:

```text
screw-agents provider-scan: execution 'cli' requires a 'cli' transport; 'codex'/'api' is 'api'
```

Conclusion: passed. The public surface rejected the API transport before any
provider invocation.

## Current Validation Matrix

| Scenario | Status | Notes |
|---|---|---|
| Package CLI `provider-scan` fixture execution | Passed | Validated from `/tmp` project |
| MCP `run_provider_scan` fixture execution | Passed | Validated through dispatcher |
| API transport rejection | Passed | No provider invocation |
| Local transport rejection | Pending | Requires local transport config fixture |
| Codex CLI primary scan live run | Passed | MLflow MoreFixes vulnerable/patched SSTI case |
| Claude CLI primary scan live run | Passed | MLflow MoreFixes vulnerable/patched SSTI case; production runner now extracts the validated `structured_output.findings` shape |
| Provider scan result accumulation/finalization | Passed | Fixture, Codex live, and Claude live outputs wrote `.screw/findings/` reports |
| Primary plus challenger public round trip | Passed | Fixture route passed; live Codex-primary/Claude-challenger and Claude-primary/Codex-challenger validation passed on the MLflow MoreFixes SSTI vulnerable/patched pair |
| Parallel independent primary scans | Fixture route passed, live pending | `/screw:scan` route-equivalent fixture validation reached `run_parallel_provider_scan`; live validation pending |
| Codex plugin YAML/MCP scan skill | Passed | `screw:screw-scan` routed command-shaped input through MCP scan/finalize tools and wrote JSON |
| `/screw:scan` provider-neutral primary UX | Route-equivalent fixture validation passed | Universal assistant command contract exposes provider-primary, primary-plus-challenger, and parallel-provider flags through MCP provider scan tools; live provider-mode host validation pending |

## Decision

Fixture-mode provider-neutral primary scan execution is validated for the new
public package CLI and MCP surfaces. Live Codex and Claude CLI primary scanning
is validated on one real benchmark vulnerable/patched pair, including report
finalization. Backend composed primary plus challenger flow is covered for both
Codex-primary/Claude-challenger and Claude-primary/Codex-challenger fixture
directions and live CLI directions. In the live vulnerable runs, the primary
provider reported one high-confidence SSTI finding and the configured
challenger agreed; in the patched runs, both primary providers returned zero
findings and no challenger review was invoked. Backend parallel independent
scan reconciliation is covered for agreed, unique, and severity-disputed
fixture findings. The universal
`/screw:scan` provider-primary command contract is implemented, and
route-equivalent fixture validation passed for single provider-primary,
primary-plus-challenger, and parallel-provider paths. Codex plugin skill
validation passed for the normal YAML/MCP scan route. Phase 5 is still not
closure-ready because live parallel independent scan reconciliation, additional
provider adapters, and live host validation for provider-primary/parallel
routes remain pending.
