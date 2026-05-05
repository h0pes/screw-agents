# Phase 5 Manual Validation

> Status: in progress. Fixture-mode provider-neutral primary scan validation is
> recorded. Live Codex and Claude CLI primary scan validation passed on one
> vulnerable/patched benchmark round trip; the Claude structured-output
> adapter behavior discovered during that run is now implemented in the
> production runner. Backend composed primary-plus-challenger workflow has
> fixture coverage; live composed challenger and parallel mode validation
> remain pending.
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
  execution, but the polished assistant-facing UX for provider-neutral primary
  selection is still pending. `/screw:scan` is the universal scan command
  contract that should be exposed consistently by Claude Code, Codex, Gemini,
  local assistants, or future plugin hosts. The currently tracked Claude Code
  plugin already supports challenger attachment; primary provider selection
  should be exposed through `/screw:scan` or a clearly related assistant command
  before Phase 5 closure.

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
| Primary plus challenger public round trip | Pending | Requires accumulation/finalization or explicit orchestration |
| Parallel independent primary scans | Pending | P5-P5 |
| `/screw:scan` provider-neutral primary UX | Pending | Backend exists; universal assistant command UX still needs provider-primary selection |

## Decision

Fixture-mode provider-neutral primary scan execution is validated for the new
public package CLI and MCP surfaces. Live Codex and Claude CLI primary scanning
is validated on one real benchmark vulnerable/patched pair, including report
finalization. Backend composed primary plus challenger flow is covered for both
Codex-primary/Claude-challenger and Claude-primary/Codex-challenger fixture
directions. Phase 5 is still not closure-ready because live composed primary
plus challenger flows, parallel independent scan reconciliation, additional
provider adapters, and the universal `/screw:scan` provider-primary UX have not
been completed and manually validated.
