# Phase 5 Manual Validation

> Status: in progress. Fixture-mode provider-neutral primary scan validation is
> recorded. Live Codex/Claude CLI validation remains pending explicit approval.
> Last updated: 2026-05-04.

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
| Codex CLI primary scan live run | Pending | Requires explicit approval |
| Claude CLI primary scan live run | Pending | Requires explicit approval |
| Provider scan result accumulation/finalization | Pending | Not implemented in current public surface |
| Primary plus challenger public round trip | Pending | Requires accumulation/finalization or explicit orchestration |
| Parallel independent primary scans | Pending | P5-P5 |

## Decision

Fixture-mode provider-neutral primary scan execution is validated for the new
public package CLI and MCP surfaces. Phase 5 is still not closure-ready because
live CLI behavior, provider result finalization, challenger composition, and
parallel reconciliation have not been manually validated.
