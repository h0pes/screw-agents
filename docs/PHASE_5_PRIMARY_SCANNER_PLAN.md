# Phase 5 Primary Scanner Plan

> Status: required Phase 5 work. The challenger/orchestration layer exists,
> and the provider-neutral primary scan contract, fixture runner, and scan
> input assembly from YAML agent knowledge are implemented. Primary scanner
> CLI runner plumbing is implemented for configured Claude/Codex/generic CLI
> transports, and the `provider-scan` package CLI plus `run_provider_scan` MCP
> tool expose fixture and opt-in CLI primary scan execution. Manual round-trip
> validation is still pending. Phase 5 is not closure-ready until this gap is
> closed or explicitly re-scoped.

## Why This Exists

The project goal is broader than Claude Code plus challenger review. A user
should be able to install `screw-agents` and choose the assistant that performs
the first-pass scan:

- Claude alone.
- Codex alone.
- Gemini or another future assistant alone.
- A chosen primary assistant with a chosen challenger assistant.
- Parallel independent scans with reconciliation.

Today, Claude Code is the implemented primary scan UX. It uses the MCP backend,
target resolver, YAML agent knowledge, accumulation, and report finalization.
Codex, Gemini, and local models do not yet have an equivalent live first-pass
scan runner that consumes the same YAML agent knowledge and emits `Finding`
JSON. The backend contract for such runners now exists in
`src/screw_agents/primary_scan/`, and `ScanEngine.assemble_primary_scan_input`
packages selected YAML agent prompts, resolved source chunks, target metadata,
and the shared `Finding` output schema without invoking a provider. The
`CliPrimaryScanRunner` can invoke a configured CLI transport shell-free and
validate JSON output back into `Finding` objects. `screw-agents provider-scan`
and MCP `run_provider_scan` expose that backend for fixture and opt-in CLI
execution; API/local transports remain pending.

The current Phase 5 challenger package supports provider-neutral participant
roles and reconciliation, but those "primary" roles operate inside the
challenger-review envelope over supplied findings. That is not the same as a
provider acting as the original scanner from YAML agent prompts and source
context.

## Current Capability Matrix

| Capability | Status |
|---|---|
| Claude Code primary scanning through `/screw:scan` | Implemented |
| Attach configured challenger review during `finalize_scan_results` | Implemented |
| `/screw:scan --challenger ... --challenger-execution dry_run\|cli` | Implemented |
| Fixture/CLI challenger mode orchestration and reconciliation | Implemented |
| Provider-neutral primary scan input/result contract | Implemented |
| Fixture primary scan runner and output validation | Implemented |
| Provider-neutral scan input assembly from YAML agent knowledge | Implemented |
| Generic/Claude/Codex CLI primary scan runner plumbing | Implemented |
| `provider-scan` package CLI and `run_provider_scan` MCP tool | Implemented |
| Codex primary review participant over supplied findings | Implemented at challenger-orchestrator level |
| Codex as first-pass scanner from YAML agent knowledge | Public CLI/MCP path implemented; manual validation pending |
| Gemini/local as first-pass scanner from YAML agent knowledge | Pending adapter |
| Parallel independent first-pass scans with reconciliation | Pending |
| Manual round-trip validation of all Phase 5 modes | Pending |

## Required Architecture

Add live provider-neutral primary scan runners that sit beside the Claude Code
plugin path and use the same backend primitives:

1. Resolve scope and target through MCP/backend code.
2. Assemble `PrimaryScanInput` from:
   - selected YAML agent definitions;
   - resolved source chunks;
   - target metadata;
   - output schema instructions for `Finding` JSON.
3. Invoke the configured primary provider/transport.
4. Parse provider output through `parse_primary_scan_output` and validate
   findings against the existing `Finding` model.
5. Accumulate findings into the existing staging protocol.
6. Optionally run challenger review using the existing Phase 5 challenger
   execution path.
7. Finalize reports through `finalize_scan_results`.

This runner must not require Claude Code. Claude Code can remain one frontend,
but it must not be the only path capable of performing primary scans.

## Proposed Public Surfaces

Candidate backend API names:

- `run_provider_scan`
- `llm_scan`
- `scan_with_provider`

Candidate MCP tool:

- `run_provider_scan(project_root, provider, transport, agents, target,
  prompt_options?, challenger_mode?, challenger_execution?, formats?)`

Candidate CLI:

```bash
uv run screw-agents provider-scan \
  --provider codex \
  --transport cli \
  --agents sqli,xss \
  --target src/api \
  --format json
```

Names can change during implementation. The important contract is that primary
scanning becomes provider-neutral and machine-readable.

## Required Modes

### Single-Provider Primary Scan

Examples:

- Claude primary only.
- Codex primary only.
- Future Gemini/local primary only.

Output: normal JSON/Markdown/CSV/SARIF reports.

### Primary Plus Challenger

Examples:

- Claude primary, Codex challenger.
- Codex primary, Claude challenger.
- Future Gemini primary, Claude/Codex challenger.

Output: normal reports enriched with challenger metadata.

### Parallel Independent Scans

Examples:

- Claude and Codex both scan independently from the same YAML agent knowledge
  and source context.
- Results are merged/reconciled into agreed, disputed, and unique findings.

Output: normal reports plus reconciliation metadata that distinguishes which
provider produced or disputed each finding.

## Guardrails

- No provider execution by default.
- No second-provider execution by default.
- No API billing unless explicitly configured and requested.
- Subscription-backed CLI transports are first-class when available.
- If a corresponding local CLI is not installed, the provider can only be used
  through an explicitly configured API, local endpoint, or other future
  transport adapter.
- `ANTHROPIC_API_KEY` remains unset for subscription-backed Claude CLI
  execution.
- Provider adapters must return structured JSON; malformed output is a failed
  run, not a best-effort free-text report.
- Source-sharing consent is required before sending source externally.
- The YAML agent schema must remain provider-neutral.

## Implementation Slices

### P5-P1 - Primary Scan Contract

- Status: implemented.
- Added provider-neutral `PrimaryScanInput`, `PrimaryScanResult`, and
  `parse_primary_scan_output`.
- Reuses existing `Finding` for output validation.
- Added fixture primary scan runner for deterministic tests.

### P5-P2 - Scan Assembly For Providers

- Status: implemented.
- Added `ScanEngine.assemble_primary_scan_input`.
- Builds scan input from the existing registry, target resolver, relevance
  filter, YAML prompt builder, and `Finding` output schema.
- Ensures Codex/Gemini/local-style provider inputs receive the same curated
  YAML knowledge used by Claude Code, without executing any provider.

### P5-P3 - CLI Runner Integration

- Status: implemented for backend runner plumbing.
- Added generic `CliPrimaryScanRunner`.
- Added Codex and Claude CLI primary scan wrappers that strip `OPENAI_API_KEY`
  and `ANTHROPIC_API_KEY` respectively for subscription-backed CLI use.
- Command invocation is shell-free and provider output is parsed through the
  shared `parse_primary_scan_output` validator.
- Live/manual CLI validation remains pending until the public surface exists
  and Marco explicitly approves provider invocation.

### P5-P4 - MCP/CLI Surface

- Status: implemented.
- Added `screw-agents provider-scan`.
- Added MCP tool `run_provider_scan`.
- Public surface supports fixture execution and opt-in configured CLI
  transports. API/local transports are still rejected until adapters exist.
- Keep `/screw:scan` as the Claude Code frontend, but make the backend surface
  usable by other assistants and future web-app workers.

### P5-P5 - Parallel Scan Reconciliation

- Status: pending.
- Run multiple primary providers independently.
- Normalize findings.
- Reconcile agreed/disputed/unique results.
- Preserve provider provenance in JSON/SARIF/Markdown.

### P5-P6 - Manual Round-Trip Validation

- Status: pending.
- Fixture-mode validation for all modes.
- CLI dry-run validation with no API keys.
- Opt-in live CLI validation only when Marco explicitly approves it.
- Record results in the Phase 5 closure readiness document.

## Phase 5 Closure Dependencies

Phase 5 closure must wait for:

- Provider-neutral primary scan runner implemented.
- Codex first-pass scan from YAML knowledge validated.
- All three required modes validated:
  - Claude primary, Codex challenger.
  - Codex primary, Claude challenger.
  - parallel independent scans with reconciliation.
- Manual round-trip checklist recorded.
- API/local provider adapter deferrals explicitly documented.
- Phase 5.5 handoff surfaces documented for web application integration.
