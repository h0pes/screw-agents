# Phase 5 Primary Scanner Plan

> Status: complete. The challenger/orchestration layer exists,
> and the provider-neutral primary scan contract, fixture runner, and scan
> input assembly from YAML agent knowledge are implemented. Primary scanner
> CLI runner plumbing is implemented for configured Claude/Codex/generic CLI
> transports, including production output normalization for Claude's JSON
> envelope and Codex structured/JSONL output shapes. The `provider-scan`
> package CLI plus `run_provider_scan` MCP tool expose fixture and opt-in CLI
> primary scan execution. Provider-scan can optionally finalize returned
> findings into normal `.screw/findings/` reports. The backend composed
> primary-plus-challenger workflow is implemented for configured modes. The
> backend parallel primary scan workflow is implemented for independent
> provider scans with agreed/disputed/unique reconciliation. Fixture-mode and
> one live Codex/Claude benchmark round-trip validation are recorded in
> `docs/PHASE_5_MANUAL_VALIDATION.md`. Universal `/screw:scan`
> provider-primary and parallel flags are implemented and route to the provider
> scan MCP tools; route-equivalent fixture validation has passed for all three
> provider-primary command paths. Live parallel validation passed for the
> Claude/Codex MLflow MoreFixes SSTI vulnerable/patched pair. Real Claude Code
> and Codex host-route fixture validation passed for provider-primary,
> primary-plus-challenger, and parallel-provider paths. API/local/additional
> provider adapters are accepted post-Phase-5 deferrals; signoff is recorded in
> `docs/PHASE_5_CLOSURE_READINESS.md`.

## Why This Exists

The project goal is broader than Claude Code plus challenger review. A user
should be able to install `screw-agents` and choose the assistant that performs
the first-pass scan:

- Claude alone.
- Codex alone.
- Gemini or another future assistant alone.
- A chosen primary assistant with a chosen challenger assistant.
- Parallel independent scans with reconciliation.

The same portability principle applies beyond scanning. The `/screw:*`
assistant command set, subagents, skills, MCP tools, and package CLI surfaces
should remain host-agnostic: scan, learning reports, adaptive cleanup, trust and
exclusion operations, challenger/provider modes, and future workflows should be
available through equivalent parameters and result shapes from any supported
assistant or integration host.

The shared `plugins/screw` package now carries both Claude Code and Codex
plugin metadata. Claude Code uses `.claude-plugin/plugin.json` plus
`--plugin-dir`; Codex uses `.codex-plugin/plugin.json` plus the repo-local
`.agents/plugins/marketplace.json` descriptor. Claude hosts load
`commands/`, `agents/`, and the Claude-native `skills/screw-review` and
`skills/screw-research` helpers; Codex hosts load `codex-skills/` and the
Codex MCP descriptor. Both hosts map to the same command semantics and MCP
backend contract without exposing duplicate Claude slash completions for
scan/learning/adaptive command workflows.

Today, the provider-neutral backend and package CLI can execute Claude and
Codex first-pass scans from YAML knowledge through configured CLI transports,
and `/screw:scan` exposes explicit provider-primary and parallel-provider
selection as the universal assistant-facing command contract. Gemini and local
models do not yet have equivalent adapters that consume the same YAML agent
knowledge and emit `Finding` JSON. The backend contract for such runners exists
in
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
| Claude Code implementation of `/screw:scan` primary scanning | Implemented |
| Attach configured challenger review during `finalize_scan_results` | Implemented |
| `/screw:scan --challenger ... --challenger-execution dry_run\|cli` | Implemented |
| Fixture/CLI challenger mode orchestration and reconciliation | Implemented |
| Provider-neutral primary scan input/result contract | Implemented |
| Fixture primary scan runner and output validation | Implemented |
| Provider-neutral scan input assembly from YAML agent knowledge | Implemented |
| Generic/Claude/Codex CLI primary scan runner plumbing | Implemented |
| `provider-scan` package CLI and `run_provider_scan` MCP tool | Implemented |
| Optional provider-scan accumulation/finalization path | Implemented |
| Fixture manual validation for provider-neutral primary scan surfaces | Passed |
| Codex primary review participant over supplied findings | Implemented at challenger-orchestrator level |
| Codex as first-pass scanner from YAML agent knowledge | Public CLI/MCP path implemented; one live vulnerable/patched benchmark round trip passed |
| Claude as first-pass scanner from YAML agent knowledge through provider-scan | Public CLI/MCP path implemented; production adapter extracts Claude `structured_output.findings`; one live vulnerable/patched benchmark round trip passed |
| Backend composed primary-plus-challenger workflow | Implemented for configured provider primary scan plus challenger finalization |
| Parallel independent first-pass scans with reconciliation | Backend workflow implemented with fixture coverage |
| Parallel independent first-pass scans with live Claude/Codex reconciliation | Passed |
| Gemini/local as first-pass scanner from YAML agent knowledge | Pending adapter |
| Provider-neutral primary selection in universal `/screw:scan` UX | Implemented; route-equivalent fixture validation passed |
| Repo-local Codex plugin metadata for shared `/screw:*` commands | Implemented |
| Manual round-trip validation of all Phase 5 backend modes | Passed |
| Live host-route validation for provider-primary/composed/parallel flags | Pending decision |

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
- Command invocation is shell-free. Generic CLI output remains strict JSON;
  Claude and Codex runners normalize known provider envelopes before using the
  shared `parse_primary_scan_output` validator.
- Live/manual CLI validation passed for one MLflow MoreFixes vulnerable/patched
  SSTI benchmark round trip with both Codex and Claude. Codex used strict
  structured output from `codex exec`; Claude emitted findings under
  `structured_output.findings`, which is now production runner behavior.

### P5-P4 - MCP/CLI Surface

- Status: implemented.
- Added `screw-agents provider-scan`.
- Added MCP tool `run_provider_scan`.
- Added MCP tools `run_composed_provider_scan` and
  `run_parallel_provider_scan`.
- Public surface supports fixture execution and opt-in configured CLI
  transports. API/local transports are still rejected until adapters exist.
- Public surface can optionally accumulate returned findings and finalize
  normal `.screw/findings/` reports.
- Keep `/screw:scan` as the universal assistant-facing scan command, not a
  Claude-only frontend. The current Claude Code plugin is one implementation;
  future Codex, Gemini, local assistant, and web-app worker integrations should
  use the same MCP/backend semantics.
- `/screw:scan` now exposes explicit `--primary-provider`,
  `--primary-transport`, `--primary-execution`, and `--parallel-providers`
  flags that route to these provider scan MCP tools.

### P5-P5 - Parallel Scan Reconciliation

- Status: backend workflow implemented.
- Runs multiple primary providers independently using the same YAML-derived
  primary scan input assembly.
- Returns provider-keyed findings plus agreed/disputed/unique reconciliation
  summaries.
- Preserves provider provenance in the backend result object and, when
  finalization is requested, writes normal `.screw/findings/` reports with
  parallel reconciliation metadata.
- Provider-primary, primary-plus-challenger, and parallel finalized reports use
  mode-aware filename prefixes such as `sqli-codex-primary-*`,
  `sqli-codex-primary-claude-challenger-*`, and
  `sqli-parallel-claude-codex-*`.

### P5-P6 - Manual Round-Trip Validation

- Status: in progress.
- Fixture-mode provider-neutral primary scan validation is recorded in
  `docs/PHASE_5_MANUAL_VALIDATION.md`.
- Live Codex and Claude CLI primary scan validation is recorded for one real
  vulnerable/patched benchmark case.
- Backend composed primary-plus-challenger workflow is implemented with fixture
  coverage for Codex-primary/Claude-challenger and
  Claude-primary/Codex-challenger directions.
- Live composed primary-plus-challenger validation is recorded for both
  Codex-primary/Claude-challenger and Claude-primary/Codex-challenger on the
  MLflow MoreFixes SSTI vulnerable/patched pair.
- Backend parallel primary reconciliation workflow is implemented with fixture
  coverage for agreed, unique, and severity-disputed findings.
- Live parallel validation is recorded for the MLflow MoreFixes SSTI
  vulnerable/patched pair: Claude and Codex independently reported the
  vulnerable SSTI and reconciled as agreed; both returned zero findings for
  the patched target.
- Route-equivalent fixture validation for the new assistant command routes is
  recorded for single provider-primary, primary-plus-challenger, and
  parallel-provider paths.
- Real Claude Code and Codex host-route fixture validation is recorded for
  provider-primary, primary-plus-challenger, and parallel-provider paths.
- Record final signoff in `docs/PHASE_5_CLOSURE_READINESS.md`.

## Phase 5 Closure Dependencies

Phase 5 closure has been signed off with these outcomes:

- Provider-neutral primary scan runner implemented.
- Codex and Claude first-pass scans from YAML knowledge validated beyond the
  single benchmark round trip already recorded.
- All three required modes validated:
  - Claude primary, Codex challenger. Passed in live CLI validation.
  - Codex primary, Claude challenger. Passed in live CLI validation.
  - parallel independent scans with reconciliation. Fixture and live CLI
    validation passed.
- Manual round-trip checklist recorded.
- Provider-specific CLI output adapters implemented without temporary wrappers.
- `/screw:scan` provider-neutral primary scanner selection is manually
  validated across Claude Code, with the equivalent Codex skill route
  validated through `screw:screw-scan`.
- API/local/additional provider adapter deferrals explicitly documented.
- Phase 5.5 handoff surfaces documented for web application integration in
  `docs/PHASE_5_5_WEB_APP_INTEGRATION.md`.
- Closure decision recorded in `docs/PHASE_5_CLOSURE_READINESS.md`.
