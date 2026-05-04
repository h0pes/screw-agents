# Phase 5 Plan - Multi-LLM Challenger System

> Status: in progress. P5-1 challenger config/model contracts are merged;
> P5-2 reconciliation engine is implemented; P5-3 provider runner interface
> and fixture runner are implemented; P5-4 required-mode orchestration is
> implemented with fixture-backed runners; subscription-backed CLI runner
> plumbing plus Claude/Codex CLI API-key isolation are implemented; runner
> factory wiring from config is implemented; the first fixture-only
> user-facing dry-run execution surface is implemented.
> Last updated: 2026-05-04.

Phase 5 adds multi-LLM secure-code-review execution without making Claude,
Codex, Anthropic, or OpenAI permanent architectural assumptions. The durable
asset remains provider-neutral YAML agent knowledge in `domains/**/*.yaml`;
provider runners are replaceable execution adapters.

## Goals

- Ship all three required Phase 5 modes:
  - Claude primary, Codex challenger.
  - Codex primary, Claude challenger, using the same YAML agent knowledge.
  - Parallel independent review with reconciliation.
- Keep provider support open-ended. Gemini, local LLMs, or future assistants
  must be addable through configuration plus a thin adapter, not a scan-engine
  rewrite.
- Support multiple execution transports per provider:
  - subscription-backed CLI or local assistant execution, such as Claude Code
    Pro or Codex Pro;
  - API-backed execution for users with provider API credits;
  - local model execution when an adapter can satisfy the same structured
    contract.
- Preserve explicit privacy, cost, and provider controls. No challenger or
  second-provider execution runs by default.
- Feed disagreement evidence into autoresearch as reviewed input, never as
  automatic YAML mutation.

## Non-Goals

- Do not build a bespoke REST API for Phase 5. The public integration boundary
  remains MCP unless a later design justifies another surface.
- Do not assume Anthropic or OpenAI API credits are available.
- Do not require API keys for the common local developer workflow when a
  subscription-backed CLI transport is available.
- Do not make provider-specific prompt formats leak into the YAML agent
  schema.
- Do not broaden the accepted agent set beyond `sqli`, `cmdi`, `ssti`, and
  `xss` as part of Phase 5.

## Design Invariants

### Provider-Neutral Core

The core Phase 5 contracts should use provider-neutral terms:

- `provider`: logical provider name, such as `anthropic`, `openai`, `google`,
  or `local`.
- `assistant`: provider-specific product or model family, such as `claude`,
  `codex`, `gemini`, or a local model profile.
- `transport`: invocation mechanism, such as `cli`, `api`, or `local`.
- `role`: `primary` or `challenger`.

The scan and reconciliation layers should depend on these contracts, not on
Claude- or Codex-specific classes.

### Transport Choice

Provider configuration must distinguish provider identity from how the provider
is invoked. A user with API credits can choose an API transport. A user with a
Pro subscription and no API credits can choose the provider's local CLI or
assistant transport when available.

Subscription-backed transports are not a fallback hack; they are first-class
Phase 5 execution paths. Benchmark and live executor commands must continue to
avoid accidental API usage. In particular, Claude Code benchmark/executor paths
must keep `ANTHROPIC_API_KEY` unset unless the user explicitly chooses an API
transport.

### Explicit Consent

Every mode that sends code or findings to a second provider requires explicit
configuration and run-time acknowledgement. Configuration should record:

- enabled providers and transports;
- whether source code may be shared with each provider;
- whether API billing is permitted;
- maximum prompt or token budget when measurable;
- whether the user has acknowledged cost and privacy implications.

### Shared Agent Knowledge

Codex-primary, Gemini-primary, or local-primary execution must use the same
YAML agent knowledge and scan assembly path as Claude-primary execution.
Provider adapters may format a provider-specific envelope around the prompt,
but they must not fork the vulnerability knowledge base.

### Documentation Alignment

Every Phase 5 implementation PR must update the relevant documentation in the
same branch as the code change. Documentation is part of the implementation,
not a follow-up cleanup task. At minimum, each PR should check whether its
change affects:

- `README.md`, for current capabilities, roadmap, and user-facing overview.
- `docs/PHASE_5_PLAN.md`, for Phase 5 task status, contracts, and guardrails.
- `docs/PROJECT_STATUS.md`, for current state and next roadmap priorities.
- `docs/PRD.md`, for product requirements or scope changes.
- `docs/ARCHITECTURE.md`, for component boundaries or lifecycle changes.
- `docs/COMMAND_REFERENCE.md`, when commands, MCP tools, CLI options, scripts,
  or user workflows change.
- `docs/AGENT_CATALOG.md` and `docs/AGENT_AUTHORING.md`, when agent dispatch,
  YAML schema, or authoring expectations change.
- `docs/DEFERRED_BACKLOG.md`, when work is intentionally deferred, retired, or
  promoted into the current phase.

If a document is reviewed and does not need a change, the PR summary should say
so when that decision is not obvious.

## Proposed Configuration Shape

```yaml
challenger:
  enabled: false
  consent:
    cost_acknowledged: false
    privacy_acknowledged: false
    api_billing_allowed: false
    source_sharing_allowed: false

  providers:
    claude:
      assistant: claude
      transports:
        cli:
          kind: cli
          enabled: true
          command: claude
          use_api_key: false
        api:
          kind: api
          enabled: false
          api_key_env: ANTHROPIC_API_KEY
          allow_api_billing: false

    codex:
      assistant: codex
      transports:
        cli:
          kind: cli
          enabled: true
          command: codex
          use_api_key: false
        api:
          kind: api
          enabled: false
          api_key_env: OPENAI_API_KEY
          allow_api_billing: false

    gemini:
      assistant: gemini
      transports:
        api:
          kind: api
          enabled: false
          api_key_env: GOOGLE_API_KEY
          allow_api_billing: false

    local:
      assistant: local
      transports:
        local:
          kind: local
          enabled: false
          endpoint: http://127.0.0.1:11434
          sends_source_externally: false

  modes:
    claude_primary_codex_challenger:
      enabled: false
      participants:
        - {provider: claude, transport: cli, role: primary}
        - {provider: codex, transport: cli, role: challenger}
    codex_primary_claude_challenger:
      enabled: false
      participants:
        - {provider: codex, transport: cli, role: primary}
        - {provider: claude, transport: cli, role: challenger}
    parallel:
      enabled: false
      participants:
        - {provider: claude, transport: cli, role: parallel}
        - {provider: codex, transport: cli, role: parallel}
```

The exact schema can change during implementation, but these separations should
remain: provider, assistant, transport, role, billing permission, and privacy
permission.

## Work Breakdown

### P5-0 - Spec And Documentation Alignment

- Add this plan.
- Update the PRD non-goal that conflicts with Phase 5.
- Document provider replacement and transport flexibility as Phase 5
  requirements.
- Keep README and project status linked to this plan.

### P5-1 - Challenger Models

Status: merged in PR #97.

- Add Pydantic models under `src/screw_agents/challenger/`.
- Define structured inputs and outputs for:
  - primary analysis runs;
  - challenger assessments;
  - parallel participant results;
  - reconciliation summaries;
  - provider/transport metadata;
  - consent and cost/privacy guardrail state.
- Keep models serializable for JSON reports and future web-app ingestion.
- Keep `docs/PHASE_5_PLAN.md` and any affected durable docs aligned with the
  implemented model names and config schema.
- Current implementation:
  - `src/screw_agents/challenger/models.py` defines provider, transport,
    consent, mode, run input, assessment, reconciliation, and result contracts.
  - `src/screw_agents/models.py` exposes optional
    `ScrewConfig.challenger`.
  - `tests/test_challenger_models.py` validates API-billing, source-sharing,
    CLI/subscription-backed, and project-config guardrails.

### P5-2 - Reconciliation Engine

Status: implemented.

- Implement deterministic reconciliation independent of any provider:
  - agreed;
  - disputed;
  - unique;
  - uncertain;
  - unsupported because a participant failed or declined.
- Use finding identity, CWE, file, line, severity, and provider assessment
  fields rather than provider-specific prose.
- Current implementation:
  - `src/screw_agents/challenger/reconciliation.py` reconciles
    finding-shaped dictionaries and `ChallengerAssessment` records.
  - Matching uses explicit finding IDs first, then `file:line_start:CWE`.
  - Status resolution is deterministic:
    `unique` < `agreed` < `uncertain` < `disputed` < `unsupported` by the
    presence of matching assessments and verdicts.
  - `tests/test_challenger_reconciliation.py` covers stable keys, ordering,
    agreement, disputes, uncertainty, unsupported runs, unique findings, and
    confidence aggregation.

### P5-3 - Provider Runner Interface

Status: implemented.

- Define an adapter interface for provider execution.
- Support dry-run and fixture-backed runners first.
- Add CLI transport adapters before API transports so Pro/subscription-backed
  usage is not blocked on API credits.
- Require every adapter to declare:
  - whether it sends source code externally;
  - whether it may bill API credits;
  - which environment variables it reads;
  - which command it invokes, if any;
  - what budget controls it can enforce.
- Current implementation:
  - `src/screw_agents/challenger/providers.py` defines provider runner
    capability metadata, guardrail preflight reports, the provider runner
    protocol, a deterministic in-memory `FixtureProviderRunner`, a generic
    `CliProviderRunner`, `ClaudeCliProviderRunner`, and
    `CodexCliProviderRunner`.
  - Fixture runs never invoke external commands, APIs, or local model
    endpoints.
  - CLI runners invoke configured commands as argv without `shell=True`, pass
    the provider prompt on stdin, parse structured JSON output, and convert
    non-zero exits into unsupported assessments.
  - `ClaudeCliProviderRunner` removes `ANTHROPIC_API_KEY` from its execution
    environment so subscription-backed Claude CLI use does not accidentally
    switch to API-key billing.
  - `CodexCliProviderRunner` removes `OPENAI_API_KEY` from its execution
    environment so subscription-backed Codex CLI use does not accidentally
    switch to API-key billing.
  - `tests/test_challenger_providers.py` validates capability extraction,
    API-billing/source-sharing guardrails, fixture isolation, assessment
    filtering, and reconciliation compatibility.
  - `tests/test_challenger_cli_providers.py` validates shell-free command
    invocation, structured output parsing, source-sharing preflight,
    failure-to-unsupported behavior, invalid output rejection, and Claude/Codex
    API-key environment isolation.

### P5-4 - Required Modes

Status: implemented.

- Implement Claude primary / Codex challenger.
- Implement Codex primary / Claude challenger.
- Implement parallel independent review with reconciliation.
- Keep each mode opt-in and testable with fixture runners.
- Current implementation:
  - `src/screw_agents/challenger/orchestrator.py` runs one configured mode
    through explicitly injected provider runners.
  - `src/screw_agents/challenger/runner_factory.py` builds those runner maps
    from `ChallengerConfig` for a selected mode.
  - The orchestrator supports primary/challenger and parallel participant
    roles without provider-specific branches.
  - The runner factory selects `ClaudeCliProviderRunner`,
    `CodexCliProviderRunner`, `FixtureProviderRunner`, or generic
    `CliProviderRunner` based on provider/transport configuration.
  - API and local transports are rejected with clear errors until their
    adapters exist.
  - All participants are preflighted before any runner executes; if cost or
    privacy guardrails block a participant, no runner is invoked and the
    result records structured guardrail blockers.
  - `tests/test_challenger_orchestrator.py` validates Claude-primary,
    Codex-primary, and parallel fixture modes, plus guardrail blocks, missing
    runners, and disabled modes.
  - `tests/test_challenger_runner_factory.py` validates config-driven runner
    selection, required-mode wiring, fixture payload wiring, API rejection, and
    injectable CLI command execution without live provider invocation.

### P5-5 - Output And MCP Surface

Status: in progress. The first user-facing execution surface is the
fixture-only `screw-agents challenger-dry-run` CLI command, which runs a
configured mode through the runner factory and refuses live CLI, API, or local
transports. This validates mode wiring and JSON output shape without provider
invocation or API spend.

- Enrich JSON and Markdown output with provider perspectives and consensus
  state without breaking existing finding consumers.
- Preserve SARIF compatibility by keeping provider-specific challenger details
  in properties when exported.
- Add live CLI/API execution and MCP tools only after the dry-run surface,
  output shape, and consent guardrails are stable.
- Update `README.md`, `docs/COMMAND_REFERENCE.md`, and architecture/status docs
  in the same PR when new MCP tools, CLI options, plugin commands, or output
  fields become user-facing.

### P5-6 - Autoresearch Feedback

- Store challenger disagreements as reviewed evidence for future
  autoresearch.
- Do not mutate `domains/**/*.yaml` automatically from disagreements.
- Require concrete examples and human review before any YAML change, matching
  the Phase 4 closure discipline.

## Verification Strategy

- Unit-test provider-neutral models and reconciliation logic with fixture
  findings.
- Add guardrail tests showing API transports are disabled unless explicitly
  enabled.
- Add tests that subscription-backed CLI transports do not require API key
  environment variables.
- Add tests that Claude CLI benchmark/executor paths keep `ANTHROPIC_API_KEY`
  unset unless an API transport is explicitly selected. Current coverage
  verifies this for the Phase 5 Claude CLI provider runner; analogous
  `OPENAI_API_KEY` isolation is covered for the Codex CLI provider runner.
  Benchmark/executor integration remains pending.
- Use fixture runners for mode orchestration before invoking real assistants.
- Run the full suite before merging implementation PRs.
- Before opening a Phase 5 PR, review the durable docs listed in
  "Documentation Alignment" and update every one affected by the code change.

## Phase 5.5 Compatibility

The web application pilot needs machine-readable outputs, background execution,
triage, and learning feedback. Phase 5 should therefore keep result objects
stable, JSON-friendly, and independent of Claude Code plugin assumptions. The
web app should be able to choose the same provider/transport configuration
without a bespoke REST API.
