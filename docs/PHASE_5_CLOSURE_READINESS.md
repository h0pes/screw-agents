# Phase 5 Closure Readiness

> Status: draft for Marco review. This document consolidates the Phase 5
> implementation and validation evidence into one closure decision checklist.
> It is intentionally decision-oriented: each remaining item is classified as
> closure blocker, explicit deferral, or follow-up candidate.
> Last updated: 2026-05-06.

## Purpose

Phase 5 set out to make `screw-agents` provider-neutral instead of
Claude-only. The durable requirement is that the same YAML agent knowledge can
drive first-pass scans and challenger review across supported assistants and
transports, with explicit privacy and cost controls.

This document does not replace the detailed implementation plans or validation
logs. It is the single page to use when deciding whether Phase 5 can be signed
off and whether remaining work moves to Phase 5.5, a Phase 5.x hardening pass,
or the deferred backlog.

Primary references:

- `docs/PHASE_5_PLAN.md`
- `docs/PHASE_5_PRIMARY_SCANNER_PLAN.md`
- `docs/PHASE_5_MANUAL_VALIDATION.md`
- `docs/PROJECT_STATUS.md`
- `docs/DEFERRED_BACKLOG.md`

## Required Phase 5 Outcomes

| Outcome | Status | Evidence |
|---|---|---|
| Provider-neutral primary scan input from YAML agent knowledge | Green | `ScanEngine.assemble_primary_scan_input`, `PrimaryScanInput`, provider scan tests |
| Claude first-pass scanner via subscription-backed CLI | Green | Live MLflow SSTI vulnerable/patched validation |
| Codex first-pass scanner via subscription-backed CLI | Green | Live MLflow SSTI vulnerable/patched validation |
| Claude primary, Codex challenger | Green | Live composed validation: vulnerable finding agreed, patched zero findings |
| Codex primary, Claude challenger | Green | Live composed validation: vulnerable finding agreed, patched zero findings |
| Parallel Claude/Codex independent scans and reconciliation | Green | Live parallel validation: vulnerable finding reconciled as `agreed`, patched zero findings |
| Normal report integration for provider findings | Green | Provider-scan, composed, and parallel finalization write normal `.screw/findings/` reports with mode-aware filenames and metadata |
| Provider privacy/cost controls | Green | CLI execution requires explicit consent; API billing remains opt-in and rejected without consent |
| Provider-neutral command contract | Green | `/screw:scan` flags for provider-primary, composed, and parallel routes are documented and route-equivalent fixture validated |
| Host-agnostic project direction beyond `/screw:scan` | Green as architecture, yellow as host UX | Shared MCP/package/skill surfaces exist; per-host command affordances still vary |

## Validation Evidence

| Validation | Status | Notes |
|---|---|---|
| Fixture provider-scan package CLI | Passed | Validated from `/tmp` project |
| MCP `run_provider_scan` fixture path | Passed | Dispatcher validation recorded |
| Provider-scan accumulation/finalization | Passed | Fixture and live provider outputs wrote reports |
| Mode-aware report naming and metadata | Passed | Provider-primary, primary-plus-challenger, and parallel reports include provider/mode labels in filenames and JSON/Markdown/SARIF metadata |
| Claude live primary scan | Passed | MLflow MoreFixes SSTI vulnerable/patched pair |
| Codex live primary scan | Passed | MLflow MoreFixes SSTI vulnerable/patched pair |
| Claude primary plus Codex challenger | Passed | Live composed validation |
| Codex primary plus Claude challenger | Passed | Live composed validation |
| Parallel Claude/Codex scan reconciliation | Passed | Live parallel validation |
| Codex MCP-backed YAML scan skill | Passed | `screw:screw-scan` executed MCP scan/finalize flow and wrote JSON |
| Claude Code plugin command discovery | Passed for current Claude host | `/screw:scan` command and MCP tools visible in manual host validation |
| Route-equivalent provider command validation | Passed | Fixture validation reached all provider-primary MCP workflows |

## Remaining Decisions

| Item | Current state | Recommended closure classification | Rationale |
|---|---|---|---|
| Live host validation for provider-primary `/screw:scan` routes | Not yet recorded end-to-end from assistant command UX | Closure blocker unless explicitly accepted as covered by route-equivalent fixture validation | The backend and command contract are implemented, but we have not yet recorded a live host session invoking provider-primary/composed/parallel flags through the assistant-facing command path. |
| Codex literal `/screw:*` autocomplete | Host limitation tracked | Not a Phase 5 closure blocker; document as host-adapter backlog | Codex currently exposes plugin skills and MCP tools, but not Claude-style slash command autocomplete. The universal command contract still exists through skills/MCP/package surfaces. |
| Additional provider adapters: Gemini, opencode, local LLMs | Not implemented | Not a Phase 5 closure blocker; defer to Phase 5.x or later adapter work | Phase 5 created the provider-neutral contracts and proved Claude/Codex. Adding every future provider is open-ended and should not block closure. |
| API transports for Claude/Codex primary scan | Explicitly not implemented for live provider scan | Not a Phase 5 closure blocker; defer with privacy/cost controls preserved | Marco's current workflow uses Pro subscriptions and no API credits. API transports should remain opt-in future adapters. |
| Local transport adapter | Not implemented | Not a Phase 5 closure blocker; defer | Local model quality, sandboxing, and structured-output reliability need separate adapter design. |
| Provider-specific temporary validation wrappers | Promoted behavior implemented in production runners; live temp scripts still exist only in `/tmp` | Not a blocker if production code remains wrapper-free | The production runners now handle the observed Claude/Codex output shapes; `/tmp` wrappers are validation harnesses, not product code. |
| Phase 5.5 web app integration handoff | Architecture surfaced, not yet implemented | Not a Phase 5 blocker; next phase entry criterion | Phase 5.5 starts after provider-neutral execution is stable enough to integrate. |
| Phase 3c sandbox hardening | Deferred | Not a Phase 5 blocker, but production-like deployment blocker | Keep visible before production-like deployments, especially for adaptive scripts. |

## Proposed Closure Gate

Phase 5 can be marked complete when Marco accepts one of these two options:

1. **Strict closure path.** Run one final manual host-route validation that
   invokes provider-primary, composed, and parallel scan routes from supported
   assistant hosts using the current plugin/skill/MCP surfaces, then update
   this document from draft to closure-ready.
2. **Pragmatic closure path.** Accept route-equivalent fixture validation plus
   direct live backend validation as sufficient for Phase 5, and explicitly
   defer host-specific UX polish and additional provider adapters to Phase 5.x
   or the backlog.

Recommended path: **strict closure path**. The remaining work is mostly
validation/documentation rather than new architecture, and it reduces ambiguity
before Phase 5.5 web application integration.

## Exit Criteria Checklist

| Criterion | Status |
|---|---|
| All three required modes implemented | Green |
| All three required modes live validated with Claude/Codex | Green |
| Provider-neutral primary scan runner validates output through shared `Finding` models | Green |
| Privacy/cost controls are explicit and opt-in | Green |
| Reports identify whether they came from provider-primary, primary-plus-challenger, or parallel mode | Green |
| Docs are aligned with code and validation reality | Green for current PR, keep current |
| Host-route provider-primary/composed/parallel validation decision made | Yellow |
| API/local/additional-provider adapter deferrals explicitly accepted | Yellow |
| Phase 5.5 handoff surfaces confirmed | Yellow |

## Recommended Next Step

After this document is reviewed, decide whether to run the strict host-route
validation PR or accept the pragmatic closure path. If strict validation is
chosen, the next PR should record:

- Claude Code host route for provider-primary/composed/parallel flags.
- Codex skill/MCP route for equivalent provider-primary/composed/parallel
  flows, with the literal `/screw:*` autocomplete limitation called out.
- Confirmation that no API keys are required for subscription-backed CLI paths.
