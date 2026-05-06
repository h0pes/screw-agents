# Phase 5.5 Web App Integration

> Status: entry document for Phase 5.5 planning.
> Last updated: 2026-05-06.

## Purpose

Phase 5.5 integrates the validated `screw-agents` provider-neutral backend into
an external web application repository. Phase 5 closed the assistant/provider
core; Phase 5.5 should consume that core through stable boundaries rather than
copying internal implementation details.

## Repository Boundary

Planning and handoff documentation can happen in this `screw-agents`
repository. Implementation work that edits the web application should happen
from the web application repository as the Codex working directory.

Recommended session split:

```bash
# screw-agents planning/docs
cd /home/marco/Programming/AI/screw-agents
codex -C /home/marco/Programming/AI/screw-agents \
  --sandbox workspace-write \
  --ask-for-approval on-request

# web application implementation
cd /path/to/web-application-repo
codex -C /path/to/web-application-repo \
  --sandbox workspace-write \
  --ask-for-approval on-request
```

The web application session must reference `screw-agents` explicitly through
one of these integration boundaries:

- MCP server launched from the local `screw-agents` checkout.
- Package CLI/subprocess invocation.
- A local path dependency only if the web app truly needs Python imports.

Prefer MCP or package CLI boundaries first. Avoid importing private
`screw_agents` internals from the web app unless a reviewed adapter layer is
added.

## Stable Backend Surfaces

The web app should treat these as the first integration candidates:

| Capability | Surface |
|---|---|
| Domain/agent discovery | MCP `list_domains`, `list_agents` |
| Scope parsing | MCP `resolve_scope` |
| YAML/MCP scan flow | MCP `scan_agents`, `scan_domain`, `get_agent_prompt` |
| Provider-primary scan | MCP `run_provider_scan` |
| Primary plus challenger | MCP `run_composed_provider_scan` |
| Parallel providers | MCP `run_parallel_provider_scan` |
| Finding persistence/reporting | MCP `accumulate_findings`, `finalize_scan_results`, `format_output` |
| Challenger-only review | MCP `challenger_dry_run`, `challenger_run` |
| Learning/exclusions | MCP `record_exclusion`, `check_exclusions`, `aggregate_learning` |
| Adaptive scripts | MCP staging, lint, promote/reject, execute, sweep, and trust tools |

The package CLI can be used for worker jobs where MCP is inconvenient:

- `screw-agents provider-scan`
- `screw-agents challenger-dry-run`
- `screw-agents challenger-run`
- existing trust/adaptive/learning CLI surfaces as needed.

## Output Contract

The web app should store and index normal `.screw/findings/` reports instead of
inventing a parallel result format.

Important properties:

- JSON is the canonical machine-readable report.
- Markdown is useful for human review.
- SARIF can feed code-scanning integrations.
- CSV is finding-only and intentionally omits rich mode/challenger metadata.
- Provider-primary, primary-plus-challenger, and parallel scans use
  mode-aware filenames and `scan_metadata.report` labels.
- Parallel scans include reconciliation metadata in JSON/Markdown/SARIF.
- Findings continue to use the shared `Finding` model shape.

## Privacy And Cost Defaults

Keep Phase 5's defaults:

- Subscription-backed CLI execution is the default user path for Claude/Codex.
- API-backed transports remain opt-in adapter work.
- Do not send source externally unless the configured provider transport
  explicitly declares that behavior and the user has consented.
- Preserve `ANTHROPIC_API_KEY` unset behavior for Claude Code subscription
  workflows unless the user explicitly chooses API billing.

## Trust, Learning, And Adaptive Constraints

The web app must surface these controls rather than hiding them:

- Signed false-positive exclusions can be active, quarantined, or absent.
- Adaptive scripts require staged review and trust verification before
  promotion/execution.
- Phase 3c sandbox hardening is still a production-like deployment blocker.
- The app should show trust/quarantine counts from scan/finalize results.
- Learning actions should map back into `screw-agents` exclusion/learning
  artifacts, not app-only state.

## Initial Phase 5.5 Questions

Before editing web application code, answer these in the web app repository:

- Will scan execution run in a background worker, request handler, or separate
  service?
- Will the web app talk to `screw-agents` through MCP stdio, a long-lived MCP
  process, or package CLI subprocesses?
- Where will `.screw/` project artifacts live for uploaded repositories or
  checked-out projects?
- How will the UI present provider mode, challenger results, reconciliation,
  exclusions, and coverage gaps?
- Which actions require explicit user consent before source leaves the machine?
- How will the app handle long-running scans, pagination, cancellation, and
  stale worker recovery?

## Phase 5.5 Entry Criteria

Phase 5.5 can start when:

- The web app repository path is known.
- A fresh Codex session is launched from that web app repository.
- The integration boundary to this `screw-agents` checkout is selected.
- The first implementation PR is scoped to one thin vertical slice, preferably
  discovery plus one fixture-backed scan path before live provider execution.
