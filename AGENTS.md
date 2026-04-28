# Codex Instructions — screw-agents

## Project Identity

`screw-agents` is a modular secure-code-review system. The durable value is the
curated vulnerability knowledge in `domains/**/*.yaml`; the Python MCP server is
the shared backend used by Claude Code, future clients, CI, and eventually
`screw.nvim`.

Primary stack:
- Python 3.11+ for the MCP server and benchmark infrastructure.
- YAML for vulnerability agent definitions.
- Markdown for Claude Code plugin agents, skills, and commands.
- `uv` for dependency and command execution. Do not use bare `pip install`.

## Current State

Phase 4 step 4.0 / D-01 is merged via PR #17. Phase 4 D-02 dry-run planning,
gate correction, failure-input schema, and controlled-run scaffold are merged
via PR #18. Dataset readiness closure is active on branch
`phase4-d02-readiness`.

Next milestone:
- Phase 4 autoresearch / D-02 dataset readiness materialization before any
  paid controlled benchmark execution.
- Before planning Phase 4 follow-on work, read `docs/PROJECT_STATUS.md`,
  `docs/DEFERRED_BACKLOG.md`, `docs/PHASE_4_D01_PLAN.md`, and
  `docs/PHASE_4_D02_PLAN.md`.
- Keep Rust metric claims scoped: real-CVE Rust coverage currently exists for
  SQLi/CmdI/XSS; Rust SSTI is synthetic-only unless refresh finds a verified
  real advisory.
- Use `benchmarks/scripts/check_autoresearch_readiness.py` to produce the
  no-execution readiness checklist before asking Marco to materialize datasets
  or allow Claude invocation.

Current implemented agent set:
- `sqli`
- `cmdi`
- `ssti`
- `xss`

Current scan surface:
- Use `scan_agents` as the primary paginated primitive.
- `scan_domain` is a thin convenience wrapper over `scan_agents`.
- Do not reintroduce retired tools: `scan_full`, `scan_sqli`, `scan_cmdi`,
  `scan_ssti`, or `scan_xss`.

## Working Rules

- Prefer repository patterns over new abstractions.
- Keep changes narrowly scoped to the task.
- Use `rg` / `rg --files` for search.
- Use `apply_patch` for manual file edits.
- Do not revert user changes.
- No AI attribution or `Co-Authored-By` trailers in commits.
- Use dedicated git worktrees for implementation branches unless Marco says
  otherwise.
- Before running `uv run` in a new worktree, run `uv sync` inside that worktree.
- For costly or long-running commands, inspect the code path first and verify
  assumptions before asking Marco to run anything.

## PR And Worktree Workflow

Use this sequence for feature branches unless Marco gives different
instructions:

1. Implement and test in a dedicated worktree, not in the main checkout.
2. Keep docs aligned with code before opening the PR.
3. Before pushing, run `git status --short --branch` in both the worktree and
   the main checkout.
4. Push the feature branch from the worktree:
   `git push -u origin <branch>`.
5. Create the PR with a concise summary and verification notes.
6. Check PR mergeability and checks. If GitHub reports no checks, state that
   explicitly.
7. Merge from the main checkout, not from a worktree whose branch is checked
   out elsewhere.
8. After merge, align local main with `git pull --ff-only origin main`.
9. Remove the worktree from the main checkout:
   `git worktree remove .worktrees/<branch>`.
10. Delete the local branch: `git branch -d <branch>`.
11. Delete the remote branch if GitHub did not already do it:
    `git push origin --delete <branch>`.
12. Final verification from main: `git status --short --branch`,
    `git worktree list`, and confirm no local/remote feature branch remains.

Prefer a normal merge commit when the branch includes local main-only commits
that should fast-forward cleanly after PR merge. Use squash only when Marco
explicitly wants a single squashed history and local main alignment has been
considered.

## Security Review Discipline

Security-sensitive artifacts are not limited to Python code. Treat all of these
as security-relevant and review them rigorously:
- `plugins/screw/agents/*.md`
- `plugins/screw/commands/*.md`
- `plugins/screw/skills/**/SKILL.md`
- `domains/**/*.yaml`
- trust, signing, sandboxing, staging, and adaptive-script code

Never silently downgrade a security recommendation. If a stronger defense is
available but appears out of scope, surface that as an explicit decision point.

## Documentation And Backlog

Durable docs:
- `docs/PRD.md`
- `docs/DECISIONS.md`
- `docs/ARCHITECTURE.md`
- `docs/PROJECT_STATUS.md`
- `docs/DEFERRED_BACKLOG.md`
- `docs/AGENT_AUTHORING.md`
- `docs/AGENT_CATALOG.md`

Working docs:
- `docs/specs/` is local working material and is gitignored.
- Most `docs/research/*` files are local working material and are gitignored.
- Tracked benchmark research docs are the exception:
  `docs/research/benchmark-*.md`.

The backlog is intentionally broad. Before Phase 4 work, check for true
blockers only; do not pull cosmetic or minor backlog items into the critical
path unless they affect benchmark/autoresearch correctness.

## Platform Notes

Marco develops on Arch Linux. macOS-specific code may be written per spec, but
macOS tests skip locally. Do not claim macOS runtime validation unless it was
actually run on macOS.

Benchmark and live-LLM runs can be expensive and slow. `ANTHROPIC_API_KEY`
should be unset before Claude CLI benchmark invocations so the Pro subscription
is used instead of paid API usage.
