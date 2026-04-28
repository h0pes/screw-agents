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

Phase 3b is closed. All Phase 4 prerequisites are complete except D-01.

Next milestone:
- Phase 4 step 4.0: D-01 Rust benchmark corpus.
- Read `docs/DECISIONS.md` ADR-014 before planning or implementing D-01.
- Also read `docs/PROJECT_STATUS.md`, `docs/DEFERRED_BACKLOG.md`, and
  `docs/research/benchmark-tier4-rust-modern.md` before starting Phase 4 work.

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
