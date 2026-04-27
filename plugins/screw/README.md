# screw-agents plugin

Universal security scanning for Claude Code via the `screw-agents` MCP server.

## Slash command: `/screw:scan`

### Quick reference

| Form | Example | Semantics |
|---|---|---|
| Bare-token (agent) | `/screw:scan sqli src/` | Single registered agent |
| Bare-token (domain) | `/screw:scan injection-input-handling src/` | All agents in a CWE-1400 domain |
| Full | `/screw:scan full src/` | All registered agents |
| Prefix-key (domain) | `/screw:scan domains:foo,bar src/` | Multiple domains in full mode |
| Prefix-key (agent) | `/screw:scan agents:sqli,xss src/` | Explicit agent subset |
| Prefix-key (mixed) | `/screw:scan domains:foo agents:bar,baz src/` | Domain in full + explicit subset |

### Flags

- `--adaptive` — interactive runtime-probe flow for context-required gaps
- `--no-confirm` — skip pre-execution confirmation (CI mode)
- `--thoroughness standard|deep` — scan depth (default `standard`)
- `--format json|markdown|csv|sarif` — single format; default emits `json+markdown+csv`
- `--help` — print grammar + flags + discovery + examples and exit

### Discovery

- `mcp__screw-agents__list_domains` — registered domains
- `mcp__screw-agents__list_agents` — registered agents (optional `domain` filter)
- `/screw:scan --help` — full grammar + examples

### Subagents

- `screw-scan` (universal) — runs the agents list against the target; replaces 5 retired per-agent + per-domain subagents
- `screw-script-reviewer` — adaptive runtime-probe review chain
- `screw-learning-analyst` — learning-mode analyst

### MCP tools (post-T-SCAN-REFACTOR)

- `scan_agents`, `scan_domain` — paginated scan primitives
- `resolve_scope` — slash command parser
- Plus 20 supporting tools (see `/mcp`)

For full architecture, see `docs/PRD.md` in the parent repo.
