# Contributing to screw-agents

TODO: Full contribution guidelines will be written during Phase 6 (Agent Expansion & Ecosystem).

For YAML agent authoring, see `docs/AGENT_AUTHORING.md`.

## Development workflow

### Loading screw-agents as a Claude Code plugin (recommended)

screw-agents ships as a Claude Code plugin with manifest at
`plugins/screw/.claude-plugin/plugin.json`. During development, load it via
the `--plugin-dir` flag so commands and agents appear under the proper
`screw:` namespace, matching what end users experience on a marketplace
install.

```bash
cd /path/to/screw-agents
claude --plugin-dir ./plugins/screw
```

Inside Claude Code you'll then see:

- `/screw:scan <sqli|cmdi|ssti|xss|injection|full> [target]` — security scan
- `/screw:learn-report` — learning aggregation report (Phase 3a PR#2+)
- `/agents` lists `screw-sqli`, `screw-cmdi`, `screw-ssti`, `screw-xss`,
  `screw-injection`, `screw-full-review`, `screw-learning-analyst`

After editing a command, agent, or skill file, run `/reload-plugins` inside
Claude Code to pick up changes without restarting.

Multiple `--plugin-dir` flags can be stacked if you're testing more than
one plugin at a time.

### Why `--plugin-dir` instead of `.claude/commands/` symlinks

The project previously used symlinks at `.claude/commands/scan.md` →
`plugins/screw/commands/scan.md` (and equivalents for skills) to make the
plugin content available during development. That worked, but it registered
commands through Claude Code's standalone (project-local) configuration
path, which does NOT apply plugin namespacing — users saw `/scan` in dev
but would see `/screw:scan` on a marketplace install. The two paths
disagreed on the slash-command string.

Per the official docs (https://code.claude.com/docs/en/plugins), the
`--plugin-dir` flag is the supported way to load a plugin from a local
directory during development without requiring marketplace installation.
It gives you the EXACT same registration path end users get on install —
including the `screw:` namespace — so what you see in dev matches
production.

The old `.claude/commands/scan.md` and `.claude/skills/screw-research` /
`.claude/skills/screw-review` symlinks were removed in the Phase 3a PR#2
namespace cleanup. If your local main checkout still has leftover
`.claude/commands/scan.md` (not tracked in git), you can safely delete it.

### Running the MCP server

The `.mcp.json` at the repo root declares the screw-agents MCP server
(project-scoped). Claude Code starts it automatically when launched in
this project, regardless of `--plugin-dir`. For a future marketplace
distribution, we'll need to publish `screw-agents` to PyPI and ship a
plugin-scoped `.mcp.json` using `uvx screw-agents serve`. See the
DEFERRED_BACKLOG entry `T-PLUGIN-M1` for details.

### Running tests

```bash
uv run pytest -q            # full suite
uv run pytest tests/test_aggregation.py -v   # single module, verbose
```

### Common dev commands

| Goal | Command |
|---|---|
| Reload plugin content after edits | `/reload-plugins` inside Claude Code |
| List loaded agents | `/agents` inside Claude Code |
| See raw plugin-loading errors | `claude --debug --plugin-dir ./plugins/screw` |
| Validate plugin manifest syntax | `claude plugin validate ./plugins/screw` |
