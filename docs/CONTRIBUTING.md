# Contributing to screw-agents

TODO: Full contribution guidelines will be written during Phase 6 (Agent Expansion & Ecosystem).

For YAML agent authoring, see `docs/AGENT_AUTHORING.md`.

## Development workflow

### Loading screw-agents as an assistant plugin

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

- `/screw:scan <agent | domain | full | domains:foo,bar | agents:baz,qux> [target] [--adaptive | --no-confirm]` — security scan (post-T-SCAN-REFACTOR multi-scope syntax; `--adaptive` and `--no-confirm` are mutually exclusive)
- `/screw:learn-report` — learning aggregation report (Phase 3a PR#2+)
- `/agents` lists `screw-scan` (universal scan runner), `screw-script-reviewer`
  (adaptive review chain), `screw-learning-analyst` (learning mode)

After editing a command, agent, or skill file, run `/reload-plugins` inside
Claude Code to pick up changes without restarting.

Multiple `--plugin-dir` flags can be stacked if you're testing more than
one plugin at a time.

screw-agents also ships Codex plugin metadata at
`plugins/screw/.codex-plugin/plugin.json` and a repo-local marketplace
descriptor at `.agents/plugins/marketplace.json`. Register the local
marketplace and MCP server during development with:

```bash
codex plugin marketplace add /path/to/screw-agents
codex mcp add screw-agents -- uv run --directory /path/to/screw-agents screw-agents serve --transport stdio
```

Because this is a local marketplace entry, Codex reads the configured root
path directly. Open `/plugins` inside Codex and enable `screw-agents` after
adding the marketplace; restart Codex after editing plugin metadata, commands,
agents, or skills. Use `codex mcp list` and `codex mcp get screw-agents` to
verify the backend registration.

Codex caches local plugins by manifest version under `~/.codex/plugins/cache`.
When changing Codex-visible plugin metadata or skill behavior, bump
`plugins/screw/.codex-plugin/plugin.json` so a restart loads the new copy.
Codex reusable workflow instructions should be packaged as skills; custom
prompts are deprecated in current OpenAI Codex docs.

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
this project, regardless of `--plugin-dir`. The Codex plugin also includes a
repo-local `plugins/screw/.mcp.json` for local marketplace development. For
external marketplace distribution, we'll need to publish `screw-agents` to PyPI
and switch the plugin-scoped MCP command to `uvx screw-agents serve`. See the
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
| Register local Codex marketplace | `codex plugin marketplace add /path/to/screw-agents` |
| Enable local Codex plugin | `/plugins` inside Codex, then enable `screw-agents` |
