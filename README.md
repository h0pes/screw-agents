# screw-agents

Modular secure-code-review agents built around a shared MCP server.

`screw-agents` provides vulnerability-specific security review knowledge as
YAML agents, exposes that knowledge through a Python MCP server, and ships a
Claude Code plugin that can scan codebases, write structured findings, learn
from false-positive triage, and run approved adaptive analysis scripts for
project-specific patterns.

The durable asset is the curated knowledge in `domains/**/*.yaml`. The Python
server is the common backend for Claude Code, future web application
integration, screw.nvim, CI, and other clients.

> Status: pre-alpha research/product build. Phase 4 is complete. The accepted
> active agents are `sqli`, `cmdi`, `ssti`, and `xss`.

## Why This Exists

General "review this code" prompts are too broad for serious security work.
High-quality security review needs specialist knowledge: precise CWE/CAPEC
scope, framework-specific vulnerability shapes, true-positive and false-positive
discriminators, bypass patterns, and remediation guidance.

`screw-agents` turns that knowledge into dedicated agents that can be reused
from multiple clients through the same backend.

Core goals:

- Provide dedicated agents for individual vulnerability classes.
- Organize coverage with CWE-1400 as the structural taxonomy.
- Keep agent knowledge editable and reviewable as YAML.
- Resolve scan targets consistently with tree-sitter.
- Emit structured findings in machine-readable and human-readable formats.
- Learn from false positives at project scope.
- Support adaptive analysis for unfamiliar project-specific patterns.
- Validate agent behavior with benchmark infrastructure before expanding.

## Current Capabilities

Implemented today:

- Python MCP server with stdio and streamable HTTP transports.
- Claude Code plugin under `plugins/screw`.
- Universal `/screw:scan` command.
- Four accepted vulnerability agents:
  - `sqli` — SQL injection
  - `cmdi` — OS command injection
  - `ssti` — server-side template injection
  - `xss` — cross-site scripting
- Target resolution for files, directories, globs, git diffs, commits, pull
  requests, classes, functions, and line ranges.
- Supported parser languages: Python, JavaScript, TypeScript, Go, Rust, Java,
  Ruby, PHP, C, C#, and C++.
- Output formats: JSON, Markdown, CSV, and SARIF.
- Project-local learning through `.screw/learning/exclusions.yaml`.
- Trust model for signed exclusions and adaptive scripts.
- Adaptive script staging, review, promotion, sandboxed execution, and cleanup.
- CWE-1400-native benchmark runner and controlled autoresearch workflow.
- Phase 4 calibration and closure evidence for the current agent set.

Not yet implemented:

- Phase 5 multi-LLM challenger execution.
- Phase 5.5 web application integration pilot.
- Phase 6 small-batch expansion beyond the current four agents.
- Phase 7 screw.nvim editor integration.

See [PROJECT_STATUS.md](docs/PROJECT_STATUS.md) for the current roadmap.

## Repository Layout

| Path | Purpose |
|---|---|
| `src/screw_agents/` | Python MCP server, scan engine, formatter, trust, learning, adaptive execution, autoresearch support |
| `domains/` | CWE-1400 domain folders and YAML agent definitions |
| `plugins/screw/` | Claude Code plugin: slash commands, subagents, skills, plugin manifest |
| `benchmarks/` | CWE-1400-native benchmark runner, ingest scripts, autoresearch planning/execution scripts |
| `docs/` | Architecture, product plan, agent authoring, catalog, decisions, benchmark and phase records |
| `tests/` | Core unit/integration tests |
| `benchmarks/tests/` | Benchmark infrastructure tests |
| `.mcp.json` | Project-local Claude Code MCP server configuration |

## Quick Start

Prerequisites:

- Python 3.11+
- `uv`
- Claude Code for the plugin workflow

Clone and install dependencies:

```bash
git clone https://github.com/h0pes/screw-agents.git
cd screw-agents
uv sync
```

Run tests:

```bash
uv run pytest
```

Run the MCP server over stdio:

```bash
uv run screw-agents serve --transport stdio
```

Run the MCP server over HTTP:

```bash
uv run screw-agents serve --transport http --port 8080
```

The HTTP MCP endpoint is exposed at `/mcp`.

## Claude Code Plugin Usage

During development, load the local plugin directory:

```bash
claude --plugin-dir ./plugins/screw
```

The repo root `.mcp.json` starts the MCP server with:

```json
{
  "mcpServers": {
    "screw-agents": {
      "command": "uv",
      "args": ["run", "screw-agents", "serve", "--transport", "stdio"]
    }
  }
}
```

Run a scan from Claude Code:

```text
/screw:scan sqli src/
/screw:scan injection-input-handling src/
/screw:scan agents:sqli,xss src/api/ --format markdown
/screw:scan full . --no-confirm
/screw:scan sqli src/api/ --adaptive
```

Useful plugin commands:

| Command | Purpose |
|---|---|
| `/screw:scan` | Run one or more vulnerability agents against a target |
| `/screw:learn-report` | Summarize project false-positive learning |
| `/screw:adaptive-cleanup` | Inspect and clean adaptive analysis scripts |

For all command forms and options, see
[COMMAND_REFERENCE.md](docs/COMMAND_REFERENCE.md).

## CLI Usage

The package installs the `screw-agents` command:

```bash
uv run screw-agents --help
```

Main CLI commands:

| Command | Purpose |
|---|---|
| `screw-agents serve` | Run the MCP server with stdio or HTTP transport |
| `screw-agents init-trust` | Register a local reviewer key for project trust |
| `screw-agents migrate-exclusions` | Sign legacy false-positive exclusions |
| `screw-agents validate-exclusion` | Re-sign a quarantined exclusion after review |
| `screw-agents validate-script` | Re-sign a quarantined adaptive script after review |

Example trust setup:

```bash
uv run screw-agents init-trust \
  --name "Reviewer Name" \
  --email reviewer@example.com \
  --project-root /path/to/project
```

## How Scanning Works

At a high level:

1. The user selects agents and a target.
2. The MCP server resolves the target into code chunks.
3. The engine applies language relevance filtering.
4. Claude Code receives agent-specific prompts and source context.
5. Findings are accumulated into a scan session.
6. The server finalizes reports in `.screw/findings/`.
7. False-positive decisions can be recorded in `.screw/learning/`.

The MCP server does not hardcode a single UI. Claude Code is one client. The
same backend is intended for the web application integration pilot, screw.nvim,
CI, and future clients.

## Programmatic Integration

The public integration boundary is MCP. Clients can connect through:

- stdio, for Claude Code and local subprocess-style clients;
- streamable HTTP, for web applications, editor integrations, workers, or CI.

The server currently exposes MCP tools rather than a bespoke REST API. The
important stable surfaces are:

- discovery: `list_domains`, `list_agents`;
- scan assembly: `scan_agents`, `scan_domain`, `get_agent_prompt`;
- output: `accumulate_findings`, `finalize_scan_results`, `format_output`;
- learning: `record_exclusion`, `check_exclusions`, `aggregate_learning`;
- adaptive analysis: staging, promotion, execution, cleanup, and trust tools.

For a web application, the expected integration model is a background worker or
service that submits scan targets to the MCP server, stores JSON/SARIF/Markdown
results, presents triage in the application, and maps approved false-positive
decisions back into screw-agents learning artifacts. The roadmap places this as
Phase 5.5, immediately after the multi-LLM challenger work and before broad
agent expansion.

## Outputs And Project State

Scan and learning artifacts are stored under the scanned project:

| Path | Purpose |
|---|---|
| `.screw/findings/` | JSON, Markdown, CSV, and SARIF scan reports |
| `.screw/learning/exclusions.yaml` | Signed false-positive exclusions |
| `.screw/config.yaml` | Project trust and adaptive-analysis configuration |
| `.screw/custom-scripts/` | Approved adaptive analysis scripts |
| `.screw/staging/` | Temporary staged findings/scripts before finalization |
| `.screw/local/` | Local-only adaptive prompt/decline state |

## Agent Knowledge

Agents live in `domains/<domain>/<agent>.yaml`.

The current implemented agents are all in
`domains/injection-input-handling/`:

| Agent | Primary vulnerability class |
|---|---|
| `sqli` | SQL injection |
| `cmdi` | OS command injection |
| `ssti` | Server-side template injection |
| `xss` | Cross-site scripting |

The full planned catalog contains 18 CWE-1400 domains and 41 planned agents.
Future agents are added as YAML definitions and run through the existing
registry, scan, output, learning, and benchmark infrastructure. No new
per-agent Claude subagent file is required.

See:

- [AGENT_CATALOG.md](docs/AGENT_CATALOG.md)
- [AGENT_AUTHORING.md](docs/AGENT_AUTHORING.md)
- [KNOWLEDGE_SOURCES.md](docs/KNOWLEDGE_SOURCES.md)

## Adaptive Analysis And Trust

Adaptive analysis is for cases where normal agent knowledge sees a suspicious
project-specific pattern but needs a reusable local probe, such as a custom ORM,
query builder, template wrapper, or command execution helper.

The adaptive path is deliberately gated:

- scripts are staged first;
- a reviewer inspects the exact staged bytes;
- promotion signs the staged bytes, not regenerated source;
- execution verifies signature, hash, trust, staleness, lint rules, and sandbox
  constraints;
- stale staging and rejected scripts are auditable and cleanable.

This is designed to preserve the invariant:

```text
bytes reviewed == bytes signed == bytes executed
```

## Benchmark And Autoresearch Infrastructure

The repository includes a CWE-1400-native benchmark system under
`benchmarks/`.

It supports:

- benchmark manifest inventory;
- dataset readiness checks;
- controlled run planning;
- no-Claude prompt-budget preflight;
- controlled Claude execution with explicit budget guards;
- failure payload generation for reviewed agent improvement;
- Phase 4 calibration evidence for the accepted agents.

Phase 4 is complete. The key closure documents are:

- [PHASE_4_CLOSURE_READINESS.md](docs/PHASE_4_CLOSURE_READINESS.md)
- [PHASE_4_D02_PLAN.md](docs/PHASE_4_D02_PLAN.md)
- [PHASE_4_OPERATING_MAP.md](docs/PHASE_4_OPERATING_MAP.md)
- [PHASE_4_WAVE_C_LEDGER.md](docs/PHASE_4_WAVE_C_LEDGER.md)

Broad benchmark runs are no longer the default next step. Future benchmark
execution should start from a concrete hypothesis, reviewed slices, and an
explicit prompt budget.

## Roadmap

Completed:

- Phase 0: initial knowledge research for the first four agents.
- Phase 0.5: benchmark infrastructure.
- Phase 1: MCP backend.
- Phase 1.7: initial benchmark pipeline validation.
- Phase 2: Claude Code integration.
- Phase 3a: trust, prompt infrastructure, learning aggregation.
- Phase 3b: adaptive analysis and staged approval flow.
- Phase 4: Rust corpus, D-02 calibration, benchmark methodology closure.

Upcoming:

- Phase 5: multi-LLM challenger system.
  - Claude primary, Codex challenger.
  - Codex primary, Claude challenger.
  - Claude and Codex parallel independent review with reconciliation.
- Phase 5.5: web application integration pilot using the four current agents.
- Phase 6: small-batch CWE-1400 agent expansion.
- Phase 7: screw.nvim integration.
- Cross-cutting: Phase 3c sandbox hardening and deferred backlog review before
  production-like deployment.

## Development

Run the full suite:

```bash
uv run pytest
```

Run a focused test module:

```bash
uv run pytest tests/test_registry_invariants.py -v
```

Run linting:

```bash
uv run ruff check .
```

The current full-suite baseline after Phase 4 signoff is:

```text
1101 passed, 9 skipped
```

## Documentation Map

| Document | Use |
|---|---|
| [PRD.md](docs/PRD.md) | Product requirements, architecture rationale, phase plan |
| [PROJECT_STATUS.md](docs/PROJECT_STATUS.md) | Current project status and roadmap |
| [ARCHITECTURE.md](docs/ARCHITECTURE.md) | System architecture and component overview |
| [COMMAND_REFERENCE.md](docs/COMMAND_REFERENCE.md) | CLI, Claude plugin, MCP, and benchmark command reference |
| [AGENT_CATALOG.md](docs/AGENT_CATALOG.md) | Planned CWE-1400 agent inventory |
| [AGENT_AUTHORING.md](docs/AGENT_AUTHORING.md) | How to write new agent YAML |
| [DECISIONS.md](docs/DECISIONS.md) | Architecture decision records |
| [DEFERRED_BACKLOG.md](docs/DEFERRED_BACKLOG.md) | Deferred hardening, polish, and future-phase work |
| [CONTRIBUTING.md](docs/CONTRIBUTING.md) | Development workflow notes |

## Security And Privacy Notes

- Scans may include source code in prompts sent to an LLM client.
- The Phase 5 challenger system is explicitly opt-in and must preserve
  provider, cost, and privacy controls.
- Adaptive scripts are powerful and therefore gated through review, signing,
  linting, sandboxing, and trust verification.
- The Linux sandbox has strong namespace/capability isolation today; seccomp
  hardening remains tracked in [DEFERRED_BACKLOG.md](docs/DEFERRED_BACKLOG.md).

## License

MIT.
