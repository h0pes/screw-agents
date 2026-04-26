# Architecture — screw-agents

> See `docs/PRD.md` §3 for the full system architecture diagram and rationale.
> See `docs/DECISIONS.md` for Architecture Decision Records (ADRs).

## System Overview

screw-agents is a modular, AI-powered secure code review system. It provides dedicated, vulnerability-specific agents that carry deeply researched security knowledge and are invocable from Claude Code, Neovim (via screw.nvim), or CI/CD pipelines through a shared MCP server backbone.

```
┌──────────────────────────────────────────────────────────────┐
│  Consumers: Claude Code │ screw.nvim │ CI/CD                │
│                         MCP Protocol                         │
│  ┌────────────────────────────────────────────────────────┐  │
│  │              screw-agents-mcp (MCP Server)             │  │
│  │                                                        │  │
│  │   Agent Registry ← YAML definitions (domains/)        │  │
│  │   Target Resolver (tree-sitter, 10 languages)         │  │
│  │   Output Formatter (JSON / SARIF / Markdown)          │  │
│  └────────────────────────────────────────────────────────┘  │
│                                                              │
│  Benchmark Evaluator (benchmarks/runner/)                    │
│  Autoresearch Loop (Phase 4)                                 │
└──────────────────────────────────────────────────────────────┘
```

### Key Design Decisions

| Decision | Why |
|---|---|
| MCP server, not embedded prompts | One source of truth — improve an agent once, every client benefits |
| CWE-1400 taxonomy backbone | Only classification with completeness + mutual exclusivity + practical granularity (ADR-002) |
| YAML agent definitions | New vulnerability types via YAML, no Python code changes. Community-extensible |
| CWE-1400-native benchmark evaluator | Score in CWE-1400 directly, not CWE-1000 with translation (ADR-013) |
| PrimeVul methodology | Without dedup + chrono splits, LLM evaluation drops from 68% to 3% F1 |

---

## Phase Lifecycle: One-Time Infrastructure vs Per-Vulnerability Work

This is the most important architectural concept to understand. The system is designed so that **adding a new vulnerability type is a content operation, not an infrastructure operation.**

### The Two Types of Work

```
 PER-VULNERABILITY (repeat for each new vuln):
 ├── Phase 0:   Knowledge Research — research, synthesize, write agent YAML
 └── Phase 2-3: Agent authoring — subagent wrappers, skills, testing
                 (one-line _active_cwes.py edit to light up benchmarks)

 ONE-TIME INFRASTRUCTURE (build once, benefits all vulns):
 ├── Phase 0.5: Benchmark infrastructure — evaluator, ingest harness, datasets
 ├── Phase 1:   MCP server — registry, resolver, formatter
 ├── Phase 4:   Autoresearch loop — self-improvement, experiment logging
 ├── Phase 5:   Multi-LLM challenger — provider-agnostic disagreement analysis
 └── Phase 6:   Agent expansion tooling — CI/CD, community workflow
```

### How a New Vulnerability Plugs In

When adding a new vulnerability type (e.g., Path Traversal / CWE-22):

**Step 1 — Research (Phase 0, per-vuln):**
Write the agent YAML definition in `domains/<cwe-1400-category>/path_traversal.yaml` following the same 4-tier research methodology used for the original 4 agents.

**Step 2 — Register with benchmarks (one-line edit):**
Add `"CWE-22"` to the `ACTIVE_CWES` frozenset in `benchmarks/scripts/_active_cwes.py`. Re-run the existing ingest scripts — CrossVul, MoreFixes, reality-check, etc. already contain CWE-22 data. It was just filtered out because CWE-22 wasn't in the active set.

**Step 3 — MCP registration (automatic):**
The agent registry (Phase 1) discovers YAML files in `domains/` and registers them as MCP tools. No code changes — drop the YAML, restart the server.

**Step 4 — Validation (existing harness):**
Run the benchmark evaluator against the new agent. The runner, metrics, dedup, splits, and report generator all work without modification — they're CWE-agnostic by design.

### The Join Point: `_active_cwes.py`

The central active-CWE registry (`benchmarks/scripts/_active_cwes.py`) is the single join point between one-time infrastructure and per-vuln content:

```python
# benchmarks/scripts/_active_cwes.py
ACTIVE_CWES: frozenset[str] = frozenset({
    "CWE-78",    # OS Command Injection
    "CWE-79",    # Cross-Site Scripting
    "CWE-89",    # SQL Injection
    "CWE-94",    # Code Injection
    "CWE-1336",  # SSTI
    # Phase 2+ additions:
    # "CWE-22",  # Path Traversal
    # "CWE-918", # SSRF
    # ...
})
```

Every ingest script, the dedup pipeline, and the MoreFixes extractor import from this single module. Adding a CWE here unlocks it across the entire benchmark system.

---

## Tool & Subagent Inventory (post-T-SCAN-REFACTOR)

### MCP tools (post-2026-04-25)

**Scan tools:**
- `scan_agents(agents, target, ...)` — paginated multi-agent primitive. Cursor binding `(target_hash, agents_hash)`. Returns init-page with `agents_excluded_by_relevance` + code-pages with per-agent prompts.
- `scan_domain(domain, target, ...)` — convenience wrapper over `scan_agents`. Resolves all agents in a CWE-1400 domain.

**Discovery tools:**
- `list_agents(domain=None)` — enumerate registered agents (optionally filtered by domain).
- `list_domains()` — enumerate domains.
- `get_agent_prompt(agent_name)` — fetch the per-agent core prompt on demand (lazy fetch from subagents).

**Adaptive tools** (Phase 3b):
- `record_context_required_match`, `detect_coverage_gaps`, `accumulate_findings`, `lint_adaptive_script`, `stage_adaptive_script`, `promote_staged_script`, `reject_staged_script`, `execute_adaptive_script`, `verify_trust`.

**Slash-command parser:**
- `resolve_scope(scope_text)` — Task 8 helper; returns `{agents, summary}`. Used by `/screw:scan` to translate user input into an agent list. Closed allowlist (registry lookup) + no shell evaluation.

**Output:**
- `finalize_scan_results(session_id, formats=...)` — emit JSON/Markdown/SARIF/CSV reports. Default format list as of T19-M D7: `["json", "markdown", "csv"]`.
- `record_exclusion`, `check_exclusions` — exclusion learning surface (Phase 2).

**Retired (T-SCAN-REFACTOR Task 6):**
- `scan_full` — replaced by `scan_agents(agents=list_agents().names, ...)` (or by the slash command's `full` keyword).
- `scan_<name>` per-agent tools (sqli/cmdi/ssti/xss) — replaced by `scan_agents(agents=[<name>], ...)`.

### Subagents (post-2026-04-25)

- **`screw-scan.md`** — universal scan runner (~559 LOC). Replaces 5 deleted per-vuln + per-domain subagents (screw-sqli, screw-cmdi, screw-ssti, screw-xss, screw-injection — Task 7 of T-SCAN-REFACTOR). Dispatched with `agents: list[str]` from main session.
- **`screw-script-reviewer.md`** — adaptive script review. Dispatched by main session per `pending_reviews` chain (chain-subagents architecture, Phase 3b-C2).
- **`screw-learning-analyst.md`** — learning-mode analyst (Phase 3a).

Subagents do NOT dispatch other subagents (Claude Code constraint, `sub-agents.md:711`). Main session is the sole orchestrator.

### Slash command grammar (post-Task-8)

`/screw:scan <scope-spec> <target> [--adaptive | --no-confirm | --thoroughness <L>] [--format <F>]`

`--adaptive` and `--no-confirm` are mutually exclusive (adaptive mode requires interactive consent).

Scope-spec forms (mutually exclusive):
- **Bare-token**: single agent name (e.g., `sqli`) or domain name (e.g., `injection-input-handling`). Disambiguated via registry lookup; the `agent name ≠ domain name` invariant guarantees uniqueness.
- **`full`** keyword: all registered agents (post-relevance-filter).
- **Prefix-key**: `domains:foo,bar agents:baz,qux` — combine multiple domains and agents in one invocation.

Examples:
```
/screw:scan sqli src/api/                    # single agent
/screw:scan injection-input-handling src/    # whole domain
/screw:scan full .                           # all agents
/screw:scan agents:sqli,xss src/api/         # subset across domains
/screw:scan domains:foo agents:baz src/      # mix
/screw:scan domains:A,B agents:1A,2A,1B src/ # subset of A + subset of B
```

### Scan flow (chain-subagents architecture)

```
slash command       resolve_scope        scan_agents (init page)
   ↓                    ↓                       ↓
main session ──────────────────────────────────→  pre-execution summary
   ↓                                                    ↓
   ↓                                              user consent (or --no-confirm)
   ↓                                                    ↓
dispatch screw-scan ──────────────────────────────────────────→ scan_agents (code pages)
   ↓                                                                  ↓
   ↓                                                            accumulate_findings
   ↓                                                                  ↓
parse return (C2 + enrichment) ←─────────────────────────────── return structured payload
   ↓
optionally chain screw-script-reviewer (per pending_reviews)
   ↓
finalize_scan_results
   ↓
report (JSON, Markdown, SARIF, CSV per --format)
```

---

## Component Architecture

### Agent Definitions (`domains/`)

YAML files carrying vulnerability-specific detection knowledge. Each agent includes:
- `meta`: CWE IDs, CAPEC mappings, OWASP Top 10:2025 overlay, research sources
- `core_prompt`: Distilled detection knowledge (2,000-4,000 tokens)
- `detection_heuristics`: Language-specific patterns at high/medium/context-required severity
- `bypass_techniques`: Real-world evasion patterns grounded in CVEs
- `remediation`: Per-language fix guidance
- `few_shot_examples`: Vulnerable + safe code pairs
- `target_strategy`: Tree-sitter queries for function/class targeting

See `docs/PRD.md` §4 for the full schema.

### MCP Server (`src/screw_agents/`)

Python MCP server exposing agent definitions as tools. Phase 1 builds:
- **Agent Registry**: YAML loader → Pydantic validation → MCP tool registration
- **Target Resolver**: tree-sitter AST parsing (10 languages) + glob file discovery + git diff parsing
- **Output Formatter**: Findings → JSON + SARIF + Markdown

Both stdio (Claude Code) and streamable HTTP (screw.nvim, CI/CD) transports.

### Benchmark Evaluator (`benchmarks/runner/`)

CWE-1400-native Python evaluator (ADR-013). Components:

| Module | Responsibility |
|---|---|
| `models.py` | Pydantic types: Finding, BenchmarkCase, MetricSet, Summary |
| `sarif.py` | bentoo-SARIF read/write (SARIF 2.1.0 subset) |
| `cwe.py` | CWE-1400 hierarchy traversal with strict/broad match modes |
| `metrics.py` | Pair-based TPR/FPR/precision/recall/F1 computation |
| `primevul.py` | Tree-sitter AST normalization, SHA-256 dedup, chrono/cross-project splits |
| `report.py` | Markdown report rendering |
| `cli.py` | `python -m benchmarks.runner` entry point |

### Ingest System (`benchmarks/scripts/`)

Reusable `IngestBase` abstract class with 8 dataset-specific subclasses. Each ingest script:
1. Downloads/clones the dataset (`ensure_downloaded()`)
2. Parses the native format, filters to `ACTIVE_CWES` (`extract_cases()`)
3. Writes bentoo-SARIF truth files + provenance manifest (base class `run()`)

| Dataset | Languages | Ingest Script |
|---|---|---|
| OpenSSF CVE Benchmark | JS/TS | `ingest_ossf.py` |
| reality-check (C#/Python/Java) | C#, Python, Java | `ingest_reality_check_*.py` |
| go-sec-code-mutated | Go | `ingest_go_sec_code.py` |
| skf-labs-mutated | Python | `ingest_skf_labs.py` |
| CrossVul | PHP, Ruby | `ingest_crossvul.py` |
| Vul4J | Java | `ingest_vul4j.py` |
| MoreFixes | All (via Postgres) | `morefixes_extract.py` |

### Claude Code Integration (`plugins/screw/`)

Thin orchestration wrappers calling MCP tools:
- **Subagents** (`agents/`): `screw-scan.md` (universal scan runner; T-SCAN-REFACTOR collapsed 5 per-vuln + per-domain subagents into this one), `screw-script-reviewer.md` (adaptive review chain), `screw-learning-analyst.md` (learning mode). Main session orchestrates dispatch (chain-subagents architecture).
- **Skills** (`skills/`): Auto-invocation triggers
- **Slash commands**: User-facing entry points (e.g., `/screw:scan` with multi-scope grammar, see "Tool & Subagent Inventory" above)

### Project-Level State (`.screw/`)

Per-project persistent state in the target repository:
- `findings/`: Scan results
- `learning/exclusions.yaml`: False positive patterns (Phase 2)
- `custom-scripts/`: Adaptive analysis scripts (Phase 3)

---

## Taxonomy

**CWE-1400** (Comprehensive Categorization) is the structural backbone — 21 categories consolidated to 18 agent domains. Every finding carries a CWE ID as the universal join key.

**OWASP Top 10:2025** is the risk communication overlay — used in reports and user-facing output, not as the domain structure.

See `docs/PRD.md` §9 for the full taxonomy mapping and `docs/DECISIONS.md` ADR-002/ADR-003 for the rationale.

---

## Phase Plan Summary

| Phase | Type | Focus | Status |
|---|---|---|---|
| Phase 0 | Per-vuln | Knowledge Research | Complete (4 agents) |
| Phase 0.5 | **One-time** | Benchmark Infrastructure | **Complete** |
| Phase 1 | **One-time** | MCP Server + Registry + Resolver + Formatter | **Complete** |
| Phase 2 | Per-vuln | Claude Code Integration (subagents, skills, FP learning) | **Complete** |
| Phase 3 | **One-time** | Adaptive Analysis & Learning | **Complete** (Phase 3a + Phase 3b + Phase 3b-C2) |
| Phase 4 | **One-time** | Autoresearch & Self-Improvement | **Pending** (gated only on D-01 Rust benchmark corpus) |
| Phase 5 | **One-time** | Multi-LLM Challenger | Pending |
| Phase 6 | Mixed | Agent Expansion (per-vuln) + Ecosystem (one-time) | Pending |
| Phase 7 | **One-time** | screw.nvim Integration | Pending |

See `docs/PRD.md` §12 for detailed phase descriptions and `docs/PROJECT_STATUS.md` for current state.

---

## Key References

- `docs/PRD.md` — Product Requirements Document (definitive)
- `docs/DECISIONS.md` — Architecture Decision Records
- `docs/PHASE_0_5_PLAN.md` — Phase 0.5 implementation plan (28 tasks)
- `docs/PHASE_0_5_VALIDATION_GATES.md` — Phase 1.7 acceptance criteria
- `docs/PROJECT_STATUS.md` — Current state + deferred obligations
- `docs/KNOWLEDGE_SOURCES.md` — Research targets for knowledge sprint
- `docs/AGENT_AUTHORING.md` — Guide for writing new agent YAMLs
