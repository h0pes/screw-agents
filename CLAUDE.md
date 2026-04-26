# CLAUDE.md — screw-agents

## Project Identity

**screw-agents** is a modular, AI-powered secure code review system. It provides dedicated, vulnerability-specific agents that carry deeply researched security knowledge (from OWASP, CWE, CAPEC, Semgrep rules, real CVEs, security research blogs) and are invocable from Claude Code, Neovim (via screw.nvim), or CI/CD pipelines through a shared MCP server backbone.

**Repository:** `github.com/h0pes/screw-agents`
**Owner:** Marco (h0pes)
**Language:** Python (MCP server), Markdown (Claude Code agents/skills), YAML (agent definitions)
**Package manager:** `uv` (preferred). Do NOT use bare `pip install` — use `uv`, `uvx`, or `pipx`.

## Current State

**Phase:** Phase 3b closed; Phase 4 prereq sweep complete (T-SCAN-REFACTOR final 2026-04-25); next milestone is Phase 4 step 4.0 (D-01 Rust benchmark corpus).
**PRD:** `docs/PRD.md` (v0.4.3, ~1,470 lines) — the comprehensive product requirements document. READ THIS FIRST for full context on architecture, taxonomy, features, and implementation plan.
**Test suite:** 996 passed, 9 skipped (HEAD baseline `c7fa9d9`, end-of-Task-8 of T-SCAN-REFACTOR).
**Phase 4 readiness:** all blockers cleared; only D-01 (Rust benchmark corpus, ADR-014) remains as a hard gate, and D-01 IS Phase 4 step 4.0.
**Subagent surface (post-T-SCAN-REFACTOR):** one universal `screw-scan.md` covers all registered agents (replaces 5 per-vuln + per-domain subagents). Supporting: `screw-script-reviewer.md` (adaptive review chain), `screw-learning-analyst.md` (learning mode).
**MCP scan surface:** `scan_agents` (paginated multi-agent primitive) + `scan_domain` (thin wrapper) + `resolve_scope` (slash command parser). The retired surface (`scan_full`, per-agent `scan_<name>`) has been deleted — there is no compat shim.

## Architecture Overview (Quick Reference)

Read `docs/PRD.md` §3 for the full architecture. Key points:

- **MCP server** (`src/screw_agents/`) is the pluggable backbone. All intelligence lives here.
- **Claude Code integration** (`plugins/screw/`) provides subagents, skills, and slash commands — thin orchestration wrappers calling MCP tools.
- **Agent definitions** (`domains/`) are YAML files carrying vulnerability-specific detection knowledge. This is where the real value lives.
- **CWE-1400** (Comprehensive Categorization, 21 categories consolidated to 18 agent domains) is the taxonomic backbone. Not OWASP Top 10, not ad-hoc categories. See `docs/DECISIONS.md` §2 for why.
- **OWASP Top 10:2025** (not 2021) is the risk communication overlay, not the structural backbone.
- **screw.nvim** integration stays in the screw.nvim repo. This repo does NOT contain Lua code.

## Key Design Decisions (Summary)

Full reasoning in `docs/DECISIONS.md`. The critical ones:

1. **MCP server, not embedded prompts** — Portability across Claude Code, screw.nvim, and CI/CD.
2. **MCP over code-execution agents** — The system delivers curated knowledge, not API wrappers. Context cost is ~800-1,200 tokens (6-8 tools), not 20k+.
3. **CWE-1400 taxonomy backbone** — Only classification with completeness + mutual exclusivity + practical granularity. Every finding carries a CWE ID as universal join key.
4. **YAML agent definitions, not hardcoded prompts** — Community extensibility. New vulnerability types via YAML, no Python code changes.
5. **Autoresearch self-improvement loop** (Karpathy-inspired) — Agents iteratively refine their own YAML against SAST benchmarks. Human review gate on all changes.
6. **Multi-LLM challenger** — Provider-agnostic interface; Codex (via codex-plugin-cc) is first implementation. Opt-in, never default.
7. **`uv` as package manager** — pip install is restricted on Arch Linux and similar. Always prefer `uv` / `uvx`.

## Coding Standards

### Python (MCP server)
- Python 3.11+
- Use `uv` for dependency management. `pyproject.toml` for package definition.
- Type hints on all function signatures
- Async where the MCP protocol requires it
- tree-sitter for AST parsing (target resolution)
- No heavy frameworks — FastMCP or similar lightweight MCP library for the server

### YAML (Agent definitions)
- Follow the schema defined in `docs/PRD.md` §4 exactly
- Every agent MUST include: `meta` (CWEs, CAPEC, OWASP mappings, sources with last_checked dates), `core_prompt`, `detection_heuristics`, `bypass_techniques`, `remediation`, `few_shot_examples`, `target_strategy`
- Detection heuristics must be language-specific and precise, not generic

### Markdown (Claude Code agents/skills)
- Subagents in `plugins/screw/agents/` follow Claude Code's agent format with YAML frontmatter
- Skills in `plugins/screw/skills/` follow the SKILL.md format with frontmatter

## Repository Structure

See `docs/PRD.md` Appendix C for the full tree. Key directories:

```
screw-agents/
├── plugins/screw/          # Claude Code plugin (agents, skills, commands)
├── src/screw_agents/       # MCP server (Python)
├── domains/                # Agent YAML definitions (the knowledge base)
├── benchmarks/             # Autoresearch evaluation infrastructure
└── docs/                   # PRD, decisions, guides
```

## What NOT to Do

- Do NOT use OWASP Top 10 as the domain structure. Use CWE-1400. Top 10 is for reporting only.
- Do NOT reference OWASP Top 10:2021. The current version is 2025.
- Do NOT use `pip install` directly. Use `uv`, `uvx`, or `pipx`.
- Do NOT build screw.nvim integration code in this repo. That goes in the screw.nvim repo.
- Do NOT make the multi-LLM challenger active by default. It's always opt-in.
- Do NOT let the autoresearch loop auto-commit YAML changes. Human review gate is mandatory.
- Do NOT use the OWASP Benchmark (Java-only, synthetic) for validation. Use flawgarden/reality-check (real CVEs, multi-language).

## Key References

- **PRD:** `docs/PRD.md` — The comprehensive product requirements document
- **Decisions:** `docs/DECISIONS.md` — Architecture Decision Records with full reasoning
- **Knowledge sources:** `docs/KNOWLEDGE_SOURCES.md` — Research targets for the knowledge sprint
- **screw.nvim:** https://github.com/h0pes/screw.nvim — The Neovim plugin this integrates with
- **CWE-1400:** https://cwe.mitre.org/data/definitions/1400.html — Taxonomy backbone
- **OWASP Top 10:2025:** https://owasp.org/Top10/2025/
- **karpathy/autoresearch:** https://github.com/karpathy/autoresearch — Autoresearch inspiration
- **openai/codex-plugin-cc:** https://github.com/openai/codex-plugin-cc — Challenger transport reference
- **flawgarden/reality-check:** https://github.com/flawgarden/reality-check — Primary SAST benchmark
