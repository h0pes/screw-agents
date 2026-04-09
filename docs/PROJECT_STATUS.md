# Project Status — screw-agents

> Last updated: 2026-04-09

## Deferred Obligations

Items explicitly deferred from earlier phases that must be completed in later phases. This section is prominent on purpose — deferred work must not be forgotten.

| # | Item | Deferred from | Owning phase | Tracking ADR | Status |
|---|---|---|---|---|---|
| D-01 | Rust benchmark corpus from RustSec (~24 verified CVE candidates + synthetic SSTI fixtures) | Phase 0.5 | **Phase 5 (step 5.0)** — hard gate, Phase 5 cannot close without it | ADR-014 | **DEFERRED** |

**When returning to Phase 5:** The first step of Phase 5 is D-01 (Rust benchmark corpus construction). Verify this deferral is still valid by re-reading ADR-014 and `docs/research/benchmark-tier4-rust-modern.md`. Do not skip this step.

---

## Current Phase: Phase 0 Complete — Phase 0.5 Active

Architecture and product design is **complete** (PRD v0.4.3 is the definitive document). Phase 0 (Knowledge Research Sprint) for the four Phase 1 injection agents is **complete**. Phase 0.5 (Benchmark Infrastructure Sprint) is active.

### What's Done

**Architecture & product design:**
- Full architecture design (MCP server backbone, Claude Code integration, screw.nvim integration boundary)
- Taxonomy decision: CWE-1400 as structural backbone with OWASP Top 10:2025 overlay (ADR-002, ADR-003)
- Domain mapping: 21 CWE-1400 categories consolidated to 18 agent domains
- Agent YAML definition format specified (PRD §4)
- Target specification format with git diff/PR support (PRD §5)
- Output schema (structured JSON + SARIF + Markdown reports) (PRD §8)
- Four advanced features designed: adaptive scripts, persistent FP learning, autoresearch, multi-LLM challenger
- Repository structure defined (PRD Appendix C)
- Phased implementation plan (Phases 0-7)
- Success metrics defined
- 16 open questions documented

**Repository scaffold:**
- `pyproject.toml` with `uv`-compatible project definition (ADR-011)
- Dependencies declared: `mcp`, `tree-sitter>=0.23`, `pyyaml>=6.0`
- Empty package skeleton at `src/screw_agents/` (autoresearch/ and challenger/ dirs present but empty)
- `docs/` structure in place (PRD, DECISIONS, CONTRIBUTING, KNOWLEDGE_SOURCES, AGENT_AUTHORING)

**Phase 0 — Knowledge Research Sprint (complete for all 4 Phase 1 agents):**

| Agent | CWE | Tier research files | Synthesis notes | YAML definition | Fixtures (vuln / safe) |
|---|---|---|---|---|---|
| **SQLi** | CWE-89 | 16 files | `docs/research/sqli-research-notes.md` | `domains/injection-input-handling/sqli.yaml` (956 lines) | 11 / 9 |
| **CmdI** | CWE-78 | 4 files | `docs/research/cmdi-research-notes.md` | `domains/injection-input-handling/cmdi.yaml` | 10 / 8 |
| **SSTI** | CWE-1336 | 4 files | `docs/research/ssti-research-notes.md` | `domains/injection-input-handling/ssti.yaml` | 11 / 8 |
| **XSS** | CWE-79 | 4 files | `docs/research/xss-research-notes.md` | `domains/injection-input-handling/xss.yaml` (1,211 lines) | 14 / 11 |

Each YAML carries a 2,000-4,000 token distilled `core_prompt`, comprehensive detection heuristics (high/medium/context-required), bypass techniques grounded in real CVEs, per-language remediation guidance, and few-shot examples. All four include deep Rust coverage — load-bearing for users scanning Rust code, but explicitly NOT benchmarked for Rust detection quality (see ADR-014 and Deferred Obligations D-01).

**Cross-cutting research:** `docs/research/rust-injection-patterns.md` (local) — shared Rust coverage feeding all four agents.

**Phase 0.5 — Benchmark Infrastructure Sprint (research complete, implementation next):**

Four benchmark research docs committed to `docs/research/benchmark-tier{1,2,3,4}-*.md` covering flawgarden ecosystem, academic datasets, C/C++ corpora, and Rust/modern ecosystems. All five architectural decisions locked in (see "Current phase" below).

### What's NOT Done

- No MCP server implementation yet
- No agent registry, target resolver, or output formatter
- No benchmark runner or CI
- `tests/` directory is empty
- Phase 0.5 implementation (not just research) — active
- Remaining 14 agents (CWE-1400 domains 2-18) not yet researched

---

## Current phase: Phase 0.5 — Benchmark Infrastructure Sprint

**Why this exists:** Phase 1 validation cannot rely on self-authored fixtures. We need a real-world CVE benchmark harness using datasets from the flawgarden ecosystem, the OpenSSF JS/TS benchmark (218 real CVEs — biggest single data source for our XSS and CmdI agents), and multi-language CVE extraction via MoreFixes.

### Five architectural decisions locked in (2026-04-09)

1. **Full sprint scope — no cuts.** Includes PrimeVul methodology, MoreFixes pipeline, CWE-1400 evaluator, all benchmark ingestion. Rationale: weak benchmark infrastructure makes Phase 1 validation meaningless and breaks the autoresearch loop downstream (ADR-006).

2. **PrimeVul methodology mandatory.** Deduplication, chronological splits, cross-project holdouts, pair-based evaluation. Non-negotiable because SOTA LLM models drop from 68% F1 on Big-Vul to 3% F1 on PrimeVul without these controls — our autoresearch loop (PRD §11.3) will silently overfit without proper methodology.

3. **Build our own Python evaluator, CWE-1400 native (ADR-013).** Reject direct bentoo adoption because bentoo scores in CWE-1000 Research View, which would force taxonomy translation everywhere and break the "universal join key" contract (ADR-002). Consume bentoo-sarif format as input, score in CWE-1400, emit bentoo-compatible `summary.json` for optional cross-check.

4. **Rust corpus deferred to Phase 5 (ADR-014).** Triple-redundantly tracked (ADR-014, PRD §12 step 5.0, Deferred Obligations D-01 above). Current Rust fixtures downgraded to smoke-test status. Phase 1 benchmark reports explicitly say "Rust detection quality not benchmarked — see ADR-014."

5. **MCP library: low-level `mcp.Server`.** Both stdio (Claude Code) and streamable HTTP (screw.nvim, CI/CD) transports supported from day 1. Rejected FastMCP because we need dynamic YAML-driven tool registration.

### Phase 0.5 sprint steps

**0.5.1 — Adopt flawgarden tooling layer**
- Clone `flawgarden/reality-check/scripts/` into `benchmarks/cve-ingest/` (Apache-2.0, direct reuse)
- Adopt bentoo-sarif ground-truth format verbatim (SARIF 2.1.0, `kind: fail|pass`, `ruleId: CWE-<id>`)
- Keep `flawgarden/bentoo` as optional external cross-check (not primary evaluator)

**0.5.2 — Ingest existing real-CVE benchmarks** (priority order)
1. `ossf-cve-benchmark/ossf-cve-benchmark` — 218 JS/TS CVEs with verified CWE-78/79/94 presence
2. `flawgarden/reality-check` C# subset — 9 XSS CVEs (strongest single cell for our Phase 1 agents)
3. `flawgarden/reality-check` Python subset — 4 XSS + path traversal / CWE-94 adjacency
4. `go-sec-code-mutated` (flawgarden) — only asset with CWE-1336 SSTI coverage via Sprig + Beego CWE-78/79/89
5. `skf-labs-mutated` (flawgarden) — Python Flask/Jinja2 SSTI via OWASP SKF labs
6. `CrossVul` — real PHP and Ruby CVEs (no other real-code source for these languages)
7. `Vul4J` — 79 Java CVEs with reproducible PoV tests for precision benchmarks
8. `flawgarden/reality-check` Java subset — 5 XSS + 3 CmdI extracted from deserialization-dominated Java coverage

**0.5.3 — Build MoreFixes extraction pipeline**
- Deploy MoreFixes from Zenodo Postgres dump (16 GB, v2024-09-26)
- Filter by `CWE ∈ {79, 78, 89, 1336}` AND `language ∈ {py, js, ts, go, java, rb, php, cs}`
- Require confidence score ≥65 (per MoreFixes README recommendation)
- Target: ~30 additional real CVE fixtures per CWE across all viable languages
- Rationale: MoreFixes is a strict superset of CVEfixes (adds GHSA ingestion, newer 2024-09-26, same schema)

**0.5.4 — Rust benchmark deferred to Phase 5** (see Deferred Obligations D-01 and ADR-014)
- Current Rust fixtures (14 vuln + 11 safe in `benchmarks/fixtures/{xss,sqli,cmdi,ssti}/`) demoted to smoke tests only
- Phase 1 reports explicitly state "Rust detection quality not benchmarked"
- Per-fixture provenance notes added where a real-CVE analog exists

**0.5.5 — Apply PrimeVul methodology to all ingested benchmarks**
- Deduplication: normalize whitespace, strip comments, hash the AST
- Chronological splits where CVE dates are available
- Pair-based evaluation: TP requires flagging vulnerable version AND not flagging patched version at the same location
- Cross-project holdout for autoresearch training (PRD §11.3)

**0.5.6 — Build benchmark runner harness**
- Single Python CLI: `screw-agents benchmark run --agent xss --dataset ossf-cve-benchmark --splits chrono`
- Outputs: per-(agent, dataset) SARIF tool output, `summary.json` with bentoo-compatible schema + CWE-1400 native metrics, Markdown report, failure dump (missed vulnerabilities + false flags)
- ~600-1,000 lines of Python, pure stdlib + PyYAML + SARIF parser

**0.5.7 — Phase 1 validation gates** (defined here, executed in Phase 1.7)
- ≥70% TPR on `ossf-cve-benchmark` XSS subset (lowered from the originally-planned 80% because real-world detection is harder than synthetic: SMU paper's best Java SAST hit only 12.7% on real-world benchmarks)
- ≤25% FPR on `ossf-cve-benchmark` patched versions
- ≥60% TPR on reality-check C# XSS + Python XSS (strongest XSS cells in flawgarden)
- No Rust gate (deferred — see D-01)
- Per-CWE and per-language breakdown required in the final report

---

## Phase 1 — Core Infrastructure (blocked on Phase 0.5 completion)

Structured as a dependency graph with three parallel tracks converging at smoke test + benchmark validation:

```
1.1.1  MCP server skeleton (low-level mcp.Server, stdio + streamable HTTP)
        |
        +---- Track A ------ Track B ------ Track C
        |                    |              |
        v                    v              v
      1.1.2               1.1.4          1.1.5
      YAML loader         Target         Output
      (Pydantic schema    resolver       formatter
       from PRD §4)       (tree-sitter:  (JSON/SARIF/MD)
        |                  10 langs)
        v
      1.1.3               (Python, JS, TS,
      Agent registry       Go, Rust, Java,
      (YAML → MCP tools,   Ruby, PHP, C, C++)
       CWE-1400 resource)
        |
        +---- synchronize ----+
                              v
                          1.1.6  Smoke test (claude --mcp-config, 4 agents)
                              v
                          1.1.7  Benchmark validation run
                                 (Phase 0.5 harness against ingested
                                  benchmarks from 0.5.2 and 0.5.3)
                                 gates: see Phase 0.5 step 0.5.7
```

### Key technical decisions (2026-04-09)

- **MCP library:** Low-level `mcp.Server` (not FastMCP) — needed for dynamic YAML-driven tool registration
- **Transports:** Both stdio (Claude Code) and streamable HTTP (screw.nvim, CI/CD) supported from day 1
- **tree-sitter scope:** 10 languages — Python, JavaScript, TypeScript, Go, Rust, Java, Ruby, PHP, C, C++
- **Benchmark evaluator:** Our own CWE-1400-native Python module (ADR-013)
- **Benchmark input format:** bentoo-sarif (SARIF 2.1.0)
- **Primary benchmark sources:** ossf-cve-benchmark (JS/TS), flawgarden/reality-check (Java/C#/Go/Python), go-sec-code-mutated + skf-labs-mutated (SSTI), CrossVul (PHP/Ruby), Vul4J (Java precision), MoreFixes (multi-language extraction)
- **Benchmark exclusions:** OWASP Benchmark, WebGoat, DVWA, Juice Shop — all excluded as synthetic or too weak for validation; bentoo as primary evaluator rejected in ADR-013

---

## Full Phase Plan (from PRD §12)

| Phase | Focus | Status |
|---|---|---|
| Phase 0 | Knowledge Research Sprint | **Complete** (4/4 Phase 1 agents) |
| **Phase 0.5** | **Benchmark Infrastructure Sprint** | **ACTIVE** (research complete, implementation next) |
| Phase 1 | Core Infrastructure (MCP server, agent registry, target resolver) | Pending (blocked on Phase 0.5) |
| Phase 2 | Claude Code Integration (subagents, skills, filesystem output, FP learning) | Pending |
| Phase 3 | screw.nvim Integration (scan commands, review-before-import, exclusions) | Pending |
| Phase 4 | Adaptive Analysis & Learning Refinement | Pending |
| Phase 5 | Autoresearch & Self-Improvement — step 5.0 is D-01 (hard gate) | Pending |
| Phase 6 | Multi-LLM Challenger System | Pending |
| Phase 7 | Agent Expansion & Ecosystem | Pending |

---

## Marco's Environment & Preferences

- **OS:** Arch Linux
- **Editor:** Neovim (screw.nvim author)
- **Package manager:** `uv` (pip install restricted on Arch — see ADR-011)
- **Languages:** Significant Rust development; also Python, TypeScript, others
- **Rust benchmark gap:** See ADR-014 and Deferred Obligations D-01
