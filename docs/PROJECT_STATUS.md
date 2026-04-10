# Project Status — screw-agents

> Last updated: 2026-04-10

## Deferred Obligations

Items explicitly deferred from earlier phases that must be completed in later phases. This section is prominent on purpose — deferred work must not be forgotten.

| # | Item | Deferred from | Owning phase | Tracking ADR | Status |
|---|---|---|---|---|---|
| D-01 | Rust benchmark corpus from RustSec (~24 verified CVE candidates + synthetic SSTI fixtures) | Phase 0.5 | **Phase 5 (step 5.0)** — hard gate, Phase 5 cannot close without it | ADR-014 | **DEFERRED** |
| D-02 | Gates G5-G7: detection rate validation against real-CVE benchmarks | Phase 1 (Task 20) | **Pre-Phase 2 gate** — must pass before Phase 2 begins | — | **DEFERRED** |

**When returning to Phase 5:** The first step of Phase 5 is D-01 (Rust benchmark corpus construction). Verify this deferral is still valid by re-reading ADR-014 and `docs/research/benchmark-tier4-rust-modern.md`. Do not skip this step.

**When starting Phase 2:** D-02 (Gates G5-G7) must pass first. See the "Phase 1.7 — Gates G5-G7" section below for the full procedure.

---

## Current Phase: Phase 1 Complete — G5-G7 Validation Then Phase 2

Architecture and product design is **complete** (PRD v0.4.3 is the definitive document). Phase 0 (Knowledge Research) is **complete**. Phase 0.5 (Benchmark Infrastructure) is **complete**. Phase 1 (Core Infrastructure) is **complete** (PR #2 merged 2026-04-10). Gates G1-G4 pass. Gates G5-G7 (detection rate validation) are deferred to a dedicated session before Phase 2 begins (see D-02).

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

**Phase 0.5 — Benchmark Infrastructure Sprint (complete):**

Four benchmark research docs committed to `docs/research/benchmark-tier{1,2,3,4}-*.md` covering flawgarden ecosystem, academic datasets, C/C++ corpora, and Rust/modern ecosystems. All five architectural decisions locked in.

| Task | Description | Status |
|---|---|---|
| 0.5.1 | Scaffold benchmarks/ tree, pyproject.toml, .gitignore | **Complete** |
| 0.5.2 | Adopt flawgarden tooling layer (bentoo-sarif format, cve-ingest scripts) | **Complete** |
| 0.5.3 | Pydantic models, bentoo-sarif parser, CWE-1400 hierarchy YAML | **Complete** |
| 0.5.4 | Metrics computation (TPR/FPR/F1, per-CWE, per-language) | **Complete** |
| 0.5.5 | PrimeVul dedup via tree-sitter AST normalization | **Complete** |
| 0.5.6 | Chronological + pair-based splits | **Complete** |
| 0.5.7 | Markdown report generator | **Complete** |
| 0.5.8 | CLI entry point (`benchmarks.runner` module) | **Complete** |
| 0.5.9 | Ingest ossf-cve-benchmark (218 JS/TS CVEs) | **Complete** |
| 0.5.10 | Ingest reality-check C# subset | **Complete** |
| 0.5.11 | Ingest reality-check Python subset | **Complete** |
| 0.5.12 | Ingest reality-check Java subset | **Complete** |
| 0.5.13 | Ingest go-sec-code-mutated (SSTI/CWE-1336) | **Complete** |
| 0.5.14 | Ingest skf-labs-mutated (Flask/Jinja2 SSTI) | **Complete** |
| 0.5.15 | Ingest CrossVul (PHP/Ruby) | **Complete** |
| 0.5.16 | Ingest Vul4J (Java precision) | **Complete** |
| 0.5.17 | MoreFixes extraction pipeline (docker-compose + filter query) | **Complete** |
| 0.5.18 | Active-CWE registry (centralized, single source of truth) | **Complete** |
| 0.5.19 | Reusable ingest base class | **Complete** |
| 0.5.20 | Run PrimeVul dedup across all ingested benchmarks | **Complete** |
| 0.5.21 | Generate chronological + cross-project splits | **Complete** |
| 0.5.22 | End-to-end smoke test with synthetic mock agent output | **Complete** |
| 0.5.23 | Demote Rust fixtures to smoke tests; add provenance headers | **Complete** |
| 0.5.24 | 81-test suite; all green | **Complete** |
| 0.5.25 | Phase 1.7 validation gates doc | **Complete** |
| 0.5.26 | Sprint retrospective + PROJECT_STATUS.md refresh | **Complete** |

**Phase 1 — Core Infrastructure (complete, PR #2 merged 2026-04-10):**

| Component | Module | Status |
|---|---|---|
| Shared tree-sitter | `src/screw_agents/treesitter.py` | **Complete** — 11 languages, individual grammar packages |
| Pydantic models | `src/screw_agents/models.py` | **Complete** — YAML schema + finding output schema |
| Agent registry | `src/screw_agents/registry.py` | **Complete** — YAML loading, validation, lookup |
| Target resolver | `src/screw_agents/resolver.py` | **Complete** — all 9 target types from PRD §5 |
| Output formatter | `src/screw_agents/formatter.py` | **Complete** — JSON, SARIF 2.1.0, Markdown |
| Scan engine | `src/screw_agents/engine.py` | **Complete** — orchestrates registry + resolver + formatter |
| MCP server | `src/screw_agents/server.py` | **Complete** — stdio + HTTP, dynamic tool registration |
| Tests | `tests/` (72 tests) | **Complete** — all passing |
| Benchmark ingest fixes | 8 scripts repaired | **Complete** — all scripts produce real data |
| Benchmark data | 9 datasets, 3,877 cases post-dedup | **Complete** — G1-G4 pass |

**Tree-sitter migration:** Replaced abandoned `tree-sitter-languages` (no maintainer since Feb 2024, no 3.14 wheels) with 11 individual grammar packages using stable ABI. Phase 0.5's ctypes hack in `primevul.py` replaced with shared module imports.

**Benchmark ingest fixes applied during Phase 1:**
- OSSF: iterate JSON files not directories
- reality-check (C#/Python/Java): fix path construction (`{version}` already includes project prefix)
- CrossVul: rewrite for actual `bad_*/good_*` file pair structure; Zenodo URL `/record/` → `/records/`, tarball → zip
- Vul4J: add correct CSV path (`dataset/vul4j_dataset.csv`)
- MoreFixes: Zenodo URL fix, zip extraction, `00-create-role.sql` for `postgrescvedumper` role, complete query rewrite for actual schema (CWE in `cwe_classification`, language in `file_change.programming_language`, join via `file_change_id`)

### What's NOT Done

- **Gates G5-G7: detection rate validation** (see D-02 and section below) — infrastructure complete, actual benchmark run deferred
- Remaining 14 agents (CWE-1400 domains 2-18) not yet researched (Phase 7)
- Rust benchmark corpus not yet built (deferred to Phase 5 step 5.0, see D-01)
- Claude Code integration: subagents, skills, filesystem output (Phase 2)
- screw.nvim integration (Phase 3)

### Benchmark Data Ingestion (complete as of Phase 1, 2026-04-10)

All 9 ingest scripts have been run successfully. MoreFixes schema has been verified and extraction query corrected for the actual database schema. Dedup and splits applied.

| Dataset | Cases | Notes |
|---|---|---|
| ossf-cve-benchmark | 118 | JS/TS CVEs with CWE-78/79/89/94 |
| reality-check-csharp | 11 | CWE-78/79/89 |
| reality-check-python | 6 | CWE-78/79/94 |
| reality-check-java | 9 | CWE-78/79/94 |
| go-sec-code-mutated | 1 | Monolithic repo, 159 CWE-89 findings in single case |
| skf-labs-mutated | 1 | Monolithic repo, 367 CWE-89 findings in single case |
| crossvul | 1,396 | PHP/Ruby bad/good file pairs |
| vul4j | 7 | CWE-78/79 |
| morefixes | 2,601 | Multi-language, MoreFixes Postgres extraction |
| **After dedup** | **3,877** | 273 duplicates removed via PrimeVul AST normalization |
| **Chrono split** | 3,753 train / 124 test | |
| **Cross-project** | 1,482 projects | |

To reproduce (if data is lost): re-run all ingest scripts, then `apply_dedup` and `apply_splits`. MoreFixes requires Docker (`bash benchmarks/scripts/deploy_morefixes.sh` — includes 00-create-role.sql for the `postgrescvedumper` role).

---

---

## Phase 1.7 — Gates G5-G7: Detection Rate Validation (D-02)

**Status:** Deferred. All infrastructure is in place. This section documents exactly what needs to happen before Phase 2 can begin.

**Why deferred:** Running 3,877 benchmark cases through Claude via the MCP server requires: (a) API cost for each scan invocation, (b) orchestration to feed each case through the MCP server and collect findings, (c) scoring the findings against ground truth using the Phase 0.5 benchmark runner. This is a focused evaluation session, not an infrastructure task.

**What exists (all complete):**
- MCP server with 4 agents (scan_sqli, scan_cmdi, scan_ssti, scan_xss)
- 9 benchmark datasets ingested: 3,877 cases after PrimeVul dedup
- Benchmark runner (`benchmarks/runner/`) with TPR/FPR/F1 metrics, CWE-1400 scoring, Markdown reports
- Validation gates defined in `docs/PHASE_0_5_VALIDATION_GATES.md`

**Procedure to execute G5-G7:**

1. **Build an orchestration script** that iterates each benchmark case, calls the appropriate MCP scan tool (via the engine's `assemble_scan()`), feeds the assembled prompt + code to Claude, and collects Claude's structured findings.

2. **Convert findings to bentoo-sarif format** — each finding must become a SARIF result with `ruleId: CWE-<id>` and `kind: fail` at the reported location. Use `formatter.py`'s SARIF output.

3. **Run the benchmark evaluator:**
   ```bash
   uv run python -m benchmarks.runner \
       --agent-output <agent-sarif-dir> \
       --ground-truth <manifest> \
       --report-dir <output-dir>
   ```

4. **Check thresholds (G5):**

   | Agent | Dataset | Metric | Threshold |
   |---|---|---|---|
   | xss | ossf-cve-benchmark (XSS subset) | TPR | >= 70% |
   | xss | ossf-cve-benchmark (patched) | FPR | <= 25% |
   | xss | reality-check-csharp (CWE-79) | TPR | >= 60% |
   | xss | reality-check-python (CWE-79) | TPR | >= 60% |
   | cmdi | ossf-cve-benchmark (CmdI subset) | TPR | >= 60% |
   | cmdi | reality-check-java (CWE-78) | TPR | >= 50% |
   | sqli | morefixes (CWE-89) | TPR | >= 50% |
   | ssti | go-sec-code-mutated (CWE-1336) | TPR | >= 70% |
   | ssti | skf-labs-mutated (CWE-1336) | TPR | >= 70% |

5. **G6: Rust disclaimer** — verify the benchmark report explicitly states "Rust detection quality not benchmarked — see ADR-014."

6. **G7: Failure dump** — for any threshold miss, the report must include the first 10 missed CVEs and false flags with file paths and expected vs actual findings.

**If thresholds are not met:** This feeds into the autoresearch loop (Phase 5). Agents can be iteratively improved by adjusting their YAML detection heuristics and re-running the benchmarks. For Phase 1, a single pass is expected — thresholds were set conservatively (real-world SAST tools average 12.7% TPR on real CVEs per SMU paper; our 50-70% targets are ambitious but achievable with curated knowledge).

---

## Phase 0.5 retrospective — Benchmark Infrastructure Sprint (complete)

**Why this existed:** Phase 1 validation cannot rely on self-authored fixtures. We need a real-world CVE benchmark harness using datasets from the flawgarden ecosystem, the OpenSSF JS/TS benchmark (218 real CVEs — biggest single data source for our XSS and CmdI agents), and multi-language CVE extraction via MoreFixes.

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

## Phase 1 — Core Infrastructure (complete, PR #2 merged 2026-04-10)

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
| Phase 0.5 | Benchmark Infrastructure Sprint | **Complete** |
| Phase 1 | Core Infrastructure (MCP server, agent registry, target resolver) | **Complete** (PR #2, 2026-04-10) |
| **Phase 1.7** | **Gates G5-G7: Detection rate validation (D-02)** | **NEXT** |
| Phase 2 | Claude Code Integration (subagents, skills, filesystem output, FP learning) | Blocked on G5-G7 |
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
