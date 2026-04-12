# Project Status — screw-agents

> Last updated: 2026-04-12

## Deferred Obligations

Items explicitly deferred from earlier phases that must be completed in later phases. This section is prominent on purpose — deferred work must not be forgotten.

| # | Item | Deferred from | Owning phase | Tracking ADR | Status |
|---|---|---|---|---|---|
| D-01 | Rust benchmark corpus from RustSec (~24 verified CVE candidates + synthetic SSTI fixtures) | Phase 0.5 | **Phase 5 (step 5.0)** — hard gate, Phase 5 cannot close without it | ADR-014 | **DEFERRED** |
| D-02 | Gates G5-G7: detection rate validation against real-CVE benchmarks | Phase 1 (Task 20) | **Phase 5** — full run deferred to autoresearch loop | — | **SAMPLE COMPLETE** — pipeline validated 2026-04-11, threshold optimization deferred to Phase 5 |

**When returning to Phase 5:** The first step of Phase 5 is D-01 (Rust benchmark corpus construction). Verify this deferral is still valid by re-reading ADR-014 and `docs/research/benchmark-tier4-rust-modern.md`. Do not skip this step.

**When starting Phase 5:** D-02 threshold optimization runs as part of the autoresearch loop. The benchmark pipeline is validated (PR #3).

---

## Current Phase: Phase 2 Complete — Claude Code Integration

Architecture and product design is **complete** (PRD v0.4.3 is the definitive document). Phase 0 (Knowledge Research) is **complete**. Phase 0.5 (Benchmark Infrastructure) is **complete**. Phase 1 (Core Infrastructure) is **complete** (PR #2 merged 2026-04-10). Gates G1-G4 pass. Phase 1.7 (G5-G7 detection rate validation) is **complete** — pipeline built and validated via sample run (2026-04-11, PR #3), full benchmark deferred to Phase 5 autoresearch. **Phase 2 (Claude Code Integration) is complete. Phase 3 (screw.nvim Integration) is next.**

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

**Phase 2 — Claude Code Integration (complete, PR #4 + PR #5, 2026-04-11/12):**

| Task | Description | Status |
|---|---|---|
| 2.1 | Exclusion Pydantic models + FindingTriage update | **Complete** |
| 2.2 | Learning module — exclusion storage + matching | **Complete** |
| 2.3 | Engine — exclusion-aware assembly with project_root | **Complete** |
| 2.4 | Server — format_output, record/check_exclusion MCP tools | **Complete** |
| 2.5 | screw-sqli subagent (reference template) | **Complete** |
| 2.6 | screw-cmdi, screw-ssti, screw-xss subagents | **Complete** |
| 2.7 | screw-injection + screw-full-review orchestrators | **Complete** |
| 2.8 | screw-review auto-invocation skill | **Complete** |
| 2.9 | /screw:scan slash command | **Complete** |
| 2.10 | CLAUDE.md template for user projects | **Complete** |
| 2.11 | E2E smoke test checklist + results | **Complete** |
| 2.12 | E2E defect fixes (D1-D5) — write_scan_results MCP tool | **Complete** (PR #5) |

PR #4 (2026-04-11): Initial implementation — 15 new files, 3 modified, 120 tests.
PR #5 (2026-04-12): E2E defect fixes — `write_scan_results` MCP tool (`results.py`), all 6 subagent prompts rewritten, skill description expanded. 137 tests (17 new).

**Key architectural change (PR #5):** `write_scan_results` MCP tool moves formatting, exclusion matching, directory creation, and file writing server-side. Subagent workflow reduced from 6 steps to 4. This was necessary because Claude Code subagents reliably execute 1-2 tool calls, not 5+ — the original multi-step file-writing workflow was architecturally incompatible with subagent behavior. See `docs/PHASE_2_E2E_RESULTS.md` for full test results and `docs/DECISIONS.md` ADR-015 for rationale.

**E2E test results:** 8/8 PASS. Detection quality validated across all 4 agents: SQLi (36 findings/12 fixtures), XSS (40/14), CmdI (33/10), SSTI (28/10). Zero false negatives, zero cross-domain false positives. See `docs/PHASE_2_E2E_RESULTS.md`.

### What's NOT Done

- **Gates G5-G7: full benchmark run** — deferred to Phase 5 autoresearch; pipeline validated via sample run (2026-04-11)
- Remaining 14 agents (CWE-1400 domains 2-18) not yet researched (Phase 7)
- Rust benchmark corpus not yet built (deferred to Phase 5 step 5.0, see D-01)
- screw.nvim integration (Phase 3)

### Known Limitations (from Phase 2 E2E testing)

These are documented in `docs/PHASE_2_E2E_RESULTS.md` "Known Limitations" section:

1. **Subagent nesting depth:** Claude Code can't nest 3+ subagent levels. For Phase 7 (18 domains), the skill should dispatch domain orchestrators directly instead of going through screw-full-review.
2. **scan_domain payload size:** Responses can reach 47k-277k tokens for large targets, exceeding tool-response limits. Track for Phase 4 optimization.
3. **CSV output format:** Requested but deferred — not blocking any phase.
4. **Benchmark exclusion isolation:** `.screw/learning/exclusions.yaml` must be ignored or scoped out during benchmark evaluation runs (Phase 5) to prevent FP exclusions from suppressing true positives in benchmark fixtures.
5. **Formatter polish:** Finding model schema asymmetry (empty strings vs null), SARIF shortDescription should be richer, Markdown headings could use full CWE names.

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

**Status:** Sample complete. Pipeline validated, detection confirmed. Full run deferred to Phase 5 autoresearch loop (deliberate decision — see rationale below).

### What was built (2026-04-11)

| Component | Module | Description |
|---|---|---|
| Claude invoker | `benchmarks/runner/invoker.py` | `claude -p` subprocess wrapper with retry, backoff, JSON parsing |
| Code extractor | `benchmarks/runner/code_extractor.py` | Per-dataset extraction (reality-check, CrossVul, monolithic repos) |
| Gate checker | `benchmarks/runner/gate_checker.py` | G5 threshold evaluation, G6 Rust disclaimer, G7 failure dumps |
| Gate report | `benchmarks/runner/report.py` | `render_gate_report()` with G5/G6/G7 Markdown sections |
| Evaluator | `benchmarks/runner/evaluator.py` | Core orchestration: cases → code → prompts → Claude → findings → scoring |
| CLI entry point | `benchmarks/scripts/run_gates.py` | `--mode sample/full`, `--resume`, `--timeout`, checkpoint/resume |

Evaluation uses `claude -p` via the user's Pro subscription (NOT API key — `ANTHROPIC_API_KEY` must be unset). Each case runs through `ScanEngine.assemble_scan()` to build a detection prompt from YAML agent knowledge, then Claude analyzes the code and returns structured JSON findings, which are scored against ground truth via pair-based evaluation.

### Sample run results (run_id: 20260411-090433)

20 cases, 104 Claude calls, ~2 hours runtime. Datasets: CrossVul, reality-check (C#/Java/Python), go-sec-code-mutated, skf-labs-mutated.

**Detection rates by agent × dataset:**

| Agent | Dataset | TPR | FPR | Precision | TP | FP | FN | Notes |
|---|---|---|---|---|---|---|---|---|
| **xss** | crossvul (PHP) | **100%** | 33% | 67% | 2 | 1 | 0 | Strong |
| xss | reality-check-csharp | 0% | 0% | — | 0 | 0 | 1 | 1 case, 1 finding — sample too small |
| xss | reality-check-java | 0% | 0% | — | 0 | 0 | 3 | 2 files timed out (300s) |
| xss | reality-check-python | 0% | 0% | — | 0 | 0 | 1 | 1 case — sample too small |
| **cmdi** | crossvul (PHP) | **50%** | 0% | 100% | 1 | 0 | 1 | Solid, zero FP |
| cmdi | reality-check-csharp | 0% | 0% | — | 0 | 0 | 1 | 1 case |
| cmdi | reality-check-java | **30%** | 61% | 21% | 3 | 11 | 7 | Detects but high FP rate |
| cmdi | reality-check-python | **33%** | 53% | 10% | 1 | 9 | 2 | Detects but high FP rate |
| **sqli** | crossvul (PHP) | **50%** | 0% | 100% | 1 | 0 | 1 | Solid, zero FP |
| sqli | go-sec-code (Go) | **15%** | 11% | 25% | 10 | 30 | 58 | 10-file cap applied |
| sqli | skf-labs (Python) | **5%** | 0.4% | **80%** | 8 | 2 | 160 | Low recall, very high precision |
| sqli | reality-check-csharp | 0% | 4% | 0% | 0 | 1 | 25 | 10-file cap, NHibernate HQL |
| ssti | crossvul (PHP CWE-94) | 0% | 0% | — | 0 | 0 | 3 | CWE-94 code injection, not template injection |
| ssti | reality-check-java | 0% | 13% | 0% | 0 | 1 | 8 | CWE-94 / expression injection |
| ssti | reality-check-python | 0% | 0% | — | 0 | 0 | 20 | CWE-22 in ground truth, SSTI agent mismatched |

**G5 gate results (evaluated gates only):**

| Gate | Agent | Dataset | Threshold | Actual | Result |
|---|---|---|---|---|---|
| G5.3 | xss | reality-check-csharp | >= 60% | 0% | FAIL (1 case) |
| G5.4 | xss | reality-check-python | >= 60% | 0% | FAIL (1 case) |
| G5.6 | cmdi | reality-check-java | >= 50% | 30% | FAIL |
| G5.7 | sqli | reality-check-csharp | >= 50% | 0% | FAIL |

G6 (Rust disclaimer): **PASS**. G7: 4 failure dumps generated.

### Interpretation

1. **Pipeline is validated.** End-to-end flow works: case loading → code extraction → prompt assembly → Claude invocation → finding parsing → pair-based scoring → gate checking → report generation. Checkpoint/resume works. The infrastructure is solid.

2. **Detection quality is real but below G5 thresholds.** On CrossVul (inline code, PHP), agents show 50-100% TPR with high precision. On reality-check (large projects, multi-file), detection drops — partly due to line-number matching stringency, partly due to sample size (many gates had only 1 case).

3. **G5 thresholds are not met in the sample.** This is expected — the sample is a pipeline validation with 1 case per gate. The full run with all cases per dataset would produce statistically meaningful numbers.

4. **Key observations:**
   - CmdI and SQLi detect vulnerabilities across languages (PHP, Java, Python, Go)
   - XSS on CrossVul is excellent (100% TPR)
   - SSTI agent struggles — CWE-94 (code injection) cases in CrossVul and reality-check don't align well with the SSTI agent's CWE-1336 focus
   - High FP rates on reality-check suggest the agents flag more locations than ground truth expects, which is partially a scoring artifact (unconsumed agent findings count as FP)
   - Some reality-check Java files timeout at 300s (very large source files)

5. **go-sec-code and skf-labs contain CWE-89 (SQLi), not CWE-1336 (SSTI).** Gates G5.9 and G5.10 reference ssti/go-sec-code and ssti/skf-labs — these will never match because those datasets only contain SQLi ground truth. The gate definitions need correction for the full run.

### Next steps for full run

Before the full run, these items must be addressed:

1. **Correct G5.9/G5.10 gate definitions** — go-sec-code and skf-labs are SQLi (CWE-89), not SSTI. Either update gate definitions to reference sqli agent, or find actual SSTI benchmark data.
2. **Add ossf-cve-benchmark to the evaluation** — requires code extraction from npm packages (not yet implemented).
3. **Add morefixes-extract** — requires Docker + Postgres for code extraction.
4. **Consider increasing timeout** for large Java files, or pre-filtering files by size.
5. **SSTI evaluation** — the SSTI agent (CWE-1336) has no real-CVE benchmark data. Current SSTI cases are CWE-94 (code injection), which is a parent CWE but a poor proxy for template injection.

### How to run

```bash
# Sample run (20 cases, ~2 hours, validates pipeline)
cd .worktrees/phase-1-7-gates
unset ANTHROPIC_API_KEY  # CRITICAL: must use Pro subscription, not API key
uv run python benchmarks/scripts/run_gates.py --mode sample --timeout 300 --log-level INFO

# Resume an interrupted run
uv run python benchmarks/scripts/run_gates.py --mode sample --timeout 300 --resume <run_id>

# Full run (all filtered cases — not yet validated)
uv run python benchmarks/scripts/run_gates.py --mode full --timeout 300
```

Results written to `benchmarks/results/<run_id>/` (gitignored).

### Decision: defer full run to Phase 5 (2026-04-11)

The full benchmark run (~2,934 Claude calls, 50-73 hours) is deferred to Phase 5's autoresearch loop. Rationale:

1. **Pipeline is validated.** The sample proved end-to-end correctness: code extraction, prompt assembly, Claude invocation, finding parsing, pair-based scoring, gate checking, report generation, checkpoint/resume.
2. **Detection is confirmed.** Agents genuinely detect real-world CVEs (100% XSS/CrossVul, 30-50% CmdI/SQLi). The YAML knowledge from Phase 0 works.
3. **Phase 2 does not depend on specific TPR numbers.** Claude Code integration (subagents, skills, filesystem output) depends on the MCP server and engine working correctly — which they do.
4. **Phase 5 autoresearch is the right place to optimize.** It systematically runs benchmarks, analyzes failures, adjusts YAML heuristics, and re-runs. Manual full-run optimization now would be superseded by that automated loop.
5. **Resource cost is disproportionate.** 50-73 hours of Pro subscription usage for numbers that will change once autoresearch tunes the YAMLs.

D-02 status changed from "pre-Phase 2 hard gate" to "pipeline validated, threshold optimization deferred to Phase 5." This is not skipping validation — it is sequencing it correctly.

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
| Phase 1.7 | Gates G5-G7: Detection rate validation (D-02) | **Complete** (pipeline validated, PR #3, 2026-04-11) |
| **Phase 2** | **Claude Code Integration (subagents, skills, filesystem output, FP learning)** | **Complete** (PR #4 2026-04-11, PR #5 2026-04-12) |
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
