# Project Status — screw-agents

> Last updated: 2026-04-29

## Deferred Obligations

Items explicitly deferred from earlier phases that must be completed in later phases. This section is prominent on purpose — deferred work must not be forgotten.

| # | Item | Deferred from | Owning phase | Tracking ADR | Status |
|---|---|---|---|---|---|
| D-01 | Rust benchmark corpus from GitHub Advisory Database + synthetic SSTI fixtures | Phase 0.5 | **Phase 4 (step 4.0)** — hard gate, Phase 4 cannot close without it | ADR-014 | **MERGED** — PR #17, real-CVE corpus + synthetic SSTI inventory |
| D-02 | Gates G5-G7: detection rate validation against real-CVE benchmarks | Phase 1 (Task 20) | **Phase 4** — full run deferred to autoresearch loop | — | **IN PROGRESS** — PR #18 merged dry-run planning, gate correction, failure-input schema, and controlled-run scaffold; dataset readiness checklist active on `phase4-d02-readiness` |
| D-03 (pointer) | Broader deferred backlog (114 active entries post-T24) | Across all phases | Various — see DEFERRED_BACKLOG §"Phase-4 Readiness Triage" | — | **TRIAGED** — see `docs/DEFERRED_BACKLOG.md` for `blocker` / `nice-to-have` / `phase-7-scoped` / `retire` tags |

**When returning to Phase 4:** D-01 is merged. Continue D-02 from
`docs/PHASE_4_D02_PLAN.md` and use `docs/PHASE_4_OPERATING_MAP.md` for the
full safe-planning/materialization/paid-execution sequence; do not run
expensive benchmarks until the dry-run plan's dataset and gate-definition
issues are addressed. The controlled executor supports focused reruns with
repeatable `--agent` and `--case-id` filters, so concrete failure-payload
examples can be revalidated without repeating the full smoke set. It also
supports opt-in related-file prompt context for multi-file benchmark cases,
which has been verified on the CmdI/Plexus slice: patched-version findings
dropped to zero, while remaining misses now need review as possible truth-span
granularity artifacts before another `cmdi.yaml` refinement. That review found
two truth-span granularity cases and one bridge-method localization gap. A
trial `cmdi.yaml` localization prompt was rejected because it caused
vulnerable-side over-reporting; keep `cmdi.yaml` at v1.0.1 and address the
remaining gap in scoring/failure-analysis tooling. Failure payloads now surface
same-file related agent findings and summary diagnostic counts for missed truth
spans to make that review explicit.

**When starting Phase 4:** D-02 threshold optimization runs as part of the autoresearch loop. The benchmark pipeline is validated (PR #3).

---

## Current Phase: Phase 4 D-02 — autoresearch planning scaffold in progress

Architecture and product design is **complete** (PRD v0.4.3). Phases 0 / 0.5 / 1 / 1.7 / 2 all **complete**. **Phase 3a** is **complete** — PR #6-#9 series merged 2026-04-16/17. **Phase 3b (Adaptive Analysis & Learning Refinement)** is in progress:
- **PR #4 (#10)** merged 2026-04-18 — adaptive-script executor pipeline + Layer 1 lint + Layer 5 sandbox + MCP tool.
- **PR #5 (#11)** merged 2026-04-20 — adaptive workflow (D1+D2 gap detection, trust-path signing, cleanup). Surfaced C1 + I1-I6.
- **PR #6 (#12)** merged 2026-04-23 (squash `fa2f42a`) — C1 staging architecture + I1-I6 polish. Test count 771 → 942 (+171). **C1 ENGINE-LAYER CLOSURE VERIFIED** via T21 E2E exit gate (`tests/test_adaptive_workflow_staged.py`); Step 11 sha256 + Step 12 read-and-compare both pass on bwrap sandbox.
  - **Post-merge finding (2026-04-23):** manual round-trip validation revealed that Claude Code's subagents cannot dispatch other subagents (nested Task dispatch unsupported per [official docs](https://code.claude.com/docs/en/sub-agents)). PR #6's T15-T17 prompt design assumed scan subagents could invoke `screw:screw-script-reviewer` for Layer 0d — architecturally incorrect. Result: `--adaptive` silently degraded to YAML-only (nothing reached `stage_adaptive_script`). **Addressed by Phase 3b-C2** (see next bullet).
- **Phase 3b-C2 (branch `phase-3b-c2-nested-dispatch-fix`)** merged 2026-04-24 — nested-dispatch fix. `/screw:scan` rewritten as main-session chain-subagents orchestrator: scan subagents now do scan + generate + lint, return structured JSON `pending_reviews` to main; main session owns reviewer dispatch, staging, `verify_trust` advisory-loud check (new spec §4.7 D7), promote, execute, accumulate, finalize. 4 per-agent subagents (sqli/cmdi/ssti/xss) truncated to byte-identical clones modulo agent name; `screw-full-review.md` deleted (second nested-dispatch instance, Option A fold+delete). Verified by T10 live round-trip: `stage_adaptive_script` reached from main, end-to-end adaptive flow works. Test count 942 → 918 passed (33 parametrized cases deleted + 9 new scan.md assertions). Adaptive mode is production-ready.
- **BACKLOG-PR6-22 (branch `retire-sign-adaptive-script`)** merged 2026-04-24 — full C1 closure at the MCP boundary. `engine.sign_adaptive_script` method + tool descriptor + dispatcher entry deleted; the direct-sign path no longer exists for programmatic consumers. `tests/test_sign_adaptive_script.py` and `tests/test_adaptive_workflow.py` deleted (the latter fully subsumed by the staged E2E); `test_adaptive_executor.py::signed_script_setup` migrated to stage→promote; `adaptive/signing.py` docstrings updated. Phase 4's autoresearch module (BACKLOG-PR6-13) now has no direct-sign path to bind to — it MUST use `stage_adaptive_script` → `promote_staged_script`. Test suite: 918 → 898 passed, 8 skipped; zero regressions. Phase 4 blocker count drops 4 → 3.
- **T19-M1/M2/M3 bundle (branch `phase-4-prep-t19m`)** merged 2026-04-24 — Phase-4 prereq closure. M3 migrates `Finding.merged_from_sources` from `list[str]` to `list[MergedSource]` (structured `{agent, severity}` Pydantic BaseModel). M1 surfaces the structured format in SARIF (`properties.mergedFromSources` per SARIF 2.1.0 §3.8) and CSV (appended `merged_sources` column, `"; "`-joined for merged; empty for unmerged; positional-parser-safe). M2 teaches `render_and_write`'s exclusion matcher to iterate primary + merged sources in deterministic primary-first, first-match-wins order; `exclusions_applied` entries gain `matched_via_agent` for audit trail. D7 flips default format list from `["json", "markdown"]` to `["json", "markdown", "csv"]`. Test suite: 898 → 906 passed, 8 skipped; zero regressions. Phase 4 blocker count drops 3 → 1 (only T-FULL-P1 remains; D-01 is Phase 4 step 4.0 itself).
- **T-SCAN-REFACTOR (branch `t-scan-refactor`)** merged 2026-04-25 — Final Phase-4 prereq. Subsumes T-FULL-P1. Replaces 6-tool scan surface (`scan_full` + `scan_domain` + 4 per-agent) with `scan_agents` paginated primitive + `scan_domain` thin wrapper. Adds per-agent language relevance filter (`_filter_relevant_agents`) with extension + shebang detection. Cursor binding generalized to `(target_hash, agents_hash)` (Option β). Rewrites slash command for multi-scope syntax (`/screw:scan domains:A,B agents:1A,2A`). Collapses 5 subagents into universal `screw-scan.md`. Test suite: 906 → 996 passed, 9 skipped (HEAD baseline `c7fa9d9`). Phase 4 blocker count drops 1 → 0.
- **Phase 3c (sandbox hardening sweep)** — deferred; see DEFERRED_BACKLOG §Phase 3c.

Gates G1-G4 pass. **Phase 4 D-02 planning scaffold shipped in PR #18; dataset
readiness closure is active on branch `phase4-d02-readiness`.** D-01 shipped in
PR #17.

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
| 0.5.13 | Ingest go-sec-code-mutated | **Complete** — D-02 audit found tracked manifest is SQLi/CWE-89, not SSTI/CWE-1336 |
| 0.5.14 | Ingest skf-labs-mutated | **Complete** — D-02 audit found tracked manifest is SQLi/CWE-89, not SSTI/CWE-1336 |
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

- **Gates G5-G7: full benchmark run** — deferred to Phase 4 autoresearch; pipeline validated via sample run (2026-04-11)
- Remaining 14 agents (CWE-1400 domains 2-18) not yet researched (Phase 6)
- Rust benchmark corpus is partially built: initial real-CVE Rust cases cover SQLi, CmdI, and XSS; Rust SSTI remains synthetic-only unless a verified real advisory appears during refresh.
- screw.nvim integration (Phase 7)

### Known Limitations (from Phase 2 E2E testing)

These are documented in `docs/PHASE_2_E2E_RESULTS.md` "Known Limitations" section:

1. **Subagent nesting depth:** Claude Code can't nest 3+ subagent levels. For Phase 6 (18 domains), the skill should dispatch domain orchestrators directly instead of going through screw-full-review. *(Resolved 2026-04-23 by Phase 3b-C2 (commit fa2f42a) — `screw-full-review` deleted; chain-subagents architecture moved orchestration to main session. ADR-016 superseded.)*
2. **scan_domain payload size:** Responses can reach 47k-277k tokens for large targets, exceeding tool-response limits. Track for Phase 3 optimization. *(Resolved 2026-04-17 by Phase 3a X1-M1 (pagination) and again 2026-04-25 by T-SCAN-REFACTOR (`scan_agents` paginated primitive).)*
3. **CSV output format:** Requested but deferred — not blocking any phase. *(Resolved 2026-04-24 by T19-M D7 (commit 02d90d1) — CSV is in the default `formats=['json','markdown','csv']` list.)*
4. **Benchmark exclusion isolation:** `.screw/learning/exclusions.yaml` must be ignored or scoped out during benchmark evaluation runs (Phase 4) to prevent FP exclusions from suppressing true positives in benchmark fixtures.
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

**Status:** Sample complete. Pipeline validated, detection confirmed. Full run deferred to Phase 4 autoresearch loop (deliberate decision — see rationale below).

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

5. **go-sec-code and skf-labs contain CWE-89 (SQLi), not CWE-1336 (SSTI).** Gates G5.9 and G5.10 previously referenced ssti/go-sec-code and ssti/skf-labs. D-02 Task 3 retires those gates rather than relabelling SQLi evidence as SSTI coverage.

### Next steps for full run

Before the full run, these items must be addressed:

1. **Correct G5.9/G5.10 gate definitions** — DONE in D-02 Task 3: retired because go-sec-code and skf-labs are SQLi (CWE-89), not SSTI. Future SSTI gates require actual SSTI benchmark data.
2. **Add ossf-cve-benchmark to the evaluation** — requires code extraction from npm packages (not yet implemented).
3. **Regenerate MoreFixes materialization** — D-02 now uses `morefixes`
   directly; requires Docker + Postgres to write `truth.sarif` plus code
   snapshots.
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

### Decision: defer full run to Phase 4 (2026-04-11)

The full benchmark run (~2,934 Claude calls, 50-73 hours) is deferred to Phase 4's autoresearch loop. Rationale:

1. **Pipeline is validated.** The sample proved end-to-end correctness: code extraction, prompt assembly, Claude invocation, finding parsing, pair-based scoring, gate checking, report generation, checkpoint/resume.
2. **Detection is confirmed.** Agents genuinely detect real-world CVEs (100% XSS/CrossVul, 30-50% CmdI/SQLi). The YAML knowledge from Phase 0 works.
3. **Phase 2 does not depend on specific TPR numbers.** Claude Code integration (subagents, skills, filesystem output) depends on the MCP server and engine working correctly — which they do.
4. **Phase 4 autoresearch is the right place to optimize.** It systematically runs benchmarks, analyzes failures, adjusts YAML heuristics, and re-runs. Manual full-run optimization now would be superseded by that automated loop.
5. **Resource cost is disproportionate.** 50-73 hours of Pro subscription usage for numbers that will change once autoresearch tunes the YAMLs.

D-02 status changed from "pre-Phase 2 hard gate" to "pipeline validated, threshold optimization deferred to Phase 4." This is not skipping validation — it is sequencing it correctly.

---

## Phase 0.5 retrospective — Benchmark Infrastructure Sprint (complete)

**Why this existed:** Phase 1 validation cannot rely on self-authored fixtures. We need a real-world CVE benchmark harness using datasets from the flawgarden ecosystem, the OpenSSF JS/TS benchmark (218 real CVEs — biggest single data source for our XSS and CmdI agents), and multi-language CVE extraction via MoreFixes.

### Five architectural decisions locked in (2026-04-09)

1. **Full sprint scope — no cuts.** Includes PrimeVul methodology, MoreFixes pipeline, CWE-1400 evaluator, all benchmark ingestion. Rationale: weak benchmark infrastructure makes Phase 1 validation meaningless and breaks the autoresearch loop downstream (ADR-006).

2. **PrimeVul methodology mandatory.** Deduplication, chronological splits, cross-project holdouts, pair-based evaluation. Non-negotiable because SOTA LLM models drop from 68% F1 on Big-Vul to 3% F1 on PrimeVul without these controls — our autoresearch loop (PRD §11.3) will silently overfit without proper methodology.

3. **Build our own Python evaluator, CWE-1400 native (ADR-013).** Reject direct bentoo adoption because bentoo scores in CWE-1000 Research View, which would force taxonomy translation everywhere and break the "universal join key" contract (ADR-002). Consume bentoo-sarif format as input, score in CWE-1400, emit bentoo-compatible `summary.json` for optional cross-check.

4. **Rust corpus deferred to Phase 4 (ADR-014).** Triple-redundantly tracked (ADR-014, PRD §12 step 4.0, Deferred Obligations D-01 above). Current Rust fixtures downgraded to smoke-test status. Phase 1 benchmark reports explicitly say "Rust detection quality not benchmarked — see ADR-014."

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

**0.5.4 — Rust benchmark deferred to Phase 4** (see Deferred Obligations D-01 and ADR-014)
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
- **Primary benchmark sources:** ossf-cve-benchmark (JS/TS), flawgarden/reality-check (Java/C#/Go/Python), go-sec-code-mutated + skf-labs-mutated (tracked SQLi/CWE-89 manifests), CrossVul (PHP/Ruby), Vul4J (Java precision), MoreFixes (multi-language extraction)
- **Benchmark exclusions:** OWASP Benchmark, WebGoat, DVWA, Juice Shop — all excluded as synthetic or too weak for validation; bentoo as primary evaluator rejected in ADR-013

---

## Full Phase Plan (from PRD §12)

| Phase | Focus | Status |
|---|---|---|
| Phase 0 | Knowledge Research Sprint | **Complete** (4/4 Phase 1 agents) |
| Phase 0.5 | Benchmark Infrastructure Sprint | **Complete** |
| Phase 1 | Core Infrastructure (MCP server, agent registry, target resolver) | **Complete** (PR #2, 2026-04-10) |
| Phase 1.7 | Gates G5-G7: Detection rate validation (D-02) | **Complete** (pipeline validated, PR #3, 2026-04-11) |
| Phase 2 | Claude Code Integration (subagents, skills, filesystem output, FP learning) | **Complete** (PR #4 2026-04-11, PR #5 2026-04-12) |
| Phase 3a | Prompt infrastructure (trust, learning aggregation, plugin-namespace, core-prompt dedup) | **Complete** (PR #6-#9 series, merged 2026-04-16/17) |
| Phase 3b | Adaptive Analysis & Learning Refinement | **Complete** — PR #4 (#10) 2026-04-18, PR #5 (#11) 2026-04-20, PR #6 (#12) 2026-04-23, Phase 3b-C2 2026-04-24, BACKLOG-PR6-22 (#14) 2026-04-24, T19-M D7 (#15) 2026-04-24, T-SCAN-REFACTOR final 2026-04-25 |
| Phase 3c | Sandbox hardening sweep (seccomp filter + thread-safety + dedup) | **Deferred** — see `docs/DEFERRED_BACKLOG.md` §"Phase 3c (sandbox hardening follow-ups)" |
| Phase 4 | Autoresearch & Self-Improvement | **In progress** — D-01 merged, D-02 controlled smoke, focused refinements, and non-OSSF consolidation execution complete; consolidation false-positive review next |
| Phase 5 | Multi-LLM Challenger System | Pending |
| Phase 6 | Agent Expansion & Ecosystem | Pending |
| Phase 7 | screw.nvim Integration (scan commands, review-before-import, exclusions) | Pending |

---

## Phase 4 Prerequisites (hard gates)

Phase 4 (Autoresearch & Self-Improvement) started with D-01. As of
2026-04-29, D-01 is merged, D-02 planning scaffold is merged in PR #18, active
G5 dataset readiness is clean in the long-lived main checkout after core
dataset and MoreFixes materialization, the first controlled smoke execution has
completed successfully, and concrete failure-input payloads can be generated
from the controlled run output.

### D-01 — Rust benchmark corpus from GitHub Advisory Database + synthetic SSTI
**Status:** MERGED in PR #17
**Why gating:** Phase 4 step 4.0 IS D-01. See ADR-014 and `docs/research/benchmark-tier4-rust-modern.md`.
**Current implementation:** `benchmarks/scripts/refresh_rust_advisories.py`,
`benchmarks/scripts/review_rust_advisory_candidates.py`,
`benchmarks/data/rust-d01-reviewed-seeds.json`,
`benchmarks/scripts/materialize_rust_d01.py`,
`benchmarks/external/manifests/rust-d01-real-cves.manifest.json`, and
`benchmarks/data/rust-d01-synthetic-ssti.json`.
**Current scope:** live refresh currently yields 53 Rust advisory candidates; initial tracked corpus includes 4 real-CVE cases for SQLi/Cmdi/XSS plus labelled synthetic SSTI fixtures.

### D-02 — Detection-rate validation thresholds (SAMPLE COMPLETE)
**Status:** Pipeline validated (PR #3, 2026-04-11); dry-run planning,
gate correction, failure-input schema, and controlled-run scaffold merged in
PR #18; active dataset readiness materialization and controlled smoke execution
are complete.
**Why gating:** Not a hard blocker to STARTING Phase 4 — autoresearch IS the threshold-tuning loop. But the benchmark run feeds D-01's corpus. Sequenced inside Phase 4, not before.

**Current D-02 closure:** `G5.8` now targets `morefixes` rather than stale
`morefixes-extract`; misleading SSTI gates `G5.9`/`G5.10` are retired instead
of relabelling SQLi evidence as SSTI coverage; MoreFixes materialization writes
code snapshots for the runner; Rust D-01 extraction reads local git clones from
provenance refs; Vul4J code extraction remains deferred until a checkout
convention is defined; failure-analysis input schema
`phase4-autoresearch-failure-input/v1` requires concrete case-level examples
before any future YAML mutation can be allowed; controlled-run preparation
now defaults to a blocked `required-dataset-smoke` plan that selects one small
slice for each active G5 dataset/agent pair and records deterministic
`selected_case_ids`; selection now requires matching truth and locally
extractable vulnerable/patched code. The controlled executor validates those
exact cases before any Claude call. The plan still requires explicit
`--allow-claude-invocation` before it can become executable, and the executor
requires a second `--execute --allow-claude-invocation` before it can invoke
Claude. The readiness checklist command is
`uv run python benchmarks/scripts/check_autoresearch_readiness.py`; the
long-lived main checkout currently has all active G5 truth files restored after
OSSF, reality-check, and MoreFixes materialization. A fresh worktree will still
report blockers until the ignored external datasets are restored there. OSSF is
truth-materialized only: its ingest restores `truth.sarif` files but not the
target-project vulnerable/patched source snapshots. Reality-check restoration
is verified as executable source material. Unchanged manifest regeneration
preserves the existing `ingested_at` value to avoid timestamp-only churn.
MoreFixes Docker/Postgres restoration is now verified with explicit empty-volume
import handling. The extractor materializes 2,601 case truth files plus 6,825
vulnerable and 6,825 patched snapshots, and streams rows to avoid the previous
large Python memory spike.
On 2026-04-29 the reviewed controlled smoke run executed seven active G5
dataset/agent slices and wrote 14 vulnerable/patched result JSON files with no
executor issues. The controlled executor report now surfaces overall metrics
and per-case finding counts directly in Markdown/JSON. Initial results are
diagnostic: several XSS and OSSF CmdI slices produced misses, while Reality
Check Java CmdI and SQLi produced some true positives plus false positives.
These concrete outcomes can now be converted by
`benchmarks/scripts/generate_autoresearch_failure_inputs.py` into
`phase4-autoresearch-failure-input/v1` payloads. Verified payload generation
from the first smoke output produced `cmdi` (5 missed, 3 false-positive), `sqli`
(5 missed), and `xss` (3 missed) payloads with YAML mutation disabled. Payload
review is the next step before any YAML refinement is considered. First CmdI
payload review rejected the OSSF miss as bad source-material evidence and
accepted the Plexus Java shell-wrapper examples as a narrow agent-knowledge
refinement: `cmdi.yaml` now records custom Java shell-wrapper builders and
patched single-quote wrapper overrides as a false-positive discriminator.
Follow-up CmdI/Plexus related-context execution removed patched findings but
left three vulnerable-side misses, so `cmdi.yaml` remains at v1.0.1 after a
rejected over-reporting v1.0.2 trial. SQLi/NHibernate review then accepted a
narrow `sqli.yaml` v1.0.1 refinement for C# ORM SQL literal/comment renderers;
the focused rerun on `rc-csharp-nhibernate-core-CVE-2024-39677` improved from
1 to 3 vulnerable findings while keeping patched findings at 0. SQLi/MoreFixes
Rails review then rejected a YAML change: the agent already found the real
vulnerable `add_limit_offset!` LIMIT/OFFSET interpolation and kept patched
files clean, while remaining misses are test-file truth spans or line drift
around `sanitize_limit`; the extra `add_lock!` vulnerable-side report is
outside the CVE-2008-4094 truth and argues against broadening the rule.
XSS triage initially rejected an `xss.yaml` change because the first XSS
payload surfaced one missing source excerpt, one sanitizer test-path span, and
one Zope framework helper span needing manual review. Follow-up Zope review
accepted a narrow `xss.yaml` v1.0.1 refinement for CVE-2009-5145: vulnerable
Zope PageTemplates push raw `request` into the `TemplateDict`/`RestrictedDTML`
namespace, while the patched version preserves taint metadata with
`request.taintWrapper()`. The focused executor rerun on
`rc-python-Zope-CVE-2009-5145` improved to TP 1, FP 0, TN 1, FN 0. The OSSF
extractor now rejects fallback files that do not cover the SARIF truth line
range, preventing the `ossf-CVE-2018-16484` one-line metadata-repo `index.js`
mismatch from being selected as valid XSS evidence. Follow-up OSSF/XSS
validation found the same class of problem in a harder form:
`ossf-CVE-2019-13506` matched the benchmark metadata repo's report server
`src/index.ts` by path and line number, not the devalue target source. The
extractor now refuses to read from the OSSF metadata clone at all until target
source snapshots are materialized. After OSSF was blocked, a filtered non-OSSF
consolidation execution ran the five currently executable slices
(AntiSamy/XSS, Zope/XSS, Plexus/CmdI, NHibernate/SQLi, MoreFixes Rails/SQLi)
at `/tmp/screw-d02-nonossf-consolidation-run`, benchmark run
`20260429-182422`. No executor issues were reported. Zope stayed fully clean,
NHibernate retained its accepted high-precision v1.0.1 behavior, and AntiSamy
remained a test-file truth-span miss. Plexus produced a patched `Shell.java`
finding when run without related context, so future Plexus validation should
keep using `--include-related-context`. MoreFixes Rails produced patched
`add_lock!` and `insert_fixture` findings in the consolidation run despite the
earlier focused Rails run keeping patched files clean; treat those concrete
false positives as the next SQLi precision/repeatability review item before
any further YAML change. A fresh Rails-only repeat reproduced the patched
`add_lock!` and `insert_fixture` reports, so this is repeatable prompt
behavior. The CVE-2008-4094 truth is specifically `add_limit_offset!` /
`sanitize_limit`; `add_lock!` and `insert_fixture` are unchanged framework
helpers. A broad SQLi prompt trial was rejected because it suppressed the real
`add_limit_offset!` finding. The accepted `sqli.yaml` v1.0.2 refinement is
narrower: Rails/ActiveRecord lock-clause and fixture helpers are
context-required unless visible attacker-controlled data flows into the
option/object, while vulnerable LIMIT/OFFSET appenders remain reportable.
Focused v1.0.2 rerun
`/tmp/screw-d02-sqli-morefixes-rails-precision-v102b-run` improved the slice to
TP 1, FP 0, TN 5, FN 4 with one vulnerable `add_limit_offset!` finding and zero
patched findings.

**When continuing Phase 4:** Continue from `docs/PHASE_4_D02_PLAN.md`; keep Rust metric claims scoped to real-CVE SQLi/Cmdi/XSS and synthetic-only SSTI unless refresh finds a verified SSTI advisory.
Use `docs/PHASE_4_OPERATING_MAP.md` as the high-level map before restoring
ignored external datasets or allowing Claude benchmark execution.

---

## Marco's Environment & Preferences

- **OS:** Arch Linux
- **Editor:** Neovim (screw.nvim author)
- **Package manager:** `uv` (pip install restricted on Arch — see ADR-011)
- **Languages:** Significant Rust development; also Python, TypeScript, others
- **Rust benchmark scope:** D-01 is merged; current real-CVE Rust coverage is scoped to SQLi/Cmdi/XSS, with SSTI synthetic-only unless a verified real advisory appears.
