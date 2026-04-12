# Architecture Decision Records — screw-agents

This document captures every significant design decision made during the architecture phase, including the alternatives considered, the reasoning, and the tradeoffs accepted. Read the PRD (`docs/PRD.md`) for the full product specification; this document explains *why* the PRD says what it says.

---

## ADR-001: MCP Server as the Pluggable Backbone

**Decision:** All security review intelligence lives in an MCP (Model Context Protocol) server. Claude Code agents, screw.nvim, and CI/CD are thin clients that call MCP tools.

**Alternatives considered:**

1. **Embedded prompts in Claude Code agents only** — Each subagent `.md` file carries its own security knowledge as a giant system prompt. No server needed.
   - Rejected because: Not portable. screw.nvim and CI/CD can't use Claude Code agent files. Updating knowledge means editing multiple agent files. No shared target resolution logic.

2. **Code-execution agents that write their own integrations** (the anti-MCP argument) — Claude Code writes Python scripts on-the-fly to analyze code, stores and reuses them.
   - Rejected for this specific use case because:
     - screw-agents delivers *curated knowledge*, not API wrappers. An agent improvising SQLi detection heuristics on the fly produces worse results than one carrying carefully researched knowledge from CWE, OWASP, Semgrep rules, and real CVEs.
     - Target resolution (tree-sitter AST parsing, git diff extraction) is complex infrastructure that shouldn't be reimplemented per-session.
     - Portability: code-execution scripts live in Claude Code's environment. screw.nvim can't call them.
     - Context cost of our MCP is ~800-1,200 tokens (6-8 tools), not the 20k+ that triggers the anti-MCP critique.
   - However: The *adaptive analysis scripts* feature (§11.1) partially adopts this pattern for the long-tail case where standard agents encounter unfamiliar code patterns. Curated knowledge handles the 90% case; code execution handles the remaining 10%.

3. **Direct API calls from a Python CLI** — A standalone CLI tool that calls Claude API directly, no MCP protocol.
   - Rejected because: Loses integration with Claude Code's subagent system (auto-delegation, isolated context windows, background execution). MCP is the standard protocol that multiple clients already speak.

**Tradeoff accepted:** Requires MCP server installation as a separate step. Users need Python + the server package before scanning works.

---

## ADR-002: CWE-1400 as the Taxonomic Backbone

**Decision:** Agent domains are organized according to CWE-1400 (Comprehensive Categorization), with 21 categories consolidated to 18 agent domains via three practical merges.

**Problem:** The initial PRD (v0.1) used ad-hoc domain names ("Injections", "Auth", "Crypto", "Data", "Config", "Logic") that were invented without reference to any established taxonomy. This raised the question: is there a well-known, authoritative classification that the security community agrees on?

**Taxonomies evaluated (8 total):**

| Taxonomy | Why rejected as backbone |
|---|---|
| OWASP Top 10:2025 | Only 10 categories, far too coarse. "Broken Access Control" alone covers 40+ CWEs. An awareness document, not a classification system. |
| OWASP ASVS v5.0 | Excellent (17 chapters, testable requirements) but web-only. No coverage of mobile, memory safety, or systems-level vulnerabilities. |
| CWE-1000 (Research Concepts) | 10 pillars, too abstract. "Improper Control of a Resource Through its Lifetime" bundles memory safety, file handling, crypto key management, and session management. |
| CWE-699 (Software Development) | ~40 categories but NOT mutually exclusive — a CWE can appear in multiple categories, creating ambiguity about which agent "owns" a finding. |
| CWE-1003 (Simplified Mapping) | ~130 entries, used by NVD for CVE classification. Too narrow and shallow for comprehensive agent coverage. |
| CAPEC | Classifies attack patterns, not code weaknesses. Many patterns involve social engineering or physical access outside code review scope. |
| SANS Top 25 | A flat ranked list, not a taxonomy. No organizational hierarchy. Useful for prioritization only. |
| STRIDE / Seven Pernicious Kingdoms / WASC | Deprecated, too coarse, or unmaintained. |

**Why CWE-1400 won:** Three properties simultaneously:
1. **Completeness** — Every one of CWE's ~944 weaknesses appears in exactly one category
2. **Mutual exclusivity** — No overlap. No ambiguity about which agent owns a finding.
3. **Practical granularity** — 21 categories is the right number: each substantive enough for specialization, none too broad.

**Three practical merges (21 → 18):**
- Encryption (CWE-1402) + Randomness (CWE-1414) → **Cryptography** (insecure randomness is almost always a crypto concern)
- Input Validation (CWE-1406) + Improper Neutralization (CWE-1407) + Injection (CWE-1409) → **Injection & Input Handling** (these are tightly coupled: neutralization failures and injection attacks are consequences of input validation failures)

**Multi-layer architecture:** CWE-1400 is the structural backbone. Other taxonomies serve as overlays:
- OWASP Top 10:2025 → risk communication (stakeholder reports)
- OWASP ASVS v5.0 → verification depth (thoroughness levels)
- CWE/SANS Top 25 → prioritization (which agents to build first)
- CAPEC → enrichment (how each weakness is exploited)
- CWE IDs → universal join key across all layers

---

## ADR-003: OWASP Top 10:2025, Not 2021

**Decision:** All OWASP Top 10 references use the 2025 edition.

**Context:** The 2025 edition was released late 2025 and introduces two new categories (A03: Software Supply Chain Failures, A10: Mishandling of Exceptional Conditions), consolidates SSRF into A01, and reorders several categories. Since this system references OWASP Top 10 for stakeholder communication, using the superseded 2021 edition would make reports look outdated.

**Key 2021→2025 changes affecting our domain mapping:**
- SSRF (was A10:2021) is now under A01:2025 Broken Access Control
- Security Misconfiguration moved from #5 to #2
- Software Supply Chain Failures is entirely new (expanded from "Vulnerable Components")
- Mishandling of Exceptional Conditions is entirely new (error handling, fail-open)

---

## ADR-004: Git Diff / PR as First-Class Target Types

**Decision:** Target specification includes `git_diff`, `pull_request`, and `git_commits` types alongside file/glob/function/class targets.

**Reasoning:** "Review what changed in this PR" is arguably the most common real-world use case. Full-codebase scans are expensive and noisy. Git-aware targeting focuses analysis on exactly the code that needs review, dramatically reducing scope and cost. The target resolver extracts affected files and changed lines, then expands context around changes for comprehension.

**Alternative considered:** Only support file/glob targets and let the user filter manually.
- Rejected because: This pushes complexity onto the user. Claude Code subagents would need to manually run `git diff`, parse the output, construct file targets — duplicating work that the MCP server's target resolver should handle once.

---

## ADR-005: Review-Before-Import Workflow (Not Direct Import)

**Decision:** AI-generated findings are NOT automatically imported into screw.nvim's note database. Instead, they go through a triage step where the user reviews a temporary report and marks findings as confirmed/false-positive/needs-investigation before import.

**Reasoning:** Direct import would flood the screw.nvim database with AI findings of varying quality, degrading the signal-to-noise ratio that makes the plugin useful for ongoing security review work. The triage step ensures only validated findings enter the database.

**Workflow:** Agent scan → structured JSON + markdown report → user reviews → marks true positives → confirmed findings imported → false positives captured in exclusions database for future scan suppression.

**This decision is also what makes persistent learning (ADR-007) possible** — the triage step generates the training signal (which findings are FPs) that feeds back into agent improvement.

---

## ADR-006: Autoresearch Self-Improvement (Karpathy-Inspired)

**Decision:** Agents can iteratively refine their own YAML definitions by running against SAST benchmarks, measuring TPR/FPR, keeping improvements, discarding regressions.

**Inspiration:** Karpathy's `autoresearch` repo — an AI agent modifies code, runs an experiment, checks if the result improved, keeps or discards, repeats. The human programs the research strategy, the agent programs the code.

**Applied to security agents:** The "code" being modified is the YAML agent definition (heuristics, prompts, examples, confidence thresholds). The "experiment" is running the modified agent against labeled benchmark code. The "metric" is accuracy (TPR - FPR).

**Critical design constraint — human review gate:** The autoresearch loop proposes changes but does NOT auto-commit to production YAML files. All changes are batched into a research report with metric diffs for human approval. Rationale: unsupervised self-modification of security detection logic could silently introduce false negatives.

**Benchmark selection:**
- Primary: `flawgarden/reality-check` (real CVEs, multi-language, SARIF ground-truth)
- Methodology: SMU research paper for building CVE-based benchmarks in new languages
- Explicitly NOT the OWASP Benchmark (Java-only, synthetic, dead-code scoring issues)
- **Language gap identified:** No established benchmarks for Rust, TypeScript, Kotlin. Strategy: build CVE-based fixtures from language-specific advisory databases (RustSec for Rust), use multi-LLM challenger as supplementary quality signal.

**Three input signals (not just benchmarks):**
1. Benchmark scores (primary, objective)
2. False positive exclusion data from user triage (§11.2)
3. Multi-LLM challenger disagreements (§11.4)

**Execution modes:** On-demand (initial development), scheduled (ongoing maintenance), research-triggered (new CVE ingestion). Decision: implement both on-demand and scheduled.

---

## ADR-007: Persistent Learning from False Positives

**Decision:** When users mark findings as false positives during triage, the system captures the reason and stores it in a project-level exclusions database (`.screw/learning/exclusions.yaml`). Future scans consult this database before reporting.

**Reasoning:** Traditional SAST tools produce the same false positives on every scan. Users experience "alert fatigue" and stop trusting the tool. Persistent learning means the system gets smarter per-project over time — the more you use it, the fewer irrelevant findings.

**Five scope levels for exclusions:** exact_line, pattern, function, file, directory. Each captures a different granularity of "this is safe."

**Feedback loop:** Exclusion patterns also serve as a signal for autoresearch (ADR-006). If `db.text_search(*)` is suppressed across 5 projects, the autoresearch loop should try reducing confidence for that pattern in the YAML definition.

**Integration with screw.nvim:** Notes with `state: not_vulnerable` in screw.nvim already represent confirmed false positives. The learning system reads these and auto-builds exclusion patterns. In collaboration mode (HTTP/PostgreSQL), exclusions are shared across the team.

---

## ADR-008: Multi-LLM Adversarial Challenger

**Decision:** Findings can be sent to a second LLM (initially OpenAI Codex) for adversarial peer review. Provider-agnostic interface so adding future LLMs is a config entry + thin adapter.

**Three challenge flows (all user-selectable):**
1. Claude primary → Codex challenger (default)
2. Codex primary → Claude challenger (reverse)
3. Both run independently → cross-validate (most thorough, most expensive)

**Why provider-agnostic:** Today it's Codex. Tomorrow it could be Gemini. The architecture defines a challenger interface (structured input → structured assessment), not a Codex integration. Adding a provider requires only a config entry and an adapter implementing the interface.

**Implementation shortcut:** `openai/codex-plugin-cc` is an official Claude Code plugin that already handles Codex invocation, background job management, and result retrieval. The `/codex:adversarial-review` command validates our challenger concept. During implementation, cross-reference this plugin as both validation and potential transport layer.

**Cost controls:**
- Never active by default. User explicitly opts in per analysis.
- Cost disclaimer displayed before first use, requiring acknowledgment.
- Configurable trigger: all findings, severity-gated, or on-demand.
- Config flag `cost_acknowledged: true` required.

**Challenger disagreements feed into autoresearch (ADR-006):** When Claude and Codex consistently disagree on a benchmark case, that case becomes a priority target for YAML heuristic refinement. This creates a three-way feedback loop: benchmarks + challenger disagreements + FP triage → agent improvement.

---

## ADR-009: Adaptive Analysis Scripts

**Decision:** When standard YAML agents encounter unfamiliar code patterns (custom ORMs, proprietary frameworks), the system can write targeted analysis scripts, execute them in a sandbox, and persist them for reuse.

**Reasoning:** Curated YAML handles the 90% case (known vulnerability patterns). But every codebase has idiosyncratic patterns that no pre-built agent can anticipate. Rather than failing silently, the system enters adaptive mode.

**This is the one place where the "code-execution agent" argument (see ADR-001) is valid** — but it's complementary to the curated knowledge, not a replacement. The YAML agents are the primary path; adaptive scripts fire only when standard agents identify a gap.

**Key constraints:**
- Sandboxed execution (read-only filesystem access)
- Human review gate (`validated: false` by default)
- CI/CD only runs validated scripts — never generates new ones in automated pipelines
- Project-scoped (`.screw/custom-scripts/`), not shared across projects

---

## ADR-010: Single Repository Strategy

**Decision:** One repository (`screw-agents`) holds the MCP server, Claude Code plugin, agent YAML definitions, and benchmarks. screw.nvim integration code stays in the screw.nvim repo.

**Reasoning:**
- Adding a new agent is a cross-cutting change (YAML definition + subagent `.md` + test fixtures) — single repo = single PR.
- Two distribution mechanisms from one repo: PyPI package (MCP server) + Claude Code plugin (agents/skills/commands).
- `domains/` directory at the top level (not buried in `src/`) because it's the community contribution target.

**screw.nvim boundary:** screw.nvim adds screw-agents as an optional dependency (same pattern as Telescope). The MCP protocol is the bridge. Transport (stdio vs HTTP) to be determined in Phase 3.

---

## ADR-011: `uv` as Preferred Package Manager

**Decision:** `uv` is the recommended installation method. `pipx` as fallback. `pip` as last resort.

**Reasoning:** Marco develops on Arch Linux where `pip install` into system Python is restricted by the distribution. `uv` handles virtual environment isolation automatically and is the modern Python standard. The project uses `uv` for its own dependency management (`pyproject.toml` + `uv.lock`).

---

## ADR-012: OWASP Code Review Guide v2 as Knowledge Source

**Decision:** Include the OWASP Code Review Guide v2 (2017) in Tier 2 knowledge sources despite its age.

**Reasoning:** Unlike the OWASP Testing Guide (which covers external probing of running applications), the Code Review Guide teaches how to *read source code* and identify vulnerabilities — tracing data flow, identifying trust boundaries, assessing authorization logic by reading controllers. This is precisely what our agents do. The methodology chapters are timeless even though the specific framework examples (Java/C# circa 2017) are dated. The systematic approach to code-level review translates directly into agent instructions regardless of language or framework vintage.

---

## ADR-013: CWE-1400-Native Benchmark Evaluator (Reject Direct Bentoo Adoption)

**Decision:** Build our own Python benchmark evaluator that is CWE-1400 native end-to-end. Adopt `flawgarden/bentoo`'s SARIF ground-truth format verbatim as input, but score and report in CWE-1400 — not in bentoo's CWE-1000 Research View. Keep bentoo as an optional external cross-check, not as the primary evaluator.

**Context:** Phase 0.5 (Benchmark Infrastructure Sprint) requires a runner that measures TPR/FPR/precision/recall/F1 for each screw-agent against real-CVE benchmarks from the flawgarden ecosystem (reality-check, vulnomicon, go-sec-code-mutated, skf-labs-mutated), the OpenSSF JS/TS benchmark (ossf-cve-benchmark, 218 real CVEs — the single biggest data source for our Phase 1 XSS and CmdI agents), and multi-language CVE extraction via MoreFixes.

`flawgarden/bentoo` is the natural candidate: it is the evaluator that drives flawgarden's own benchmark suite, it consumes `truth.sarif` ground-truth files in a clean SARIF 2.1.0 format, and it produces the exact metrics we need.

**Alternatives considered:**

1. **Adopt bentoo directly** — Use the Rust CLI as our evaluator. Consume its `summary.json` output and report it to users unchanged.
   - Rejected because: bentoo's "broad CWE" scoring dimension maps findings through **CWE-1000 (Research View)**, not CWE-1400. A CWE-89 finding's CWE-1000 parent path is `CWE-707 → CWE-943 (Data Query Logic)`, but its CWE-1400 parent is `CWE-1406 (Injection category)`. These are structurally different hierarchies, not cosmetic renamings. Adopting bentoo directly would force a bidirectional CWE-1000 ↔ CWE-1400 translation layer at every surface where bentoo output meets the rest of the system: evaluator input, `summary.json` parsing, autoresearch experiment logging (ADR-006), challenger disagreement analysis (PRD §11.3), and finding output to screw.nvim.
   - This **breaks the "universal join key" contract** established in ADR-002: "Every finding carries a CWE ID as universal join key." Two taxonomies in one system is the highest-probability route to subtle bugs in the autoresearch loop, where benchmark metrics silently disagree with what the agents were optimized for.
   - Additional concerns: bentoo shipped a breaking `rule_id_match` change in July 2025; external Rust toolchain dependency conflicts with our `uv`-managed Python stack (ADR-011); our YAML-driven MCP server deliberately avoids non-Python runtime deps.

2. **Adopt bentoo's format but hand-roll a CWE-1000 → CWE-1400 translator at the boundary** — Run bentoo, then translate its per-CWE summaries into CWE-1400 after the fact.
   - Rejected because: this is strictly worse than option 1 — it keeps the external dependency AND adds a fragile translation layer. The translator has to walk two CWE hierarchies and handle asymmetric mappings (one CWE-1000 parent may correspond to multiple CWE-1400 categories and vice versa). Each bentoo upgrade risks silent translation drift.

3. **Build our own Python evaluator, CWE-1400 native end-to-end** — Read bentoo-sarif ground-truth files (the input format is identical), walk the CWE-1400 hierarchy for parent/child traversal, compute the same metrics (TPR, FPR, precision, recall, F1, accuracy = TPR − FPR), emit `summary.json` in a bentoo-compatible schema so users can optionally run bentoo on the same ground truth as a cross-check.
   - **Accepted.** ~600-1,000 lines of Python, pure stdlib plus our existing PyYAML and SARIF parser dependencies. Full control over scoring semantics. No taxonomy dissonance. Autoresearch (ADR-006), challenger (ADR-008), and FP learning (ADR-007) all see the same CWE-1400 hierarchy that the agents themselves reason about.

**What we keep from flawgarden:**
- **bentoo-sarif ground-truth format** — verbatim, as input. This is plain SARIF 2.1.0 with `kind: "fail"|"pass"`, `ruleId: "CWE-<id>"`, and method-level `logicalLocations`. Adopting it costs us nothing and lets us reuse reality-check's 338 existing ground-truth files directly.
- **reality-check's Python CVE ingestion pipeline** — clone `reality-check/scripts/` into our `benchmarks/cve-ingest/`. This is the `bootstrap.sh → collect_cve_benchmark.py → build_and_clean_benchmark.py → markup_benchmark.py` pipeline that turns a CVE CSV into a materialized benchmark with ground-truth SARIF. Apache-2.0, direct reuse.
- **bentoo as optional external cross-check** — our evaluator emits a bentoo-compatible `summary.json` so users can run `bentoo` against the same ground-truth benchmarks and compare results. If our numbers diverge from bentoo's, we investigate — but our CWE-1400 numbers are authoritative.

**Tradeoff accepted:** We write and maintain ~600-1,000 lines of Python evaluator code instead of taking bentoo's battle-tested Rust CLI for free. This cost is real but bounded; the alternative (taxonomy dissonance everywhere) would be a continuous tax on every autoresearch iteration, every challenger comparison, every finding report, for the life of the project.

**Related decisions:** ADR-002 (CWE-1400 as taxonomic backbone), ADR-006 (autoresearch pattern), ADR-008 (multi-LLM challenger), ADR-011 (uv as package manager).

---

## ADR-014: Rust Benchmark Corpus Deferred to Phase 5 (Hard Gate)

**Decision:** Phase 0.5 (Benchmark Infrastructure Sprint) does NOT construct a Rust benchmark corpus from RustSec. The Rust corpus is deferred to Phase 5 (Autoresearch & Self-Improvement), where it becomes the first mandatory sub-step. Phase 5 cannot close without it.

**Context:** Our Phase 1 agents (SQLi, CmdI, SSTI, XSS) target injection-class vulnerabilities. Rust is a memory-safe language: its CVE history is dominated by memory corruption (145 advisories), denial of service (84), crypto failures (66), and memory exposure (52). Direct grep of the 1,010-advisory RustSec database (cloned 2026-04-09) plus GHSA-authoritative CWE cross-reference yields the following counts for our four Phase 1 CWEs:

| CWE | Name | Verified Rust advisories |
|---|---|---|
| CWE-79 | XSS | **16** (ammonia ×3, comrak ×2, salvo ×2, mdbook, pagefind, cargo, vaultwarden ×2, microbin, static-web-server, rustfs, deno_doc) |
| CWE-77/78 | Command Injection | **5-8** (lettre, gix-transport, starship, grep-cli/ripgrep, aliyundrive-webdav, plus Deno runtime) |
| CWE-89 | SQL Injection | **3** (matrix-sdk-sqlite, diesel, sqlx*) |
| CWE-1336 | SSTI | **0 verified** (zebrad is a MITRE mislabel) |

\* sqlx GHSA CWE field is empty; classification derived from shared root cause with diesel.

**Total real-CVE seed: ~24 advisories across all 4 CWEs, one CWE with zero coverage.** This is not a statistically meaningful sample for benchmark-driven evaluation in the style of flawgarden/reality-check (165 Java CVEs, 16.5 person-months to construct), nor does it satisfy the PrimeVul methodology requirement for chronological and cross-project splits. Furthermore, the five Rust web frameworks we have deepest agent coverage for — axum, rocket, warp, poem, loco-rs — have **zero** matching advisories as of 2026-04-09.

**Alternatives considered:**

1. **Construct Rust benchmark in Phase 0.5 anyway** — Manually curate the ~24 candidates plus authored fixtures modeled on real Rust web framework patterns (Tera/MiniJinja/Askama/Handlebars-rust for SSTI), promote them to "primary Rust validation."
   - Rejected because: the sample is too small to support the ≥70% TPR / ≤25% FPR validation gates proposed for Phase 1. Any number we report would be derived from fewer than 30 cases, some of which are already cited in agent YAMLs (hold-out conflicts). Calling such a number "Rust detection accuracy" would overstate confidence.

2. **Defer Rust validation entirely, keep self-authored fixtures as smoke tests only** — The existing 14 vulnerable + 11 safe Rust fixtures in `benchmarks/fixtures/xss/`, `sqli/`, `cmdi/`, `ssti/` continue to validate MCP plumbing (agent can load a Rust file, run tree-sitter extraction, produce a finding) but do not claim detection accuracy. All Phase 1 benchmark reports explicitly say "Rust detection quality not benchmarked — see ADR-014."
   - **Accepted.**

**Why Phase 5 resolves this:** Phase 5 targets broader agent coverage beyond injection (memory safety, thread safety, crypto issues, access control, file handling). These align directly with the dominant Rust CVE categories: 256+ memory-class advisories, 84 DoS advisories, 66 crypto-failure advisories, 10 thread-safety advisories are all within scope of Phase 2-5 agents. By the time we reach Phase 5, the Rust corpus will be statistically meaningful across multiple CWEs, and the autoresearch loop has something to optimize against.

**Triple-redundant tracking (this deferral must not be forgotten):**

1. `docs/PROJECT_STATUS.md` carries a prominent "Deferred Obligations" section listing the Rust corpus with its owning phase and acceptance criteria.
2. This ADR (ADR-014) is cross-referenced from `docs/DECISIONS.md` ADR-006 (autoresearch) and ADR-011 (uv package manager, which notes the Rust gap).
3. `docs/PRD.md` §12 Phase 5 lists "5.0 — Rust benchmark corpus construction from RustSec (blocked-in from Phase 0.5 per ADR-014)" as the first sub-step, with the gating language "Phase 5 cannot close without this sub-step complete."

Any of these three tripwires surfaces the obligation during Phase 5 kickoff. All three would have to be missed for the deferral to slip silently.

**Phase 5 starting corpus (reference, from `docs/research/benchmark-tier4-rust-modern.md`):**
1. **salvo** — GHSA-rjf8-2wcw-f6mp (reflected XSS) + GHSA-54m3-5fxr-2f3j (stored XSS), file:line at `serve-static/dir.rs:593/:581`, commit `16efeba312a274`
2. **diesel** — RUSTSEC-2024-0365, CWE-89, `diesel/src/pg/connection/stmt/mod.rs#L36`, commit `ae82c4a5a133`. **Conflict flag:** already cited in `domains/injection-input-handling/sqli.yaml`; must be held out from training data if used for validation.
3. **ammonia** — RUSTSEC-2021-0074, 2022-0003, 2025-0071 — three CVEs in one HTML-sanitizer library across 4 years, giving temporal regression coverage for mXSS.
4. **lettre** — RUSTSEC-2020-0069, CWE-77, function-level `SendmailTransport::send`, commit `bbe7cc5381c5380b54fb8bbb4f77a3725917ff0b`.
5. **matrix-sdk-sqlite** — RUSTSEC-2025-0043, CWE-89, canonical `format!("... WHERE id = '{}'", ...)` pattern in `SqliteEventCacheStore::find_event_with_relations`.

**Critical methodology note for Phase 5:** RustSec's `categories = ["format-injection"]` label is unreliable — it conflates CWE-89, CWE-79, CWE-444, CWE-150, CWE-601, CWE-116. Always cross-reference via `gh api /advisories/GHSA-xxxx` for authoritative CWE classification. Benchmark ingestion must also filter out the ~14 data-race crates (kekbit, bunch, dces, lexer, syncpool, etc.) that MITRE mislabeled as CWE-77.

**Tradeoff accepted:** Phase 1 ships without quantitative Rust detection claims. The agent YAMLs still carry deep Rust knowledge (load-bearing for users running scans on Rust code), but the evaluation gate does not include a "Rust TPR %" number. Users are informed explicitly.

**Related decisions:** ADR-002 (CWE-1400), ADR-006 (autoresearch), ADR-013 (CWE-1400-native evaluator). Related PRD sections: §12 Phase 5, §11.3 autoresearch.

## ADR-015: Server-Side Results Writing (`write_scan_results`)

**Decision:** Move scan result persistence (exclusion matching, formatting, directory creation, file writing) from Claude Code subagent multi-step workflows to a single server-side MCP tool call.

**Context:** Phase 2 E2E testing (2026-04-11) revealed that Claude Code subagents reliably execute 1-2 MCP tool calls per dispatch, but not 5+. The original design (PRD §7, design spec §3) expected subagents to orchestrate a 6-step workflow: scan → analyze → check exclusions → format_output → create .screw/ directories → Write files. In practice, subagents consistently completed steps 1-3 (scan + analyze) and then presented results conversationally without executing steps 4-6. This was observed across all test cases regardless of token budget (TC-2: 43k tokens, TC-3: 72k tokens, TC-4: 150k tokens).

**Root cause:** Claude Code subagents are optimized for analysis and conversation, not for executing long procedural tool-call sequences. The more tool calls a workflow requires, the less likely the subagent is to complete all of them. This is a platform behavioral constraint, not a code bug.

**Alternatives considered:**

1. **Stronger prompt language** — Add "YOU MUST" and bold emphasis to file-writing steps.
   - Rejected in isolation because: TC-3 had 42 tool uses but still didn't write files. The subagent has the capability but doesn't prioritize multi-step file operations over conversational response. Prompt emphasis alone is insufficient.

2. **Keep format_output + Write as separate steps, reduce to 2 calls** — Have format_output return content, then one Write call.
   - Rejected because: Still requires the subagent to execute 2 additional calls after analysis, and doesn't solve exclusion matching (D5 — subagent does its own scope interpretation).

3. **New `write_scan_results` MCP tool** — Single server-side call handles everything.
   - **Accepted.** Reduces the post-analysis workflow from 4+ tool calls to 1. Server-side exclusion matching ensures correct scope semantics. Directory creation and .gitignore are deterministic, not dependent on subagent behavior.

**What `write_scan_results` does:**
1. Parses findings via Pydantic (validates schema)
2. Loads exclusions from `.screw/learning/exclusions.yaml`
3. Runs `match_exclusions` server-side (correct scope: exact_line, pattern, file, directory, function)
4. Sets `excluded`/`exclusion_ref`/`status` on matched findings
5. Creates `.screw/` structure (findings/, learning/, .gitignore)
6. Formats as JSON + Markdown via `format_findings`
7. Writes `.screw/findings/{prefix}-{timestamp}.json` and `.md`
8. Returns summary dict (total, suppressed, active, by_severity, files_written, exclusions_applied)

**Impact on subagent prompts:** Workflow reduced from 6 steps to 4: scan → analyze → write_scan_results (MANDATORY) → present summary. Prompts shortened from ~180 lines to ~80 lines. Step 3 marked with bold emphasis as the single most important tool call.

**Impact on existing tools:** `format_output`, `record_exclusion`, `check_exclusions` remain available for ad-hoc use. `write_scan_results` is the primary workflow tool for scans.

**Defects resolved:** D2 (files not written), D3 (format_output skipped), D5 (exclusion scope semantics). Combined with D1 fix (skill description) and D4 fix (screw-full-review tool list), all 5 E2E defects are resolved.

**Test coverage:** 15 unit tests in `tests/test_results.py` covering directory creation, .gitignore, file writing, filename prefixes, summary counts, empty findings, metadata passthrough, and all exclusion scope types (file, exact_line, directory, wrong-agent). 2 additional server dispatch tests.

**Related decisions:** ADR-001 (MCP server as backbone — this reinforces it by moving more logic server-side), ADR-007 (persistent FP learning — scope matching is now server-authoritative).

## ADR-016: Subagent Nesting Limitation and Full-Review Architecture

**Decision:** Accept Claude Code's subagent nesting limitation (max ~2 levels) and plan for Phase 7 to dispatch domain orchestrators directly from the skill rather than nesting through screw-full-review.

**Context:** Phase 2 E2E testing (TC-4) revealed that Claude Code cannot reliably nest 3 levels of subagents: skill → screw-full-review → screw-injection. The screw-full-review subagent reported "can't nest subagents" and the skill adapted by dispatching screw-injection directly. This produced correct results because Phase 2 only has one domain (injection-input-handling).

**Current behavior:** The screw-review skill dispatches screw-full-review, which calls `list_domains` and attempts to dispatch domain orchestrators. When nesting fails, the skill falls back to dispatching the domain orchestrator directly.

**Phase 7 implication:** With 18 domains, screw-full-review would need to dispatch 18 orchestrators. The nesting limitation means this won't work as designed. The skill should instead:
1. Call `list_domains` directly
2. Dispatch each domain orchestrator in parallel via the Agent tool
3. Consolidate results from `.screw/findings/` after all orchestrators complete

**Action:** Redesign screw-full-review or remove it in Phase 7, replacing with direct orchestrator dispatch from the skill. The skill already has the routing logic. screw-full-review's only added value (consolidated executive report) can move to the skill itself.

**Related:** ADR-015 (write_scan_results makes file-based result collection reliable).
