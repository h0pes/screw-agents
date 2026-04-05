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
