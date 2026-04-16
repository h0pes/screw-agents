# Phase 2 E2E Test Results

## Summary

**Phase 2 E2E testing: 8/8 PASS.** All defects from the initial test run (2026-04-11) have been resolved via PR #5 (2026-04-12).

---

## Test Run History

### Run 1 — 2026-04-11 (pre-fix)

Initial E2E testing revealed 5 defects in Claude Code subagent behavior. Infrastructure (MCP server, tools, models, 120 unit tests) was working correctly, but the Claude Code integration layer was broken.

**Result:** 3 PASS, 3 PARTIAL, 1 MOSTLY PASS, 1 FAIL.

### Run 2 — 2026-04-12 (post-fix, PR #5)

All 5 defects resolved. Architectural fix: new `write_scan_results` MCP tool collapses formatting + exclusion matching + directory creation + file writing into a single server-side call. Subagent prompts rewritten from ~180 lines to ~80 lines with 4-step workflow.

**Result:** 8/8 PASS.

---

## Run 2 Test Results (2026-04-12)

### TC-1: Individual agent scan (natural language) — PASS

**Prompt:** "review benchmarks/fixtures/sqli/vulnerable/ for SQL injection"

| Check | Run 1 | Run 2 |
|---|---|---|
| screw-review skill activates | **FAIL** | **PASS** — `Skill(screw-review)` loaded |
| Delegates to screw-sqli subagent | **FAIL** | **PASS** |
| Calls `scan_sqli` MCP tool | **FAIL** | **PASS** |
| Calls `write_scan_results` | N/A | **PASS** — files written |
| `.screw/` directory created | **FAIL** | **PASS** — findings/, learning/, .gitignore |
| `.screw/findings/sqli-*.json` written | **FAIL** | **PASS** — 72KB, 36 findings |
| `.screw/findings/sqli-*.md` written | **FAIL** | **PASS** — 58KB report |
| Structured summary presented | **FAIL** | **PASS** — 36 findings, 32 high / 4 medium |

**Stats:** 2 tool uses (subagent), 57.5k tokens, 6m 34s.

### TC-2: Individual agent scan (slash command) — PASS

**Prompt:** `/screw:scan xss benchmarks/fixtures/xss/vulnerable/`

(Historical note: Run 1 and Run 2 were executed in dev-mode with the
`.claude/commands/scan.md` symlink in place, where the command registered
under the bare `/scan` basename. After the Phase 3a PR#2 plugin-namespace
restructure, the canonical invocation is `/screw:scan` — same underlying
command, namespaced through the plugin system.)

| Check | Run 1 | Run 2 |
|---|---|---|
| `/screw:scan` command discovered (recorded as `/scan` at test time) | **PASS** | **PASS** |
| Dispatches to screw-xss subagent | **PASS** | **PASS** |
| Calls `scan_xss` MCP tool | **PASS** | **PASS** |
| Calls `write_scan_results` | N/A | **PASS** |
| `.screw/findings/xss-*.json` written | **FAIL** | **PASS** — 85KB, 40 findings |
| `.screw/findings/xss-*.md` written | **FAIL** | **PASS** — 69KB report |

**Stats:** 23 tool uses, 64.5k tokens, 6m 48s. 40 findings across 14 fixtures, 0 false negatives, all high severity. Notable: all 3 Rust fixtures detected (Html(format!()), HttpResponse::body(format!()), Tera with autoescape=false).

### TC-3: Domain scan (natural language) — PASS

**Prompt:** "review benchmarks/fixtures/cmdi/vulnerable/ for injection vulnerabilities"

| Check | Run 1 | Run 2 |
|---|---|---|
| screw-review skill activates | **PASS** | **PASS** |
| Routes to screw-injection orchestrator | **PASS** | **PASS** |
| Calls `scan_domain` MCP tool | **PASS** | **PASS** |
| All 4 agents analyzed | **PASS** | **PASS** — cmdi: 33, sqli/ssti/xss: 0 |
| Calls `write_scan_results` | N/A | **PASS** |
| `.screw/findings/injection-*.json` written | **FAIL** | **PASS** — 59KB |
| `.screw/findings/injection-*.md` written | **FAIL** | **PASS** — 46KB |

**Stats:** 25 tool uses, 66.8k tokens, 8m 34s. 33 cmdi findings (29 CWE-78 shell injection + 4 CWE-88 argument injection). Zero false positives from sqli/ssti/xss on cmdi-only fixtures.

**Observation:** The orchestrator noted that `scan_domain` returned ~47k tokens exceeding tool-response limits, causing fallback to reading fixture files from disk. See "Known Limitations" below.

### TC-4: Full review — PASS

**Prompt:** "full security review of benchmarks/fixtures/ssti/"

| Check | Run 1 | Run 2 |
|---|---|---|
| screw-review skill activates | **PASS** | **PASS** |
| Routes to screw-full-review | **PASS** | **PASS** |
| Calls `list_domains` | **PASS** | **PASS** |
| Dispatches domain orchestrator | **FAIL** — read YAMLs directly | **PASS** — dispatched screw-injection |
| Uses MCP scan tools | **FAIL** | **PASS** — `scan_domain` called |
| Files written | **FAIL** | **PASS** — injection-*.json + .md |

**Stats:** screw-full-review: 2 tool uses, 7.3k tokens, 34s. screw-injection: 32 tool uses, 67.5k tokens, 6m 24s. Total: 7m 11s. 28 ssti findings across 10 vulnerable fixtures, 0 false positives from sqli/cmdi/xss. 10/10 vulnerable fixtures detected, 0/5 safe fixtures flagged (Jinja2 SandboxedEnvironment, FreeMarker classpath, Tera file render, Askama compile-time, etc.).

**Subagent nesting:** Claude Code cannot nest 3 levels of subagents (skill → screw-full-review → screw-injection). The skill worked around this by dispatching screw-injection directly after screw-full-review reported it couldn't nest. Result is identical since only one domain has agents. See "Known Limitations" below.

### TC-5: False positive recording — PASS

**Prompt:** "mark this as a false positive: SSTI in benchmarks/fixtures/ssti/vulnerable/python_jinja2_from_string.py line 15, reason: 'sandboxed in production', scope: file"

| Check | Run 1 | Run 2 |
|---|---|---|
| Calls `record_exclusion` | **PASS** | **PASS** |
| Correct exclusion data | **PASS** | **PASS** — agent: ssti, scope: file, CWE-1336 |
| `.screw/learning/exclusions.yaml` created | **PASS** | **PASS** — fp-2026-04-12-001 |
| Confirms with summary | **PASS** | **PASS** |

**Agent intelligence:** The subagent correctly noted that line 15 is the `def render_widget():` line, not the vulnerable call at line 20 — but confirmed the file-scope exclusion covers it regardless.

### TC-6: Exclusion applied on re-scan — PASS

**Prompt:** `/screw:scan ssti benchmarks/fixtures/ssti/vulnerable/python_jinja2_from_string.py` (recorded at test time as `/scan`; see TC-2 note)

| Check | Run 1 | Run 2 |
|---|---|---|
| Calls `scan_ssti` with `project_root` | **PASS** | **PASS** |
| File-scope suppresses ALL findings in file | **FAIL** — only line 18 | **PASS** — all 3 findings suppressed |
| Exclusion ref set correctly | Partial | **PASS** — all 3 reference fp-2026-04-12-001 |
| Files written | **FAIL** | **PASS** — ssti-*.json + .md |
| Summary shows suppressed count | N/A | **PASS** — 3 suppressed, 0 active |

**Stats:** 2 tool uses, 24.2k tokens, 1m 9s. Server-side `match_exclusions` with correct file-scope semantics (D5 fix validated). All 3 `Environment.from_string()` sinks (render_widget, email_preview, cms_page) correctly suppressed by single file-scope exclusion.

**Important note from subagent:** The fixture uses a non-sandboxed `Environment(loader=FileSystemLoader(...))`, so the "sandboxed in production" justification doesn't match the code. The exclusion will artificially zero out TP recall for this file in future benchmark runs. See "Known Limitations" item 4.

### TC-7: Unavailable agent fallback — PASS

**Prompt:** "check for SSRF vulnerabilities"

| Check | Run 1 | Run 2 |
|---|---|---|
| Does not crash | **PASS** | **PASS** |
| Lists available agents | **PASS** | **PASS** |
| No hallucinated agent | **PASS** | **PASS** |

Correctly identified SSRF as CWE-918, noted it belongs to request-forgery/resource-access CWE-1400 domain.

### TC-8: format_output tool — PASS

**Prompt:** "format this finding in all 3 formats (json, sarif, markdown): [SSTI finding]"

| Check | Run 1 | Run 2 |
|---|---|---|
| JSON valid | **PASS** | **PASS** — full Finding schema with triage.excluded |
| SARIF 2.1.0 valid | **PASS** | **PASS** — correct schema, rules, results, fingerprints |
| Markdown readable | **PASS** | **PASS** — severity table, detail sections, CWE links |

**Round-trip observations:**
- JSON: optional fields hydrated to null/""/[] — clean round-trip but `impact` and `exploitability` are empty strings instead of null (minor schema asymmetry in Finding model defaults)
- SARIF: `shortDescription` just echoes `cwe_name` (e.g. "SSTI") — should be a proper human-readable sentence once agent metadata is richer
- Markdown: section heading uses `cwe_name` ("SSTI") not full CWE long name — less grep-friendly. Consider "CWE-1336 — Server-Side Template Injection" format

---

## Defect Register

### D1: Skill auto-invocation inconsistent — RESOLVED (PR #5)

**Was:** "for SQL injection" didn't trigger skill; "for injection vulnerabilities" did.
**Fix:** Expanded skill `description` field with explicit trigger phrases: SQL injection, SQLi, XSS, CmdI, SSTI, secure code review, etc.
**Verified:** TC-1 Run 2 — "for SQL injection" now triggers skill correctly.

### D2: Subagents never write `.screw/` files — RESOLVED (PR #5)

**Was:** Subagents consistently skipped Step 5 (file writing) across all test cases. Format + directory creation + file writing required 3+ separate Write tool calls that subagents never executed.
**Root cause:** Claude Code subagents reliably execute 1-2 tool calls per task, not 5+. The 6-step workflow was architecturally incompatible with subagent behavior.
**Fix:** New `write_scan_results` MCP tool (`src/screw_agents/results.py`) collapses formatting, exclusion matching, directory creation, and file writing into a single server-side MCP call. Subagent workflow reduced from 6 steps to 4.
**Verified:** TC-1 through TC-4 Run 2 — all write `.screw/findings/` files successfully.

### D3: format_output sometimes skipped — RESOLVED (PR #5)

**Was:** TC-2 (2 tool uses) did not call format_output. TC-3 (42 tool uses) did.
**Fix:** `write_scan_results` calls `format_findings` internally — formatting is no longer a separate subagent action.
**Verified:** All test cases produce correctly formatted JSON + Markdown output.

### D4: screw-full-review bypasses MCP pipeline — RESOLVED (PR #5)

**Was:** screw-full-review read YAML definitions and fixture files directly instead of dispatching domain orchestrators. 40% file coverage vs 100%.
**Fix:** Removed Read/Glob from screw-full-review's tool list. Added explicit "NEVER read code files directly" rules. Only tools: `list_domains` + `Agent`.
**Verified:** TC-4 Run 2 — dispatched screw-injection which called `scan_domain`. 100% coverage.

### D5: Subagent ignores exclusion scope semantics — RESOLVED (PR #5)

**Was:** File-scoped exclusion only suppressed the exact line in `finding.line` instead of all findings in the file. Subagent did its own in-prompt matching.
**Fix:** `write_scan_results` runs `match_exclusions` server-side with correct scope semantics. Subagent no longer does exclusion matching — it produces raw findings and the server handles it.
**Verified:** TC-6 Run 2 — file-scope exclusion suppressed all 3 findings in the file (not just line 15).

---

## Known Limitations and Future Work

### 1. Subagent nesting depth (Phase 6)

Claude Code cannot nest 3+ levels of subagents (skill → screw-full-review → screw-injection). In TC-4, the skill worked around this by dispatching screw-injection directly after screw-full-review reported it couldn't nest further. This works for Phase 2 (single domain), but for Phase 6 (18 domains), the screw-review skill should dispatch domain orchestrators directly rather than going through screw-full-review.

**Action:** When implementing Phase 6, redesign the skill's routing to dispatch domain orchestrators directly for multi-domain scans.

### 2. scan_domain payload size (~47k-277k tokens)

The injection domain orchestrator noted that `scan_domain` responses exceed Claude Code's tool-response limits when scanning directories with many files. The subagent falls back to reading fixture files from disk via Claude Code's internal tool-result cache. Not a defect — the scan still works — but worth optimizing.

**Action:** Track for Phase 3 optimization. Consider pagination, response truncation, or splitting large payloads.

### 3. CSV output format

Marco requested CSV as a third output format alongside JSON and Markdown in `write_scan_results`.

**Action:** Deferred. Implement when needed (not blocking any phase).

### 4. Exclusions on benchmark fixtures suppress TP recall

Recording FP exclusions on files in `benchmarks/fixtures/` will zero out true-positive recall for those files in future benchmark evaluation runs. The autoresearch loop (Phase 4) and gate evaluations must handle this.

**Action:** The benchmark evaluator (`benchmarks/runner/evaluator.py`) must either: (a) ignore `.screw/learning/exclusions.yaml` during evaluation, or (b) scope exclusions so they don't apply to benchmark fixture paths. Address in Phase 4 step 4.0.

### 5. Format output quality improvements

- **JSON:** `impact` and `exploitability` default to empty strings instead of null — minor schema asymmetry in Finding model
- **SARIF:** `shortDescription` echoes `cwe_name` verbatim — should be a full human-readable sentence once agent metadata is richer
- **Markdown:** Section heading uses `cwe_name` (e.g. "SSTI") not full CWE long name — consider "CWE-1336 — Server-Side Template Injection" for grep-friendliness

**Action:** Address as polish items in Phase 3 or when agent metadata expansion requires formatter updates.

---

## Architectural Change Log

### write_scan_results MCP tool (PR #5, 2026-04-12)

**What changed:** New `write_scan_results` MCP tool added to the server. Replaces the subagent's multi-step workflow (format_output → create .screw/ → Write JSON → Write Markdown) with a single server-side call.

**Why:** Claude Code subagents reliably execute 1-2 tool calls, not 5+. The original 6-step workflow was architecturally incompatible with subagent behavior. After 3 test cases consistently failed to write files (D2), the design was changed to move persistence logic server-side.

**What it does:**
1. Parses findings via Pydantic
2. Loads exclusions from `.screw/learning/exclusions.yaml`
3. Runs `match_exclusions` server-side (correct scope semantics)
4. Sets `excluded`/`exclusion_ref`/`status` on matched findings
5. Creates `.screw/` directory structure (findings/, learning/, .gitignore)
6. Formats as JSON + Markdown via `format_findings`
7. Writes to `.screw/findings/{prefix}-{timestamp}.json` and `.md`
8. Returns summary (total, suppressed, active, by_severity, files_written)

**Files:** `src/screw_agents/results.py` (new), `src/screw_agents/server.py` (dispatch), `src/screw_agents/engine.py` (tool definition), `tests/test_results.py` (15 tests), `tests/test_phase2_server.py` (2 tests).

**Subagent prompt changes:** All 6 subagent .md files rewritten from ~180 lines to ~80 lines. 4-step workflow: scan → analyze → write_scan_results (MANDATORY) → present. Step 3 marked with bold emphasis.

**Impact on existing tools:** `format_output`, `record_exclusion`, `check_exclusions` remain available for ad-hoc use. `write_scan_results` is the primary workflow tool.
