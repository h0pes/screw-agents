# Deferred Items Backlog

> Cross-phase registry of items deferred from completed PRs. Each entry tags a target phase or trigger so future plan authors can pull these items in at the natural time. Append new entries as future PRs defer items beyond their immediate scope.

---

## ★ IMMEDIATE — Phase 3b-C2 (nested subagent dispatch fix) — discovered post-merge 2026-04-23

PR #6's manual round-trip validation surfaced a critical end-to-end regression that static review could not catch. C1's engine-layer closure holds; the LLM-flow integration is broken pending Phase 3b-C2.

### BACKLOG-C2-01 — Nested subagent dispatch unsupported: adaptive Layer 0d cannot fire from scan subagent
**Phase-4 readiness:** `blocker` — highest priority; **Phase 3b-C2 must land before any Phase 4 work begins**
**Source:** Phase 3b PR #6 post-merge manual round-trip (squash `fa2f42a`), 2026-04-23
**Discovery:** `claude --plugin-dir /home/marco/Programming/AI/screw-agents/plugins/screw` launched from `/tmp/screw-roundtrip-qb/`; ran `/screw:scan sqli src/ --adaptive` on seeded QueryBuilder fixture. The `screw:screw-sqli` subagent ran scan → accumulate_findings → record_context_required_match → detect_coverage_gaps → lint_adaptive_script correctly, then failed to invoke `Task(subagent_type="screw:screw-script-reviewer", ...)` at Step 3.5d/F. Runtime output: *"Layer 0d semantic review could not be invoked from the subagent's toolset — so nothing was staged, signed, or executed."* Graceful degradation path fired per prompt design (line 322 of `screw-sqli.md`), producing YAML-only output + "manual look" suggestions.

**Root cause (definitive, official docs):** Claude Code's architecture explicitly forbids nested subagent dispatch:
> *"Subagents cannot spawn other subagents. If your workflow requires nested delegation, use Skills or chain subagents from the main conversation."*
> — [code.claude.com/docs/en/sub-agents, line 711](https://code.claude.com/docs/en/sub-agents)

The Task tool is unavailable (or allowlist-restricted to empty) inside subagent context to prevent infinite nesting. Phase 3b T15-T17 prompt design assumed the scan subagent could dispatch the review subagent — architecturally incorrect vs Claude Code's design. The 24 Opus review cycles during PR #6 execution reviewed STATIC prompt content; T21 E2E test bypasses subagent dispatch by calling engine methods via Python. Nothing in review actually ran the full `main → subagent → nested-subagent` dispatch chain. The Phase 2 E2E notes memory flagged "subagent nesting limit" and this was not treated as a blocking discovery for PR #6's design — a process failure.

**What is NOT broken** (C2 can build on this foundation):
- C1 engine-layer closure — T21 exit gate still passes; `promote_staged_script(source-less, reads-from-staging, sha256-verified)` is correct.
- Full staging + signing + sandbox infrastructure.
- YAML scan path end-to-end (round-trip produced correct CWE-89 at dao.py:8 with full data-flow analysis).
- Coverage-gap detection (4 gaps correctly identified).
- All 942 unit + integration tests.
- The `screw:screw-script-reviewer` subagent itself (unchanged — only WHERE it gets dispatched from needs to change).

**What IS broken:** end-to-end `--adaptive` flow in live Claude Code sessions. `stage_adaptive_script` is never called from the LLM path. Feature silently degrades to YAML-only. Adaptive-mode is NOT production-ready.

**Fix — architecturally idiomatic pattern (Phase 3b-C2):** chain subagents from main session per [sub-agents#chain-subagents](https://code.claude.com/docs/en/sub-agents#chain-subagents) (the code-reviewer-then-optimizer pattern in the docs is the direct template). Rewrite the `/screw:scan` slash command prompt to become the orchestrator:

1. Main session dispatches scan subagent (`screw:screw-sqli` or orchestrator) with scope/target/--adaptive flag.
2. Scan subagent does scan + generation + lint, then **returns** `{ findings, pending_reviews: [{gap, script, rationale}] }` to main session. No more Layer 0d / stage / promote / execute calls inside the subagent.
3. Main session loops over `pending_reviews`:
   - Dispatches `screw:screw-script-reviewer` (fresh context — security property preserved) with script + rationale. Returns `SemanticReviewReport` JSON.
   - If review verdict passes filters: main session calls `stage_adaptive_script` MCP tool directly.
   - Main session shows 5-section review to user, waits for `approve <name>` / `reject <name>`.
   - On approve: main session calls `promote_staged_script` → `execute_adaptive_script` → `accumulate_findings` (script-produced findings merged).
   - On reject: main session calls `reject_staged_script`.
4. Main session calls `finalize_scan_results`.

**Context-isolation security property preserved:** each subagent invocation gets a fresh context window. Scan subagent doesn't see review subagent's output and vice versa. The only difference from the original design is WHO initiates the review dispatch — main session, not the scan subagent.

**Engine layer (Python code): ZERO changes.** MCP tools, staging, signing, T21 exit gate all stay untouched.

**Files to modify (5 markdown + 1 test):**
- `plugins/screw/commands/scan.md` — rewrite as orchestrator (MAIN WORK; ~150 LOC)
- `plugins/screw/agents/screw-{sqli,cmdi,ssti,xss}.md` — simplify Step 3.5: truncate at "return script + metadata" (byte-identical across 4 files modulo agent name; ~30 LOC delta each)
- `plugins/screw/agents/screw-injection.md` — simplify Step 2.5 orchestrator similarly
- `tests/test_adaptive_subagent_prompts.py` — assertion updates: scan subagents no longer reference stage/promote/reject/execute; new assertions for slash command prompt's orchestration flow

**Subagent tool lists change:** scan subagents lose `mcp__screw-agents__stage_adaptive_script`, `promote_staged_script`, `reject_staged_script`, `execute_adaptive_script` (those move to main-session invocation). They keep lint, record_context_required_match, detect_coverage_gaps, accumulate_findings, finalize_scan_results.

**Estimated scope:** ~300-400 LOC markdown + ~50 LOC test assertion updates. **Target: 1 focused session** (brainstorm + spec + plan + implement + review + round-trip re-validation in ≤4 hours active work, not 2-3 days).

**Trigger:** IMMEDIATELY as the next PR after PR #6 close-out (T26 Steps 11-12 + T27 memory). Blocks `--adaptive` production use. Blocks Phase 4 (autoresearch requires end-to-end adaptive-mode working).

**Round-trip evidence captured 2026-04-23:** fixture `/tmp/screw-roundtrip-qb/src/dao.py`; observed 1 CWE-89 critical finding at line 8, 4 coverage gaps identified, "Adaptive mode — halted before staging" graceful-degradation message; no files written to `.screw/staging/` or `.screw/custom-scripts/` — confirming C1 closure property (the regeneration vector doesn't fire because nothing reaches the signing layer).

---

## Phase 3b-C2 T1-review minors + coverage gaps (discovered 2026-04-23)

Non-blocking minors and spec-coverage gaps surfaced during T1 (pre-update assertions) spec + quality review rounds. All are safe to defer past C2 merge; each has a natural resolution point.

### BACKLOG-C2-M-SR-T1-M2 — Schema-key subset (5 of §5.1's 10 / §6.1's 7)
**Phase-4 readiness:** `non-blocker` — test-quality polish; no correctness impact on C2 ship path
**Source:** Phase 3b-C2 T1 spec review, 2026-04-23 (SR-T1-M2)
**File:** `tests/test_adaptive_subagent_prompts.py::test_scan_md_contains_subagent_return_schema_keys`

**Why deferred:** The test asserts 5 of spec §5.1's 10 top-level keys (`pending_reviews`, `session_id`, `trust_status`, `scan_subagent`, `scan_metadata`). This is defensible per plan step 8 intent — the 5-key set matches the "consumed-by-main" subset from §6.1's pseudocode — but the defensive-parse guard in §6.1 validates 7 keys (adding `schema_version`, `yaml_findings_accumulated`, `adaptive_mode_engaged`). The current 5-key assertion leaves 2 validated keys unasserted, weakening the coupling between §6.1's guard and the prompt surface. T2 author may choose whether expanding to the 7-key set buys better drift protection.

**Remediation sketch:** In T2 (scan.md rewrite) or immediately after, decide between (a) keeping the 5-key minimal set as "what main parses" (documenting the rationale in the docstring), or (b) expanding to §6.1's 7 validated keys. If (b), also close BACKLOG-C2-M-QR-T1-M5 in the same edit.

**Estimated scope:** ~5 LOC test + docstring clarification.

### BACKLOG-C2-M-QR-T1-M4 — Commit-message template vs immutable commit inconsistency
**Phase-4 readiness:** `non-blocker` — process lesson; no code fix needed
**Source:** Phase 3b-C2 T1 quality review, 2026-04-23 (QR-T1-M4)
**File:** `docs/PHASE_3B_C2_PLAN.md` Step 11 (historical pattern only)

**Why deferred:** When a plan is amended mid-task (as commit `ab884c4` adjusted T1 counts after `176f7ac` shipped), embedded commit-message templates in the plan should also update so a future implementer following the plan literally doesn't re-introduce stale language into a NEW commit. In this case, the historical commit `176f7ac` cannot be rewritten (already pushed, immutable), and the plan was updated in the T1 fix-up to match reality. No further action needed — this entry is a process record, not an actionable fix.

**Remediation sketch:** None. Documented here to preserve the lesson: whenever amending a plan that contains literal commit-message templates, sync both (plan text AND template block) in the same edit.

### BACKLOG-C2-M-QR-T1-M5 — Schema-key docstring substring-match caveat
**Phase-4 readiness:** `non-blocker` — docstring polish; folds into BACKLOG-C2-M-SR-T1-M2 if that is resolved
**Source:** Phase 3b-C2 T1 quality review, 2026-04-23 (QR-T1-M5)
**File:** `tests/test_adaptive_subagent_prompts.py::test_scan_md_contains_subagent_return_schema_keys`

**Why deferred:** The test uses plain substring matching (`key in body`). A key name could appear in an unrelated example snippet inside scan.md (e.g., an illustrative JSON fragment that isn't the real §5.1 schema). Docstring should note this weakness so future readers don't mistake the test for a strict schema validator. Low-value alone; best folded into the schema-key expansion in BACKLOG-C2-M-SR-T1-M2.

**Remediation sketch:** Add one sentence to the test docstring: "Substring-match; does not validate the keys appear in the authoritative §5.1 schema block rather than an example snippet — stronger matching would require parsing scan.md's fenced blocks. Considered acceptable at format-smoke scope." Ideally combined with the §6.1 7-key expansion.

### BACKLOG-C2-GAP-SPEC-5-3 — Spec §5.3 defensive-parse (schema_version mismatch) not asserted
**Phase-4 readiness:** `non-blocker` — coverage gap at the prompt-format-smoke layer; runtime path is T10 / engine-pytest territory
**Source:** Phase 3b-C2 T1 spec review, 2026-04-23 (GAP-SPEC-5-3)
**File:** `tests/test_adaptive_subagent_prompts.py` (candidate home) OR engine-level test in a future PR

**Why deferred:** Spec §5.3 requires the main session to reject / downgrade scan-subagent returns whose `schema_version` does not match the version main expects — a defensive parse to catch drift between engine schema versions and scan-subagent emit templates. Prompt-format-smoke tests lock structure only; they cannot verify the main session actually rejects an older-version payload at runtime. The T10 live round-trip is the natural acceptance check, supplemented by an engine-level pytest that injects a bad `schema_version`.

**Remediation sketch:** Either (a) add T10 E2E acceptance criterion "inject schema_version='0.0-fake' into a mocked subagent return; verify scan.md downgrades to YAML-only + logs a warning"; or (b) add an engine-level integration test once a dedicated entrypoint exists for the main-session parse loop (post-C2 refactor may expose it).

### BACKLOG-C2-GAP-SPEC-6-1 — Spec §6.1 sequential approve/reject invariant not asserted
**Phase-4 readiness:** `non-blocker` — prompt-level smoke can't cover; T10 or future integration test territory
**Source:** Phase 3b-C2 T1 spec review, 2026-04-23 (GAP-SPEC-6-1)
**File:** `tests/test_adaptive_subagent_prompts.py` (not the right home) OR T10 E2E / future integration test

**Why deferred:** Spec §6.1 requires main-session review loop to process pending_reviews one-at-a-time (no batch `approve all`; each approval promotes → executes → accumulates before proceeding to the next). Prompt-format-smoke cannot assert runtime ordering; asserting the NEGATIVE ("no batch language") is too brittle (any informal list in prose trips it). Live round-trip is the right surface.

**Remediation sketch:** Add T10 E2E acceptance criterion "stage 2 scripts in one adaptive turn; verify main session prompts user for approval on #1 before staging #2 is accessible" (exact UX wording per implementer). Alternatively, once a mock-harness exists for main-session orchestration, pytest can assert the call order on stubbed MCP tools.

---

## Phase 3b-C2 T4 review minors (discovered 2026-04-24)

Non-blocking minors and one pre-audit process lesson surfaced during T4 (sqli.md adaptive-flow truncation) spec + quality review rounds. The 5 Important + 1 Minor content issues were resolved inline in the T4 fix-up commit; these 4 remaining minors + 1 process lesson are deferred.

### BACKLOG-C2-M-QR-T4-M2 — MCP tool name qualification inconsistency in screw-sqli.md
**Phase-4 readiness:** `non-blocker` — style/consistency polish; no correctness impact
**Source:** Phase 3b-C2 T4 quality review, 2026-04-24 (QR-T4-M2)
**File:** `plugins/screw/agents/screw-sqli.md` (post-T4 fix-up; mirrors to cmdi/ssti/xss after T5/T6/T7)

**Why deferred:** The `mcp__screw-agents__accumulate_findings` reference in Step 4 is fully-qualified because the adaptive-section test (`test_adaptive_section_per_agent_references_only_required_tools`) requires the qualified token to appear inside the extracted adaptive range. Other MCP tool references in prose (`record_context_required_match`, `detect_coverage_gaps`, `lint_adaptive_script`) appear unqualified in surrounding text for readability. Defensible as-is (single site is mechanically required; others don't affect the test), but inconsistent; a polish PR could unify qualification style (either qualify all prose references, or confine the qualified form to the code fence and keep prose unqualified).

**Remediation sketch:** Pick a style rule ("all prose references unqualified; code-fence references fully-qualified" is the less-churn option) and apply consistently across sqli/cmdi/ssti/xss subagent markdown in one pass.

**Estimated scope:** ~12 LOC across 4 files.

### BACKLOG-C2-M-QR-T4-M3 — Trailing newline missing at end of screw-sqli.md
**Phase-4 readiness:** `non-blocker` — POSIX-text hygiene; purely cosmetic
**Source:** Phase 3b-C2 T4 quality review, 2026-04-24 (QR-T4-M3)
**File:** `plugins/screw/agents/screw-sqli.md`

**Why deferred:** The file ends on a content line with no trailing LF (`wc -l` reports 414 instead of 415 post-fix-up). POSIX text-file convention is to terminate with a newline; most editors add one automatically on save. Cosmetic only; `pytest`, git, and the plugin loader don't care. Fix alongside any future sqli.md touch that already opens the file.

**Remediation sketch:** Add a single trailing LF; no test expectation changes. Ideally combined with T5/T6/T7 clone operations (the clone source can be re-terminated then cloned) or any subsequent sqli.md content edit.

**Estimated scope:** 1 byte per file × 4 files.

### BACKLOG-C2-M-QR-T4-M4 — Commit b8f6c74 did not name 2 judgment-call deviations
**Phase-4 readiness:** `non-blocker` — process lesson; no code remediation
**Source:** Phase 3b-C2 T4 quality review, 2026-04-24 (QR-T4-M4)
**File:** Historical — commit `b8f6c74` (truncate screw-sqli.md adaptive flow)

**Why deferred:** Per `feedback_plan_sync_on_deviation` spirit (plan and code coherent at merge time; deviations named in commit messages), the T4 truncation commit made 2 defensible judgment calls not surfaced in the commit message: (a) removed a stale `screw:screw-script-reviewer` bullet from preserved Step 3.5d-D that described impossible post-C2 state; (b) qualified `accumulate_findings` to `mcp__screw-agents__accumulate_findings` in Step 3.5a to preserve the adaptive-section test invariant. Both are correct decisions; not calling them out weakens the audit trail. Historical commit cannot be rewritten (pushed, immutable). Process record for future truncation commits.

**Remediation sketch:** None. Documented to preserve the lesson: when executing a truncation task, any edit outside the explicitly-enumerated truncation range (preserved-range fixes, test-coupled qualifications) MUST be named in the commit message alongside the in-scope changes.

### BACKLOG-C2-M-QR-T4-C1 — Line 91 "approval surface" framing borderline confusing
**Phase-4 readiness:** `non-blocker` — clarity polish; post-C2 readability sweep
**Source:** Phase 3b-C2 T4 quality review, 2026-04-24 (QR-T4-C1)
**File:** `plugins/screw/agents/screw-sqli.md` line ~91 (and mirrored files post-T5/T6/T7)

**Why deferred:** The `--adaptive` interactive-consent paragraph describes the approval surface from the system-wide perspective ("the human can type `approve <name>` or `reject <name>` in response to the 5-section review"). Accurate for the overall adaptive flow, but borderline confusing when read by a freshly-respawned scan subagent — because THIS subagent never sees the review surface (main session composes it). A clarity pass could qualify as *"…review that the main session will present"* or restructure the paragraph to separate "user-facing behavior" from "this subagent's role" more crisply.

**Remediation sketch:** One-sentence edit in a future clarity pass; apply to sqli/cmdi/ssti/xss uniformly.

**Estimated scope:** ~4 LOC across 4 files.

### BACKLOG-C2-PROC-PA-TRUNCATION-SCOPE — Pre-audit must simulate test extraction range, not truncation range
**Phase-4 readiness:** `non-blocker` — pre-audit process improvement; propagate to T5/T6/T7 pre-audit discipline
**Source:** Phase 3b-C2 T4 fix-up retrospective, 2026-04-24
**File:** Pre-audit skill / checklist (process doc; no code file to edit)

**Why deferred:** The T4 pre-audit scoped its grep-and-review effort to the truncation range (lines 298-600 of the pre-T4 file — the content being deleted-and-replaced). The `test_adaptive_section_per_agent_references_only_required_tools` test, however, extracts content from `### Step 3.5: Adaptive Mode` through the next `### Step` heading — the FULL adaptive section, including the preserved 3.5a-E steps. Four stale-reference issues (QR-T4-I1/I2/I3/I4 + SR-T4-M2) slipped past the pre-audit because the preserved range was assumed coherent when it was not (several references became stale once the new Step 4 structure landed).

**Remediation sketch:** Expand the standard pre-audit checklist for truncation tasks to include a `sed -n '<step-start>,<step-end>p'` test-extraction simulation covering the full range the target test walks, not just the truncated-then-appended region. Apply this discipline to T5/T6/T7 pre-audits (cmdi/ssti/xss clones) — even though the clones are byte-identical to sqli modulo agent name, the pre-audit should verify the clone source is clean (which it now is post-T4 fix-up) and that the cloned agent name doesn't interact badly with preserved-range prose. Also apply to any future Phase 3b+ truncation task.

**Estimated scope:** ~5 lines added to the pre-audit checklist; zero code change.

---

## Phase-4 Readiness Triage

Every active backlog entry below carries a `**Phase-4 readiness:**` tag with one of:

- `blocker` — must be addressed before Phase 4 can start. Affects the surfaces Phase 4 autoresearch exercises (scan_full scale, benchmark ingestion path, signing-path programmatic consumers, trust-layer, exclusions model).
- `nice-to-have` — would help Phase 4 ergonomics or performance, but not correctness-critical. Phase 4 can start with these unaddressed; they'd be nice polish before Phase 4 lands.
- `phase-7-scoped` — deferred until Phase 7 (multi-process MCP server) work. Single-process screw-agents is unaffected.
- `retire` — trigger has not fired and the risk/value has decayed; candidate for deletion if no trigger activates by a named future milestone.

Entries already in `## Shipped` / `## Shipped (PR #6)` do NOT carry this tag — they're done.

### Tag summary (as of T24 fix-up, 2026-04-23)

114 active entries tagged (Shipped / Shipped (PR #6) entries excluded).

| Tag | Count | Key entries |
|---|---|---|
| `blocker` | 5 | T-FULL-P1 (scan_full scale), T19-M1 / T19-M2 / T19-M3 (SARIF + CSV + exclusion semantics consumed by Phase 4 autoresearch output), BACKLOG-PR6-22 (sign_adaptive_script retirement / C1 full closure) |
| `nice-to-have` | 90 | Performance, ergonomics, determinism polish; majority of PR6-01..78 cosmetic entries; sandbox hardening (Phase 3c) |
| `phase-7-scoped` | 5 | T6-M1, T6-M4, T9-I1 (multi-process concurrency); T8-Sec2 (preexec thread-safety); BACKLOG-PR6-09 (registry compaction at scale) |
| `retire` | 14 | Trust-layer T4-M6 + T1-M1 (flagged for Marco review — triggers repeatedly not fired) + 12 PR6-* cosmetic/docstring entries whose files are unlikely to be revisited |

**Phase 4 gate:** the `blocker` count must drop to 0 before Phase 4's step 4.0 (D-01 Rust benchmark corpus) can start. Current blockers: T-FULL-P1, T19-M1/M2/M3, BACKLOG-PR6-22. T-FULL-P1 (paginate `scan_full` + agent-relevance filter — Phase 4 autoresearch uses it in volume at 41-agent expansion); T19-M1/M2/M3 (SARIF / CSV / exclusion-semantics of merged findings — Phase 4 FP-learning loop consumes these); BACKLOG-PR6-22 (direct-sign MCP tool retirement — must land before Phase 4's autoresearch module is designed against the direct-sign API, preventing future migration debt). See `docs/PROJECT_STATUS.md` §"Phase 4 Prerequisites (hard gates)" for scheduling + estimated scope.

---

## Trust-layer polish (was "Phase 3b Task 13", re-scoped 2026-04-19)

### T4-M6 — Split `src/screw_agents/trust.py` into a package
**Source:** Phase 3a PR#1 punchlist (commit `27d147d`)
**File:** `src/screw_agents/trust.py` (~552 lines after Task 7.1)
**Phase-4 readiness:** `retire` — trigger has not fired across Phase 3b; repeatedly surveyed at T13/T17/T18a/T20 and rejected — flagged for Marco review
**Why deferred:** ~~Phase 3b Task 13 (init-trust CLI) will naturally extend trust.py with key-generation utilities. Splitting now would mean churning the file twice.~~ REVISED 2026-04-19: Phase 3b T13 validate-script CLI was reviewed and found to only IMPORT existing trust.py functions, not extend them. The original split-avoidance rationale no longer applies; trigger revised accordingly.
**Trigger:** When trust.py gains new exported functions (e.g., Phase 3b T17 screw-script-reviewer or T18 subagent-prompt integration may need new helpers) OR during a dedicated polish commit. Phase 3b T13 validate-script CLI does NOT extend trust.py — it only imports `canonicalize_script`, `load_config`, `sign_content`, and the internal helpers — so T13 is no longer a valid trigger. REVISED 2026-04-19 (post-T18a): T18a (`sign_adaptive_script` + `lint_adaptive_script` MCP tools) does NOT extend trust.py either — it imports the same internal helpers and places the shared canonicalization wrapper at `src/screw_agents/adaptive/signing.py` (adaptive-specific signing lives with adaptive code). T18a is no longer a valid trigger.
**Suggested split:**
- `trust/__init__.py` — re-exports
- `trust/canonical.py` — `canonicalize_exclusion`, `canonicalize_script`, `_canonical_json_bytes`, exclude sets
- `trust/sign.py` — `sign_content`
- `trust/verify.py` — `verify_signature`, `VerificationResult`, `_fingerprint_public_key`, `verify_exclusion`, `verify_script`, helper trio
- `trust/keys.py` — `_public_key_to_openssh_line`, future key generation
- `trust/config.py` — `load_config`, `_CONFIG_STUB_TEMPLATE`
**Note (T6-M7 subsumed here):** The line-count trajectory observation T6-M7 from the Phase 3a PR#1 punchlist points back to this same split — addressing T4-M6 will resolve T6-M7 too.

### T1-M1 — `AdaptiveScriptMeta` runtime-flag fields (dual-layer defense pattern)
**Source:** Phase 3b PR #4 Task 1 quality review, 2026-04-18
**File:** `src/screw_agents/models.py` `AdaptiveScriptMeta`
**Phase-4 readiness:** `retire` — T20 surfaced the stale-script trigger but T20 shipped without needing runtime-flag fields; Exclusion dual-layer pattern now covers exclusion path fully — flagged for Marco review
**Why deferred:** ~~Task 11-14 (executor + validate-script CLI) will need per-script trust state ("trusted", "warned", "quarantined", "allowed") on `AdaptiveScriptMeta`, mirroring the `Exclusion.quarantined` + `Exclusion.trust_state` runtime fields added in Phase 3a. Adding the fields speculatively in Task 1 was rejected — the exact field name and value set should be decided by the implementer who has the executor context.~~ REVISED 2026-04-19: T11 (shipped in PR #4) and T13 (bundled in PR #5) were both reviewed and found to NOT need runtime-flag fields. T11's executor returns `AdaptiveScriptResult.stale` as a top-level runtime flag and does not annotate the meta model itself; T13's validate-script writes only persisted fields (`signed_by`, `signature`, `validated`, `sha256`). First likely trigger is T20 stale-script detection (runtime `stale` annotation) or T21 adaptive-cleanup (user-visible trust state).
**Trigger:** When the executor OR a CLI command needs to annotate `AdaptiveScriptMeta` at runtime (e.g., Phase 3b T20 stale-script detection may attach a `stale: True` runtime flag, or T21 adaptive-cleanup may want `quarantined`/`trust_state` annotations). Phase 3b T11 executor shipped without needing runtime state; T13 validate-script writes only persisted fields (`signed_by`, `signature`, `validated`, `sha256`). Neither is a trigger.
**Suggested approach:** Mirror the `Exclusion` dual-layer defense exactly — `Field(default=..., exclude=True)` at the schema level + `_RUNTIME_ONLY_FIELDS` ClassVar set + `model_dump` override to catch caller-side `include=` edge cases (see `Exclusion._RUNTIME_ONLY_FIELDS` at `src/screw_agents/models.py` line ~262 and the `model_dump` override at line ~264 for the template). Don't skip the override — Pydantic v2's `include`/`exclude` precedence can let `include` win over field-level `exclude`, so the runtime override is the load-bearing second layer.
**Estimated scope:** ~30 LOC in models.py + 2-3 new tests. Trivial.

---

## Phase 3c (sandbox hardening follow-ups)

### T8-Sec1 — Real seccomp filter for the Linux sandbox
**Source:** Phase 3b PR #4 Task 8 quality reviews (commits `7d07dc2`, `be9ccfc`), 2026-04-18
**File:** `src/screw_agents/adaptive/sandbox/linux.py`
**Priority:** **HIGH** (security depth) — currently the sandbox relies on bwrap's namespace + capability isolation for syscall-level defense; capability drop (`CapEff = 0`) blocks the most dangerous syscalls (ptrace, raw sockets, etc.) but is broader than necessary and offers less defense-in-depth than a real BPF-based seccomp filter.
**Phase-4 readiness:** `nice-to-have` — Phase 4 autoresearch doesn't target the sandbox adversarially; multi-layer bwrap defense covers current threat model

**Why deferred:** Implementing a proper seccomp filter requires either a libseccomp Python binding (`pyseccomp` or `seccomp-bpf`) or hand-rolling the BPF bytecode via `libc.prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, ...)`. Either path is significant work (~200-400 LOC, careful syscall allowlist tuning, per-Python-version compatibility testing). The Phase 3b sandbox already has structurally-correct multi-layer defense (17 properties locked by regression tests in `tests/test_adaptive_sandbox_linux_isolation.py`); seccomp is hardening, not gap closure.

**Trigger:** Any of:
- Before screw-agents reaches a deployment scale where a single sandbox compromise has high blast radius (e.g., shared CI runners, multi-tenant SaaS deployment)
- A real-world adversarial-script audit demands BPF-level syscall denylist
- Phase 3c is opened explicitly for sandbox hardening sweep
- A CVE in bwrap or the Linux user-ns implementation forces re-evaluation

**Suggested approach:**
1. Add `pyseccomp` to `pyproject.toml` (or `python-libseccomp` depending on what's maintained).
2. Build the syscall allowlist by running the existing isolation tests under `strace -ff` and recording every syscall the legitimate adaptive-script workflow needs (Python startup, stdlib imports, file reads, write to /findings, exit). Cross-reference with `tree-sitter`'s syscalls if scripts use it.
3. Apply the filter via `prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &filter)` in `_preexec()`, AFTER `prctl(PR_SET_NO_NEW_PRIVS, 1, ...)` (required for non-root seccomp).
4. Add explicit regression tests: `test_seccomp_blocks_unallowed_syscall` (e.g., script attempting `process_vm_readv` should fail with EPERM regardless of capabilities).
5. Document the allowlist in `linux.py` as the source of truth for "what the sandboxed Python actually needs at the kernel boundary".

**Estimated scope:** 250-400 LOC + 5-10 regression tests + dependency add. Medium PR.

### T8-Sec2 — preexec_fn thread-safety swap
**Source:** Phase 3b PR #4 Task 8 quality reviews (commits `7d07dc2`, `be9ccfc`), 2026-04-18
**File:** `src/screw_agents/adaptive/sandbox/linux.py` `_preexec()`
**Priority:** Low (currently single-threaded; conditional)
**Phase-4 readiness:** `phase-7-scoped` — preexec_fn thread-safety only matters when MCP server becomes multi-process

**Why deferred:** Python's `subprocess` `preexec_fn` runs in the FORKED child between `fork()` and `exec()`. If the parent process has multiple threads concurrently allocating memory, the fork can deadlock on the GIL or on `malloc`'s internal locks (POSIX-fork-after-thread anti-pattern). screw-agents is currently single-threaded — the orchestrator runs one sandbox at a time per request — so the deadlock risk is zero today. Becomes relevant if the executor is ever parallelized (Task 11 + future) or the MCP server moves to a multi-process / multi-threaded model (Phase 7 — see existing T6-M1, T6-M4, T9-I1 entries for related concurrency risks).

**Trigger:** Any of:
- Task 11's executor introduces threading (e.g., parallel script execution for batch scans)
- Phase 7 multi-process MCP server is implemented
- A `RuntimeWarning: preexec_fn not safe in multithreaded application` appears in logs

**Suggested approach:** Replace the `preexec_fn=_preexec` keyword with a fork-safe alternative. Two options:
1. **Python 3.11+ `process_group=0` API** — sets the process group atomically without preexec_fn; more limited (doesn't directly support setrlimit, but combined with `prctl` set up post-fork via setrlimit AFTER exec is workable). Cleanest for Python 3.11+ projects.
2. **`prlimit` shell wrapper** — invoke `prlimit --cpu=N --as=M --nproc=K --nofile=L --fsize=F bwrap ...` instead of bwrap directly. Trades a fork+exec for a small wrapper. Works on all Python versions.

Either path requires re-validating all 17 isolation properties (the rlimit values must still apply to the script process, not just to the wrapper).

**Estimated scope:** 50-100 LOC + re-validation of isolation tests. Small-to-medium PR.

### T8-Sec3 — Rename `_SCRIPT_PROCESS_BUDGET` / `_BWRAP_HEADROOM` to reflect thread-counting semantics
**Phase-4 readiness:** `nice-to-have` — naming-only polish; no correctness impact

**Source:** T8 latent-bug fix (commit `7cff916`, 2026-04-19)
**File:** `src/screw_agents/adaptive/sandbox/linux.py`
**Priority:** Low (naming consistency, not correctness)

**Why deferred:** Following the thread-counting bug fix (RLIMIT_NPROC accounts per-UID threads, not processes; `_compute_nproc_cap` was previously counting processes), the constants `_SCRIPT_PROCESS_BUDGET` and `_BWRAP_HEADROOM` semantically quantify thread-budget, not process-budget. Renaming is a cosmetic improvement with zero behavioral impact. Deferred because it's a symbol rename on module-private constants — trivial to do but noisy churn that doesn't carry its own commit weight.

**Trigger:** Any dedicated sandbox-cleanup polish commit, or alongside T8-Sec1 / T8-Sec2 (the other Phase 3c sandbox-hardening deferrals).

**Suggested fix:** Rename to `_SCRIPT_THREAD_BUDGET` and `_BWRAP_THREAD_HEADROOM`. Update docstrings + the inline comment block at lines 90-113 of `linux.py` + the in-function NOTE at the bottom of `_compute_nproc_cap`'s docstring. ~15 LOC diff.

### T9-Sec1 — Deduplicate host-side sandbox defenses into shared `_common.py`
**Source:** Phase 3b PR #4 Task 9 implementation, 2026-04-18
**File:** `src/screw_agents/adaptive/sandbox/_common.py` (new) + linux.py + macos.py
**Priority:** Low (code quality, not security gap)
**Phase-4 readiness:** `nice-to-have` — host-side dedup is code-quality polish, not Phase 4 surface

**Why deferred:** T9's macos.py duplicates 3 host-side helpers from linux.py
verbatim (`_safe_read_findings`, `_clean_findings_path`,
`_check_findings_aggregate_size`) plus the related constants
(`_MAX_FILE_SIZE_BYTES`, `_MAX_OUTPUT_BYTES`, `_MAX_FINDINGS_AGGREGATE_BYTES`,
`_MAX_OPEN_FILES`). These are pure Python, platform-agnostic — they
operate on the host filesystem and the orchestrator's tempfiles. Refactoring
during T9 was rejected as out-of-scope (would have required re-validating
T8's shipped tests). Cleaner architecture: extract into
`sandbox/_common.py`; linux.py and macos.py import from there.

**Trigger:** Polish pass before PR #5 starts, OR when a third sandbox
backend lands (BSD jails? Windows when supported?), OR when the helpers
need a fix that would have to be applied in two places.

**Suggested approach:**
1. Create `src/screw_agents/adaptive/sandbox/_common.py` with the 3
   helpers + 4 constants (the platform-specific NPROC cap stays in each
   backend).
2. Import them in both linux.py and macos.py: `from screw_agents.adaptive.sandbox._common import _safe_read_findings, _clean_findings_path, _check_findings_aggregate_size, _MAX_FILE_SIZE_BYTES, ...`
3. Delete the duplicated code from each backend.
4. Re-run all sandbox tests (Linux + macOS skip on each other) to verify
   no behavioral change.

**Estimated scope:** ~80 LOC moved; net negative LOC. Trivial PR.

---

## Phase 4+ (autoresearch / scale)

### T19-M1 — Surface `merged_from_sources` in SARIF and CSV output
**Source:** Phase 3b T19 (commit `bff35b5`, 2026-04-19)
**File:** `src/screw_agents/formatter.py` `_format_sarif` + `format_csv`
**Priority:** Low — Markdown + JSON are the primary structured paths and both surface the field.
**Phase-4 readiness:** `blocker` — Phase 4 autoresearch consumes SARIF / CSV output of merged findings in volume

**What's shipped:** Phase 3b T19 adds `merged_from_sources: list[str] | None` to `Finding`. When a finding is the result of an augmentative merge (multiple scan sources detected the same `(file, line_start, cwe)`), the list carries `"<agent> (<severity>)"` entries in input order. Markdown renders a `**Sources:**` line after Description; JSON carries the field via `model_dump()` automatically.

**What is NOT shipped:** SARIF and CSV formatters do not render the field.
- **SARIF** has no natural top-level slot for multi-source attribution. The current SARIF `result` object surfaces a single `tool.driver.rules[]` entry per finding; multi-source would need to go into the `properties` bag (SARIF 2.1 schema allows arbitrary property extensions) or a synthetic `relatedLocations` block.
- **CSV** iterates a fixed column list. Adding a new column would break backward compat for positional parsers (spreadsheet imports, legacy tooling) that expect the current header row.

**Why deferred:** Markdown + JSON cover the primary structured-consumer path:
- Human reviewers read Markdown.
- Phase 4 autoresearch consumes JSON.
- Future SARIF consumers (GitHub Code Scanning, SonarQube) can fall back to the primary's `agent` field; multi-source attribution is useful but not correctness-critical.
- CSV consumers have stable columns today; breaking them for a secondary format is the wrong trade.

**Trigger:** Any of:
- Phase 4 autoresearch uses SARIF output in volume and needs source attribution for ranking/filtering
- A CSV consumer complains about losing source attribution when findings are merged
- Phase 4+ reporting uplift touches both formatters anyway

**Suggested fix:**
1. **SARIF** — embed `merged_from_sources` in the finding's `properties` bag under key `merged_from_sources`. Consumers who understand the bag surface it; others see the primary's `agent` field. This is the SARIF-idiomatic path for tool-specific extensions.
2. **CSV** — append an optional `merged_sources` column AT THE END of the existing column list (appending preserves backward compat for positional parsers that read by index up to the old column count). Empty string for unmerged findings; `"; "`-joined list for merged findings (same separator as other CSV-list fields, comma would collide with CSV delimiter).

**Estimated scope:** ~30 LOC + 2 tests (one SARIF assertion, one CSV assertion). Trivial.

### T19-M2 — Per-source exclusion matching for merged findings
**Phase-4 readiness:** `blocker` — Phase 4 FP-learning correlates exclusions against merged findings — per-source matching is correctness-critical

**Source:** Phase 3b T19 quality review, 2026-04-19
**File:** `src/screw_agents/results.py` (exclusion-match call site around line 200)
+ `src/screw_agents/learning.py::match_exclusions`
**Priority:** Medium (pre-existing exclusion-model limitation, newly addressable post-T19)

**What's shipped (T19):** Augmentative merge by `(file, line_start, cwe)`.
Merged primary's `agent` field is the severity-winning source; other
sources listed in `merged_from_sources: list[str]`. `match_exclusions` at
`learning.py:363` still keys strict-equal on `agent`.

**What is NOT shipped:** when a merged finding's primary agent differs
from the exclusion's agent (e.g., user excluded `agent=sqli` but the
merge's primary is now `agent=adaptive_script:qb-check` because adaptive
outranked sqli on severity), the exclusion silently fails to match.
This is a PRE-EXISTING limitation (before T19, the same adaptive finding
would also not have matched the sqli exclusion because they were SEPARATE
findings with different agent labels), but T19 makes it newly ADDRESSABLE
because the structured `merged_from_sources` carries the information
needed to do per-source matching.

**Why deferred from T19:** T19 was scoped as "augmentative merge", not
"exclusion-semantics rework". Per-source exclusion matching is a change
in the exclusion-matching contract, not the merge contract, and deserves
its own review cycle with exclusion-model implications (e.g., what happens
when DIFFERENT sources have DIFFERENT matching exclusions? Does one
override the other? How does `exclusions_applied` in the render result
represent per-source suppression?).

**Trigger:** Any of:
- User reports "I excluded this SQLi finding and it came back" after
  enabling adaptive mode
- Phase 4 autoresearch needs to correlate exclusions with merged findings
- The exclusion-model audit that goes with Phase 4's FP learning loop

**Suggested fix:**
1. In `render_and_write`, when matching a Finding with non-None
   `merged_from_sources`, iterate ALL source agents (parsed from the
   list) and call `match_exclusions` for each. Suppress the finding if
   ANY source matches an exclusion.
2. Dependency on T19-M3: if `merged_from_sources` migrates from
   `list[str]` ("agent (severity)") to `list[dict]` ({"agent": ...,
   "severity": ...}), the per-source iteration becomes cleaner — no
   string parsing.
3. Add regression test: merged finding with agent=A primary,
   merged_from_sources includes agent=B. Exclusion keyed on agent=B
   must suppress the merged finding. Exclusion keyed on agent=A must
   also suppress it.
4. Update `exclusions_applied` in render result to carry the
   matched-source-agent (so downstream consumers understand why the
   merged finding was suppressed).

**Estimated scope:** ~40 LOC in `render_and_write` + per-source
iteration helper + 3 regression tests. Medium complexity due to the
exclusions_applied schema extension.

### T19-M3 — Structured `merged_from_sources` format (list[str] → list[dict])
**Phase-4 readiness:** `blocker` — structured `merged_from_sources` format is the schema Phase 4 autoresearch reads

**Source:** Phase 3b T19 quality review, 2026-04-19
**File:** `src/screw_agents/models.py::Finding.merged_from_sources` +
`src/screw_agents/results.py::_merge_findings_augmentatively` +
`src/screw_agents/formatter.py` (Markdown renderer) + tests

**Priority:** Low (current format works for display + known consumers)

**What's shipped (T19):** `merged_from_sources: list[str] | None` where
each string is formatted as `"<agent> (<severity>)"`. Works for Markdown
display and for JSON consumers who just read the list. Downstream SARIF
emission (T19-M1 deferral) and potential regex-parsing consumers would
find the string format fragile — nested parens in agent names would
break `rsplit(" (", 1)` parsing.

**Why deferred:** Migrating now is strictly an ergonomic improvement
with no current failing consumer. JSON-side structure is stable; the
LIST wrapper is the schema contract, element shape is the
evolvability concern.

**Trigger:** Any of:
- Phase 4 autoresearch consumes `merged_from_sources` and needs
  per-source severity programmatically
- SARIF emission (T19-M1) goes structured via the properties bag
- A consumer reports the format can't roundtrip an edge-case agent name

**Suggested fix:**
1. Change schema to `merged_from_sources: list[MergedSource] | None`
   where:
   ```python
   class MergedSource(BaseModel):
       agent: str
       severity: str
   ```
2. Update merge function to emit `MergedSource(agent=f.agent,
   severity=f.classification.severity)` instead of formatted strings.
3. Update Markdown renderer to format on the fly:
   `", ".join(f"{s.agent} ({s.severity})" for s in f.merged_from_sources)`.
4. Update all 9 T19 tests to expect structured objects (or use helper
   to convert for display assertion).
5. Update T19-M2 (per-source exclusion matching) to iterate structured
   sources rather than parse strings.
6. Backward-compat consideration: existing JSON output consumers who
   parse `list[str]` will break. Because `merged_from_sources` is
   Phase-3b-new, there are no shipped external consumers yet —
   migration has zero user impact right now. Later migration would
   be more expensive.

**Estimated scope:** ~100 LOC across 4 files + 9 test updates +
1 new model. Small PR.

### T-FULL-P1 — Paginate `assemble_full_scan` + apply lazy-fetch + agent-relevance filter
**Source:** X1-M1 (PR #9, 2026-04-17) — incremental dedup landed; full architectural fix deferred.
**File:** `src/screw_agents/engine.py` `assemble_full_scan`, `plugins/screw/agents/screw-full-review.md`
**Priority:** **HIGH** — `scan_full` is unusable at CWE-1400 expansion scale (41 agents per `docs/AGENT_CATALOG.md`).
**Phase-4 readiness:** `blocker` — HIGH priority — scan_full is non-paginated + agent-relevance-blind; at 41-agent CWE-1400 expansion it's unusable; Phase 4 autoresearch uses scan_full in volume

**Why deferred:** X1-M1 shipped incremental improvements to `assemble_full_scan`:
- PR #9 T5: changed return shape from `list[dict]` to `dict` with top-level `prompts`
- PR #9 T14: dropped top-level `prompts` dict; per-agent entries carry only `{agent_name, code, meta, exclusions?}`; subagents fetch prompts lazily via `get_agent_prompt`

However, the function remains:
1. **Non-paginated** — returns all code for all files for all agents in a single response
2. **Agent-relevance blind** — invokes every registered agent regardless of whether the target contains code the agent can usefully analyze (e.g., PHP-specific agents on a Python-only target)

At CWE-1400 expansion scale (41 agents × ~5-7k tokens prompt each + all code), even lazy per-agent prompt fetch cannot prevent the cumulative subagent context from approaching practical limits:
- 41 agents × 5-7k tokens cached prompts = ~205-287k tokens
- Plus cumulative code across all files × 41 agent analyses
- Opus 1M context window fits it in theory, but practically wasteful and fragile

**Trigger:** Any of:
- A round-trip test confirms `scan_full` stalls on a realistic project at Phase 3b+ agent count (≥10)
- Phase 4 autoresearch uses `scan_full` in volume and trips budget limits
- A user reports `scan_full` failures due to payload size or context exhaustion

**Suggested fix (three components, ship as one or sequential PRs):**

1. **Pagination** — cursor-based over the flattened `(agent, file_chunk)` space. Cursor carries `{target_hash, agent_offset, file_offset}`. Same init-page/code-page split as `scan_domain` post-T13.
2. **Lazy per-agent prompt fetch** — scan_full response never includes `prompts`; orchestrator uses `get_agent_prompt` on first-encounter per agent, caches for reuse across pages. This is already the pattern T13-T16 applies to scan_domain.
3. **Agent-relevance pre-filter** — scan_full returns only agents whose `target_strategy.relevance_signals` match files present in the target. For example, on a Python-only target, skip LDAP/NoSQL/PHP-specific agents that would produce no findings anyway. Could halve active-agent count on typical targets. New `ScanEngine._filter_relevant_agents(codes, agents)` helper.

**Estimated scope:** ~500-700 LOC across engine.py, server.py, orchestrator prompts, tests. Separate focused PR (likely Phase 4 prerequisite).

### T5-M4 — Lazy fingerprint computation in `verify_signature`
**Source:** Phase 3a PR#1 punchlist (commit `27d147d`)
**File:** `src/screw_agents/trust.py` `_fingerprint_public_key` and `verify_signature`
**Phase-4 readiness:** `nice-to-have` — fingerprint compute cost; perf polish only
**Why deferred:** Each successful verify computes the fingerprint even when the caller doesn't read `matched_key_fingerprint`. Trivial cost today; CLI batch verification could amplify.
**Trigger:** When batch verification becomes a measurable cost (Phase 4 autoresearch loop or Phase 7 multi-tenant MCP).
**Suggested fix:** Add `compute_fingerprint: bool = True` parameter to `verify_signature` OR make the fingerprint a `VerificationResult` cached property.

### T8-M4 — `record_exclusion` O(n²) verification cost
**Source:** Phase 3a PR#1 punchlist (commit `27d147d`)
**File:** `src/screw_agents/learning.py` `record_exclusion`
**Phase-4 readiness:** `nice-to-have` — O(n²) verification cost at scale; Phase 4 scale may amplify but not blocker
**Why deferred:** Tens of entries today; Phase 4+ autoresearch may record hundreds per run.
**Trigger:** When `record_exclusion` calls dominate a per-run profile.
**Suggested fix:** Cache verification results keyed on `(exclusion.id, exclusion.signature)` OR add a "skip re-verification on append" fast path.

### T9-I2 (record_exclusion path) — Atomic write in `learning.py`
**Source:** Phase 3a PR#1 punchlist (commit `27d147d`)
**File:** `src/screw_agents/learning.py` `record_exclusion` write
**Phase-4 readiness:** `nice-to-have` — atomic write on single-record path; race window is small
**Note:** CLI write paths (`cli/migrate_exclusions.py`, `cli/validate_exclusion.py`) already use `tmp.write_text + os.replace`. The `learning.py` `record_exclusion` path is the remaining non-atomic write.
**Why deferred:** Single-record write; risk window is small at current scale.
**Trigger:** When concurrent or high-frequency `record_exclusion` calls become possible.
**Suggested fix:** Mirror the CLI pattern — `tmp = path.with_suffix(".yaml.tmp"); tmp.write_text(...); os.replace(tmp, path)`.

### T10-I2 — Full-scan exclusion-load amplification
**Source:** Phase 3a PR#1 punchlist (commit `27d147d`)
**File:** `src/screw_agents/engine.py` `assemble_full_scan` / `assemble_domain_scan`
**Phase-4 readiness:** `nice-to-have` — exclusion-load amplification; perf only
**Why deferred:** Both methods call `assemble_scan` in a list comprehension; each iteration reloads exclusions independently. For an N-agent full scan, that's N×(parse+verify) where 1 would suffice. Task 10's I1 fix halved per-iteration cost but didn't touch per-scan amplification.
**Trigger:** When full-scan latency becomes user-visible (Phase 4 autoresearch loop or large project benchmarks).
**Suggested fix:** Scan-scoped cache at `assemble_full_scan` / `assemble_domain_scan` level — load exclusions once, pass through `assemble_scan` via an optional `_preloaded_exclusions` parameter (~15 lines).

---

## Phase 7 (multi-process MCP server)

### T6-M1 — TOCTOU race on `load_config` stub creation
**Source:** Phase 3a PR#1 punchlist (commit `27d147d`)
**File:** `src/screw_agents/trust.py` `load_config` stub-write block
**Phase-4 readiness:** `phase-7-scoped` — TOCTOU only possible under multi-process load_config
**Why deferred:** Single-process CLI is safe; concurrent `load_config` calls can only happen in multi-process MCP server.
**Trigger:** Phase 7 multi-process MCP server work.
**Suggested fix:** Use `os.open(path, O_CREAT | O_EXCL | O_WRONLY)` for atomic stub creation.

### T6-M4 — `load_config` `@lru_cache` with staleness invalidation
**Source:** Phase 3a PR#1 punchlist (commit `27d147d`)
**File:** `src/screw_agents/trust.py` `load_config`
**Phase-4 readiness:** `phase-7-scoped` — load_config caching only matters under Phase 7 request volume
**Why deferred:** Each call re-reads the file; fine for single-scan CLI; per-request disk hit in Phase 7 MCP server.
**Trigger:** Phase 7 MCP server profiling.
**Suggested fix:** `@lru_cache` keyed on `project_root` with mtime-based invalidation hook.

### T9-I1 — Concurrent `record_exclusion` race condition
**Source:** Phase 3a PR#1 punchlist (commit `27d147d`)
**File:** `src/screw_agents/learning.py` `record_exclusion`
**Phase-4 readiness:** `phase-7-scoped` — concurrent record_exclusion race needs multi-process MCP
**Why deferred:** Two concurrent calls both compute the same `next_seq` — second write overwrites the first. Single-process CLI never sees this.
**Trigger:** Phase 7 multi-process MCP risk surface.
**Suggested fix:** Wrap read-modify-write in `fcntl.flock` on a sibling `.lock` file. Lower-cost alternative: document the limitation in the docstring as "Not safe for concurrent invocation — external serialization required."

---

## Project-wide (not Phase-tagged)

### T-ORCHESTRATOR-SCHEMA — Backfill finding-object schema in domain orchestrator subagents
**Source:** X1-M1 PR#9 T6 quality review, 2026-04-17 (gap pre-existing, not introduced by T6)
**File:** `plugins/screw/agents/screw-injection.md` (and any future domain orchestrators)
**Priority:** Medium — determinism regression, not a correctness bug.
**Phase-4 readiness:** `nice-to-have` — determinism regression, not correctness; Phase 4 copes without

**Why deferred:** Single-agent orchestrators like `plugins/screw/agents/screw-sqli.md` carry the full finding-object JSON schema + field-population rules (line_start precision, verbatim CWE/OWASP copy, severity/confidence guidance). Domain orchestrators (currently just `screw-injection.md`, more will land in Phase 3b) delegate analysis to the per-agent prompts via `prompts[agent_name]` but don't carry an output-contract schema themselves. Two LLM sessions analyzing the same code under `/screw:injection` may produce differently-formatted findings (different field coverage, different severity interpretations). Pre-existing gap — not introduced by X1-M1. Worth addressing before Phase 3b multiplies the number of domain orchestrators (copy-paste amplifies the gap).

**Trigger:** Before Phase 3b adds a second or third domain orchestrator template, OR if a round-trip test shows cross-session finding-format drift under `/screw:injection`.

**Suggested fix:**
1. Extract the finding-object schema + field-population rules from `screw-sqli.md` into a reusable snippet (could live in a shared Markdown fragment or be duplicated verbatim for now).
2. Apply to `screw-injection.md` in Step 2 (the "Analyze All Accumulated Payloads" step).
3. Apply to future Phase 3b domain orchestrators.
4. Optional: add a lightweight round-trip test that invokes `/screw:injection` twice on a small fixture and asserts findings-format stability.

**Estimated scope:** ~50 LOC per orchestrator + optional test. Small PR.

### T10-M1 — `additionalProperties: false` on tool input schemas (PARTIAL SHIPPED PR #6)
**Source:** Phase 3a PR#1 punchlist (commit `27d147d`)
**File:** `src/screw_agents/engine.py` `list_tool_definitions` (and all sibling tool schemas)
**Phase-4 readiness:** `nice-to-have` — PARTIAL shipped in PR #6 for the 6 new tools; remaining project-wide audit is schema-tightening polish, not blocker
**Why deferred:** None of the existing Phase 2+ tools set this. Adding it to `verify_trust` alone would be inconsistent — this is a project-wide tightening that needs a dedicated polish commit covering all tools.

**Partial shipped:** PR #6 T22 applied `additionalProperties: false` to the 6 new MCP tools shipped in this PR (`stage_adaptive_script`, `promote_staged_script`, `reject_staged_script`, `sweep_stale_staging`, `list_adaptive_scripts`, `remove_adaptive_script`) — locked by regression test `test_tool_definitions_pr6_new_tools_reject_additional_properties` in commit `43cdabe`. The project-wide audit of pre-Phase-3b tool schemas (scan_*, accumulate_findings, finalize_scan_results, record_exclusion, etc.) remains deferred.

**Trigger (remaining scope):** Dedicated schema-tightening polish commit covering all pre-Phase-3b tools, OR when a confused-deputy concern surfaces.
**Suggested fix:** Apply `"additionalProperties": false` uniformly across all remaining tool input schemas in one commit.

### T16-M1 — Typed sub-models for `PatternSuggestion.evidence` / `DirectorySuggestion.evidence`
**Source:** Phase 3a PR#2 Task 16 quality review (commit `bb3b7a0`)
**File:** `src/screw_agents/models.py`
**Phase-4 readiness:** `nice-to-have` — typed evidence sub-models polish
**Why deferred:** Plan prescribes `dict[str, Any]`. Task 17/18/19 populate different evidence keys per feature, so typed sub-models need at least 2 variants. Deferring until the evidence-dict keys stabilize across Tasks 17–19 + Task 23 MCP output.
**Trigger:** When the MCP wire format for `aggregate_learning` is frozen (end of PR#2) OR when a downstream consumer breaks because of an evidence-key typo.
**Suggested fix:** Introduce `PatternEvidence` and `DirectoryEvidence` BaseModels; update aggregation.py to construct them; update tests. Enforces construction-time validation of evidence keys.

### T16-M2 — `generated_at: datetime` migration across all timestamp fields
**Source:** Phase 3a PR#2 Task 16 quality review (commit `bb3b7a0`)
**File:** `src/screw_agents/models.py` (`FPReport.generated_at`, `Exclusion.created`, and any future timestamp fields)
**Phase-4 readiness:** `nice-to-have` — datetime migration consistency pass
**Why deferred:** Task 16 inherits the str-convention from `Exclusion.created` (PR#1). Changing `FPReport.generated_at` alone would fragment the convention. A coordinated migration pass benefits from being one commit.
**Trigger:** When a malformed-timestamp bug surfaces, OR during a formatter-polish commit that already touches timestamp handling.
**Suggested fix:** Change all timestamp fields from `str` to `datetime`; add `model_config = ConfigDict(json_encoders={datetime: lambda v: v.strftime("%Y-%m-%dT%H:%M:%SZ")})` or use Pydantic v2's native json mode serializer; update tests that assert on string-literal timestamps.

### T16-M3 — `cwe: str` regex constraint consistency pass
**Source:** Phase 3a PR#2 Task 16 quality review (commit `bb3b7a0`)
**File:** all models with `cwe: str` fields — `FPPattern`, `PatternSuggestion`, `DirectorySuggestion` (wait — `DirectorySuggestion` has no `cwe` field; only `FPPattern` and `PatternSuggestion`), `ExclusionFinding`, `FindingClassification`
**Phase-4 readiness:** `nice-to-have` — CWE regex constraint consistency
**Why deferred:** Today any string is accepted (e.g., `"CWE89"` and `"CWE-89"` both pass). Normalization drift is possible. Fix needs a coordinated pass across all `cwe` fields to avoid one-model-at-a-time inconsistency.
**Trigger:** When CWE-normalization drift actually bites (first mismatched comparison), OR during the T16-M2 timestamp migration (same scope of coordinated-model-constraint work).
**Suggested fix:** Apply `Field(pattern=r"^CWE-\d+$")` uniformly to every `cwe: str` field. Update tests that construct CWE values.

### T16-M4 — Max-length constraints on FPReport list fields
**Source:** Phase 3a PR#2 Task 16 quality review (commit `bb3b7a0`)
**File:** `src/screw_agents/models.py` `FPReport`, `FPPattern`
**Phase-4 readiness:** `nice-to-have` — model-layer max_length bounds; aggregation caps already protect the path
**Why deferred:** Aggregation (Task 19) already caps `top_fp_patterns` to `_FP_REPORT_TOP_N = 10` and `example_reasons` to `[:5]`. Model-layer max_length would be redundant belt-and-suspenders. Deferring until a bypass surfaces (e.g., a different aggregation caller that doesn't cap).
**Trigger:** When a non-aggregation caller constructs FPReport (e.g., Phase 4 autoresearch) and evidence shows unbounded lists reaching the model layer.
**Suggested fix:** Add `Field(max_length=N)` to `top_fp_patterns`, `example_reasons`, `evidence.files_affected`.

### T17-M1 — Cap `files_affected` list size in `aggregate_pattern_confidence`
**Source:** Phase 3a PR#2 Task 17 quality review (commit `9c6ec7e`)
**File:** `src/screw_agents/aggregation.py` `aggregate_pattern_confidence`
**Phase-4 readiness:** `nice-to-have` — files_affected cap; unbounded-growth polish
**Why deferred:** A bucket with hundreds of matching files produces a `PatternSuggestion.evidence.files_affected` list containing all of them — unbounded growth proportional to FP-marked files. Aggregation is the producer, so the cap belongs here, but real-world bucket sizes in current usage are small. Related to T16-M4 (model-layer bounds); the caller-side cap is complementary.
**Trigger:** When a project with many FPs-per-pattern makes the emitted report unwieldy (subagent truncates, Markdown renderer stalls), OR during the T16-M4 bounds pass.
**Suggested fix:** Truncate `files_affected` to the top 20 lexicographically and emit an `evidence["files_affected_truncated"]: True` + `"files_affected_total": len(group)` fields when truncation occurs.

### T18-M1 — Multi-level directory grouping for `aggregate_directory_suggestions`
**Source:** Phase 3a PR#2 Task 18 quality review (commit `ce0773e`)
**File:** `src/screw_agents/aggregation.py` `aggregate_directory_suggestions`
**Phase-4 readiness:** `nice-to-have` — multi-level directory grouping UX polish
**Why deferred:** Current algorithm buckets by FIRST path component only — a repo with most files under `src/` collapses into one giant `src/` bucket, obliterating the "concentration" signal for sub-directories like `src/vendor/` or `src/services/`. The plan explicitly specifies first-segment grouping in §7.2 ("All 12 findings under `test/` were marked FP"), so the coarse granularity is by design for the initial release. Deferring the design question until user feedback shows whether sub-directory granularity is actually needed.
**Trigger:** User reports saying "the suggestion is too coarse — my whole src/ collapsed" OR Phase 4 autoresearch needs finer-grained signal.
**Suggested fix:** Extend signature with `granularity: Literal["top", "full"] = "top"` parameter. When `"full"`, use `os.path.dirname(file) + "/"` as the top_dir. Update tests to cover both modes. Or: emit suggestions at multiple granularities and let the subagent choose.

### T18-m1 — Sanitize `reason_distribution` keys in subagent render (Task 21 concern)
**Source:** Phase 3a PR#2 Task 18 quality review (commit `ce0773e`)
**File:** `plugins/screw/agents/screw-learning-analyst.md` (Task 21 subagent prompt)
**Phase-4 readiness:** `nice-to-have` — render-layer sanitization; shipped via T21-m1 render-layer escape already
**Why deferred:** The `evidence["reason_distribution"]` dict carries user-controlled reason strings as keys. They reach the rendered Markdown via the subagent. Task 18 doesn't sanitize at the data layer (reason is semantically text, not a code-pattern). The correct layer for escape-handling is the subagent prompt — instruct the LLM to render reasons as inline code (backticks) or truncate/escape.
**Trigger:** Task 21 implementation OR during the first real-world subagent run if a reason contains Markdown-structural characters.
**Suggested fix:** In `screw-learning-analyst.md`, add rule: "When rendering `evidence.reason_distribution` keys, wrap each reason in backticks to prevent Markdown injection from user-controlled exclusion-reason text."

### T19-N1 — Parameterize `aggregate_fp_report` `scope` and tuning constants
**Source:** Phase 3a PR#2 Task 19 quality review (commit `156508c`)
**File:** `src/screw_agents/aggregation.py` `aggregate_fp_report`
**Phase-4 readiness:** `nice-to-have` — aggregate_fp_report parameterization
**Why deferred:** Currently `scope` is hardcoded `"project"` and `_FP_REPORT_TOP_N=10` / `_FP_REPORT_MIN_COUNT=3` / `_FP_REPORT_MAX_REASONS=5` are module constants. Phase 4 autoresearch may want `"global"` scope (cross-project rollups), and different consumers may want different top-N caps (Phase 4 per-agent vs. display per-report). Adding parameters now without a known consumer shape would be speculative; the FPReport model already supports `Literal["project", "global"]`.
**Trigger:** Phase 4 autoresearch implementation, OR when Task 20's MCP tool gets a second consumer that needs different tuning.
**Suggested fix:** Add `*, scope: Literal["project", "global"] = "project", top_n: int | None = None, min_count: int | None = None, max_reasons: int | None = None` kwargs — defaults fall through to the module constants.

### T-PLUGIN-M1 — Marketplace packaging: publish `screw-agents` to PyPI + plugin-scoped `.mcp.json`
**Source:** Phase 3a PR#2 plugin-namespace restructure (commit `31bac3a`)
**File:** `pyproject.toml`, `plugins/screw/.mcp.json` (to be created), `.mcp.json` (at repo root, project-scoped — may be removed once plugin-scoped path is live)
**Phase-4 readiness:** `nice-to-have` — marketplace packaging; blocks external distribution not Phase 4
**Why deferred:** Today `.mcp.json` at repo root declares the MCP server as `uv run screw-agents serve --transport stdio`. That command only works when `pyproject.toml` is reachable (i.e., when Claude Code's cwd is the repo root). For marketplace distribution, Claude Code copies the plugin to `~/.claude/plugins/cache/...`, which does NOT include `pyproject.toml` — the server command would fail. The fix requires publishing `screw-agents` to PyPI and rewriting the MCP command to use `uvx screw-agents serve`, which works from anywhere.
**Trigger:** Before the first marketplace submission (Phase 7+ typical timing, but earlier if someone wants external users to install the plugin without cloning the repo).
**Suggested fix:**
1. Polish `pyproject.toml` for PyPI: add classifiers, long_description (point at README), fix any missing metadata.
2. Run `uv build` and `uv publish` (or `twine upload`) to push screw-agents to PyPI.
3. Add `plugins/screw/.mcp.json` with `{"mcpServers": {"screw-agents": {"command": "uvx", "args": ["screw-agents", "serve", "--transport", "stdio"]}}}`.
4. Optionally drop the project-scoped `.mcp.json` at repo root (or keep for editable-install dev mode).
5. Update `CONTRIBUTING.md` to document: "for marketplace install, plugin MCP uses the PyPI-published CLI."

### T-PLUGIN-M2 — Rename `screw-research` / `screw-review` skills to drop the redundant `screw-` prefix
**Source:** Phase 3a PR#2 plugin-namespace restructure (audit)
**File:** `plugins/screw/skills/screw-research/SKILL.md`, `plugins/screw/skills/screw-review/SKILL.md`, plus 33 files referencing these names (domains/*.yaml fixtures, docs, plans).
**Phase-4 readiness:** `nice-to-have` — skill-name prefix cleanup; cosmetic
**Why deferred:** After the plugin-namespace fix, skill invocations are `/screw:screw-research` and `/screw:screw-review` — the `screw-` prefix is redundant because the plugin namespace already provides it. Renaming to `/screw:research` and `/screw:review` is cleaner, but the skill names appear in ~33 tracked files (domain YAMLs, plans, PRD, PHASE_*.md, DECISIONS.md, KNOWLEDGE_SOURCES.md, benchmark fixtures). Out of scope for PR#2's namespace cleanup; deserves a dedicated rename commit with its own audit pass.
**Trigger:** Any of: (a) a dedicated polish commit before the first marketplace submission, (b) a user-visible redundancy complaint, (c) alongside T-PLUGIN-M1.
**Suggested fix:**
1. `git mv plugins/screw/skills/screw-research plugins/screw/skills/research`; same for screw-review.
2. Update SKILL.md frontmatter `name:` fields if they reference the dirname.
3. Bulk find-replace: `screw-research` → `research`, `screw-review` → `review` across all tracked files. Careful: `screw-review` appears as a substring in other contexts — do a scoped replacement with per-file review.
4. Verify benchmark fixtures still reference the right skill (they're consumed by other tooling, not invoked as slash commands; likely no change needed).
5. Run `uv run pytest -q` to confirm no test regression.

### T21-m1 — Server-side reason backtick-wrapping in `aggregation.py`
**Source:** Phase 3a PR#2 round-trip test (commits `c468041` + `41bd19f`), 2026-04-16
**File:** `src/screw_agents/aggregation.py` (`aggregate_directory_suggestions`, `aggregate_fp_report`), `plugins/screw/agents/screw-learning-analyst.md`
**Phase-4 readiness:** `nice-to-have` — render-layer escape shipped; server-side pre-wrap is defense-in-depth
**Why deferred:** T18-m1's subagent prompt rule (backtick-wrap reason strings from `evidence.reason_distribution` keys + `FPPattern.example_reasons`) was tightened to MANDATORY framing with negative examples during PR#2 (commit `41bd19f`). Observed behavior: Opus 4.6 renders reasons with backticks; Opus 4.7 renders them with double-quotes (partial adherence). Prompt-level enforcement can't deterministically control cross-model LLM output. The correct defense is structural: aggregation.py emits pre-wrapped reason strings, eliminating LLM discretion from the Markdown-injection boundary. Current state is not a vulnerability — fixture reasons are benign strings — but the defense is preventive against future attacker-influenced reasons.
**Trigger:** (a) Before PR#3 work starts is natural (same file, no merge conflicts), OR (b) when a reason string in the wild contains Markdown-structural characters that visibly leak through the report.
**Suggested fix:**
1. In `DirectorySuggestion.evidence`, add a parallel `reason_distribution_rendered: str` field (pre-formatted Markdown like `` `Full-text search` (11), `one-shot migration` (3) ``). Keep `reason_distribution: dict[str, int]` for programmatic consumers.
2. In `FPPattern`, add `example_reasons_rendered: list[str]` (each element already backtick-wrapped). Keep `example_reasons: list[str]` for machine use (Phase 4 autoresearch).
3. Update `plugins/screw/agents/screw-learning-analyst.md` to instruct the subagent to output `reason_distribution_rendered` and `example_reasons_rendered` fields VERBATIM (no further wrapping needed).
4. Update Task 23 integration test to assert the rendered fields contain backticks.
5. Simplify the T18-m1 MANDATORY rule in the subagent prompt — it becomes a single line referencing the pre-rendered fields, not a rule the LLM must apply.

### T21-m2 — Server-side trust-notice rendering
**Source:** Phase 3a PR#2 round-trip test (commits `c468041` + `41bd19f`), 2026-04-16
**File:** `src/screw_agents/engine.py` `aggregate_learning`, `plugins/screw/agents/screw-learning-analyst.md`
**Phase-4 readiness:** `nice-to-have` — trust-notice structural rendering polish
**Why deferred:** The trust-notice block in the subagent prompt is a 4-line template the LLM is supposed to output verbatim when `quarantine_count > 0`. Observed behavior: Opus 4.6 renders it cleanly; Opus 4.7 paraphrases (drops `⚠`, drops bold, truncates the `screw-agents migrate-exclusions` sentence). Tightening the prompt rule to "render character-for-character" (commit `41bd19f`) didn't fully pin down 4.7's behavior. Same class of issue as T21-m1 — prompt adherence is not a security boundary. The core fact (quarantine count > 0) IS communicated; only template fidelity drifts. Structural fix: have `aggregate_learning` include a pre-rendered `trust_notice_markdown` field when `quarantine_count > 0`, which the subagent outputs verbatim (LLM-generated → LLM-copied; less drift).
**Trigger:** Alongside T21-m1 (same file, same design pattern, same follow-up PR is natural).
**Suggested fix:**
1. In `ScanEngine.aggregate_learning`, when `trust_status["exclusion_quarantine_count"] > 0`, compose the trust-notice Markdown block server-side and attach it as `trust_status["notice_markdown"]: str`. Use the canonical template verbatim, interpolating the count.
2. Update subagent prompt: replace the "render character-for-character" rule with "output `trust_status.notice_markdown` verbatim as the FIRST content line when it is non-empty." Simpler rule, deterministic content.
3. Add a test to `tests/test_aggregate_learning_tool.py` asserting `notice_markdown` is present when quarantine_count > 0 AND absent otherwise.
4. Round-trip test should re-validate that the notice appears correctly across model versions.

### T16-N1 — `AggregateReport.generated_at` convenience field
**Source:** Phase 3a PR#2 Task 16 quality review (commit `bb3b7a0`)
**File:** `src/screw_agents/models.py` `AggregateReport`
**Phase-4 readiness:** `nice-to-have` — convenience timestamp field
**Why deferred:** `FPReport.generated_at` is already present; the wrapper doesn't need its own. Adding one now is YAGNI until a consumer actually demands a single authoritative timestamp for the whole report.
**Trigger:** When a consumer of `aggregate_learning` output (MCP caller, markdown formatter, etc.) needs a wrapper-level timestamp and can't satisfy it via `fp_report.generated_at`.
**Suggested fix:** Add `generated_at: str` (matching the inner FPReport convention pre-T16-M2, or `datetime` post-T16-M2) populated by `ScanEngine.aggregate_learning`.

### T21-m3 — Pydantic validator guard on `ExclusionInput.reason`
**Source:** Phase 3a PR#3 Task 0a (T21-m1) fix-up review, 2026-04-16
**File:** `src/screw_agents/models.py` `ExclusionInput.reason`
**Phase-4 readiness:** `nice-to-have` — pydantic validator guard; belt-and-suspenders on top of render escape
**Why deferred:** T21-m1's fix-up added a render-layer escape for backticks in `src/screw_agents/aggregation.py::_escape_reason_for_code_span`. Belt-and-suspenders would add a Pydantic validator on `ExclusionInput.reason` that rejects or strips backticks at storage time — guaranteeing every path that persists an exclusion carries a safe reason, not just the aggregation rendering path. Deferring because (a) the render-layer fix is already load-bearing for the current consumer, (b) storage-layer validation is a separate design decision (reject vs strip vs warn) that deserves its own PR, (c) existing exclusions-YAML data may contain backticks and would need migration.
**Trigger:** When a second consumer of `ExclusionInput.reason` renders to Markdown (e.g., Phase 3b adaptive-script rejection reasons piped through the same FP report — see `PHASE_3B_PLAN.md` Task 3b-18), OR when a data audit shows wild backticks in exclusions.yaml, OR during a dedicated data-integrity polish commit.
**Suggested fix:**
1. Add `@field_validator("reason")` to `ExclusionInput` that either strips backticks (silent sanitization) or raises ValueError (fail-closed). Recommend fail-closed so the user knows their reason was altered.
2. Provide a one-shot CLI migration (`screw-agents sanitize-exclusions`) that rewrites existing exclusions.yaml entries with sanitized reasons (preserving signatures via re-signing with the local key).
3. Remove the render-layer escape in aggregation.py as redundant (optional — can keep as defense-in-depth).

### T-ACCUMULATE-ONCE — UX polish: encourage single accumulate_findings call per scan
**Source:** Phase 3a X1-M1 round-trip testing (PR #9, 2026-04-17)
**File:** `plugins/screw/agents/screw-injection.md` (Step 3 critical rules), and other orchestrators if the pattern spreads
**Priority:** **Low** — UX annoyance, not a correctness issue
**Phase-4 readiness:** `nice-to-have` — UX polish; doesn't affect Phase 4 correctness

**Why deferred:** Final round-trip showed the subagent making 3 × `accumulate_findings` calls (one per agent batch), each carrying a cumulative findings payload. Each call required user confirmation with a "wall of text" approval prompt. The current `screw-injection.md` prompt explicitly permits multiple accumulate calls ("You MAY call this multiple times"). Narrowing to "prefer ONE accumulate call at the end with all findings" would reduce tool-call approvals from 4-6 to 2 in typical scans.

**Why not now:** The current behavior is correct (findings deduped by id; final output right). The wall-of-text approvals are annoying but not blocking. Tightening the prompt is a simple doc-only change, but without round-trip validation there's risk of over-constraining (e.g., if a subagent hits an LLM context limit partway through a scan, per-batch persistence is actually useful). Defer until: (a) users complain, OR (b) a round-trip test proves single-accumulate works reliably at current scale.

**Trigger:** Any of:
- User-visible complaint about approval-prompt fatigue during `/screw:scan domain ...`
- Round-trip test at larger scale (injection domain at full 10 agents per AGENT_CATALOG.md) shows single-accumulate is reliable
- Dedicated prompt-polish commit that tackles multiple orchestrator UX issues together

**Suggested fix:**
1. Update `plugins/screw/agents/screw-injection.md` Step 3a to soften "you MAY call this multiple times" → "prefer a SINGLE call at the end with all findings; multiple calls are safe (dedup by id) but each requires approval and is noisy".
2. Run round-trip. Confirm single-accumulate works.
3. Apply same softening to per-agent orchestrators if needed (they already call accumulate once since single-agent scans have only one batch).

**Estimated scope:** ~5-10 LOC of prompt text + round-trip validation.

### T11-M2 — Opt-in `require_all_target_patterns` metadata flag
**Source:** Phase 3b PR #4 Task 11 quality review (commit `da24076`), 2026-04-18
**File:** `src/screw_agents/adaptive/executor.py` `_is_stale` + `src/screw_agents/models.py` `AdaptiveScriptMeta`
**Priority:** Low (current semantic is acceptable Phase 3b default)
**Phase-4 readiness:** `nice-to-have` — require_all_target_patterns flag; autoresearch can opt in if needed

**Why deferred:** `_is_stale` currently returns False as soon as ANY
target_pattern matches at least one call site in the project. A script
declaring three target patterns where only one is present still runs
against "stale context" for the other two patterns. This is the liberal
"best-effort" default appropriate for Phase 3b's adaptive-script
generation model. Some future adaptive scripts may want strict semantics
("only run if ALL patterns still exist") to avoid producing irrelevant
findings against partially-obsolete code.

**Trigger:** When a real-world adaptive script produces noisy findings
because partial target_patterns are out-of-date, OR when autoresearch
(Phase 4) feedback flags the ANY semantic as a false-positive source.

**Suggested approach:**
1. Add `require_all_target_patterns: bool = False` to `AdaptiveScriptMeta`.
2. Update `_is_stale`: if the flag is True, require ALL patterns present
   (not ANY). Default False preserves current behavior.
3. Add a test covering each of the four combinations (flag on/off × patterns
   partial/complete).
4. Document in the adaptive-scripts authoring guide (Task 14+).

**Estimated scope:** ~20 LOC + 4 tests. Trivial.

### T16-M1 — Server-side context-required match detection (vs LLM-reported)
**Source:** Phase 3b PR #5 Task 16 implementation, 2026-04-19
**File:** `src/screw_agents/gap_signal.py`, `src/screw_agents/engine.py`
**Priority:** Medium (Phase 4 refinement)
**Phase-4 readiness:** `nice-to-have` — server-side context-required match detection; Phase 4 autoresearch scaffolding has its own pattern-match telemetry

**What's shipped now:** Subagent LLMs call `record_context_required_match` when they investigate a `severity: context-required` pattern and decide not to emit a finding. The scan engine has no independent way to detect context-required matches; it trusts the LLM's self-report. This closes the adaptive E2E loop but puts the onus on the subagent prompt (T18) to be disciplined.

**Why defer to Phase 4:** Server-side detection of context-required pattern matches would require parsing each agent's `detection_heuristics.context_required` patterns, compiling them against scanned source, and recording every match programmatically — independent of LLM reasoning. That's a lot of heuristic-compilation infrastructure (regex vs tree-sitter pattern matching, per-language behavior, false-positive filtering) and belongs with Phase 4's autoresearch scaffolding that already needs pattern-match telemetry.

**Trigger:** When Phase 4 autoresearch scaffolding lands OR when subagent-prompt discipline for `record_context_required_match` proves unreliable in production (measured via the matches-per-scan metric not moving when scans clearly encounter context_required patterns).

**Suggested approach:** Extend `gap_signal.py` with a `compile_heuristic_patterns(agent: AgentDefinition) -> list[CompiledHeuristic]` helper, add `scan_for_context_required_matches(project_root, agent) -> list[ContextRequiredMatch]` that runs at scan time, call alongside the LLM-driven path, and merge into staging with the existing 4-tuple dedup.

**Estimated scope:** ~150-250 LOC + 6-10 tests. Medium. Depends on Phase 4 heuristic-compilation framework.

### T16-M2 — Multi-session context-required match correlation
**Source:** Phase 3b PR #5 Task 16 implementation, 2026-04-19
**File:** `src/screw_agents/staging.py`
**Priority:** Low (deferred unless cross-session analytics prove useful)
**Phase-4 readiness:** `nice-to-have` — multi-session context-required correlation; analytics layer, not Phase 4 surface

**What's shipped now:** `context_required_matches.json` is strictly per-session. Each scan's matches are consumed at finalize and deleted. There's no cross-session retention or correlation.

**Why defer:** Cross-session correlation (e.g., "this file has had a context-required match on line 42 across 3 scans — promote to persistent watchlist") is an analytics layer, not a coverage-gap-signal layer. Likely belongs alongside `learning/exclusions.yaml` as a second learning artifact once the autoresearch loop (Phase 4) is live. Premature work without clear Phase 4 semantics.

**Trigger:** When autoresearch (Phase 4) needs historical context-required match telemetry as a signal input, OR when a user asks for a "chronic gap" report similar to `aggregate_learning`'s FP report.

**Suggested approach:** New `.screw/learning/context_required_history.yaml` written at finalize (mirroring the `exclusions.yaml` stable-artifact pattern), one `ScanEngine.aggregate_context_required_patterns` method for chronic-gap reporting, never auto-deleted.

**Estimated scope:** ~100 LOC + 5 tests. Small. Can be implemented independently of autoresearch when/if the use case materializes.

---

## Shipped

### X1-M1 — Core-prompt deduplication in `scan_domain` paginated responses
**Source:** Phase 3a PR#3 manual round-trip test, 2026-04-17
**Shipped in:** PR #9 (`phase-3a-prompt-dedup`), merge commit `4685671`
**Final design:** `docs/specs/2026-04-17-prompt-dedup-x1-m1-design.md` (local, not in git)
**Plan:** `docs/PHASE_3A_X1_M1_PLAN.md`

**Solution:** Applied Option A′ (init page + code pages) to `assemble_domain_scan` and Option A (top-level `prompts` dedup) to `assemble_full_scan`. `assemble_scan` gained `include_prompt: bool = True` kwarg. Cursor schema unchanged. `assemble_full_scan` return type changed from `list[dict]` to `dict` — breaking change to `scan_full` MCP tool.

**Follow-ups:**
- `T-FULL-P1` (Phase 4+) — paginate `assemble_full_scan` and apply Option A'
- `T-ORCHESTRATOR-SCHEMA` (project-wide) — backfill finding-object schema in domain orchestrator subagents
- `T-WRITE-SPLIT` (Shipped in this PR) — split write_scan_results into accumulate + finalize
- `T-STAGING-ORPHAN-GC` (Phase 4+) — clean up orphaned .screw/staging/ directories
- `T-ACCUMULATE-ONCE` (project-wide, Low) — prompt polish to prefer single accumulate call

### T-WRITE-SPLIT — Split `write_scan_results` into `accumulate_findings` + `finalize_scan_results`
**Source:** Phase 3a X1-M1 round-trip testing (PR #9, 2026-04-17)
**Shipped in:** PR #9 (`phase-3a-prompt-dedup`), merge commit `4685671`
**Plan:** `docs/PHASE_3A_X1_M1_PLAN.md`

**Problem:** Round-trip testing after the lazy-fetch fix (T12-T16) revealed a second defect — subagents called `write_scan_results` once per agent-batch (4 times for a 4-agent injection scan). Overwrite semantics masked this as "just wasteful" (the final call had all findings), but each intermediate call triggered file rewrites + user approvals + tool-call tokens. Prompt-level "call once" discipline was not load-bearing.

**Solution:** Option D — architectural split into two tools:
- `accumulate_findings(project_root, findings_chunk, session_id?) -> {session_id, accumulated_count}` — incremental staging in `.screw/staging/{session_id}/findings.json`; dedup by finding.id on merge; atomic tmp+replace writes
- `finalize_scan_results(project_root, session_id, agent_names, scan_metadata?, formats?) -> {files_written, summary, exclusions_applied, trust_status}` — one-shot render+write; reads staging, applies exclusions, renders formats, cleans up staging; second call raises ValueError

The subagent's natural "persist after each batch" instinct is channeled into cheap `accumulate_findings` calls; `finalize_scan_results` is an explicit terminal event. The legacy `write_scan_results` function and MCP tool were removed.

**Follow-up:** `T-STAGING-ORPHAN-GC` (Phase 4+) — orphan cleanup for scans that accumulate but never finalize.

---

## Shipped (PR #6)

> Items from the PR #5 round-trip test findings (C1 + I1-I6) and absorbed backlog entries that were addressed by the C1 staging architecture work in PR #6 (branch `phase-3b-c1-staging`, merge commit `<PR-6-merge-SHA>` — T26 closeout fills the actual SHA).

### C1 — CRITICAL: Human-approval flow regenerates script after approval (trust violation)
**Source:** Phase 3b PR #5 manual round-trip test, 2026-04-20
**Shipped in:** PR #6 (phase-3b-c1-staging), merge commit `<PR-6-merge-SHA>`
**Plan:** `docs/PHASE_3B_C1_PLAN.md`

Closed via staging architecture (spec §3.1-3.2): the LLM-flow subagent
stages via `stage_adaptive_script(source, meta)`, the reviewer reads staged
bytes, the user approves, then `promote_staged_script(script_name, session_id)`
reads the staged bytes from disk and signs them — no source parameter, no
regeneration. Locked by `tests/test_adaptive_workflow_staged.py` (T21 C1
exit gate): Step 11 asserts
`promote_response["sha256"] == compute_script_sha256(source)` and Step 12
asserts `signed_py.read_text() == source`.

### I1 — Layer 0d screw-script-reviewer subagent not invoked (plugin-namespace bug)
**Source:** Phase 3b PR #5 manual round-trip test, 2026-04-20
**Shipped in:** PR #6 (phase-3b-c1-staging), merge commit `<PR-6-merge-SHA>`

Addressed by T15-T17 prompt rewrites across the 4 per-agent adaptive-mode
sections: `subagent_type: "screw:screw-script-reviewer"` (plugin-namespaced)
replaces the bare name, with a format-smoke assertion in
`tests/test_adaptive_subagent_prompts.py` locking the namespace prefix.

### I2 — Layer 1 AST lint doesn't validate imported SYMBOLS against adaptive.__all__
**Source:** Phase 3b PR #5 manual round-trip test, 2026-04-20
**Shipped in:** PR #6 (phase-3b-c1-staging), merge commit `<PR-6-merge-SHA>`

Addressed by T10: `adaptive/lint.py` now loads `screw_agents.adaptive.__all__`
(cached via `@lru_cache(maxsize=1)`) and emits an `unknown_symbol` lint
violation for any `from screw_agents.adaptive import <name>` whose `<name>`
is not in the allowlist. The aliased-import attribute-access case
(`import screw_agents.adaptive as X; X.unknown`) remains deferred as
BACKLOG-PR6-11.

### I3 — Sandbox execution stderr not surfaced on failure
**Source:** Phase 3b PR #5 manual round-trip test, 2026-04-20
**Shipped in:** PR #6 (phase-3b-c1-staging), merge commit `<PR-6-merge-SHA>`

Addressed by T11: the executor surfaces `stderr` on execution failure
through `AdaptiveScriptResult.stderr`; the subagent prompts (T15-T17)
render it in a fenced block when `returncode != 0`. Regression test:
`test_executor_surfaces_stderr_on_failure`.

### I4 — Failed adaptive script stays on disk at .screw/custom-scripts/ after execution failure
**Source:** Phase 3b PR #5 manual round-trip test, 2026-04-20
**Shipped in:** PR #6 (phase-3b-c1-staging), merge commit `<PR-6-merge-SHA>`

Addressed by T15-T17 prompt hardening: the execute-failure branch in
each per-agent subagent explicitly documents the keep-on-disk behavior
and directs the user to `/screw:adaptive-cleanup remove <name>` for
removal. No code change — policy decision captured in prompt text.

### I5 — Prompt engineering to reduce LLM API hallucination
**Source:** Phase 3b PR #5 manual round-trip test, 2026-04-20
**Shipped in:** PR #6 (phase-3b-c1-staging), merge commit `<PR-6-merge-SHA>`

Addressed by T15-T17 prompt hardening: the generation-prompt section
in each per-agent subagent now carries a `MUST import ONLY`
declarative allowlist + negative-examples block naming forbidden
hallucinations (`read_source`, `parse_module`, `walk_module`). Defense
in depth with I2's lint-layer validation.

### I6 — `adaptive-cleanup.md` `uv run python -c` fails when cwd ≠ worktree
**Source:** Phase 3b PR #5 manual round-trip Steps 7-9, 2026-04-20
**Shipped in:** PR #6 (phase-3b-c1-staging), merge commit `<PR-6-merge-SHA>`

Addressed by T7-T9 + T19: list/remove/stale/sweep functionality promoted
to proper MCP tools (`list_adaptive_scripts`, `remove_adaptive_script`,
`sweep_stale_staging`), and `plugins/screw/commands/adaptive-cleanup.md`
rewritten to invoke via the MCP server (cwd-independent by construction).
`src/screw_agents/cli/adaptive_cleanup.py` deleted outright in T9.

### T-STAGING-ORPHAN-GC — Clean up orphaned `.screw/staging/` directories
**Source:** T-WRITE-SPLIT (PR #9, 2026-04-17) — deferred orphan cleanup
**Shipped in:** PR #6 (phase-3b-c1-staging), merge commit `<PR-6-merge-SHA>`

Absorbed by T6: new `sweep_stale_staging` MCP tool sweeps
`.screw/staging/<session>/adaptive-scripts/` directories older than
`staging_max_age_days` (default 30), preserving `TAMPERED` markers. The
companion `/screw:adaptive-cleanup stale` command surfaces this via the
MCP path. Tested in `test_adaptive_staging_sweep.py`.

### T3-M1 — Narrow exception handling in `adaptive/ast_walker.py` find_* helpers
**Source:** Phase 3b PR #4 Task 3 quality review, 2026-04-18
**Shipped in:** PR #6 (phase-3b-c1-staging), merge commit `<PR-6-merge-SHA>`

Addressed by T13: bare `except Exception: continue` in `find_calls`,
`find_imports`, `find_class_definitions` narrowed to
`except (UnicodeDecodeError, OSError)`; unexpected exceptions now
propagate as before. Regression fixtures in
`tests/test_adaptive_ast_walker.py` exercise the UTF-8 boundary.

### BACKLOG-PR6-49 — Stale docstring in `cli/adaptive_cleanup.py:16-19`
**Source:** Phase 3b PR #6 T7 Opus code-review (M-T7-1), 2026-04-22
**Shipped in:** PR #6 (phase-3b-c1-staging), commit `e91fe42` (T9)

Auto-resolved by T9's deletion of `src/screw_agents/cli/adaptive_cleanup.py`
— the docstring drift no longer exists because the module no longer
exists.

### T11-N1 — Signature-path regression test for `execute_script`
**Source:** Phase 3b PR #4 Task 11 quality review (commit `da24076`), 2026-04-18
**Shipped in:** PR #6 (phase-3b-c1-staging), commit `dc3762c` (T14)

Absorbed by T14: end-to-end signature-path regression test for
`execute_adaptive_script` covers Layer 2 (hash) AND Layer 3
(Ed25519 signature) on a real signed script + metadata. Tests
assert `SignatureFailure` on tampered signature and
`AdaptiveScriptResult` on valid signature, closing the
Layer 3 integration gap identified in T11's review.

### T11-N2 — `MetadataError` exception wrapper for meta-load failures
**Source:** Phase 3b PR #4 Task 11 quality review (commit `da24076`), 2026-04-18
**Shipped in:** PR #6 (phase-3b-c1-staging), commit `c3c52fd` (T12)

Absorbed by T12: `execute_script` now wraps both `yaml.YAMLError`
and `pydantic.ValidationError` from meta-loading as
`MetadataError(RuntimeError)`. The MCP tool wiring catches the
single unified exception family alongside `LintFailure` /
`HashMismatch` / `SignatureFailure`, closing the
exception-family-design inconsistency identified in T11's review.

### Round-trip test validation summary (PR #5 → PR #6)

The PR #5 round-trip manual test (2026-04-20) surfaced C1 + I1-I6
against a seeded QueryBuilder fixture. PR #6 (C1 staging architecture)
closed all seven findings via:
- **Staging architecture** (T3-T6, T20-T22) — `stage_adaptive_script` /
  `promote_staged_script` / `reject_staged_script` / `sweep_stale_staging`
- **Shared signing helper** (`_sign_script_bytes`) — one canonical-bytes
  source for both direct-sign and promote-sign paths
- **MCP-tool-based slash commands** (T7-T9 + T19) — cwd-independent
- **T15-T17 subagent prompt rewrite** — byte-identical adaptive-mode
  section enforced by `test_adaptive_subagent_prompts.py`
- **I2 lint-layer defense-in-depth** (T10) + **I3 stderr surfacing** (T11)
  + **T13 narrow-exceptions**

The PR #6 post-merge round-trip validation (T26) will confirm the
C1 trust invariant (`bytes_reviewed == bytes_signed == bytes_executed`)
end-to-end on a fresh fixture.

**See also:** `T10-M1` in the project-wide section below is PARTIAL
SHIPPED — the 6 new PR #6 MCP tools carry `additionalProperties: false`;
the project-wide audit of pre-Phase-3b tool schemas remains deferred.

---

## Phase 3b PR #6 follow-ups (Opus re-review polish)

> Items surfaced by the Opus 4.7 re-review of T1 + T2 on 2026-04-21. All are cosmetic polish or test-coverage gaps that don't block C1 trust-path correctness (which is proven by the 817-test suite + C1 regression test `test_sign_output_passes_executor_verification`). Scheduled for picking up during the next polish sweep, next test-hygiene sweep, or a dedicated cleanup commit.

### BACKLOG-PR6-01 — Nested `TargetGap` TypedDict inside `PendingApproval.target_gap`
**Source:** Phase 3b PR #6 T1 Opus re-review (I-opus-4), 2026-04-21
**File:** `src/screw_agents/models.py` — `PendingApproval` TypedDict
**Phase-4 readiness:** `nice-to-have` — PR #6 Opus re-review polish — cosmetic / test-coverage / ergonomics
**Why deferred:** Cosmetic typing improvement; no runtime impact. `target_gap: dict` with an inline comment documenting shape (`{type, file, line, agent}`) works at runtime but skips static type checking. The rest of `models.py` uses nested TypedDicts/BaseModels consistently — this is one departure.
**Trigger:** Next polish pass touching `models.py`, OR before Phase 4 autoresearch if it consumes `target_gap` programmatically and wants static guarantees.
**Suggested approach:** Define `class TargetGap(TypedDict): type: str; file: str; line: int; agent: str` and change `target_gap: dict` to `target_gap: TargetGap`. Update test-fixture dicts to conform.
**Estimated scope:** ~15 LOC + 1 test.

### BACKLOG-PR6-02 — Nested TypedDicts for `StaleStagingReport.scripts_removed` and `.tampered_preserved`
**Source:** Phase 3b PR #6 T1 Opus re-review (I-opus-5), 2026-04-21
**File:** `src/screw_agents/models.py` — `StaleStagingReport` TypedDict
**Phase-4 readiness:** `nice-to-have` — PR #6 Opus re-review polish — cosmetic / test-coverage / ergonomics
**Why deferred:** Same as BACKLOG-PR6-01. `list[dict]` with a trailing shape comment compiles but doesn't enforce keys. These fields are the return shape for `sweep_stale_staging` landing in T6; typed shape matters when CLI or autoresearch consumes the report.
**Trigger:** T6 implementation (`sweep_stale_staging` engine method) — natural point to tighten since the code producing these dicts is being written.
**Suggested approach:** Define `class RemovedScriptEntry(TypedDict)` with `script_name, session_id, reason, age_days` and `class TamperedPreservedEntry(TypedDict)` with `script_name, session_id, evidence_path, age_days`. Change the two `list[dict]` fields to use these types.
**Estimated scope:** ~25 LOC + 1 test.

### BACKLOG-PR6-03 — Rollback test asserts meta_tmp cleanup
**Source:** Phase 3b PR #6 T1 Opus re-review (M-opus-1), 2026-04-21
**File:** `tests/test_adaptive_staging.py` — `test_write_staged_files_rolls_back_py_on_meta_failure`
**Phase-4 readiness:** `nice-to-have` — PR #6 Opus re-review polish — cosmetic / test-coverage / ergonomics
**Why deferred:** Test coverage gap. The rollback loop in `write_staged_files` iterates `(meta_tmp, py_path)`, but the test only asserts `.py` absence. `meta_tmp` cleanup is load-bearing for disk-state hygiene on restart. Currently verified empirically but not asserted in the test.
**Trigger:** Next test-coverage sweep.
**Suggested approach:** Add two assertions to the existing rollback test:
```python
assert not (stage_dir / "test-script.meta.yaml.tmp").exists()
assert list(stage_dir.iterdir()) == []
```
**Estimated scope:** 2-3 LOC.

### BACKLOG-PR6-04 — UTF-8 / CRLF / long-content round-trip test for staging.py
**Source:** Phase 3b PR #6 T1 Opus re-review (M-opus-2), 2026-04-21
**File:** `tests/test_adaptive_staging.py`
**Phase-4 readiness:** `nice-to-have` — PR #6 Opus re-review polish — cosmetic / test-coverage / ergonomics
**Why deferred:** Current `test_read_staged_files_returns_str_roundtrip` uses pure-ASCII content. A unicode / CRLF / long-content round-trip would guard against someone swapping `Path.write_text(encoding="utf-8")` for a lossy encoder or forgetting the explicit encoding argument.
**Trigger:** Next test-coverage sweep.
**Suggested approach:** Add a test that writes a source containing unicode (`"# café\nprint('ünîcôdé')\n"`), CRLF line endings, and content >PIPE_BUF (e.g., 8KB), then reads back and asserts byte-identical.
**Estimated scope:** ~20 LOC.

### BACKLOG-PR6-05 — Valid-edge-cases test writes into same dir across iterations
**Source:** Phase 3b PR #6 T1 Opus re-review (M-opus-3), 2026-04-21
**File:** `tests/test_adaptive_staging.py` — `test_write_staged_files_accepts_valid_script_name_edge_cases`
**Phase-4 readiness:** `nice-to-have` — PR #6 Opus re-review polish — cosmetic / test-coverage / ergonomics
**Why deferred:** Minor test quality — the test writes 4 names sequentially into the same `session_id` dir. `os.replace` is overwrite-atomic so the test passes, but it doesn't fully test iteration independence. Refactoring to parametrize or separate tmp_path per iteration would make the test cleaner.
**Trigger:** Next test-coverage sweep.
**Estimated scope:** ~5 LOC refactor.

### BACKLOG-PR6-06 — `staging.py` module docstring event-type list scope clarification
**Source:** Phase 3b PR #6 T1 Opus re-review (M-opus-4), 2026-04-21
**File:** `src/screw_agents/adaptive/staging.py` — module-level docstring (lines 1-32)
**Phase-4 readiness:** `retire` — cosmetic/docstring-wording polish — trigger unlikely to fire
**Why deferred:** The docstring lists registry event types (`staged`, `promoted`, `rejected`, `tamper_detected`, `swept`, etc.) as if registry-write is part of this module. T1 only provides `resolve_registry_path`; append/query land in T3, sweep in T6. A one-line note ("Event-type catalog listed here for reference; append/read lands in T3, sweep in T6") would prevent reader confusion.
**Trigger:** Next docstring polish pass OR after T3 lands (when the module actually implements registry write — the event-type list would then be authoritative).
**Estimated scope:** 1-2 line docstring clarification.

### BACKLOG-PR6-07 — `test_public_api_count_is_under_29` function-name / assertion inconsistency
**Source:** Phase 3b PR #6 T2 Opus re-review (M-2), 2026-04-21
**File:** `tests/test_adaptive_public_api.py`
**Phase-4 readiness:** `retire` — cosmetic/docstring-wording polish — trigger unlikely to fire
**Why deferred:** Function `test_public_api_count_is_under_29` asserts `public_count <= 28` (mathematically equivalent for integers but visually jarring). Docstring says "Over 28 is a red flag." Rename to `test_public_api_count_is_at_most_28` OR change assertion to `< 29` for consistency.
**Trigger:** Next test-hygiene sweep.
**Estimated scope:** 1-line rename or assertion style change.

### BACKLOG-PR6-08 — `adaptive/__init__.py` stale "under 25 exports" docstring
**Source:** Phase 3b PR #6 T2 Opus re-review (M-3), 2026-04-21
**File:** `src/screw_agents/adaptive/__init__.py`
**Phase-4 readiness:** `retire` — cosmetic/docstring-wording polish — trigger unlikely to fire
**Why deferred:** Module docstring claims "under 25 exports" but `EXPECTED_PUBLIC_API` curated set has 18 entries; total `dir(adaptive)` after T1+T2 is 28 (18 curated + 10 internal submodule bindings). Docstring has been drifting since T18a added `signing`; T1 + T2 each added a submodule without refreshing the claim.
**Trigger:** Next docstring polish pass OR whenever editing `adaptive/__init__.py`.
**Suggested replacement:** "(18 curated exports in EXPECTED_PUBLIC_API; total `dir(adaptive)` includes ~10 internal submodule bindings)".
**Estimated scope:** 2-3 line docstring update.

### BACKLOG-PR6-09 — Registry compaction when pending-approvals.jsonl exceeds 10MB or 1yr
**Source:** Phase 3b PR #6 design, 2026-04-20
**File:** `src/screw_agents/adaptive/staging.py` + new compaction CLI
**Priority:** Low — append-only JSONL; size stays manageable at current scale.
**Phase-4 readiness:** `phase-7-scoped` — registry compaction trigger fires only at large scale (>10MB or >1yr); single-process screw-agents unlikely to hit it
**Trigger:** registry exceeds 10 MB OR oldest entry exceeds 1 year OR audit performance becomes noticeable.
**Suggested fix:** `screw-agents compact-registry` CLI that archives old entries to `.screw/local/pending-approvals-archive/YYYY-MM.jsonl`; keep signatures preserved.

### BACKLOG-PR6-10 — Shared-prompt skill refactor via Claude Code `skills:` frontmatter
**Source:** Phase 3b PR #6 design; Claude Code guide confirmed feasible 2026-04-20
**File:** new `plugins/screw/skills/adaptive-mode/SKILL.md`; per-agent frontmatter in `plugins/screw/agents/screw-{sqli,cmdi,ssti,xss}.md`
**Priority:** Medium — byte-identical duplication across 4 files is painful when edited. Investigated in PR #6; Claude Code's `skills:` frontmatter preloads skill content into subagent context at startup — architecturally feasible.
**Phase-4 readiness:** `nice-to-have` — shared-prompt skill refactor; byte-identical duplication test catches drift today
**Trigger:** next T18b prompt edit that hits drift, OR after PR #6 demonstrates the byte-identity test has caught drifts in practice.
**Suggested fix:** extract the ~300-line Step 3.5d section to a skill entry; list the skill in each per-agent `skills:` frontmatter. Prototype to verify the preload order preserves the prompt's intended position in the subagent's context.

### BACKLOG-PR6-11 — Attribute-access lint for `import screw_agents.adaptive as X; X.unknown`
**Source:** I2 edge case (PR #6)
**File:** `src/screw_agents/adaptive/lint.py`
**Priority:** Low — requires attribute-access analysis; common case covered by I2.
**Phase-4 readiness:** `nice-to-have` — aliased-import lint edge case; common case covered by I2
**Trigger:** a real adaptive script uses aliased imports + accesses a non-existent attribute, OR a user reports lint-pass-then-execute-fail.
**Suggested fix:** extend AST walker to track `import X as Y` bindings and validate `Y.attr` against `screw_agents.adaptive.__all__`.

### BACKLOG-PR6-12 — Level 3 review-markdown hash binding (cryptographic)
**Source:** Phase 3b PR #6 design Q6; rejected Level 3 during brainstorm
**File:** TBD — would add `review_markdown_sha256` to registry entries
**Priority:** Low — only if threat model escalates (e.g., future UI auto-populates reviews). Current source-hash binding closes the realistic attacker path.
**Phase-4 readiness:** `nice-to-have` — Level 3 review-markdown hash binding; explicitly rejected at brainstorm — trigger is threat-model escalation
**Trigger:** threat-model change making source-only binding insufficient.
**Suggested fix:** TBD (would require `review_markdown_sha256` field in staging registry entries + `promote_staged_script` re-verification against the review markdown displayed to the user).

### BACKLOG-PR6-13 — Phase 4 autoresearch hook into staged-signing path
**Source:** Phase 3b PR #6 design Q4; revised 2026-04-23 (T24 fix-up) to migrate onto stage→promote per Option (b) architectural closure.
**File:** `src/screw_agents/engine.py::stage_adaptive_script` + `promote_staged_script` (already in place); Phase 4 autoresearch module (not yet written)
**Priority:** Phase 4 work (not standalone)
**Phase-4 readiness:** `nice-to-have` — Phase 4 autoresearch builds this hook itself; tracked BY Phase 4 build, not prerequisite to starting Phase 4 (tagging `blocker` would be circular — Phase 4 IS the consumer)
**Trigger:** Phase 4 autoresearch scaffolding needs a programmatic script-signing path after automated review.
**Suggested approach:** Phase 4's autoresearch module MUST use `stage_adaptive_script` → `promote_staged_script`, NOT the direct `sign_adaptive_script` path (which is retired per BACKLOG-PR6-22). After automated review produces approved source + meta, the module stages the script, performs its own verification step against the staged bytes, then calls `promote_staged_script` to sign and install. Blocked-by: BACKLOG-PR6-22 must be resolved before PR6-13 lands so the autoresearch module migrates onto stage→promote from day 1 (not after-the-fact).

### BACKLOG-PR6-14 — `append_registry_entry` `fsync` omission rationale
**Source:** Phase 3b PR #6 T3 Opus re-review (M1), 2026-04-21
**File:** `src/screw_agents/adaptive/staging.py` — `append_registry_entry`
**Phase-4 readiness:** `nice-to-have` — PR #6 Opus re-review polish — cosmetic / test-coverage / ergonomics
**Why deferred:** Current `os.write` is followed by `os.close` with no `os.fsync`. On a power-loss between write and kernel flush, the registry entry is lost. The staged `.py` + `.meta.yaml` remain, so T6 sweep reconciles — but the contract isn't documented in the function docstring. Either add `os.fsync(fd)` before close (perf cost, correct for forensic audit log) OR document the sweep-reconciles rationale.
**Trigger:** When deployment moves beyond single-process dev workflow, OR when a forensic incident requires stronger durability.
**Suggested fix:** Add a one-line comment and optionally `os.fsync(fd)` before `os.close(fd)`. If adding fsync, mirror the same call pattern in any future registry writers (promote, reject, sweep).
**Estimated scope:** 2 LOC + 1 comment + 1 optional test.

### BACKLOG-PR6-15 — `session_id_short = session_id[:12]` magic number
**Source:** Phase 3b PR #6 T3 Opus re-review (M2), 2026-04-21
**File:** `src/screw_agents/engine.py` — `stage_adaptive_script`
**Phase-4 readiness:** `nice-to-have` — PR #6 Opus re-review polish — cosmetic / test-coverage / ergonomics
**Why deferred:** The 12-char prefix is chosen to match the review header display format (plan spec §3.1). Code has no comment explaining the choice. Future reader wonders "why 12".
**Trigger:** Next docstring polish pass OR when the review header format changes.
**Suggested fix:** Add a one-line comment: `# 12 chars = display-friendly session prefix for the T18b review header`.
**Estimated scope:** 1 LOC comment.

### BACKLOG-PR6-16 — Collision check ignores meta content
**Source:** Phase 3b PR #6 T3 Opus re-review (M3), 2026-04-21
**File:** `src/screw_agents/engine.py` — `stage_adaptive_script` collision-check
**Phase-4 readiness:** `nice-to-have` — PR #6 Opus re-review polish — cosmetic / test-coverage / ergonomics
**Why deferred:** Idempotency check compares source `sha256` only. If source matches but meta differs, the existing meta file is silently overwritten. Defensible (only source bytes get signed and executed) but a caller expecting meta-divergence to be an error may be surprised.
**Trigger:** If a user reports surprising re-stage behavior when they changed meta but kept source, OR a security reviewer flags this as a tamper channel.
**Suggested fix:** Either (a) document the behavior explicitly in the docstring: "Meta differences are silently overwritten on re-stage; only source bytes participate in the collision check." — OR (b) hash `(source, meta_yaml)` together for the collision check (stricter, but breaks idempotency when callers legitimately update meta).
**Estimated scope:** 3-5 LOC docstring OR ~15 LOC behavioral change + test.

### BACKLOG-PR6-17 — `staging.py` module docstring event-type list is forward-looking
**Source:** Phase 3b PR #6 T3 Opus re-review (M4), 2026-04-21
**File:** `src/screw_agents/adaptive/staging.py` — module docstring
**Phase-4 readiness:** `retire` — cosmetic/docstring-wording polish — trigger unlikely to fire
**Why deferred:** The docstring enumerates 7 event types (`staged`, `promoted`, `promoted_via_fallback`, `promoted_confirm_stale`, `rejected`, `tamper_detected`, `swept`). At commit `a568f56`, only `staged` has a producer. T4 adds `promoted` variants + `tamper_detected`; T5 adds `rejected`; T6 adds `swept`. A reader confused by the gap would be helped by "(T3 produces: staged; T4-T6 produce the rest)".
**Trigger:** After T6 ships (when all producers exist) OR next docstring polish pass.
**Suggested fix:** Either add the scope-clarifying comment, or wait until T6 when the comment becomes authoritative.
**Estimated scope:** 1-2 line docstring update.

### BACKLOG-PR6-18 — Parametrize redundant slash cases
**Source:** Phase 3b PR #6 T3 Opus re-review (M5), 2026-04-21
**File:** `tests/test_adaptive_staging.py` — `test_stage_adaptive_script_rejects_threat_session_ids`
**Phase-4 readiness:** `nice-to-have` — PR #6 Opus re-review polish — cosmetic / test-coverage / ergonomics
**Why deferred:** Parametrize includes both `"../etc/passwd"` and `"foo/bar"` — both exercise the slash character-class rejection. Harmless duplication (each would catch a regression independently). Could be consolidated to one slash test OR kept as both (each represents a distinct threat model: traversal attempt vs generic path separator).
**Trigger:** Next test-hygiene sweep.
**Estimated scope:** 1-line parametrize removal OR 2-line rationale comment clarifying why both.

### BACKLOG-PR6-19 — `confirm_sha_prefix` entropy (8 hex chars = 32 bits)
**Source:** Phase 3b PR #6 T4 pre-audit (C2), 2026-04-21
**File:** `src/screw_agents/engine.py` — `promote_staged_script` fallback path
**Phase-4 readiness:** `nice-to-have` — PR #6 Opus re-review polish — cosmetic / test-coverage / ergonomics
**Why deferred:** The fallback-path confirmation phrase uses `script_sha256[:8]` (8 hex chars = 32 bits of entropy). Birthday-collision attack threshold is ~65,536 attempts. Not exploitable in practice — the UX is "user already typed approve {name} once; now re-typing a modified phrase" and the attacker must also overwrite the staging .py with matching source. But 32-bit entropy on a security-relevant confirmation is light.
**Trigger:** Next security-review sweep of the approve flow, OR if a real-world incident suggests the fallback path needs stronger confirmation.
**Suggested fix:** raise to 12 hex chars (48 bits, ~17M attempts for birthday) OR use a longer prefix (16 chars = 64 bits). Test + prompt text + docstring update + ~5 LOC.
**Estimated scope:** 10 LOC + 1-2 tests + prompt text updates in `plugins/screw/agents/screw-*.md`.

### BACKLOG-PR6-20 — `invalid_staged_meta` does not write TAMPERED marker
**Source:** Phase 3b PR #6 T4 pre-audit (C5), 2026-04-21
**File:** `src/screw_agents/engine.py` — `promote_staged_script` invalid-meta branch
**Phase-4 readiness:** `nice-to-have` — PR #6 Opus re-review polish — cosmetic / test-coverage / ergonomics
**Why deferred:** When `yaml.safe_load(meta_yaml)` fails (line ~2151-2157), promote returns `invalid_staged_meta` but does NOT touch the filesystem — no TAMPERED marker, no audit event. A tampered meta is arguably the same class of threat as a tampered .py (both invalidate the staging contract), so asymmetric treatment is defensible but not obviously correct.
**Trigger:** If an attacker is observed targeting .meta.yaml specifically (rather than .py), OR next trust-path threat-model refresh.
**Suggested fix:** on `yaml.YAMLError`, touch a `.METATAMPERED` marker + append a `meta_tampered` (or reuse `tamper_detected` with an evidence_type field) audit event. Same forensic-preservation pattern as the sha-mismatch tamper path.
**Estimated scope:** 15 LOC + 1 test.

### BACKLOG-PR6-21 — Fallback-path UX: reviewer-responsibility disclaimer
**Source:** Phase 3b PR #6 T4 Opus re-review (I-opus-3), 2026-04-21
**File:** `src/screw_agents/engine.py` — `promote_staged_script` fallback-path error message
**Phase-4 readiness:** `nice-to-have` — trust-path UX safety disclaimer on the promote fallback message; not a blocker but should not be silently dropped
**Why deferred:** The `fallback_required` response message hands the user the sha prefix and instructs them to paste it back. A user who did not personally review the staged bytes can copy-paste their way to a confirm. This is a design tradeoff (Q3 spec accepted) rather than a vulnerability, but the UX should explicitly name the reviewer's responsibility.
**Trigger:** Next UX polish pass on the approve-flow slash commands, OR if a user reports confusion / a post-incident review flags the UX.
**Suggested fix:** append to the fallback message body: "You are confirming the staging bytes' sha matches what you reviewed at stage time. If you did not personally review these bytes, run `reject` instead."
**Estimated scope:** ~5 LOC message text change + 1 format-smoke test assertion update.

### BACKLOG-PR6-22 — `sign_adaptive_script` retirement / C1-closure migration
**Source:** Phase 3b PR #6 T4 Opus re-review (I-opus-2), 2026-04-21
**File:** `src/screw_agents/engine.py` — `sign_adaptive_script`; `src/screw_agents/server.py` dispatcher; `plugins/screw/agents/screw-{sqli,cmdi,ssti,xss}.md` subagent prompts
**Phase-4 readiness:** `blocker` — architectural closure of C1; must be resolved before Phase 4's autoresearch module (BACKLOG-PR6-13) is designed against the direct-sign API
**Why deferred:** T4 closed C1 for the staged-path approve flow via `promote_staged_script`. The direct `sign_adaptive_script` MCP tool still accepts `source` / `meta` arguments — the regeneration vector at the MCP boundary. PR #6's T15-T17 subagent-prompt rewrite removed `sign_adaptive_script` from all 5 adaptive-mode subagent frontmatters, so no LLM-flow consumer exists today; the tool remains exposed server-side for programmatic consumers only. Fully closing C1 requires: (a) keeping subagent prompts on stage→promote (done in T15-T17), (b) retiring or dev-gating the direct-sign path at the server boundary, (c) ensuring the autoresearch hook (BACKLOG-PR6-13) is built against stage→promote from day 1. Phase 4 must be designed against stage→promote from day 1; tagging as blocker now prevents designing the autoresearch module against the direct-sign interface and creating a migration debt.
**Trigger:** Before Phase 4 step 4.0 (D-01 Rust benchmark corpus) — retire the direct-sign tool now, while it has zero real callers, rather than after the autoresearch module acquires it as a consumer.
**Suggested approach:** Direct retirement (no deprecation shim needed since no live callers exist) — (1) delete `engine.sign_adaptive_script`, (2) remove dispatcher entry in `server.py::_dispatch_tool`, (3) update the 1-2 remaining test files that exercise the direct path, (4) enforce Phase 4's autoresearch module is built against `stage_adaptive_script` → `promote_staged_script` from day 1.
**Estimated scope:** ~50 LOC (delete direct-sign code path + dispatcher entry + test migrations) plus design-discipline that Phase 4's autoresearch module uses stage→promote.

### BACKLOG-PR6-23 — Tamper-path `append_registry_entry` failure handling
**Source:** Phase 3b PR #6 T4 Opus re-review (I-opus-5), 2026-04-21
**File:** `src/screw_agents/engine.py` — `promote_staged_script` tamper branch
**Phase-4 readiness:** `nice-to-have` — PR #6 Opus re-review polish — cosmetic / test-coverage / ergonomics
**Why deferred:** If `append_registry_entry(tamper_entry)` fails (filesystem error) during tamper handling, the marker file is touched but the audit event is missing, and the `ValueError` escapes before the caller receives the tamper-detected error-dict. Tamper path is rare but critical; slightly more resilient surface is defensible.
**Trigger:** If a real-world incident shows a tamper case followed by a registry-write failure leaving ops with incomplete forensic evidence, OR next trust-path polish pass.
**Suggested fix:** wrap `append_registry_entry(tamper_entry)` in try/except ValueError; log the append failure (stderr / warn) but still return the tamper-detected error-dict with marker path.
**Estimated scope:** ~10 LOC + 1 monkey-patch test.

### BACKLOG-PR6-24 — Promoted-audit append failure rationale comment
**Source:** Phase 3b PR #6 T4 Opus re-review (I-opus-4), 2026-04-21
**File:** `src/screw_agents/engine.py` — `promote_staged_script` success path (after sign + delete)
**Phase-4 readiness:** `retire` — cosmetic/docstring-wording polish — trigger unlikely to fire
**Why deferred:** The final `append_registry_entry(promoted_entry)` at the end of promote is intentionally NOT wrapped — filesystem errors escape loud for ops to see. But the symmetry with the Step 8 swallowed-delete comment would help future readers; add an explicit comment documenting the choice.
**Trigger:** Next docstring polish pass.
**Suggested fix:** add a 3-line comment: "Step 9: append promoted audit event. If this raises, the sign already succeeded (custom-scripts is ground truth); the missing audit entry is recoverable by reconciling custom-scripts/ against the registry. We do NOT swallow here — ops needs to see the filesystem error loudly."
**Estimated scope:** 3 LOC comment.

### BACKLOG-PR6-25 — Lazy imports style consistency in `promote_staged_script`
**Source:** Phase 3b PR #6 T4 Opus re-review (I-opus-6), 2026-04-21
**File:** `src/screw_agents/engine.py` — `promote_staged_script` method body
**Phase-4 readiness:** `nice-to-have` — PR #6 Opus re-review polish — cosmetic / test-coverage / ergonomics
**Why deferred:** `promote_staged_script` imports `yaml`, `datetime`, and staging/signing helpers inside the method body. Other engine methods (e.g., `stage_adaptive_script` as implemented in T3) keep these at module scope. Style inconsistency; not a correctness issue. No circular-import concern visible.
**Trigger:** Next readability polish pass, OR if a contributor trips over the inconsistent style.
**Suggested fix:** hoist lazy imports to module scope; verify no circular imports introduced.
**Estimated scope:** ~15 LOC import consolidation + verification.

### BACKLOG-PR6-26 — Future-dated `staged_at` test coverage
**Source:** Phase 3b PR #6 T4 Opus re-review (I-opus-8), 2026-04-21
**File:** `tests/test_adaptive_staging.py`
**Phase-4 readiness:** `nice-to-have` — PR #6 Opus re-review polish — cosmetic / test-coverage / ergonomics
**Why deferred:** No test for clock-skew: `staged_at` in the future. Current behavior: `age` is negative; `age > timedelta(hours=24)` is False; staleness check is skipped; promote succeeds. Not a security concern (negative age means "staged recently"), but the behavior should be documented by a test.
**Trigger:** Next test-coverage sweep.
**Suggested fix:** add `test_promote_future_staged_at_proceeds_without_stale_error` asserting the promote path proceeds cleanly when `staged_at` is in the future.
**Estimated scope:** ~20 LOC test.

### BACKLOG-PR6-27 — `confirm_stale` schema `default` key
**Source:** Phase 3b PR #6 T4 Opus re-review (I-opus-9), 2026-04-21
**File:** `src/screw_agents/engine.py` — `promote_staged_script` tool schema
**Phase-4 readiness:** `nice-to-have` — PR #6 Opus re-review polish — cosmetic / test-coverage / ergonomics
**Why deferred:** Tool schema does not include `"default": false` for `confirm_stale`; method implementation defaults to False; dispatcher reads `args.get("confirm_stale", False)`. Functionally correct but not self-documenting from the schema alone.
**Trigger:** Next schema polish pass OR T22 additionalProperties sweep (if it also audits default keys).
**Suggested fix:** add `"default": false` to the `confirm_stale` schema block.
**Estimated scope:** 1-2 LOC.

### BACKLOG-PR6-28 — `promote_staged_script` method-length refactor
**Source:** Phase 3b PR #6 T4 Opus re-review (I-opus-10), 2026-04-21
**File:** `src/screw_agents/engine.py` — `promote_staged_script` (~340 LOC)
**Phase-4 readiness:** `nice-to-have` — PR #6 Opus re-review polish — cosmetic / test-coverage / ergonomics
**Why deferred:** Method is long. The staleness check (~60 LOC), fallback path (~40 LOC), and primary/tamper branch (~40 LOC) are distinct phases and could extract cleanly into `_check_staleness`, `_resolve_via_fallback`, `_handle_tamper` private helpers. This would simplify unit-testing those branches in isolation. The method IS readable as written, but a refactor would aid maintainability.
**Trigger:** Next readability polish pass, OR if a future T5/T6/T7 task touches the same method and the size becomes a merge-conflict risk.
**Suggested fix:** extract three private helpers; update tests to exercise them directly where helpful; preserve public signature.
**Estimated scope:** ~100 LOC refactor + test reorganization.

### BACKLOG-PR6-29 — `adaptive_prompts.json` tmp-file naming uses `with_suffix`
**Source:** Phase 3b PR #6 T5 pre-audit (N1), 2026-04-21
**File:** `src/screw_agents/engine.py` — `reject_staged_script`
**Phase-4 readiness:** `nice-to-have` — PR #6 Opus re-review polish — cosmetic / test-coverage / ergonomics
**Why deferred:** The tmp file for atomic JSON write uses `prompts_path.with_suffix(".json.tmp")`. Works correctly for `.json` (single-suffix), but inconsistent with T1's string-concat tmp-naming discipline (locked in to avoid the `.meta.yaml` double-suffix bug). Defensive consistency would prefer `prompts_path.parent / f"{prompts_path.name}.tmp"`.
**Trigger:** Next consistency-polish pass touching engine.py tmp-write sites.
**Suggested fix:** replace `with_suffix` with string-concat form.
**Estimated scope:** 1-line change + possibly a code comment.

### BACKLOG-PR6-30 — Silent swallow of `adaptive_prompts.json` write failures lacks impact comment
**Source:** Phase 3b PR #6 T5 pre-audit (N2), 2026-04-21
**File:** `src/screw_agents/engine.py` — `reject_staged_script`
**Phase-4 readiness:** `nice-to-have` — PR #6 Opus re-review polish — cosmetic / test-coverage / ergonomics
**Why deferred:** The `try/except (PermissionError, OSError): pass` around the `adaptive_prompts.json` update is documented as "best-effort; not critical to the reject flow's correctness". True, but what IS lost: T18b decline-tracking for this specific target — the scan may re-propose the same script next run. Comment should spell out the user-visible impact so an operator reading the code understands what gets skipped on filesystem failure.
**Trigger:** Next readability polish pass.
**Suggested fix:** expand the comment to "best-effort; on failure, T18b decline-tracking for this target is lost — the target may be re-proposed on next scan. Reject succeeds regardless since the audit entry in pending-approvals.jsonl already recorded the decision."
**Estimated scope:** 2-3 line comment.

### BACKLOG-PR6-31 — No test for rejecting a script already in promoted lifecycle state
**Source:** Phase 3b PR #6 T5 pre-audit (N4), 2026-04-21
**File:** `tests/test_adaptive_staging.py`
**Phase-4 readiness:** `nice-to-have` — PR #6 Opus re-review polish — cosmetic / test-coverage / ergonomics
**Why deferred:** `reject_staged_script` operates only on staging files — it doesn't check registry lifecycle. If a script was already promoted but staging files somehow exist (shouldn't happen in practice per T4's `delete_staged_files` cleanup, but possible after sweep race or hand-edit), reject would still delete staging and emit a `rejected` event. This is semantically ambiguous ("you promoted AND rejected?") but benign — reject acts on stage state, not on custom-scripts. Worth a test documenting the behavior.
**Trigger:** Next test-hygiene sweep OR if an incident surfaces unexpected post-promote reject behavior.
**Suggested fix:** add `test_reject_after_promote_is_noop_on_custom_scripts` — promote a script, manually re-plant staging files, reject, assert staging is deleted AND custom-scripts artifact is untouched.
**Estimated scope:** ~25 LOC test.

### BACKLOG-PR6-32 — Local `import json` shadows module-level `_json` alias
**Source:** Phase 3b PR #6 T5 Opus re-review (B-T5-1), 2026-04-21
**File:** `src/screw_agents/engine.py` — `reject_staged_script` (and possibly `promote_staged_script`)
**Phase-4 readiness:** `nice-to-have` — PR #6 Opus re-review polish — cosmetic / test-coverage / ergonomics
**Why deferred:** engine.py imports `json as _json` at module top (line 13) to avoid shadowing. `reject_staged_script` does a local `import json` inside the method body. Functionally correct (Python resolves local binding), but inconsistent with module style.
**Trigger:** Next engine.py style consistency pass.
**Suggested fix:** drop the local `import json`; rely on module-level `_json`; rename uses.
**Estimated scope:** ~3 LOC.

### BACKLOG-PR6-33 — Happy-path reject test missing full schema assertion
**Source:** Phase 3b PR #6 T5 Opus re-review (B-T5-3), 2026-04-21
**File:** `tests/test_adaptive_staging.py` — `test_reject_staged_script_deletes_files_and_audits`
**Phase-4 readiness:** `nice-to-have` — PR #6 Opus re-review polish — cosmetic / test-coverage / ergonomics
**Why deferred:** Test asserts `rej["reason"]` but not `rejected_at`, `schema_version`, `script_name`, `session_id`. `validate_pending_approval` catches absence at write-time, so absence would fail elsewhere — but explicit schema assertions are cheap regression insurance.
**Trigger:** Next test-hygiene sweep.
**Estimated scope:** ~5 LOC.

### BACKLOG-PR6-34 — Extract decline-tracking update into private helper
**Source:** Phase 3b PR #6 T5 Opus re-review (B-T5-4), 2026-04-21
**File:** `src/screw_agents/engine.py` — `reject_staged_script`
**Phase-4 readiness:** `nice-to-have` — PR #6 Opus re-review polish — cosmetic / test-coverage / ergonomics
**Why deferred:** The ~20-line block that updates `adaptive_prompts.json` is a self-contained concern ("remember this script was declined so it's not re-proposed"). Extracting to `_record_decline_in_prompts_file(project_root, script_name)` would shorten the main method and co-locate the best-effort policy.
**Trigger:** Next readability polish pass OR when T18b gets its own module.
**Estimated scope:** ~25 LOC refactor.

### BACKLOG-PR6-35 — No test for fresh-stage-between-rejects corner case
**Source:** Phase 3b PR #6 T5 Opus re-review (B-T5-5), 2026-04-21
**File:** `tests/test_adaptive_staging.py`
**Phase-4 readiness:** `nice-to-have` — PR #6 Opus re-review polish — cosmetic / test-coverage / ergonomics
**Why deferred:** If between first and second reject, a fresh stage happens with same `(script_name, session_id)`, second reject would delete the FRESH stage. Semantically correct ("reject acts on whatever is currently staged for that name+session") but not tested.
**Trigger:** Next test-hygiene sweep.
**Suggested fix:** add `test_reject_after_fresh_restage_deletes_fresh_stage` — stage, reject, stage again, reject again, assert the second fresh stage is deleted and two `rejected` audit events appear.
**Estimated scope:** ~25 LOC test.

### BACKLOG-PR6-36 — `invalid_session_id` error-dict omits helper-readable `session_id` field
**Source:** Phase 3b PR #6 T5 Opus re-review (minor observation), 2026-04-21
**File:** `src/screw_agents/engine.py` — `reject_staged_script`, `stage_adaptive_script`, `promote_staged_script`
**Phase-4 readiness:** `nice-to-have` — PR #6 Opus re-review polish — cosmetic / test-coverage / ergonomics
**Why deferred:** Error dicts for invalid session_id include the rejected value in `message` but not as a dedicated `session_id` field. Callers pattern-matching on `response["session_id"]` get KeyError on error paths. Minor UX.
**Trigger:** Next error-taxonomy polish pass.
**Suggested fix:** include `session_id` (or `rejected_session_id` if the raw one is ugly) as a dedicated field on the error dict. Apply uniformly across T3/T4/T5 error paths.
**Estimated scope:** ~10 LOC + test updates.

### BACKLOG-PR6-37 — `sweep_stale` inline walk vs `fallback_walk_for_script` helper
**Source:** Phase 3b PR #6 T6 pre-audit (N1), 2026-04-21
**File:** `src/screw_agents/adaptive/staging.py` — `sweep_stale` + `fallback_walk_for_script`
**Phase-4 readiness:** `nice-to-have` — PR #6 Opus re-review polish — cosmetic / test-coverage / ergonomics
**Why deferred:** `sweep_stale` uses inline `staging_root.iterdir()` + per-session `adapt_dir.glob("*.py")` walk. T3 added `fallback_walk_for_script(project_root, *, script_name)` for promote's fallback path. Different semantics (per-script lookup vs all-scripts scan), so direct reuse doesn't fit, but a shared `walk_all_staging` helper could consolidate the iteration pattern if a third consumer appears.
**Trigger:** If a T25+ task introduces a third iterator over `.screw/staging/**`.
**Suggested fix:** extract `walk_all_staging(project_root) -> Iterator[tuple[session_id, py_path]]`; use from sweep_stale; leave fallback_walk_for_script's per-script optimization intact.
**Estimated scope:** ~15 LOC extraction.

### BACKLOG-PR6-38 — Use `ScrewConfig.staging_max_age_days` field instead of raw YAML read
**Source:** Phase 3b PR #6 T6 pre-audit (N2), 2026-04-21
**File:** `src/screw_agents/engine.py` — `_read_staging_max_age_days`
**Phase-4 readiness:** `nice-to-have` — PR #6 Opus re-review polish — cosmetic / test-coverage / ergonomics
**Why deferred:** T4-part-2 (I1) added `ScrewConfig.staging_max_age_days: int = Field(default=14, ge=1, le=365)` to the Pydantic schema. T6's `_read_staging_max_age_days` reads raw YAML via `yaml.safe_load` + `.get()` as fallback (symmetric with T4's `_read_stale_staging_hours`). Could route through `load_config(project_root)` → Pydantic validation → then fall back to raw YAML only if Pydantic fails. Gives schema-validated default path.
**Trigger:** Next config-read polish pass; or when T6 behavior surprises a user due to silent schema bypass.
**Suggested fix:** attempt `load_config(project_root).staging_max_age_days`; on ValidationError or config absence, fall back to current raw-YAML path.
**Estimated scope:** ~10 LOC + 1 test.

### BACKLOG-PR6-39 — `sweep_stale` does not preserve TAMPERED files past max_age_days explicitly
**Source:** Phase 3b PR #6 T6 pre-audit follow-up, 2026-04-21
**File:** `src/screw_agents/adaptive/staging.py` — `sweep_stale` + `_classify_sweep_reason`
**Phase-4 readiness:** `nice-to-have` — PR #6 Opus re-review polish — cosmetic / test-coverage / ergonomics
**Why deferred:** Current logic: if TAMPERED marker exists AND age < max_age_days, preserve (report in tampered_preserved). If age >= max_age_days, fall through and sweep. This treats tamper evidence as "expires eventually". A stronger stance: tamper files NEVER auto-sweep; require explicit operator action (e.g., `screw-agents forensics-acknowledge <session> <script>`).
**Trigger:** If a post-incident review shows the auto-sweep expired useful forensic evidence, OR during Phase 4+ forensic-tooling work.
**Suggested fix:** add `force_sweep_tampered: bool = False` kwarg to `sweep_stale_staging`; default False means tampered files NEVER swept regardless of age.
**Estimated scope:** ~15 LOC + 2 tests.

### BACKLOG-PR6-40 — `_read_staging_max_age_days` exception breadth asymmetric with T4
**Source:** Phase 3b PR #6 T6 Opus review (M-T6-1), 2026-04-21
**File:** `src/screw_agents/engine.py` — `_read_staging_max_age_days`
**Phase-4 readiness:** `nice-to-have` — PR #6 Opus re-review polish — cosmetic / test-coverage / ergonomics
**Why deferred:** T6's helper catches `(PermissionError, OSError, ValueError)`. T4's sibling `_read_stale_staging_hours` catches `(ValueError, TypeError, OSError, yaml.YAMLError)`. Malformed YAML in T6's helper will crash sweep instead of falling back to 14.
**Trigger:** Next config-read polish pass.
**Suggested fix:** broaden to match T4's exception tuple; consolidate to a shared `_read_config_int(key, default, lo, hi)` helper.
**Estimated scope:** ~5 LOC.

### BACKLOG-PR6-41 — Orphaned TAMPERED marker when .py missing
**Source:** Phase 3b PR #6 T6 Opus review (M-T6-2 / M-T6-9), 2026-04-21
**File:** `src/screw_agents/adaptive/staging.py` — `sweep_stale`
**Phase-4 readiness:** `nice-to-have` — PR #6 Opus re-review polish — cosmetic / test-coverage / ergonomics
**Why deferred:** If `.py` is deleted but `.TAMPERED` marker remains (crash mid-sweep, manual user delete), sweep's `glob("*.py")` never iterates → marker never cleaned up → session dir pinned as non-empty forever.
**Trigger:** Observed in production OR when session-dir cleanup becomes a reliability concern.
**Suggested fix:** after the per-script loop, glob `"*.TAMPERED"` and unlink any orphans whose corresponding `.py` is absent.
**Estimated scope:** ~10 LOC + 1 test.

### BACKLOG-PR6-42 — `sessions_scanned` counter has no test coverage
**Source:** Phase 3b PR #6 T6 Opus review (M-T6-3), 2026-04-21
**File:** `tests/test_adaptive_staging.py` — sweep test suite
**Phase-4 readiness:** `nice-to-have` — PR #6 Opus re-review polish — cosmetic / test-coverage / ergonomics
**Why deferred:** The `sessions_scanned` field is returned in every sweep response but no test asserts it. Silent regression potential.
**Trigger:** Next test-hygiene sweep.
**Suggested fix:** extend an existing sweep test to stage in 3 sessions and assert `response["sessions_scanned"] == 3`.
**Estimated scope:** ~5 LOC.

### BACKLOG-PR6-43 — No positive test for `swept` event shape
**Source:** Phase 3b PR #6 T6 Opus review (M-T6-4), 2026-04-21
**File:** `tests/test_adaptive_staging.py`
**Phase-4 readiness:** `nice-to-have` — PR #6 Opus re-review polish — cosmetic / test-coverage / ergonomics
**Why deferred:** Dry-run test asserts registry UNCHANGED (negative case). No test verifies the real-path `swept` entry has all required fields per `_REQUIRED_FIELDS_BY_EVENT["swept"]`.
**Trigger:** Next test-hygiene sweep.
**Suggested fix:** add `test_sweep_appends_well_formed_swept_event` — reads JSONL tail after sweep, asserts event has {event, script_name, session_id, swept_at, sweep_reason, schema_version}.
**Estimated scope:** ~15 LOC.

### BACKLOG-PR6-44 — No test for tampered+expired→sweep transition
**Source:** Phase 3b PR #6 T6 Opus review (M-T6-5), 2026-04-21
**File:** `tests/test_adaptive_staging.py`
**Phase-4 readiness:** `nice-to-have` — PR #6 Opus re-review polish — cosmetic / test-coverage / ergonomics
**Why deferred:** `test_sweep_preserves_tampered_files` covers `age=10d, max=14d → preserve`. The spec path `tamper_detected + age >= max → swept (marker removed)` is implemented but unverified.
**Trigger:** Next test-hygiene sweep.
**Suggested fix:** stage → mark TAMPERED → age to 30d → sweep with max=14d → assert .py + marker both gone + `swept` event with reason `stale_orphan`.
**Estimated scope:** ~25 LOC.

### BACKLOG-PR6-45 — No test for `completed_orphan` path
**Source:** Phase 3b PR #6 T6 Opus review (M-T6-6), 2026-04-21
**File:** `tests/test_adaptive_staging.py`
**Phase-4 readiness:** `nice-to-have` — PR #6 Opus re-review polish — cosmetic / test-coverage / ergonomics
**Why deferred:** `_TERMINAL_EVENTS` classifier returns `completed_orphan` when registry has promoted/rejected/swept event but staging files are still present. Defensive-GC claim unverified by tests.
**Trigger:** Next test-hygiene sweep.
**Suggested fix:** construct the mocked partial state (promote, then replant staging files), run sweep with large max_age_days, assert files swept with reason `completed_orphan`.
**Estimated scope:** ~25 LOC.

### BACKLOG-PR6-46 — Outer `staging_root.iterdir()` not snapshotted
**Source:** Phase 3b PR #6 T6 Opus review (M-T6-7), 2026-04-21
**File:** `src/screw_agents/adaptive/staging.py` — `sweep_stale`
**Phase-4 readiness:** `nice-to-have` — PR #6 Opus re-review polish — cosmetic / test-coverage / ergonomics
**Why deferred:** Inner loop uses `list(adapt_dir.glob("*.py"))` defensively. Outer loop is a raw generator. Current code only mutates the CURRENT session_dir, which CPython os.scandir handles, but asymmetric defense is a readability smell.
**Trigger:** Next readability polish pass.
**Suggested fix:** wrap outer iteration in `list(staging_root.iterdir())` for symmetry.
**Estimated scope:** 1 LOC + comment.

### BACKLOG-PR6-47 — `sweep_stale` length (~120 LOC) refactor candidate
**Source:** Phase 3b PR #6 T6 Opus review (M-T6-8), 2026-04-21
**File:** `src/screw_agents/adaptive/staging.py` — `sweep_stale`
**Phase-4 readiness:** `nice-to-have` — PR #6 Opus re-review polish — cosmetic / test-coverage / ergonomics
**Why deferred:** Function is long. The per-script inner block could extract to `_process_staging_script(...)` returning `(removed | preserved | None)`. Simplifies unit-testing those branches in isolation.
**Trigger:** Next readability polish pass, OR when a future task touches `sweep_stale` and the size becomes a merge-conflict risk.
**Estimated scope:** ~30 LOC refactor.

### BACKLOG-PR6-48 — Session with only TAMPERED marker (no .py) not cleaned
**Source:** Phase 3b PR #6 T6 Opus review (M-T6-9), 2026-04-21
**File:** `src/screw_agents/adaptive/staging.py` — `sweep_stale`
**Phase-4 readiness:** `nice-to-have` — PR #6 Opus re-review polish — cosmetic / test-coverage / ergonomics
**Why deferred:** Edge case where `.py` unlink succeeded but marker unlink failed (or user manually deleted `.py`). Marker never cleaned up, session dir never removed. Related to BACKLOG-PR6-41 but distinct scenario.
**Trigger:** Post-incident review OR M-PR6-41 implementation (both fixed together).
**Estimated scope:** bundled with BACKLOG-PR6-41.

### BACKLOG-PR6-50 — `except Exception` inside `_check_stale` (verbatim-lift of pre-T7 code)
**Source:** Phase 3b PR #6 T7 Opus spec review (M2), 2026-04-22
**File:** `src/screw_agents/adaptive/executor.py:260` (relocated from `cli/adaptive_cleanup.py:249` in T7)
**Phase-4 readiness:** `nice-to-have` — PR #6 Opus re-review polish — cosmetic / test-coverage / ergonomics
**Why deferred:** The per-pattern `find_calls` call is wrapped in `except Exception:` to tolerate tree-sitter parse failures on any single file without failing the whole stale-check. Plan §T7 mandated verbatim lift (no behavioral changes during the move). Narrowing to a specific tree-sitter exception class is a follow-up concern that belongs with the broader T3-M1 narrow-exception work, not the move itself.
**Trigger:** Next adaptive-exception sweep OR when `find_calls` grows richer error types worth distinguishing.
**Estimated scope:** ~3 LOC (narrow the except; add a test that a single tree-sitter failure doesn't derail siblings).

### BACKLOG-PR6-51 — `test_adaptive_cleanup.py` module docstring drift
**Source:** Phase 3b PR #6 T8 Opus code-review (M1), 2026-04-22
**File:** `tests/test_adaptive_cleanup.py:1-15`
**Phase-4 readiness:** `retire` — cosmetic/docstring-wording polish — trigger unlikely to fire
**Why deferred:** Module header docstring still says "Tests for the adaptive_cleanup listing + removal backend (T21)" and lists the T21 remove coverage shape ("both-present happy path, not-found, partial-state recovery"). Does not mention the T8-era confirmation-gate and delete_failed tests, nor the migration from `cli.adaptive_cleanup` → `engine`. Class-level docstring for `TestRemoveAdaptiveScript` WAS updated; only the module header was missed. Cosmetic — no behavior impact.
**Trigger:** Next docs pass in this file, OR when someone touching this file reads the header and notices the drift.
**Estimated scope:** ~5 LOC (rewrite the module docstring to reflect T8's shape).

### BACKLOG-PR6-52 — Asymmetric filesystem assertion in `test_remove_cleans_up_partial_state_py_only`
**Source:** Phase 3b PR #6 T8 Opus code-review (M2), 2026-04-22
**File:** `tests/test_adaptive_cleanup.py` — `test_remove_cleans_up_partial_state_py_only`
**Phase-4 readiness:** `nice-to-have` — PR #6 Opus re-review polish — cosmetic / test-coverage / ergonomics
**Why deferred:** Py-only variant asserts only `not (script_dir / "lonely.py").exists()`. The sibling meta-only variant asserts both "not meta.exists()" and no-other-side-present. Adding `assert not (script_dir / "lonely.meta.yaml").exists()` to the py-only test would make the sibling pair diff-grep-comparable. Currently vacuous (meta never existed), so not a correctness concern.
**Trigger:** Next test-polish pass, OR if a future change introduces leftover-meta risk in the py-only path.
**Estimated scope:** 1 LOC (add the symmetric negative assertion).

### BACKLOG-PR6-53 — `_load_adaptive_all()` no-spec / no-origin failure paths are untested
**Source:** Phase 3b PR #6 T10 Opus spec review (Minor 1), 2026-04-22
**File:** `src/screw_agents/adaptive/lint.py:96-120` — `_load_adaptive_all` helper
**Phase-4 readiness:** `nice-to-have` — PR #6 Opus re-review polish — cosmetic / test-coverage / ergonomics
**Why deferred:** The defensive `frozenset()` return paths at `lint.py:107-108` (no spec) and `lint.py:120` (no `__all__` assign found) are not exercised by any test. A corrupted `screw_agents/adaptive/__init__.py` or a transient import-system failure would cause `_load_adaptive_all()` to return empty, and every adaptive import would then fail `unknown_symbol`. Existing `test_lint_accepts_valid_script` acts as a downstream canary (it would fail if the helper returns empty unexpectedly), so this is low-risk. A dedicated test (monkeypatch `importlib.util.find_spec` to return None, verify `frozenset()`) would pin the failure-closed contract explicitly.
**Trigger:** Next lint-polish pass OR if a future change touches `_load_adaptive_all()`.
**Estimated scope:** ~10 LOC (1 test function with monkeypatch + cache_clear + assertion).

### BACKLOG-PR6-54 — Star-import UX via `unknown_symbol` rule is slightly misleading
**Source:** Phase 3b PR #6 T10 Opus reviews (spec Minor 2, quality edge-cases item 5), 2026-04-22
**File:** `src/screw_agents/adaptive/lint.py:226-242` — `unknown_symbol` rule
**Phase-4 readiness:** `nice-to-have` — PR #6 Opus re-review polish — cosmetic / test-coverage / ergonomics
**Why deferred:** `from screw_agents.adaptive import *` produces `alias.name == "*"`, which is not in `__all__`, so the rule emits `"'*' is not exported from screw_agents.adaptive. Valid names: ..."`. The rejection is correct (star imports are not a legitimate idiom in adaptive scripts), but the error message phrasing is minor-awkward — a user seeing it might expect a dedicated `disallowed_star` rule. Behavioral correctness is not affected.
**Trigger:** Next lint-message-UX pass OR if a user surfaces confusion about the `'*'` message.
**Estimated scope:** ~5 LOC (add a guard before the symbol loop: if `alias.name == "*"`, emit a dedicated `disallowed_star` rule instead).

### BACKLOG-PR6-55 — `@lru_cache(maxsize=1)` on `_load_adaptive_all` may surprise future monkeypatch tests
**Source:** Phase 3b PR #6 T10 Opus reviews (spec Minor 3, quality focus-2), 2026-04-22
**File:** `src/screw_agents/adaptive/lint.py:96` — `@lru_cache(maxsize=1)` decorator
**Phase-4 readiness:** `nice-to-have` — PR #6 Opus re-review polish — cosmetic / test-coverage / ergonomics
**Why deferred:** Cache-for-process means a future test that monkeypatches `screw_agents.adaptive.__all__` (or mocks `importlib.util.find_spec`) after `_load_adaptive_all()` has already been called will see stale data. No current test does this, so no live issue. Tests that need fresh state must call `_load_adaptive_all.cache_clear()` explicitly. Worth documenting in the helper's docstring.
**Trigger:** When a future test needs dynamic `__all__` manipulation, OR on next lint-helper docstring pass.
**Estimated scope:** ~2 LOC (add a comment in the helper docstring noting the cache-clear requirement for mutation tests).

### BACKLOG-PR6-56 — Module docstring doesn't list the new `unknown_symbol` rule
**Source:** Phase 3b PR #6 T10 Opus code-review (Minor 1), 2026-04-22
**File:** `src/screw_agents/adaptive/lint.py:7-38` — "Forbidden constructs" section of the module docstring
**Phase-4 readiness:** `retire` — cosmetic/docstring-wording polish — trigger unlikely to fire
**Why deferred:** The docstring enumerates forbidden constructs inline (e.g., `forbidden_name`, `forbidden_dunder_*`, etc.), but does NOT explicitly call out the new `unknown_symbol` rule. The existing parenthetical at `lint.py:10` "(with only allowlist-approved names)" became enforced rather than aspirational after T10. A future auditor has to read `_check_node` to discover the `unknown_symbol` rule. A one-line addition under "Forbidden constructs" (e.g. `- Importing any name from screw_agents.adaptive that is not in __all__ (rule=unknown_symbol)`) would close the gap.
**Trigger:** Next lint-docstring pass.
**Estimated scope:** 2 LOC (one bullet in the docstring).

### BACKLOG-PR6-57 — `_load_adaptive_all()` handles only `ast.Assign`, not `ast.AugAssign`
**Source:** Phase 3b PR #6 T10 Opus code-review (Minor 2), 2026-04-22
**File:** `src/screw_agents/adaptive/lint.py:112` — `_load_adaptive_all()` helper AST walk
**Phase-4 readiness:** `nice-to-have` — PR #6 Opus re-review polish — cosmetic / test-coverage / ergonomics
**Why deferred:** If a future maintainer appends to `__all__` via `__all__ += [...]` or `__all__.append(...)` instead of a single `__all__ = [...]` assignment, those names are silently ignored by the helper → every such appended import would fail `unknown_symbol` (failure-closed — safe, but surprising). Current `adaptive/__init__.py:65` uses a single assignment; this is a latent constraint, not a live bug. Fix options: (a) walk `ast.AugAssign` as well; (b) add a comment in `adaptive/__init__.py` warning future editors to keep `__all__` as a single assignment.
**Trigger:** Next lint-helper-polish pass OR if `adaptive/__init__.py` grows enough that multi-statement `__all__` assembly becomes tempting.
**Estimated scope:** ~5 LOC for option (a); 1 LOC for option (b).

### BACKLOG-PR6-58 — Asymmetric alias assertion in `test_execute_stderr_empty_on_success`
**Source:** Phase 3b PR #6 T11 Opus spec review (Minor 1), 2026-04-22
**File:** `tests/test_adaptive_executor.py` — `test_execute_stderr_empty_on_success`
**Phase-4 readiness:** `nice-to-have` — PR #6 Opus re-review polish — cosmetic / test-coverage / ergonomics
**Why deferred:** The failure-path test (`test_execute_surfaces_stderr_on_nonzero_return`) asserts `result["stderr"] == result["sandbox_result"]["stderr"]` — the alias-consistency check that protects against a future dual-decode bug. The success-path test asserts `result["stderr"] == ""` AND `result["sandbox_result"]["returncode"] == 0` but NOT the symmetric alias equality. Because both positions are emitted from the same `stderr_str` local (`engine.py:311, 316`), drift cannot occur without a code change; the gap is immaterial. The ripple-fix in `test_execute_adaptive_script_tool.py:80` already asserts `result["sandbox_result"]["stderr"] == ""` on success, so coverage exists — it's just not co-located with the dedicated success test.
**Trigger:** Next test-polish pass; negligible priority.
**Estimated scope:** 1 LOC (add `assert result["stderr"] == result["sandbox_result"]["stderr"]` alongside the existing `""` check).

### BACKLOG-PR6-59 — Inaccurate required-fields comment in `test_executor_wraps_validation_error_as_metadata_error`
**Source:** Phase 3b PR #6 T12 Opus spec + quality reviews (both flagged), 2026-04-22
**File:** `tests/test_adaptive_executor.py` — `test_executor_wraps_validation_error_as_metadata_error` (around line 838)
**Phase-4 readiness:** `nice-to-have` — PR #6 Opus re-review polish — cosmetic / test-coverage / ergonomics
**Why deferred:** Inline comment says required fields include `description` and `target_patterns`, but those have defaults in `AdaptiveScriptMeta` (`description: str = ""`, `target_patterns: list[str] = []` at `models.py:497-498`). Actual required-and-missing set is `created, created_by, domain, sha256`. Comment inaccuracy only — test behavior is unaffected (ValidationError fires on whichever required field is missing first). Test actually provides only `name: test-yaml-002`, so missing-required list is larger than comment suggests but the validation error is guaranteed either way.
**Trigger:** Next test-comment polish pass, OR if `AdaptiveScriptMeta` schema changes (e.g., `description` becomes required) and the comment's accidentally-right prediction breaks.
**Estimated scope:** 1 LOC (rewrite the comment to name only `created, created_by, domain, sha256`).

### BACKLOG-PR6-60 — Missing inline comment explaining `meta_raw or {}` fallback in `_load_meta`
**Source:** Phase 3b PR #6 T12 Opus code-review (Minor 2), 2026-04-22
**File:** `src/screw_agents/adaptive/executor.py:94` — `_load_meta` helper
**Phase-4 readiness:** `retire` — cosmetic/docstring-wording polish — trigger unlikely to fire
**Why deferred:** `AdaptiveScriptMeta(**(meta_raw or {}))` defensively handles the `None` return from `yaml.safe_load("")` (empty file or only-comments YAML). Without the `or {}` fallback, `AdaptiveScriptMeta(**None)` would raise `TypeError` instead of the expected `ValidationError` — bypassing the `MetadataError` wrapper and emitting a bare stack trace. A one-line comment would make the defensive intent explicit for future maintainers: `# empty / only-comments YAML → None → {} → ValidationError on required fields`.
**Trigger:** Next executor-docstring polish pass.
**Estimated scope:** 1 LOC (inline comment at the `or {}` site).

### BACKLOG-PR6-61 — Coverage parity: add non-UTF-8 tests for `find_imports` and `find_class_definitions`
**Source:** Phase 3b PR #6 T13 Opus code-review (Minor 1), 2026-04-22
**File:** `tests/test_adaptive_ast_walker.py`
**Phase-4 readiness:** `nice-to-have` — PR #6 Opus re-review polish — cosmetic / test-coverage / ergonomics
**Why deferred:** T13 narrowed `except Exception` to `except FileNotFoundError` in all 3 ast_walker helpers (`find_calls`, `find_imports`, `find_class_definitions`), but only `find_calls` has a dedicated non-UTF-8 regression test (`test_find_calls_raises_on_non_utf8_source`). A future regression that restores `except Exception` in `find_imports` or `find_class_definitions` would go undetected by the automated suite — though it'd be textually obvious in code review. The 3 sites share byte-for-byte identical try/except shape, so mechanical parity via 2 more tests (or parametrization over all 3 helpers) would close the gap cleanly.
**Trigger:** Next test-hardening pass on adaptive/. Low priority — the 3-way textual identity provides strong implicit coverage.
**Estimated scope:** ~20 LOC (2 sibling tests, or 1 parametrize wrapper).

### BACKLOG-PR6-62 — `execute_script` Raises docstring doesn't mention `UnicodeDecodeError` post-T13
**Source:** Phase 3b PR #6 T13 Opus code-review (Minor 2), 2026-04-22
**File:** `src/screw_agents/adaptive/executor.py:148-154` — `execute_script` docstring
**Phase-4 readiness:** `retire` — cosmetic/docstring-wording polish — trigger unlikely to fire
**Why deferred:** Post-T13, `_is_stale` (which `execute_script` calls at `:191`) propagates UnicodeDecodeError from `find_calls` when the target project contains a non-UTF-8 `.py` file. The `execute_script` Raises clause currently lists LintFailure / HashMismatch / SignatureFailure / MetadataError but NOT UnicodeDecodeError. This is a documentation gap: the behavior (surfacing the error) is intended per T13's "surface, don't swallow" philosophy; only the docstring is stale. A real-world concern would be a Python-2 codebase with `# -*- coding: latin-1 -*-` declarations — scanning that project would now hard-fail rather than silently skip. Speculative concern until reported; no change to behavior proposed here.
**Trigger:** Next executor-docstring polish pass, OR if a user reports unexpected UnicodeDecodeError from `execute_adaptive_script`.
**Estimated scope:** 1 LOC docstring line (`UnicodeDecodeError: project contains a file that fails UTF-8 decoding`). If behavior change is later wanted (graceful degradation via `errors="replace"` in `project.read_file`), that's a larger task — not in this entry's scope.

### BACKLOG-PR6-63 — Section banner style inconsistency in `test_adaptive_executor.py`
**Source:** Phase 3b PR #6 T14 Opus code-review (Minor 1), 2026-04-22
**File:** `tests/test_adaptive_executor.py:851` — T14 section banner
**Phase-4 readiness:** `retire` — cosmetic/docstring-wording polish — trigger unlikely to fire
**Why deferred:** T14 uses a single-line banner `# --- Task 14 — T11-N1 E2E signature-path regression ---` while Tasks 11 and 12 use a three-line boxed format:
```python
# -------------------------------------------------------------------------
# Task 11 — executor pipeline tests
# -------------------------------------------------------------------------
```
Purely visual drift, no correctness impact. Cosmetic polish.
**Trigger:** Next test-file polish pass.
**Estimated scope:** 3 LOC (expand the single-line banner to the 3-line boxed form).

### BACKLOG-PR6-64 — `test_execute_adaptive_script_rejects_tampered_signature` uses bare `pytest.raises(SignatureFailure)` rather than tight match
**Source:** Phase 3b PR #6 T14 Opus code-review (Minor 2), 2026-04-22
**File:** `tests/test_adaptive_executor.py:~1013` — T14 Layer 3 tamper test
**Phase-4 readiness:** `nice-to-have` — PR #6 Opus re-review polish — cosmetic / test-coverage / ergonomics
**Why deferred:** T14's Layer 3 tamper test uses `pytest.raises(SignatureFailure)` bare, while the pre-existing Layer 3 test at `test_adaptive_executor.py:665` uses `pytest.raises(SignatureFailure, match="signature invalid or content mismatch")` — a tight match string pinning the specific failure reason. Bare form would false-pass if the signature path ever started raising a different `SignatureFailure` reason (e.g., missing-public-key, wrong-version). The pre-existing line-628 test already locks the tight match, so T14's bare form doesn't regress overall coverage; it just doesn't tighten further. Defense-in-depth opportunity.
**Trigger:** Next test-precision polish, OR if a signature-path regression surfaces a different failure mode that slips past the bare `pytest.raises`.
**Estimated scope:** 1 LOC (add `match="signature invalid or content mismatch"` or the current engine-wrapped equivalent to the `pytest.raises` call).

### BACKLOG-PR6-67 — Stale `sign_adaptive_script` reference in test-file comment
**Source:** Phase 3b PR #6 T17 Opus spec review (Minor 2), 2026-04-22
**File:** `tests/test_adaptive_subagent_prompts.py:306`
**Phase-4 readiness:** `retire` — cosmetic/docstring-wording polish — trigger unlikely to fire
**Why deferred:** A regex-documentation test comment still says "matches `sign_adaptive_script` validation". Factually accurate (the regex lives in `adaptive/signing.py` which `sign_adaptive_script` calls), but post-T17 the direct-call tool is absent from all 5 LLM-flow subagent frontmatters. A future reviewer might reasonably rewrite the comment as "matches `adaptive/signing.py` validation" for clarity, since the test now operates on the server-internal validation not the tool name. Pure cosmetic; no behavior impact.
**Trigger:** Next test-docs polish pass.
**Estimated scope:** 1 LOC comment rewrite.

### BACKLOG-PR6-68 — Orchestrator body names only 4/7 adaptive tools (prose clarity)
**Source:** Phase 3b PR #6 T17 Opus code-review (Minor 2), 2026-04-22
**File:** `plugins/screw/agents/screw-injection.md` — Step 2.5 prose (around lines 165-171)
**Phase-4 readiness:** `nice-to-have` — PR #6 Opus re-review polish — cosmetic / test-coverage / ergonomics
**Why deferred:** The orchestrator's frontmatter carries 7 adaptive tools (record_context_required_match, detect_coverage_gaps, lint, stage, promote, reject, execute) but the body only names 4 by tool name (record_context_required_match, detect_coverage_gaps, stage_adaptive_script, accumulate_findings) — those with orchestrator-specific meta (domain field, session ID reuse). promote/reject/execute/lint are covered via delegation to per-agent Step 3.5d. Reviewer's suggestion: a one-line pointer like "per-agent Step 3.5d names the full tool sequence used in-flow" would preempt reader confusion about why only 4/7 are named. Not a defect (delegation is the design); style suggestion.
**Trigger:** Next orchestrator-prose polish pass.
**Estimated scope:** ~2 LOC (one sentence added near line 167).

### BACKLOG-PR6-66 — Orchestrator body-vs-frontmatter symmetry guard (forward-looking)
**Source:** Phase 3b PR #6 T17 Opus code-review (Minor 1), 2026-04-22
**File:** `plugins/screw/agents/screw-injection.md` + `tests/test_adaptive_subagent_prompts.py`
**Phase-4 readiness:** `nice-to-have` — PR #6 Opus re-review polish — cosmetic / test-coverage / ergonomics
**Why deferred:** T17 lifted the `sign_adaptive_script NOT in tools` negative guard to cover the orchestrator, but `test_adaptive_section_references_all_required_mcp_tools` intentionally does NOT apply the positive tool-presence assertion to the orchestrator body (rationale documented inline: orchestrator Step 2.5 delegates to per-agent Step 3.5d rather than naming every tool verbatim). Currently the orchestrator body names 4/7 adaptive tools (the ones with orchestrator-specific meta: `stage_adaptive_script.meta`, `record_context_required_match`, `detect_coverage_gaps`, `accumulate_findings`). Latent risk: if a future edit removes a tool from the orchestrator's frontmatter but keeps body prose referencing it (pointing readers at a tool the orchestrator can't call), no current test catches that drift. Inherent to the delegation pattern — not actionable for this PR.
**Trigger:** If the orchestrator body grows more detailed OR if body-frontmatter drift becomes a recurring regression type.
**Estimated scope:** ~20 LOC (targeted test that greps orchestrator body for `mcp__screw-agents__<tool>` mentions and cross-checks each appears in frontmatter; invert the per-agent symmetry direction).

### BACKLOG-PR6-65 — Subagent session-id lookup relies on LLM-driven JSONL parsing
**Source:** Phase 3b PR #6 T15+T16 Opus spec review (Minor 1), 2026-04-22
**File:** `plugins/screw/agents/screw-{sqli,cmdi,ssti,xss}.md` — Step 3.5d-I (resume-from-approval branch, around line 449 in each)
**Phase-4 readiness:** `nice-to-have` — PR #6 Opus re-review polish — cosmetic / test-coverage / ergonomics
**Why deferred:** The promote path requires the subagent to look up `session_id` by reading `.screw/local/pending-approvals.jsonl` with the `Read` tool and picking the MOST-RECENT entry where `script_name == {script_name}` AND `event == "staged"`. This implicitly trusts the LLM to correctly implement "walk JSONL lines, filter by predicate, take last match" — not pick line 1, not pick an earlier `staged` event when there's been a re-stage, etc. The `promote_staged_script` server tool has diagnostic fallbacks: `fallback_required` / `staging_not_found` return `recovered_prefix` so the subagent can re-prompt the user, and `fallback_sha_mismatch` rejects a mismatched prefix. So the LLM lookup is guard-railed at the server, but a server-side `lookup_session_id(script_name)` tool would remove the trust-the-LLM link entirely. Hardening opportunity, not a live bug.
**Trigger:** Next adaptive-flow hardening pass, OR if user reports a "wrong session_id" promote failure that traces to subagent mis-parsing.
**Estimated scope:** ~30 LOC (new engine helper `engine.lookup_most_recent_staged_session(project_root, script_name)` + MCP tool registration + test + prose update in the 4 subagent markdown files replacing the `Read` instruction with the new tool call).

### BACKLOG-PR6-69 — Slash-command argument-description style drift across `plugins/screw/commands/`
**Source:** Phase 3b PR #6 T19 Opus code-review (Minor, Category A), 2026-04-23
**File:** `plugins/screw/commands/adaptive-cleanup.md` (Stale-sweep action's Arguments subsection) + `plugins/screw/commands/scan.md` (Arguments section)
**Phase-4 readiness:** `nice-to-have` — PR #6 Opus re-review polish — cosmetic / test-coverage / ergonomics
**Why deferred:** `scan.md` documents CLI args with a **bold-name** convention: `**--thoroughness** (optional, default \`standard\`): \`standard\` or \`deep\` ...`. T19's new `adaptive-cleanup.md` uses inline-code names instead: `- \`--max-age-days N\` (optional): override the threshold in days.`. `learn-report.md` takes a more narrative form again (no formal Arguments section at all). The three styles coexist today so T19 did NOT violate any committed precedent — but when the plugin grows more slash commands, reviewers will keep choosing whichever style matches the nearest commit. A single house-style pass (probably standardizing on `scan.md`'s **bold-name** + default-value-in-backticks form) would preempt the bikeshed. Style-only; no behavior or correctness impact.
**Trigger:** Next slash-command docs polish pass, OR when a 4th slash command is added and the drift becomes visible.
**Estimated scope:** ~6 LOC (rewrite the two CLI args in adaptive-cleanup.md's `stale` action to match scan.md's bold-name convention). If learn-report.md is also normalized, add ~10 LOC there.

### BACKLOG-PR6-70 — `<if dry_run:>` pseudo-template syntax in `stale` render block may be mis-copied as literal output
**Source:** Phase 3b PR #6 T19 Opus code-review (Minor, Category A), 2026-04-23
**File:** `plugins/screw/commands/adaptive-cleanup.md` — the "Render as" fenced block inside the Stale-sweep action (around lines 164-176)
**Phase-4 readiness:** `nice-to-have` — PR #6 Opus re-review polish — cosmetic / test-coverage / ergonomics
**Why deferred:** The render template uses `<if dry_run:>` (angle-bracket pseudo-template) and `<session_id>/<script_name>` (angle-bracket placeholders) inside the same fenced block. Context makes it clear these are template conditionals/placeholders, not literal output — the quality reviewer explicitly noted "Not ambiguous enough to be Important (context makes it clear)". But an operator quickly skimming the block could plausibly copy the `<if dry_run:>` line verbatim into a bug report, muddying the trace. A less-ambiguous convention (e.g., `# if dry_run:` comment-style prefix, or moving the conditional outside the fenced block) would eliminate the ambiguity at ~2 LOC cost. Pure cosmetic; no operational defect.
**Trigger:** Next slash-command rendering-template polish pass.
**Estimated scope:** ~2 LOC (either change `<if dry_run:>` to `# if dry_run:` inside the block, or lift the dry-run conditional above/below the block as prose).

### BACKLOG-PR6-71 — Parametrize test IDs include Path repr (verbose in CI logs)
**Source:** Phase 3b PR #6 T20 Opus code-review (Minor 1, Category A), 2026-04-23
**File:** `tests/test_adaptive_subagent_prompts.py` — 12 `@pytest.mark.parametrize("agent,path", sorted(_PER_AGENT_FILES.items()))` decorator sites (lines ~408, 414, 420, 426, 436, 442, 452, 460, 471, 489, 497, 506 — one per new test added in T20)
**Phase-4 readiness:** `nice-to-have` — PR #6 Opus re-review polish — cosmetic / test-coverage / ergonomics
**Why deferred:** Parametrizing over `dict.items()` yields test IDs that include the Path stringification — e.g. `[cmdi-<absolute-path>]` instead of `[cmdi]`. The second parameter is fully determined by the first (`_PER_AGENT_FILES["cmdi"]` is unique), so the Path contributes zero signal to the test ID but makes CI output noisier. Cleaner forms: (a) parametrize over `sorted(_PER_AGENT_FILES)` (keys only) and look up the path inside with `_PER_AGENT_FILES[agent]`, or (b) add `ids=lambda v: v if isinstance(v, str) else None` to the decorator to drop Path values from IDs. `pytest -k 'cmdi'` filtering works correctly today so this is log-verbosity polish only.
**Trigger:** Next test-polish pass, OR when CI log readability becomes a friction point.
**Estimated scope:** ~12 LOC (rewrite 12 decorators to the keys-only form and add `path = _PER_AGENT_FILES[agent]` as the first line of each function body).

### BACKLOG-PR6-72 — `adaptive.__all__` "18 entries" docstring claim can drift silently
**Source:** Phase 3b PR #6 T20 Opus code-review (Minor 2, Category A), 2026-04-23
**File:** `tests/test_adaptive_subagent_prompts.py::test_adaptive_prompt_lists_all_adaptive_exports` (docstring, around line 477-486)
**Phase-4 readiness:** `retire` — cosmetic/docstring-wording polish — trigger unlikely to fire
**Why deferred:** The test's docstring says "At PR #6 HEAD `adaptive.__all__` has 18 entries; this test auto-tracks any additions so the prompt stays in sync with the public surface." The test body iterates `__all__` dynamically so it remains correct as the export set grows — but the docstring's hardcoded "18" would drift silently. Two hardening options: (a) remove the count from the docstring (simpler, no belt-and-suspenders), or (b) add `assert len(adaptive_pkg.__all__) == 18` inside the test as a canary — a new export would fail the canary, forcing the maintainer to (1) update the agent prompt to include the new name, (2) update the test's expected count. Option (b) turns a silent docstring drift into a loud test failure. Marco's call on whether the belt-and-suspenders check is worth the minor maintenance friction.
**Trigger:** Next test-docs polish pass, OR if a new `adaptive/` public function is added (which would drift the docstring silently and the review should catch the opportunity then).
**Estimated scope:** 1-2 LOC (option (a) removes the count; option (b) adds a 1-line length assertion).

### BACKLOG-PR6-73 — `accumulated_count == 1` diagnostic check dropped at T21 Step 4
**Source:** Phase 3b PR #6 T21 Opus code-review (Minor A1, Category A), 2026-04-23
**File:** `tests/test_adaptive_workflow_staged.py::test_full_adaptive_workflow_with_staging_composition` — Step 4 accumulate_findings call (around line 97)
**Phase-4 readiness:** `nice-to-have` — PR #6 Opus re-review polish — cosmetic / test-coverage / ergonomics
**Why deferred:** T22's E2E test at `tests/test_adaptive_workflow.py:198` asserts `acc_response["accumulated_count"] == 1` in addition to the session_id echo. T21 only asserts the session_id threading. `accumulated_count` catches a regression where `accumulate_findings` silently no-ops the append even though it returns a valid session id — a subtle diagnostic angle T22 carries but T21 skipped (because the plan skeleton itself omitted the count). Low cost (~1 LOC), distinct angle on accumulator behavior.
**Trigger:** Next T21 diagnostic-tightening pass, OR if a silent-accumulator regression surfaces in another task.
**Estimated scope:** 1 LOC (`assert acc_response["accumulated_count"] == 1` after the existing session_id assert at line 97).

### BACKLOG-PR6-74 — `acc2["accumulated_count"] >= 2` diagnostic check dropped at T21 Step 15
**Source:** Phase 3b PR #6 T21 Opus code-review (Minor A2, Category A), 2026-04-23
**File:** `tests/test_adaptive_workflow_staged.py::test_full_adaptive_workflow_with_staging_composition` — Step 15 accumulate second call (around line 234)
**Phase-4 readiness:** `nice-to-have` — PR #6 Opus re-review polish — cosmetic / test-coverage / ergonomics
**Why deferred:** T22's Step 10 at `tests/test_adaptive_workflow.py:369` asserts `acc2["accumulated_count"] >= 2`, proving BOTH the YAML finding AND the adaptive-script finding landed in the session buffer pre-finalize. T21's Step 15 only asserts session_id threading. If the executor regresses to zero findings but Step 14's `>= 1` bound slips past, Step 16's `summary.total == 1` still passes (1 = YAML alone) — the merge-collapsed-2→1 evidence chain is lost. T22's Review I4 inline comment calls this out.
**Trigger:** Next T21 diagnostic-tightening pass, OR if a silent-merge regression surfaces.
**Estimated scope:** 1 LOC (`assert acc2["accumulated_count"] >= 2`).

### BACKLOG-PR6-75 — `match_response["matches_recorded"] == 1` diagnostic check dropped at T21 Step 3
**Source:** Phase 3b PR #6 T21 Opus code-review (Minor A3, Category A), 2026-04-23
**File:** `tests/test_adaptive_workflow_staged.py::test_full_adaptive_workflow_with_staging_composition` — Step 3 record_context_required_match call (around line 85)
**Phase-4 readiness:** `nice-to-have` — PR #6 Opus re-review polish — cosmetic / test-coverage / ergonomics
**Why deferred:** T22 at `tests/test_adaptive_workflow.py:155` asserts `match_response["matches_recorded"] == 1` — confirms the idempotent-dedup key actually recorded the match rather than returning a valid session id with zero effect. T21 only captures `session_id` from the response. Deferring hides a potential silent no-op regression in `record_context_required_match`. Low cost, high diagnostic value.
**Trigger:** Next T21 diagnostic-tightening pass, OR if `record_context_required_match` surfaces a no-op bug.
**Estimated scope:** 1 LOC (`assert match_response["matches_recorded"] == 1` after the existing `session_id = match_response["session_id"]` extraction).

### BACKLOG-PR6-76 — `l` loop variable (E741) in registry list comprehensions at T21 Steps 10 + 13
**Source:** Phase 3b PR #6 T21 Opus code-review (Minor A4, Category A), 2026-04-23
**File:** `tests/test_adaptive_workflow_staged.py::test_full_adaptive_workflow_with_staging_composition` — list comprehensions at approximately lines 176 and 211
**Phase-4 readiness:** `nice-to-have` — PR #6 Opus re-review polish — cosmetic / test-coverage / ergonomics
**Why deferred:** Both Step 10 and Step 13 use `[json.loads(l) for l in registry.read_text().splitlines() if l.strip()]`. PEP 8 / flake8 E741 flags `l` as ambiguous (visually indistinguishable from `1` or uppercase `I`). T22 does not have this pattern (T22 does not touch the registry directly). Trivial fix: rename to `line` or `raw`. Pure style; no behavior impact.
**Trigger:** Next test-style polish pass, OR if ruff/flake8 is added to CI with E741 enabled.
**Estimated scope:** 2-4 LOC (rename `l` → `line` at 2 list-comprehension sites).

### BACKLOG-PR6-77 — Step 17 `trust_status["script_quarantine_count"] == 0` bare assert lacks failure message
**Source:** Phase 3b PR #6 T21 Opus code-review (Minor A5, Category A), 2026-04-23
**File:** `tests/test_adaptive_workflow_staged.py::test_full_adaptive_workflow_with_staging_composition` — Step 17 verify_trust assertion (around line 244)
**Phase-4 readiness:** `nice-to-have` — PR #6 Opus re-review polish — cosmetic / test-coverage / ergonomics
**Why deferred:** If this assert fails with `script_quarantine_count == 1`, the bare form tells the reader nothing about why. T22's Step 12 at `tests/test_adaptive_workflow.py:466` has a multi-line failure message explaining the T20 signing-round-trip regression pathway (verify_script sees a quarantined script → sign-side canonical bytes drifted from verify-side → check PR #6 T2 consolidation points). T21 exercises the same T20 surface through a different approach path (promote rather than direct sign), so the same diagnostic guidance is relevant. Pure diagnostic polish; catches nothing new but makes breakage-pinpointing faster.
**Trigger:** Next T21 diagnostic-tightening pass, OR if a trust-count regression surfaces and the bare assert impedes root-cause analysis.
**Estimated scope:** 4-6 LOC (add a multi-line failure message to the existing assert; copy-adapt from T22:466-472).

### BACKLOG-PR6-78 — Diagnostic-message convention drift between adjacent tool-schema tests
**Source:** Phase 3b PR #6 T22 Opus code-review (Minor, Category A), 2026-04-23
**File:** `tests/test_engine.py` — `test_tool_definitions_json_schema_valid` (lines 100-107, bare asserts) vs `test_tool_definitions_pr6_new_tools_reject_additional_properties` (lines 110-144, asserts with diagnostic messages)
**Phase-4 readiness:** `nice-to-have` — PR #6 Opus re-review polish — cosmetic / test-coverage / ergonomics
**Why deferred:** The new T22 test carries assertion messages naming the specific tool and invariant that regressed (e.g., `"Tool {tool['name']!r} input_schema missing additionalProperties: false (T10-M1 partial regressed)"`). The adjacent baseline test uses bare asserts (no message) for `schema["type"] == "object"` / `"properties" in schema` / `target` presence. Broader file convention is majority-bare (3 of 13 asserts carry messages). The divergence IS principled — the baseline test is broad-coverage "something's off" surfacing, while the new test locks a tighter invariant and benefits from diagnostic messages for CI failure readability. But style consistency across adjacent tool-schema tests matters for future maintainers. Option (a): retrofit the baseline test with diagnostic messages (closes the gap). Option (b): document the divergence with an inline comment (lower cost, accepts the difference).
**Trigger:** Next test-diagnostic polish pass, OR if a baseline schema assertion fails in CI and the bare form makes root-cause analysis harder.
**Estimated scope:** Option (a) ~3 LOC (add messages to 3 asserts in `test_tool_definitions_json_schema_valid`); Option (b) ~2 LOC (inline comment explaining the intentional divergence).

---

## Phase 3b-C2 T2-review minors + observational items (discovered 2026-04-24)

Non-blocking minors and observational items surfaced during T2 (scan.md rewrite) spec + quality review rounds on commit `e7a33d2`. All are safe to defer past C2 merge; each has a natural resolution point. Partial resolution shipped in the T2 fix-up (Bucket A); this section tracks what was consciously deferred (Bucket C).

### BACKLOG-C2-M-QR-T2-M1 — Wide-line D1/D2 gap-vocabulary definition at scan.md:149
**Phase-readiness:** `non-blocker` — readability polish; no semantic impact
**Source:** T2 review-triage round (spec + quality reviews on commit `e7a33d2`), 2026-04-24

**Why deferred:** The single prose line defining D1 / D2 gap types in Step 3 is approximately 700 characters wide, mixing gap.type values, gap.evidence keys, and parenthetical field lists. In rendered terminal views with narrow wrap settings, the line becomes visually dense and hard to scan. A 2-bullet rewrite (D1 on one bullet, D2 on another, each with its evidence-field list) would improve readability without changing meaning. The current inline form is defensible because the two definitions sit beside each other, but the density is worth tracking.

**Remediation sketch:** Next scan.md readability pass: rewrite the "Gap-type vocabulary" sentence at line ~149 as two bullets: `- **D1** (`gap.type == "context_required"`): ...` / `- **D2** (`gap.type == "unresolved_sink"`): ...`. ~3 LOC net change. No test impact (phrases already locked by `test_scan_md_phrase_grammar_locked`).

### BACKLOG-C2-M-QR-T2-M2 — Pipe-separator render on narrow terminals (scan.md:262)
**Phase-readiness:** `non-blocker` — readability polish; no semantic impact
**Source:** T2 review-triage round (spec + quality reviews on commit `e7a33d2`), 2026-04-24

**Why deferred:** The review-template header line `**Staged:** {staged_at}  |  **Session:** `{session_id_short}`  |  **SHA256:** `{script_sha256_prefix}`` uses two pipe separators (with surrounding spaces) on a single line. On narrow terminal widths the line wraps unpredictably, and the pipe-as-separator convention is uncommon enough in markdown reviews that a bullet form (3 short bullets) would be clearer. The current form is deliberate to keep the header compact when it fits, so this is readability-only.

**Remediation sketch:** Next readability pass: consider converting the header triple to three bullets (`- **Staged:** ...` / `- **Session:** ...` / `- **SHA256:** ...`). No behavioral change. Verify no locked-phrase test asserts the pipe-separator form before rewriting.

### BACKLOG-C2-M-QR-T2-M3 — Stage-meta dict literal mixes angle-bracket pseudocode with `.get()` f-string
**Phase-readiness:** `non-blocker` — readability polish; no semantic impact
**Source:** T2 review-triage round (spec + quality reviews on commit `e7a33d2`), 2026-04-24

**Why deferred:** The `stage_adaptive_script` call at scan.md:203-204 uses `f"Evidence: {pending_review.gap.evidence.get('method') or pending_review.gap.evidence.get('pattern') or 'see gap.evidence'}."` — an executable-looking Python f-string with chained `.get()` fallbacks — inside a block otherwise written in angle-bracket pseudocode (`<absolute project root>`, `<derived from pending_review.gap.agent>`, etc.). The style mix is jarring for a reader who expects either pure pseudocode OR pure Python. No correctness issue — the intent is clear either way.

**Remediation sketch:** Next readability pass: either (a) convert the f-string to pseudocode (`<gap.evidence.method if D2 else gap.evidence.pattern, else "see gap.evidence">`) for consistency with surrounding lines, or (b) convert the surrounding angle-bracket pseudocode to Python f-strings. Option (a) is lower-risk. ~2 LOC.

### BACKLOG-C2-M-QR-T2-M4 — Step 5 item 6 quoted-string offers vs imperative style
**Phase-readiness:** `non-blocker` — stylistic inconsistency; cosmetic
**Source:** T2 review-triage round (spec + quality reviews on commit `e7a33d2`), 2026-04-24

**Why deferred:** Step 5 item 6 offers: `"Apply a fix?", "Mark a finding as false positive?", "Run another agent?"` — three quoted question strings. Elsewhere scan.md uses imperative phrasing for user-facing prompts (e.g., "Type `approve {script_name}` to promote...", "END turn; await user's re-attempt"). The quoted-question form is a minor style outlier; replacing with imperative directives ("Offer to apply a fix, mark a false positive, or run another agent.") would match house style. Cosmetic only.

**Remediation sketch:** Next readability pass: rewrite item 6 as one imperative sentence. No test impact.

### BACKLOG-C2-M-QR-T2-M5 — Ambiguous-response counter has no upper bound on LLM turn-count memory
**Phase-readiness:** `non-blocker` — observational; precedent-consistent behavior
**Source:** T2 review-triage round (spec + quality reviews on commit `e7a33d2`), 2026-04-24

**Why deferred:** Step 3e's "ambiguous response" branch says: *"ask ONCE... On a second ambiguous response: treat as REJECT."* This assumes the main-session LLM reliably tracks a 1-turn counter across messages. If the LLM loses count across long conversations (e.g., context compression mid-flow), it could re-ask ambiguity prompts indefinitely. The precedent at `plugins/screw/agents/screw-sqli.md:432-438` has the same "ask once → reject on second" property and has shipped in PR #6 without observed issue, so the pattern is acceptable as-is. Worth tracking because a future T10 round-trip could expose the drift in a long-running adaptive session.

**Remediation sketch:** No immediate action. If T10 round-trip or future production traffic shows ambiguity-loop drift: either (a) encode the counter in the prompt more explicitly (e.g., "your previous message also asked for clarification — treat any remaining ambiguity as REJECT"), or (b) move the ambiguity state to MCP-server-side (session-scoped counter). Option (b) is more invasive; option (a) is prompt-only.

### BACKLOG-C2-M-SR-T2-M1 — scan.md:244 mentions `validate-script` not in spec §4.7 banner template
**Phase-readiness:** `non-blocker` — additive; consistency-tracking
**Source:** T2 review-triage round (spec + quality reviews on commit `e7a33d2`), 2026-04-24

**Why deferred:** The Step 3c.5 loud banner in scan.md:244 includes `Resolve scripts with \`screw-agents validate-script <name>\`.` Spec §4.7 banner template (line 419) only mentions `validate-exclusion` / `migrate-exclusions` — it does not list `validate-script`. The implementer-authored addition is reasonable (scripts CAN be quarantined too, and the banner's script_quarantine_count field motivates the CLI hint), but it extends beyond what the spec literally prescribes. Semantic fidelity is intact (the banner is about trust state, and script-validate IS the trust-resolve tool for scripts). Consistency tracking for a future spec refresh.

**Remediation sketch:** Next spec-refresh pass: either (a) update spec §4.7 banner template (line 419) to include `validate-script` (align spec to implementation), or (b) drop the `validate-script` line from scan.md:244 (align implementation to spec). Option (a) is preferred since the CLI hint is genuinely useful when scripts ARE quarantined. ~1 LOC either way.

### BACKLOG-C2-M-SR-T2-M3 — "--adaptive flag IS the user consent" wording is implementer-authored
**Phase-readiness:** `non-blocker` — cosmetic; semantic fidelity intact
**Source:** T2 review-triage round (spec + quality reviews on commit `e7a33d2`), 2026-04-24

**Why deferred:** scan.md:39-41 declares `The --adaptive flag IS the user consent.` This literal sentence does not appear in the plan or spec — it is an implementer-authored gloss added during the T2 rewrite to reinforce spec §4.3 D3 (consent-bundled-in-flag model). The wording is accurate and supports the right mental model, but future readers tracing the plan→implementation chain may spend time looking for the exact phrase. Low cost to track; decide later whether to (a) promote the wording into the plan / spec verbatim, or (b) replace with a phrasing that more closely mirrors spec §4.3 D3's language.

**Remediation sketch:** Next plan/spec coherence pass: either (a) add the "--adaptive flag IS the user consent" sentence verbatim to PHASE_3B_C2_PLAN.md's user-consent discussion so scan.md is a literal echo, or (b) soften scan.md's wording to mirror spec §4.3 D3 more directly. Cosmetic only.

### BACKLOG-C2-W3 — Structural `{if}`/`{endif}` count-balance assertion missing
**Phase-readiness:** `non-blocker` — test-coverage gap; caught by T10 round-trip only today
**Source:** T2 review-triage round (spec + quality reviews on commit `e7a33d2`), 2026-04-24

**Why deferred:** scan.md uses `{if <predicate>:}` / `{endif}` pseudo-directive pairs in the 5-section review template to indicate conditional rendering. A future edit that drops one `{endif}` (or adds an unmatched `{if}`) would silently degrade the rendered review without any existing test catching it — `test_scan_md_phrase_grammar_locked` asserts phrase presence, not structural balance. The balance IS verified end-to-end in the T10 live round-trip, but that is a manual gate. An automated assertion would be cheap and catch the class of drift.

**Remediation sketch:** Add a new test in `tests/test_adaptive_subagent_prompts.py` that greps scan.md body for `{if ` occurrences (prefix with space to avoid matching `{if:}` or inline references) and `{endif}` occurrences and asserts `count(if) == count(endif)`. ~6 LOC. Place it adjacent to `test_scan_md_phrase_grammar_locked`. Post-C2 T2 commit `e7a33d2` baseline is 3 `{if}` / 3 `{endif}` after the Bucket A fix-up (was 3 / 2 before — the bare comma-style directive had no `{endif}` partner), so the test would have caught the pre-fix-up asymmetry.

### BACKLOG-C2-W4 — Step 1b fenced-block wrapper adds no value over plain prose
**Phase-readiness:** `non-blocker` — observational; cosmetic
**Source:** T2 review-triage round (spec + quality reviews on commit `e7a33d2`), 2026-04-24

**Why deferred:** scan.md:83-114 (Step 1b: Full-scope fan-out) wraps mixed prose + pseudocode in a single fenced block using triple-backtick without language tag. The fence does not add syntactic value — the content mixes prose explanations, markdown tables, and Python-like pseudocode — and arguably makes the block less approachable (prose inside a code fence renders as monospace without word-wrap). Removing the outer fence and letting the prose flow naturally (with the inner Task() pseudocode remaining in its own inner fence) would improve readability. No behavioral impact.

**Remediation sketch:** Next readability pass: unwrap Step 1b's outer fence. Keep the inner `Task(...)` block fenced (if such an inner fence exists) but move the surrounding prose to flat paragraphs. Verify no locked-phrase test asserts the outer-fence form. ~4-6 LOC net (delete two fence lines, reflow interior).

---

## Phase 3b-C2 T3-review minors (discovered 2026-04-24)

Non-blocking minors surfaced during T3 (screw-full-review.md deletion + SKILL.md routing) spec + quality review rounds on commit `474647e`. The T3 fix-up (commit `4b92add`) resolved the actionable ones; this section tracks the remainder for audit trail.

### BACKLOG-C2-M-QR-T3-M2 — SKILL.md broad-row cell is cognitively wider than other rows

**Phase-readiness:** `non-blocker`
**Source:** T3 quality review on commit `474647e` (Marco-approved deferral 2026-04-24)

**Why deferred:** Post-I1 fix-up (commit `4b92add`), the broad row now reads "See §3 redirect" (matches cell-width of the other 5 dispatch rows). The original QR-T3-M2 concern (broad row ~4× wider than other rows, breaks table-scan pattern) is resolved BY the I1 fix-up — the long prose moved to §3. Filing this entry for audit trail completeness only; no remaining action.

**Remediation sketch:** Closed by I1 fix-up. No further work needed.

---

## Phase 3b-C2 T4 pre-audit minors (discovered 2026-04-24)

Non-blocking minors surfaced during T4 (per-agent screw-sqli.md truncation) pre-audit on commit `cc52906`. Both items are observational and fold into a future scan.md polish PR.

### BACKLOG-C2-M-PA-T4-M1 — pending_review entries lack explicit session_id; implicit top-level enrichment

**Phase-readiness:** `non-blocker`
**Source:** T4 pre-audit (Marco-approved deferral 2026-04-24)

**Why deferred:** T4 pre-audit found that the prescribed pending_review schema at plan line 1203-1222 omits per-entry `session_id`, but scan.md's Step 3 references `pending_review.session_id` in 4 places (scan.md line 205/360/384/413). Spec §5.1 confirms session_id is top-level only, not per-entry. The implication: scan.md's parser must implicitly enrich each pending_review with the top-level session_id at parse time. Works, but the implicit-enrichment step isn't documented in scan.md Step 2.

**Remediation sketch:** Two options for a future polish PR — (a) T4/T5/T6/T7 re-land with explicit per-entry session_id duplication at emit time (simpler scan.md), OR (b) scan.md Step 2 adds an explicit "enrich each pending_review.session_id from top-level session_id" instruction. Option (b) is cheaper; fold into a scan.md-polish PR alongside the other T2 deferred minors.

### BACKLOG-C2-M-PA-T4-M2 — scan-subagent Step 5 return JSON emits keys scan.md doesn't consume

**Phase-readiness:** `non-blocker`
**Source:** T4 pre-audit (Marco-approved deferral 2026-04-24)

**Why deferred:** Plan's prescribed new Step 5 return JSON (plan lines 1269-1284) includes `adaptive_quota_note` and `blocklist_skipped_gaps` keys. Grep on scan.md (post-T2) shows zero consumer references for either. The keys are informational, carried for possible future main-session surfacing (e.g., summary of quota exhaustion events or blocklist skips), but currently dead payload.

**Remediation sketch:** Either (a) wire into scan.md Step 5 summary (one extra section for each) to surface to the user, OR (b) drop the keys from per-agent Step 5 JSON and remove the corresponding spec §5.1 entries. Option (a) preserves information flow and matches the spec's intent; do it alongside the scan.md polish PR referenced by PA-T4-M1.
