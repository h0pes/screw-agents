# Phase 3a — X1-M1 Core-Prompt Deduplication: Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.
>
> **Per-task workflow (from `feedback_phase3a_workflow_discipline.md`):** 7-step cycle — pre-audit → implementer → spec review → quality review → triage → fix-up → cross-plan sync. Non-negotiable. Every code-producing task runs the full cycle.
>
> **Historical note (2026-04-17):** The original plan (committed as `b486850` on main) covered T1-T11 under Option A′. Three extension rounds followed, each driven by round-trip testing surfacing a failure mode in the prior iteration. The final shipped architecture is NOT Option A′ — see **Iteration history** below for the full story, and **Final architecture summary** for the shape that actually shipped.

**Goal:** Ship X1-M1 core-prompt deduplication for `scan_domain` and `scan_full`, unblocking Phase 3b Task 3b-19 and eliminating the round-trip-observed per-page token overflow in domain orchestration.

**Final architecture (shipped):** `assemble_scan` gains `include_prompt: bool = True` kwarg; `assemble_domain_scan` splits into init page (per-agent metadata, no prompts, no code) and code pages (per-agent code, no prompts); `assemble_full_scan` returns a dict with per-agent `{agent_name, code, meta, exclusions?}` (no `prompts` dict). Orchestrator subagents fetch prompts lazily via a new `get_agent_prompt` MCP tool on first encounter per agent. The legacy `write_scan_results` is removed and replaced by `accumulate_findings` (incremental staging in `.screw/staging/{session_id}/findings.json`) + `finalize_scan_results` (idempotent one-shot render+write). See **Final architecture summary** at the end of this document for the full shape.

**Tech Stack:** Python 3.11+, Pydantic models (unchanged), tree-sitter (unchanged), pytest, Claude Code subagent Markdown.

**Spec:** `docs/specs/2026-04-17-prompt-dedup-x1-m1-design.md` (local, not in git)

**Upstream phase plan:** Phase 3a complete (PRs #6, #7, #8 merged). This is a focused carryover PR #9 between Phase 3a and Phase 3b.

**Downstream phase plan:** `docs/PHASE_3B_PLAN.md` — Tasks 9 and 20 of this plan sync upstream-deps table rows 69 (assemble_domain_scan), 74 (X1-M1 marker), and add the Option D `accumulate_findings` / `finalize_scan_results` entries.

**Branch:** `phase-3a-prompt-dedup` (per `project_execution_mode.md`: subagent-driven + dedicated worktree).

**Key references for implementers:**
- `docs/specs/2026-04-17-prompt-dedup-x1-m1-design.md` — design rationale + invariants (local-only spec evolved through rounds 1-3)
- `src/screw_agents/engine.py` — `assemble_scan`, `assemble_domain_scan`, `assemble_full_scan`, `get_agent_prompt`, `accumulate_findings`, `finalize_scan_results`
- `src/screw_agents/staging.py` — session-scoped staging directory management (introduced by T17)
- `tests/test_engine.py`, `tests/test_pagination.py`, `tests/test_prompt_dedup_roundtrip.py`, `tests/test_accumulate_finalize.py` — relevant test modules
- `plugins/screw/agents/screw-injection.md` — domain orchestrator (rewritten by T15 + T19)
- `plugins/screw/agents/screw-full-review.md` — full-scan orchestrator (rewritten by T16 + T19)
- `docs/DEFERRED_BACKLOG.md` — X1-M1 Shipped entry; Phase 4+ section for `T-FULL-P1`, `T-STAGING-ORPHAN-GC`, `T-ACCUMULATE-ONCE`
- `docs/PHASE_3B_PLAN.md` — upstream-deps table (lines 69, 74) for cross-plan sync

---

## Iteration history

The original plan (T1-T11) implemented Option A′ as designed. Three round-trip tests uncovered follow-on failure modes, each triggering an extension round. Future readers: **read this before reading the task bodies** — it is the load-bearing narrative for why the plan balloons from 11 to 23 tasks.

### Round 0 — Baseline (T1-T11 Option A′)

Design: `assemble_domain_scan` splits into init page (top-level `prompts` dict + per-agent metadata) and code pages (code only). `assemble_full_scan` returns a dict with top-level `prompts` + per-agent `agents` list. Orchestrators cache `prompts` from the init page and reference by `agent_name` on code pages.

Shipped: T1-T9 (commits `4f013cd` through `df2524e`). T10 is the manual round-trip validation checkpoint.

**Round-trip (T10 attempt 1) FAILED.** The init page itself was still too large: 4 agents × ~5-7k tokens per `core_prompt` = ~20-28k tokens aggregate on the init page. Full-scan init was worse: 10+ agents × 5-7k = ~50-84k tokens. The init-page design deduped prompts across code pages but did not cap the init-page size itself. Subagent hit token pressure on the init page and fell back to direct file inspection (the same failure mode that drove Round 0).

### Round 1 — Option B: lazy per-agent prompt fetch (T12-T16)

Pivot: drop `prompts` dicts entirely. Add a new MCP tool `get_agent_prompt(agent_name, thoroughness)` that returns a single agent's core_prompt. Init page carries metadata only. Orchestrator subagents fetch prompts lazily on first-encounter per agent and cache for reuse across code pages.

Shipped: T12 (commit `3549283` — new tool), T13 (commit `f8cb80c` — drop `prompts` from `assemble_domain_scan` init), T14 (commit `520b9e6` — drop `prompts` from `assemble_full_scan`), T15 (commit `c86a76c` — rewrite `screw-injection.md`), T16 (commit `5335ac4` — rewrite `screw-full-review.md`).

**Round-trip (T10 attempt 2) PASS for pagination.** No more init-page overflow. Subagent fetched `get_agent_prompt` once per agent and cached for reuse. But a second defect surfaced: the subagent called `write_scan_results` **4 times** during a 4-agent injection scan — once per agent batch. Each call rewrote `.screw/reports/*` with accumulated findings. Correct output (last write wins, findings deduped by id), but the intermediate writes triggered user approval prompts and token waste, and the "call once" prompt discipline proved not load-bearing.

### Round 2 — Option D: accumulate + finalize split (T17-T21)

Pivot: replace `write_scan_results` with two tools. `accumulate_findings(project_root, findings_chunk, session_id?) -> {session_id, accumulated_count}` stages findings incrementally in `.screw/staging/{session_id}/findings.json` (dedup by finding.id on merge, atomic tmp+replace writes). `finalize_scan_results(project_root, session_id, agent_names, scan_metadata?, formats?)` reads staging, applies exclusions, renders formats, writes report files, cleans up staging.

Shipped: T17 (commit `1aad87d` — engine split + staging.py), T18 (commit `9b6f277` — server registration), T19 (commit `20fc4b8` — rewrite all 6 orchestrator subagents), T20 (commit `890cf63` — Phase 3b cross-plan sync), T21 (commit `8e0569d` — mark T-WRITE-SPLIT shipped + log T-STAGING-ORPHAN-GC).

**Round-trip (T10 attempt 3) PASS for pagination AND single-finalize.** But a third defect surfaced: if the subagent called `finalize_scan_results` more than once (re-retry after partial render failure, or defensive "make sure it's written" instinct), the second call raised `FileNotFoundError` on staging (cleaned up by the first call) and cascaded to a ValueError. Correct by spec but terrible UX: the user saw a red stacktrace after an apparently successful scan.

### Round 3 — Idempotent finalize (T23)

Pivot: make `finalize_scan_results` idempotent. On first call, compute + cache the result in a sidecar `.screw/staging/{session_id}/finalized.json` before cleaning up the primary staging files. On second call with the same `session_id`, detect the sidecar, return the cached result verbatim, no ValueError. Track finalized sessions for the lifetime of the staging directory (cheap — each sidecar is small).

Shipped: T23 (commit `11a2cc4`).

**Round-trip (T10 attempt 4) CLEAN PASS.** 11 findings across the fixture, one report file set, 12 tool uses total (init page + 3 code pages + 3 get_agent_prompt + 3 accumulate_findings + 1 finalize_scan_results + 1 confirmatory list), no errors, no fallback to direct file inspection. Final validated shape; promoted to ship.

### Task numbering quirk

T22 is this documentation alignment task (not a round of iteration). There is no T22 in the commit history — T1-T9 + T10 + T11 + T12-T21 + T23 = 23 commits total, with T22 reserved for the plan-file cleanup (this document).

---

## Upstream Dependencies (Phase 3a artifacts this plan consumes)

| Phase 3a artifact | Current shape | How this plan uses it |
|---|---|---|
| `ScanEngine.assemble_scan(agent_name, target, thoroughness, project_root, *, preloaded_codes, _preloaded_exclusions) -> dict` | Per-agent scan payload builder. Returns `{agent_name, core_prompt, code, resolved_files, meta, exclusions?, trust_status?}`. | T1: extend with `include_prompt: bool = True` kwarg. |
| `ScanEngine.assemble_domain_scan(..., cursor, page_size)` | Paginated domain scan. Returns `{domain, agents, next_cursor, page_size, total_files, offset, trust_status?}`. | T2-T4: split into init-page and code-page branches. **Superseded by T13** (drops `prompts` dict; lazy fetch). |
| `ScanEngine.assemble_full_scan(target, thoroughness, project_root) -> list[dict]` | Flat full-agent fan-out. Currently returns `list[dict]`. | T5: change return type to `dict` with top-level `prompts`. **Superseded by T14** (drops `prompts` dict). |
| `resolve_target(target) -> list[ResolvedCode]` | File resolution (unchanged). | Used internally by init/code branches. |
| `load_exclusions(project_root) -> list[Exclusion]` | Exclusion YAML loader (unchanged). | Init page loads once; code pages receive `_preloaded_exclusions=[]`. |
| `write_scan_results(project_root, findings, agent_names, scan_metadata?, formats?) -> {...}` | One-shot report writer (PR#3 shape). | **Removed by T17.** Replaced by `accumulate_findings` + `finalize_scan_results`. |

---

## File Structure

Files created or modified across the full T1-T23 arc (annotated by round):

| Path | Action | Responsibility | Round |
|---|---|---|---|
| `src/screw_agents/engine.py` | Modify | `include_prompt` kwarg; init/code-page split; `get_agent_prompt`; `accumulate_findings`; `finalize_scan_results` | 0,1,2,3 |
| `src/screw_agents/server.py` | Modify | Register `get_agent_prompt`, `accumulate_findings`, `finalize_scan_results`; remove `write_scan_results` | 1,2 |
| `src/screw_agents/staging.py` | Create | Session-scoped staging directory; atomic merge writes; finalized-session tracking | 2,3 |
| `tests/test_engine.py` | Modify | `assemble_scan(include_prompt=False)`; reshaped `assemble_full_scan` | 0 |
| `tests/test_pagination.py` | Modify | Init-page shape, code-page shape, full-walk continuity | 0,1 |
| `tests/test_prompt_dedup_roundtrip.py` | Create | Integration test simulating the multi-page orchestration | 0 |
| `tests/test_get_agent_prompt.py` | Create | MCP tool happy-path + error cases | 1 |
| `tests/test_accumulate_finalize.py` | Create | Accumulate/finalize protocol + dedup + idempotent finalize | 2,3 |
| `plugins/screw/agents/screw-injection.md` | Modify | Pagination loop + lazy fetch + accumulate/finalize protocol | 0,1,2 |
| `plugins/screw/agents/screw-full-review.md` | Modify | Full-scan shape + lazy fetch + accumulate/finalize protocol | 0,1,2 |
| `plugins/screw/agents/screw-sqli.md` (and 5 siblings) | Modify | Accumulate/finalize protocol for per-agent orchestrators | 2 |
| `docs/DEFERRED_BACKLOG.md` | Modify | X1-M1 Shipped entry; T-FULL-P1; T-WRITE-SPLIT (shipped); T-STAGING-ORPHAN-GC; T-ACCUMULATE-ONCE | 0,2,3 |
| `docs/PHASE_3B_PLAN.md` | Modify | Cross-plan sync for X1-M1 SHIPPED + Option D split | 0,2 |
| `docs/PHASE_3A_X1_M1_PLAN.md` | Modify | This document — final alignment (T22) | — |

---

## Task 0: Pre-implementation audit (no commit)

**Purpose:** Ensure the implementer has full context before touching code. Per `feedback_phase3a_workflow_discipline.md`, every code task gets a pre-audit subagent dispatch.

- [x] **Step 1: Read the spec end-to-end**

Read `docs/specs/2026-04-17-prompt-dedup-x1-m1-design.md`. Confirm understanding of:
- Init page invariants (§2): `prompts` present IFF `cursor is None`; `agents[].core_prompt` never present; `exclusions` init-only; `code_chunks_on_page == 0` on init
- Code page invariants: no `prompts`, no `exclusions`, `agents[].code` present, `agents[].core_prompt` absent
- Cursor schema UNCHANGED (still `{target_hash, offset}`)
- `assemble_full_scan` breaking change (`list[dict]` → `dict`)
- Explicit `include_prompt` kwarg (not post-hoc strip)

> **Post-Round 1 note:** Spec evolved — `prompts` dict was removed entirely in T13-T14 (Round 1 pivot to lazy fetch). The post-Round 1 invariants are: init page carries per-agent metadata only; code pages carry per-agent code only; orchestrators fetch prompts via `get_agent_prompt`.

- [x] **Step 2: Read the current `assemble_scan` and `assemble_domain_scan` implementations**
- [x] **Step 3: Read existing pagination tests**
- [x] **Step 4: Read the two subagent orchestrator prompts**
- [x] **Step 5: Verify baseline tests pass** — 430 passing (Phase 3a PR#3 baseline).

---

## Task 1: Add `include_prompt` kwarg to `assemble_scan`

**Status:** SHIPPED in commit `4f013cd`.

**Files:**
- Modified: `src/screw_agents/engine.py` (`assemble_scan`)
- Modified: `tests/test_engine.py` (new test methods)

Added `include_prompt: bool = True` kwarg to `assemble_scan`. Gates both the `_build_prompt` call and the `core_prompt` dict assignment. Default `True` preserves per-agent callers (scan_sqli, scan_cmdi, etc.). Domain-level and full-scan callers pass `False` on fan-out iterations to enable prompt deduplication at the response top level.

**Tests added:**
- `test_assemble_scan_default_includes_core_prompt` — regression for default behavior
- `test_assemble_scan_include_prompt_false_omits_core_prompt` — key absent (not empty string) when False

---

## Task 2: `assemble_domain_scan` init-page branch

**Status:** SHIPPED in commit `f59b816` (fix-up in `7af7def`). **Partially superseded by T13** — the `prompts` dict added here was removed in Round 1's lazy-fetch pivot.

**Files:**
- Modified: `src/screw_agents/engine.py` (`assemble_domain_scan`)
- Modified: `tests/test_pagination.py` (init-page tests)

Split `assemble_domain_scan` into init-page (cursor=None) and code-page branches. On init, returned:
```
{
  "domain": ...,
  "prompts": {agent_name: core_prompt, ...},   # <-- REMOVED by T13
  "agents": [{agent_name, meta, exclusions}, ...],
  "next_cursor": <offset=0 cursor> | null,
  "code_chunks_on_page": 0,
  "offset": 0,
  "total_files": N,
  "trust_status": {...}?
}
```

**Tests added (still valid post-T13 with `prompts` assertion removed):**
- `test_domain_scan_init_page_shape`
- `test_domain_scan_init_page_idempotent`
- `test_domain_scan_init_page_empty_target`

---

## Task 3: `assemble_domain_scan` code-page branch

**Status:** SHIPPED in commit `5d80f8c`.

Code-page branch (cursor!=None): fans out `assemble_scan` with `include_prompt=False` and `_preloaded_exclusions=[]`, strips any lingering `exclusions`/`trust_status` from per-agent entries, emits `trust_status` once at the response top level.

**Tests added:**
- `test_domain_scan_code_page_shape`
- `test_domain_scan_code_page_cursor_replay_different_target_rejected`
- `test_domain_scan_trust_status_on_every_page`

---

## Task 4: Full-walk integration test

**Status:** SHIPPED in commit `9b38450`.

Created `tests/test_prompt_dedup_roundtrip.py` with two integration tests walking the entire pagination sequence. Assertions updated post-Round 1 to drop `prompts` dict references and use lazy fetch shape instead.

---

## Task 5: `assemble_full_scan` prompt dedup (breaking change)

**Status:** SHIPPED in commit `b3aadb0` (fix-up in `d58106b`). **Superseded by T14** — the `prompts` dict added here was removed in Round 1's lazy-fetch pivot.

Changed return type from `list[dict]` to `dict` with top-level `prompts` + `agents` list. Per-agent entries no longer carry `core_prompt`.

Round 1 update (T14): `prompts` dict removed entirely; per-agent entries carry only `{agent_name, code, meta, exclusions?}`.

---

## Task 6: Update `screw-injection.md` orchestrator subagent

**Status:** SHIPPED in commit `994d710` (fix-up in `b4b0cc6`). **Rewritten by T15** (Round 1) and again by T19 (Round 2).

Original Round 0 rewrite documented init-page vs code-page shapes with the `prompts` dict. T15 replaced this with lazy `get_agent_prompt` fetch protocol. T19 added the accumulate/finalize two-phase persistence protocol.

---

## Task 7: Update `screw-full-review.md` orchestrator subagent

**Status:** SHIPPED in commit `0a54b4c` (fix-up in `7761a73`). **Rewritten by T16** (Round 1) and again by T19 (Round 2).

Parallel to T6 for the full-scan orchestrator. Same supersession pattern.

---

## Task 8: Update `docs/DEFERRED_BACKLOG.md`

**Status:** SHIPPED in commit `3f5755a`. Amended by T21 (Round 2) to add T-WRITE-SPLIT (shipped) + T-STAGING-ORPHAN-GC (deferred). Amended by T22 (this task) to add T-ACCUMULATE-ONCE.

Moved X1-M1 from TOP PRIORITY to Shipped; logged T-FULL-P1 (Phase 4+, HIGH priority) and T-ORCHESTRATOR-SCHEMA (project-wide, medium priority).

---

## Task 9: Cross-plan sync — `docs/PHASE_3B_PLAN.md`

**Status:** SHIPPED in commit `df2524e`. Amended by T20 (Round 2) for Option D split.

Updated upstream-deps table rows 69 (`assemble_domain_scan`) and 74 (X1-M1 marker) to reflect the init-page + code-pages shape. T20 amended to reflect the Option D `accumulate_findings` + `finalize_scan_results` protocol and add Task 3b-19 entries.

---

## Task 10: Round-trip validation (manual, fish shell)

**Status:** Round 0 attempt FAILED (init-page too large → Round 1 pivot). Round 1 attempt PASS for pagination, FAILED for multi-write (→ Round 2 pivot). Round 2 attempt PASS for pagination + single-finalize, FAILED for multi-finalize UX (→ Round 3 pivot). Round 3 attempt CLEAN PASS.

**Final round-trip result:** 11 findings across the fixture, one report file set, 12 tool uses total, no errors, no fallback to direct file inspection.

**Final tool-use breakdown (post-T23):**
- 1× `scan_domain` (init page, cursor=None)
- 3× `scan_domain` (code pages, cursor non-None, next_cursor transitions)
- 3× `get_agent_prompt` (one per unique agent encountered)
- 3× `accumulate_findings` (one per agent-batch — see T-ACCUMULATE-ONCE deferred entry for UX polish follow-up)
- 1× `finalize_scan_results`
- 1× confirmatory list/read

No commit for this task — validation checkpoint only.

---

## Task 11: Final verification + PR open

**Status:** Superseded by the expanded arc. PR #9 is opened after T23 (not T11) with the expanded summary covering all three iteration rounds. Full test count at PR open: 457 passing.

---

## Task 12 — `get_agent_prompt` MCP tool (Round 1)

**Status:** SHIPPED in commit `3549283`.

Added `get_agent_prompt(agent_name, thoroughness="standard") -> {agent_name, thoroughness, core_prompt}` as a new MCP tool in `engine.py` + `server.py`. Pure function — no side effects, no project context. Returns the same prompt the original `assemble_scan` would have built for that agent + thoroughness.

**Why:** Round 0's init page still carried N agents × 5-7k tokens aggregate prompts. Lazy per-agent fetch eliminates this upfront cost — the subagent fetches a given agent's prompt once on first-encounter and caches in its own context.

**Tests added:** `tests/test_get_agent_prompt.py` — happy path, unknown agent, invalid thoroughness.

---

## Task 13 — drop `prompts` dict from `assemble_domain_scan` init page (Round 1)

**Status:** SHIPPED in commit `f8cb80c`. Supersedes the `prompts` dict output added in T2.

Removed the `prompts_dict` construction from the init-page branch. Init page now carries per-agent metadata only (`{agent_name, meta, exclusions?}`). Orchestrator subagents call `get_agent_prompt(agent_name)` lazily for each agent encountered.

**Tests updated:** `test_domain_scan_init_page_shape` no longer asserts `"prompts" in result`; instead asserts `"prompts" not in result`. Integration tests similarly updated.

---

## Task 14 — drop `prompts` dict from `assemble_full_scan` (Round 1)

**Status:** SHIPPED in commit `520b9e6`. Supersedes the `prompts` dict output added in T5.

Parallel to T13 for the full-scan response. `assemble_full_scan` now returns `{agents: [{agent_name, code, meta, exclusions?}, ...], trust_status?}` — no top-level `prompts`. Orchestrator fetches prompts lazily.

---

## Task 15 — rewrite `screw-injection.md` for lazy get_agent_prompt (Round 1)

**Status:** SHIPPED in commit `c86a76c`. Rewrites Step 1 from T6's caching-of-init-prompts protocol to lazy-fetch protocol.

Subagent's pagination loop now:
1. Call `scan_domain` with `cursor=None` — cache exclusions + trust_status from init page.
2. For each unique `agent_name` encountered across pages: call `get_agent_prompt(agent_name)` once, cache result.
3. For each code page `agent_entry`: apply cached `prompts[entry.agent_name]` + `entry.code`.
4. Accumulate findings across pages.

---

## Task 16 — rewrite `screw-full-review.md` for lazy fetch (Round 1)

**Status:** SHIPPED in commit `5335ac4`. Parallel to T15 for full-scan orchestrator.

---

## Task 17 — `accumulate_findings` + `finalize_scan_results` protocol (Round 2)

**Status:** SHIPPED in commit `1aad87d`.

Replaced `write_scan_results` (removed from `engine.py` + `server.py`) with two tools:

- `accumulate_findings(project_root, findings_chunk, session_id?) -> {session_id, accumulated_count}`
  - If `session_id` is omitted, a new UUID is generated and returned.
  - Writes `.screw/staging/{session_id}/findings.json` atomically (tmp+replace). Dedup by `finding.id` on merge with prior stage.
  - Safe to call N times per session — cheap, intermediate, user-approval-per-call but no file rewrites at `.screw/reports/*`.
- `finalize_scan_results(project_root, session_id, agent_names, scan_metadata?, formats?) -> {files_written, summary, exclusions_applied, trust_status}`
  - Reads staging, applies exclusions, renders formats (JSON + Markdown + CSV), writes report files to `.screw/reports/*`.
  - Cleans up staging directory post-write.
  - Second call in the original design raised ValueError (later replaced by idempotent behavior in T23).

**New module:** `src/screw_agents/staging.py` — session directory management, atomic writes, dedup merge.

**Tests added:** `tests/test_accumulate_finalize.py` — dedup by id, multi-session isolation, atomic write failure recovery.

---

## Task 18 — register `accumulate_findings` + `finalize_scan_results` in server (Round 2)

**Status:** SHIPPED in commit `9b6f277`.

Wired both tools into `src/screw_agents/server.py` MCP dispatcher. `write_scan_results` MCP tool removed. Input/output schemas published.

---

## Task 19 — rewrite all 6 orchestrator subagents for accumulate+finalize (Round 2)

**Status:** SHIPPED in commit `20fc4b8`.

Rewrote persistence step in:
- `plugins/screw/agents/screw-injection.md` (domain orchestrator)
- `plugins/screw/agents/screw-full-review.md` (full-scan orchestrator)
- `plugins/screw/agents/screw-sqli.md`, `screw-cmdi.md`, `screw-ssti.md`, `screw-xss.md` (per-agent orchestrators)

Protocol (current):
1. Accumulate findings during scan (may be called multiple times; dedup by id — see T-ACCUMULATE-ONCE for UX polish follow-up).
2. Finalize exactly once at scan end with the collected `session_id`, `agent_names`, and desired `formats`.

---

## Task 20 — Phase 3b cross-plan sync for Option D split (Round 2)

**Status:** SHIPPED in commit `890cf63`.

Updated `docs/PHASE_3B_PLAN.md` upstream-deps table: added rows for `accumulate_findings` and `finalize_scan_results`, removed the `write_scan_results` row. Updated Task 3b-19 to reference the two-phase protocol.

---

## Task 21 — DEFERRED_BACKLOG updates: T-WRITE-SPLIT shipped + T-STAGING-ORPHAN-GC deferred (Round 2)

**Status:** SHIPPED in commit `8e0569d`.

Logged T-WRITE-SPLIT as shipped in this PR. Added T-STAGING-ORPHAN-GC (Phase 4+, medium priority) — orphan cleanup for scans that accumulate but never finalize (crashed/aborted subagent sessions).

---

## Task 22 — Plan-file alignment (this task)

**Status:** This document. Rewrites `PHASE_3A_X1_M1_PLAN.md` to reflect the final 23-task shape, the three extension rounds, and the final shipped architecture. Adds T-ACCUMULATE-ONCE to `DEFERRED_BACKLOG.md` (project-wide, Low priority — UX polish to encourage single `accumulate_findings` call per scan). Updates X1-M1 Shipped entry Follow-ups list.

No test changes. Doc-only commit.

---

## Task 23 — idempotent `finalize_scan_results` + finalized-session guard (Round 3)

**Status:** SHIPPED in commit `11a2cc4`.

Made `finalize_scan_results` idempotent. On first call: compute result, write to `.screw/staging/{session_id}/finalized.json` sidecar BEFORE cleaning up primary staging files. On subsequent calls with the same `session_id`: detect the sidecar, return the cached result verbatim. No ValueError. No state corruption.

**Why:** Round 2 round-trip showed the subagent occasionally re-called `finalize_scan_results` defensively (retry after partial render error, or "make sure it's written" instinct). Second call raised `FileNotFoundError` on staging (cleaned up by first call) → cascade to ValueError → red stacktrace after an apparently successful scan. Idempotent finalize channels this instinct into a cheap no-op.

**Tests added (in `tests/test_accumulate_finalize.py`):**
- `test_finalize_idempotent_returns_cached_result` — second call returns same result as first
- `test_finalize_idempotent_no_file_rewrite` — second call does NOT rewrite `.screw/reports/*`
- `test_finalize_idempotent_sidecar_survives_staging_cleanup`

---

## Final architecture summary

The shape that actually shipped. **This is what future readers should match mental models against**, NOT T1-T9's Option A′ design.

### Engine surface

```
ScanEngine.assemble_scan(agent_name, target, thoroughness, project_root,
                         *, preloaded_codes, _preloaded_exclusions,
                         include_prompt=True) -> dict
  # Per-agent payload builder. include_prompt=False omits core_prompt key entirely.

ScanEngine.assemble_domain_scan(domain, target, thoroughness, project_root,
                                *, cursor, page_size) -> dict
  # Paginated domain scan.
  # Init page  (cursor=None): {domain, agents[{agent_name, meta, exclusions?}],
  #                            next_cursor, page_size, total_files,
  #                            code_chunks_on_page:0, offset:0, trust_status?}
  # Code page  (cursor set):  {domain, agents[{agent_name, code, resolved_files, meta}],
  #                            next_cursor, page_size, total_files,
  #                            code_chunks_on_page:N, offset, trust_status?}
  # NO `prompts` dict on either page. Subagents use get_agent_prompt lazily.

ScanEngine.assemble_full_scan(target, thoroughness, project_root) -> dict
  # {agents[{agent_name, code, meta, exclusions?}], trust_status?}
  # NO `prompts` dict. NOT paginated (see T-FULL-P1).

ScanEngine.get_agent_prompt(agent_name, thoroughness="standard") -> dict
  # {agent_name, thoroughness, core_prompt}
  # Pure function; no project context; used by orchestrators for lazy prompt fetch.

ScanEngine.accumulate_findings(project_root, findings_chunk, session_id=None) -> dict
  # {session_id, accumulated_count}
  # Incremental staging; atomic merge with dedup-by-id.

ScanEngine.finalize_scan_results(project_root, session_id, agent_names,
                                 scan_metadata=None, formats=None) -> dict
  # {files_written, summary, exclusions_applied, trust_status}
  # Idempotent — second call with same session_id returns cached result.
```

### MCP tools registered

- `scan_{sqli,cmdi,ssti,xss,...}` — per-agent scan (unchanged)
- `scan_domain` — paginated domain scan (shape updated)
- `scan_full` — full-scan (shape updated, not paginated)
- `get_agent_prompt` — **NEW** (Round 1)
- `accumulate_findings` — **NEW** (Round 2)
- `finalize_scan_results` — **NEW, idempotent** (Round 2 + Round 3)
- `write_scan_results` — **REMOVED** (Round 2)
- `list_agents`, `list_domains`, `check_exclusions`, `record_exclusion`, `verify_trust`, `aggregate_learning`, `format_output` — unchanged

### Orchestrator subagent protocol (post-T23)

1. **Init call:** `scan_domain(target, cursor=None)` or `scan_full(target)`. Cache `exclusions` + `trust_status` from the response.
2. **Lazy prompt fetch:** for each unique `agent_name` encountered, call `get_agent_prompt(agent_name)` exactly once. Cache the returned `core_prompt` for reuse across subsequent pages.
3. **Pagination loop (scan_domain only):** while `next_cursor` is non-null, call `scan_domain(target, cursor=next_cursor)`. For each code page's `agent_entry`: analyze `cached_prompts[agent_entry.agent_name]` + `agent_entry.code`, produce findings.
4. **Accumulate:** call `accumulate_findings(project_root, findings_chunk, session_id)` with the findings gathered so far. (Currently may be called multiple times — see T-ACCUMULATE-ONCE for UX polish.) Save the returned `session_id` for finalization.
5. **Finalize:** call `finalize_scan_results(project_root, session_id, agent_names, scan_metadata, formats)` exactly once. Returns `{files_written, summary, exclusions_applied, trust_status}`. Idempotent if accidentally re-called.

### Staging layout

```
<project_root>/.screw/staging/<session_id>/
  findings.json       # incremental accumulation; cleaned up on finalize
  findings.json.tmp   # transient atomic-write tmp file
  finalized.json      # sidecar, written on first finalize; enables idempotent re-call
```

`.screw/reports/` is untouched until finalize; then it receives JSON + Markdown + CSV output files.

---

## Exit Criteria (updated for final shape)

1. All tests passing: **457 passing** (up from 430 baseline). ✓
2. Round-trip test (Task 10, attempt 4) completes CLEAN: ✓
   - 11 findings across fixture
   - One report file set in `.screw/reports/`
   - 12 tool uses total (init + 3 code pages + 3 get_agent_prompt + 3 accumulate + 1 finalize + 1 confirmatory)
   - No errors
   - No fallback to direct file inspection
3. `docs/PHASE_3B_PLAN.md` upstream-deps rows updated (T9 + T20). ✓
4. `docs/DEFERRED_BACKLOG.md` updated:
   - X1-M1 moved to Shipped. ✓
   - `T-FULL-P1` added (Phase 4+, HIGH priority). ✓
   - `T-ORCHESTRATOR-SCHEMA` added (project-wide). ✓
   - `T-WRITE-SPLIT` logged as Shipped. ✓
   - `T-STAGING-ORPHAN-GC` added (Phase 4+). ✓
   - `T-ACCUMULATE-ONCE` added (project-wide, Low — this T22 commit). ✓
5. All orchestrator subagents updated (T15, T16, T19): ✓
6. PR #9 opened with expanded summary covering Rounds 0-3.
7. No AI attribution / Co-Authored-By in any commit message (per `feedback_no_cc_commits.md`). ✓

---

## Deferred items generated by this PR

| Item | Priority | Where | Status |
|---|---|---|---|
| `T-FULL-P1` — Paginate `assemble_full_scan` + apply lazy-fetch + agent-relevance filter | HIGH | Phase 4+ | Deferred |
| `T-ORCHESTRATOR-SCHEMA` — Backfill finding-object schema in domain orchestrator subagents | Medium | Project-wide | Deferred |
| `T-WRITE-SPLIT` — Split `write_scan_results` into `accumulate_findings` + `finalize_scan_results` | — | — | **Shipped in this PR (T17-T19)** |
| `T-STAGING-ORPHAN-GC` — Clean up orphaned `.screw/staging/` directories | Medium | Phase 4+ | Deferred |
| `T-ACCUMULATE-ONCE` — UX polish: encourage single accumulate_findings call per scan | Low | Project-wide | Deferred (T22) |

All deferred entries live in `docs/DEFERRED_BACKLOG.md` with full context, triggers, and suggested fixes.

---

## Cross-Plan Synchronization Summary (for auditor convenience)

| Downstream plan | Entry | Action in this PR | Task |
|---|---|---|---|
| `docs/PHASE_3B_PLAN.md` row 69 | `assemble_domain_scan` upstream-deps row | Rewrite for init/code-page shape + lazy fetch (post-T13); Option D protocol (T20) | T9 + T20 |
| `docs/PHASE_3B_PLAN.md` row 74 | `X1-M1 — core-prompt deduplication` marker row | Mark SHIPPED; point to DEFERRED_BACKLOG | T9 |
| `docs/PHASE_3B_PLAN.md` | `write_scan_results` references | Replace with `accumulate_findings` + `finalize_scan_results` | T20 |
| `docs/DEFERRED_BACKLOG.md` TOP PRIORITY section | `X1-M1 — Core-prompt deduplication` | Move to Shipped section | T8 |
| `docs/DEFERRED_BACKLOG.md` Phase 4+ section | `T-FULL-P1` (new) | Add with HIGH priority | T8 |
| `docs/DEFERRED_BACKLOG.md` Phase 4+ section | `T-STAGING-ORPHAN-GC` (new) | Add with medium priority | T21 |
| `docs/DEFERRED_BACKLOG.md` Project-wide section | `T-ORCHESTRATOR-SCHEMA` (new) | Add with medium priority | T8 quality-review surfaced |
| `docs/DEFERRED_BACKLOG.md` Project-wide section | `T-ACCUMULATE-ONCE` (new) | Add with Low priority | T22 (this task) |
| `docs/DEFERRED_BACKLOG.md` Shipped section | `T-WRITE-SPLIT` entry | Add as Shipped | T21 |

Phase 3b Task 3b-19 implementation body does NOT reference `agents[].core_prompt` or `prompts` dict directly (verified via grep), so no Phase 3b task code needs in-plan editing beyond the upstream-deps table + tool-name references. The cross-plan sync in T9 + T20 is sufficient for the 3b-19 implementer to know the lazy-fetch + accumulate/finalize protocol.
