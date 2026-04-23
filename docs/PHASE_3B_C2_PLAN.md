# Phase 3b C2 — Nested Subagent Dispatch Fix (Chain-Subagents Refactor): Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.
>
> **Per-task workflow (from `feedback_phase3a_workflow_discipline.md`):** 7-step cycle — pre-audit → implementer → spec review → quality review → triage → fix-up → cross-plan sync. Non-negotiable. Every content-producing task runs the full cycle.
>
> **Opus-for-all-subagents (from `feedback_opus_for_all_subagents.md`):** every Agent dispatch passes `model: "opus"`. Marco's "best-in-class" directive overrides the cost-conscious default.
>
> **Name precedents (from `feedback_name_precedents`):** implementer prompts MUST explicitly name the patterns from T_{1..N-1} that T_N must match. Pre-audit greps for asymmetries. Target 0–1 Important finding per review, not 2–4.
>
> **Plan-sync on deviation (from `feedback_plan_sync_on_deviation.md`):** whenever implementation differs from this plan, update this file in the SAME PR (or defer the item to DEFERRED_BACKLOG). Plan and code must be coherent at merge time.
>
> **Live round-trip is a HARD GATE (from `project_phase2_e2e_notes.md` + PR #6 process failure):** static content tests cannot catch runtime dispatch failures. T10 runs a live `claude` session round-trip; its pass/fail is the binary merge signal.

**Goal:** Rewrite `/screw:scan` as a main-session orchestrator that chains subagents from main, removing the architecturally-blocked nested-subagent-dispatch pattern introduced by Phase 3b PR #6. Restore end-to-end adaptive-mode functionality that silently degrades to YAML-only today.

**Architecture:** Main session becomes the orchestrator. Scan subagents (screw-sqli/cmdi/ssti/xss, screw-injection) do scan + generation + lint, then return a structured JSON payload (findings + pending_reviews). Main parses, dispatches screw:screw-script-reviewer per pending_review (now main → subagent, a permitted single-level hop), stages the reviewed script via `stage_adaptive_script` MCP tool directly, displays the 5-section review, handles approve/reject in a sequential loop, and calls promote + execute + accumulate per approval. `/screw:scan full`'s logic folds into scan.md; `screw-full-review.md` is deleted (it had the same latent nested-dispatch bug).

**Tech Stack:** Markdown (Claude Code subagent + slash-command prompts), Python 3.11+ (pytest for test-suite updates). NO engine changes — MCP tool signatures and semantics unchanged from PR #6's C1 staging architecture.

**Spec:** `docs/specs/2026-04-23-phase-3b-c2-nested-dispatch-fix-design.md` (local working material, gitignored per `project_docs_not_committed`).

**Upstream phase plan:** Phase 3b PR #6 merged 2026-04-23 (squash `fa2f42a`) + docs commit `4618c60`. 942 passed / 8 skipped on main HEAD. This is the immediate C1 follow-up; BACKLOG-C2-01 blocks Phase 4.

**Downstream phase plan:** C2 merge drops the Phase-4 blocker count from 5 to 4. Remaining blockers: `T-FULL-P1`, `T19-M1/M2/M3`, `BACKLOG-PR6-22`. Phase 4 (autoresearch) gates on all 5 → 0.

**Branch:** `phase-3b-c2-nested-dispatch-fix` (per `project_execution_mode.md`: subagent-driven + dedicated worktree at `.worktrees/phase-3b-c2-nested-dispatch-fix`).

**Key references for implementers:**
- `docs/specs/2026-04-23-phase-3b-c2-nested-dispatch-fix-design.md` — design + invariants (local-only spec)
- `docs/DEFERRED_BACKLOG.md` § `BACKLOG-C2-01` — canonical scope entry
- `docs/PROJECT_STATUS.md` § Phase 4 Prerequisites (hard gates) — C2 is ★ first prerequisite
- `docs/PHASE_3B_C1_PLAN.md` — preceding PR #6 work (read-only, historical reference for patterns)
- `/home/marco/GitRepos/claude-code-docs/docs/sub-agents.md` — official Claude Code subagents doc. Lines 59, 324, 711: nested-dispatch-forbidden rule. Lines 683-689: chain-subagents pattern.
- `/home/marco/GitRepos/claude-code-docs/docs/commands.md` line 13: slash commands are skills (main-session prompts).
- `plugins/screw/commands/scan.md` — the orchestrator to rewrite
- `plugins/screw/agents/screw-{sqli,cmdi,ssti,xss}.md` — 4 per-agent subagents to truncate
- `plugins/screw/agents/screw-injection.md` — domain orchestrator to truncate
- `plugins/screw/agents/screw-full-review.md` — file to DELETE (second nested-dispatch instance)
- `plugins/screw/agents/screw-script-reviewer.md` — UNCHANGED; only the dispatch initiator moves from scan-subagent to main session
- `tests/test_adaptive_subagent_prompts.py` — assertion flips + additions
- `src/screw_agents/engine.py` — read-only reference for MCP tool signatures (no changes)

---

## PR Scope Summary

| Category | Items | Net LOC |
|---|---|---|
| scan.md rewrite | Main-session orchestrator; argument parsing + single-scope + domain-scope + full-scope branches; subagent-return JSON parsing; adaptive review loop (reviewer dispatch → stage → 5-section → approve/reject → promote/execute/accumulate); finalize; summary | +180 (97 → 277) |
| Per-agent truncations | screw-sqli/cmdi/ssti/xss.md — truncate adaptive Step 3.5 at Step 3.5d-D; add structured JSON return; frontmatter cleanup | 4 × −325 = −1300 |
| Orchestrator truncation | screw-injection.md — truncate Step 2.5 similarly; add structured JSON return; frontmatter cleanup | −55 |
| File deletion | screw-full-review.md (second nested-dispatch instance; Option A fold+delete per spec §4.3) | −124 |
| Test updates | tests/test_adaptive_subagent_prompts.py — 2 polarity-flip rewrites (frontmatter + adaptive-section refs) + 9 deletions (8 parametrized × 4 agents = 32 cases + 1 non-parametrized = 33 cases) + 8 new test functions for scan.md orchestration (one of which is the file-absence assertion) | +45 |
| Cross-plan updates | DEFERRED_BACKLOG (BACKLOG-C2-01 → Shipped), PROJECT_STATUS (Phase 4 blocker count 5 → 4) | ~+20 doc lines |
| **Total** | | **~−1,230 LOC, +9 tests (net assertion count)** |

**Target:** 942 passed → **~917 passed, 8 skipped**. Math: 8 parametrized tests × 4 agent instances = 32 parametrized cases deleted + 1 non-parametrized (`test_execute_adaptive_script_invocation_omits_session_id`) = 33 cases removed. 8 new non-parametrized tests added. Net: 942 − 33 + 8 = 917. Recount during T9 if mismatch.

---

## File Structure Map

### Created (0 files)

### Modified (7 files)

| Path | What changes |
|---|---|
| `plugins/screw/commands/scan.md` | Full rewrite as main-session orchestrator. Sections 1 (arg parse), 1b (full-scope fan-out), 2 (parse subagent return), 3 (adaptive review loop a–f), 4 (finalize), 5 (summary). Contains ALL post-generation flow: reviewer dispatch, staging, 5-section review composition, approve/reject phrase grammar (including `confirm-high` per spec D2), promote + execute + accumulate MCP calls. |
| `plugins/screw/agents/screw-sqli.md` | Truncate adaptive Step 3.5 after Step 3.5d-E (retains scan + Steps 3.5a–c + Steps 3.5d-A through 3.5d-E inclusive). Remove Steps 3.5d-F through 3.5d-K + old Step 4 + old Step 5 + Confidence Calibration. ADD new Step 3.5d-F "Emit pending_review entry", new Step 4 "Persist YAML findings", new Step 5 "Return structured payload", re-append the "## Confidence Calibration" block at end. Relocate the 400-line size cap from old 3.5d-H into new Step 3.5d-D so the safety check survives truncation. Frontmatter: remove `Task`, `stage_adaptive_script`, `promote_staged_script`, `reject_staged_script`, `execute_adaptive_script`, `finalize_scan_results`. |
| `plugins/screw/agents/screw-cmdi.md` | Byte-identical to sqli modulo agent name (the existing test `test_adaptive_section_identical_modulo_agent_name` enforces this). |
| `plugins/screw/agents/screw-ssti.md` | Byte-identical to sqli modulo agent name. |
| `plugins/screw/agents/screw-xss.md` | Byte-identical to sqli modulo agent name. |
| `plugins/screw/agents/screw-injection.md` | Truncate Step 2.5c delegation paragraph (the per-gap pipeline delegation → per-agent Step 3.5d A-K); replace with "apply sub-steps A through E". REMOVE Step 3b (finalize). ADD new Step 4 "Return structured payload" with orchestrator-specific `scan_subagent: "screw-injection"` + `scan_metadata.agent_names: ["sqli","cmdi","ssti","xss"]`. Frontmatter: same removals as per-agent. |
| `tests/test_adaptive_subagent_prompts.py` | Rewrite 2 polarity assertions (frontmatter tool-surface + adaptive-section tool-references — per-agent files must NOT reference stage/promote/reject/execute/Task/reviewer). Delete 9 obsolete tests (8 parametrized × 4 agents = 32 cases + 1 non-parametrized = 33 cases total: sha256 prefix render, stderr render, retention notice, plugin-namespaced reviewer, bare-reviewer negative, stage/promote/reject contains, execute-invocation-omits-session_id). Add 8 new test functions for scan.md orchestration (see T1 body; one of the 8 is the screw-full-review.md file-absence assertion). |

### Deleted (1 file)

| Path | Reason |
|---|---|
| `plugins/screw/agents/screw-full-review.md` | Second instance of the nested-subagent-dispatch anti-pattern (dispatches domain orchestrators via Agent tool — architecturally blocked). Replaced by scan.md's `full` scope branch (Option A fold+delete per spec §4.3). |

### Read-only references (spec says zero changes)

| Path | Note |
|---|---|
| `src/screw_agents/engine.py` | MCP tool signatures unchanged (stage/promote/reject/execute/accumulate/finalize) |
| `src/screw_agents/server.py` | Tool dispatch unchanged |
| `src/screw_agents/adaptive/*.py` | Adaptive package unchanged |
| `src/screw_agents/models.py` | Models unchanged |
| `plugins/screw/agents/screw-script-reviewer.md` | Unchanged; only who dispatches it moves |
| `plugins/screw/agents/screw-learning-analyst.md` | Unrelated (learn-report flow) |
| `plugins/screw/commands/adaptive-cleanup.md` | Unrelated |
| `plugins/screw/commands/learn-report.md` | Unrelated |

---

## Task List

### Task 0: Worktree Setup + Baseline Verification

**Files:**
- Create: `.worktrees/phase-3b-c2-nested-dispatch-fix` (git worktree)

- [ ] **Step 1: Verify starting state**

Run: `git status && git log --oneline -1`
Expected: clean working tree; HEAD is `4618c60` (Phase 3b PR #6 docs commit).

- [ ] **Step 2: Verify `.worktrees/` is gitignored**

Run: `grep "^\.worktrees/" /home/marco/Programming/AI/screw-agents/.gitignore`
Expected: match returned (prevents accidentally committing the worktree).

- [ ] **Step 3: Create worktree + branch**

Run:
```fish
cd /home/marco/Programming/AI/screw-agents
git worktree add -b phase-3b-c2-nested-dispatch-fix .worktrees/phase-3b-c2-nested-dispatch-fix main
cd .worktrees/phase-3b-c2-nested-dispatch-fix
```
Expected: new branch created off main; `git status` shows clean on `phase-3b-c2-nested-dispatch-fix`.

- [ ] **Step 4: Sync dependencies**

Run: `uv sync`
Expected: resolver completes with no warnings.

- [ ] **Step 5: Verify baseline test suite passes**

Run: `uv run pytest -q 2>&1 | tail -3`
Expected: `942 passed, 8 skipped` (+ 10 warnings, ~44s).

- [ ] **Step 6: Verify spec file is reachable**

Run: `ls docs/specs/2026-04-23-phase-3b-c2-nested-dispatch-fix-design.md && wc -l docs/specs/2026-04-23-phase-3b-c2-nested-dispatch-fix-design.md`
Expected: file exists, ~700 lines.

- [ ] **Step 7: Verify BACKLOG-C2-01 canonical entry still present**

Run: `grep -A2 "BACKLOG-C2-01" docs/DEFERRED_BACKLOG.md | head -10`
Expected: entry visible; "Phase 3b-C2" heading visible.

---

### Task 1: Pre-update `tests/test_adaptive_subagent_prompts.py` (RED state for T2–T6)

**Files:**
- Modify: `tests/test_adaptive_subagent_prompts.py` (1 file)

**Rationale:** Per TDD + plan-discipline: write the target assertions FIRST so the test suite goes red, then T2–T6 walk the implementation to green. This task performs 2 polarity-flip rewrites, 9 deletions, and 8 new test-function additions in one coherent test-file edit. Expected end-state: 24 tests still green (stable properties like 15-layer stack reference, prompt-injection fence, import allowlist, Option D isolation), 10 tests RED (2 rewritten polarity tests + 8 new scan.md orchestrator tests — one of which is the file-absence assertion for screw-full-review.md).

**Precedent:** Phase 3b PR #6 (squash `fa2f42a`) added the Option D isolation guard `test_adaptive_prompt_does_not_reference_sign_adaptive_script`. T1 must PRESERVE that assertion as-is — it's C1 closure, unchanged by C2.

- [ ] **Step 1: Read the current test file in full**

Run: `wc -l tests/test_adaptive_subagent_prompts.py`
Expected: 535 lines.

Read the file to understand existing assertions before editing.

- [ ] **Step 2: Update the module docstring**

Edit the opening docstring (lines 1-22) to reflect C2 semantics:

```python
"""Format smoke tests for the `--adaptive` prompt surface.

Post-C2 (Phase 3b-C2 Nested Subagent Dispatch Fix): the 4 per-agent injection
subagents emit a structured pending_review payload and RETURN to main session;
they DO NOT stage/promote/reject/execute scripts, DO NOT dispatch the
screw:screw-script-reviewer subagent (nested dispatch is architecturally
blocked — docs/en/sub-agents.md line 711). Post-generation flow (reviewer
dispatch, staging, 5-section review, approve/reject, promote/execute/accumulate)
lives in scan.md's main-session prompt.

These tests are NOT semantic — they lock markdown structure and tool-surface
absence (scan subagents) / presence (scan.md) so a future edit can't silently
reintroduce the nested-dispatch pattern. Runtime dispatch correctness is
validated by the live round-trip protocol in spec §8 — NOT by this file.

Design decisions locked here:

- Per-agent subagent adaptive sections: byte-identical across the 4
  modulo agent-name substitution. Drift is a regression.
- The orchestrator (screw-injection.md) has its own adaptive section because
  it implements the shared Layer 0f quota. We only check for section presence
  and shared-quota language.
- scan.md documents --adaptive flag + phrase grammar including confirm-high
  (C2 UX friction for HIGH-risk scripts per spec §4.2 D2).
- scan.md owns post-generation MCP tool calls (stage/promote/reject/execute);
  per-agent + orchestrator files do NOT list these tools.
- screw-full-review.md is DELETED (C2 Option A fold+delete per spec §4.3).
"""
```

- [ ] **Step 3: Update the `_ADAPTIVE_MCP_TOOLS` constant (per-agent tool surface)**

The current list is the POSITIVE tool set scan-subagents must have. Post-C2 it's smaller — stage/promote/reject/execute/Task move to scan.md and are NEGATIVE assertions on scan subagents.

Replace the current constant block (around line 53) with:

```python
# Tools required in all 5 adaptive-mode subagent files (4 per-agent +
# orchestrator). Post-C2 (Phase 3b-C2): the scan subagents no longer
# own the post-generation MCP surface. Stage/promote/reject/execute/Task
# move to scan.md's main-session orchestrator (chain-subagents pattern
# per sub-agents.md:683-689); they MUST NOT appear in per-agent or
# orchestrator frontmatter or body.
_ADAPTIVE_MCP_TOOLS_REQUIRED_PER_AGENT = [
    "mcp__screw-agents__record_context_required_match",
    "mcp__screw-agents__detect_coverage_gaps",
    "mcp__screw-agents__lint_adaptive_script",
    "mcp__screw-agents__accumulate_findings",
]

_ADAPTIVE_MCP_TOOLS_FORBIDDEN_ON_PER_AGENT = [
    "mcp__screw-agents__stage_adaptive_script",
    "mcp__screw-agents__promote_staged_script",
    "mcp__screw-agents__reject_staged_script",
    "mcp__screw-agents__execute_adaptive_script",
    "mcp__screw-agents__finalize_scan_results",
    "Task",
]

# Tools required on scan.md (main session orchestrator) — the inverse of
# _ADAPTIVE_MCP_TOOLS_FORBIDDEN_ON_PER_AGENT plus accumulate_findings +
# finalize (main session owns the two-phase persist pattern post-C2).
_ADAPTIVE_MCP_TOOLS_REQUIRED_ON_SCAN_MD = [
    "mcp__screw-agents__stage_adaptive_script",
    "mcp__screw-agents__promote_staged_script",
    "mcp__screw-agents__reject_staged_script",
    "mcp__screw-agents__execute_adaptive_script",
    "mcp__screw-agents__accumulate_findings",
    "mcp__screw-agents__finalize_scan_results",
    "mcp__screw-agents__list_domains",
]
```

- [ ] **Step 4: Rewrite `test_tools_frontmatter_includes_adaptive_mcp_tools` (flip polarity)**

Replace the body of this test (around lines 137-164) with:

```python
def test_tools_frontmatter_per_agent_positive_and_negative() -> None:
    """Post-C2: scan subagents (per-agent + orchestrator) retain
    record_context_required_match / detect_coverage_gaps / lint_adaptive_script
    / accumulate_findings; MUST NOT list stage/promote/reject/execute /
    finalize / Task (those moved to scan.md)."""
    all_files = {f"screw-{a}.md": p for a, p in _PER_AGENT_FILES.items()}
    all_files["screw-injection.md"] = _ORCHESTRATOR_FILE
    for name, path in all_files.items():
        frontmatter, _ = _parse_subagent_file(path)
        tools = frontmatter.get("tools", [])
        assert isinstance(tools, list), f"{name} tools must be a list"
        for required in _ADAPTIVE_MCP_TOOLS_REQUIRED_PER_AGENT:
            assert required in tools, (
                f"{name} tools frontmatter missing required tool: {required}"
            )
        for forbidden in _ADAPTIVE_MCP_TOOLS_FORBIDDEN_ON_PER_AGENT:
            assert forbidden not in tools, (
                f"{name} tools frontmatter still lists forbidden tool: {forbidden} "
                f"— Phase 3b-C2 moved this to scan.md's main-session orchestrator"
            )
        # Option D (C1) isolation guard stays — sign_adaptive_script reserved
        # for non-LLM callers; not permitted in any LLM-flow file.
        assert "mcp__screw-agents__sign_adaptive_script" not in tools, (
            f"{name} tools frontmatter lists sign_adaptive_script — "
            f"Option D isolation regressed (spec §3.2)"
        )
```

- [ ] **Step 5: Rewrite `test_adaptive_section_references_all_required_mcp_tools` (flip polarity)**

Replace the body (around lines 206-236) with:

```python
def test_adaptive_section_per_agent_references_only_required_tools() -> None:
    """Post-C2: per-agent adaptive sections reference required tools;
    MUST NOT reference stage/promote/reject/execute or the reviewer subagent
    (those moved to scan.md)."""
    required = set(_ADAPTIVE_MCP_TOOLS_REQUIRED_PER_AGENT)
    forbidden = set(_ADAPTIVE_MCP_TOOLS_FORBIDDEN_ON_PER_AGENT) | {
        "screw-script-reviewer",
        "screw:screw-script-reviewer",
    }
    for agent, path in _PER_AGENT_FILES.items():
        _, body = _parse_subagent_file(path)
        section = _extract_adaptive_section(body, "### Step 3.5: Adaptive Mode")
        for token in required:
            assert token in section, (
                f"screw-{agent}.md adaptive section missing required: `{token}`"
            )
        for token in forbidden:
            assert token not in section, (
                f"screw-{agent}.md adaptive section still references forbidden: "
                f"`{token}` — Phase 3b-C2 moved it to scan.md orchestrator"
            )
        assert "sign_adaptive_script" not in section, (
            f"screw-{agent}.md still references sign_adaptive_script — "
            f"Option D isolation regressed"
        )
    # Orchestrator: same negative guards; positive assertion is delegated to
    # test_injection_orchestrator_has_adaptive_section for its own content.
    _, body = _parse_subagent_file(_ORCHESTRATOR_FILE)
    section = _extract_adaptive_section(body, "### Step 2.5: Adaptive Mode")
    for token in forbidden:
        assert token not in section, (
            f"screw-injection.md adaptive section still references forbidden: "
            f"`{token}`"
        )
    assert "sign_adaptive_script" not in section
```

- [ ] **Step 6: DELETE obsolete tests**

Delete these 9 test functions (8 parametrized × 4 agents = 32 cases + 1 non-parametrized — per-agent scan subagents no longer own this content post-C2; they move to scan.md where new assertions will cover them):

1. `test_adaptive_prompt_contains_stage_adaptive_script` (was at ~line 409)
2. `test_adaptive_prompt_contains_promote_staged_script` (was at ~line 418)
3. `test_adaptive_prompt_contains_reject_staged_script` (was at ~line 424)
4. `test_adaptive_prompt_does_not_use_bare_reviewer_name` (was at ~line 454) — the reviewer name isn't in per-agent files at all post-C2, so both polarity forms are irrelevant
5. `test_adaptive_prompt_uses_plugin_namespaced_reviewer` (was at ~line 445) — same reason as 4; new scan.md assertion replaces this
6. `test_adaptive_prompt_contains_stderr_render_on_failure` (was at ~line 504) — stderr render moves to scan.md
7. `test_adaptive_prompt_contains_retention_notice` (was at ~line 513) — retention notice moves to scan.md
8. `test_adaptive_prompt_displays_sha256_prefix_in_review_header` (was at ~line 523) — 5-section review moves to scan.md
9. `test_execute_adaptive_script_invocation_omits_session_id` (was at ~line 353) — execute invocation moves to scan.md (new scan.md assertion replaces)

All replacements land in T1 step 8 below.

- [ ] **Step 7: KEEP these assertions unchanged (they test stable post-C2 properties)**

Do NOT modify these — they are correct post-C2:

1. `test_adaptive_section_exists_in_all_four_per_agent_subagents` (section heading still present; truncated content is inside it)
2. `test_adaptive_section_identical_modulo_agent_name` (4 files byte-identical modulo agent name; truncation applies identically)
3. `test_injection_orchestrator_has_adaptive_section` (orchestrator Section 2.5 still present post-C2 with shared-quota language)
4. `test_scan_command_doc_documents_adaptive_flag` (scan.md still documents --adaptive)
5. `test_adaptive_section_has_prompt_injection_resistance` (UNTRUSTED_CODE fence + fence_token + sha256 in Step 3.5d-C, preserved)
6. `test_adaptive_section_documents_15_layer_stack` (15-layer references in Step 3.5 preamble, preserved)
7. `test_adaptive_section_documents_script_naming_regex` (regex in Step 3.5d-B, preserved)
8. `test_adaptive_section_removes_noninteractive_detection` (flag-is-consent framing preserved)
9. `test_adaptive_prompt_contains_must_import_only_phrase` (I5 hardening in Step 3.5d-C, preserved)
10. `test_adaptive_prompt_lists_all_adaptive_exports` (I5, preserved)
11. `test_adaptive_prompt_contains_negative_examples_block` (I5, preserved)
12. `test_adaptive_prompt_does_not_reference_sign_adaptive_script` (C1 Option D isolation; STRICTLY preserve — this is load-bearing post-C2 too)

- [ ] **Step 8: ADD new assertions for scan.md orchestration**

Add the following NEW test functions at the END of the file (after the existing parametrized block):

```python
# ---- C2 NEW: scan.md main-session orchestrator assertions -------------------


def test_scan_md_references_all_required_orchestration_mcp_tools() -> None:
    """Post-C2: scan.md's main-session prompt must reference every MCP tool
    the orchestrator calls directly: stage/promote/reject/execute +
    accumulate + finalize + list_domains (for full-scope branch)."""
    _, body = _parse_subagent_file(_SCAN_COMMAND_FILE)
    for required in _ADAPTIVE_MCP_TOOLS_REQUIRED_ON_SCAN_MD:
        tool_basename = required.replace("mcp__screw-agents__", "")
        assert tool_basename in body, (
            f"scan.md missing reference to {tool_basename} "
            f"(Phase 3b-C2: main session owns post-generation flow)"
        )


def test_scan_md_dispatches_plugin_namespaced_reviewer() -> None:
    """Post-C2: scan.md dispatches screw:screw-script-reviewer from main
    session via the Task tool. The `subagent_type` literal must be the
    plugin-namespaced form (I1 hardening from C1 PR #6, preserved here)."""
    _, body = _parse_subagent_file(_SCAN_COMMAND_FILE)
    assert "screw:screw-script-reviewer" in body, (
        "scan.md missing plugin-namespaced reviewer dispatch (I1)"
    )
    # The bare name (without plugin prefix) must not appear as subagent_type.
    import re
    bare_refs = re.findall(
        r'subagent_type[\'": ]+\s*"screw-script-reviewer"', body
    )
    assert not bare_refs, (
        "scan.md uses bare screw-script-reviewer as subagent_type (I1 regressed)"
    )


def test_scan_md_phrase_grammar_locked() -> None:
    """Post-C2 spec §4.2 D2: phrase grammar includes approve, confirm-high
    (C2-new for HIGH-risk UX friction), confirm-stale, confirm-<8hex>, reject."""
    _, body = _parse_subagent_file(_SCAN_COMMAND_FILE)
    required_phrases = [
        "approve",
        "reject",
        "confirm-high",
        "confirm-stale",
        "confirm-",
    ]
    for phrase in required_phrases:
        assert phrase in body, (
            f"scan.md missing approval phrase token: `{phrase}`"
        )


def test_scan_md_contains_subagent_return_schema_keys() -> None:
    """Post-C2: scan.md parses scan-subagent fenced JSON return. The schema's
    top-level keys (from spec §5.1) must be visible in scan.md so the
    orchestrator knows what to parse."""
    _, body = _parse_subagent_file(_SCAN_COMMAND_FILE)
    required_keys = [
        "pending_reviews",
        "session_id",
        "trust_status",
        "scan_subagent",
        "scan_metadata",
    ]
    for key in required_keys:
        assert key in body, (
            f"scan.md missing subagent-return schema key: `{key}`"
        )


def test_scan_md_does_not_reference_deleted_full_review_subagent() -> None:
    """Post-C2: screw-full-review.md is deleted (Option A fold+delete).
    scan.md MUST NOT reference it."""
    _, body = _parse_subagent_file(_SCAN_COMMAND_FILE)
    assert "screw-full-review" not in body, (
        "scan.md still references deleted screw-full-review subagent "
        "(Phase 3b-C2 Option A: full scope folded into scan.md)"
    )


def test_screw_full_review_md_file_is_deleted() -> None:
    """Post-C2: screw-full-review.md file does not exist on disk."""
    deleted_path = _AGENTS_DIR / "screw-full-review.md"
    assert not deleted_path.exists(), (
        f"{deleted_path} still exists — Phase 3b-C2 Option A requires deletion "
        f"(second nested-subagent-dispatch instance per spec §1.4)"
    )


def test_per_agent_files_instruct_fenced_json_return() -> None:
    """Post-C2: per-agent + orchestrator scan subagents end their turn with
    a fenced JSON code block per spec §5.1 schema. The instruction to do so
    must be discoverable in the prompt."""
    all_files = {f"screw-{a}.md": p for a, p in _PER_AGENT_FILES.items()}
    all_files["screw-injection.md"] = _ORCHESTRATOR_FILE
    for name, path in all_files.items():
        content = _read_agent_content(path)
        assert "pending_reviews" in content, (
            f"{name} missing pending_reviews reference — structured return "
            f"schema (spec §5.1) not discoverable"
        )
        assert "scan_subagent" in content, (
            f"{name} missing scan_subagent reference"
        )
        # Instruct the subagent to emit the fenced JSON block (rough
        # regex — exact phrase is implementer-authored; this is a
        # substring heuristic).
        assert ("fenced JSON" in content or "fenced json" in content.lower()
                or "```json" in content), (
            f"{name} missing instruction to emit fenced JSON return block"
        )


def test_scan_md_contains_full_scope_list_domains_branch() -> None:
    """Post-C2 Option A: scan.md's `full` branch dispatches domain
    orchestrators via list_domains (no more screw-full-review). The branch
    must reference list_domains and iterate per-domain dispatch."""
    _, body = _parse_subagent_file(_SCAN_COMMAND_FILE)
    assert "list_domains" in body, (
        "scan.md missing list_domains reference (full scope branch)"
    )
    # Sanity: full scope is documented
    assert "full" in body.lower()
```

- [ ] **Step 9: Run the test file — verify expected RED state**

Run: `uv run pytest tests/test_adaptive_subagent_prompts.py -v 2>&1 | tail -40`

Expected: most newly-added + flipped assertions FAIL (scan.md doesn't have the content yet; per-agent files still reference stage/promote/reject/execute). A few assertions PASS (stable ones from step 7 + the existing preserved ones). No Python syntax/import errors in the test file.

Expected empirical failure count: 10 failing test functions (2 rewritten polarity tests + 8 new scan.md orchestrator tests). This is the target RED state.

- [ ] **Step 10: Run full pytest to verify no other suite is broken**

Run: `uv run pytest -q 2>&1 | tail -5`

Expected: only `tests/test_adaptive_subagent_prompts.py` has failures. Empirically after T1 the count is `10 failed, 907 passed, 8 skipped` (10 failing test functions rather than ~20 individual assertions — many rewrites consolidated per-agent parametrized cases into single non-parametrized functions). Any failure outside test_adaptive_subagent_prompts.py is a regression — fix before proceeding.

- [ ] **Step 11: Commit**

```fish
git add tests/test_adaptive_subagent_prompts.py
git commit -m "test(phase3b-c2): pre-update assertions for chain-subagents refactor (RED)

2 polarity-flip rewrites + 9 obsolete test deletions (8 parametrized ×
4 agents + 1 non-parametrized = 33 cases) + 8 new test functions
(including 1 file-absence + 1 trust-path Option S assertion from
fix-up) for scan.md orchestration. After this commit + fix-up the test
suite is RED on ~11 assertions — expected; T2-T6 walk implementation
to green.

Preserves all 12 stable assertions (15-layer stack, injection fence,
import allowlist, Option D isolation guard, etc.) unchanged.

See docs/PHASE_3B_C2_PLAN.md Task 1."
```

---

### Task 2: Rewrite `plugins/screw/commands/scan.md` as Main-Session Orchestrator

**Files:**
- Modify: `plugins/screw/commands/scan.md` (full rewrite, 97 → ~280 lines)

**Rationale:** This is the main work of C2. scan.md becomes the chain-subagents orchestrator per spec §6.1. It owns: argument parsing, scan-subagent dispatch, structured-return JSON parsing, adaptive review loop (reviewer dispatch + staging + 5-section review + approve/reject + promote/execute/accumulate), finalize, summary. Phrase grammar includes `confirm-high` per spec §4.2 D2 (HIGH-risk UX friction).

**Precedent to match:**
- From PR #6 C1: 5-section review header format (`script_name`, `staged_at`, `session_id_short`, `script_sha256_prefix`) — preserve verbatim in scan.md
- From PR #6 I1: plugin-namespaced `subagent_type="screw:screw-script-reviewer"` (never bare)
- From PR #6 C1: approval phrases `approve {name}`, `approve {name} confirm-stale`, `approve {name} confirm-<8hex>` — preserve. ADD new `approve {name} confirm-high` for HIGH-risk (C2-new).
- From Phase 2: ambiguous-phrase handling (ask once; second-ambiguity → REJECT bias-toward-safety) — preserve.

- [ ] **Step 1: Read current scan.md**

Run: `cat plugins/screw/commands/scan.md`
Expected: 97 lines starting with frontmatter `name: screw:scan`.

- [ ] **Step 2: Replace the entire file with the new orchestrator content**

Write the following to `plugins/screw/commands/scan.md`:

````markdown
---
name: screw:scan
description: "Run a security scan with screw-agents. Usage: /screw:scan <agent|domain|full> [target] [--thoroughness standard|deep] [--format json|sarif|markdown] [--adaptive]"
---

# /screw:scan — Security Scan Orchestrator (main-session)

You are the MAIN-SESSION orchestrator for screw-agents scans. You chain subagents
in sequence (main session → scan subagent → return to main; main session →
reviewer subagent → return to main) per the Claude Code chain-subagents pattern
(sub-agents.md:683-689).

**Why this lives in the main session and not a subagent:** Claude Code's
architecture forbids nested subagent dispatch (sub-agents.md:711: *"Subagents
cannot spawn other subagents"*). The adaptive-mode flow requires dispatching
both a scan subagent AND a reviewer subagent; only the main session can chain
both. This slash command IS the main session — its prompt runs in the main
conversation context and has full tool surface (MCP tools, Task tool).

## Syntax

```
/screw:scan <scope> [target] [--thoroughness standard|deep] [--format json|sarif|markdown] [--adaptive]
```

## Arguments

**scope** (required): `sqli` | `cmdi` | `ssti` | `xss` | `injection` | `full`

**target** (optional, defaults to codebase root): bare path, `src/api/**` glob,
`git_diff:BASE`, `function:NAME@FILE`, `class:NAME@FILE`, `commits:RANGE`.

**--thoroughness** (default `standard`): passed to scan tool.

**--format** (default `markdown`): `json`, `sarif`, `markdown`. Passed to
`finalize_scan_results`.

**--adaptive** (optional flag, default disabled): Enable adaptive analysis mode.
Requires `.screw/config.yaml` with `script_reviewers` populated (run
`screw-agents init-trust` first) and interactive session (CI/piped contexts
MUST NOT pass `--adaptive`). The `--adaptive` flag IS the user consent.

**Example:** `/screw:scan sqli src/api/ --adaptive`

## Workflow

### Step 1: Parse arguments and dispatch scan subagent(s)

Parse scope, target, thoroughness, format, and the `--adaptive` flag.

| Scope | Dispatch |
|---|---|
| `sqli` | `screw:screw-sqli` |
| `cmdi` | `screw:screw-cmdi` |
| `ssti` | `screw:screw-ssti` |
| `xss` | `screw:screw-xss` |
| `injection` | `screw:screw-injection` (domain orchestrator, runs 4 agents) |
| `full` | See Step 1b (list_domains + per-domain loop) |

For single-scope and injection-scope: one `Task` dispatch:

```
Task(
  subagent_type="screw:screw-<scope>",
  description="Security scan — <scope>",
  prompt="""
    Run the scan with these parameters:
    - target: <parsed target spec>
    - project_root: <absolute project root>
    - thoroughness: <standard|deep>
    - adaptive_flag: <true|false>

    Follow your subagent instructions. End your turn with a fenced JSON
    code block matching the schema described in the subagent prompt's
    Step 5 (Return structured payload). DO NOT dispatch any other subagent
    — you cannot, and the main session handles all post-generation flow.
  """
)
```

After the subagent returns, proceed to Step 2.

### Step 1b: Full-scope fan-out (`scope == full`)

```
Call list_domains MCP tool:
  mcp__screw-agents__list_domains({})

Domain → orchestrator lookup (hardcoded for C2; becomes convention-driven at
Phase 6 per DEFERRED_BACKLOG). Today the table has one entry:

| list_domains entry       | orchestrator subagent_type |
|--------------------------|----------------------------|
| injection-input-handling | screw:screw-injection      |

For each domain entry in response.domains:
  - Look up the orchestrator subagent_type in the table above.
  - If the domain is NOT in the table: surface "Domain {name} has N agents but
    no orchestrator mapped in scan.md — skipped." and continue to next domain.
  - Otherwise, dispatch the orchestrator sequentially (one per domain):
    Task(
      subagent_type="<looked-up orchestrator subagent_type>",
      description="Full-scope scan — <domain>",
      prompt="""
        Run the domain scan with target <target> and project_root <root>,
        thoroughness <standard|deep>, adaptive_flag <true|false>.
        End with the fenced JSON return per your subagent Step 5.
      """
    )

Collect each orchestrator's structured return into a list
`per_orchestrator_returns`. Proceed to Step 2.
```

### Step 2: Parse each scan-subagent's structured return

Each scan-subagent ends its final turn with ONE fenced JSON code block matching
the schema in spec §5.1 (for agentic workers: see
docs/specs/2026-04-23-phase-3b-c2-nested-dispatch-fix-design.md §5).

For each return:

1. Locate the LAST fenced JSON code block in the subagent's output.
2. Parse it via `json.loads` (or mental equivalent — the JSON MUST be valid).
3. Validate `schema_version == 1` and required top-level keys are present:
   - `scan_subagent`, `session_id`, `trust_status`, `yaml_findings_accumulated`,
     `adaptive_mode_engaged`, `pending_reviews`, `scan_metadata`
4. If parse fails or schema mismatches:
   Surface to user: *"Scan subagent (<scan_subagent-name>) returned malformed
   structured output. Falling back to YAML-only mode; adaptive features
   unavailable for this scan."*
   Show the raw subagent output as a fenced code block for user inspection.
   If `session_id` can still be extracted, proceed to Step 4 (finalize); else
   report the error and stop.

5. If `adaptive_mode_engaged` is false OR `pending_reviews` is empty: skip to
   Step 4.

Collect all `pending_reviews` across orchestrators (for `full` scope). Preserve
`(session_id, scan_subagent)` per review so downstream MCP calls use the
correct session.

### Step 3: Adaptive review loop (sequential, one review per main-session turn)

Gap-type vocabulary (preserved from scan-subagent prompts): D1 = `gap.type == "context_required"` (the YAML heuristic couldn't statically resolve; `gap.evidence` has a `pattern` field). D2 = `gap.type == "unresolved_sink"` (call to a method the YAML heuristic flagged, receiver type unknown; `gap.evidence` has `method` + `receiver` fields).

For each `pending_review` in order:

#### 3a. Skip failed generations

If `pending_review.generation_status != "ok"`, surface to user:
*"Gap at `{gap.file}:{gap.line}` — generation failed (`{generation_status}`).
Skipping."* Move to next review.

#### 3b. Dispatch the semantic reviewer (Layer 0d)

Task dispatch from main session:

```
Task(
  subagent_type="screw:screw-script-reviewer",
  description=f"Layer 0d semantic review of {pending_review.script_name}",
  prompt=f"""## Rationale
{pending_review.rationale}

## Script source
{pending_review.script_source}
""",
)
```

The plugin-namespaced `screw:` prefix is REQUIRED (I1 hardening from PR #6).

Parse the reviewer's return. It MUST be ONLY a JSON object matching the
`SemanticReviewReport` Pydantic model (see src/screw_agents/models.py) with
fields: `risk_score` (`"low"` | `"medium"` | `"high"`), `flagged_patterns`
(list[str]), `unusual_imports` (list[str]), `control_flow_summary` (str),
`estimated_runtime_ms` (int).

If reviewer dispatch fails or returns malformed JSON:
*"Layer 0d reviewer returned malformed output for `{pending_review.script_name}`.
Skipping this gap (malformed review is a safety signal — do not proceed)."*
Move to next review.

#### 3c. Stage the reviewed script (main-session MCP call)

```
mcp__screw-agents__stage_adaptive_script({
  "project_root": <absolute project root>,
  "script_name": pending_review.script_name,
  "source": pending_review.script_source,
  "meta": {
    "name": pending_review.script_name,
    "created": <current ISO8601 timestamp>,
    "created_by": <script_reviewers[0].email from .screw/config.yaml>,
    "domain": <derived from pending_review.gap.agent>,
    "description": f"Generated for {pending_review.gap.type} gap at "
                   f"{pending_review.gap.file}:{pending_review.gap.line}. "
                   f"Evidence: {pending_review.gap.evidence.get('method') or pending_review.gap.evidence.get('pattern') or 'see gap.evidence'}.",
    "target_patterns": [<inferred: gap.evidence.method if gap.type == "unresolved_sink" (D2), else gap.evidence.pattern (D1)>],
  },
  "session_id": pending_review.session_id,
  "target_gap": {
    "type": pending_review.gap.type,
    "file": pending_review.gap.file,
    "line": pending_review.gap.line,
    "agent": pending_review.gap.agent,
  }
})
```

Capture from the response: `script_sha256_prefix`, `session_id_short`,
`staged_at`. On `status != "staged"` (e.g., `stage_name_collision`,
`invalid_script_name`, `invalid_session_id`), render the tool's error message
verbatim to the user, move to next review.

#### 3d. Compose the 5-section review and END your main-session turn

Compose ONE markdown message to the user with the header and five sections
exactly as follows. The header carries trust-relevant metadata so the user can
verify session and sha prefix:

````markdown
## Adaptive script review — awaiting approval

{if semantic_report.risk_score == "high":}
⚠ **LAYER 0D HIGH RISK** — the semantic reviewer flagged this script as HIGH
risk. Read Section 2 carefully. Approval requires the explicit phrase
`approve {script_name} confirm-high` (bare `approve {script_name}` is rejected
for HIGH-risk scripts per spec §4.2 D2).
{endif}

**Script:** `{script_name}`
**Staged:** {staged_at}  |  **Session:** `{session_id_short}`  |  **SHA256:** `{script_sha256_prefix}`

### 1. Rationale
{pending_review.rationale, prose-formatted}

### 2. Semantic reviewer (Layer 0d)
- **Risk:** {semantic_report.risk_score} (low/medium/high)
- **Control flow:** {semantic_report.control_flow_summary}
- **Estimated runtime:** {semantic_report.estimated_runtime_ms}ms
- **Flagged patterns:**
  {bullet list, or "_none_"}
- **Unusual imports:**
  {bullet list, or "_none_"}

### 3. AST lint (Layer 1)
- **Status:** {pending_review.lint_report.status}
- **Violations:**
  {bullet list "line N: rule — message", or "_none_" on pass}
  {if status == "syntax_error", show details as indented block}

### 4. Script content (sha256 prefix `{script_sha256_prefix}`)

```python
{pending_review.script_source}
```

### 5. Your decision

Type **`approve {script_name}`** to promote, sign, and execute.
{if risk_score == "high":}
HIGH-risk scripts require the explicit confirmation: **`approve {script_name} confirm-high`**. Bare `approve {script_name}` will be rejected for HIGH-risk
scripts — this is a deliberate speed bump (spec §4.2 D2).
{endif}

Type **`reject {script_name} <optional reason>`** to discard.

Staging-specific confirmations (if applicable):
- If staging is older than 24h: `approve {script_name} confirm-stale`
- If the approval registry was lost: `approve {script_name} confirm-<8hex-prefix>`

````

**Then END your main-session turn.** The user's next message begins the next
turn; parse their response in Step 3e.

#### 3e. Parse user response (next main-session turn)

Match the user's input against the current `pending_review.script_name`:

**Accepted phrase variants:**

| Phrase | Action | Allowed when |
|---|---|---|
| `approve <name>` | Normal promote | risk_score ∈ {"low", "medium"} |
| `approve <name> confirm-high` | HIGH-risk promote | risk_score == "high" (required); also OK if lower (belt-and-suspenders) |
| `approve <name> confirm-stale` | Stale staging promote | set `confirm_stale: true` |
| `approve <name> confirm-<8hex>` | Fallback prefix promote | set `confirm_sha_prefix: "<8hex>"` |
| `reject <name> <optional reason>` | Decline | always |

**HIGH-risk rejection of bare approve:**
If `semantic_report.risk_score == "high"` and user typed `approve <name>` (no
`confirm-high`), respond:
*"Script `{script_name}` was flagged HIGH risk by the Layer 0d reviewer
(section 2 of the review). HIGH-risk scripts require explicit
`approve {script_name} confirm-high` (spec §4.2 D2). Either re-type with the
suffix, or `reject {script_name}`."*
END turn; await user's re-attempt.

**Ambiguous response:**
If the response is not a clean approve/reject phrase for THIS
`pending_review.script_name` (e.g., bare `approve` without name, or approve
with a DIFFERENT script name), ask ONCE:
*"Ambiguous response. Type `approve {script_name}` (or the confirm-high /
confirm-stale / confirm-<hex> variant) or `reject {script_name} <optional reason>`."*
END turn. On a second ambiguous response: treat as REJECT (bias toward safety
per PR #6 precedent in screw-sqli.md:432-438).

**On approve (any valid variant):**

```
mcp__screw-agents__promote_staged_script({
  "project_root": <absolute project root>,
  "script_name": pending_review.script_name,
  "session_id": pending_review.session_id,
  "confirm_stale": <true if confirm-stale variant, else false>,
  "confirm_sha_prefix": <"<8hex>" if confirm-<8hex> variant, else null>
})
```

Expected on success: `status == "signed"`, `script_path`, `meta_path`,
`signed_by`, `sha256`, `session_id`, `promoted_via_fallback`.

On error: render the tool's message verbatim (taxonomy: `staging_not_found`,
`stale_staging`, `invalid_registry_entry`, `tamper_detected`,
`invalid_lifecycle_state`, `fallback_required`, `fallback_sha_mismatch`,
`invalid_staged_meta`, `sign_failed`, `invalid_session_id`,
`custom_scripts_collision`). `tamper_detected` is LOUDLY SURFACED — do not
retry. Move to next review.

On `status == "signed"`: proceed to 3f.

**On reject:**

```
mcp__screw-agents__reject_staged_script({
  "project_root": <absolute project root>,
  "script_name": pending_review.script_name,
  "session_id": pending_review.session_id,
  "reason": <free-text reason or null>
})
```

Accept `status == "rejected"` OR `status == "already_rejected"` (idempotent).
Brief user confirmation. Move to next review.

#### 3f. Execute the signed script

```
mcp__screw-agents__execute_adaptive_script({
  "project_root": <absolute project root>,
  "script_name": pending_review.script_name,
  "wall_clock_s": 30
})
```

Note: `execute_adaptive_script` does NOT accept a `session_id` parameter — the
engine signature is `(project_root, script_name, wall_clock_s, skip_trust_checks)`
only. Omitting session_id here matches the engine's T18a deviation 1 locked
in C1 PR #6's test-11 regression guard.

On `status == "ok"` and `findings` non-empty:

```
mcp__screw-agents__accumulate_findings({
  "project_root": <absolute project root>,
  "findings_chunk": <findings from execute response>,
  "session_id": pending_review.session_id
})
```

Brief confirmation: *"Adaptive script `{script_name}` promoted, executed,
produced {N} finding(s). Continuing."*

On `status == "sandbox_failure"` OR `returncode != 0`, render the failure
diagnostic verbatim (this format matches the PR #6 per-agent spec):

````markdown
**Adaptive script `{script_name}` execution failed**

Return code: {returncode}
Wall clock: {wall_clock_s}s
Killed by timeout: {killed_by_timeout}

Standard error output:
```
{stderr}
```

The script is retained at `.screw/custom-scripts/{script_name}.py` for your
inspection. Run `/screw:adaptive-cleanup remove {script_name}` to clear it.
````

Do NOT accumulate findings from a failed execution. Move to next review (do NOT
abort the entire adaptive flow — other reviews may succeed).

After all `pending_reviews` are processed, proceed to Step 4.

### Step 4: Finalize

For single-scope (sqli/cmdi/ssti/xss/injection): ONE finalize per session_id.

For full scope: one finalize per orchestrator session_id (each domain has its
own session and writes to `.screw/findings/<session>/`):

```
For each (session_id, scan_metadata, agent_names) across dispatched orchestrators:
  mcp__screw-agents__finalize_scan_results({
    "project_root": <absolute project root>,
    "session_id": session_id,
    "agent_names": agent_names,  // e.g., ["sqli"] for per-agent, ["sqli","cmdi","ssti","xss"] for injection
    "scan_metadata": scan_metadata  // includes target + timestamp
  })
```

Capture each response's `files_written` paths, `summary` counts, and
`exclusions_applied`.

### Step 5: Present consolidated summary

1. Finding count + severity breakdown (aggregated across orchestrators for
   full scope).
2. **MANDATORY**: if any orchestrator's `trust_status` had non-zero quarantine
   counts, include the trust-verification section BEFORE the per-orchestrator
   breakdown:
   - `N exclusions quarantined. Review with screw-agents validate-exclusion <id>
     or bulk-sign with screw-agents migrate-exclusions.`
   - `M scripts quarantined. Review with screw-agents validate-script <name>.`
3. Per-orchestrator report paths (from `finalize` responses).
4. Adaptive summary: how many pending_reviews → how many promoted → how many
   rejected → how many skipped (failed review, malformed output, sandbox
   failure).
5. Any `confirm-high` approvals: note in summary for audit visibility.
6. Offer: "Apply a fix?", "Mark a finding as false positive?", "Run another
   agent?"
````

- [ ] **Step 3: Run scan.md-specific test assertions — verify they go GREEN**

Run: `uv run pytest tests/test_adaptive_subagent_prompts.py::test_scan_md_references_all_required_orchestration_mcp_tools tests/test_adaptive_subagent_prompts.py::test_scan_md_dispatches_plugin_namespaced_reviewer tests/test_adaptive_subagent_prompts.py::test_scan_md_phrase_grammar_locked tests/test_adaptive_subagent_prompts.py::test_scan_md_contains_subagent_return_schema_keys tests/test_adaptive_subagent_prompts.py::test_scan_md_does_not_reference_deleted_full_review_subagent tests/test_adaptive_subagent_prompts.py::test_scan_md_contains_full_scope_list_domains_branch -v`

Expected: ALL 6 scan.md-related new assertions GREEN (the file-absence test still RED since we haven't deleted screw-full-review.md yet; that's T3).

- [ ] **Step 4: Run full pytest — verify no other regression**

Run: `uv run pytest -q 2>&1 | tail -5`

Expected: count of failing tests has dropped (scan.md assertions now green); remaining failures are per-agent + file-absence.

- [ ] **Step 5: Commit**

```fish
git add plugins/screw/commands/scan.md
git commit -m "feat(phase3b-c2): rewrite scan.md as main-session orchestrator

Chain-subagents pattern per sub-agents.md:683-689. scan.md becomes the
main-session orchestrator: dispatches scan subagent → parses structured
return → dispatches screw:screw-script-reviewer per pending_review →
stages → shows 5-section review → processes approve/reject → promotes +
executes + accumulates → finalizes.

Phrase grammar adds confirm-high (spec §4.2 D2): HIGH-risk scripts
require explicit approve {name} confirm-high for UX friction against
autopilot approval.

Full-scope branch (Step 1b) uses list_domains + per-domain dispatch
(Option A fold+delete per spec §4.3; full-review.md deletion in T3).

See docs/PHASE_3B_C2_PLAN.md Task 2."
```

---

### Task 3: Delete `plugins/screw/agents/screw-full-review.md`

**Files:**
- Delete: `plugins/screw/agents/screw-full-review.md`

**Rationale:** screw-full-review.md contains a second instance of the nested-subagent-dispatch anti-pattern (it dispatches `screw-injection` and future domain orchestrators via the Agent tool — architecturally blocked per sub-agents.md:324). Spec §4.3 D3 Option A: fold its logic into scan.md's `full` branch (done in T2 Step 1b) and delete the file.

- [ ] **Step 1: Verify screw-full-review.md exists before deletion**

Run: `ls plugins/screw/agents/screw-full-review.md`
Expected: file listed.

- [ ] **Step 2: Grep for references elsewhere (should be isolated)**

```fish
grep -rn "screw-full-review\|screw:screw-full-review" plugins/ docs/ tests/ CLAUDE.md 2>&1 | grep -v "^Binary" | grep -v "\.worktrees/"
```

Expected: references in:
- `plugins/screw/commands/scan.md` (post-T2: the dispatch table row `| full | screw-full-review |` should be GONE from T2's rewrite; verify zero matches in scan.md)
- `docs/AGENT_CATALOG.md` line 24: "Full-review orchestrator | 1" — this is a doc count reference; update in T9 cross-plan sync if needed
- `docs/DEFERRED_BACKLOG.md` — historical notes (acceptable)
- `docs/PHASE_3B_C1_PLAN.md` — historical reference (read-only, acceptable)
- `docs/specs/2026-04-23-phase-3b-c2-nested-dispatch-fix-design.md` — this spec itself references it (acceptable)
- This plan itself (acceptable)
- `tests/test_adaptive_subagent_prompts.py` — the file-absence assertion from T1 (acceptable)

Any reference in production code (plugins/, src/) OTHER than scan.md's scope lookup is unexpected — investigate before deletion.

- [ ] **Step 3: Delete the file**

Run: `git rm plugins/screw/agents/screw-full-review.md`
Expected: git stages the deletion.

- [ ] **Step 4: Re-grep to confirm clean**

Run: `grep -rn "screw-full-review" plugins/ src/ 2>&1`
Expected: zero output (no production-code references anywhere).

- [ ] **Step 5: Run file-absence test assertion — verify GREEN**

Run: `uv run pytest tests/test_adaptive_subagent_prompts.py::test_screw_full_review_md_file_is_deleted tests/test_adaptive_subagent_prompts.py::test_scan_md_does_not_reference_deleted_full_review_subagent -v`

Expected: both GREEN.

- [ ] **Step 6: Commit**

```fish
git commit -m "refactor(phase3b-c2): delete screw-full-review.md (Option A fold+delete)

screw-full-review.md contained a second instance of the nested-subagent-
dispatch anti-pattern (Agent-tool dispatch of screw-injection and future
domain orchestrators — architecturally blocked per sub-agents.md:324).

Its logic folds into scan.md's full-scope branch (list_domains +
per-domain dispatch, T2 Step 1b).

See docs/PHASE_3B_C2_PLAN.md Task 3 + spec §4.3 D3."
```

---

### Task 4: Truncate `plugins/screw/agents/screw-sqli.md`

**Files:**
- Modify: `plugins/screw/agents/screw-sqli.md` (600 → ~275 lines)

**Rationale:** Apply spec §6.2 truncation plan. The scan subagent retains scan + Step 3.5 preamble + Steps 3.5a (record_context_required_match) + 3.5b (detect_coverage_gaps) + 3.5c (Layer 0f quota) + 3.5d-A (Layer 0e blocklist) + 3.5d-B (derive script_name) + 3.5d-C (Layers 0a-c generation prompt) + 3.5d-D (generate + hash6) + 3.5d-E (Layer 1 lint). Everything AFTER 3.5d-E (Step 3.5d-F through 3.5d-K + old Step 4 + Step 5) gets replaced by a streamlined "emit pending_review entry + return structured payload" block.

**Precedent:** T5/T6/T7 will apply this exact same truncation to cmdi/ssti/xss — the existing test `test_adaptive_section_identical_modulo_agent_name` enforces byte-identical content modulo agent name.

- [ ] **Step 1: Read current screw-sqli.md**

Run: `wc -l plugins/screw/agents/screw-sqli.md`
Expected: 600 lines.

- [ ] **Step 2: Update frontmatter tools list**

Replace lines 4-20 (the `tools:` block) with:

```yaml
tools:
  - mcp__screw-agents__scan_sqli
  - mcp__screw-agents__accumulate_findings
  - mcp__screw-agents__record_exclusion
  - mcp__screw-agents__record_context_required_match
  - mcp__screw-agents__detect_coverage_gaps
  - mcp__screw-agents__lint_adaptive_script
  - Read
  - Glob
  - Grep
```

Removed (moved to scan.md main session):
- `mcp__screw-agents__stage_adaptive_script`
- `mcp__screw-agents__promote_staged_script`
- `mcp__screw-agents__reject_staged_script`
- `mcp__screw-agents__execute_adaptive_script`
- `mcp__screw-agents__finalize_scan_results`
- `Task`

- [ ] **Step 3: Delete old Step 3.5d-F through old Step 5 (through end of file)**

In the current file, delete lines 298–600 (file ends at line 600; the range
starts at the old `##### F. Layer 0d — Semantic review via `screw:screw-script-reviewer` subagent`
heading at line 298 and goes through the old `## Confidence Calibration`
block at lines 596–600). The new content re-introduces its own `## Confidence
Calibration` at the very end of Step 4's append.

Verify with:
```fish
sed -n '296,302p' plugins/screw/agents/screw-sqli.md
sed -n '596,600p' plugins/screw/agents/screw-sqli.md
```
Expected: line 298 starts with `##### F. Layer 0d`, line 600 is the last
content line.

- [ ] **Step 4: Append new Step 3.5d-F + Step 4 + Step 5**

After the current Step 3.5d-E content (ending around line 296), append:

````markdown
##### F. Size-cap safety check + emit pending_review entry

**Pre-emission size cap (relocated from old Step 3.5d-H pre-render check):**
If `len(source.splitlines()) > 400`, do NOT emit the script source to main
session (it would dominate the 5-section review surface and may be an LLM
resource-exhaustion symptom). Instead append a pending_review entry with
`generation_status: "script_too_large"` and omit `script_source`. Main
session surfaces the per-gap failure to the user without showing the
pathological script. Continue to next gap.

A legitimate adaptive script is 50–150 lines; anything over 400 is either
the LLM losing focus or target-code attempting to inflate the review
surface. This check is defense-in-depth (Layer 5 sandbox still bounds
actual execution, but keeping the gate here means HIGH-risk review
surfaces never reach the user's attention).

Otherwise, after Step E's lint returns `pass` (or `fail` with violations to
surface; continue to F either way — lint failures are INFORMATIVE, not retry
triggers), build a `pending_review` dict per the schema spec
(docs/specs/2026-04-23-phase-3b-c2-nested-dispatch-fix-design.md §5.1):

```json
{
  "gap": {
    "type": "<gap.type>",
    "file": "<gap.file>",
    "line": <gap.line>,
    "agent": "sqli",
    "evidence": <gap.evidence>
  },
  "script_name": "<computed in Step 3.5d-B>",
  "script_source": "<the generated source from Step 3.5d-D, verbatim>",
  "rationale": "<your rationale from Step 3.5d-C, prose-formatted>",
  "lint_report": {
    "status": "<pass|fail|syntax_error from Step 3.5d-E>",
    "violations": [<violations list from the lint response, or empty>]
  },
  "fence_token": "<32-hex token from Step 3.5d-C>",
  "generation_status": "ok"
}
```

Append this dict to an in-memory `pending_reviews: list[dict]` variable that
you maintain across the per-gap loop. On generation failures (Step 3.5d-D
syntax error after retry, fence collision, name-regex failure, or the
400-line size cap in this step above), emit an entry with `generation_status`
set to the appropriate failure code (`"syntax_error_after_retry"`,
`"fence_collision"`, `"invalid_name"`, `"script_too_large"`) and omit
`script_source` — main session will surface the failure to the user.

Do NOT call stage_adaptive_script. Do NOT dispatch screw:screw-script-reviewer.
Do NOT call promote/execute/reject/finalize. The main session orchestrator
(/screw:scan) handles all post-generation flow (reviewer dispatch, staging,
5-section review, approve/reject, promote + execute + accumulate).

Increment Layer 0f quota counter: `scripts_generated_this_session += 1`.
Move to next gap.

### Step 4: Persist YAML findings

Call `accumulate_findings` with your YAML findings (the findings you produced
in Step 2 before any adaptive-mode work) — using the same session_id from
Step 3.5a's first `record_context_required_match` call (or null if Step 3.5a
was not executed):

```
mcp__screw-agents__accumulate_findings({
  "project_root": "<same project root as Step 1>",
  "findings_chunk": [<your YAML findings from Step 2>],
  "session_id": "<session_id from Step 3.5a, or null>"
})
```

The response contains `session_id` (server generates one on first call). Save
it — Step 5's structured return needs it.

**Do NOT call finalize_scan_results.** Main session owns the finalize call so
it can consolidate findings across adaptive script executions with your YAML
findings in the same session.

### Step 5: Return structured payload to main session

END your turn by emitting ONE fenced JSON code block with the following
structure. Emit NOTHING after the fenced block — the main session parses the
LAST fenced JSON block.

```json
{
  "schema_version": 1,
  "scan_subagent": "screw-sqli",
  "session_id": "<session_id from Step 4's accumulate_findings response>",
  "trust_status": <trust_status dict from Step 1 scan response>,
  "yaml_findings_accumulated": <count of YAML findings persisted in Step 4>,
  "adaptive_mode_engaged": <true if Step 3.5 executed, else false>,
  "adaptive_quota_note": <null or Layer 0f quota exhausted message from Step 3.5c>,
  "pending_reviews": [<pending_review entries built in Step 3.5d-F, in order>],
  "blocklist_skipped_gaps": [<gaps skipped by Step 3.5d-A Layer 0e blocklist, with file/line/matched_string>],
  "scan_metadata": {
    "target": "<what was scanned, human-readable>",
    "target_spec": <target spec dict>,
    "timestamp": "<ISO8601>"
  }
}
```

On non-adaptive scans (user did NOT pass `--adaptive`, OR `.screw/config.yaml`
has `adaptive: false` and no `--adaptive` override), the `pending_reviews`
list is empty and `adaptive_mode_engaged` is false — main session skips the
adaptive review loop.

After emitting the fenced JSON, END your turn. Do not compose any conversational
response, any summary, any follow-up offer — main session owns those.

## Confidence Calibration

- **High**: Direct string concat/interpolation into SQL with user input, no parameterization
- **Medium**: Dynamic query where parameterization unclear, or input through unknown wrapper
- **Low**: Patterns resembling SQLi but likely safe due to framework guarantees
````

- [ ] **Step 5: Verify the truncation is correct**

Run: `wc -l plugins/screw/agents/screw-sqli.md`
Expected: ~275 lines (down from 600).

Run: `grep -c "stage_adaptive_script\|promote_staged_script\|reject_staged_script\|execute_adaptive_script\|screw-script-reviewer\|Task tool" plugins/screw/agents/screw-sqli.md`
Expected: 0.

- [ ] **Step 6: Run sqli-specific test assertions — verify they go GREEN**

Run: `uv run pytest tests/test_adaptive_subagent_prompts.py -k "sqli or per_agent or adaptive_section" -v 2>&1 | tail -40`

Expected: sqli-specific assertions GREEN. cmdi/ssti/xss still RED (T5/T6/T7 not done yet). The `test_adaptive_section_identical_modulo_agent_name` test will FAIL here — that's expected because the other 3 agents haven't been truncated yet. It goes green after T7.

- [ ] **Step 7: Commit**

```fish
git add plugins/screw/agents/screw-sqli.md
git commit -m "refactor(phase3b-c2): truncate screw-sqli.md adaptive flow

Scan subagent now does scan → generation → lint (Steps 1-3.5d-E preserved),
then returns a structured JSON payload per spec §5.1. Drops post-generation
responsibilities: staging, screw:screw-script-reviewer dispatch, 5-section
review, approve/reject, promote/execute/reject/accumulate/finalize. Those
now live in scan.md main-session orchestrator (T2).

Frontmatter removes stage/promote/reject/execute/Task/finalize_scan_results
— all moved to main session.

The 4 per-agent files (sqli/cmdi/ssti/xss) must stay byte-identical modulo
agent name; T5/T6/T7 apply this truncation to the other 3.

See docs/PHASE_3B_C2_PLAN.md Task 4."
```

---

### Task 5: Replicate sqli truncation to `screw-cmdi.md`

**Files:**
- Modify: `plugins/screw/agents/screw-cmdi.md` (600 → ~275 lines)

**Rationale:** The 4 per-agent files must stay byte-identical modulo agent name (`test_adaptive_section_identical_modulo_agent_name`). Apply T4's truncation with `sqli` → `cmdi` substitution. The other existing differences (CWE-78 vs CWE-89, domain knowledge text, confidence calibration) are outside the adaptive section and stay.

- [ ] **Step 1: Confirm current cmdi.md size**

Run: `wc -l plugins/screw/agents/screw-cmdi.md`
Expected: 600 lines.

- [ ] **Step 2: Overlay sqli's truncated adaptive section onto cmdi.md**

cmdi.md has cmdi-specific non-adaptive content (CWE-78 semantics, shell
metacharacters, domain knowledge) that is NOT in sqli.md. Preserve that.
Replace ONLY the adaptive section (Step 3.5 through end of file) with the
truncated version from sqli, agent-name-substituted.

Procedure:

a. Locate `### Step 3.5: Adaptive Mode` heading in current cmdi.md. Expected
   line ≈ 91 (matches sqli's line numbering pre-T4 since the adaptive section
   starts at the same place). Confirm with:
   `grep -n "^### Step 3.5: Adaptive Mode" plugins/screw/agents/screw-cmdi.md`

b. Delete cmdi.md from that line through end of file.

c. Read sqli.md from its `### Step 3.5: Adaptive Mode` heading through end of
   file (post-T4 truncated state). That block becomes the replacement payload.

d. Substitute in the replacement payload before pasting into cmdi.md:
   - `sqli` → `cmdi` (globally)
   - `CWE-89` → `CWE-78`
   - `SQL Injection` (wherever the full phrase appears as prose or heading
     anchor) → `Command Injection`
   - `scan_sqli` → `scan_cmdi` (if this tool name appears anywhere in the
     truncated adaptive section). Verify with:
     `grep -n "scan_sqli" plugins/screw/agents/screw-sqli.md` — any hit lines
     in the adaptive-section range (lines 91+) need substitution.
   - `"agent": "sqli"` → `"agent": "cmdi"` inside the pending_review JSON
     schema in Step 3.5d-F
   - `"scan_subagent": "screw-sqli"` → `"scan_subagent": "screw-cmdi"` in
     Step 5's fenced JSON return schema

e. RESTORE the literal `sqli/cmdi/ssti/xss` self-reference hint in Step 3.5d-B
   (current sqli text: `"this subagent's name: sqli/cmdi/ssti/xss"`). After
   step d's global `sqli → cmdi` substitution, this becomes
   `cmdi/cmdi/ssti/xss` — WRONG. Restore to `sqli/cmdi/ssti/xss` with a
   targeted sed on the final cmdi.md:
   `sed -i 's|cmdi/cmdi/ssti/xss|sqli/cmdi/ssti/xss|g' plugins/screw/agents/screw-cmdi.md`

f. Paste the substituted payload into cmdi.md at the location where the old
   adaptive section was deleted (Step b).

g. Update cmdi.md frontmatter `tools:` list (lines 4-20) per T4 Step 2's
   pattern: remove `stage_adaptive_script`, `promote_staged_script`,
   `reject_staged_script`, `execute_adaptive_script`, `finalize_scan_results`,
   `Task`. Keep `scan_cmdi` (NOT `scan_sqli`), `accumulate_findings`,
   `record_exclusion`, `record_context_required_match`, `detect_coverage_gaps`,
   `lint_adaptive_script`, `Read`, `Glob`, `Grep`.

- [ ] **Step 3: Verify byte-identical-modulo-agent-name invariant**

Run a diff of the adaptive section across sqli and cmdi, normalized for agent
name:

```fish
diff \
  <(sed -n '91,$p' plugins/screw/agents/screw-sqli.md | sed 's/sqli/AGENT/g') \
  <(sed -n '91,$p' plugins/screw/agents/screw-cmdi.md | sed 's/cmdi/AGENT/g') \
  | head -30
```

Expected: only differences are the domain-specific lines (e.g., CWE-89 vs
CWE-78; tool names like `scan_sqli` vs `scan_cmdi` if they appear in the
truncated content; confidence-calibration bullet wording). The adaptive
section SHOULD be byte-identical after agent normalization.

- [ ] **Step 4: Run cmdi-specific tests**

Run: `uv run pytest tests/test_adaptive_subagent_prompts.py -k "cmdi or identical" -v 2>&1 | tail -20`
Expected: cmdi-specific tests GREEN.

- [ ] **Step 5: Commit**

```fish
git add plugins/screw/agents/screw-cmdi.md
git commit -m "refactor(phase3b-c2): replicate sqli truncation to screw-cmdi.md

Same truncation pattern as T4: drop post-generation flow (stage/review/
promote/execute/accumulate/finalize) from the scan subagent; add pending_review
emit + structured JSON return.

Byte-identical to sqli.md's adaptive section modulo agent-name substitution
(sqli→cmdi) + domain-specific CWE reference (CWE-89→CWE-78).

See docs/PHASE_3B_C2_PLAN.md Task 5."
```

---

### Task 6: Replicate sqli truncation to `screw-ssti.md`

**Files:**
- Modify: `plugins/screw/agents/screw-ssti.md` (600 → ~275 lines)

- [ ] **Step 1: Confirm current ssti.md size**

Run: `wc -l plugins/screw/agents/screw-ssti.md`
Expected: 600 lines.

- [ ] **Step 2: Overlay sqli's truncated adaptive section onto ssti.md**

ssti.md has ssti-specific non-adaptive content (CWE-1336 semantics, Jinja2 /
Mako / Twig template engine specifics) that is NOT in sqli.md. Preserve that.
Replace ONLY the adaptive section (Step 3.5 through end of file) with the
truncated version from sqli, agent-name-substituted.

Procedure:

a. Locate `### Step 3.5: Adaptive Mode` heading in current ssti.md. Expected
   line ≈ 91. Confirm with:
   `grep -n "^### Step 3.5: Adaptive Mode" plugins/screw/agents/screw-ssti.md`

b. Delete ssti.md from that line through end of file.

c. Read sqli.md from its `### Step 3.5: Adaptive Mode` heading through end of
   file (post-T4 truncated state). That block becomes the replacement payload.

d. Substitute in the replacement payload before pasting into ssti.md:
   - `sqli` → `ssti` (globally)
   - `CWE-89` → `CWE-1336`
   - `SQL Injection` → `Server-Side Template Injection`
   - `scan_sqli` → `scan_ssti` (verify with `grep -n "scan_sqli" plugins/screw/agents/screw-sqli.md`; any hit in adaptive-section lines needs substitution)
   - `"agent": "sqli"` → `"agent": "ssti"` in pending_review schema (Step 3.5d-F)
   - `"scan_subagent": "screw-sqli"` → `"scan_subagent": "screw-ssti"` in Step 5 return schema

e. RESTORE the literal `sqli/cmdi/ssti/xss` self-reference hint. After the
   global `sqli → ssti` sub, it becomes `ssti/cmdi/ssti/xss` — WRONG. Restore:
   `sed -i 's|ssti/cmdi/ssti/xss|sqli/cmdi/ssti/xss|g' plugins/screw/agents/screw-ssti.md`

f. Paste the substituted payload into ssti.md at the location where the old
   adaptive section was deleted.

g. Update ssti.md frontmatter `tools:` list (lines 4-20): remove the 6 listed
   in T4 Step 2; keep `scan_ssti` (NOT `scan_sqli`), `accumulate_findings`,
   `record_exclusion`, `record_context_required_match`, `detect_coverage_gaps`,
   `lint_adaptive_script`, `Read`, `Glob`, `Grep`.

- [ ] **Step 3: Verify byte-identical-modulo-agent-name invariant**

```fish
diff \
  <(sed -n '91,$p' plugins/screw/agents/screw-sqli.md | sed 's/sqli/AGENT/g') \
  <(sed -n '91,$p' plugins/screw/agents/screw-ssti.md | sed 's/ssti/AGENT/g') \
  | head -30
```

Expected: only domain-specific line differences (CWE-89 vs CWE-1336; tool name;
confidence-calibration wording). Adaptive section byte-identical after
normalization.

- [ ] **Step 4: Run ssti-specific tests**

Run: `uv run pytest tests/test_adaptive_subagent_prompts.py -k "ssti or identical" -v 2>&1 | tail -20`
Expected: ssti-specific tests GREEN.

- [ ] **Step 5: Commit**

```fish
git add plugins/screw/agents/screw-ssti.md
git commit -m "refactor(phase3b-c2): replicate sqli truncation to screw-ssti.md

Same overlay procedure as T5 (cmdi): preserve ssti's non-adaptive content
(CWE-1336 / template-engine knowledge); replace adaptive section with
agent-name-substituted content from sqli.

See docs/PHASE_3B_C2_PLAN.md Task 6."
```

---

### Task 7: Replicate sqli truncation to `screw-xss.md`

**Files:**
- Modify: `plugins/screw/agents/screw-xss.md` (600 → ~275 lines)

- [ ] **Step 1: Confirm current xss.md size**

Run: `wc -l plugins/screw/agents/screw-xss.md`
Expected: 600 lines.

- [ ] **Step 2: Overlay sqli's truncated adaptive section onto xss.md**

xss.md has xss-specific non-adaptive content (CWE-79, reflected/stored/DOM
distinctions, sanitizer patterns, framework-specific escaping). Preserve that.
Replace ONLY the adaptive section (Step 3.5 through end of file) with the
truncated version from sqli, agent-name-substituted.

Procedure:

a. Locate `### Step 3.5: Adaptive Mode` heading in current xss.md. Expected
   line ≈ 91. Confirm with:
   `grep -n "^### Step 3.5: Adaptive Mode" plugins/screw/agents/screw-xss.md`

b. Delete xss.md from that line through end of file.

c. Read sqli.md from its `### Step 3.5: Adaptive Mode` heading through end of
   file (post-T4 truncated state). That block becomes the replacement payload.

d. Substitute in the replacement payload before pasting into xss.md:
   - `sqli` → `xss` (globally)
   - `CWE-89` → `CWE-79`
   - `SQL Injection` → `Cross-Site Scripting`
   - `scan_sqli` → `scan_xss` (verify with `grep -n "scan_sqli" plugins/screw/agents/screw-sqli.md`; any hit in adaptive-section lines needs substitution)
   - `"agent": "sqli"` → `"agent": "xss"` in pending_review schema
   - `"scan_subagent": "screw-sqli"` → `"scan_subagent": "screw-xss"` in Step 5 return schema

e. RESTORE the literal `sqli/cmdi/ssti/xss` self-reference hint. After the
   global `sqli → xss` sub, it becomes `xss/cmdi/ssti/xss` — WRONG. Restore:
   `sed -i 's|xss/cmdi/ssti/xss|sqli/cmdi/ssti/xss|g' plugins/screw/agents/screw-xss.md`

f. Paste the substituted payload into xss.md at the location where the old
   adaptive section was deleted.

g. Update xss.md frontmatter `tools:` list (lines 4-20): remove the 6 listed
   in T4 Step 2; keep `scan_xss` (NOT `scan_sqli`), `accumulate_findings`,
   `record_exclusion`, `record_context_required_match`, `detect_coverage_gaps`,
   `lint_adaptive_script`, `Read`, `Glob`, `Grep`.

- [ ] **Step 3: Verify byte-identical-modulo-agent-name invariant AND full 4-way consistency**

Pairwise diff vs sqli:
```fish
diff \
  <(sed -n '91,$p' plugins/screw/agents/screw-sqli.md | sed 's/sqli/AGENT/g') \
  <(sed -n '91,$p' plugins/screw/agents/screw-xss.md | sed 's/xss/AGENT/g') \
  | head -30
```
Expected: only domain-specific lines differ.

Then run the 4-way locking test (the critical invariant across all per-agent files):

```fish
uv run pytest tests/test_adaptive_subagent_prompts.py::test_adaptive_section_identical_modulo_agent_name -v
```

Expected: GREEN. This is the gate — if any of the 4 drifted, fix before proceeding.

- [ ] **Step 4: Run all per-agent tests**

Run: `uv run pytest tests/test_adaptive_subagent_prompts.py -v 2>&1 | tail -30`
Expected: all per-agent assertions GREEN (injection orchestrator still RED — that's T8).

- [ ] **Step 5: Commit**

```fish
git add plugins/screw/agents/screw-xss.md
git commit -m "refactor(phase3b-c2): replicate sqli truncation to screw-xss.md

Same overlay procedure as T5/T6. All 4 per-agent files (sqli/cmdi/ssti/xss)
now share byte-identical adaptive-section content modulo agent-name
substitution (locked by test_adaptive_section_identical_modulo_agent_name).

See docs/PHASE_3B_C2_PLAN.md Task 7."
```

---

### Task 8: Truncate `plugins/screw/agents/screw-injection.md` Orchestrator

**Files:**
- Modify: `plugins/screw/agents/screw-injection.md` (231 → ~175 lines)

**Rationale:** Apply spec §6.4 truncation. The orchestrator keeps scan_domain pagination, trust handling, record_context_required_match across all 4 agents inline, detect_coverage_gaps aggregation, shared Layer 0f quota, per-gap dispatching to Steps 3.5d-A through 3.5d-E (delegated to per-agent Step 3.5d). Drops per-gap dispatch of reviewer/stage/promote/reject/execute (those move to main session). Drops old finalize (main calls finalize).

- [ ] **Step 1: Read current screw-injection.md**

Run: `wc -l plugins/screw/agents/screw-injection.md`
Expected: 231 lines.

- [ ] **Step 2: Update frontmatter tools list**

Replace the current `tools:` block (around lines 4-20) with:

```yaml
tools:
  - mcp__screw-agents__scan_domain
  - mcp__screw-agents__get_agent_prompt
  - mcp__screw-agents__accumulate_findings
  - mcp__screw-agents__record_exclusion
  - mcp__screw-agents__record_context_required_match
  - mcp__screw-agents__detect_coverage_gaps
  - mcp__screw-agents__lint_adaptive_script
  - Read
  - Glob
  - Grep
```

Removed: `stage_adaptive_script`, `promote_staged_script`, `reject_staged_script`, `execute_adaptive_script`, `finalize_scan_results`, `Task`. Retained `scan_domain` + `get_agent_prompt` + lint + accumulate + detect_coverage_gaps + record_* + Read/Glob/Grep.

- [ ] **Step 3: Modify Step 2.5c delegation paragraph**

The current Step 2.5c (around line 167) contains the clause:

> For each gap that passes the quota gate: apply the per-gap pipeline documented in `screw-<gap.agent_name>.md` Step 3.5d (sub-steps A through K)

Replace the phrase "sub-steps A through K" with:

> sub-steps A through E (Layer 0e blocklist + derive script_name + Layers 0a-c generation prompt + generate + hash6 + Layer 1 lint). Then emit a pending_review entry per docs/specs/2026-04-23-phase-3b-c2-nested-dispatch-fix-design.md §5.1 and append to the in-memory pending_reviews list.

Also clarify that `pending_review.gap.agent` is set to the gap's actual per-agent name (sqli/cmdi/ssti/xss), NOT to `"injection"`. Main session uses `gap.agent` for routing + display.

- [ ] **Step 4: Delete old Step 3b (finalize) AND old Step 4 (Present Summary)**

The current screw-injection.md has two deletions needed:

1. Lines 209-222: Step 3b `#### 3b. Finalize the scan results` — calls
   `finalize_scan_results`. Main session owns finalize post-C2.
2. Lines 224-231: `### Step 4: Present Summary and Offer Follow-Up` through
   its five numbered bullets. Main session owns user-facing summary post-C2.

Both must be deleted. Verify pre-deletion with:
```fish
sed -n '209,232p' plugins/screw/agents/screw-injection.md
```
Expected: lines 209 starts with `#### 3b. Finalize the scan results`, line
224 starts with `### Step 4: Present Summary and Offer Follow-Up`, line 231
is the last "Offer:" bullet.

Post-deletion, the file ends after Step 3a (accumulate_findings). Verify:
```fish
tail -5 plugins/screw/agents/screw-injection.md
```
Expected: end-of-file is the accumulate_findings response-shape block or
whatever followed Step 3a.

- [ ] **Step 5: Append new Step 4 (return structured payload)**

After Step 3a (accumulate_findings), which is now the last surviving step,
append:

````markdown
### Step 4: Return structured payload to main session

END your turn by emitting ONE fenced JSON code block with:

```json
{
  "schema_version": 1,
  "scan_subagent": "screw-injection",
  "session_id": "<session_id from Step 3a's accumulate_findings response>",
  "trust_status": <trust_status dict from Step 1 init-page response>,
  "yaml_findings_accumulated": <count persisted in Step 3a>,
  "adaptive_mode_engaged": <true if Step 2.5 executed, else false>,
  "adaptive_quota_note": <null or Layer 0f quota exhaustion message from Step 2.5c>,
  "pending_reviews": [<pending_review entries built during Step 2.5c per-gap loop, preserving gap.agent for each>],
  "blocklist_skipped_gaps": [<gaps skipped by Layer 0e blocklist in Step 2.5c per-gap loop>],
  "scan_metadata": {
    "target": "<what was scanned>",
    "target_spec": <target spec dict>,
    "agent_names": ["sqli", "cmdi", "ssti", "xss"],
    "timestamp": "<ISO8601>"
  }
}
```

Note `agent_names` is a list (all 4 domain agents) — main session passes this
to `finalize_scan_results` so the Markdown report covers all 4.

Emit NOTHING after the fenced block. END your turn. Main session owns
finalize, summary, and all post-generation flow (reviewer dispatch, staging,
approve/reject, promote/execute/accumulate).
````

- [ ] **Step 6: Run injection-specific tests**

Run: `uv run pytest tests/test_adaptive_subagent_prompts.py -k "injection or orchestrator" -v 2>&1 | tail -20`
Expected: injection-orchestrator assertions GREEN.

Run: `uv run pytest tests/test_adaptive_subagent_prompts.py -v 2>&1 | tail -10`
Expected: full test file green (at this point T1–T8 should have walked everything to green).

- [ ] **Step 7: Commit**

```fish
git add plugins/screw/agents/screw-injection.md
git commit -m "refactor(phase3b-c2): truncate screw-injection.md orchestrator

Orchestrator retains scan_domain pagination + per-agent analysis + shared
Layer 0f quota. Drops Step 3b finalize (main owns it now). Step 2.5c
delegation to per-agent Step 3.5d now limits delegation to sub-steps A-E;
sub-steps F-K (staging/review/promote/etc) are gone from per-agents too.
Adds Step 4 structured JSON return per spec §5.1.

See docs/PHASE_3B_C2_PLAN.md Task 8."
```

---

### Task 9: Full pytest Gate

**Files:**
- (verification only)

**Rationale:** Hard gate before the live round-trip. All 942+ tests must pass. Any failure here indicates a drift from the plan that must be fixed before T10.

- [ ] **Step 1: Run full pytest**

Run: `uv run pytest -q 2>&1 | tail -5`
Expected: `~917 passed, 8 skipped` (942 existing − 33 deleted cases [8 parametrized × 4 agents + 1 non-parametrized] + 8 new assertions = 917). Preserved assertions stay part of the 942 base.

If any failure: triage (test regression vs plan drift vs genuine bug). Fix in a follow-up commit before T10.

- [ ] **Step 2: Verify no pytest warnings beyond the known-baseline**

Run: `uv run pytest -q 2>&1 | grep -i "warning\|deprecat"`
Expected: same count of warnings as baseline (10 warnings per pre-flight).

---

### Task 10: Live Round-Trip Validation (HARD GATE)

**Files:**
- Create (ephemeral): `/tmp/screw-roundtrip-qb/src/dao.py`
- Create (ephemeral): `/tmp/screw-roundtrip-qb/.mcp.json`
- Create (ephemeral): `/tmp/screw-roundtrip-qb/.claude/settings.local.json`
- Create (ephemeral): `/tmp/screw-roundtrip-qb/.screw/config.yaml` (via init-trust)

**Rationale:** Static content tests (T1–T9) lock structure but cannot validate runtime dispatch. This is the process gap that shipped PR #6 with a latent regression. T10 runs a live `claude` session against a fresh fixture. The binary fix signal is: `/screw:scan sqli src/ --adaptive` reaches `stage_adaptive_script` from main session. If not, C2 hasn't fixed the bug.

Per `feedback_roundtrip_stepbystep`: ONE STEP AT A TIME. Wait for Marco between steps. Do not batch. Fish shell.

- [ ] **Step 1: Clean fixture directory**

Tell Marco to run (fish):

```fish
rm -rf /tmp/screw-roundtrip-qb
mkdir -p /tmp/screw-roundtrip-qb/src
cd /tmp/screw-roundtrip-qb
```

Expected: fresh empty directory.

WAIT for Marco confirmation before Step 2.

- [ ] **Step 2: Seed `src/dao.py` fixture (no git init per Marco directive)**

Write `/tmp/screw-roundtrip-qb/src/dao.py`:

```python
"""QueryBuilder fixture — 3 unresolved SQL execute sinks for adaptive testing."""

from somewhere import QueryBuilder


def list_users(user_id: str) -> list:
    qb = QueryBuilder()
    result1 = qb.execute(f"SELECT * FROM users WHERE id = {user_id}")
    result2 = qb.execute("SELECT * FROM users WHERE active = 1")
    result3 = qb.execute("SELECT name FROM users LIMIT 10")
    return result1 + result2 + result3
```

WAIT for Marco confirmation.

- [ ] **Step 3: Run init-trust WITH --project-root (the flag missed in PR #6)**

Tell Marco:

```fish
set -e ANTHROPIC_API_KEY
uv run --directory /home/marco/Programming/AI/screw-agents screw-agents init-trust \
  --name "Marco" --email "marco@test" \
  --project-root /tmp/screw-roundtrip-qb
```

Expected: CLI output reports new Ed25519 keypair generated, `.screw/config.yaml`
seeded, `.screw/local/keys/` populated.

WAIT for Marco confirmation.

- [ ] **Step 4: Create `.mcp.json`**

Write `/tmp/screw-roundtrip-qb/.mcp.json`:

```json
{
  "mcpServers": {
    "screw-agents": {
      "command": "uv",
      "args": [
        "run",
        "--project",
        "/home/marco/Programming/AI/screw-agents",
        "screw-agents",
        "serve-stdio"
      ],
      "env": {}
    }
  }
}
```

WAIT for Marco confirmation.

- [ ] **Step 5: Create `.claude/settings.local.json` with pre-approved tool allowlist**

Write `/tmp/screw-roundtrip-qb/.claude/settings.local.json`:

```json
{
  "enabledMcpjsonServers": ["screw-agents"],
  "permissions": {
    "allow": [
      "mcp__screw-agents__scan_sqli",
      "mcp__screw-agents__scan_cmdi",
      "mcp__screw-agents__scan_ssti",
      "mcp__screw-agents__scan_xss",
      "mcp__screw-agents__scan_domain",
      "mcp__screw-agents__scan_full",
      "mcp__screw-agents__list_domains",
      "mcp__screw-agents__list_agents",
      "mcp__screw-agents__get_agent_prompt",
      "mcp__screw-agents__accumulate_findings",
      "mcp__screw-agents__finalize_scan_results",
      "mcp__screw-agents__record_exclusion",
      "mcp__screw-agents__record_context_required_match",
      "mcp__screw-agents__detect_coverage_gaps",
      "mcp__screw-agents__lint_adaptive_script",
      "mcp__screw-agents__stage_adaptive_script",
      "mcp__screw-agents__promote_staged_script",
      "mcp__screw-agents__reject_staged_script",
      "mcp__screw-agents__execute_adaptive_script",
      "mcp__screw-agents__sweep_stale_staging",
      "mcp__screw-agents__check_exclusions",
      "mcp__screw-agents__aggregate_learning",
      "mcp__screw-agents__list_adaptive_scripts",
      "mcp__screw-agents__remove_adaptive_script",
      "mcp__screw-agents__verify_trust",
      "mcp__screw-agents__format_output"
    ]
  }
}
```

WAIT for Marco confirmation.

- [ ] **Step 6: Flip `adaptive: true` in `.screw/config.yaml`**

init-trust seeds the config with `adaptive: false`. Flip it to `true`:

```fish
sed -i 's/^adaptive:.*/adaptive: true/' /tmp/screw-roundtrip-qb/.screw/config.yaml
grep '^adaptive:' /tmp/screw-roundtrip-qb/.screw/config.yaml
```
Expected: `adaptive: true`.

WAIT for Marco confirmation.

- [ ] **Step 7: Launch claude with the worktree's plugins**

Tell Marco:

```fish
set -e ANTHROPIC_API_KEY
cd /tmp/screw-roundtrip-qb
claude --plugin-dir /home/marco/Programming/AI/screw-agents/.worktrees/phase-3b-c2-nested-dispatch-fix/plugins/screw
```

WAIT for Marco confirmation that claude launched.

- [ ] **Step 8: Run pre-launch sanity checks INSIDE the claude session**

In the claude session, have Marco run:

1. `/sc<TAB>` — expect completions: `/screw:scan`, `/screw:adaptive-cleanup`, `/screw:learn-report`
2. `/agents` → Library tab — expect: `screw:screw-sqli`, `screw:screw-cmdi`, `screw:screw-ssti`, `screw:screw-xss`, `screw:screw-injection`, `screw:screw-script-reviewer`, `screw:screw-learning-analyst`. **`screw:screw-full-review` should NOT appear** (the file was deleted in T3).
3. `/mcp` — expect `screw-agents` MCP server connected (green); in tool list: `stage_adaptive_script`, `promote_staged_script`, `reject_staged_script`, `execute_adaptive_script` visible.
4. `/permissions` — expect the MCP tool allowlist active.

If any fails: debug before continuing.

WAIT for Marco to confirm all 4 sanity checks pass.

- [ ] **Step 9: RT-1 — non-adaptive baseline**

In the claude session, run: `/screw:scan sqli src/`

Expected:
- 3 CWE-89 findings produced (dao.py lines 7, 8, 9 — all unresolved execute)
- No coverage-gap detection (non-adaptive skips)
- `.screw/findings/<session>/` written with JSON + Markdown
- No staging activity (no `.screw/staging/` or `.screw/custom-scripts/` writes)

Capture: session transcript + `.screw/` directory tree + finalize response.

WAIT for Marco to share results.

- [ ] **Step 10: RT-2 — per-agent adaptive (THE BINARY FIX SIGNAL)**

In the claude session, run: `/screw:scan sqli src/ --adaptive`

Expected FLOW:
1. scan.md dispatches `screw:screw-sqli`
2. screw-sqli scans, detects 3 unresolved_sink gaps at dao.py:7/8/9
3. Subagent generates scripts for up to 3 gaps (Layer 0f quota)
4. Subagent returns fenced JSON with `pending_reviews` populated
5. Main session parses the JSON
6. For EACH pending_review (sequential):
   - Main dispatches `screw:screw-script-reviewer` — expect to see the dispatch
   - Main calls `stage_adaptive_script` — **EXPECT to see this tool call in the transcript**. This is the BINARY SIGNAL.
   - Main composes 5-section review, shows to Marco
7. Marco types `approve <name>` for at least one pending_review
8. Main calls `promote_staged_script`, then `execute_adaptive_script`, then `accumulate_findings`
9. Main calls `finalize_scan_results`

Expected ARTIFACTS (after at least one approve):
- `.screw/custom-scripts/<name>.py` + `.meta.yaml` files exist (at least one promoted script)
- `.screw/local/pending-approvals.jsonl` contains `staged` + `promoted` + possibly `rejected` events
- `.screw/findings/<session>/` contains JSON + Markdown with YAML findings AND adaptive findings

**BINARY GATE CRITERIA:** `stage_adaptive_script` MUST appear in the transcript as being called from main session. If `stage_adaptive_script` is NEVER called, C2 hasn't fixed the bug — triage and fix before proceeding.

WAIT for Marco to share results. If binary gate fails, debug. If binary gate passes but something else looks wrong (e.g., `confirm-high` isn't triggered for a HIGH-flagged script), flag for fix-up.

- [ ] **Step 11: RT-3 — domain adaptive**

Run: `/screw:scan injection src/ --adaptive`

Expected:
- Main dispatches `screw:screw-injection`
- Orchestrator runs scan_domain across 4 agents (only sqli triggers gaps in this fixture)
- Orchestrator returns with `scan_subagent: "screw-injection"`, `scan_metadata.agent_names: ["sqli","cmdi","ssti","xss"]`
- Main loops reviews same as RT-2
- Shared Layer 0f quota respected across agents (max 3 scripts)

WAIT for Marco to share results.

- [ ] **Step 12: RT-4 — full-scope non-adaptive**

Run: `/screw:scan full src/`

Expected:
- Main calls `list_domains` (MCP tool)
- For each returned domain with an orchestrator, main dispatches that orchestrator
- At Phase 3b, only `injection-input-handling` → `screw:screw-injection` dispatches
- Findings aggregated and finalized per-domain
- **No references to `screw-full-review` anywhere in the transcript** (file deleted in T3)

WAIT for Marco to share results.

- [ ] **Step 13: RT-5 (optional) — full-scope adaptive**

If time permits: `/screw:scan full src/ --adaptive`

Combines RT-3 and RT-4 paths. Heavier test.

WAIT for Marco.

- [ ] **Step 14: Capture and organize round-trip evidence**

After all RT scenarios pass, collect:
- Session transcripts (copy or screenshot each)
- `.screw/` directory tree after RT-2 + RT-3 + RT-4
- `.screw/local/pending-approvals.jsonl` contents
- Any MCP tool error stderr

Store in a temporary location for the PR description (T11).

---

### Task 11: Cross-Plan Sync + PR Preparation

**Files:**
- Modify: `docs/DEFERRED_BACKLOG.md`
- Modify: `docs/PROJECT_STATUS.md`
- (verify no changes needed): `CLAUDE.md`

**Rationale:** Close out cross-plan markers per `feedback_cross_plan_sync`. Prepare PR per `feedback_no_cc_commits` (no AI attribution).

- [ ] **Step 1: Update `docs/DEFERRED_BACKLOG.md`**

a. Move `BACKLOG-C2-01` entry from § "★ IMMEDIATE — Phase 3b-C2" to a new § "Shipped (Phase 3b-C2)" section (append at the appropriate place — similar to how PR #6 has a "Shipped (PR #6)" section).

b. In § "Phase-4 Readiness Triage" tag summary table (§ "Tag summary (as of T24 fix-up, 2026-04-23)"), update the blocker count from 5 to 4. Remove `BACKLOG-C2-01` from the "Key entries" list for `blocker`; remaining blockers: `T-FULL-P1`, `T19-M1`, `T19-M2`, `T19-M3`, `BACKLOG-PR6-22`.

c. Update the "Phase 4 gate" paragraph: blocker count `5 → 0` becomes `4 → 0`.

- [ ] **Step 2: Update `docs/PROJECT_STATUS.md`**

a. In § "Phase 4 Prerequisites (hard gates)": remove the ★ "Phase 3b-C2" first-prerequisite entry; move it to a "Shipped" / "Complete" section with PR # + merge date.

b. Update any Phase 3b timeline references to include C2's completion.

- [ ] **Step 3: Grep `CLAUDE.md` for stale references**

Run: `grep -in "screw-full-review\|nested.*dispatch\|screw-agents.*subagent.*subagent" CLAUDE.md`
Expected: zero output (or only historical notes, which are acceptable).

If there are stale statements to fix, edit them and commit.

- [ ] **Step 4: Commit cross-plan updates**

```fish
git add docs/DEFERRED_BACKLOG.md docs/PROJECT_STATUS.md
git commit -m "docs(phase3b-c2): move BACKLOG-C2-01 to Shipped; drop Phase-4 blocker count

BACKLOG-C2-01 resolved by this PR. Phase-4 blocker count drops 5 → 4.
Remaining blockers: T-FULL-P1, T19-M1/M2/M3, BACKLOG-PR6-22.

See docs/PHASE_3B_C2_PLAN.md Task 11."
```

- [ ] **Step 5: Audit full diff against main**

Run: `git diff main..HEAD --stat`

Expected to see changes in:
- `plugins/screw/commands/scan.md` (+180)
- `plugins/screw/agents/screw-sqli.md` (−325)
- `plugins/screw/agents/screw-cmdi.md` (−325)
- `plugins/screw/agents/screw-ssti.md` (−325)
- `plugins/screw/agents/screw-xss.md` (−325)
- `plugins/screw/agents/screw-injection.md` (−55)
- `plugins/screw/agents/screw-full-review.md` (deleted)
- `tests/test_adaptive_subagent_prompts.py` (+45)
- `docs/DEFERRED_BACKLOG.md` (small)
- `docs/PROJECT_STATUS.md` (small)

ANY unexpected file: investigate or revert.

- [ ] **Step 6: Push branch + create PR**

```fish
git push -u origin phase-3b-c2-nested-dispatch-fix

gh pr create --title "Phase 3b C2 — Nested Subagent Dispatch Fix (Chain-Subagents)" --body "$(cat <<'EOF'
## Summary

Rewrite `/screw:scan` as a main-session orchestrator. Scan subagents return structured JSON; main session dispatches screw:screw-script-reviewer + owns staging/promote/execute. Deletes screw-full-review.md (second instance of the nested-dispatch anti-pattern).

## Root cause

Per Claude Code sub-agents.md:711: *"Subagents cannot spawn other subagents. If your workflow requires nested delegation, use Skills or chain subagents from the main conversation."* PR #6 T15-T17 prompt design assumed scan subagents could dispatch screw:screw-script-reviewer for Layer 0d. Architecturally blocked; adaptive mode silently degraded to YAML-only.

## Fix

Chain-subagents pattern per sub-agents.md:683-689. Main session (scan.md) becomes the orchestrator.

## Scope

- 1 file rewritten (scan.md)
- 4 per-agent files truncated (sqli/cmdi/ssti/xss)
- 1 orchestrator file truncated (injection)
- 1 file deleted (screw-full-review.md — Option A fold+delete)
- 1 test file updated (20 assertion changes)
- 2 doc files updated (BACKLOG + STATUS)

ZERO engine changes.

## Test plan

- [x] Full pytest green (~917 passed, 8 skipped)
- [x] Live round-trip RT-1 (non-adaptive baseline)
- [x] Live round-trip RT-2 (per-agent adaptive — stage_adaptive_script called from main session; binary fix signal)
- [x] Live round-trip RT-3 (domain adaptive)
- [x] Live round-trip RT-4 (full-scope non-adaptive)

## Downstream

- Phase-4 blocker count drops 5 → 4. Remaining blockers: T-FULL-P1, T19-M1/M2/M3, BACKLOG-PR6-22.
- Resolves BACKLOG-C2-01 (DEFERRED_BACKLOG).
EOF
)"
```

NOTE: per `feedback_no_cc_commits`, the PR body does NOT include "🤖 Generated with Claude Code" or "Co-Authored-By: Claude" attribution.

- [ ] **Step 7: Share the PR URL**

Return the PR URL to Marco after `gh pr create` succeeds.

---

## Pre-merge Acceptance Gates (summary — all must hold)

1. ✅ `uv run pytest -q` — ~917 passed, 8 skipped, no new warnings
2. ✅ Live RT-1 passes — non-adaptive baseline works
3. ✅ Live RT-2 passes — `stage_adaptive_script` called from main session (the binary fix signal)
4. ✅ Live RT-3 passes — domain adaptive flow
5. ✅ Live RT-4 passes — `/screw:scan full` without screw-full-review reference
6. ✅ DEFERRED_BACKLOG BACKLOG-C2-01 moved to Shipped; Phase-4 blocker count dropped to 4
7. ✅ PROJECT_STATUS.md Phase 4 Prerequisites updated
8. ✅ No `screw-full-review` / `nested subagent dispatch` stale references in CLAUDE.md / plugins / src
9. ✅ Every actionable Minor from T1–T8 triage has a DEFERRED_BACKLOG entry
10. ✅ PR body free of AI attribution

## Out-of-Scope (explicitly deferred)

These do NOT block C2. They live in DEFERRED_BACKLOG (or are Phase-6-and-later):

- Parallel fan-out for `/screw:scan full` (Phase 6 concern, > 5 orchestrators shipped)
- `scan_full_preflight` pre-filter MCP tool (tracked as `T-FULL-P1`, Phase 4 blocker)
- Convention-driven domain→orchestrator mapping (hardcoded lookup is fine at 1 orchestrator)
- Cross-orchestrator session consolidation (if Phase 4 autoresearch needs it)
- `confirm-high` audit event name in pending-approvals registry (currently only the inline render; structured event could be a Phase 3c polish item)

## Post-merge Follow-up (NOT in C2)

1. Memory writes:
   - Create `project_phase3b_c2_complete.md`
   - Update `MEMORY.md` index
   - Supersede `project_phase3b_pr6_complete.md` (retain historical)
2. `/tmp/screw-roundtrip-qb/` cleanup (Marco decides when)
3. Phase 4 scoping discussion — remaining 4 blockers to schedule

---

## Appendix — Task Dependency Graph

```
T0 (worktree + preflight)
  │
  └─► T1 (test updates, RED)
        │
        ├─► T2 (scan.md rewrite)
        │     │
        │     └─► T3 (delete full-review)
        │           │
        │           └─► T9 (gate)
        │
        ├─► T4 (sqli truncate)
        │     │
        │     ├─► T5 (cmdi) ──► T9
        │     │
        │     ├─► T6 (ssti) ──► T9
        │     │
        │     └─► T7 (xss)  ──► T9
        │
        └─► T8 (injection truncate)
              │
              └─► T9 (gate)

T9 (full pytest gate)
  │
  └─► T10 (live round-trip RT-1..RT-4, HARD GATE)
        │
        └─► T11 (cross-plan sync + PR)
```

T2, T4–T8 can technically parallelize after T1 lands (they touch disjoint files). Sequential is fine at ≤4h total work; parallel coordination overhead outweighs wall-clock savings.

## Appendix — Per-task Agent dispatch template

Every implementer / reviewer / fix-up dispatch follows:

```
Agent({
  description: "<short task desc>",
  subagent_type: "general-purpose",
  model: "opus",                     // per feedback_opus_for_all_subagents
  prompt: `<full self-contained context: task goal, file list,
           acceptance criteria, relevant spec section references,
           precedent pattern citations from prior C1 tasks if applicable>`
})
```

Per `feedback_name_precedents`: implementer prompts MUST explicitly name precedent patterns from prior tasks. Pre-audit greps for asymmetries (especially in T5/T6/T7 where the 4 per-agent files must stay byte-identical).

---

## Execution Handoff

**Plan complete at `docs/PHASE_3B_C2_PLAN.md`.** Two execution options:

1. **Subagent-Driven (recommended — per `project_execution_mode`)** — I dispatch a fresh subagent per task, review between tasks (7-step workflow). Each task runs pre-audit → implementer → spec review → quality review → triage → fix-up → cross-plan sync.
2. **Inline Execution** — Execute tasks in this session using superpowers:executing-plans, batch execution with checkpoints.

Marco's default per memory is **Subagent-Driven**. Confirm before starting T0.
