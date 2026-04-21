# Phase 3b C1 — Staging Architecture + I1-I6 + Bundled Polish: Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.
>
> **Per-task workflow (from `feedback_phase3a_workflow_discipline.md`):** 7-step cycle — pre-audit → implementer → spec review → quality review → triage → fix-up → cross-plan sync. Non-negotiable. Every code-producing task runs the full cycle.
>
> **Deep adversarial pre-audit (from `feedback_deeper_pre_audit.md`):** C1 is trust-path. Trace sign/verify symmetry explicitly. Every sign-side canonical byte string must match verify-side. Prefer OSError-broad over sibling-enumeration. Trust-path bugs caught in pre-audit are 10× cheaper.
>
> **Plan-sync on deviation (from `feedback_plan_sync_on_deviation.md`):** whenever implementation differs from this plan, update this file in the SAME PR (or defer the item to DEFERRED_BACKLOG). Plan and code must be coherent at merge time.

**Goal:** Ship the staging-architecture fix (C1) that restores the trust invariant `bytes_reviewed == bytes_signed == bytes_executed` for adaptive-mode analysis scripts, and bundle 6 round-trip defects (I1-I6) + 5 adjacent backlog items (T-STAGING-ORPHAN-GC, T10-M1 partial, T11-N1, T11-N2, T3-M1) that reinforce the same trust and error-surfacing story.

**Architecture:** Introduce a session-scoped staging phase between generation and signing. Scripts written atomically at generation time (when the user reviews them); on approval, a new `promote_staged_script` MCP tool (no `source` parameter) reads the staged bytes from disk, verifies sha256 against registry, and signs. Regeneration has no surface in the approve path. A shared `_sign_script_bytes` helper is the single source of canonical-bytes truth for both signing entry points.

**Tech Stack:** Python 3.11+, Pydantic v2 models, cryptography (Ed25519 signing unchanged), tree-sitter (unchanged), pytest, Claude Code subagent Markdown.

**Spec:** `docs/specs/2026-04-20-phase-3b-c1-staging-design.md` (local, not in git per `project_docs_not_committed`).

**Upstream phase plan:** Phase 3b PR #5 shipped 2026-04-20 (squash commit `1d07d6b`). 771 tests passing on main. This is the immediate C1 follow-up before Phase 4 autoresearch.

**Downstream phase plan:** Phase 3c sandbox hardening (PR #7), trust-layer polish (PR #8), schema tightening (PR #9), output-format polish (PR #10), Phase 4 autoresearch (PR #11+). See spec §7.3 for full post-C1 roadmap.

**Branch:** `phase-3b-c1-staging` (per `project_execution_mode.md`: subagent-driven + dedicated worktree at `.worktrees/phase-3b-c1-staging`).

**Key references for implementers:**
- `docs/specs/2026-04-20-phase-3b-c1-staging-design.md` — design rationale + invariants (local-only spec)
- `docs/PHASE_3B_PLAN.md` — preceding PR #5 work (T13-T22 + sandbox fix)
- `src/screw_agents/engine.py` — add 6 new methods (stage/promote/reject/sweep/list/remove), refactor `sign_adaptive_script` to delegate
- `src/screw_agents/adaptive/signing.py` — extract `_sign_script_bytes` shared helper
- `src/screw_agents/adaptive/staging.py` — NEW module for staging-dir + registry management
- `src/screw_agents/server.py` — register 6 new MCP tools with `additionalProperties: false`
- `plugins/screw/agents/screw-{sqli,cmdi,ssti,xss}.md` — byte-identical Step 3.5d section rewrite
- `plugins/screw/commands/adaptive-cleanup.md` — add `stale` subcommand; switch backend from Bash to MCP tools
- `docs/DEFERRED_BACKLOG.md` — move C1/I1-I6/absorbed items to Shipped section; confirm `BACKLOG-PR6-01..08` (added 2026-04-21 from Opus re-review) and append `BACKLOG-PR6-09..13` (original-plan design items) under "Phase 3b PR #6 follow-ups"

---

## PR Scope Summary

| Category | Items | Net LOC |
|---|---|---|
| Core C1 fix | Staging module, 4 new MCP tools, shared `_sign_script_bytes`, T18b prompt rewrite, sha256 binding, fallback re-confirm, staleness check | ~850 |
| Round-trip fixes | I1-I6 (plugin namespace, lint __all__, stderr, retention docs, prompt hardening, MCP promotion) | (included in core via same files) |
| Absorbed from backlog | T-STAGING-ORPHAN-GC (covered by sweep_stale_staging) | 0 (covered) |
| Bundled polish | T10-M1 partial (6 new tool schemas), T11-N1 (signature E2E), T11-N2 (MetadataError wrapper), T3-M1 (narrow exceptions) | +113 |
| **Total** | | **~963 LOC, +49 tests** |

**Target:** 771 passed → **820 passed, 8 skipped**.

---

## File Structure Map

### Created (5 files)

| Path | Responsibility |
|---|---|
| `src/screw_agents/adaptive/staging.py` | Staging filesystem ops (write/read/delete), registry append/query, fallback walk, stale sweep. ~180 LOC. No signing logic. Pure filesystem + JSONL. |
| `tests/test_adaptive_staging.py` | Unit tests for `staging.py` + `stage_adaptive_script` / `promote_staged_script` / `reject_staged_script` / `sweep_stale_staging` engine methods. ~300 LOC, 20 tests. |
| `tests/test_adaptive_workflow_staged.py` | End-to-end integration test — C1 exit gate. Modeled on T22; signing goes through stage→promote. ~250 LOC, 1 test. |

### Modified (14 files)

| Path | What changes |
|---|---|
| `src/screw_agents/adaptive/signing.py` | Extract `_sign_script_bytes` internal helper from engine's current `sign_adaptive_script` logic. Keep `build_signed_script_meta` + `compute_script_sha256` (already live here). |
| `src/screw_agents/adaptive/lint.py` | I2: cache `adaptive.__all__`; validate `from screw_agents.adaptive import <name>` against cached set; emit `rule=unknown_symbol` violation. |
| `src/screw_agents/adaptive/executor.py` | I3: propagate `SandboxResult.stderr` into `execute_script`'s return on returncode != 0. T11-N2: wrap `yaml.YAMLError` + `pydantic.ValidationError` in new `MetadataError(RuntimeError)`. |
| `src/screw_agents/adaptive/sandbox/linux.py` | I3: verify `subprocess.run(capture_output=True)` + ensure `SandboxResult.stderr` is populated from `proc.stderr.decode('utf-8', errors='replace')`. |
| `src/screw_agents/adaptive/ast_walker.py` | T3-M1: narrow `except Exception` → `except (UnicodeDecodeError, OSError)` in `find_calls`, `find_imports`, `find_class_definitions`. |
| `src/screw_agents/engine.py` | Add 6 methods: `stage_adaptive_script`, `promote_staged_script`, `reject_staged_script`, `sweep_stale_staging`, `list_adaptive_scripts`, `remove_adaptive_script`. Refactor `sign_adaptive_script` to delegate to `_sign_script_bytes`. |
| `src/screw_agents/server.py` | Register 6 new MCP tools with `additionalProperties: false` (T10-M1 partial). |
| `src/screw_agents/models.py` | Add `PendingApproval` TypedDict + `StaleStagingReport` TypedDict. |
| `tests/test_adaptive_signing.py` | +5 tests: shared helper invariance, canonical-bytes roundtrip, delegation mocks. |
| `tests/test_adaptive_lint.py` | +4 tests for I2 (unknown symbol, all allowed, regressions for `read_source`/`parse_module`, allowlist in message). |
| `tests/test_adaptive_executor.py` | +2 tests for I3 (stderr surfacing); +60 LOC for T11-N1 (Ed25519 fixture + 2 signature-path tests); +2 tests for T11-N2 (MetadataError wraps YAMLError + ValidationError). |
| `tests/test_adaptive_ast_walker.py` | +1 test for T3-M1 (non-UTF-8 source raises cleanly, not silently swallowed). |
| `tests/test_adaptive_subagent_prompts.py` | +12 format-smoke assertions for C1 + I1/I3/I4/I5. |
| `tests/test_adaptive_workflow.py` | (T22) Migrate `from screw_agents.cli.adaptive_cleanup import list_adaptive_scripts` → `engine.list_adaptive_scripts(project_root)`. |
| `tests/test_adaptive_cleanup.py` | Migrate all `from cli.adaptive_cleanup import ...` → `engine` method calls. |
| `plugins/screw/agents/screw-sqli.md` | Rewrite Step 3.5d adaptive-mode section: stage→present→approve/reject→promote/reject; I1 plugin namespace; I4 retention hint; I5 prompt hardening; staged_at + session_id_short + sha_prefix in review header. |
| `plugins/screw/agents/screw-cmdi.md` | Byte-identical copy of sqli's Step 3.5d section (modulo agent-name substitution). |
| `plugins/screw/agents/screw-ssti.md` | Same as cmdi. |
| `plugins/screw/agents/screw-xss.md` | Same as cmdi. |
| `plugins/screw/agents/screw-injection.md` | Orchestrator: update shared-quota section to reference new step IDs where they change. |
| `plugins/screw/commands/scan.md` | Minor: document staging conceptually (~10 lines). |
| `plugins/screw/commands/adaptive-cleanup.md` | Rewrite Bash backends → MCP tool calls (I6); add `stale` subcommand with `--max-age-days` + `--preview`. |
| `docs/PHASE_3B_PLAN.md` | Add new section "PR #6 — C1 Staging Architecture + I1-I6 Polish" at the end, matching existing structure. |
| `docs/DEFERRED_BACKLOG.md` | Move C1/I1-I6/T-STAGING-ORPHAN-GC/T10-M1 partial/T11-N1/T11-N2/T3-M1 entries to a new "Shipped (PR #6)" block with post-merge commit SHA. Confirm 8 existing entries `BACKLOG-PR6-01..08` (Opus re-review findings 2026-04-21); append 5 original-plan entries as `BACKLOG-PR6-09..13`. |

### Deleted (1 file)

| Path | Reason |
|---|---|
| `src/screw_agents/cli/adaptive_cleanup.py` | Not a shell-command entry point (absent from `pyproject.toml [project.scripts]`). Superseded by engine methods + MCP tools per I6 decision. Tests migrate to engine calls. |

### Config schema addition

`.screw/config.yaml` schema gains two optional fields (both have safe defaults):
- `staging_max_age_days: int = 14` (range 1-365) — age threshold for `sweep_stale_staging`
- `stale_staging_hours: int = 24` (range 1-168) — age threshold for `promote_staged_script` staleness check

---

## Task Dependency Graph

```
T0 (worktree) ─┬─> T1 (staging.py)  ─┬─> T3 (stage tool) ─┐
               │                     │                    │
               └─> T2 (_sign_script) ┴─> T4 (promote) ────┤
                                                          │
                                     T5 (reject) ─────────┤
                                     T6 (sweep) ──────────┤
                                                          │
                                     T7 (list) ──┐        │
                                     T8 (remove) ┤        │
                                                 │        │
                                     T9 (del cli + test migration)
                                                 │        │
                     T10 (I2 lint) ──────────────┤        │
                     T11 (I3 stderr) ────────────┤        │
                     T12 (T11-N2 MetadataError) ─┤        │
                     T13 (T3-M1 narrow exc) ─────┤        │
                     T14 (T11-N1 sig test) ──────┤        │
                                                 │        │
                                     T15 (screw-sqli.md) ─┤
                                                 │        │
                                     T16 (cmdi/ssti/xss) ─┤
                                     T17 (screw-injection) ┤
                                     T18 (scan.md) ───────┤
                                                          │
                                     T19 (slash cmd) ─────┤
                                     T20 (format-smoke) ──┤
                                                          │
                                     T21 (integration test) ← depends on T3-T6, T15-T16
                                     T22 (additionalProps) ← depends on T3-T8
                                                          │
                                     T23 (PHASE_3B_PLAN sync)
                                     T24 (DEFERRED_BACKLOG update)
                                                          │
                                     T25 (PR + reviews)
                                     T26 (merge + round-trip)
                                     T27 (memory updates)
```

Parallelization opportunities:
- T5, T6 can run in parallel after T1 lands (independent of T3/T4)
- T7, T8 can run in parallel
- T10, T11, T12, T13, T14 are independent adjacencies — can parallelize freely
- T16 must run after T15 (byte-identical copy from sqli)
- T17, T18 can parallel with T16
- T19, T20 wait for T15+T16 (prompt content)
- T21, T22 wait for infrastructure (T3-T8)

---

## Phase A — Infrastructure (T0-T2)

### Task 0: Worktree Setup + Baseline Verification

**Files:**
- Create: `.worktrees/phase-3b-c1-staging` (git worktree)

- [ ] **Step 1: Verify starting state**

Run: `git status && git log --oneline -1`
Expected: clean working tree; HEAD is `1d07d6b` (Phase 3b PR #5 squash-merge).

- [ ] **Step 2: Create worktree + branch**

Run:
```bash
git worktree add -b phase-3b-c1-staging .worktrees/phase-3b-c1-staging main
cd .worktrees/phase-3b-c1-staging
```

- [ ] **Step 3: Verify baseline test suite passes**

Run: `uv run pytest -q 2>&1 | tail -3`
Expected: `771 passed, 8 skipped, 10 warnings in 35-40s`

If not exactly 771: stop and investigate. Any deviation means main has diverged from the plan's baseline assumptions.

- [ ] **Step 4: Set up .screw/config.yaml locally for tests (if not present)**

Tests use ephemeral project roots per-fixture — no action needed here. Project-level `.screw/config.yaml` is only relevant during round-trip (T26).

- [ ] **Step 5: No commit yet — worktree setup is environmental, not code**

---

### Task 1: New `adaptive/staging.py` Module

**Files:**
- Create: `src/screw_agents/adaptive/staging.py`
- Create: `tests/test_adaptive_staging.py` (partial; most tests added in T3-T6)
- Modify: `src/screw_agents/models.py` (add `PendingApproval`, `StaleStagingReport` TypedDicts)

**Rationale:** Isolate filesystem-only staging operations (write/read/delete + registry append/query + sweep) from engine/signing concerns. `staging.py` has NO signing logic and NO Pydantic-schema logic beyond TypedDicts — pure filesystem + JSONL. This keeps the shared helper (`_sign_script_bytes`) focused on canonical-bytes + signing without conflating staging-layout concerns.

- [ ] **Step 1: Write failing tests for staging-dir path resolution**

Create `tests/test_adaptive_staging.py`:

```python
"""Unit tests for adaptive/staging.py — filesystem + registry ops.

Scope: staging path resolution, file writes, registry append/query, fallback
walk, stale sweep. Signing is NOT tested here — that's test_adaptive_signing.py.
The full stage→promote→execute integration is test_adaptive_workflow_staged.py.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest


def test_resolve_staging_dir_creates_session_scoped_path(tmp_path: Path) -> None:
    from screw_agents.adaptive.staging import resolve_staging_dir

    project = tmp_path / "project"
    project.mkdir()
    session_id = "sess-abc123"

    staging_dir = resolve_staging_dir(project, session_id)

    assert staging_dir == project / ".screw" / "staging" / session_id / "adaptive-scripts"
    # Function resolves path but does NOT create (caller decides when to mkdir).
    assert not staging_dir.exists()


def test_resolve_staging_dir_rejects_empty_session_id(tmp_path: Path) -> None:
    from screw_agents.adaptive.staging import resolve_staging_dir

    project = tmp_path / "project"
    project.mkdir()

    with pytest.raises(ValueError, match="session_id"):
        resolve_staging_dir(project, "")


def test_resolve_registry_path(tmp_path: Path) -> None:
    from screw_agents.adaptive.staging import resolve_registry_path

    project = tmp_path / "project"
    project.mkdir()

    registry = resolve_registry_path(project)

    assert registry == project / ".screw" / "local" / "pending-approvals.jsonl"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_adaptive_staging.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'screw_agents.adaptive.staging'`

- [ ] **Step 3: Create `src/screw_agents/adaptive/staging.py` skeleton**

```python
"""Staging-directory + pending-approvals registry for adaptive scripts.

Layout:
    .screw/staging/{session_id}/adaptive-scripts/{script_name}.{py,meta.yaml}
    .screw/local/pending-approvals.jsonl  (append-only JSONL audit log)

This module has NO signing logic. It only reads/writes files on disk and
appends/queries the registry. The shared signing helper lives at
``adaptive/signing.py::_sign_script_bytes``; engine methods compose the
two. See spec §1.1 "File inventory" for the deliberate separation.

Registry event types (one entry per event, append-only):
    - staged
    - promoted
    - promoted_via_fallback
    - promoted_confirm_stale
    - rejected
    - tamper_detected
    - swept (issued by sweep_stale_staging)
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import TypedDict

__all__ = [
    "resolve_staging_dir",
    "resolve_registry_path",
    # More exports added in subsequent steps and in T3-T6.
]


def resolve_staging_dir(project_root: Path, session_id: str) -> Path:
    """Return the absolute path to the session-scoped staging dir.

    Does NOT create the directory. Caller decides when to mkdir (so read-only
    lookups don't pollute the filesystem).

    Raises ValueError if session_id is empty or contains path separators.
    """
    if not session_id:
        raise ValueError("session_id must be non-empty")
    if "/" in session_id or "\\" in session_id or ".." in session_id:
        raise ValueError(f"session_id contains invalid path chars: {session_id!r}")
    return project_root / ".screw" / "staging" / session_id / "adaptive-scripts"


def resolve_registry_path(project_root: Path) -> Path:
    """Return the absolute path to pending-approvals.jsonl (may not exist)."""
    return project_root / ".screw" / "local" / "pending-approvals.jsonl"
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_adaptive_staging.py -v`
Expected: 3 tests PASS.

- [ ] **Step 5: Extend tests for atomic file writes**

Append to `tests/test_adaptive_staging.py`:

```python
def test_write_staged_files_atomic_writes_both_files(tmp_path: Path) -> None:
    from screw_agents.adaptive.staging import write_staged_files

    project = tmp_path / "project"
    project.mkdir()
    source = "from screw_agents.adaptive import emit_finding\n\ndef analyze(project):\n    pass\n"
    meta_yaml = "name: test-script\ntarget_patterns: [foo]\n"

    paths = write_staged_files(
        project_root=project,
        script_name="test-script",
        source=source,
        meta_yaml=meta_yaml,
        session_id="sess-abc",
    )

    assert paths.py_path.exists()
    assert paths.meta_path.exists()
    assert paths.py_path.read_text(encoding="utf-8") == source
    assert paths.meta_path.read_text(encoding="utf-8") == meta_yaml


def test_write_staged_files_rolls_back_py_on_meta_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from screw_agents.adaptive import staging

    project = tmp_path / "project"
    project.mkdir()

    # Force the meta write to fail on os.replace (after tmp write succeeded).
    original_replace = os.replace
    call_count = {"n": 0}

    def flaky_replace(src, dst):
        call_count["n"] += 1
        # First call is .py replace (success), second is .meta.yaml (fail).
        if call_count["n"] == 2:
            raise PermissionError("simulated meta-write failure")
        return original_replace(src, dst)

    monkeypatch.setattr(os, "replace", flaky_replace)

    with pytest.raises(ValueError, match="PermissionError"):
        staging.write_staged_files(
            project_root=project,
            script_name="test-script",
            source="print('hi')\n",
            meta_yaml="name: test\n",
            session_id="sess-abc",
        )

    # Rollback: .py should have been unlinked.
    stage_dir = staging.resolve_staging_dir(project, "sess-abc")
    assert not (stage_dir / "test-script.py").exists()
```

- [ ] **Step 6: Run tests to verify they fail**

Run: `uv run pytest tests/test_adaptive_staging.py -v`
Expected: 3 PASS, 2 FAIL with `ImportError: cannot import name 'write_staged_files'`

- [ ] **Step 7: Implement `write_staged_files` + supporting types**

Append to `src/screw_agents/adaptive/staging.py`:

```python
from dataclasses import dataclass


@dataclass(frozen=True)
class StagedPaths:
    """Return value from write_staged_files; paths to staged artifacts."""
    py_path: Path
    meta_path: Path


def write_staged_files(
    *,
    project_root: Path,
    script_name: str,
    source: str,
    meta_yaml: str,
    session_id: str,
) -> StagedPaths:
    """Write source + meta to staging-dir atomically.

    Order: source (.py) first, then meta (.meta.yaml). On meta failure,
    best-effort unlinks the just-written .py to avoid leaving a partial
    stage. Mirrors T18a's atomic-write discipline for custom-scripts/.

    Raises ValueError wrapping (PermissionError, OSError) with
    {type(exc).__name__} in the message (T13-C1 discipline).
    """
    stage_dir = resolve_staging_dir(project_root, session_id)
    try:
        stage_dir.mkdir(parents=True, exist_ok=True)
    except (PermissionError, OSError) as exc:
        raise ValueError(
            f"failed to create staging dir {stage_dir} "
            f"({type(exc).__name__}: {exc})"
        ) from exc

    py_path = stage_dir / f"{script_name}.py"
    meta_path = stage_dir / f"{script_name}.meta.yaml"
    # String-concat from script_name (not Path.with_suffix) — mirrors T18a's
    # engine.py pattern exactly. `Path("x.meta.yaml").with_suffix(".meta.yaml.tmp")`
    # produces `x.meta.meta.yaml.tmp` because Path.suffix is only the last
    # dotted segment. Concat keeps tmp names symmetric with their targets.
    py_tmp = stage_dir / f"{script_name}.py.tmp"
    meta_tmp = stage_dir / f"{script_name}.meta.yaml.tmp"

    # Source first.
    try:
        py_tmp.write_text(source, encoding="utf-8")
        os.replace(py_tmp, py_path)
    except (PermissionError, OSError) as exc:
        py_tmp.unlink(missing_ok=True)
        raise ValueError(
            f"failed to write staged source {py_path} "
            f"({type(exc).__name__}: {exc})"
        ) from exc

    # Meta second, with rollback-of-.py on failure.
    try:
        meta_tmp.write_text(meta_yaml, encoding="utf-8")
        os.replace(meta_tmp, meta_path)
    except (PermissionError, OSError) as exc:
        meta_tmp.unlink(missing_ok=True)
        py_path.unlink(missing_ok=True)  # best-effort rollback
        raise ValueError(
            f"failed to write staged meta {meta_path} "
            f"({type(exc).__name__}: {exc}); "
            f"rolled back source file"
        ) from exc

    return StagedPaths(py_path=py_path, meta_path=meta_path)
```

Export `write_staged_files` + `StagedPaths` from `__all__`.

- [ ] **Step 8: Run tests to verify they pass**

Run: `uv run pytest tests/test_adaptive_staging.py -v`
Expected: 5 tests PASS.

- [ ] **Step 9: Add tests + implementation for `read_staged_files`, `delete_staged_files`**

Append tests:

```python
def test_read_staged_files_returns_bytes(tmp_path: Path) -> None:
    from screw_agents.adaptive.staging import read_staged_files, write_staged_files

    project = tmp_path / "project"
    project.mkdir()
    source = "print('hello')\n"
    meta_yaml = "name: test\n"
    write_staged_files(
        project_root=project,
        script_name="test-script",
        source=source,
        meta_yaml=meta_yaml,
        session_id="sess-abc",
    )

    read_source, read_meta = read_staged_files(
        project_root=project,
        script_name="test-script",
        session_id="sess-abc",
    )

    assert read_source == source
    assert read_meta == meta_yaml


def test_read_staged_files_raises_on_missing(tmp_path: Path) -> None:
    from screw_agents.adaptive.staging import read_staged_files

    project = tmp_path / "project"
    project.mkdir()

    with pytest.raises(FileNotFoundError):
        read_staged_files(
            project_root=project,
            script_name="nope",
            session_id="sess-abc",
        )


def test_delete_staged_files_removes_both(tmp_path: Path) -> None:
    from screw_agents.adaptive.staging import (
        delete_staged_files,
        resolve_staging_dir,
        write_staged_files,
    )

    project = tmp_path / "project"
    project.mkdir()
    write_staged_files(
        project_root=project,
        script_name="test-script",
        source="x\n",
        meta_yaml="y\n",
        session_id="sess-abc",
    )

    delete_staged_files(
        project_root=project,
        script_name="test-script",
        session_id="sess-abc",
    )

    stage_dir = resolve_staging_dir(project, "sess-abc")
    assert not (stage_dir / "test-script.py").exists()
    assert not (stage_dir / "test-script.meta.yaml").exists()


def test_delete_staged_files_idempotent_on_missing(tmp_path: Path) -> None:
    from screw_agents.adaptive.staging import delete_staged_files

    project = tmp_path / "project"
    project.mkdir()
    # Should not raise.
    delete_staged_files(
        project_root=project,
        script_name="nope",
        session_id="sess-abc",
    )
```

- [ ] **Step 10: Implement `read_staged_files`, `delete_staged_files`**

Append to `staging.py`:

```python
def read_staged_files(
    *,
    project_root: Path,
    script_name: str,
    session_id: str,
) -> tuple[str, str]:
    """Return (source, meta_yaml) strings from staging.

    Raises FileNotFoundError if either file is missing.
    Raises ValueError wrapping OSError on other filesystem errors.
    """
    stage_dir = resolve_staging_dir(project_root, session_id)
    py_path = stage_dir / f"{script_name}.py"
    meta_path = stage_dir / f"{script_name}.meta.yaml"

    try:
        source = py_path.read_text(encoding="utf-8")
        meta_yaml = meta_path.read_text(encoding="utf-8")
    except FileNotFoundError:
        raise
    except (PermissionError, OSError) as exc:
        raise ValueError(
            f"failed to read staged files for {script_name} in {session_id} "
            f"({type(exc).__name__}: {exc})"
        ) from exc

    return source, meta_yaml


def delete_staged_files(
    *,
    project_root: Path,
    script_name: str,
    session_id: str,
) -> None:
    """Delete .py + .meta.yaml from staging (idempotent).

    Missing files are NOT an error — second-reject/second-promote scenarios.
    Raises ValueError wrapping OSError on permission / busy-file errors.
    """
    stage_dir = resolve_staging_dir(project_root, session_id)
    for suffix in (".py", ".meta.yaml"):
        target = stage_dir / f"{script_name}{suffix}"
        try:
            target.unlink(missing_ok=True)
        except (PermissionError, OSError) as exc:
            raise ValueError(
                f"failed to delete staged {target} "
                f"({type(exc).__name__}: {exc})"
            ) from exc
```

Export both from `__all__`.

- [ ] **Step 11: Run tests to verify they pass**

Run: `uv run pytest tests/test_adaptive_staging.py -v`
Expected: 9 tests PASS.

- [ ] **Step 12: Add `PendingApproval` + `StaleStagingReport` TypedDicts to models.py**

Edit `src/screw_agents/models.py`, add at end of file:

```python
class PendingApproval(TypedDict, total=False):
    """One entry in .screw/local/pending-approvals.jsonl (append-only JSONL)."""

    event: str  # "staged" | "promoted" | "promoted_via_fallback" |
                # "promoted_confirm_stale" | "rejected" | "tamper_detected" | "swept"
    script_name: str
    session_id: str
    script_sha256: str      # 64-char hex (present on staged, promoted, tamper_detected)
    target_gap: dict        # {type, file, line, agent} — present on staged
    staged_at: str          # ISO8601 UTC — present on staged
    schema_version: int     # 1 for this PR; increments on incompatible changes

    # Event-specific fields:
    signed_by: str          # promoted events
    reason: str             # rejected events
    expected_sha256: str    # tamper_detected
    actual_sha256: str      # tamper_detected
    evidence_path: str      # tamper_detected
    promoted_at: str        # promoted events
    rejected_at: str        # rejected events
    tampered_at: str        # tamper_detected
    swept_at: str           # swept events
    sweep_reason: str       # swept events ("stale_orphan" | "completed_orphan")


class StaleStagingReport(TypedDict):
    """Return shape for sweep_stale_staging."""

    status: str
    max_age_days: int
    dry_run: bool
    sessions_scanned: int
    sessions_removed: int
    scripts_removed: list[dict]       # [{script_name, session_id, reason, age_days}, ...]
    tampered_preserved: list[dict]    # [{script_name, session_id, evidence_path, age_days}, ...]
```

Verify `TypedDict` is already imported at top of file; if not, add `from typing import TypedDict`.

- [ ] **Step 13: Run full test suite**

Run: `uv run pytest -q`
Expected: `780 passed, 8 skipped` (baseline 771 + 9 new staging tests).

- [ ] **Step 14: Commit**

```bash
git add src/screw_agents/adaptive/staging.py \
        src/screw_agents/models.py \
        tests/test_adaptive_staging.py
git commit -m "feat(phase3b-c1): staging.py module with atomic file ops (T1 part 1)"
```

Registry operations (`append_registry_entry`, `query_registry`, `fallback_walk`) are added in T3-T5. Sweep (`sweep_stale`) is added in T6. This first slice covers the filesystem primitives **plus a defense-in-depth `script_name` regex validator** (`_SCRIPT_NAME_RE = r"^[a-z0-9][a-z0-9-]{2,62}$"`, byte-identical to the sibling regex in `engine.py`). Validation runs at the top of `write_staged_files`, `read_staged_files`, and `delete_staged_files` so that path-traversal primitives via `script_name` (e.g., `"../../etc/shadow"`) are rejected at the closest boundary, independent of whether the engine-layer caller validates (it will, per T3). Short-term regex duplication with `_sign_script_bytes` is absorbed by T2's shared-constant extraction — see T2's "Absorbed from T1 re-review" block below.

**Post-review absorbed scope:** two T2-destined items were flagged during T1 re-review and are recorded under Task 2 (I-new-1 trailing-newline regex footgun + I-new-2 coverage gaps). They are within-plan deferrals; nothing escapes to `docs/DEFERRED_BACKLOG.md`.

**T1 Opus 4.7 re-review findings (2026-04-21):** After the initial Sonnet review approved T1 parts 1-3, an Opus re-review caught three Important items Sonnet missed:
- **I-opus-1 + I-opus-2 (session_id validator asymmetry, commit `d70c344` T1 part 4):** the original 5-char denylist (`.` / `..` / `/` / `\\` / `\x00`) let through newlines, colons, tabs, trailing periods, leading dots, and high-bit bytes — each a distinct threat (JSONL log-injection, NTFS alternate-data-stream, hidden-dir bypass, homoglyph attack). Fix: tightened to allowlist regex `\A[A-Za-z0-9_-]{1,64}\Z` symmetric with `script_name`'s allowlist discipline. Existing `test_resolve_staging_dir_accepts_dots_within_session_id` rewritten as `test_resolve_staging_dir_rejects_dots_within_session_id` (the previous regression-guard against substring-overmatch is obsolete under an allowlist). +5 new regression tests cover newline/CR, whitespace/colon, high-bit bytes, over-length, and valid-edge-cases.
- **I-opus-3 (PendingApproval runtime per-event-type validator):** within-plan deferral to T3. See §T3's "Absorbed from T1 Opus re-review" block below.

Minor items (I-opus-4 `target_gap: dict` nesting, I-opus-5 `StaleStagingReport` nested-dict typing, M-opus-1..4 test-coverage/docstring nits) deferred to `docs/DEFERRED_BACKLOG.md` as BACKLOG-PR6-01..06 under "Phase 3b PR #6 follow-ups".

---

### Task 2: Extract `_sign_script_bytes` Shared Helper (Option D Refactor) + Absorb I-new-1 / I-new-2

**Files:**
- **Create:** `src/screw_agents/adaptive/script_name.py` — dedicated 20-line module owning the shared regex + validator. Contents:
  - `SCRIPT_NAME_RE = re.compile(r"\A[a-z0-9][a-z0-9-]{2,62}\Z")` — anchored with `\A…\Z` (not `^…$`) so terminal newlines are rejected (see I-new-1).
  - `USER_FACING_NAME_REGEX = "^[a-z0-9][a-z0-9-]{2,62}$"` — string constant for error messages shown to users (keeps the familiar `^…$` notation users see in docs; internal match uses the precise `\A…\Z` form).
  - `validate_script_name(script_name: str) -> None` — raises `ValueError` with `f"script_name {script_name!r} does not match {USER_FACING_NAME_REGEX} (...)"` on mismatch.
  - `__all__ = ["SCRIPT_NAME_RE", "USER_FACING_NAME_REGEX", "validate_script_name"]`.
  - This module is a pure leaf — no imports from other `screw_agents` submodules. Both `staging.py` and `signing.py` import from here; `engine.py` imports from here too (for the error-message constants; the validation itself runs inside `_sign_script_bytes`).
- Modify: `src/screw_agents/adaptive/signing.py` (add `_sign_script_bytes`; import `SCRIPT_NAME_RE` / `USER_FACING_NAME_REGEX` / `validate_script_name` from `script_name.py`)
- Modify: `src/screw_agents/adaptive/staging.py` — **DELETE** lines 46-48 (local `_SCRIPT_NAME_RE` constant), DELETE `_validate_script_name` helper body, replace with `from screw_agents.adaptive.script_name import validate_script_name` and a one-liner wrapper (or directly call `validate_script_name(script_name)` at the 3 public FS-op entry points). Existing `staging.py` test coverage remains valid because the public FS-op behavior is unchanged — only the error message wording may shift (see test-assertion audit in Step 9).
- Modify: `src/screw_agents/engine.py` — **DELETE** line 51 (`_SCRIPT_NAME_RE = re.compile(...)` module constant) since it's no longer used (the current 2 in-method references at lines 324 + 329 both move into `_sign_script_bytes`). The `import re` may also be removable from engine.py if no other usage remains — implementer to verify and clean. Refactor `sign_adaptive_script` to delegate to `_sign_script_bytes` (Step 5).
- Modify: `tests/test_adaptive_signing.py` (+5 original shared-helper tests + 5-7 regression tests for I-new-1 / I-new-2)
- Modify: `tests/test_adaptive_staging.py` — update the existing `_validate_script_name` import to route via `script_name.py` (or via staging.py's re-export). Keep existing staging regex-validation tests unchanged — they exercise the public staging FS-op API which still enforces validation. Add ONE locking test: `test_staging_imports_from_shared_script_name_module` asserting `staging.py` no longer has a local `_SCRIPT_NAME_RE`.

**Rationale:** Per Q4 / spec §3.7, both `sign_adaptive_script` (direct path) and the upcoming `promote_staged_script` (staged path) must produce byte-identical signed output for the same (source, meta). A shared internal helper is the single canonical-bytes source, eliminating drift risk. T2 also becomes the architectural fix site for the two regex items the T1 re-review surfaced — both the shared-helper extraction and the regex-constant extraction land in one coherent refactor.

**Pre-audit checklist (per `feedback_deeper_pre_audit`):**
- Map every place in engine.py's current `sign_adaptive_script` that touches canonical bytes, signature bytes, or file bytes. Confirm each translates 1:1 to a call into `_sign_script_bytes`.
- Verify `build_signed_script_meta` and `compute_script_sha256` already live in signing.py (they do, from T18a). `_sign_script_bytes` COMPOSES them; does not duplicate them.
- T22's test calls `engine.sign_adaptive_script(...)`. After refactor, T22 MUST pass unchanged. If T22 changes behavior, refactor is wrong.
- **Regex anchors:** Switch from `^…$` to `\A…\Z` (or use `.fullmatch()` consistently) when consolidating. Python's `$` anchor matches before a terminal `\n`, which lets `"abc\n"` through — not a traversal primitive but a registry/log-formatting footgun. Both `staging.py` and `engine.py:51`'s current regex inherit this; the single consolidation must close it for both.
- **Audit existing call sites** of the current `engine.py` name regex and `staging.py`'s local validator. All should route through the new shared constant after T2. No more duplication.

**Absorbed from T1 re-review (2026-04-21):** Two items the quality reviewer flagged at T1 re-review are in-scope for T2 because T2 is the architectural fix site (shared-constant extraction):

- **I-new-1 (trailing-newline regex footgun):** `r"^[a-z0-9][a-z0-9-]{2,62}$"` matches `"abc\n"` because Python's `$` anchor matches before a terminal newline. Not a traversal primitive (no slash) but corrupts JSONL registry lines in T3+ that embed `script_name`, poisons error-message formatting, and breaks log parsing. **Fix at shared-constant extraction time** — use `r"\A[a-z0-9][a-z0-9-]{2,62}\Z"` in ONE place (the new `script_name.py` module). `\A` and `\Z` are true start/end-of-string anchors with no newline-special-casing. Pre-audit note: `"abc\r\n"` is already rejected today (the `\r` fails the `[a-z0-9-]` character class check before the anchor is reached), so the only newline-case the anchor switch actually changes is `"abc\n"`. The CRLF case is preserved as a regression test to lock behavior.
- **I-new-2 (regex test coverage gaps):** Add dedicated regression tests for these named cases. Note which ones the anchor switch changes vs which were already covered by the character class:
  - `""` (empty) — reject (length < 3); currently rejected; lock with explicit test.
  - `"---"` (dash-only) — **reject** (first char `-` is not in `[a-z0-9]`; regex requires first-char alnum). Clarification: the reviewer's note said "should match per regex" which was incorrect on my part — the first-char class is `[a-z0-9]` (no dash). Already rejected today; lock with explicit test.
  - `"a\x00b"` (null byte) — reject (null not in `[a-z0-9-]`); currently rejected; lock.
  - `"a" * 64` (over-limit) — reject (length > 63); currently rejected; lock.
  - `"abc\n"` (trailing LF) — **currently passes; becomes rejection after I-new-1**. The primary fix.
  - `"abc\r\n"` (trailing CRLF) — reject (`\r` fails char class); currently rejected; lock for regression coverage.
  - `"ab cd"` (space) — reject (space not in char class); currently rejected; lock.

  Place tests in `tests/test_adaptive_signing.py` (alongside the new `_sign_script_bytes` tests). Also add ONE locking test in `tests/test_adaptive_staging.py`: `test_staging_imports_from_shared_script_name_module` asserting the local `_SCRIPT_NAME_RE` constant was removed and `staging.py` imports from `adaptive.script_name`.

- [ ] **Step 1: Read current engine.sign_adaptive_script carefully**

Run: `grep -n "def sign_adaptive_script" src/screw_agents/engine.py`
Then open the method. Count: the lines between the `def` and the next method. That's the chunk we're moving into `_sign_script_bytes`.

- [ ] **Step 2: Write failing tests for shared-helper invariance**

Add to `tests/test_adaptive_signing.py`:

```python
import inspect


def test_sign_script_bytes_is_defined_in_signing_module() -> None:
    """Locking: _sign_script_bytes lives in adaptive.signing, not engine.

    If this test breaks, the Option D refactor has regressed — the shared
    helper got moved back inline into engine.sign_adaptive_script.
    """
    from screw_agents.adaptive import signing

    assert hasattr(signing, "_sign_script_bytes"), (
        "_sign_script_bytes missing from adaptive/signing.py — "
        "Option D shared helper regressed"
    )


def test_sign_adaptive_script_delegates_to_sign_script_bytes(
    tmp_path, monkeypatch
) -> None:
    """Option D delegation: sign_adaptive_script MUST call _sign_script_bytes.

    Mocks _sign_script_bytes, asserts engine.sign_adaptive_script calls it
    with the same inputs and returns its result.

    PYTHON SEMANTICS NOTE: engine.py uses `from screw_agents.adaptive.signing
    import _sign_script_bytes` which binds the name in engine.py's namespace
    at import time. Monkey-patching `signing._sign_script_bytes` does NOT
    redirect engine's already-captured reference — engine would still call
    the real function, call_log["called"] would stay False, and the test
    would fail confusingly. The correct patch target is engine's own
    reference (`engine_module._sign_script_bytes`). Pre-audit caught this
    pattern on 2026-04-21; do not "simplify" back to patching `signing`.
    """
    import screw_agents.engine as engine_module
    from screw_agents.engine import ScanEngine

    call_log = {"called": False, "kwargs": None}

    def fake_helper(**kwargs):
        call_log["called"] = True
        call_log["kwargs"] = kwargs
        return {
            "status": "signed",
            "message": f"Signed adaptive script {kwargs['script_name']} (mock).",
            "script_path": str(kwargs["project_root"] / ".screw" / "custom-scripts" / f"{kwargs['script_name']}.py"),
            "meta_path": str(kwargs["project_root"] / ".screw" / "custom-scripts" / f"{kwargs['script_name']}.meta.yaml"),
            "signed_by": "mock@example.com",
            "sha256": "a" * 64,
            "session_id": kwargs.get("session_id"),
        }

    # Patch engine's captured reference, NOT signing's module attribute.
    monkeypatch.setattr(engine_module, "_sign_script_bytes", fake_helper)

    project = tmp_path / "project"
    project.mkdir()
    engine = ScanEngine.from_defaults()

    result = engine.sign_adaptive_script(
        project_root=project,
        script_name="test-script",
        source="print('hi')\n",
        meta={"name": "test-script", "created": "2026-04-20T00:00:00Z",
              "created_by": "me@example.com", "domain": "injection-input-handling",
              "description": "test", "target_patterns": ["foo.bar"]},
        session_id="sess-abc",
    )

    assert call_log["called"]
    assert call_log["kwargs"]["script_name"] == "test-script"
    assert result["status"] == "signed"
```

Add 3 more tests:
- `test_sign_script_bytes_canonical_bytes_stable` — calling `_sign_script_bytes` twice with equivalent inputs produces byte-identical signed output on disk.
- `test_sign_script_bytes_roundtrip_verifies` — output of `_sign_script_bytes` passes `trust.verify_script`.
- `test_sign_script_bytes_no_writes_on_collision` — if custom-scripts target exists, raises without touching filesystem.

(Implement the 3 by expanding the fixture in step 2 to set up a real signing key via `run_init_trust`; see existing `test_sign_adaptive_script.py` for the pattern — copy the setup, NOT re-invent.)

- [ ] **Step 3: Run tests to verify they fail**

Run: `uv run pytest tests/test_adaptive_signing.py -v`
Expected: First 2 new tests FAIL with `AttributeError: module 'screw_agents.adaptive.signing' has no attribute '_sign_script_bytes'`. Others depend on the helper existing.

- [ ] **Step 4: Move canonical-bytes + sign + atomic-write logic from engine to signing.py**

In `src/screw_agents/adaptive/signing.py`, add (after existing functions):

```python
def _sign_script_bytes(
    *,
    project_root: Path,
    script_name: str,
    source: str,
    meta_dict: dict,
    session_id: str | None = None,
) -> dict:
    """Sign + atomically write source + meta to .screw/custom-scripts/.

    This is the SINGLE canonical-bytes source for both signing entry points:
    - engine.sign_adaptive_script (direct path; caller provides source+meta)
    - engine.promote_staged_script (staged path; caller loaded source+meta
      from staging dir before calling here)

    Design: Q4 / spec §3.7. The T13-C1 canonical-bytes discipline (route
    meta through AdaptiveScriptMeta().model_dump() BEFORE canonicalize_script)
    lives here. Callers MUST NOT bypass this helper — no direct calls to
    sign_content/canonicalize_script from engine methods.

    Atomic write ORDER-SENSITIVE (same as T18a): .py first, .meta.yaml second,
    with best-effort unlink-of-.py on meta failure. If this order changes,
    Layer 2 hash-pin may read a file with stale meta.

    Raises:
        ValueError: wrapping (PermissionError, OSError) on filesystem errors.
        ValueError: on invalid inputs (name regex, missing reviewer).
    Returns:
        {"status": "signed" | "error", ...}
    """
    # [Implementation: LIFT the current body of engine.sign_adaptive_script
    # starting from the name-regex validation through the final success-return.
    # Keep the fresh-script semantics (collision check), Model A fingerprint
    # matching, canonicalize_script + sign_content call, atomic write pair,
    # and the friendly-wrapped (PermissionError, OSError) handler.
    # See the current engine.sign_adaptive_script for the exact source to move.]
    ...
```

**Implementation note:** The body that currently lives in `engine.sign_adaptive_script` is ~80 LOC (engine.py lines ~320-545). LIFT IT VERBATIM into `_sign_script_bytes`, adjusting only these concrete items:

1. **Remove `self,` from the signature** — helper is module-level. Rename `meta: dict` → `meta_dict: dict` (parameter name matches plan's `_sign_script_bytes` signature).
2. **Name validation** — replace the 2 current call sites (engine.py:324 and :329) with a single call to `validate_script_name(script_name)` from the new `script_name.py` module. The validator raises `ValueError`; catch it and convert to the `{"status": "error", "message": ...}` dict shape to preserve the current error-return contract. Keep `"Invalid script name"` as the substring in the error message — the existing `test_sign_rejects_invalid_names` parametrize test asserts this at test_sign_adaptive_script.py:177.
3. **Imports** — add to `signing.py`'s import block: `os`, `yaml`, `Path`, `_get_or_create_local_private_key` from `screw_agents.learning`, `load_config` + `_find_matching_reviewer` + `_fingerprint_public_key` + `_load_public_keys_with_reviewers` from `screw_agents.trust`, and the new `SCRIPT_NAME_RE` / `USER_FACING_NAME_REGEX` / `validate_script_name` from `screw_agents.adaptive.script_name`.
4. **No `self._config` reads to adjust** — pre-audit (2026-04-21) confirmed the current method does NOT read `self._config`; it already calls `load_config(project_root)` locally at engine.py:373. An earlier draft of this plan warned about `self._config` migration — that note was incorrect and has been removed.

**PROHIBITED during the move:**
- Adding `# type: ignore` annotations
- Changing the method's return-dict shape (keys must remain: `status`, `message`, `script_path`, `meta_path`, `signed_by`, `sha256`, `session_id`)
- Changing error-message substrings that existing tests assert on:
  - `"Invalid script name"` (test_sign_adaptive_script.py:177)
  - `"already exists"` + `"validate-script"` (:113, :140)
  - `"script_reviewers"` + `"init-trust"` (:197)
  - `"does not match any registered reviewer"` + `"init-trust"` (:251)
  - `"AdaptiveScriptMeta schema"` (:401)
  - `"rolled back"` (:368) — from the `ValueError` raised on meta-write failure
  - `"script source"` (:446) — from the `ValueError` raised on source-write failure
- Changing the atomic-write filename pattern (`{script_name}.py.tmp`, `{script_name}.meta.yaml.tmp`) — `test_sign_atomic_write_rollback_on_meta_failure` asserts on `rollback-test.meta.yaml.tmp` at :372.

Pre-audit discipline: before committing, run `diff <(git show 1d07d6b:src/screw_agents/engine.py | sed -n '320,545p') <(grep -n ... _sign_script_bytes body)` and visually confirm the moved body is behaviorally identical (allowing for the name-validation-via-validator refactor at point 2 above).

- [ ] **Step 5: Refactor `engine.sign_adaptive_script` to delegate**

In `src/screw_agents/engine.py`, replace the entire body of `sign_adaptive_script` with:

```python
def sign_adaptive_script(
    self,
    *,
    project_root: Path,
    script_name: str,
    source: str,
    meta: dict,
    session_id: str | None = None,
) -> dict:
    """Sign + write a fresh adaptive script (approve-path for programmatic
    callers and autoresearch). For LLM-driven review flows, use
    ``stage_adaptive_script`` + ``promote_staged_script`` instead —
    promote_staged_script takes no ``source`` parameter, closing the C1
    regeneration surface.

    Delegates signing to ``adaptive.signing._sign_script_bytes``, the
    shared helper (Option D; spec §3.7). The public API + side effects
    are unchanged from T18a.

    See signing._sign_script_bytes for validation, atomic-write, and
    friendly-error-wrapping contracts.
    """
    return _sign_script_bytes(
        project_root=project_root,
        script_name=script_name,
        source=source,
        meta_dict=meta,
        session_id=session_id,
    )
```

Ensure `from screw_agents.adaptive.signing import _sign_script_bytes` is at the top of engine.py.

- [ ] **Step 6: Run targeted tests first**

Run: `uv run pytest tests/test_adaptive_signing.py tests/test_sign_adaptive_script.py tests/test_adaptive_workflow.py -v`
Expected: All pass. Both test files exercise the same `engine.sign_adaptive_script` public API, and the refactor is transparent.

- [ ] **Step 7: Run full test suite**

Run: `uv run pytest -q`
Expected: **~800 passed, 8 skipped** (790 post-T1 part 3 + 5 new signing-helper tests + ~5 regression tests for I-new-1 / I-new-2; final count depends on how many boundary cases the implementer adds per I-new-2). The baseline bumped from 780 to 790 because T1 absorbed 10 additional tests (part-2 quality-fix regressions + part-3 defense-in-depth coverage).

- [ ] **Step 8: Commit**

```bash
git add src/screw_agents/adaptive/script_name.py \
        src/screw_agents/adaptive/signing.py \
        src/screw_agents/adaptive/staging.py \
        src/screw_agents/engine.py \
        tests/test_adaptive_signing.py \
        tests/test_adaptive_staging.py
git commit -m "refactor(phase3b-c1): extract _sign_script_bytes + shared SCRIPT_NAME_RE (T2, Option D + I-new-1/2)"
```

**Cross-plan sync:** no deviation from spec §3.7 on the shared-helper refactor. The regex-extraction addition (I-new-1 / I-new-2) was deferred from T1 per `feedback_deferral_destination` (within-plan deferral, plan-sync committed before T2 dispatch). If the refactor requires changing `sign_adaptive_script`'s public signature (it should NOT), stop and update spec §3.7 + this task before continuing.

**T2 Opus 4.7 re-review (2026-04-21):** APPROVED — nothing substantive missed by the earlier Sonnet spec review. Three minor items identified:
- **M-1 (dead imports in `engine.py` after refactor):** fixed in T1 part 4 commit `d70c344` (bundled with the session_id tightening since both touched `engine.py`). Removed unused `build_signed_script_meta`, `compute_script_sha256`, `_get_or_create_local_private_key`, `_find_matching_reviewer`, `_fingerprint_public_key`, `_load_public_keys_with_reviewers` imports.
- **M-2 (`test_public_api_count_is_under_29` function-name / assertion visual inconsistency):** deferred to DEFERRED_BACKLOG as BACKLOG-PR6-07.
- **M-3 (`adaptive/__init__.py` stale "under 25 exports" docstring):** deferred to DEFERRED_BACKLOG as BACKLOG-PR6-08.

---

## Phase B — C1 Core MCP Tools (T3-T6)

### Task 3: `stage_adaptive_script` MCP Tool

**Files:**
- Modify: `src/screw_agents/adaptive/staging.py` (add `append_registry_entry`, `query_registry_most_recent`, `fallback_walk_for_script`, `validate_pending_approval`, `_REQUIRED_FIELDS_BY_EVENT`, `_utc_now_iso`; import `compute_script_sha256` from `signing.py` — do NOT duplicate it)
- Modify: `src/screw_agents/engine.py` (add `stage_adaptive_script` method)
- Modify: `src/screw_agents/server.py` (register MCP tool)
- Modify: `tests/test_adaptive_staging.py` (+6 tests for stage flow)

**Pre-audit checklist:**
- Confirm atomic registry append semantics: JSONL append via `open(..., "a")` + single `write()` call is POSIX-atomic for writes under PIPE_BUF (4096 bytes). Registry entries are <500 bytes. Safe for single-process MCP.
- Name-regex lives as a shared constant after T2 (`SCRIPT_NAME_RE`, anchored `\A…\Z`, extracted per T2's "Absorbed from T1 re-review" block). Both `adaptive/staging.py` (defense-in-depth, added in T1 part 3) and `_sign_script_bytes` call the shared validator. T3's `stage_adaptive_script` gets name validation for free by routing through both layers — do NOT duplicate the regex a third time. If T2 did NOT consolidate as planned, STOP and fix T2 first.
- Session_id validator is the `\A[A-Za-z0-9_-]{1,64}\Z` allowlist added in T1 part 4 (commit `d70c344`). T3's `stage_adaptive_script` calls into `resolve_staging_dir` which enforces it — no additional session_id validation needed at the engine layer.
- stage is idempotent on byte-identical re-stage (same sha256 → update timestamps, no error). Error on same script_name + different sha256.

**Absorbed from T1 Opus re-review (2026-04-21):** One item requires T3's attention as the first producer of `PendingApproval` entries to the JSONL audit log:

- **I-opus-3 (PendingApproval runtime per-event-type validator):** `PendingApproval(TypedDict, total=False)` in `models.py` has inline comments documenting which fields are required per event type (`staged`, `promoted`, `promoted_via_fallback`, `promoted_confirm_stale`, `rejected`, `tamper_detected`, `swept`) but no runtime enforcement. A producer could silently emit `{"event": "staged"}` without `script_sha256` / `target_gap` / `staged_at` — corrupting the forensic-audit JSONL stream. T3 is the first task that writes `PendingApproval` entries (`append_registry_entry`); validate the entry shape before the JSONL write.

  **Suggested approach:** Add to `adaptive/staging.py`:
  ```python
  _REQUIRED_FIELDS_BY_EVENT: dict[str, frozenset[str]] = {
      "staged": frozenset({"event", "script_name", "session_id", "script_sha256",
                          "target_gap", "staged_at", "schema_version"}),
      "promoted": frozenset({"event", "script_name", "session_id", "script_sha256",
                            "signed_by", "promoted_at", "schema_version"}),
      "promoted_via_fallback": frozenset({"event", "script_name", "session_id",
                                         "script_sha256", "signed_by", "promoted_at",
                                         "schema_version"}),
      "promoted_confirm_stale": frozenset({"event", "script_name", "session_id",
                                          "script_sha256", "signed_by", "promoted_at",
                                          "schema_version"}),
      "rejected": frozenset({"event", "script_name", "session_id", "reason",
                            "rejected_at", "schema_version"}),
      "tamper_detected": frozenset({"event", "script_name", "session_id",
                                   "expected_sha256", "actual_sha256",
                                   "evidence_path", "tampered_at", "schema_version"}),
      "swept": frozenset({"event", "script_name", "session_id", "swept_at",
                         "sweep_reason", "schema_version"}),
  }

  def validate_pending_approval(entry: PendingApproval) -> None:
      """Raise ValueError if entry lacks required fields for its event type.

      Called from `append_registry_entry` before the JSONL write to
      prevent silent forensic-audit corruption. Unknown event types raise
      (new event types require an explicit opt-in via this dict).
      """
      event = entry.get("event")
      if event is None:
          raise ValueError("PendingApproval entry missing required 'event' field")
      required = _REQUIRED_FIELDS_BY_EVENT.get(event)
      if required is None:
          raise ValueError(f"PendingApproval entry has unknown event type: {event!r}")
      missing = required - set(entry.keys())
      if missing:
          raise ValueError(
              f"PendingApproval '{event}' entry missing required fields: "
              f"{sorted(missing)}"
          )
  ```

  Call site (at the top of `append_registry_entry`):
  ```python
  def append_registry_entry(project_root: Path, entry: PendingApproval) -> None:
      validate_pending_approval(entry)  # fail fast before any I/O
      registry_path = resolve_registry_path(project_root)
      registry_path.parent.mkdir(parents=True, exist_ok=True)
      with open(registry_path, "a", encoding="utf-8") as f:
          f.write(json.dumps(entry, sort_keys=True) + "\n")
  ```

  **Tests to add in T3** (alongside the existing stage-flow tests): (a) valid `staged` entry writes successfully; (b) `{"event": "staged"}` without `script_sha256` raises `ValueError`; (c) unknown event type raises; (d) `tamper_detected` entry missing `evidence_path` raises.

- [ ] **Step 1: Write failing tests — happy-path stage**

Add to `tests/test_adaptive_staging.py`:

```python
def test_stage_adaptive_script_writes_files_and_registry(tmp_path: Path) -> None:
    from screw_agents.engine import ScanEngine
    from screw_agents.adaptive.staging import resolve_registry_path, resolve_staging_dir

    project = tmp_path / "project"
    project.mkdir()
    engine = ScanEngine.from_defaults()
    source = (
        "from screw_agents.adaptive import emit_finding, find_calls\n"
        "\n"
        "def analyze(project):\n"
        "    for call in find_calls(project, 'foo.bar'):\n"
        "        emit_finding(cwe='CWE-89', file=call.file, line=call.line,\n"
        "                     message='stub', severity='high')\n"
    )
    meta = {
        "name": "test-stage-001",
        "created": "2026-04-20T10:00:00Z",
        "created_by": "tester@example.com",
        "domain": "injection-input-handling",
        "description": "fixture for stage test",
        "target_patterns": ["foo.bar"],
    }

    response = engine.stage_adaptive_script(
        project_root=project,
        script_name="test-stage-001",
        source=source,
        meta=meta,
        session_id="sess-abc",
        target_gap={"type": "unresolved_sink", "file": "dao.py", "line": 13, "agent": "sqli"},
    )

    assert response["status"] == "staged"
    assert response["script_name"] == "test-stage-001"
    assert response["session_id"] == "sess-abc"
    assert len(response["script_sha256"]) == 64
    assert response["script_sha256_prefix"] == response["script_sha256"][:8]
    assert response["session_id_short"].startswith("sess-abc")

    stage_dir = resolve_staging_dir(project, "sess-abc")
    assert (stage_dir / "test-stage-001.py").read_text() == source

    # Registry entry exists.
    registry_path = resolve_registry_path(project)
    assert registry_path.exists()
    entries = [json.loads(line) for line in registry_path.read_text().splitlines() if line.strip()]
    assert len(entries) == 1
    entry = entries[0]
    assert entry["event"] == "staged"
    assert entry["script_name"] == "test-stage-001"
    assert entry["session_id"] == "sess-abc"
    assert entry["script_sha256"] == response["script_sha256"]
    assert entry["target_gap"]["file"] == "dao.py"
    assert entry["schema_version"] == 1


def test_stage_adaptive_script_rejects_invalid_script_name(tmp_path: Path) -> None:
    from screw_agents.engine import ScanEngine

    project = tmp_path / "project"
    project.mkdir()
    engine = ScanEngine.from_defaults()

    response = engine.stage_adaptive_script(
        project_root=project,
        script_name="AA",  # too short (regex requires len 3-63)
        source="pass\n",
        meta={"name": "AA", "created": "2026-04-20T10:00:00Z",
              "created_by": "t@e.co", "domain": "injection-input-handling",
              "description": "d", "target_patterns": ["x"]},
        session_id="sess-abc",
        target_gap=None,
    )

    assert response["status"] == "error"
    assert response["error"] == "invalid_script_name"
    assert "AA" in response["message"]


def test_stage_adaptive_script_rejects_empty_session_id(tmp_path: Path) -> None:
    from screw_agents.engine import ScanEngine

    project = tmp_path / "project"
    project.mkdir()
    engine = ScanEngine.from_defaults()

    response = engine.stage_adaptive_script(
        project_root=project,
        script_name="test-001",
        source="pass\n",
        meta={"name": "test-001", "created": "2026-04-20T10:00:00Z",
              "created_by": "t@e.co", "domain": "injection-input-handling",
              "description": "d", "target_patterns": ["x"]},
        session_id="",
        target_gap=None,
    )

    assert response["status"] == "error"
    assert response["error"] == "invalid_session_id"


@pytest.mark.parametrize(
    "bad_session_id",
    [
        "foo\nbar",        # newline — I-opus-1 JSONL injection
        "foo:bar",         # colon — NTFS ADS primitive
        ".hidden",         # leading dot — hidden-dir bypass
        "foo\xff",         # high-bit byte — homoglyph primitive
        "foo bar",         # space
        "foo\tbar",        # tab
        "a" * 65,          # over-length
        "../etc/passwd",   # path traversal
        "foo/bar",         # slash
        "foo\\bar",        # backslash
        ".",               # bare dot
        "..",              # bare dots
    ],
)
def test_stage_adaptive_script_rejects_threat_session_ids(
    tmp_path: Path, bad_session_id: str
) -> None:
    """P2 regression: the engine-layer error-dict conversion fires for
    all session_id threat vectors closed by the T1-part-4 allowlist
    (I-opus-1 + I-opus-2). Validates the ValueError → error-dict path
    in `stage_adaptive_script` rather than just `resolve_staging_dir`.
    """
    from screw_agents.engine import ScanEngine

    project = tmp_path / "project"
    project.mkdir()
    engine = ScanEngine.from_defaults()

    response = engine.stage_adaptive_script(
        project_root=project,
        script_name="test-001",
        source="pass\n",
        meta={"name": "test-001", "created": "2026-04-20T10:00:00Z",
              "created_by": "t@e.co", "domain": "injection-input-handling",
              "description": "d", "target_patterns": ["x"]},
        session_id=bad_session_id,
        target_gap=None,
    )

    assert response["status"] == "error"
    assert response["error"] == "invalid_session_id"


def test_stage_adaptive_script_idempotent_on_same_content(tmp_path: Path) -> None:
    from screw_agents.engine import ScanEngine
    from screw_agents.adaptive.staging import resolve_registry_path

    project = tmp_path / "project"
    project.mkdir()
    engine = ScanEngine.from_defaults()
    common = dict(
        project_root=project,
        script_name="test-idem-001",
        source="pass\n",
        meta={"name": "test-idem-001", "created": "2026-04-20T10:00:00Z",
              "created_by": "t@e.co", "domain": "injection-input-handling",
              "description": "d", "target_patterns": ["x"]},
        session_id="sess-abc",
        target_gap=None,
    )

    r1 = engine.stage_adaptive_script(**common)
    r2 = engine.stage_adaptive_script(**common)

    assert r1["status"] == "staged"
    assert r2["status"] == "staged"
    # P4: `sha256(same source) == sha256(same source)` is tautological;
    # assert FILESYSTEM + REGISTRY state to prove idempotency actually
    # worked end-to-end:
    from screw_agents.adaptive.staging import resolve_staging_dir
    stage_dir = resolve_staging_dir(project, "sess-abc")
    assert (stage_dir / "test-idem-001.py").read_text(encoding="utf-8") == "pass\n"
    assert (stage_dir / "test-idem-001.meta.yaml").exists()

    # Registry gets TWO entries even on idempotent re-stage (each event is recorded).
    # The LOOKUP path uses "most-recent" semantics so this is fine.
    entries = [json.loads(line) for line in resolve_registry_path(project).read_text().splitlines() if line.strip()]
    assert len(entries) == 2
    assert all(e["event"] == "staged" for e in entries)
    assert all(e["script_sha256"] == r1["script_sha256"] for e in entries)
    # Second entry's staged_at >= first entry's staged_at (monotonic).
    assert entries[1]["staged_at"] >= entries[0]["staged_at"]


def test_stage_adaptive_script_collision_on_same_name_different_content(tmp_path: Path) -> None:
    from screw_agents.engine import ScanEngine

    project = tmp_path / "project"
    project.mkdir()
    engine = ScanEngine.from_defaults()

    r1 = engine.stage_adaptive_script(
        project_root=project,
        script_name="test-coll-001",
        source="pass\n",
        meta={"name": "test-coll-001", "created": "2026-04-20T10:00:00Z",
              "created_by": "t@e.co", "domain": "injection-input-handling",
              "description": "d", "target_patterns": ["x"]},
        session_id="sess-abc",
        target_gap=None,
    )
    assert r1["status"] == "staged"

    r2 = engine.stage_adaptive_script(
        project_root=project,
        script_name="test-coll-001",
        source="print('different')\n",  # different bytes, same name
        meta={"name": "test-coll-001", "created": "2026-04-20T10:00:00Z",
              "created_by": "t@e.co", "domain": "injection-input-handling",
              "description": "d", "target_patterns": ["x"]},
        session_id="sess-abc",
        target_gap=None,
    )

    assert r2["status"] == "error"
    assert r2["error"] == "stage_name_collision"
    assert "existing_sha256_prefix" in r2
    assert r2["existing_sha256_prefix"] == r1["script_sha256"][:8]


def test_stage_adaptive_script_wraps_permission_error(tmp_path, monkeypatch) -> None:
    from screw_agents.engine import ScanEngine

    project = tmp_path / "project"
    project.mkdir()
    engine = ScanEngine.from_defaults()

    def boom(*args, **kwargs):
        raise PermissionError("simulated")

    monkeypatch.setattr(Path, "mkdir", boom)

    with pytest.raises(ValueError, match="PermissionError"):
        engine.stage_adaptive_script(
            project_root=project,
            script_name="test-perm-001",
            source="pass\n",
            meta={"name": "test-perm-001", "created": "2026-04-20T10:00:00Z",
                  "created_by": "t@e.co", "domain": "injection-input-handling",
                  "description": "d", "target_patterns": ["x"]},
            session_id="sess-abc",
            target_gap=None,
        )
```

- [ ] **Step 2: Run tests — verify they fail**

Run: `uv run pytest tests/test_adaptive_staging.py -v -k "stage_adaptive_script"`
Expected: 6 FAILs with `AttributeError: 'ScanEngine' object has no attribute 'stage_adaptive_script'`.

- [ ] **Step 3: Implement registry helpers in `staging.py`**

Append to `src/screw_agents/adaptive/staging.py`:

```python
import json
from datetime import datetime, timezone


# NOTE: do NOT define a new `compute_script_sha256_str` here. T2 already
# exports `compute_script_sha256` from `screw_agents.adaptive.signing`
# (same encoding, same algorithm, same hex output). Re-use it. Add to
# staging.py's imports block at the top of the module:
#
#     from screw_agents.adaptive.signing import compute_script_sha256
#
# A duplicate helper would re-introduce exactly the drift risk T2 worked
# to eliminate when it consolidated SCRIPT_NAME_RE.


def append_registry_entry(project_root: Path, entry: dict) -> None:
    """Append one JSONL entry to pending-approvals.jsonl atomically.

    POSIX-atomicity: a single write() call < PIPE_BUF bytes is atomic
    on Linux. Entries are <500 bytes; safe for single-process MCP.
    Creates parent dirs if needed. Raises ValueError on filesystem
    errors per T13-C1 discipline.

    Call `validate_pending_approval(entry)` BEFORE this function in the
    engine layer (or invoke it here as the first line) to ensure the
    entry meets the per-event-type required-field contract. See
    "Absorbed from T1 Opus re-review" above for the validator spec.

    PARTIAL-STATE SEMANTICS: If the engine has already written the
    staged `.py` + `.meta.yaml` files and THIS registry append raises
    ValueError, the staged files remain on disk without a registry
    entry. This is deliberate — the filesystem is the source of truth;
    the registry is the audit log. T6's `sweep_stale_staging` recovers
    orphaned staging dirs by age. The engine does NOT roll back staged
    files on registry-write failure.
    """
    validate_pending_approval(entry)  # I-opus-3: fail-fast before any I/O
    registry_path = resolve_registry_path(project_root)
    try:
        registry_path.parent.mkdir(parents=True, exist_ok=True)
        line = json.dumps(entry, separators=(",", ":"), sort_keys=True) + "\n"
        # O_APPEND | O_WRONLY | O_CREAT; let OS handle the atomic append.
        fd = os.open(registry_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)
        try:
            os.write(fd, line.encode("utf-8"))
        finally:
            os.close(fd)
    except (PermissionError, OSError) as exc:
        raise ValueError(
            f"failed to append registry entry to {registry_path} "
            f"({type(exc).__name__}: {exc})"
        ) from exc


def query_registry_most_recent(
    project_root: Path,
    *,
    script_name: str,
    session_id: str,
) -> dict | None:
    """Return the most-recent registry entry matching (script_name, session_id).

    Returns None if registry file is missing, empty, or no matching entry.
    Ignores corrupted JSONL lines (logs-then-skips); returns whatever valid
    entries matched. The caller interprets "no matching entry" as "fall back
    to filesystem walk" per Q3.
    """
    registry_path = resolve_registry_path(project_root)
    if not registry_path.exists():
        return None
    try:
        lines = registry_path.read_text(encoding="utf-8").splitlines()
    except (PermissionError, OSError) as exc:
        raise ValueError(
            f"failed to read registry {registry_path} "
            f"({type(exc).__name__}: {exc})"
        ) from exc

    most_recent: dict | None = None
    for raw in lines:
        raw = raw.strip()
        if not raw:
            continue
        try:
            entry = json.loads(raw)
        except json.JSONDecodeError:
            continue  # corrupt line; tolerate
        if entry.get("script_name") == script_name and entry.get("session_id") == session_id:
            most_recent = entry  # later entries overwrite earlier
    return most_recent


def fallback_walk_for_script(
    project_root: Path,
    *,
    script_name: str,
) -> list[tuple[str, Path]]:
    """Walk .screw/staging/*/adaptive-scripts/ for {script_name}.py.

    Returns [(session_id, py_path), ...]. Used when registry lookup fails
    (Q3 fallback path). Empty list if nothing found.
    """
    staging_root = project_root / ".screw" / "staging"
    if not staging_root.exists():
        return []
    matches: list[tuple[str, Path]] = []
    try:
        for session_dir in sorted(staging_root.iterdir()):
            if not session_dir.is_dir():
                continue
            py = session_dir / "adaptive-scripts" / f"{script_name}.py"
            if py.exists():
                matches.append((session_dir.name, py))
    except (PermissionError, OSError) as exc:
        raise ValueError(
            f"failed to walk staging root {staging_root} "
            f"({type(exc).__name__}: {exc})"
        ) from exc
    return matches


def _utc_now_iso() -> str:
    """Return UTC now as ISO8601 with Z suffix (seconds precision)."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
```

**Exports in `__all__`:** add the three public helpers — `append_registry_entry`, `query_registry_most_recent`, `fallback_walk_for_script`, and `validate_pending_approval` (the I-opus-3 validator). Keep underscore-prefixed helpers PRIVATE (do NOT add to `__all__`): `_utc_now_iso`, `_REQUIRED_FIELDS_BY_EVENT`, `_SESSION_ID_RE`. The existing `_validate_script_name` alias (imported from `script_name.py` in T2) also stays private.

Also add `_REQUIRED_FIELDS_BY_EVENT` + `validate_pending_approval` per the "Absorbed from T1 Opus re-review" block above (same file, placed near `append_registry_entry` so the relationship is visible).

- [ ] **Step 4: Implement `engine.stage_adaptive_script`**

In `src/screw_agents/engine.py`, add method (near other adaptive methods):

```python
def stage_adaptive_script(
    self,
    *,
    project_root: Path,
    script_name: str,
    source: str,
    meta: dict,
    session_id: str,
    target_gap: dict | None = None,
) -> dict:
    """Atomically write an unsigned adaptive script to session-scoped staging.

    The LLM-driven review path: subagent calls this BEFORE composing the
    5-section human review. The staged bytes are the source of truth for
    the subsequent promote_staged_script call — the user reviews what is
    staged, and promote signs what is staged, with sha256 verification
    preventing tamper.

    Spec §3.1. Raises ValueError wrapping filesystem errors per T13-C1.
    Returns domain-error dict on name/session validation failures.
    """
    import yaml
    from screw_agents.adaptive.script_name import validate_script_name
    from screw_agents.adaptive.signing import compute_script_sha256
    from screw_agents.adaptive.staging import (
        _utc_now_iso,
        append_registry_entry,
        resolve_staging_dir,
        write_staged_files,
    )

    # Name validation (delegates to shared `adaptive.script_name` per T2
    # consolidation). Raises ValueError on mismatch — catch and convert
    # to the existing error-dict contract callers depend on.
    try:
        validate_script_name(script_name)
    except ValueError as exc:
        return {
            "status": "error",
            "error": "invalid_script_name",
            "message": str(exc),
        }

    # Session_id validation is enforced by `resolve_staging_dir` (uses
    # the `\\A[A-Za-z0-9_-]{1,64}\\Z` allowlist regex added in T1 part 4
    # for I-opus-1/2). Catch the ValueError it raises and convert to the
    # error-dict contract. Do NOT re-implement a denylist here — that
    # would diverge from the allowlist and re-open I-opus-1.
    try:
        stage_dir = resolve_staging_dir(project_root, session_id)
    except ValueError as exc:
        return {
            "status": "error",
            "error": "invalid_session_id",
            "message": str(exc),
        }

    # Compute sha.
    script_sha256 = compute_script_sha256(source)

    # Collision check: same script_name exists under this session?
    py_path = stage_dir / f"{script_name}.py"
    if py_path.exists():
        existing = py_path.read_text(encoding="utf-8")
        existing_sha = compute_script_sha256(existing)
        if existing_sha != script_sha256:
            return {
                "status": "error",
                "error": "stage_name_collision",
                "message": f"{script_name} already staged in {session_id} "
                           f"with different content",
                "existing_sha256_prefix": existing_sha[:8],
            }
        # Same content — idempotent; proceed to re-write + re-record.

    # Serialize meta to YAML (simple sanitization: ensure it round-trips).
    meta_yaml = yaml.safe_dump(meta, sort_keys=True, default_flow_style=False)

    # Atomic write (staging.py helper; raises ValueError on fs errors).
    write_staged_files(
        project_root=project_root,
        script_name=script_name,
        source=source,
        meta_yaml=meta_yaml,
        session_id=session_id,
    )

    # Append registry entry. Partial-state semantics: if this fails,
    # the staged files remain on disk (T6 sweep recovers them by age).
    # See append_registry_entry's docstring for the rationale.
    entry = {
        "event": "staged",
        "script_name": script_name,
        "session_id": session_id,
        "script_sha256": script_sha256,
        "target_gap": target_gap or {},
        "staged_at": _utc_now_iso(),
        "schema_version": 1,
    }
    append_registry_entry(project_root, entry)

    return {
        "status": "staged",
        "script_name": script_name,
        "stage_path": str(py_path),
        "script_sha256": script_sha256,
        "script_sha256_prefix": script_sha256[:8],
        "session_id": session_id,
        "session_id_short": session_id[:12] if len(session_id) > 12 else session_id,
    }
```

**Pre-audit note (2026-04-21):** The regex + validator were consolidated into `screw_agents.adaptive.script_name` in T2 (commit `7ba25bb`). Earlier drafts of this plan referenced `SCRIPT_NAME_PATTERN` in `signing.py` which does NOT exist — that guidance was incorrect and has been removed. `validate_script_name` is the canonical entry point. Similarly, `compute_script_sha256` already lives in `signing.py` from T18a — do NOT add a `compute_script_sha256_str` duplicate (see Step 3's NOTE).

- [ ] **Step 5: Register MCP tool in `server.py` AND add schema to `engine.list_tool_definitions`**

**5a. Dispatch branch in `src/screw_agents/server.py`**

The actual pattern is `_dispatch_tool` with `if name == "...":` branches (NOT `@mcp.tool()` decorators). See the existing `sign_adaptive_script` handler at `server.py:144-151` for the canonical form. Add to the dispatcher (near the other adaptive handlers, after `sign_adaptive_script`):

```python
# --- Phase 3b T3: stage_adaptive_script (C1 staging-path) ---

if name == "stage_adaptive_script":
    return engine.stage_adaptive_script(
        project_root=Path(args["project_root"]),
        script_name=args["script_name"],
        source=args["source"],
        meta=args["meta"],
        session_id=args["session_id"],
        target_gap=args.get("target_gap"),
    )
```

Use `args.get("target_gap")` (optional kwarg with `None` default on the engine side), NOT `args["target_gap"]` (KeyError on absent).

**5b. Tool schema in `src/screw_agents/engine.list_tool_definitions`**

Tool schemas are defined in `engine.list_tool_definitions()` (starts at `engine.py:1211`). See the existing `sign_adaptive_script` schema at `engine.py:1593` for the canonical format. Append a new `tools.append({...})` block with:

```python
tools.append({
    "name": "stage_adaptive_script",
    "description": (
        "Atomically write an unsigned adaptive analysis script to "
        "session-scoped staging (`.screw/staging/{session_id}/"
        "adaptive-scripts/`). Called by the generating subagent BEFORE "
        "composing the human review. The staged bytes persist on disk "
        "and become the source of truth for the subsequent "
        "promote_staged_script call — the user reviews what is staged, "
        "and promote signs what is staged, with sha256 verification "
        "preventing tamper (C1 trust invariant). Appends a `staged` "
        "event to .screw/local/pending-approvals.jsonl for audit. "
        "Idempotent on byte-identical re-stage; returns status=\"error\" "
        "with error=\"stage_name_collision\" on same name + different "
        "content. See design spec §3.1."
    ),
    "input_schema": {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "project_root": {
                "type": "string",
                "description": "Absolute path to the project root.",
            },
            "script_name": {
                "type": "string",
                "description": (
                    "Filesystem-safe name (regex "
                    "`^[a-z0-9][a-z0-9-]{2,62}$`). Validated by the "
                    "shared `adaptive.script_name.validate_script_name` "
                    "(T2 consolidation) before any filesystem op."
                ),
            },
            "source": {
                "type": "string",
                "description": (
                    "Python source code for the adaptive script. "
                    "Caller should have run `lint_adaptive_script` "
                    "BEFORE staging (pre-review), though staging itself "
                    "does not enforce this."
                ),
            },
            "meta": {
                "type": "object",
                "description": (
                    "Partial meta dict that will eventually conform to "
                    "AdaptiveScriptMeta (minus signing fields). Must "
                    "include name, created, created_by, domain; may "
                    "include description, target_patterns."
                ),
            },
            "session_id": {
                "type": "string",
                "description": (
                    "Scan session id. Validated against "
                    "`^[A-Za-z0-9_-]{1,64}$` (T1 part 4 allowlist, "
                    "I-opus-1/2 fix). Scopes the staging directory — "
                    "different session_ids get different dirs."
                ),
            },
            "target_gap": {
                "type": "object",
                "description": (
                    "Optional coverage-gap metadata recorded in the "
                    "registry entry. Shape: "
                    "{type, file, line, agent}. Null for non-gap stages."
                ),
            },
        },
        "required": [
            "project_root",
            "script_name",
            "source",
            "meta",
            "session_id",
        ],
    },
})
```

**`additionalProperties: false`** is set directly in this schema per T10-M1 partial. T22 performs the project-wide uniform audit but we ship the new tool correctly from the start. Do NOT omit this — the schema gate is trust-path defense in depth (stops schema-extension smuggling).

**Cross-check before commit:** run the dispatcher smoke test template (mirror `test_sign_via_dispatcher_smoke` at `test_sign_adaptive_script.py:481`) in the new stage-flow test block — call `_dispatch_tool(engine, "stage_adaptive_script", {...})` and verify it returns `status="staged"` and the tool appears in `engine.list_tool_definitions()`.

- [ ] **Step 6: Run tests to verify they pass**

Run: `uv run pytest tests/test_adaptive_staging.py -v -k "stage_adaptive_script"`
Expected: 6 PASS.

- [ ] **Step 7: Run full suite**

Run: `uv run pytest -q`
Expected: **~828 passed, 8 skipped** (817 post-T1-part-4 + 6 plan stage tests + 4 I-opus-3 validator tests + 1 engine-layer session_id parametrize test that exercises the full T1-part-4 threat surface through the engine's error-dict conversion path). Final count depends on exactly how many parametrize cases land; floor is 825, ceiling is 832.

- [ ] **Step 8: Commit**

```bash
git add src/screw_agents/adaptive/staging.py \
        src/screw_agents/adaptive/signing.py \
        src/screw_agents/engine.py \
        src/screw_agents/server.py \
        tests/test_adaptive_staging.py
git commit -m "feat(phase3b-c1): stage_adaptive_script MCP tool (T3)"
```

**Cross-plan sync:** confirm spec §3.1 matches the shipped signature + behavior. Deviation flag: did `additionalProperties: false` actually get applied at server registration? If not, move to T22 and document.

**T3 Opus 4.7 re-review (2026-04-21):** Spec review APPROVED (all 24 checks pass). Quality review found 4 Important + 5 Minor items. Important items fixed in T3 part 2 commit (add SHA after you commit the fix-up below):

- **I1 (dead re-export):** removed the unused `compute_script_sha256` re-export at `staging.py:43`. `engine.py:314` imports directly from `adaptive.signing`; staging.py did not need the alias.
- **I2 (helper test coverage gap):** added 5 direct unit tests for the three new registry helpers (corrupted-JSONL tolerance, most-recent-wins, fallback-walk non-directory skip, fallback-walk missing-staging-root, append_registry_entry error wrapping). T4/T6 depend on these helpers; transitive coverage through `stage_adaptive_script` was insufficient.
- **I4 (UnicodeDecodeError leak):** wrapped the collision-check `read_text(encoding="utf-8")` in try/except UnicodeDecodeError → error-dict with `"error": "stage_corrupted"`. Future attacker with fs-write can't crash the tool via corrupted bytes.
- **I5 (fail-fast contract untested):** added test that asserts `append_registry_entry` raises ValueError BEFORE creating the registry file when the entry is malformed. Locks the I-opus-3 validator's fail-fast-before-I/O contract.

Minor items (M1-M5) deferred to `docs/DEFERRED_BACKLOG.md` as `BACKLOG-PR6-14..18`.

---

### Task 4: `promote_staged_script` MCP Tool — The C1 Fix

**Files:**
- Modify: `src/screw_agents/models.py` — add `stale_staging_hours: int = 24` and `staging_max_age_days: int = 14` to `ScrewConfig` with range validators (1-168 and 1-365 respectively)
- Modify: `src/screw_agents/engine.py` (add `promote_staged_script`)
- Modify: `src/screw_agents/server.py` (register MCP tool; `additionalProperties: false`)
- Modify: `tests/test_adaptive_staging.py` (+13 tests — the bulk of C1 regression locks, now including I5 promoted_confirm_stale event assertion)

**Pre-audit (critical — trust-path):**
- Trace sign/verify symmetry: `promote_staged_script` reads staging bytes → calls `_sign_script_bytes`. `_sign_script_bytes` must route meta through `AdaptiveScriptMeta().model_dump()` BEFORE `canonicalize_script`. Verify the meta loaded from staging's `.meta.yaml` goes through THIS path. A bypass would reopen T13-C1 drift.
- `promote_staged_script` MUST NOT accept a `source` parameter. This is the C1 architectural closure. A format-smoke regression lock (`test_promote_staged_script_signature_rejects_source_param`) is mandatory.
- Staleness check uses `datetime.fromisoformat(entry["staged_at"].replace("Z", "+00:00"))` or equivalent. ISO8601 `Z` suffix parsing varies by Python version; use `datetime.strptime(..., "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)` for consistency.
- Tamper case leaves staging files in place + touches `.TAMPERED` marker. The marker + audit entry together = forensic evidence.

- [ ] **Step 0: Add `ScrewConfig` fields (I1 pre-audit fix)**

In `src/screw_agents/models.py`, the `ScrewConfig` Pydantic model currently defines `version`, `exclusion_reviewers`, `script_reviewers`, `adaptive`, `legacy_unsigned_exclusions`, `trusted_reviewers_file`. Add two new fields for the staging lifecycle:

```python
from pydantic import BaseModel, ConfigDict, Field  # Field may already be imported

class ScrewConfig(BaseModel):
    ...existing fields...
    stale_staging_hours: int = Field(default=24, ge=1, le=168)
    staging_max_age_days: int = Field(default=14, ge=1, le=365)
```

Rationale: T4's `_read_stale_staging_hours` and T6's `sweep_stale_staging` both consume these fields. Adding them to the Pydantic model enforces validation at config-load time (invalid values raise on `load_config(project_root)` instead of silently degrading to defaults inside helpers). Keeps the ad-hoc `yaml.safe_load` read in `_read_stale_staging_hours` as a lightweight fallback (config file may be absent on fresh projects), but the canonical path now goes through the schema.

**Tests for the schema update:** `tests/test_models.py` (or wherever `ScrewConfig` is tested today) should add:
- Valid config with custom `stale_staging_hours` value → loads correctly
- `stale_staging_hours: 0` or `169` → raises `ValidationError`
- Missing field → defaults to 24

If `tests/test_models.py` doesn't exist yet, inline these 2-3 tests into `tests/test_adaptive_staging.py` next to the other T4 tests. This counts toward the +13 tests total.

- [ ] **Step 1: Write failing test — C1 REGRESSION LOCK (signature rejects source)**

Add to `tests/test_adaptive_staging.py`:

```python
def test_promote_staged_script_signature_rejects_source_param() -> None:
    """C1 REGRESSION LOCK.

    promote_staged_script MUST NOT accept a `source` parameter. The whole
    point of the C1 fix is that the approve path reads source from disk,
    not from an LLM-provided argument. If a future refactor adds `source`
    back, the regeneration vulnerability reopens. This test catches it.
    """
    from screw_agents.engine import ScanEngine
    import inspect

    sig = inspect.signature(ScanEngine.promote_staged_script)
    assert "source" not in sig.parameters, (
        "promote_staged_script must not accept `source` parameter — C1 "
        "architectural closure regressed. See spec §3.2."
    )
    # Also reject `meta` — meta is read from staging, same rationale.
    assert "meta" not in sig.parameters, (
        "promote_staged_script must not accept `meta` parameter either"
    )
```

- [ ] **Step 2: Write failing tests for happy-path promote**

```python
def test_promote_staged_script_happy_path(tmp_path: Path) -> None:
    """Stage then promote: signed artifact lands in custom-scripts/ with
    byte-identical source."""
    from screw_agents.cli.init_trust import run_init_trust
    from screw_agents.engine import ScanEngine
    from screw_agents.adaptive.staging import resolve_registry_path

    project = tmp_path / "project"
    project.mkdir()
    run_init_trust(project_root=project, name="T4 Tester", email="t4@example.com")
    engine = ScanEngine.from_defaults()
    source = "from screw_agents.adaptive import emit_finding\n\ndef analyze(project):\n    pass\n"
    meta = {
        "name": "test-promote-001",
        "created": "2026-04-20T10:00:00Z",
        "created_by": "t4@example.com",
        "domain": "injection-input-handling",
        "description": "test",
        "target_patterns": ["foo.bar"],
    }

    stage_r = engine.stage_adaptive_script(
        project_root=project,
        script_name="test-promote-001",
        source=source,
        meta=meta,
        session_id="sess-abc",
        target_gap=None,
    )
    assert stage_r["status"] == "staged"

    promote_r = engine.promote_staged_script(
        project_root=project,
        script_name="test-promote-001",
        session_id="sess-abc",
    )

    assert promote_r["status"] == "signed"
    assert promote_r["signed_by"] == "t4@example.com"
    assert promote_r["sha256"] == stage_r["script_sha256"]
    assert promote_r["promoted_via_fallback"] is False

    # Custom-scripts file contains EXACTLY the staged source.
    signed_py = project / ".screw" / "custom-scripts" / "test-promote-001.py"
    assert signed_py.exists()
    assert signed_py.read_text(encoding="utf-8") == source

    # Staging files deleted.
    stage_py = project / ".screw" / "staging" / "sess-abc" / "adaptive-scripts" / "test-promote-001.py"
    assert not stage_py.exists()

    # Registry has both staged + promoted entries.
    entries = [json.loads(line) for line in resolve_registry_path(project).read_text().splitlines() if line.strip()]
    events = [e["event"] for e in entries]
    assert "staged" in events
    assert "promoted" in events


def test_promote_staging_not_found(tmp_path: Path) -> None:
    from screw_agents.engine import ScanEngine

    project = tmp_path / "project"
    project.mkdir()
    engine = ScanEngine.from_defaults()

    response = engine.promote_staged_script(
        project_root=project,
        script_name="nope",
        session_id="sess-abc",
    )

    assert response["status"] == "error"
    assert response["error"] == "staging_not_found"


def test_promote_detects_tamper(tmp_path: Path) -> None:
    """Between stage and promote, overwrite staging .py with different bytes.
    Promote must reject with tamper_detected + evidence_path + TAMPERED marker."""
    from screw_agents.cli.init_trust import run_init_trust
    from screw_agents.engine import ScanEngine
    from screw_agents.adaptive.staging import resolve_staging_dir

    project = tmp_path / "project"
    project.mkdir()
    run_init_trust(project_root=project, name="T", email="t@e.co")
    engine = ScanEngine.from_defaults()
    source = "from screw_agents.adaptive import emit_finding\ndef analyze(p):\n    pass\n"
    meta = {
        "name": "test-tamper-001",
        "created": "2026-04-20T10:00:00Z",
        "created_by": "t@e.co",
        "domain": "injection-input-handling",
        "description": "test",
        "target_patterns": ["foo"],
    }

    engine.stage_adaptive_script(
        project_root=project,
        script_name="test-tamper-001",
        source=source,
        meta=meta,
        session_id="sess-abc",
        target_gap=None,
    )

    # TAMPER: overwrite staging .py with different bytes.
    stage_py = resolve_staging_dir(project, "sess-abc") / "test-tamper-001.py"
    stage_py.write_text("# malicious\nimport os\nos.system('rm -rf /')\n", encoding="utf-8")

    response = engine.promote_staged_script(
        project_root=project,
        script_name="test-tamper-001",
        session_id="sess-abc",
    )

    assert response["status"] == "error"
    assert response["error"] == "tamper_detected"
    assert response["expected_sha256_prefix"]
    assert response["actual_sha256_prefix"]
    assert response["expected_sha256_prefix"] != response["actual_sha256_prefix"]
    assert "evidence_path" in response

    # TAMPERED marker file exists.
    marker = resolve_staging_dir(project, "sess-abc") / "test-tamper-001.TAMPERED"
    assert marker.exists()

    # Staging files NOT deleted (forensic evidence).
    assert stage_py.exists()

    # No custom-scripts artifact written.
    signed_py = project / ".screw" / "custom-scripts" / "test-tamper-001.py"
    assert not signed_py.exists()


def test_promote_stale_staging_requires_confirm_stale(tmp_path, monkeypatch) -> None:
    """Stage with staged_at 48h in the past; promote without confirm_stale
    returns stale_staging error."""
    from screw_agents.cli.init_trust import run_init_trust
    from screw_agents.engine import ScanEngine
    from screw_agents.adaptive.staging import (
        append_registry_entry,
        resolve_registry_path,
    )

    project = tmp_path / "project"
    project.mkdir()
    run_init_trust(project_root=project, name="T", email="t@e.co")
    engine = ScanEngine.from_defaults()
    source = "pass\n"
    meta = {
        "name": "test-stale-001",
        "created": "2026-04-18T10:00:00Z",  # 2 days ago
        "created_by": "t@e.co",
        "domain": "injection-input-handling",
        "description": "test",
        "target_patterns": ["foo"],
    }

    # Stage normally.
    engine.stage_adaptive_script(
        project_root=project,
        script_name="test-stale-001",
        source=source,
        meta=meta,
        session_id="sess-old",
        target_gap=None,
    )

    # Rewrite registry with a 48h-old staged_at.
    from datetime import datetime, timedelta, timezone
    old_time = (datetime.now(timezone.utc) - timedelta(hours=48)).strftime("%Y-%m-%dT%H:%M:%SZ")
    registry = resolve_registry_path(project)
    lines = registry.read_text().splitlines()
    import json as _json
    rewritten = []
    for line in lines:
        entry = _json.loads(line)
        if entry.get("script_name") == "test-stale-001":
            entry["staged_at"] = old_time
        rewritten.append(_json.dumps(entry, separators=(",", ":"), sort_keys=True))
    registry.write_text("\n".join(rewritten) + "\n")

    # Promote without confirm_stale → stale error.
    response = engine.promote_staged_script(
        project_root=project,
        script_name="test-stale-001",
        session_id="sess-old",
    )

    assert response["status"] == "error"
    assert response["error"] == "stale_staging"
    assert response["hours_old"] >= 48
    assert response["threshold_hours"] == 24

    # Retry with confirm_stale → success.
    response2 = engine.promote_staged_script(
        project_root=project,
        script_name="test-stale-001",
        session_id="sess-old",
        confirm_stale=True,
    )
    assert response2["status"] == "signed"

    # I5 regression: confirm-stale retry must emit `promoted_confirm_stale`
    # audit event (not plain `promoted`). Locks the audit-event taxonomy
    # so downstream forensics can distinguish routine promotes from
    # staleness-override promotes.
    import json as _json
    entries = [
        _json.loads(line) for line in
        resolve_registry_path(project).read_text().splitlines() if line.strip()
    ]
    promoted_events = [e for e in entries if e.get("event", "").startswith("promoted")]
    assert len(promoted_events) == 1
    assert promoted_events[0]["event"] == "promoted_confirm_stale", (
        f"Expected `promoted_confirm_stale` audit event; got {promoted_events[0]['event']!r}"
    )


def test_promote_rejects_malformed_staged_at(tmp_path) -> None:
    """I3 hardening: staleness check must NOT silently bypass on a
    malformed timestamp. Force ops to investigate corrupted registry."""
    from screw_agents.cli.init_trust import run_init_trust
    from screw_agents.engine import ScanEngine
    from screw_agents.adaptive.staging import resolve_registry_path

    project = tmp_path / "project"
    project.mkdir()
    run_init_trust(project_root=project, name="T", email="t@e.co")
    engine = ScanEngine.from_defaults()
    engine.stage_adaptive_script(
        project_root=project,
        script_name="test-bad-ts",
        source="pass\n",
        meta={"name": "test-bad-ts", "created": "2026-04-21T10:00:00Z",
              "created_by": "t@e.co", "domain": "injection-input-handling",
              "description": "d", "target_patterns": ["x"]},
        session_id="sess-abc",
        target_gap=None,
    )

    # Corrupt the staged_at timestamp in the registry.
    registry = resolve_registry_path(project)
    import json as _json
    lines = registry.read_text().splitlines()
    rewritten = []
    for line in lines:
        entry = _json.loads(line)
        if entry.get("script_name") == "test-bad-ts":
            entry["staged_at"] = "not-a-timestamp"
        rewritten.append(_json.dumps(entry, separators=(",", ":"), sort_keys=True))
    registry.write_text("\n".join(rewritten) + "\n")

    response = engine.promote_staged_script(
        project_root=project,
        script_name="test-bad-ts",
        session_id="sess-abc",
    )

    assert response["status"] == "error"
    assert response["error"] == "invalid_registry_entry"
    assert "malformed" in response["message"].lower() or "parse error" in response["message"].lower()
```

Add 6 more tests covering:
- `test_promote_fallback_registry_missing` (registry file absent → fallback_required)
- `test_promote_fallback_sha_prefix_accepted` (confirm_sha_prefix matches recovered sha → promote proceeds with event `promoted_via_fallback`)
- `test_promote_fallback_sha_prefix_mismatch` (wrong prefix → fallback_sha_mismatch error)
- `test_promote_custom_scripts_collision` (signed file already exists → custom_scripts_collision)
- `test_promote_invalid_lifecycle_state` (most-recent registry event is `rejected` and staging resurrected somehow → invalid_lifecycle_state defensive error; mock scenario)
- `test_promote_audit_on_tamper` (tamper event appended to registry)

(Follow the pattern of the tests above; each is 20-30 LOC with a clear Arrange/Act/Assert structure.)

- [ ] **Step 3: Run tests — verify they fail**

Run: `uv run pytest tests/test_adaptive_staging.py -v -k "promote"`
Expected: All FAIL with `AttributeError: 'ScanEngine' object has no attribute 'promote_staged_script'`.

- [ ] **Step 4: Implement `engine.promote_staged_script`**

In `src/screw_agents/engine.py`:

```python
def promote_staged_script(
    self,
    *,
    project_root: Path,
    script_name: str,
    session_id: str,
    confirm_sha_prefix: str | None = None,
    confirm_stale: bool = False,
) -> dict:
    """Sign + promote a staged script to .screw/custom-scripts/.

    THE C1 FIX. Does NOT accept a ``source`` or ``meta`` parameter — both
    are read from the staging directory on disk. This is the architectural
    closure of the regeneration vulnerability.

    Flow (spec §3.2):
      1. Resolve staging paths; missing → staging_not_found
      2. Read .py + .meta.yaml bytes from staging
      3. Compute actual_sha256
      4. Registry lookup; most-recent (script_name, session_id) entry
      4b. Staleness check (24h default; confirm_stale bypasses)
      5. Primary path: sha match → proceed; mismatch → tamper_detected
      6. Fallback path: registry missing → require confirm_sha_prefix
      7. Delegate to _sign_script_bytes (Option D)
      8. Delete staging files
      9. Append promoted/promoted_via_fallback/promoted_confirm_stale event

    Spec §3.2. Raises ValueError wrapping filesystem errors per T13-C1.
    """
    import yaml
    from datetime import datetime, timedelta, timezone
    from screw_agents.adaptive.signing import _sign_script_bytes, compute_script_sha256
    from screw_agents.adaptive.staging import (
        _utc_now_iso,
        append_registry_entry,
        delete_staged_files,
        fallback_walk_for_script,
        query_registry_most_recent,
        read_staged_files,
        resolve_staging_dir,
    )
    from screw_agents.trust import load_config

    # Step 1: resolve + verify staging exists.
    stage_dir = resolve_staging_dir(project_root, session_id)
    py_path = stage_dir / f"{script_name}.py"
    meta_path = stage_dir / f"{script_name}.meta.yaml"
    if not (py_path.exists() and meta_path.exists()):
        return {
            "status": "error",
            "error": "staging_not_found",
            "message": f"No staged script named {script_name!r} in session {session_id!r}",
        }

    # Step 2 + 3: read + compute sha.
    try:
        source, meta_yaml = read_staged_files(
            project_root=project_root,
            script_name=script_name,
            session_id=session_id,
        )
    except FileNotFoundError:
        # Race between exists-check and read; rare but possible.
        return {
            "status": "error",
            "error": "staging_not_found",
            "message": f"Staged files vanished between check and read for {script_name!r}",
        }
    actual_sha256 = compute_script_sha256(source)

    # Step 4: registry lookup.
    registry_entry = query_registry_most_recent(
        project_root, script_name=script_name, session_id=session_id
    )

    # Staleness check when we have a staged_at timestamp.
    stale_threshold_hours = _read_stale_staging_hours(project_root)  # helper below
    if registry_entry and registry_entry.get("event") == "staged":
        staged_at_str = registry_entry.get("staged_at")
        if staged_at_str is None:
            # I3 hardening: registry entry missing staged_at is a schema
            # violation (validate_pending_approval should have caught this
            # on write; if we see it at read time, the registry has been
            # tampered or a legacy entry predates the validator). Force
            # ops to investigate rather than silently bypass staleness.
            return {
                "status": "error",
                "error": "invalid_registry_entry",
                "message": (
                    f"Registry entry for {script_name!r}/{session_id!r} is missing "
                    f"the 'staged_at' field required for staleness check. "
                    f"Registry may be corrupted or written by an older schema version. "
                    f"Inspect `.screw/local/pending-approvals.jsonl` and run "
                    f"`sweep_stale_staging` to recover orphans."
                ),
            }
        try:
            staged_at = datetime.strptime(
                staged_at_str, "%Y-%m-%dT%H:%M:%SZ"
            ).replace(tzinfo=timezone.utc)
        except ValueError as exc:
            return {
                "status": "error",
                "error": "invalid_registry_entry",
                "message": (
                    f"Registry entry for {script_name!r}/{session_id!r} has malformed "
                    f"staged_at ({staged_at_str!r}; expected ISO8601 with Z suffix). "
                    f"Parse error: {exc}. Inspect `.screw/local/pending-approvals.jsonl`."
                ),
            }
        age = datetime.now(timezone.utc) - staged_at
        if age > timedelta(hours=stale_threshold_hours) and not confirm_stale:
            return {
                "status": "error",
                "error": "stale_staging",
                "message": (
                    f"Staged {script_name!r} is {age.total_seconds()/3600:.1f}h old "
                    f"(staged_at: {staged_at_str}); "
                    f"threshold is {stale_threshold_hours}h. "
                    f"Re-type `approve {script_name} confirm-stale` to proceed anyway."
                ),
                "hours_old": round(age.total_seconds() / 3600, 1),
                "threshold_hours": stale_threshold_hours,
            }

    # Step 4b-5: lifecycle + primary/tamper.
    audit_event = "promoted"
    if registry_entry:
        last_event = registry_entry.get("event")
        if last_event != "staged":
            return {
                "status": "error",
                "error": "invalid_lifecycle_state",
                "message": (
                    f"Most-recent registry event for {script_name!r} in {session_id!r} "
                    f"is {last_event!r}; expected 'staged'. Staging should not exist."
                ),
                "last_event": last_event,
            }
        registry_sha = registry_entry.get("script_sha256")
        if actual_sha256 != registry_sha:
            # TAMPER DETECTED.
            marker = stage_dir / f"{script_name}.TAMPERED"
            try:
                marker.touch()
            except OSError:
                pass  # best-effort marker
            tamper_entry = {
                "event": "tamper_detected",
                "script_name": script_name,
                "session_id": session_id,
                "expected_sha256": registry_sha,
                "actual_sha256": actual_sha256,
                "evidence_path": str(py_path),
                "tampered_at": _utc_now_iso(),
                "schema_version": 1,
            }
            append_registry_entry(project_root, tamper_entry)
            return {
                "status": "error",
                "error": "tamper_detected",
                "message": (
                    f"Staged content sha256 does not match staging registry. "
                    f"Expected {registry_sha[:8]}; got {actual_sha256[:8]}. "
                    f"Approval REJECTED for safety. Tampered bytes preserved at "
                    f"{py_path} for forensic inspection. Re-run scan."
                ),
                "expected_sha256_prefix": registry_sha[:8],
                "actual_sha256_prefix": actual_sha256[:8],
                "evidence_path": str(py_path),
            }
    else:
        # Step 6: fallback path (registry missing / no matching entry).
        if confirm_sha_prefix is None:
            # Walk to validate the file really exists + report prefix.
            matches = fallback_walk_for_script(project_root, script_name=script_name)
            if not matches:
                return {
                    "status": "error",
                    "error": "staging_not_found",
                    "message": f"No staged script named {script_name!r} anywhere",
                }
            # We already know py_path exists (verified in Step 1); use its sha.
            return {
                "status": "error",
                "error": "fallback_required",
                "message": (
                    f"Registry lookup failed. Staging file found with sha256 "
                    f"prefix {actual_sha256[:8]}. Re-type "
                    f"`approve {script_name} confirm-{actual_sha256[:8]}` to proceed."
                ),
                "recovered_sha256_prefix": actual_sha256[:8],
            }
        if confirm_sha_prefix != actual_sha256[:8]:
            return {
                "status": "error",
                "error": "fallback_sha_mismatch",
                "message": (
                    f"Confirm phrase sha prefix does not match the recovered "
                    f"staging file. Re-run scan."
                ),
                "expected_in_phrase": actual_sha256[:8],
                "got_in_phrase": confirm_sha_prefix,
            }
        audit_event = "promoted_via_fallback"

    # Confirm-stale variant of audit event.
    if confirm_stale and audit_event == "promoted":
        audit_event = "promoted_confirm_stale"

    # Step 7: delegate to shared signing helper.
    try:
        meta_dict = yaml.safe_load(meta_yaml)
    except yaml.YAMLError as exc:
        return {
            "status": "error",
            "error": "invalid_staged_meta",
            "message": f"staged meta YAML is malformed: {exc}",
        }

    sign_result = _sign_script_bytes(
        project_root=project_root,
        script_name=script_name,
        source=source,
        meta_dict=meta_dict,
        session_id=session_id,
    )
    if sign_result.get("status") != "signed":
        # I2 taxonomy-normalization: _sign_script_bytes returns
        # {"status": "error", "message": "..."} without an "error" key
        # (no_matching_reviewer, custom_scripts_collision, meta_schema, etc.).
        # Inject a stable error-key so callers pattern-matching on
        # response["error"] don't KeyError. Preserve the original message in
        # "detail" for operators.
        return {
            "status": "error",
            "error": "sign_failed",
            "message": sign_result.get("message", "Signing failed with no message"),
            "detail": sign_result,
        }

    # Step 8: delete staging.
    try:
        delete_staged_files(
            project_root=project_root,
            script_name=script_name,
            session_id=session_id,
        )
    except ValueError as exc:
        # Signed but staging cleanup failed — promote is still successful;
        # staging will be collected by sweep_stale_staging.
        pass  # intentional: promote succeeded

    # Step 9: audit.
    promoted_entry = {
        "event": audit_event,
        "script_name": script_name,
        "session_id": session_id,
        "signed_by": sign_result["signed_by"],
        "sha256": sign_result["sha256"],
        "promoted_at": _utc_now_iso(),
        "schema_version": 1,
    }
    append_registry_entry(project_root, promoted_entry)

    return {
        "status": "signed",
        "script_name": script_name,
        "script_path": sign_result["script_path"],
        "meta_path": sign_result["meta_path"],
        "signed_by": sign_result["signed_by"],
        "sha256": sign_result["sha256"],
        "session_id": session_id,
        "promoted_via_fallback": audit_event == "promoted_via_fallback",
    }


def _read_stale_staging_hours(project_root: Path) -> int:
    """Return stale_staging_hours from .screw/config.yaml (default 24, clamped 1-168)."""
    try:
        import yaml
        config_path = project_root / ".screw" / "config.yaml"
        if not config_path.exists():
            return 24
        with open(config_path, encoding="utf-8") as f:
            cfg = yaml.safe_load(f) or {}
        val = int(cfg.get("stale_staging_hours", 24))
        return max(1, min(168, val))
    except Exception:
        return 24
```

- [ ] **Step 5: Register MCP tool in `server.py` AND add schema to `engine.list_tool_definitions`**

**5a. Dispatch branch in `src/screw_agents/server.py`** (add after the T3 `stage_adaptive_script` branch, following the same `_dispatch_tool` `if name == "...":` pattern used by `sign_adaptive_script` at `server.py:144-151`):

```python
# --- Phase 3b T4: promote_staged_script (C1 fix — approve path) ---

if name == "promote_staged_script":
    return engine.promote_staged_script(
        project_root=Path(args["project_root"]),
        script_name=args["script_name"],
        session_id=args["session_id"],
        confirm_sha_prefix=args.get("confirm_sha_prefix"),
        confirm_stale=args.get("confirm_stale", False),
    )
```

Required args (`project_root`, `script_name`, `session_id`) use `args["..."]`. Optional args (`confirm_sha_prefix`, `confirm_stale`) use `args.get(...)` with the same defaults as the engine method — avoids KeyError on absence. **There is no `source` or `meta` arg — the C1 architectural closure.**

**5b. Tool schema in `src/screw_agents/engine.list_tool_definitions`** — append a new `tools.append({...})` block:

```python
tools.append({
    "name": "promote_staged_script",
    "description": (
        "Sign and promote a staged adaptive script — THE C1 FIX. Reads "
        "source and meta from the session-scoped staging directory on "
        "disk (no source/meta parameter, by construction), verifies the "
        "staging bytes match the registry-recorded sha256 (tamper-detect), "
        "then delegates to the shared _sign_script_bytes helper and "
        "appends a promoted/promoted_via_fallback/promoted_confirm_stale "
        "audit event. Promoted artifacts land in `.screw/custom-scripts/`. "
        "Returns status=\"error\" with error=\"tamper_detected\" on sha "
        "mismatch (preserves bytes for forensics), error=\"stale_staging\" "
        "when staged_at age exceeds the configured threshold unless "
        "confirm_stale=true, and error=\"fallback_required\" when the "
        "registry entry is missing (caller re-invokes with "
        "confirm_sha_prefix). See design spec §3.2."
    ),
    "input_schema": {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "project_root": {
                "type": "string",
                "description": "Absolute path to the project root.",
            },
            "script_name": {
                "type": "string",
                "description": (
                    "Filesystem-safe name (regex "
                    "`^[a-z0-9][a-z0-9-]{2,62}$`) of the staged script "
                    "to promote."
                ),
            },
            "session_id": {
                "type": "string",
                "description": (
                    "Scan session id the script was staged under "
                    "(allowlist `^[A-Za-z0-9_-]{1,64}$`)."
                ),
            },
            "confirm_sha_prefix": {
                "type": ["string", "null"],
                "description": (
                    "Short sha256 prefix (first 8 hex chars) re-supplied "
                    "by the caller when the registry lookup failed and "
                    "a filesystem fallback walk is used (Q3 fallback "
                    "path). Null for the normal registry-hit path."
                ),
            },
            "confirm_stale": {
                "type": "boolean",
                "description": (
                    "When true, allows promotion even if the staging "
                    "entry is older than `stale_staging_hours` (default "
                    "24). Caller must re-type an explicit "
                    "`approve {name} confirm-stale` phrase."
                ),
            },
        },
        "required": [
            "project_root",
            "script_name",
            "session_id",
        ],
    },
})
```

**`additionalProperties: false`** is set directly per T10-M1 partial — do NOT omit. The schema gate is trust-path defense in depth (stops schema-extension smuggling that would re-introduce a `source` parameter).

- [ ] **Step 6: Run tests — verify they pass**

Run: `uv run pytest tests/test_adaptive_staging.py -v -k "promote"`
Expected: all 12 promote tests PASS.

- [ ] **Step 7: Run full suite**

Run: `uv run pytest -q`
Expected: **~859 passed, 8 skipped** (846 post-T3 + ~13 new promote tests + ScrewConfig schema tests). Floor is 856, ceiling is ~862 depending on how parametrize + schema-validator tests count.

- [ ] **Step 8: Commit**

```bash
git add src/screw_agents/engine.py \
        src/screw_agents/server.py \
        tests/test_adaptive_staging.py
git commit -m "feat(phase3b-c1): promote_staged_script MCP tool — C1 fix (T4)"
```

**Cross-plan sync:** confirm all 12 Q-decisions from spec §3.2 are exercised by at least one test. If a Q decision ISN'T exercised (e.g., no test for invalid_lifecycle_state), add one now. C1 regression coverage is non-negotiable.

**T4 Opus 4.7 re-review (2026-04-21):** Spec review APPROVED (all 10 HR + 15 tests pass). Quality review found 2 Important + 8 Minor items. Both Important items fixed in T4 part 2 commit:

- **I-opus-1 (missing `script_sha256` in registry):** symmetric to I3's `staged_at` discipline. The tamper-detection code path used `registry_sha[:8]` in error messages; a missing `script_sha256` would crash with `TypeError: 'NoneType' object is not subscriptable`. Fixed with an explicit `invalid_registry_entry` return + regression test `test_promote_rejects_missing_script_sha256`.
- **I-opus-2 (cross-plan C1-closure status):** added a C1 STATUS NOTE docstring paragraph to `sign_adaptive_script` documenting that T4 closes C1 for the staged-path approve flow but the direct-sign path remains open. Operators/auditors should not assume C1 is fully closed at the MCP boundary. Retirement migration tracked as BACKLOG-PR6-22.

Minor items (I-opus-3 through I-opus-10) deferred to `docs/DEFERRED_BACKLOG.md` as `BACKLOG-PR6-21..28`.

---

### Task 5: `reject_staged_script` MCP Tool

**Files:**
- Modify: `src/screw_agents/engine.py` (add `reject_staged_script`)
- Modify: `src/screw_agents/server.py` (register MCP tool)
- Modify: `tests/test_adaptive_staging.py` (+6 tests)

- [ ] **Step 1: Write failing tests**

```python
def test_reject_staged_script_deletes_files_and_audits(tmp_path: Path) -> None:
    from screw_agents.engine import ScanEngine
    from screw_agents.adaptive.staging import resolve_registry_path, resolve_staging_dir

    project = tmp_path / "project"
    project.mkdir()
    engine = ScanEngine.from_defaults()

    engine.stage_adaptive_script(
        project_root=project, script_name="test-rej-001", source="pass\n",
        meta={"name": "test-rej-001", "created": "2026-04-20T10:00:00Z",
              "created_by": "t@e.co", "domain": "injection-input-handling",
              "description": "d", "target_patterns": ["x"]},
        session_id="sess-abc", target_gap=None,
    )

    response = engine.reject_staged_script(
        project_root=project,
        script_name="test-rej-001",
        session_id="sess-abc",
        reason="imports look suspicious",
    )

    assert response["status"] == "rejected"
    assert response["reason"] == "imports look suspicious"

    stage_py = resolve_staging_dir(project, "sess-abc") / "test-rej-001.py"
    assert not stage_py.exists()

    entries = [json.loads(l) for l in resolve_registry_path(project).read_text().splitlines() if l.strip()]
    events = [e["event"] for e in entries]
    assert "rejected" in events
    rej = [e for e in entries if e["event"] == "rejected"][0]
    assert rej["reason"] == "imports look suspicious"


def test_reject_staged_script_idempotent_on_second_reject(tmp_path: Path) -> None:
    from screw_agents.engine import ScanEngine

    project = tmp_path / "project"
    project.mkdir()
    engine = ScanEngine.from_defaults()

    engine.stage_adaptive_script(
        project_root=project, script_name="test-rej-002", source="pass\n",
        meta={"name": "test-rej-002", "created": "2026-04-20T10:00:00Z",
              "created_by": "t@e.co", "domain": "injection-input-handling",
              "description": "d", "target_patterns": ["x"]},
        session_id="sess-abc", target_gap=None,
    )
    r1 = engine.reject_staged_script(
        project_root=project, script_name="test-rej-002", session_id="sess-abc", reason=None,
    )
    r2 = engine.reject_staged_script(
        project_root=project, script_name="test-rej-002", session_id="sess-abc", reason=None,
    )

    assert r1["status"] == "rejected"
    assert r2["status"] == "already_rejected"  # idempotent


def test_reject_staged_script_rejects_invalid_session_id(tmp_path: Path) -> None:
    """I1 regression: invalid session_id (rejected by T1-part-4 allowlist)
    must become an error-dict, not an uncaught ValueError."""
    from screw_agents.engine import ScanEngine

    project = tmp_path / "project"
    project.mkdir()
    engine = ScanEngine.from_defaults()

    response = engine.reject_staged_script(
        project_root=project,
        script_name="test-001",
        session_id="foo\nbar",  # newline rejected by allowlist
        reason=None,
    )

    assert response["status"] == "error"
    assert response["error"] == "invalid_session_id"


def test_reject_staged_script_rejects_invalid_script_name(tmp_path: Path) -> None:
    """I1 regression: invalid script_name must become error-dict."""
    from screw_agents.engine import ScanEngine

    project = tmp_path / "project"
    project.mkdir()
    engine = ScanEngine.from_defaults()

    response = engine.reject_staged_script(
        project_root=project,
        script_name="UPPERCASE",  # allowlist rejects uppercase
        session_id="sess-abc",
        reason=None,
    )

    assert response["status"] == "error"
    assert response["error"] == "invalid_script_name"


def test_reject_staged_script_updates_adaptive_prompts_json(tmp_path: Path) -> None:
    """T18b's decline tracking lives in .screw/local/adaptive_prompts.json —
    reject MUST update it so the same target isn't re-proposed on the next scan."""
    import json as _json
    from screw_agents.engine import ScanEngine

    project = tmp_path / "project"
    project.mkdir()
    engine = ScanEngine.from_defaults()

    engine.stage_adaptive_script(
        project_root=project, script_name="test-rej-003", source="pass\n",
        meta={"name": "test-rej-003", "created": "2026-04-20T10:00:00Z",
              "created_by": "t@e.co", "domain": "injection-input-handling",
              "description": "d", "target_patterns": ["x"]},
        session_id="sess-abc", target_gap=None,
    )

    response = engine.reject_staged_script(
        project_root=project,
        script_name="test-rej-003",
        session_id="sess-abc",
        reason="too speculative",
    )

    assert response["status"] == "rejected"

    # The decline-tracking artifact must include the rejected script_name.
    prompts_path = project / ".screw" / "local" / "adaptive_prompts.json"
    assert prompts_path.exists(), (
        "reject_staged_script must create adaptive_prompts.json if absent"
    )
    state = _json.loads(prompts_path.read_text(encoding="utf-8"))
    assert "declined" in state
    assert "test-rej-003" in state["declined"]

    # Second reject on same target MUST NOT produce duplicate declined entries.
    engine.stage_adaptive_script(
        project_root=project, script_name="test-rej-003", source="pass\n",
        meta={"name": "test-rej-003", "created": "2026-04-20T10:00:00Z",
              "created_by": "t@e.co", "domain": "injection-input-handling",
              "description": "d", "target_patterns": ["x"]},
        session_id="sess-xyz", target_gap=None,  # different session
    )
    engine.reject_staged_script(
        project_root=project,
        script_name="test-rej-003",
        session_id="sess-xyz",
        reason=None,
    )
    state2 = _json.loads(prompts_path.read_text(encoding="utf-8"))
    assert state2["declined"].count("test-rej-003") == 1, (
        "declined list must deduplicate by script_name"
    )


def test_reject_staged_script_no_staging_returns_already_rejected(tmp_path: Path) -> None:
    from screw_agents.engine import ScanEngine

    project = tmp_path / "project"
    project.mkdir()
    engine = ScanEngine.from_defaults()

    response = engine.reject_staged_script(
        project_root=project, script_name="never-staged", session_id="sess-abc", reason=None,
    )

    assert response["status"] == "already_rejected"
```

- [ ] **Step 2: Run tests — verify they fail**

Expected: 4 FAIL with `AttributeError`.

- [ ] **Step 3: Implement `engine.reject_staged_script`**

```python
def reject_staged_script(
    self,
    *,
    project_root: Path,
    script_name: str,
    session_id: str,
    reason: str | None = None,
) -> dict:
    """Delete staging files and record a rejection audit event.

    Idempotent: a second reject on already-deleted staging returns
    status=already_rejected (success). Also updates the existing T18b
    decline tracking file .screw/local/adaptive_prompts.json to mark
    this target as declined.

    Spec §3.3.
    """
    import json
    from screw_agents.adaptive.staging import (
        _utc_now_iso,
        append_registry_entry,
        delete_staged_files,
        resolve_staging_dir,
    )

    # Symmetric script_name validation (T3/T4 pattern).
    from screw_agents.adaptive.script_name import validate_script_name
    try:
        validate_script_name(script_name)
    except ValueError as exc:
        return {
            "status": "error",
            "error": "invalid_script_name",
            "message": str(exc),
        }

    # I1 defense-in-depth: resolve_staging_dir raises ValueError on invalid
    # session_id (T1-part-4 allowlist). Catch + convert to error-dict for
    # consistency with T3/T4's engine-layer contract — no ValueError leak.
    try:
        stage_dir = resolve_staging_dir(project_root, session_id)
    except ValueError as exc:
        return {
            "status": "error",
            "error": "invalid_session_id",
            "message": str(exc),
        }
    py_path = stage_dir / f"{script_name}.py"
    if not py_path.exists():
        return {
            "status": "already_rejected",
            "script_name": script_name,
            "session_id": session_id,
            "reason": reason or "",
        }

    delete_staged_files(
        project_root=project_root, script_name=script_name, session_id=session_id,
    )

    reject_entry = {
        "event": "rejected",
        "script_name": script_name,
        "session_id": session_id,
        "reason": reason or "",
        "rejected_at": _utc_now_iso(),
        "schema_version": 1,
    }
    append_registry_entry(project_root, reject_entry)

    # Update adaptive_prompts.json — existing T18b decline-tracking artifact.
    prompts_path = project_root / ".screw" / "local" / "adaptive_prompts.json"
    try:
        if prompts_path.exists():
            state = json.loads(prompts_path.read_text(encoding="utf-8"))
        else:
            state = {"declined": []}
        declined = state.setdefault("declined", [])
        if script_name not in declined:
            declined.append(script_name)
        prompts_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = prompts_path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(state, indent=2), encoding="utf-8")
        import os as _os
        _os.replace(tmp, prompts_path)
    except (PermissionError, OSError):
        pass  # best-effort; not critical to the reject flow's correctness

    return {
        "status": "rejected",
        "script_name": script_name,
        "session_id": session_id,
        "reason": reason or "",
    }
```

- [ ] **Step 4: Register MCP tool in `server.py` AND add schema to `engine.list_tool_definitions`**

**4a. Dispatch branch in `src/screw_agents/server.py`** (add after the T4 `promote_staged_script` branch, following the `_dispatch_tool` pattern):

```python
# --- Phase 3b T5: reject_staged_script (decline path) ---

if name == "reject_staged_script":
    return engine.reject_staged_script(
        project_root=Path(args["project_root"]),
        script_name=args["script_name"],
        session_id=args["session_id"],
        reason=args.get("reason"),
    )
```

`reason` is optional via `args.get("reason")` — None when the caller supplies no rationale.

**4b. Tool schema in `src/screw_agents/engine.list_tool_definitions`** — append a new `tools.append({...})` block:

```python
tools.append({
    "name": "reject_staged_script",
    "description": (
        "Delete the staging files for a rejected adaptive script and "
        "record a `rejected` audit event in the pending-approvals "
        "registry. Idempotent: a second reject on already-deleted "
        "staging returns status=\"already_rejected\" (success). Also "
        "updates `.screw/local/adaptive_prompts.json` — the existing "
        "T18b decline-tracking artifact — to add the target to the "
        "`declined` list so it is not re-proposed. See design spec §3.3."
    ),
    "input_schema": {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "project_root": {
                "type": "string",
                "description": "Absolute path to the project root.",
            },
            "script_name": {
                "type": "string",
                "description": (
                    "Filesystem-safe name of the staged script to reject."
                ),
            },
            "session_id": {
                "type": "string",
                "description": (
                    "Scan session id the script was staged under."
                ),
            },
            "reason": {
                "type": ["string", "null"],
                "description": (
                    "Optional short rationale recorded in the audit "
                    "event (why the reviewer declined this script)."
                ),
            },
        },
        "required": [
            "project_root",
            "script_name",
            "session_id",
        ],
    },
})
```

`additionalProperties: false` is set directly per T10-M1 partial.

- [ ] **Step 5: Run tests + full suite**

Run: `uv run pytest tests/test_adaptive_staging.py -v -k "reject"`
Expected: 4 PASS.

Run: `uv run pytest -q`
Expected: **868 passed, 8 skipped** (862 post-T4 + 6 new reject tests). Floor 866, ceiling ~870.

- [ ] **Step 6: Commit**

```bash
git add src/screw_agents/engine.py \
        src/screw_agents/server.py \
        tests/test_adaptive_staging.py
git commit -m "feat(phase3b-c1): reject_staged_script MCP tool (T5)"
```

**T5 Opus 4.7 re-review (2026-04-21):** Spec review APPROVED (all 10 HRs pass). Quality review found 3 Important + 5 Minor items. All 3 Important fixed in T5 part 2 commit:

- **I-T5-1 (prompts-file exception breadth):** `adaptive_prompts.json` update now catches `(PermissionError, OSError, ValueError)` and self-heals corrupted files (wrong shape, invalid JSON). +2 regression tests.
- **I-T5-2 (delete_staged_files wrap):** symmetric to T4's wrap; ValueError → `{"error": "delete_failed", ...}` error-dict. +1 regression test.
- **I-T5-3 (audit-count invariant):** idempotent test now asserts exactly one `rejected` event in registry after two rejects.

Minor items deferred to DEFERRED_BACKLOG as `BACKLOG-PR6-32..36`.

---

### Task 6: `sweep_stale_staging` MCP Tool (Absorbs T-STAGING-ORPHAN-GC)

**Files:**
- Modify: `src/screw_agents/adaptive/staging.py` (add `sweep_stale`)
- Modify: `src/screw_agents/engine.py` (add `sweep_stale_staging`)
- Modify: `src/screw_agents/server.py` (register MCP tool)
- Modify: `tests/test_adaptive_staging.py` (+5 tests)

**Rationale:** Absorbs `T-STAGING-ORPHAN-GC` from Phase 4+ section of DEFERRED_BACKLOG — the sweep we're building here covers both the new staging artifacts AND the legacy session-scoped finalize-never-called staging dirs already tracked by that item. Implementation scope is the same either way; absorbing avoids a later one-off PR.

- [ ] **Step 1: Write failing tests**

```python
def test_sweep_removes_stale_orphans(tmp_path: Path) -> None:
    """Fixture: 2 sessions, one 5d old, one 20d old. Threshold 14d → old one swept."""
    from datetime import datetime, timedelta, timezone
    from screw_agents.engine import ScanEngine
    from screw_agents.adaptive.staging import resolve_registry_path, resolve_staging_dir

    project = tmp_path / "project"
    project.mkdir()
    engine = ScanEngine.from_defaults()

    # Stage two scripts in two sessions.
    engine.stage_adaptive_script(
        project_root=project, script_name="new-001", source="pass\n",
        meta={"name": "new-001", "created": "2026-04-20T10:00:00Z",
              "created_by": "t@e.co", "domain": "injection-input-handling",
              "description": "d", "target_patterns": ["x"]},
        session_id="sess-new", target_gap=None,
    )
    engine.stage_adaptive_script(
        project_root=project, script_name="old-001", source="pass\n",
        meta={"name": "old-001", "created": "2026-04-20T10:00:00Z",
              "created_by": "t@e.co", "domain": "injection-input-handling",
              "description": "d", "target_patterns": ["x"]},
        session_id="sess-old", target_gap=None,
    )

    # Manually rewrite registry staged_at for sess-old to 20 days ago.
    registry = resolve_registry_path(project)
    old_time = (datetime.now(timezone.utc) - timedelta(days=20)).strftime("%Y-%m-%dT%H:%M:%SZ")
    new_time = (datetime.now(timezone.utc) - timedelta(days=5)).strftime("%Y-%m-%dT%H:%M:%SZ")
    lines = registry.read_text().splitlines()
    rewritten = []
    for line in lines:
        entry = json.loads(line)
        if entry.get("script_name") == "old-001":
            entry["staged_at"] = old_time
        elif entry.get("script_name") == "new-001":
            entry["staged_at"] = new_time
        rewritten.append(json.dumps(entry, separators=(",", ":"), sort_keys=True))
    registry.write_text("\n".join(rewritten) + "\n")

    response = engine.sweep_stale_staging(project_root=project, max_age_days=14)

    assert response["status"] == "swept"
    assert response["sessions_removed"] >= 1
    removed_names = [r["script_name"] for r in response["scripts_removed"]]
    assert "old-001" in removed_names
    assert "new-001" not in removed_names

    # Filesystem state matches.
    assert not (resolve_staging_dir(project, "sess-old") / "old-001.py").exists()
    assert (resolve_staging_dir(project, "sess-new") / "new-001.py").exists()


def test_sweep_preserves_tampered_files(tmp_path: Path) -> None:
    """TAMPERED marker preserves files for full max_age_days regardless
    of the normal age-based sweep. The tampered_preserved report field
    enumerates preserved entries for operator review."""
    from datetime import datetime, timedelta, timezone
    from screw_agents.engine import ScanEngine
    from screw_agents.adaptive.staging import resolve_registry_path, resolve_staging_dir

    project = tmp_path / "project"
    project.mkdir()
    engine = ScanEngine.from_defaults()

    # Stage a script, then plant a TAMPERED marker next to it.
    engine.stage_adaptive_script(
        project_root=project, script_name="tampered-001", source="pass\n",
        meta={"name": "tampered-001", "created": "2026-04-20T10:00:00Z",
              "created_by": "t@e.co", "domain": "injection-input-handling",
              "description": "d", "target_patterns": ["x"]},
        session_id="sess-t", target_gap=None,
    )
    stage_dir = resolve_staging_dir(project, "sess-t")
    (stage_dir / "tampered-001.TAMPERED").touch()

    # Rewrite staged_at so file is 10d old; max_age_days=14 → not yet expired.
    ten_days_ago = (datetime.now(timezone.utc) - timedelta(days=10)).strftime("%Y-%m-%dT%H:%M:%SZ")
    registry = resolve_registry_path(project)
    import json as _json
    lines = registry.read_text().splitlines()
    rewritten = []
    for line in lines:
        entry = _json.loads(line)
        if entry.get("script_name") == "tampered-001":
            entry["staged_at"] = ten_days_ago
        rewritten.append(_json.dumps(entry, separators=(",", ":"), sort_keys=True))
    registry.write_text("\n".join(rewritten) + "\n")

    response = engine.sweep_stale_staging(project_root=project, max_age_days=14)

    # File preserved, reported in tampered_preserved.
    assert response["status"] == "swept"
    preserved_names = [t["script_name"] for t in response["tampered_preserved"]]
    assert "tampered-001" in preserved_names
    assert (stage_dir / "tampered-001.py").exists()
    assert (stage_dir / "tampered-001.TAMPERED").exists()


def test_sweep_dry_run_no_side_effects(tmp_path: Path) -> None:
    """dry_run=True reports what WOULD be removed but touches no filesystem
    and appends no swept audit events."""
    from datetime import datetime, timedelta, timezone
    from screw_agents.engine import ScanEngine
    from screw_agents.adaptive.staging import resolve_registry_path, resolve_staging_dir

    project = tmp_path / "project"
    project.mkdir()
    engine = ScanEngine.from_defaults()

    # Stage an old script that would be swept in a real run.
    engine.stage_adaptive_script(
        project_root=project, script_name="dry-001", source="pass\n",
        meta={"name": "dry-001", "created": "2026-04-20T10:00:00Z",
              "created_by": "t@e.co", "domain": "injection-input-handling",
              "description": "d", "target_patterns": ["x"]},
        session_id="sess-dry", target_gap=None,
    )
    old = (datetime.now(timezone.utc) - timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%SZ")
    registry = resolve_registry_path(project)
    import json as _json
    lines = registry.read_text().splitlines()
    rewritten = []
    for line in lines:
        entry = _json.loads(line)
        if entry.get("script_name") == "dry-001":
            entry["staged_at"] = old
        rewritten.append(_json.dumps(entry, separators=(",", ":"), sort_keys=True))
    registry.write_text("\n".join(rewritten) + "\n")

    # Snapshot registry line count before dry-run.
    lines_before = len(registry.read_text().splitlines())

    response = engine.sweep_stale_staging(
        project_root=project, max_age_days=14, dry_run=True,
    )

    assert response["status"] == "swept"
    assert response["dry_run"] is True
    # Report populated.
    removed_names = [r["script_name"] for r in response["scripts_removed"]]
    assert "dry-001" in removed_names
    # Filesystem unchanged.
    assert (resolve_staging_dir(project, "sess-dry") / "dry-001.py").exists()
    # Registry unchanged — NO swept event appended.
    lines_after = len(registry.read_text().splitlines())
    assert lines_after == lines_before


def test_sweep_removes_empty_session_dirs(tmp_path: Path) -> None:
    """After removing the last script in a session's adaptive-scripts dir,
    the empty session directory itself is also removed + counted in
    sessions_removed."""
    from datetime import datetime, timedelta, timezone
    from screw_agents.engine import ScanEngine
    from screw_agents.adaptive.staging import resolve_registry_path, resolve_staging_dir

    project = tmp_path / "project"
    project.mkdir()
    engine = ScanEngine.from_defaults()

    engine.stage_adaptive_script(
        project_root=project, script_name="only-001", source="pass\n",
        meta={"name": "only-001", "created": "2026-04-20T10:00:00Z",
              "created_by": "t@e.co", "domain": "injection-input-handling",
              "description": "d", "target_patterns": ["x"]},
        session_id="sess-solo", target_gap=None,
    )
    old = (datetime.now(timezone.utc) - timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%SZ")
    registry = resolve_registry_path(project)
    import json as _json
    lines = registry.read_text().splitlines()
    rewritten = [
        _json.dumps({**_json.loads(line), "staged_at": old}
                    if _json.loads(line).get("script_name") == "only-001"
                    else _json.loads(line),
                    separators=(",", ":"), sort_keys=True)
        for line in lines
    ]
    registry.write_text("\n".join(rewritten) + "\n")

    response = engine.sweep_stale_staging(project_root=project, max_age_days=14)

    assert response["sessions_removed"] >= 1
    # Session dir gone.
    session_dir = project / ".screw" / "staging" / "sess-solo"
    assert not session_dir.exists()


def test_sweep_reads_config_yaml_threshold(tmp_path: Path) -> None:
    """.screw/config.yaml staging_max_age_days overrides the default 14.
    With threshold=7, a 10-day-old script is swept."""
    from datetime import datetime, timedelta, timezone
    from screw_agents.engine import ScanEngine
    from screw_agents.adaptive.staging import resolve_registry_path, resolve_staging_dir

    project = tmp_path / "project"
    project.mkdir()
    config_dir = project / ".screw"
    config_dir.mkdir()
    (config_dir / "config.yaml").write_text(
        "version: 1\n"
        "staging_max_age_days: 7\n",
        encoding="utf-8",
    )
    engine = ScanEngine.from_defaults()

    engine.stage_adaptive_script(
        project_root=project, script_name="cfg-001", source="pass\n",
        meta={"name": "cfg-001", "created": "2026-04-20T10:00:00Z",
              "created_by": "t@e.co", "domain": "injection-input-handling",
              "description": "d", "target_patterns": ["x"]},
        session_id="sess-cfg", target_gap=None,
    )
    ten = (datetime.now(timezone.utc) - timedelta(days=10)).strftime("%Y-%m-%dT%H:%M:%SZ")
    registry = resolve_registry_path(project)
    import json as _json
    lines = registry.read_text().splitlines()
    rewritten = []
    for line in lines:
        entry = _json.loads(line)
        if entry.get("script_name") == "cfg-001":
            entry["staged_at"] = ten
        rewritten.append(_json.dumps(entry, separators=(",", ":"), sort_keys=True))
    registry.write_text("\n".join(rewritten) + "\n")

    # max_age_days=None → engine reads from config.yaml → 7.
    response = engine.sweep_stale_staging(project_root=project)

    assert response["max_age_days"] == 7
    removed_names = [r["script_name"] for r in response["scripts_removed"]]
    assert "cfg-001" in removed_names
```

- [ ] **Step 2: Run tests — verify they fail**

Expected: 5 FAIL with `AttributeError: 'ScanEngine' object has no attribute 'sweep_stale_staging'`.

- [ ] **Step 3: Implement `staging.sweep_stale`**

```python
def sweep_stale(
    *,
    project_root: Path,
    max_age_days: int,
    dry_run: bool,
) -> dict:
    """Scan .screw/staging/*/ and delete entries older than max_age_days.

    Rules:
      - TAMPERED marker preserves staging files regardless of age (they
        get swept with the rest on final expiration).
      - Most-recent registry event in {promoted, rejected}: the staging
        file shouldn't be there; delete unconditionally (defensive GC of
        post-promote orphans).
      - Empty session dirs are removed.

    Spec §3.4.
    """
    from datetime import datetime, timedelta, timezone

    staging_root = project_root / ".screw" / "staging"
    scripts_removed: list[dict] = []
    tampered_preserved: list[dict] = []
    sessions_scanned = 0
    sessions_removed = 0

    if not staging_root.exists():
        return {
            "status": "swept",
            "max_age_days": max_age_days,
            "dry_run": dry_run,
            "sessions_scanned": 0,
            "sessions_removed": 0,
            "scripts_removed": [],
            "tampered_preserved": [],
        }

    try:
        for session_dir in staging_root.iterdir():
            if not session_dir.is_dir():
                continue
            sessions_scanned += 1
            adapt_dir = session_dir / "adaptive-scripts"
            if not adapt_dir.exists():
                continue

            for py_path in list(adapt_dir.glob("*.py")):
                script_name = py_path.stem
                session_id = session_dir.name
                entry = query_registry_most_recent(
                    project_root, script_name=script_name, session_id=session_id,
                )
                tampered_marker = adapt_dir / f"{script_name}.TAMPERED"

                # Compute file age from staged_at (or mtime as fallback).
                age_days = _compute_age_days(entry, py_path)
                reason = _classify_sweep_reason(entry, age_days, max_age_days)

                if reason is None:
                    continue  # keep

                if tampered_marker.exists() and age_days < max_age_days:
                    tampered_preserved.append({
                        "script_name": script_name,
                        "session_id": session_id,
                        "evidence_path": str(py_path),
                        "age_days": age_days,
                    })
                    continue

                if not dry_run:
                    py_path.unlink(missing_ok=True)
                    (adapt_dir / f"{script_name}.meta.yaml").unlink(missing_ok=True)
                    tampered_marker.unlink(missing_ok=True)
                    sweep_entry = {
                        "event": "swept",
                        "script_name": script_name,
                        "session_id": session_id,
                        "sweep_reason": reason,
                        "swept_at": _utc_now_iso(),
                        "schema_version": 1,
                    }
                    append_registry_entry(project_root, sweep_entry)
                scripts_removed.append({
                    "script_name": script_name,
                    "session_id": session_id,
                    "reason": reason,
                    "age_days": age_days,
                })

            # Remove empty adaptive-scripts + session dir.
            if not dry_run and adapt_dir.exists() and not any(adapt_dir.iterdir()):
                try:
                    adapt_dir.rmdir()
                except OSError:
                    pass
                if session_dir.exists() and not any(session_dir.iterdir()):
                    session_dir.rmdir()
                    sessions_removed += 1
    except (PermissionError, OSError) as exc:
        raise ValueError(
            f"sweep failed ({type(exc).__name__}: {exc})"
        ) from exc

    return {
        "status": "swept",
        "max_age_days": max_age_days,
        "dry_run": dry_run,
        "sessions_scanned": sessions_scanned,
        "sessions_removed": sessions_removed,
        "scripts_removed": scripts_removed,
        "tampered_preserved": tampered_preserved,
    }


def _compute_age_days(entry: dict | None, py_path: Path) -> int:
    """Return age in days based on registry staged_at or file mtime fallback."""
    from datetime import datetime, timezone
    if entry and "staged_at" in entry:
        try:
            t = datetime.strptime(entry["staged_at"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
            return (datetime.now(timezone.utc) - t).days
        except ValueError:
            pass
    mtime = datetime.fromtimestamp(py_path.stat().st_mtime, tz=timezone.utc)
    return (datetime.now(timezone.utc) - mtime).days


# Terminal/completed events — staging files shouldn't still exist if the
# lifecycle reached any of these. A staged→promoted path deletes staging
# files (per T4's flow) or logs the failure (per T5's I-T5-2 wrap). Any
# staged files left behind = orphan to sweep. All 3 promote variants
# (T4 emits them depending on fallback / confirm-stale) + reject + swept.
_TERMINAL_EVENTS: frozenset[str] = frozenset({
    "promoted",
    "promoted_via_fallback",
    "promoted_confirm_stale",
    "rejected",
    "swept",
})


def _classify_sweep_reason(
    entry: dict | None, age_days: int, max_age_days: int
) -> str | None:
    """Decide whether this staging entry should be swept.

    Returns reason string or None (keep).

    Rules:
      - `tamper_detected` as most-recent event → preserve regardless of age
        (forensic evidence; sweep after max_age_days expiration via the
        age-based branch, but the TAMPERED marker check in sweep_stale
        gets the first vote).
      - Any terminal-lifecycle event → completed_orphan (sweep regardless
        of age — the files shouldn't be there post-lifecycle).
      - Age >= max_age_days → stale_orphan.
      - Otherwise keep.
    """
    if entry and entry.get("event") == "tamper_detected":
        # Do NOT report tamper_detected as sweepable here; the marker-file
        # check in sweep_stale owns the preserve-vs-expire decision.
        if age_days >= max_age_days:
            return "stale_orphan"  # tamper evidence expired; sweep caller
                                    # still has tampered_preserved reporting
        return None
    if entry and entry.get("event") in _TERMINAL_EVENTS:
        return "completed_orphan"
    if age_days >= max_age_days:
        return "stale_orphan"
    return None
```

- [ ] **Step 4: Implement `engine.sweep_stale_staging`**

```python
def sweep_stale_staging(
    self,
    *,
    project_root: Path,
    max_age_days: int | None = None,
    dry_run: bool = False,
) -> dict:
    """User-invoked orphan sweep. Reads threshold from config or uses default 14d."""
    from screw_agents.adaptive.staging import sweep_stale

    if max_age_days is None:
        max_age_days = _read_staging_max_age_days(project_root)
    max_age_days = max(1, min(365, int(max_age_days)))

    return sweep_stale(
        project_root=project_root,
        max_age_days=max_age_days,
        dry_run=dry_run,
    )


def _read_staging_max_age_days(project_root: Path) -> int:
    """Return staging_max_age_days from config (default 14, clamped 1-365).

    Module-level helper symmetric with `_read_stale_staging_hours` (T4 /
    engine.py:63). Raw YAML fallback handles missing/corrupt config; the
    canonical validation path is `ScrewConfig.staging_max_age_days`
    (T4-part-2 I1 schema addition).
    """
    try:
        import yaml
        config_path = project_root / ".screw" / "config.yaml"
        if not config_path.exists():
            return 14
        with open(config_path, encoding="utf-8") as f:
            cfg = yaml.safe_load(f) or {}
        return max(1, min(365, int(cfg.get("staging_max_age_days", 14))))
    except (PermissionError, OSError, ValueError):
        return 14
```

- [ ] **Step 5: Register MCP tool in `server.py` AND add schema to `engine.list_tool_definitions`**

**5a. Dispatch branch in `src/screw_agents/server.py`** (add after the T5 `reject_staged_script` branch, following the `_dispatch_tool` pattern):

```python
# --- Phase 3b T6: sweep_stale_staging (orphan GC — absorbs T-STAGING-ORPHAN-GC) ---

if name == "sweep_stale_staging":
    return engine.sweep_stale_staging(
        project_root=Path(args["project_root"]),
        max_age_days=args.get("max_age_days"),
        dry_run=args.get("dry_run", False),
    )
```

Both `max_age_days` and `dry_run` are optional via `args.get(...)`. `max_age_days=None` makes the engine fall back to `staging_max_age_days` from config (default 14, clamped 1-365).

**5b. Tool schema in `src/screw_agents/engine.list_tool_definitions`** — append a new `tools.append({...})` block:

```python
tools.append({
    "name": "sweep_stale_staging",
    "description": (
        "Clean up orphaned staging entries — session directories under "
        "`.screw/staging/` that are stale (older than max_age_days) or "
        "whose most-recent registry event is a terminal state "
        "(promoted / rejected / swept) but whose files were left behind. "
        "Absorbs the deferred T-STAGING-ORPHAN-GC backlog item: covers "
        "both the new C1 staging artifacts and legacy session-scoped "
        "finalize-never-called staging dirs. When dry_run=true, reports "
        "what would be removed without deleting anything. See design "
        "spec §3.4."
    ),
    "input_schema": {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "project_root": {
                "type": "string",
                "description": "Absolute path to the project root.",
            },
            "max_age_days": {
                "type": ["integer", "null"],
                "description": (
                    "Maximum age (in days) before a staging entry is "
                    "considered stale. Null means read from config "
                    "(`staging_max_age_days`, default 14). Clamped to "
                    "[1, 365]."
                ),
            },
            "dry_run": {
                "type": "boolean",
                "description": (
                    "When true, returns the list of entries that would "
                    "be removed without actually deleting files. Useful "
                    "for preview / CI assertions."
                ),
            },
        },
        "required": [
            "project_root",
        ],
    },
})
```

`additionalProperties: false` is set directly per T10-M1 partial.

- [ ] **Step 6: Run tests + full suite**

Expected: 5 PASS, full suite **~876 passed, 8 skipped** (871 post-T5 + 5 new sweep tests).

- [ ] **Step 7: Commit**

```bash
git add src/screw_agents/adaptive/staging.py \
        src/screw_agents/engine.py \
        src/screw_agents/server.py \
        tests/test_adaptive_staging.py
git commit -m "feat(phase3b-c1): sweep_stale_staging MCP tool (T6, absorbs T-STAGING-ORPHAN-GC)"
```

**Cross-plan sync:** once merged, `T-STAGING-ORPHAN-GC` moves from Phase 4+ deferred to Shipped (PR #6). Update DEFERRED_BACKLOG in T24.

---

## Phase C — I6 MCP Promotion (T7-T9)

### Task 7: Promote `list_adaptive_scripts` to Engine Method + MCP Tool

**Files:**
- Modify: `src/screw_agents/engine.py` (add `list_adaptive_scripts` method)
- Modify: `src/screw_agents/server.py` (register MCP tool)
- Modify: `tests/test_adaptive_cleanup.py` (migrate existing tests to engine)

**Rationale:** I6 fix. Slash command's `uv run python -c "from screw_agents.cli.adaptive_cleanup import ..."` breaks when `cwd != worktree`. Promote the function to an engine method exposed via MCP; slash command then uses the MCP tool (which already has correct `--project` in `.mcp.json`).

- [ ] **Step 1: Read current `cli/adaptive_cleanup.py::list_adaptive_scripts`**

Run: `grep -n "def list_adaptive_scripts" src/screw_agents/cli/adaptive_cleanup.py`

Note the current function signature, the return shape (list of dicts with `name`, `validated`, `signed_by`, `stale`, `stale_reason`, etc.), and the stale-detection helper functions it uses. We will LIFT this logic verbatim into an engine method.

- [ ] **Step 2: Write the migration tests first**

In `tests/test_adaptive_cleanup.py`, REPLACE the top-level import:

```python
# OLD (remove this line):
# from screw_agents.cli.adaptive_cleanup import list_adaptive_scripts, remove_adaptive_script

# NEW:
from screw_agents.engine import ScanEngine
```

In every test that previously called `list_adaptive_scripts(project_root)`, change to:

```python
engine = ScanEngine.from_defaults()
result = engine.list_adaptive_scripts(project_root=project)
scripts = result["scripts"]  # engine returns dict wrapper, not bare list
```

(Existing tests return `list`; new engine method returns `dict` with `scripts` key and `status` key per spec §3.5.)

Similarly `remove_adaptive_script(project_root, script_name, confirmed)` becomes `engine.remove_adaptive_script(...)`.

**Critical:** keep ALL existing test assertions. The behavior must not regress — this is purely a re-homing of the function.

- [ ] **Step 3: Run migrated tests — they MUST fail**

Run: `uv run pytest tests/test_adaptive_cleanup.py -v`
Expected: FAIL with `AttributeError: 'ScanEngine' object has no attribute 'list_adaptive_scripts'`.

- [ ] **Step 4: Implement `engine.list_adaptive_scripts`**

LIFT the logic from `cli/adaptive_cleanup.py::list_adaptive_scripts` into `engine.py` as a method. The CLI helper functions (`_check_stale`, etc.) move alongside. Preserve every behavioral detail: stale flag computation, signed_by extraction, target_patterns check.

```python
def list_adaptive_scripts(
    self,
    *,
    project_root: Path,
) -> dict:
    """List all adaptive scripts at .screw/custom-scripts/ with validation
    status and per-script staleness.

    Promoted from cli/adaptive_cleanup.py in PR #6 per I6 — slash command
    invocation was breaking on cwd mismatch. Behavior unchanged from T21.

    Returns ``{"status": "ok", "scripts": [{"name", "validated",
    "signed_by", "stale", "stale_reason"}, ...]}`` per spec §3.5.
    """
    custom_scripts_dir = project_root / ".screw" / "custom-scripts"
    if not custom_scripts_dir.exists():
        return {"status": "ok", "scripts": []}

    scripts: list[dict] = []
    for py_path in sorted(custom_scripts_dir.glob("*.py")):
        meta_path = py_path.with_suffix(".meta.yaml")
        if not meta_path.exists():
            continue
        # ... LIFT full logic from current CLI function, including
        # the stale-detection helper's call to find_calls ...
        scripts.append(self._inspect_adaptive_script(project_root, py_path, meta_path))
    return {"status": "ok", "scripts": scripts}


def _inspect_adaptive_script(self, project_root, py_path, meta_path) -> dict:
    """Per-script inspection extracted from the old CLI helper."""
    # ... verbatim lift of the per-script logic from cli/adaptive_cleanup.py ...
```

- [ ] **Step 5: Register MCP tool in `server.py` AND add schema to `engine.list_tool_definitions`**

**5a. Dispatch branch in `src/screw_agents/server.py`** (add in the adaptive-handlers block, following the `_dispatch_tool` pattern):

```python
# --- Phase 3b T7: list_adaptive_scripts (I6 MCP promotion) ---

if name == "list_adaptive_scripts":
    return engine.list_adaptive_scripts(
        project_root=Path(args["project_root"]),
    )
```

**5b. Tool schema in `src/screw_agents/engine.list_tool_definitions`** — append a new `tools.append({...})` block:

```python
tools.append({
    "name": "list_adaptive_scripts",
    "description": (
        "List all adaptive scripts present at `.screw/custom-scripts/` "
        "with their validation status and per-script staleness "
        "information. Promoted from `cli/adaptive_cleanup.py` in PR #6 "
        "per I6 — slash-command invocation was breaking on `cwd` "
        "mismatch. Returns `{\"status\": \"ok\", \"scripts\": [{name, "
        "validated, signed_by, stale, stale_reason, ...}]}`. Behavior "
        "unchanged from T21. See design spec §3.5."
    ),
    "input_schema": {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "project_root": {
                "type": "string",
                "description": "Absolute path to the project root.",
            },
        },
        "required": [
            "project_root",
        ],
    },
})
```

`additionalProperties: false` is set directly per T10-M1 partial.

- [ ] **Step 6: Run tests — verify pass**

Run: `uv run pytest tests/test_adaptive_cleanup.py -v`
Expected: all migrated tests PASS.

Run: `uv run pytest tests/test_adaptive_workflow.py -v -k "list"`
Expected: T22's list_adaptive_scripts use site passes too.

Run: `uv run pytest -q`
Expected: 812 passed (unchanged — we migrated tests, didn't add new ones yet).

- [ ] **Step 7: Commit**

```bash
git add src/screw_agents/engine.py \
        src/screw_agents/server.py \
        tests/test_adaptive_cleanup.py
git commit -m "feat(phase3b-c1): promote list_adaptive_scripts to engine + MCP tool (T7, I6 part 1)"
```

---

### Task 8: Promote `remove_adaptive_script` to Engine Method + MCP Tool

**Files:**
- Modify: `src/screw_agents/engine.py` (add `remove_adaptive_script`)
- Modify: `src/screw_agents/server.py` (register MCP tool)
- Modify: `tests/test_adaptive_cleanup.py` (migration already done in T7)

Follow the T7 pattern exactly. Existing T21 confirmation-gate semantics preserved.

- [ ] **Step 1: Implement `engine.remove_adaptive_script`**

```python
def remove_adaptive_script(
    self,
    *,
    project_root: Path,
    script_name: str,
    confirmed: bool = False,
) -> dict:
    """Delete an adaptive script pair from .screw/custom-scripts/.

    T21 confirmation gate preserved: confirmed=False returns
    ``{"status":"error","error":"confirmation_required"}``. Caller is
    expected to prompt the user for "yes" before passing confirmed=True.

    Spec §3.6.
    """
    if not confirmed:
        return {
            "status": "error",
            "error": "confirmation_required",
            "message": "remove_adaptive_script requires confirmed=True",
        }

    custom_scripts_dir = project_root / ".screw" / "custom-scripts"
    py_path = custom_scripts_dir / f"{script_name}.py"
    meta_path = custom_scripts_dir / f"{script_name}.meta.yaml"

    if not py_path.exists():
        return {
            "status": "error",
            "error": "not_found",
            "message": f"{script_name}.py not found in custom-scripts/",
        }

    try:
        py_path.unlink(missing_ok=True)
        meta_path.unlink(missing_ok=True)
    except (PermissionError, OSError) as exc:
        raise ValueError(
            f"failed to remove {script_name} ({type(exc).__name__}: {exc})"
        ) from exc

    return {"status": "removed", "script_name": script_name}
```

- [ ] **Step 2: Register MCP tool in `server.py` AND add schema to `engine.list_tool_definitions`**

**2a. Dispatch branch in `src/screw_agents/server.py`** (add after the T7 `list_adaptive_scripts` branch, following the `_dispatch_tool` pattern):

```python
# --- Phase 3b T8: remove_adaptive_script (I6 MCP promotion — confirmation-gated) ---

if name == "remove_adaptive_script":
    return engine.remove_adaptive_script(
        project_root=Path(args["project_root"]),
        script_name=args["script_name"],
        confirmed=args.get("confirmed", False),
    )
```

`confirmed` defaults to False via `args.get(...)`; the engine method returns `status="error"` / `error="confirmation_required"` when False. The caller (slash command) is expected to prompt the user for "yes" before passing `confirmed=True`.

**2b. Tool schema in `src/screw_agents/engine.list_tool_definitions`** — append a new `tools.append({...})` block:

```python
tools.append({
    "name": "remove_adaptive_script",
    "description": (
        "Delete an adaptive script pair (`{name}.py` + `{name}.meta.yaml`) "
        "from `.screw/custom-scripts/`, gated by an explicit "
        "`confirmed=true` flag (T21 confirmation-gate semantics "
        "preserved). Returns status=\"error\" / "
        "error=\"confirmation_required\" when confirmed is False or "
        "omitted, status=\"error\" / error=\"not_found\" when the "
        "script is missing, otherwise status=\"removed\". Promoted from "
        "`cli/adaptive_cleanup.py` in PR #6 per I6. See design spec §3.6."
    ),
    "input_schema": {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "project_root": {
                "type": "string",
                "description": "Absolute path to the project root.",
            },
            "script_name": {
                "type": "string",
                "description": (
                    "Filesystem-safe name of the adaptive script to "
                    "remove (without `.py` / `.meta.yaml` suffix)."
                ),
            },
            "confirmed": {
                "type": "boolean",
                "description": (
                    "Must be true to actually delete. False (or absent) "
                    "returns error=\"confirmation_required\" — the "
                    "caller is expected to prompt the user for \"yes\" "
                    "before retrying with confirmed=true."
                ),
            },
        },
        "required": [
            "project_root",
            "script_name",
        ],
    },
})
```

`additionalProperties: false` is set directly per T10-M1 partial.

- [ ] **Step 3: Run tests + full suite**

Run: `uv run pytest tests/test_adaptive_cleanup.py -v`
Expected: all migrated tests PASS.

Run: `uv run pytest -q`
Expected: 812 passed.

- [ ] **Step 4: Commit**

```bash
git add src/screw_agents/engine.py \
        src/screw_agents/server.py
git commit -m "feat(phase3b-c1): promote remove_adaptive_script to engine + MCP tool (T8, I6 part 2)"
```

---

### Task 9: Delete `cli/adaptive_cleanup.py` + Migrate T22

**Files:**
- Delete: `src/screw_agents/cli/adaptive_cleanup.py`
- Modify: `tests/test_adaptive_workflow.py` (migrate T22's `from screw_agents.cli.adaptive_cleanup import list_adaptive_scripts` to engine call)

**Rationale:** Per I6 / Q4: no shell-command entry point; no programmatic users outside tests; engine + MCP path is now the single surface.

- [ ] **Step 1: Verify nothing outside tests imports from cli.adaptive_cleanup**

Run: `grep -rn "from screw_agents.cli.adaptive_cleanup" --include="*.py" --include="*.md"`
Expected ONLY:
- `tests/test_adaptive_cleanup.py` (already migrated in T7)
- `tests/test_adaptive_workflow.py` (needs migration in this task)
- `plugins/screw/commands/adaptive-cleanup.md` (will be rewritten in T19)

If any OTHER file imports — stop. Revise plan before deleting.

- [ ] **Step 2: Migrate T22 import**

In `tests/test_adaptive_workflow.py`:

```python
# OLD:
from screw_agents.cli.adaptive_cleanup import list_adaptive_scripts
# ... later:
scripts = list_adaptive_scripts(project)

# NEW:
# (delete the import; add engine call at the use site)
scripts_response = engine.list_adaptive_scripts(project_root=project)
scripts = scripts_response["scripts"]  # unwrap the dict wrapper
```

- [ ] **Step 3: Run T22 to verify migration**

Run: `uv run pytest tests/test_adaptive_workflow.py -v`
Expected: `test_full_adaptive_workflow_composition` PASSES (same behavior, new import path).

- [ ] **Step 4: Delete the CLI file**

```bash
git rm src/screw_agents/cli/adaptive_cleanup.py
```

- [ ] **Step 5: Run full suite**

Run: `uv run pytest -q`
Expected: 812 passed (T22 migrated, behavior preserved).

Run: `grep -rn "from screw_agents.cli.adaptive_cleanup"` (Python files only)
Expected: 0 matches (file deleted; imports all migrated).

- [ ] **Step 6: Commit**

```bash
git add tests/test_adaptive_workflow.py
git add -u src/screw_agents/cli/adaptive_cleanup.py  # -u records the deletion
git commit -m "refactor(phase3b-c1): delete cli/adaptive_cleanup.py, migrate T22 import (T9, I6 part 3)"
```

**Cross-plan sync:** confirm DEFERRED_BACKLOG entry I6 is ready to move to Shipped (will happen in T24). Also cross-check: does the slash command at `plugins/screw/commands/adaptive-cleanup.md` still reference the deleted module? If yes (it will), T19 fixes it — don't worry about it here.

---

## Phase D — Adjacent Polish (T10-T14)

### Task 10: I2 — Layer 1 AST Lint Symbol Validation

**Files:**
- Modify: `src/screw_agents/adaptive/lint.py` (add `__all__` symbol validation)
- Modify: `tests/test_adaptive_lint.py` (+4 tests)

**Rationale:** Current lint allows `from screw_agents.adaptive import anything`; only the MODULE is allowlisted. I5's prompt hardening helps but doesn't guarantee; I2 is the structural defense that ALWAYS catches hallucinated imports.

- [ ] **Step 1: Write failing tests**

```python
# tests/test_adaptive_lint.py

def test_lint_rejects_import_of_read_source() -> None:
    """Round-trip regression: script v1 imported `read_source` (not in __all__).
    Lint MUST reject with rule=unknown_symbol."""
    from screw_agents.adaptive.lint import lint_script

    source = (
        "from screw_agents.adaptive import emit_finding, read_source\n"
        "\n"
        "def analyze(project):\n"
        "    read_source(project, 'foo.py')\n"
    )

    report = lint_script(source)
    assert not report.passed
    violations = [v for v in report.violations if v.rule == "unknown_symbol"]
    assert len(violations) == 1
    assert "read_source" in violations[0].message


def test_lint_rejects_import_of_parse_module() -> None:
    from screw_agents.adaptive.lint import lint_script

    source = (
        "from screw_agents.adaptive import parse_module\n"
        "\n"
        "def analyze(project):\n"
        "    pass\n"
    )

    report = lint_script(source)
    assert not report.passed
    assert any(v.rule == "unknown_symbol" and "parse_module" in v.message for v in report.violations)


def test_lint_accepts_all_exported_names() -> None:
    """Parametrized sanity: every name in screw_agents.adaptive.__all__ must
    lint clean when imported alone."""
    from screw_agents import adaptive as adaptive_pkg
    from screw_agents.adaptive.lint import lint_script

    for name in adaptive_pkg.__all__:
        source = (
            f"from screw_agents.adaptive import {name}\n"
            f"\n"
            f"def analyze(project):\n"
            f"    pass\n"
        )
        report = lint_script(source)
        # Some names are classes/constants and may not be directly callable
        # at analyze; we only care that they pass SYMBOL check (no unknown_symbol
        # violation). Other violations (unused import, etc.) are tolerated here.
        symbol_violations = [v for v in report.violations if v.rule == "unknown_symbol"]
        assert symbol_violations == [], (
            f"{name} from adaptive.__all__ wrongly flagged as unknown_symbol"
        )


def test_lint_violation_message_lists_allowlist() -> None:
    """UX: when a symbol is rejected, the message should enumerate valid
    names so the caller can fix the import."""
    from screw_agents.adaptive.lint import lint_script
    from screw_agents import adaptive as adaptive_pkg

    source = "from screw_agents.adaptive import nonexistent\n"
    report = lint_script(source)
    violations = [v for v in report.violations if v.rule == "unknown_symbol"]
    assert len(violations) == 1
    # Every __all__ entry should appear somewhere in the message.
    for name in adaptive_pkg.__all__:
        assert name in violations[0].message
```

- [ ] **Step 2: Run — verify failures**

Run: `uv run pytest tests/test_adaptive_lint.py -v -k "symbol or unknown or exported or allowlist"`
Expected: 4 FAIL (rule `unknown_symbol` doesn't exist yet).

- [ ] **Step 3: Implement symbol validation in `adaptive/lint.py`**

Add to `src/screw_agents/adaptive/lint.py`:

```python
import ast
import importlib.util
from functools import lru_cache
from pathlib import Path


@lru_cache(maxsize=1)
def _load_adaptive_all() -> frozenset[str]:
    """Return the cached __all__ set from screw_agents.adaptive.

    Uses AST parsing (not runtime import) to stay hermetic — lint must not
    depend on the adaptive package being fully importable in the linting
    environment.
    """
    spec = importlib.util.find_spec("screw_agents.adaptive")
    if spec is None or spec.origin is None:
        return frozenset()
    source = Path(spec.origin).read_text(encoding="utf-8")
    tree = ast.parse(source)
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == "__all__":
                    if isinstance(node.value, ast.List | ast.Tuple):
                        names = frozenset(
                            elt.value for elt in node.value.elts
                            if isinstance(elt, ast.Constant) and isinstance(elt.value, str)
                        )
                        return names
    return frozenset()


# ... inside the existing lint walker's ImportFrom handler:
class LintWalker(ast.NodeVisitor):
    # ... existing methods ...

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        # ... existing module-allowlist check ...
        if node.module == "screw_agents.adaptive":
            allowed = _load_adaptive_all()
            for alias in node.names:
                if alias.name not in allowed:
                    allowlist_display = ", ".join(sorted(allowed))
                    self._add_violation(
                        line=node.lineno,
                        rule="unknown_symbol",
                        message=(
                            f"'{alias.name}' is not exported from screw_agents.adaptive. "
                            f"Valid names: {allowlist_display}"
                        ),
                    )
        self.generic_visit(node)
```

(Adjust to match the actual class/function names in the existing lint.py — the pattern of visit_ImportFrom is likely present; add the symbol check to it.)

- [ ] **Step 4: Run tests — verify pass**

Run: `uv run pytest tests/test_adaptive_lint.py -v`
Expected: all previously-passing tests still pass + 4 new tests PASS.

- [ ] **Step 5: Full suite**

Run: `uv run pytest -q`
Expected: 816 passed.

- [ ] **Step 6: Commit**

```bash
git add src/screw_agents/adaptive/lint.py tests/test_adaptive_lint.py
git commit -m "feat(phase3b-c1): lint validates imported symbols against adaptive.__all__ (T10, I2)"
```

---

### Task 11: I3 — Sandbox Execution stderr Surfacing

**Files:**
- Modify: `src/screw_agents/adaptive/sandbox/linux.py` (verify/tighten stderr capture)
- Modify: `src/screw_agents/adaptive/executor.py` (propagate stderr to tool return on failure)
- Modify: `tests/test_adaptive_executor.py` (+2 tests)

- [ ] **Step 1: Trace current stderr path**

Read `sandbox/linux.py::run_in_sandbox`:
- Confirm `subprocess.run(..., capture_output=True)` is present. If using `stdout=subprocess.PIPE` + `stderr=subprocess.PIPE`, that's equivalent.
- Confirm `SandboxResult.stderr` is populated from `proc.stderr.decode("utf-8", errors="replace")`.

Read `executor.py::execute_script`:
- Confirm on `sandbox_result.returncode != 0`, the return payload includes `stderr`.

Where gaps exist — add them.

- [ ] **Step 2: Write failing test**

```python
# tests/test_adaptive_executor.py

@pytest.mark.skipif(
    shutil.which("bwrap") is None and shutil.which("sandbox-exec") is None,
    reason="requires sandbox backend",
)
def test_execute_surfaces_stderr_on_nonzero_return(tmp_path: Path) -> None:
    """A script with bad import raises ImportError → sandbox returncode=1.
    Executor MUST surface stderr in the returned result so the subagent's
    failure-render path has something to show the user."""
    # ... Arrange: write a script with `from screw_agents.adaptive import nonexistent`
    # into .screw/custom-scripts/ (sign with a local key via init-trust).
    # Act: execute_adaptive_script
    # Assert: result["status"] in ("error", "failed") AND
    #         "ImportError" in result["stderr"] OR equivalent
    ...


def test_execute_stderr_absent_on_success(tmp_path: Path) -> None:
    """Happy path: no stderr field or empty string. Don't clutter success payloads."""
    ...
```

- [ ] **Step 3: Run — verify failure**

- [ ] **Step 4: Implement — ensure `executor.py` returns stderr on failure**

Modify the relevant branch in `executor.py::execute_script`:

```python
# Existing (conceptually):
sandbox_result = run_in_sandbox(...)
if sandbox_result.returncode != 0:
    return {
        "status": "sandbox_failure",
        "returncode": sandbox_result.returncode,
        "wall_clock_s": sandbox_result.wall_clock_s,
        "killed_by_timeout": sandbox_result.killed_by_timeout,
        # ADD:
        "stderr": sandbox_result.stderr or "",
    }
```

If `stderr` is missing from `SandboxResult`, add it to the dataclass and populate in `sandbox/linux.py::run_in_sandbox` via `proc.stderr.decode("utf-8", errors="replace")`.

- [ ] **Step 5: Run tests — verify pass**

Run: `uv run pytest tests/test_adaptive_executor.py -v`

- [ ] **Step 6: Commit**

```bash
git add src/screw_agents/adaptive/sandbox/linux.py \
        src/screw_agents/adaptive/executor.py \
        tests/test_adaptive_executor.py
git commit -m "feat(phase3b-c1): surface sandbox stderr on execution failure (T11, I3)"
```

**Note:** T18b prompt render-on-failure branch update is part of T15 (per-agent subagent prompt rewrite).

---

### Task 12: T11-N2 — `MetadataError` Exception Wrapper

**Files:**
- Modify: `src/screw_agents/adaptive/executor.py` (add `MetadataError`; wrap yaml + Pydantic errors)
- Modify: `tests/test_adaptive_executor.py` (+2 tests)

- [ ] **Step 1: Write failing tests**

```python
def test_executor_wraps_yaml_error_as_metadata_error(tmp_path: Path) -> None:
    """Invalid YAML in .meta.yaml → MetadataError (not bare yaml.YAMLError)."""
    from screw_agents.adaptive.executor import MetadataError, execute_script
    from screw_agents.cli.init_trust import run_init_trust

    project = tmp_path / "project"
    project.mkdir()
    run_init_trust(project_root=project, name="T", email="t@e.co")
    custom_dir = project / ".screw" / "custom-scripts"
    custom_dir.mkdir(parents=True)
    (custom_dir / "test-yaml-001.py").write_text("pass\n")
    (custom_dir / "test-yaml-001.meta.yaml").write_text("not: valid: yaml: {\n")  # malformed

    with pytest.raises(MetadataError, match="invalid YAML"):
        execute_script(project_root=project, script_name="test-yaml-001", wall_clock_s=5)


def test_executor_wraps_validation_error_as_metadata_error(tmp_path: Path) -> None:
    """Malformed meta dict (missing required fields) → MetadataError."""
    # ... similar setup with a meta.yaml that parses but fails
    # AdaptiveScriptMeta validation ...
```

- [ ] **Step 2: Run — verify failure**

- [ ] **Step 3: Implement `MetadataError`**

In `src/screw_agents/adaptive/executor.py`:

```python
class MetadataError(RuntimeError):
    """Raised when an adaptive script's .meta.yaml cannot be loaded.

    Wraps the underlying yaml.YAMLError or pydantic.ValidationError so
    the MCP tool layer (execute_adaptive_script dispatch) has a single
    exception-family to catch alongside LintFailure / HashMismatch /
    SignatureFailure.

    T11-N2 (bundled polish in Phase 3b PR #6).
    """


# In execute_script, replace:
#     meta_raw = yaml.safe_load(meta_path.read_text(encoding="utf-8"))
#     meta = AdaptiveScriptMeta(**meta_raw)
# with:
def _load_meta(meta_path: Path) -> "AdaptiveScriptMeta":
    try:
        meta_raw = yaml.safe_load(meta_path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise MetadataError(f"invalid YAML in {meta_path}: {exc}") from exc
    try:
        return AdaptiveScriptMeta(**(meta_raw or {}))
    except ValidationError as exc:
        raise MetadataError(f"malformed metadata in {meta_path}: {exc}") from exc
```

Update the executor dispatch / engine wrapper for `execute_adaptive_script` to catch `MetadataError` and return `{"status":"error","error":"invalid_metadata",...}` (preserving existing UX for bad meta).

- [ ] **Step 4: Run tests + suite**

Run: `uv run pytest -q`
Expected: 818 passed (816 post-T10 + 2 new T11-N2 tests).

- [ ] **Step 5: Commit**

```bash
git add src/screw_agents/adaptive/executor.py tests/test_adaptive_executor.py
git commit -m "feat(phase3b-c1): wrap yaml+pydantic errors as MetadataError (T12, T11-N2 polish)"
```

---

### Task 13: T3-M1 — Narrow Exception Handling in `ast_walker.py`

**Files:**
- Modify: `src/screw_agents/adaptive/ast_walker.py`
- Modify: `tests/test_adaptive_ast_walker.py` (+1 test for non-UTF-8)

- [ ] **Step 1: Write failing test**

```python
def test_find_calls_raises_on_non_utf8_source(tmp_path: Path) -> None:
    """Non-UTF-8 source file → UnicodeDecodeError propagates cleanly.

    Previously (T3-M1 deferred item): `except Exception: continue` silently
    swallowed this, so adaptive scripts couldn't distinguish "no findings"
    from "couldn't read this file". Post-fix: the exception surfaces to
    the caller (executor), which can log / surface to subagent.
    """
    from screw_agents.adaptive.ast_walker import ProjectRoot, find_calls

    project = tmp_path / "project"
    project.mkdir()
    # Write Latin-1-encoded bytes that aren't valid UTF-8.
    (project / "weird.py").write_bytes(b"# Latin-1: caf\xe9\n")
    root = ProjectRoot(project)

    # find_calls should NOT silently skip this; it should either raise
    # (preferred for this fix) OR emit a diagnostic that the caller can surface.
    with pytest.raises(UnicodeDecodeError):
        list(find_calls(root, "foo.bar"))
```

- [ ] **Step 2: Run — verify failure**

Expected: test FAILS because current code silently swallows the exception.

- [ ] **Step 3: Implement narrowing**

In `ast_walker.py`, locate the helpers (`find_calls`, `find_imports`, `find_class_definitions`). Each currently has a pattern like:

```python
try:
    source = project.read_file(rel_path)
    # ... parse + match ...
except Exception:
    continue
```

Change to:

```python
try:
    source = project.read_file(rel_path)
    # ... parse + match ...
except (UnicodeDecodeError, OSError):
    # Deliberately narrow: raise these so adaptive scripts can distinguish
    # "no findings" from "couldn't read this file". Catching bare Exception
    # silently swallowed both T3-M1 category errors (pre-PR #6).
    raise
except tree_sitter.TreeSitterError:
    # Parse errors are still swallowed — the file is not usefully analyzable;
    # other files in the project may be. Log via logger if one exists.
    continue
```

(Adjust the `tree_sitter.TreeSitterError` branch to match the actual exception class the project raises.)

- [ ] **Step 4: Run tests + suite**

Run: `uv run pytest -q`
Expected: 819 passed.

- [ ] **Step 5: Commit**

```bash
git add src/screw_agents/adaptive/ast_walker.py tests/test_adaptive_ast_walker.py
git commit -m "refactor(phase3b-c1): narrow exception handling in ast_walker helpers (T13, T3-M1 polish)"
```

---

### Task 14: T11-N1 — Signature-Path E2E Regression Test

**Files:**
- Modify: `tests/test_adaptive_executor.py` (+60 LOC fixture + 2 tests)

**Rationale:** The most valuable bundled test. Locks the Option D invariant: `execute_script(skip_trust_checks=False)` MUST round-trip through Layer 3 signature verification for any script signed by `_sign_script_bytes` (direct or via promote).

- [ ] **Step 1: Add Ed25519 signing helper fixture**

Append to `tests/test_adaptive_executor.py`:

```python
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding, PrivateFormat, PublicFormat, NoEncryption,
)


@pytest.fixture
def signed_script_setup(tmp_path: Path):
    """Yields a (project_root, script_name, source, meta_dict, cleanup) tuple
    where the script + meta are fully signed and verifiable via Layer 3.

    Used by T11-N1's end-to-end signature-path tests to exercise the real
    sign → verify round-trip, not just skip_trust_checks=True shortcuts.
    """
    from screw_agents.adaptive.signing import _sign_script_bytes
    from screw_agents.cli.init_trust import run_init_trust
    from screw_agents.engine import ScanEngine

    project = tmp_path / "project"
    project.mkdir()
    run_init_trust(project_root=project, name="T11N1", email="sig@example.com")
    engine = ScanEngine.from_defaults()

    source = (
        "from screw_agents.adaptive import emit_finding\n\n"
        "def analyze(project):\n"
        "    pass\n"
    )
    meta = {
        "name": "test-sig-e2e",
        "created": "2026-04-20T10:00:00Z",
        "created_by": "sig@example.com",
        "domain": "injection-input-handling",
        "description": "T11-N1 fixture",
        "target_patterns": ["nothing.at.all"],
    }

    r = engine.sign_adaptive_script(
        project_root=project,
        script_name="test-sig-e2e",
        source=source,
        meta=meta,
        session_id=None,
    )
    assert r["status"] == "signed"

    yield (project, "test-sig-e2e", source, meta)


def test_execute_script_verifies_layer3_signature_happy_path(signed_script_setup) -> None:
    """Full sign → verify round-trip. skip_trust_checks=False.

    T11-N1: end-to-end Layer 3 coverage that was not exercised before.
    """
    from screw_agents.adaptive.executor import execute_script

    project, script_name, _, _ = signed_script_setup

    result = execute_script(
        project_root=project,
        script_name=script_name,
        wall_clock_s=5,
        skip_trust_checks=False,
    )
    assert result["status"] in ("ok", "success") or result.get("returncode") == 0


def test_execute_script_rejects_tampered_signature(signed_script_setup) -> None:
    """Tamper the .py source after signing. Layer 3 verification MUST fail."""
    from screw_agents.adaptive.executor import execute_script, SignatureFailure

    project, script_name, _, _ = signed_script_setup
    py_path = project / ".screw" / "custom-scripts" / f"{script_name}.py"
    py_path.write_text("# tampered\npass\n", encoding="utf-8")

    with pytest.raises(SignatureFailure):
        execute_script(
            project_root=project,
            script_name=script_name,
            wall_clock_s=5,
            skip_trust_checks=False,
        )
```

- [ ] **Step 2: Run tests — should PASS (trust infrastructure already works; these just exercise it)**

Run: `uv run pytest tests/test_adaptive_executor.py -v -k "layer3 or tampered"`
Expected: 2 PASS.

- [ ] **Step 3: Full suite**

Run: `uv run pytest -q`
Expected: 821 passed (819 + 2 T11-N1 tests).

- [ ] **Step 4: Commit**

```bash
git add tests/test_adaptive_executor.py
git commit -m "test(phase3b-c1): end-to-end signature-path regression for execute_script (T14, T11-N1)"
```

Note: the test count is now 821, not 820 as projected. Acceptable — we added one more test than the spec's projection. Update expected-count in Exit Checklist (§below) if needed.

---

## Phase E — Subagent Prompt Rewrite (T15-T18)

### Task 15: Rewrite T18b Adaptive-Mode Section in `screw-sqli.md`

**Files:**
- Modify: `plugins/screw/agents/screw-sqli.md` (Step 3.5d rewrite; also adjust `tools:` frontmatter to add new MCP tools)

**Rationale:** This is THE user-facing C1 fix. The new flow stages BEFORE review, promotes on approve, rejects on reject, and handles respawn via registry lookup. Also applies I1 (plugin namespace), I4 (retention notice), I5 (prompt hardening). The file is the CANONICAL per-agent subagent; T16 then copies this byte-identical section to cmdi/ssti/xss.

**Pre-audit (critical — LLM-flow surface is security-relevant, per `feedback_no_skip_security_artifact_reviews`):**
- The byte-identical-section contract (T18b's `test_adaptive_section_identical_modulo_agent_name`) enforces cmdi/ssti/xss == sqli after agent-name substitution. Edit sqli FIRST; T16 is a byte-copy with `sqli` → `cmdi`/`ssti`/`xss` substitution ONLY.
- Format-smoke tests in T20 will lock: `stage_adaptive_script`, `promote_staged_script`, `reject_staged_script` all present; `sign_adaptive_script` ABSENT; `screw:screw-script-reviewer` (not bare) present; "MUST import ONLY" phrase + 18-name allowlist + negative-examples block all present; stderr render in failure branch; retention notice in failure branch.
- Approve-phrase parser: must reject approve/reject phrases containing a DIFFERENT script_name. Existing I3 hardening (exact-match rule) preserved. ADD: accept `approve {name} confirm-stale` (Q4 staleness override) and `approve {name} confirm-{sha_prefix}` (Q3+Q6a fallback re-confirmation).

- [ ] **Step 1: Update frontmatter `tools:`**

In `plugins/screw/agents/screw-sqli.md`, find the `tools:` frontmatter field and ADD (maintaining existing entries):

```yaml
tools:
  # ... existing entries preserved ...
  - mcp__screw-agents__stage_adaptive_script
  - mcp__screw-agents__promote_staged_script
  - mcp__screw-agents__reject_staged_script
  # REMOVE (no longer used by subagent):
  # - mcp__screw-agents__sign_adaptive_script
```

`sign_adaptive_script` MUST be absent from the tools list — format-smoke test will enforce this.

- [ ] **Step 2: Rewrite Step 3.5d (the adaptive-mode generate + review section)**

Locate the current `### Step 3.5d — Generate adaptive script for this gap` subsection (around lines 161-450 of sqli.md post-PR #5). REPLACE with the staging-architecture version below.

The rewrite is extensive (~300 lines of prompt). Key sub-steps after the rewrite:

- **3.5d-A**: pick next gap + check `adaptive_prompts.json` for `declined` set (unchanged)
- **3.5d-B**: derive `script_name = f"{agent_part}-{file_slug}-{line_part}-{hash6}"` (unchanged; `hash6 = sha256(source_generated)[:6]`)
- **3.5d-C**: GENERATION PROMPT (apply I5 hardening): "You MUST import ONLY from this list of 18 functions: [enumerate all 18 names]. Any import of a name NOT in this list is a HARD FAIL. DO NOT invent helper names like `read_source`, `parse_module`, `walk_module` — [examples of correct alternatives]."
- **3.5d-D**: LLM generation + syntax check (unchanged)
- **3.5d-E**: `lint_adaptive_script(source)` (I2 will now catch unknown-symbol hallucinations; preserve the "informative, not blocking" framing)
- **3.5d-F**: `Task(subagent_type="screw:screw-script-reviewer", ...)` (I1: plugin-namespace prefix)
- **3.5d-G**: **NEW — STAGING**. Call `stage_adaptive_script(project_root, script_name, source, meta, session_id, target_gap)`. Capture `stage_response.script_sha256_prefix` + `stage_response.session_id_short`. If error, abort gap (same as T18b's existing regenerate-once policy; staging errors are rare — permission/collision).
- **3.5d-H**: **REWRITTEN — 5-SECTION REVIEW**. New header format:
  ```
  Script: {script_name}
  Staged: {staged_at_iso}  |  Session: {session_id_short}  |  SHA256: {sha_prefix}
  ```
  Sections 1-4 unchanged structurally; Section 4 label updated: `### 4. Script content (sha256 prefix {sha_prefix})`.
  Section 5 updated:
  ```
  Type `approve {script_name}` to sign and execute.
  Type `reject {script_name} <optional reason>` to discard.

  If the staging is stale (>24h old), you'll be prompted to use:
    `approve {script_name} confirm-stale`
  If the staging registry is missing, you'll be prompted to use:
    `approve {script_name} confirm-<sha_prefix>`
  ```
- **3.5d-I (was 3.5d-H approve)**: **REWRITTEN** — `promote_staged_script(project_root, script_name, session_id, confirm_stale?, confirm_sha_prefix?)` (NOT sign_adaptive_script). Parse approval phrase: if suffix `confirm-stale` → `confirm_stale=True`; if suffix `confirm-<8hex>` → `confirm_sha_prefix=<8hex>`. Handle each error code: `staging_not_found` (re-run scan), `tamper_detected` (loudly surface + abort gap), `stale_staging` (re-prompt with confirm-stale), `fallback_required` (re-prompt with confirm-<prefix>), `fallback_sha_mismatch` (re-run scan).
- **3.5d-J (was 3.5d-I reject)**: **REWRITTEN** — `reject_staged_script(project_root, script_name, session_id, reason)` (NOT manual file deletion). Idempotent; `status:already_rejected` is success.
- **3.5d-K (was 3.5d-H execute)**: **UNCHANGED + I3** — `execute_adaptive_script(project_root, script_name, wall_clock_s=30)`. On returncode != 0: render `result["stderr"]` in a fenced block. Add I4 retention notice: "Script retained at `.screw/custom-scripts/{script_name}.py` for inspection. Run `/screw:adaptive-cleanup remove {script_name}` to clear it."

**Concrete patch — NEW Step 3.5d-G (STAGE) prompt text:**

```markdown
##### G. Stage the script for human review

Before presenting the 5-section review, STAGE the generated script so that
the approval flow reads the exact bytes you generated (no regeneration after
respawn). Use:

\`\`\`json
{
  "tool": "stage_adaptive_script",
  "arguments": {
    "project_root": "{project_root_abs}",
    "script_name": "{script_name}",
    "source": "{exact source string from step D}",
    "meta": {
      "name": "{script_name}",
      "created": "{iso_timestamp}",
      "created_by": "{reviewer_email}",
      "domain": "injection-input-handling",
      "description": "{one-line rationale from the gap}",
      "target_patterns": [{inferred target patterns}]
    },
    "session_id": "{session_id from record_context_required_match / accumulate}",
    "target_gap": {
      "type": "{gap.type}",
      "file": "{gap.file}",
      "line": {gap.line},
      "agent": "sqli"
    }
  }
}
\`\`\`

Expected response on success:
\`\`\`json
{
  "status": "staged",
  "script_name": "{script_name}",
  "stage_path": "/abs/.../.screw/staging/{session_id}/adaptive-scripts/{script_name}.py",
  "script_sha256": "<64-char hex>",
  "script_sha256_prefix": "<8-char>",
  "session_id": "{session_id}",
  "session_id_short": "{first 12 chars}"
}
\`\`\`

Capture `script_sha256_prefix` and `session_id_short` for the review header.
If `status == "error"`:
- `invalid_script_name`: abort this gap with the reported message.
- `invalid_session_id`: critical bug in your previous step; abort entire adaptive flow and surface to user.
- `stage_name_collision`: rare; the existing stage has DIFFERENT content. Regenerate the script from scratch (retry-once policy) then re-stage.
```

**Concrete patch — NEW Step 3.5d-H (REVIEW) header:**

```markdown
##### H. Present the 5-section review to the human

Compose a SINGLE markdown message with the following header and five sections.
The header carries the trust-relevant metadata from the stage response — the
user can visually verify the session and sha prefix match what they expect.

\`\`\`markdown
# Adaptive analysis script ready for your review

**Script:** \`{script_name}\`
**Staged:** {staged_at_iso}  |  **Session:** \`{session_id_short}\`  |  **SHA256:** \`{script_sha256_prefix}\`

### 1. Rationale

{one-paragraph explanation: why this script, which gap it targets,
 what the expected outcome is if findings are produced}

### 2. Semantic reviewer report (Layer 0d)

{render the SemanticReviewReport JSON from step F — risk_score, flagged_patterns,
 unusual_imports, control_flow_summary, estimated_runtime_ms}

### 3. AST lint result (Layer 1)

{pass | fail with violations enumerated; include rule + message per violation}

### 4. Script content (sha256 prefix \`{script_sha256_prefix}\`)

\`\`\`python
{source verbatim from step D}
\`\`\`

### 5. Your decision

Type \`approve {script_name}\` to sign, promote, and execute the script above.

Type \`reject {script_name} <optional reason>\` to discard it without signing.

(If you step away for >24h and come back, you'll be prompted to confirm the
staging isn't stale. If the approval registry has been lost, you'll be
prompted to re-confirm the sha prefix \`{script_sha256_prefix}\`.)
\`\`\`

**Then END your turn.** The main Claude Code session will show your review
to the user and, after they type their approval or rejection, respawn you
with the approval context. Do NOT continue to the execute step in this turn.
```

**Concrete patch — NEW Step 3.5d-I (RESUME → PROMOTE) prompt text:**

```markdown
##### I. On approve `{script_name}` [resume-from-approval branch]

This branch runs when the main session respawns you with an approval phrase.
The staging was written by a PRIOR turn of this subagent — the exact source
is on disk. You do NOT regenerate; you promote.

Parse the approval phrase:
- Bare: \`approve {script_name}\` → normal promote
- \`approve {script_name} confirm-stale\` → \`confirm_stale: true\`
- \`approve {script_name} confirm-{8hex}\` → \`confirm_sha_prefix: "{8hex}"\`

Look up the session_id by reading \`.screw/local/pending-approvals.jsonl\`:
find the MOST-RECENT entry where \`script_name == {script_name}\` and \`event == staged\`.
The entry's \`session_id\` field is what you pass below.

If the registry file is missing or the lookup returns nothing, and the user
did NOT include \`confirm-<prefix>\`, the promote tool will return
\`fallback_required\` — surface that error to the user with the recovered
prefix, and stop. The user re-approves with the prefix in hand.

Call \`promote_staged_script\`:

\`\`\`json
{
  "tool": "promote_staged_script",
  "arguments": {
    "project_root": "{project_root_abs}",
    "script_name": "{script_name}",
    "session_id": "{session_id from registry lookup}",
    "confirm_stale": {true | false},
    "confirm_sha_prefix": {"<8hex>" | null}
  }
}
\`\`\`

Expected success:
\`\`\`json
{
  "status": "signed",
  "script_name": "{script_name}",
  "script_path": "/abs/.../.screw/custom-scripts/{script_name}.py",
  "meta_path": "/abs/.../.screw/custom-scripts/{script_name}.meta.yaml",
  "signed_by": "{reviewer_email}",
  "sha256": "{64-char}",
  "session_id": "{session_id}",
  "promoted_via_fallback": false
}
\`\`\`

Error handling:
- \`staging_not_found\`: the staging was cleaned up or the script_name/session_id
  combination never staged. Surface: "The staged approval for \`{script_name}\`
  was not found. Please re-run the scan." Abort this gap.
- \`tamper_detected\`: LOUDLY SURFACE. The sha256 of the staged file does NOT
  match what was recorded at stage time. Render the tool's message
  verbatim (it names the expected vs actual sha prefixes and the evidence
  path). Abort this gap. Do NOT attempt to retry. The user must re-run.
- \`stale_staging\`: staging is >24h old. Re-prompt the user: "The staging
  for \`{script_name}\` is {hours_old}h old (threshold {threshold_hours}h).
  If you still want to proceed, type: \`approve {script_name} confirm-stale\`.
  Otherwise, re-run the scan for a fresh review."
- \`fallback_required\`: registry missing. Re-prompt: "The approval registry
  was not found. The staged file's sha256 prefix is \`{recovered_prefix}\`.
  Re-type: \`approve {script_name} confirm-{recovered_prefix}\` to proceed,
  or re-run the scan."
- \`fallback_sha_mismatch\`: prefix in phrase doesn't match recovered.
  Surface: "The confirmation prefix you typed does not match the staged
  file. Please re-run the scan." Abort.
- \`invalid_lifecycle_state\`: defensive — the most-recent registry event
  for this script_name is not \`staged\`. Surface verbatim; abort.
- \`custom_scripts_collision\`: a signed script with this name already
  exists. Surface and abort (name collisions in our content-binding scheme
  require the exact source already signed, so this is a rare re-stage
  edge case).

After successful promote, continue to step K (execute).
```

**Concrete patch — NEW Step 3.5d-J (RESUME → REJECT) prompt text:**

```markdown
##### J. On reject `{script_name} <optional reason>` [resume-from-rejection branch]

Parse the rejection phrase; extract optional free-text reason after the
script_name.

Look up session_id as in step I (registry MOST-RECENT staged event).

Call \`reject_staged_script\`:

\`\`\`json
{
  "tool": "reject_staged_script",
  "arguments": {
    "project_root": "{project_root_abs}",
    "script_name": "{script_name}",
    "session_id": "{session_id}",
    "reason": "{free-text reason or null}"
  }
}
\`\`\`

Success: \`status == "rejected"\` or \`status == "already_rejected"\`
(both are acceptable; the reject tool is idempotent).

After reject, continue to the next gap OR finalize.
```

**Concrete patch — NEW Step 3.5d-K (EXECUTE) failure branch (I3 + I4):**

```markdown
##### K. Execute the signed script

Call \`execute_adaptive_script(project_root, script_name, wall_clock_s=30)\`
(note: no session_id per T18a Deviation 1).

On success (status == "ok" or returncode == 0), findings are in \`result["findings"]\`.
Accumulate them into this scan's session, then proceed to next gap / finalize.

On failure (returncode != 0 or status == "error"):

Render the failure diagnostic for the user:
\`\`\`markdown
**Adaptive script \`{script_name}\` execution failed**

Return code: {returncode}
Wall clock: {wall_clock_s}s
Killed by timeout: {killed_by_timeout}

Standard error output:
\`\`\`
{result["stderr"]}
\`\`\`

The script is retained at \`.screw/custom-scripts/{script_name}.py\` for your
inspection. Run \`/screw:adaptive-cleanup remove {script_name}\` to clear it.
\`\`\`

Proceed to next gap (do NOT abort the entire adaptive flow on a single
script failure; other gaps may succeed).
```

- [ ] **Step 3: Regenerate the expected byte-identical section for T16**

After step 2 is complete, the Step 3.5d section of screw-sqli.md is the canonical version. Copy its full text (from `##### A.` through `##### K.`) to a scratch file for use in T16.

- [ ] **Step 4: Run existing subagent-prompt tests to verify frontmatter + section still structurally valid**

Run: `uv run pytest tests/test_adaptive_subagent_prompts.py -v`
Expected: existing tests PASS (byte-identity test will FAIL until T16 lands; that's expected — run with `-k "not identical"` for now).

Run: `uv run pytest tests/test_adaptive_subagent_prompts.py -v -k "not identical"`
Expected: all non-byte-identity tests PASS.

- [ ] **Step 5: Commit (partial — byte-identity test broken until T16)**

```bash
git add plugins/screw/agents/screw-sqli.md
git commit -m "feat(phase3b-c1): rewrite screw-sqli.md Step 3.5d with staging flow (T15, C1+I1+I4+I5)"
```

**Cross-plan sync:** spec §3.1-§3.3 prompt-side expectations verified. Note any deviation (e.g., if the approval-phrase parser ends up more permissive than specified) and update spec or this plan accordingly.

---

### Task 16: Byte-Identical Copy to cmdi/ssti/xss Subagents

**Files:**
- Modify: `plugins/screw/agents/screw-cmdi.md`
- Modify: `plugins/screw/agents/screw-ssti.md`
- Modify: `plugins/screw/agents/screw-xss.md`

- [ ] **Step 1: For each of cmdi, ssti, xss — copy sqli's Step 3.5d verbatim + frontmatter changes**

Per-agent substitutions ONLY (NO other differences allowed — byte-identity test enforces this):
- `sqli` → `cmdi` / `ssti` / `xss` (agent name in target_gap's `agent` field, in the domain string only if different — check)
- The `domain` field: sqli uses `injection-input-handling`; cmdi/ssti/xss use the same (all in injection domain)
- The `{agent_part}` variable in the script_name derivation section: `"sqli"` → `"cmdi"` / `"ssti"` / `"xss"`

For each file, do the following:

1. Read sqli's current Step 3.5d section (from `##### A.` through `##### K.`).
2. Replace occurrences of `sqli` with the target agent name (case-sensitive exact match).
3. Paste into the target agent's file, replacing the existing Step 3.5d section.
4. Update `tools:` frontmatter same as T15.

- [ ] **Step 2: Verify byte-identity test passes**

Run: `uv run pytest tests/test_adaptive_subagent_prompts.py::test_adaptive_section_identical_modulo_agent_name -v`
Expected: PASS (the existing test should accept the new content as long as the agent-name substitution is the only difference).

- [ ] **Step 3: Run full subagent-prompt tests**

Run: `uv run pytest tests/test_adaptive_subagent_prompts.py -v`
Expected: all PASS (byte-identity + existing structural tests; new format-smoke assertions are T20).

- [ ] **Step 4: Full suite**

Run: `uv run pytest -q`
Expected: 821 passed.

- [ ] **Step 5: Commit**

```bash
git add plugins/screw/agents/screw-cmdi.md \
        plugins/screw/agents/screw-ssti.md \
        plugins/screw/agents/screw-xss.md
git commit -m "feat(phase3b-c1): copy Step 3.5d staging section to cmdi/ssti/xss subagents (T16)"
```

---

### Task 17: Orchestrator Update — `screw-injection.md`

**Files:**
- Modify: `plugins/screw/agents/screw-injection.md` (update step-ID references if any changed in T15)

**Rationale:** The injection orchestrator's Step 2.5 shared-quota logic references per-agent Step 3.5d by ID. If T15 introduced new sub-step IDs (3.5d-G, -I, -J), update the cross-references.

- [ ] **Step 1: Diff current orchestrator references against new per-agent IDs**

Run: `grep -n "3\.5d" plugins/screw/agents/screw-injection.md`

Compare to the new per-agent IDs from T15/T16. For any `3.5d-H` references that now mean something different (old H = review, new H = review; old H=promote is now I; etc.), update.

- [ ] **Step 2: Apply minimal updates**

This task is primarily verification. If T15's sub-step renaming requires orchestrator updates, apply them minimally — do NOT restructure the orchestrator's logic. Orchestrator's share-quota behavior is unchanged.

- [ ] **Step 3: Run tests to verify orchestrator's format-smoke checks still pass**

Run: `uv run pytest tests/test_adaptive_subagent_prompts.py -v -k "orchestrator or injection"`
Expected: PASS.

- [ ] **Step 4: Commit (if changes were made)**

```bash
git add plugins/screw/agents/screw-injection.md
git commit -m "feat(phase3b-c1): orchestrator refs updated for new T18b sub-step IDs (T17)"
```

If no changes were needed: skip the commit; move on to T18.

---

### Task 18: Minor Update to `plugins/screw/commands/scan.md`

**Files:**
- Modify: `plugins/screw/commands/scan.md` (document staging conceptually)

- [ ] **Step 1: Add a short "Staging" paragraph near the `--adaptive` flag section**

Add approximately:

```markdown
### Adaptive mode: staging and approval

When \`--adaptive\` is passed, each generated analysis script is first
*staged* to \`.screw/staging/{session_id}/adaptive-scripts/\` before the
human-review step. Your approval phrase is matched against the staged
file on disk — so the exact bytes you reviewed are the exact bytes that
get signed and executed. The approval flow never re-generates the script
after you've seen it.

If you walk away from a review for more than 24h, you'll be prompted to
re-confirm with \`approve <name> confirm-stale\`. If the local approval
registry at \`.screw/local/pending-approvals.jsonl\` has been lost, you'll
be prompted to re-confirm the sha256 prefix with
\`approve <name> confirm-<8hex>\`. Both flows produce audit events in the
registry for post-hoc inspection.

Orphaned stagings (scans you never approved/rejected) are collected by
\`/screw:adaptive-cleanup stale\` at the default 14-day threshold.
```

- [ ] **Step 2: Commit**

```bash
git add plugins/screw/commands/scan.md
git commit -m "docs(phase3b-c1): scan.md documents adaptive staging flow (T18)"
```

---

## Phase F — Slash Command + Format-Smoke (T19-T20)

### Task 19: Rewrite `plugins/screw/commands/adaptive-cleanup.md`

**Files:**
- Modify: `plugins/screw/commands/adaptive-cleanup.md`

**Rationale:** I6 fix. Replace `uv run python -c` Bash blocks with MCP tool invocations. Add `stale` subcommand per Q5c / spec §3.4.

- [ ] **Step 1: Rewrite file with three actions: list, remove, stale**

Replace the existing `list` + `remove` Bash blocks with MCP tool call blocks. Add new `stale` subcommand.

Skeleton:

```markdown
---
description: Inspect and clean up adaptive analysis scripts (list, remove, stale sweep)
---

# /screw:adaptive-cleanup

## Actions

### \`list\` — show all adaptive scripts

Use the MCP tool \`list_adaptive_scripts\`:

\`\`\`json
{
  "tool": "list_adaptive_scripts",
  "arguments": {"project_root": "{abs path of current project}"}
}
\`\`\`

Render the response as a table with columns: Name, Signed By, Stale.
For stale scripts, show the \`stale_reason\` on the next indented line.

If no scripts, render: "No adaptive scripts present in \`.screw/custom-scripts/\`."

### \`remove <name>\` — delete one adaptive script pair

1. Confirm with the user: "Remove \`{name}\` from .screw/custom-scripts/? Type 'yes' to confirm."
2. On user typing exactly 'yes':

\`\`\`json
{
  "tool": "remove_adaptive_script",
  "arguments": {"project_root": "{abs path}", "script_name": "{name}", "confirmed": true}
}
\`\`\`

3. Render result.

### \`stale [--max-age-days N] [--preview]\` — sweep stale staging artifacts

For inspecting + cleaning the \`.screw/staging/\` directory tree. Removes
orphaned staging entries from scans that were never approved/rejected, plus
post-promote/reject residue.

Call:

\`\`\`json
{
  "tool": "sweep_stale_staging",
  "arguments": {
    "project_root": "{abs path}",
    "max_age_days": {N if provided; else null (uses config default 14)},
    "dry_run": {true if --preview else false}
  }
}
\`\`\`

Render report: sessions scanned / removed, scripts removed (with reason + age),
tampered-preserved (with evidence path). For --preview, add a note that no
filesystem changes were made.
```

- [ ] **Step 2: Verify no residual `uv run python -c` in the file**

Run: `grep "uv run" plugins/screw/commands/adaptive-cleanup.md`
Expected: 0 matches (full cut-over to MCP tools).

Run: `grep "cli.adaptive_cleanup" plugins/screw/commands/adaptive-cleanup.md`
Expected: 0 matches (old import pattern gone).

- [ ] **Step 3: Commit**

```bash
git add plugins/screw/commands/adaptive-cleanup.md
git commit -m "feat(phase3b-c1): rewrite adaptive-cleanup slash cmd to use MCP tools (T19, I6)"
```

---

### Task 20: Format-Smoke Test Extensions

**Files:**
- Modify: `tests/test_adaptive_subagent_prompts.py` (+12 new assertions)

**Rationale:** The test is the load-bearing lock on the prompt-side trust isolation. These assertions catch any future regression where a subagent prompt reintroduces `sign_adaptive_script` or drops the I5 hardening.

- [ ] **Step 1: Add 12 assertions**

In `tests/test_adaptive_subagent_prompts.py`:

```python
# Each per-agent file:
PER_AGENT_FILES = [
    "plugins/screw/agents/screw-sqli.md",
    "plugins/screw/agents/screw-cmdi.md",
    "plugins/screw/agents/screw-ssti.md",
    "plugins/screw/agents/screw-xss.md",
]


def _read_agent(filename: str) -> str:
    return Path(filename).read_text(encoding="utf-8")


@pytest.mark.parametrize("filename", PER_AGENT_FILES)
def test_prompt_contains_stage_adaptive_script(filename: str) -> None:
    assert "stage_adaptive_script" in _read_agent(filename), (
        f"{filename} missing stage_adaptive_script reference — C1 fix regressed"
    )


@pytest.mark.parametrize("filename", PER_AGENT_FILES)
def test_prompt_contains_promote_staged_script(filename: str) -> None:
    assert "promote_staged_script" in _read_agent(filename), (
        f"{filename} missing promote_staged_script reference"
    )


@pytest.mark.parametrize("filename", PER_AGENT_FILES)
def test_prompt_contains_reject_staged_script(filename: str) -> None:
    assert "reject_staged_script" in _read_agent(filename), (
        f"{filename} missing reject_staged_script reference"
    )


@pytest.mark.parametrize("filename", PER_AGENT_FILES)
def test_prompt_does_not_reference_sign_adaptive_script(filename: str) -> None:
    """Option D isolation: LLM flow must NEVER reach sign_adaptive_script
    (the direct-path tool). If this test fails, the C1 regeneration-surface
    closure has regressed."""
    content = _read_agent(filename)
    assert "sign_adaptive_script" not in content, (
        f"{filename} references sign_adaptive_script — LLM-flow isolation "
        f"regressed. Use stage + promote instead (spec §3.2)."
    )


@pytest.mark.parametrize("filename", PER_AGENT_FILES)
def test_prompt_uses_plugin_namespaced_reviewer(filename: str) -> None:
    """I1: subagent_type MUST be the plugin-namespaced form."""
    content = _read_agent(filename)
    assert "screw:screw-script-reviewer" in content, (
        f"{filename} missing plugin-namespaced reviewer name (I1)"
    )


@pytest.mark.parametrize("filename", PER_AGENT_FILES)
def test_prompt_does_not_use_bare_reviewer_name(filename: str) -> None:
    """I1 negative: the bare form (without plugin prefix) must not appear."""
    content = _read_agent(filename)
    # The bare name could legitimately appear as part of the namespaced one;
    # search for contexts that clearly refer to a subagent_type value.
    import re
    bare_refs = re.findall(r"subagent_type['\": ]+\s*\"screw-script-reviewer\"", content)
    assert not bare_refs, (
        f"{filename} uses bare screw-script-reviewer as subagent_type (I1 regressed)"
    )


@pytest.mark.parametrize("filename", PER_AGENT_FILES)
def test_prompt_contains_must_import_only_phrase(filename: str) -> None:
    """I5: prompt enforces the allowlist loudly."""
    content = _read_agent(filename)
    assert "MUST import ONLY" in content, (
        f"{filename} missing 'MUST import ONLY' hardening phrase (I5)"
    )


@pytest.mark.parametrize("filename", PER_AGENT_FILES)
def test_prompt_lists_all_18_adaptive_exports(filename: str) -> None:
    """I5: every name in adaptive.__all__ must appear in the generation prompt."""
    from screw_agents import adaptive as adaptive_pkg
    content = _read_agent(filename)
    for name in adaptive_pkg.__all__:
        assert name in content, (
            f"{filename} missing adaptive.__all__ entry {name!r} in prompt (I5)"
        )


@pytest.mark.parametrize("filename", PER_AGENT_FILES)
def test_prompt_contains_negative_examples_block(filename: str) -> None:
    """I5: negative examples mention common hallucinated names."""
    content = _read_agent(filename)
    assert "DO NOT invent helper names" in content
    for hallucinated in ("read_source", "parse_module", "walk_module"):
        assert hallucinated in content, (
            f"{filename} missing hallucinated name example {hallucinated!r} (I5)"
        )


@pytest.mark.parametrize("filename", PER_AGENT_FILES)
def test_prompt_contains_stderr_render_on_failure(filename: str) -> None:
    """I3: execute-failure branch renders stderr in a fenced block."""
    content = _read_agent(filename)
    assert "Standard error output" in content, (
        f"{filename} missing stderr render in failure branch (I3)"
    )


@pytest.mark.parametrize("filename", PER_AGENT_FILES)
def test_prompt_contains_retention_notice(filename: str) -> None:
    """I4: retention notice on execute failure."""
    content = _read_agent(filename)
    assert "retained at" in content and "adaptive-cleanup remove" in content, (
        f"{filename} missing retention notice (I4)"
    )


@pytest.mark.parametrize("filename", PER_AGENT_FILES)
def test_prompt_displays_sha256_prefix_in_review_header(filename: str) -> None:
    """C1 UX: the 5-section review header surfaces the staged sha prefix."""
    content = _read_agent(filename)
    assert "SHA256" in content or "script_sha256_prefix" in content, (
        f"{filename} missing sha256 prefix in review header (C1 UX)"
    )
```

- [ ] **Step 2: Run — verify all 12 × 4 = 48 parametrized cases pass**

Run: `uv run pytest tests/test_adaptive_subagent_prompts.py -v`
Expected: all existing + 48 new assertions PASS.

Total test count delta from format-smoke: +48 parametrized (pytest counts each parametrize instance as 1 test). But the PR #6 test projection counted each assertion once (12) — the delta is actually 48, not 12.

**Plan-sync note:** update exit checklist if tests exceed 820 target. Adjust to "at least 820" or update the count. Likely final count: 820 + 36 = 856 (since +12 format-smoke × 4 files = 48; baseline +20 staging + 5 signing + 4 lint + 6 executor + 1 ast_walker + 1 integration + 48 format-smoke = ~85 new tests). That's more than the spec projected (+49). Accept the difference; spec's count was approximate.

- [ ] **Step 3: Full suite**

Run: `uv run pytest -q`
Expected: ~869 passed (exact count depends on parametrize vs per-test accounting).

- [ ] **Step 4: Commit**

```bash
git add tests/test_adaptive_subagent_prompts.py
git commit -m "test(phase3b-c1): 12 format-smoke assertions for T18b prompt rewrite (T20)"
```

---

## Phase G — Integration + Schema Hygiene (T21-T22)

### Task 21: New Integration Test — `tests/test_adaptive_workflow_staged.py`

**Files:**
- Create: `tests/test_adaptive_workflow_staged.py`

**Rationale:** The C1 exit gate. One test that composes every MCP tool shipped in T3-T20 in the exact order a real subagent would run them, asserting the C1 invariant at the signing step (`signed_py.read_text() == staged_source`).

- [ ] **Step 1: Write the composition test**

```python
"""End-to-end integration test for the PR #6 staged adaptive-workflow.

Mirrors tests/test_adaptive_workflow.py (T22) but substitutes the staging
flow (stage → review → approve → promote) for the direct sign_adaptive_script
path. Asserts the C1 invariant: the source bytes seen at stage time are
byte-identical to the signed artifact at custom-scripts/ post-promote.

If this test breaks, the C1 architectural closure has regressed — the
regeneration-after-approval vulnerability may have reopened.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest


pytestmark = pytest.mark.skipif(
    shutil.which("bwrap") is None and shutil.which("sandbox-exec") is None,
    reason="adaptive workflow requires bwrap (Linux) or sandbox-exec (macOS)",
)


def test_full_adaptive_workflow_with_staging_composition(tmp_path: Path) -> None:
    """PR #6 exit gate: full composition with stage → promote substituting
    for direct sign.

    The 13 steps mirror T22's composition order (identical seed fixture,
    identical YAML finding, identical adaptive script, identical gap-signal
    expectations); only the signing step is different.

    Breakage diagnosis: the FIRST failing assertion pins the regressing
    integration boundary. If Step 12's invariant fails
    (`signed_py.read_text() == source`), C1 has regressed — do not merge.
    """
    from screw_agents.adaptive.signing import compute_script_sha256
    from screw_agents.adaptive.staging import resolve_registry_path
    from screw_agents.cli.init_trust import run_init_trust
    from screw_agents.engine import ScanEngine

    # Step 1: Seed project (IDENTICAL to T22).
    project = tmp_path / "project"
    project.mkdir()
    fixture_file = project / "dao.py"
    fixture_file.write_text(
        "# Fixture for PR #6 full-composition E2E test\n"
        "class QueryBuilder:\n"
        "    def execute_raw(self, sql):\n"
        "        pass\n"
        "\n"
        "def handle(request):\n"
        "    q = request.args.get('q')\n"
        "    # D1 — context_required drop:\n"
        "    cursor.execute(q)\n"
        "    # D2 — qb not in known_receivers, tainted arg:\n"
        "    self.qb.execute_raw(q)\n"
        "    # Adaptive target + YAML merge alignment:\n"
        "    QueryBuilder().execute_raw(q)\n"
    )

    # Step 2: init-trust (IDENTICAL).
    run_init_trust(
        project_root=project, name="C1 Tester", email="c1@example.com",
    )
    engine = ScanEngine.from_defaults()

    # Step 3: record_context_required_match (IDENTICAL).
    match_response = engine.record_context_required_match(
        project_root=project,
        match={"agent": "sqli", "file": "dao.py", "line": 9, "pattern": "any-raw-method-check"},
        session_id=None,
    )
    session_id = match_response["session_id"]

    # Step 4: accumulate_findings — YAML finding (IDENTICAL).
    yaml_finding = {
        "id": "sqli-001",
        "agent": "sqli",
        "domain": "injection-input-handling",
        "timestamp": "2026-04-20T10:00:00Z",
        "location": {"file": "dao.py", "line_start": 13, "line_end": 13},
        "classification": {
            "cwe": "CWE-89", "cwe_name": "SQL Injection",
            "severity": "high", "confidence": "medium",
        },
        "analysis": {"description": "YAML detection"},
        "remediation": {"recommendation": "use parameterized queries"},
    }
    engine.accumulate_findings(
        project_root=project, findings_chunk=[yaml_finding], session_id=session_id,
    )

    # Step 5: detect_coverage_gaps (IDENTICAL).
    gaps = engine.detect_coverage_gaps(
        agent_name="sqli", project_root=project, session_id=session_id,
    )
    assert len(gaps) >= 1

    # Step 6: Hand-write adaptive script source (IDENTICAL).
    script_source = (
        "from screw_agents.adaptive import emit_finding, find_calls\n"
        "\n"
        "def analyze(project):\n"
        "    for call in find_calls(project, 'QueryBuilder.execute_raw'):\n"
        "        emit_finding(\n"
        "            cwe='CWE-89',\n"
        "            file=call.file,\n"
        "            line=call.line,\n"
        "            message='QueryBuilder.execute_raw sink (adaptive)',\n"
        "            severity='high',\n"
        "        )\n"
    )

    # Step 7: Layer 1 lint (IDENTICAL).
    lint_result = engine.lint_adaptive_script(source=script_source)
    assert lint_result["status"] == "pass"

    # Step 8: **NEW — stage_adaptive_script** (replaces T22's direct sign).
    meta = {
        "name": "qb-check",
        "created": "2026-04-20T10:00:00Z",
        "created_by": "c1@example.com",
        "domain": "injection-input-handling",
        "description": "E2E fixture: QueryBuilder.execute_raw verifier",
        "target_patterns": ["QueryBuilder.execute_raw"],
    }
    stage_response = engine.stage_adaptive_script(
        project_root=project,
        script_name="qb-check",
        source=script_source,
        meta=meta,
        session_id=session_id,
        target_gap={"type": "unresolved_sink", "file": "dao.py", "line": 13, "agent": "sqli"},
    )
    assert stage_response["status"] == "staged"
    assert stage_response["script_sha256"] == compute_script_sha256(script_source)

    # Step 9: Verify staging file exists AND has exact source.
    stage_py = project / ".screw" / "staging" / session_id / "adaptive-scripts" / "qb-check.py"
    assert stage_py.exists()
    assert stage_py.read_text(encoding="utf-8") == script_source

    # Step 10: Verify registry entry exists with correct sha.
    registry = resolve_registry_path(project)
    entries = [json.loads(l) for l in registry.read_text().splitlines() if l.strip()]
    staged_entries = [e for e in entries if e["event"] == "staged" and e["script_name"] == "qb-check"]
    assert len(staged_entries) == 1
    assert staged_entries[0]["script_sha256"] == stage_response["script_sha256"]

    # Step 11: **NEW — promote_staged_script** (the C1 fix).
    promote_response = engine.promote_staged_script(
        project_root=project, script_name="qb-check", session_id=session_id,
    )
    assert promote_response["status"] == "signed"
    assert promote_response["signed_by"] == "c1@example.com"
    assert promote_response["promoted_via_fallback"] is False

    # Step 12: **★ C1 INVARIANT LOCK ★** — signed source == staged source == hand-written source.
    signed_py = project / ".screw" / "custom-scripts" / "qb-check.py"
    assert signed_py.exists()
    signed_content = signed_py.read_text(encoding="utf-8")
    assert signed_content == script_source, (
        "C1 INVARIANT VIOLATED: signed source bytes do NOT match "
        "hand-written staged source. The regeneration-after-approval "
        "vulnerability has reopened. DO NOT MERGE."
    )

    # Step 13: Staging files deleted; registry has 'promoted' event.
    assert not stage_py.exists()
    promoted_entries = [
        e for e in (json.loads(l) for l in registry.read_text().splitlines() if l.strip())
        if e["event"] == "promoted" and e["script_name"] == "qb-check"
    ]
    assert len(promoted_entries) == 1

    # Step 14: execute_adaptive_script (UNCHANGED from T22).
    exec_result = engine.execute_adaptive_script(
        project_root=project, script_name="qb-check", wall_clock_s=30,
    )
    assert exec_result["stale"] is False
    assert len(exec_result["findings"]) >= 1
    adaptive_finding = exec_result["findings"][0]
    assert adaptive_finding["location"]["file"] == "dao.py"
    assert adaptive_finding["location"]["line_start"] == 13
    assert adaptive_finding["classification"]["cwe"] == "CWE-89"
    assert adaptive_finding["agent"] == "adaptive_script:qb-check"

    # Step 15: Accumulate adaptive findings (IDENTICAL to T22).
    engine.accumulate_findings(
        project_root=project,
        findings_chunk=exec_result["findings"],
        session_id=session_id,
    )

    # Step 16: finalize_scan_results with coverage_gaps + T19 Sources line.
    finalize_response = engine.finalize_scan_results(
        project_root=project,
        session_id=session_id,
        agent_names=["sqli"],
        scan_metadata={"target": "dao.py", "timestamp": "2026-04-20T10:00:00Z"},
    )
    assert "coverage_gaps" in finalize_response
    md_path = Path(finalize_response["files_written"]["markdown"])
    md = md_path.read_text(encoding="utf-8")
    assert "**Sources:**" in md
    assert md.count("**Sources:**") == 1
    sources_line = next(l for l in md.splitlines() if "**Sources:**" in l)
    assert "sqli" in sources_line
    assert "adaptive_script:qb-check" in sources_line
    assert finalize_response["summary"]["total"] == 1

    # Step 17: verify_trust — script active (T20 regression still holds).
    trust_status = engine.verify_trust(project_root=project)
    assert trust_status["script_active_count"] == 1
    assert trust_status["script_quarantine_count"] == 0

    # Step 18: list_adaptive_scripts (I6 migration: engine method, not CLI).
    list_response = engine.list_adaptive_scripts(project_root=project)
    scripts = list_response["scripts"]
    assert len(scripts) == 1
    qb = scripts[0]
    assert qb["name"] == "qb-check"
    assert qb["validated"] is True
    assert qb["signed_by"] == "c1@example.com"
    assert qb["stale"] is False
```

- [ ] **Step 2: Run the integration test**

Run: `uv run pytest tests/test_adaptive_workflow_staged.py -v`
Expected: PASS.

- [ ] **Step 3: Run full suite**

Run: `uv run pytest -q`
Expected: ~870 passed (baseline 771 + ~85 from T1-T20 + 1 from T21).

- [ ] **Step 4: Commit**

```bash
git add tests/test_adaptive_workflow_staged.py
git commit -m "test(phase3b-c1): E2E integration test for staged workflow — C1 exit gate (T21)"
```

**Cross-plan sync:** the Step 12 invariant assertion is the LOAD-BEARING TEST FOR C1. If it ever flakes or needs loosening, stop. Investigate why. Do not relax it.

---

### Task 22: Apply `additionalProperties: false` Uniformly to 6 New MCP Tool Schemas (T10-M1 Partial)

**Files:**
- Modify: `src/screw_agents/engine.py` (verify all 6 new tool schemas in `list_tool_definitions` have the flag)
- Potentially: `tests/test_mcp_tool_schemas.py` or similar (if a schema-consistency test exists; add one if not)

**Rationale:** T10-M1 partial. Applied as tools are registered, but this task audits + adds a regression lock test.

**Pre-audit note (2026-04-21):** Tool schemas are hand-written as `tools.append({...})` blocks inside `engine.list_tool_definitions()` (starts at `engine.py:1211`). The server layer (`src/screw_agents/server.py`) uses a `_dispatch_tool` function with `if name == "tool_name":` branches — there are NO FastMCP `@mcp.tool()` decorators in this codebase. Any task guidance referencing decorators is stale; use the `list_tool_definitions` schema pattern instead.

- [ ] **Step 1: Locate the 6 new tool schemas in `engine.list_tool_definitions`**

Run: `grep -n 'tools.append({' src/screw_agents/engine.py | head -20`

This lists every hand-written tool schema block. For each of the 6 new-in-PR#6 tools (`stage_adaptive_script`, `promote_staged_script`, `reject_staged_script`, `sweep_stale_staging`, `list_adaptive_scripts`, `remove_adaptive_script`), confirm the schema block is present. Cross-check the corresponding `_dispatch_tool` branches in `server.py` (roughly `server.py:71-200`) — each dispatcher branch must have exactly one matching schema, and vice versa.

- [ ] **Step 2: Verify all 6 new tools have the flag**

For each of: `stage_adaptive_script`, `promote_staged_script`, `reject_staged_script`, `sweep_stale_staging`, `list_adaptive_scripts`, `remove_adaptive_script` — inspect the emitted schema (`input_schema.additionalProperties` should be `False`).

- [ ] **Step 3: Add a regression-lock test**

```python
# tests/test_mcp_tool_schemas.py (new file, or add to existing schema test)

def test_new_phase3b_pr6_tools_reject_additional_properties() -> None:
    """Lock T10-M1 partial: each new MCP tool introduced in PR #6 sets
    additionalProperties: false on its input schema.

    A future tool schema change that relaxes this invariant would regress
    T10-M1 discipline project-wide (the full audit remains deferred to PR #9).
    """
    from screw_agents.engine import ScanEngine

    engine = ScanEngine.from_defaults()
    tools = engine.list_tool_definitions()

    pr6_new_tools = {
        "stage_adaptive_script",
        "promote_staged_script",
        "reject_staged_script",
        "sweep_stale_staging",
        "list_adaptive_scripts",
        "remove_adaptive_script",
    }

    found = {t["name"] for t in tools if t["name"] in pr6_new_tools}
    assert found == pr6_new_tools, (
        f"Missing new PR #6 tools from tool definitions: {pr6_new_tools - found}"
    )

    for tool in tools:
        if tool["name"] in pr6_new_tools:
            schema = tool["input_schema"]
            assert schema.get("additionalProperties") is False, (
                f"Tool {tool['name']!r} input_schema missing "
                f"additionalProperties: false (T10-M1 partial regressed)"
            )
```

- [ ] **Step 4: Run test**

Run: `uv run pytest tests/test_mcp_tool_schemas.py -v`
Expected: PASS.

- [ ] **Step 5: Full suite**

Run: `uv run pytest -q`
Expected: +1 test from baseline.

- [ ] **Step 6: Commit**

```bash
git add src/screw_agents/server.py tests/test_mcp_tool_schemas.py
git commit -m "test(phase3b-c1): lock additionalProperties: false on new PR #6 tools (T22, T10-M1 partial)"
```

---

## Phase H — Docs + Plan Sync (T23-T24)

### Task 23: Sync `docs/PHASE_3B_PLAN.md` with PR #6 Section

**Files:**
- Modify: `docs/PHASE_3B_PLAN.md`

- [ ] **Step 1: Add a new top-level section after "PR #5 Exit Checklist"**

Structure:

```markdown
## PR #6: C1 Staging Architecture + I1-I6 Polish

> **SHIPPED NOTE (PR #6 complete, 2026-XX-XX):** [to be filled post-merge
> with commit SHA and a summary of shipped tasks T0-T27, test count delta,
> manual round-trip validation result.]

Scope: close the C1 trust-invariant violation surfaced by PR #5's
round-trip (approve path regenerated source after approval). Bundle I1-I6
polish items and 5 adjacent backlog items whose overlapping file sets
make single-PR delivery cleaner than separate ones. See
`docs/specs/2026-04-20-phase-3b-c1-staging-design.md` for the consolidated
design and `docs/PHASE_3B_C1_PLAN.md` for the task breakdown.

**Test count: 771 → 820+ (exact count TBD post-merge)**

### Task 0: Worktree setup
### Task 1: New adaptive/staging.py module
### Task 2: Extract _sign_script_bytes shared helper (Option D refactor)
### Task 3: stage_adaptive_script MCP tool
### Task 4: promote_staged_script MCP tool — the C1 fix
### Task 5: reject_staged_script MCP tool
### Task 6: sweep_stale_staging MCP tool (absorbs T-STAGING-ORPHAN-GC)
### Task 7: Promote list_adaptive_scripts to engine + MCP
### Task 8: Promote remove_adaptive_script to engine + MCP
### Task 9: Delete cli/adaptive_cleanup.py + migrate T22
### Task 10: I2 — lint validates adaptive.__all__ symbols
### Task 11: I3 — sandbox stderr surfacing
### Task 12: T11-N2 — MetadataError wrapper
### Task 13: T3-M1 — narrow exceptions in ast_walker
### Task 14: T11-N1 — E2E signature-path regression test
### Task 15: Rewrite screw-sqli.md Step 3.5d with staging flow
### Task 16: Copy Step 3.5d byte-identical to cmdi/ssti/xss
### Task 17: Orchestrator ref updates (screw-injection.md)
### Task 18: scan.md staging-flow docs
### Task 19: Rewrite /screw:adaptive-cleanup slash command
### Task 20: Format-smoke test extensions (+12 assertions × 4 files)
### Task 21: New integration test — tests/test_adaptive_workflow_staged.py
### Task 22: additionalProperties: false on new PR #6 tools (T10-M1 partial)
### Task 23: Cross-plan sync (this file update)
### Task 24: DEFERRED_BACKLOG updates (move Shipped, append BACKLOG-PR6-09..13 to existing 01..08)

## PR #6 Exit Checklist
[mirrors the Exit Checklist in PHASE_3B_C1_PLAN.md]
```

Each task gets a brief (3-5 line) summary mirroring the SHIPPED NOTE style used by PR #5's sections. Full detail stays in PHASE_3B_C1_PLAN.md.

- [ ] **Step 2: Commit**

```bash
git add docs/PHASE_3B_PLAN.md
git commit -m "sync(phase3b): add PR #6 section to PHASE_3B_PLAN (T23)"
```

---

### Task 24: Update `docs/DEFERRED_BACKLOG.md`

**Files:**
- Modify: `docs/DEFERRED_BACKLOG.md`

- [ ] **Step 1: Move C1 + I1-I6 to Shipped**

In the "Phase 3b PR #5 round-trip test findings" section, move entries to a new "Shipped (PR #6)" block. Example format:

```markdown
### C1 — CRITICAL: Human-approval flow regenerates script after approval (trust violation)
**Source:** Phase 3b PR #5 manual round-trip test, 2026-04-20
**Shipped in:** PR #6 (phase-3b-c1-staging), merge commit <SHA>
**Plan:** docs/PHASE_3B_C1_PLAN.md

Closed via staging architecture: promote_staged_script takes no source
parameter, reads staged bytes from disk, verifies sha256 against registry.
[2-3 line summary]
```

Repeat for I1, I2, I3, I4, I5, I6.

- [ ] **Step 2: Move absorbed backlog items to Shipped**

Move `T-STAGING-ORPHAN-GC` (from "Phase 4+ (autoresearch / scale)") to Shipped. Note: absorbed by sweep_stale_staging. Add commit SHA.

Move `T3-M1` (from "Project-wide"), `T11-N1` + `T11-N2` (from their respective sections) to Shipped. Note: bundled with PR #6 per spec §7.

Move `T10-M1 partial` to a new "Partially shipped (PR #6)" block (project-wide audit remains deferred to PR #9).

- [ ] **Step 3: Verify and augment the "Phase 3b PR #6 follow-ups" section**

As of 2026-04-21, `docs/DEFERRED_BACKLOG.md` already contains a `## Phase 3b PR #6 follow-ups (Opus re-review polish)` section with 8 entries (`BACKLOG-PR6-01..08`) captured when the Opus re-review of T1 + T2 completed. Verify those entries are still present and accurate.

Then **append** the 5 original-plan entries to the same section, renumbered as `BACKLOG-PR6-09..13`:

```markdown
### BACKLOG-PR6-09 — Registry compaction when pending-approvals.jsonl exceeds 10MB or 1yr
**Source:** Phase 3b PR #6 design, 2026-04-20
**File:** `src/screw_agents/adaptive/staging.py` + new compaction CLI
**Priority:** Low — append-only JSONL; size stays manageable at current scale.
**Trigger:** registry exceeds 10 MB OR oldest entry exceeds 1 year OR
audit performance becomes noticeable.
**Suggested fix:** `screw-agents compact-registry` CLI that archives old
entries to `.screw/local/pending-approvals-archive/YYYY-MM.jsonl`; keep
signatures preserved.

### BACKLOG-PR6-10 — Shared-prompt skill refactor via Claude Code `skills:` frontmatter
**Source:** Phase 3b PR #6 design; Claude Code guide confirmed feasible 2026-04-20
**File:** new `plugins/screw/skills/adaptive-mode/SKILL.md`; per-agent
frontmatter in `plugins/screw/agents/screw-{sqli,cmdi,ssti,xss}.md`
**Priority:** Medium — byte-identical duplication across 4 files is painful
when edited. Investigated in PR #6; Claude Code's `skills:` frontmatter
preloads skill content into subagent context at startup — architecturally
feasible.
**Trigger:** next T18b prompt edit that hits drift, OR after PR #6
demonstrates the byte-identity test has caught drifts in practice.
**Suggested fix:** extract the ~300-line Step 3.5d section to a skill
entry; list the skill in each per-agent `skills:` frontmatter. Prototype
to verify the preload order preserves the prompt's intended position in
the subagent's context.

### BACKLOG-PR6-11 — Attribute-access lint for `import screw_agents.adaptive as X; X.unknown`
**Source:** I2 edge case (PR #6)
**File:** `src/screw_agents/adaptive/lint.py`
**Priority:** Low — requires attribute-access analysis; common case covered
by I2.
**Trigger:** a real adaptive script uses aliased imports + accesses a
non-existent attribute, OR a user reports lint-pass-then-execute-fail.
**Suggested fix:** extend AST walker to track `import X as Y` bindings
and validate `Y.attr` against `screw_agents.adaptive.__all__`.

### BACKLOG-PR6-12 — Level 3 review-markdown hash binding (cryptographic)
**Source:** Phase 3b PR #6 design Q6; rejected Level 3 during brainstorm
**File:** TBD — would add `review_markdown_sha256` to registry entries
**Priority:** Low — only if threat model escalates (e.g., future UI
auto-populates reviews). Current source-hash binding closes the realistic
attacker path.
**Trigger:** threat-model change making source-only binding insufficient.

### BACKLOG-PR6-13 — Phase 4 autoresearch hook into sign_adaptive_script
**Source:** Phase 3b PR #6 design Q4; Option D preserved the direct-sign
wrapper for this consumer.
**Priority:** Phase 4 work (not standalone)
**Trigger:** Phase 4 autoresearch scaffolding needs a programmatic
script-signing path after automated review.
**Suggested approach:** existing `engine.sign_adaptive_script` is already
the right API; Phase 4's autoresearch module uses it directly after its
own review produces approved source + meta.
```

Also review whether the ongoing implementation of T3-T22 surfaced additional follow-up items that belong in the same section (e.g., T4 `promote_staged_script` reviewer findings, T6 sweep edge cases, T21 integration-test findings). If so, append them as `BACKLOG-PR6-14..` etc.

- [ ] **Step 4: Commit**

```bash
git add docs/DEFERRED_BACKLOG.md
git commit -m "docs(phase3b-c1): shipped + follow-up updates in DEFERRED_BACKLOG (T24)"
```

---

## Phase I — Merge + Validation (T25-T27)

### Task 25: PR Creation + Review Cycles

- [ ] **Step 1: Push branch**

From the worktree (`.worktrees/phase-3b-c1-staging`):

```bash
git push -u origin phase-3b-c1-staging
```

- [ ] **Step 2: Create PR**

```bash
gh pr create --title "Phase 3b PR #6 — C1 Staging Architecture + I1-I6 Polish" \
  --body "$(cat <<'EOF'
## Phase 3b PR #6 — C1 Staging Architecture + I1-I6 Polish

Closes the C1 trust-invariant violation surfaced by PR #5's round-trip test.
The approve path no longer regenerates source after approval: the new
`promote_staged_script` MCP tool takes NO `source` parameter and reads
staged bytes from disk, verifying sha256 against the registry before signing.

### What shipped
- Staging architecture: 4 new MCP tools (stage/promote/reject/sweep)
- 2 MCP tools promoted from CLI: list + remove
- Shared `_sign_script_bytes` helper — single canonical-bytes source
- T18b prompt rewrite across 4 per-agent subagents (byte-identical section)
- Bundled polish: I1 (plugin namespace), I2 (lint __all__), I3 (stderr),
  I4 (retention), I5 (hallucination hardening), I6 (MCP cwd-independence)
- Absorbed backlog: T-STAGING-ORPHAN-GC, T10-M1 partial, T11-N1 (sig E2E),
  T11-N2 (MetadataError), T3-M1 (narrow exceptions)
- Deleted: src/screw_agents/cli/adaptive_cleanup.py

### Test count
771 baseline → 820+ (exact count after all tasks land; see exit checklist)

### Security property restored
`bytes_reviewed == bytes_signed == bytes_executed`, enforced by
(a) script_name content-binding via hash6(source) and
(b) sha256 registry verification at promote time.

See `docs/specs/2026-04-20-phase-3b-c1-staging-design.md` for the
consolidated design and `docs/PHASE_3B_C1_PLAN.md` for task-level detail.
EOF
)"
```

- [ ] **Step 3: Iterate review cycles**

Follow the existing PR review discipline (per `feedback_phase3a_workflow_discipline`): spec-review → quality-review → triage → fix-up → cross-plan-sync per iteration.

If reviewer-flagged issues require plan deviation:
- Update `docs/PHASE_3B_C1_PLAN.md` in the SAME PR (per `feedback_plan_sync_on_deviation`)
- Update `docs/specs/2026-04-20-phase-3b-c1-staging-design.md` if architectural change
- Note the deviation prominently in the PHASE_3B_PLAN PR #6 section

- [ ] **Step 4: Do NOT amend — create NEW commits for review feedback**

Per git-safety discipline (`feedback_no_cc_commits` + platform conventions):
- NEW commits for fixes, never `git commit --amend`
- NO Claude Code / AI attribution in commit messages

---

### Task 26: Merge + Post-Merge Round-Trip Validation

- [ ] **Step 1: Merge from main worktree (not from the feature worktree)**

Per `reference_claude_code_plugin_dev` memory: `gh pr merge --delete-branch` fails from inside a worktree.

```bash
cd /home/marco/Programming/AI/screw-agents  # main worktree
gh pr merge <PR-number> --squash --delete-branch
git pull --ff-only
git log --oneline -1  # new squash SHA
```

- [ ] **Step 2: Clean up worktree**

```bash
git worktree remove .worktrees/phase-3b-c1-staging
git branch -d phase-3b-c1-staging  # local cleanup if needed
```

- [ ] **Step 3: Run full suite on main**

```bash
uv run pytest -q
```

Expected: 820+ passed on main.

- [ ] **Step 4: Execute the 12-step post-merge round-trip validation**

(See the "Post-Merge Round-Trip Validation (T26)" section at the bottom of this plan document.)

Success criteria:
- Step 9 (trust invariant): signed source == reviewed source, byte-identical
- Step 10 (I1): Layer 0d reviewer actually fires (not "not-run")
- Step 11 (I6): `/screw:adaptive-cleanup` works without cwd workaround
- Step 12 (Q5): `--preview` mode reports cleanly, zero filesystem changes

If any step fails, **do NOT consider the PR validated**. Open a follow-up regression investigation.

---

### Task 27: Memory Updates

- [ ] **Step 1: Write new `project_phase3b_c1_complete.md`**

Content:

```markdown
---
name: Phase 3b PR #6 complete — C1 staging architecture shipped
description: PR #<N> merged <DATE> (squash commit <SHA>). Closes the C1 trust-invariant violation + bundles I1-I6 + 5 backlog items. ~963 LOC net, ~820+ tests. Adaptive-mode production-ready.
type: project
originSessionId: <this-session-id>
---

**PR #<N> — Phase 3b PR #6 MERGED <DATE>:**

- **Squash-merge commit:** `<SHA>` on `main`
- **Final state:** <count> commits squashed to 1; <N> tests passing on main (baseline 771, net +~85)
- **Branch + worktree cleaned up**

**What shipped (27 tasks):**

[list of tasks T0-T26 with brief summary each]

**Manual round-trip validation (POST-MERGE, <DATE>):**
- 12 steps executed on /tmp/screw-roundtrip-qb/
- Trust invariant holds: signed source == reviewed source (byte-identical)
- I1 Layer 0d reviewer fires correctly (plugin namespace)
- I6 /screw:adaptive-cleanup works without cwd workaround
- Stale sweep --preview reports 0 orphans on clean slate

**Adaptive mode: PRODUCTION READY** (C1 shipper-blocker resolved).

**Next:** Phase 3c sandbox hardening (PR #7) OR Phase 4 autoresearch (PR #11)
depending on priority. See `docs/specs/2026-04-20-phase-3b-c1-staging-design.md`
§7.3 for the post-C1 roadmap sequence.
```

- [ ] **Step 2: Demote `project_phase3b_pr5_complete.md` to historical**

Edit the file — update its description field to `"historical (C1 has since shipped in PR #6)"`. Keep the content.

- [ ] **Step 3: Update `MEMORY.md` index**

- Replace the existing `[Phase 3b PR #5 complete — C1 staging fix next]` entry's text with a pointer to the PR #6 entry.
- Add the new `project_phase3b_c1_complete.md` pointer.

- [ ] **Step 4: Verify MEMORY.md length still under 200 lines**

Run: `wc -l ~/.claude/projects/-home-marco-Programming-AI-screw-agents/memory/MEMORY.md`
Expected: ≤ 200 (system enforces truncation beyond).

If close: consolidate historical entries (demote multiple to a single "historical Phase 3b" line).

- [ ] **Step 5: No git commit needed**

Memory files are local to `~/.claude/...`, not part of the repo. They persist across sessions but aren't version-controlled.

---

---

## PR #6 Exit Checklist

Before requesting PR review:

- [ ] All tasks T0-T24 complete
- [ ] `uv run pytest -q` → 820 passed, 8 skipped, 0 failed
- [ ] `uv run pytest tests/test_adaptive_subagent_prompts.py -v` → all 12 new format-smoke assertions pass
- [ ] `uv run pytest tests/test_adaptive_workflow.py tests/test_adaptive_workflow_staged.py -v` → both integration tests pass
- [ ] `git diff main --stat` → ~963 LOC net across files in `File Structure Map` table above
- [ ] `grep -r "sign_adaptive_script" plugins/screw/agents/screw-*.md` → zero matches (LLM-flow isolation invariant)
- [ ] `grep -rn "from screw_agents.cli.adaptive_cleanup" .` → only match is in deleted file (post-T9)
- [ ] `docs/PHASE_3B_PLAN.md` has the new "PR #6" section
- [ ] `docs/DEFERRED_BACKLOG.md` has C1 + I1-I6 + T-STAGING-ORPHAN-GC moved to Shipped; `BACKLOG-PR6-01..08` confirmed (from Opus re-review, 2026-04-21); `BACKLOG-PR6-09..13` appended (original-plan design items)
- [ ] Spec at `docs/specs/2026-04-20-phase-3b-c1-staging-design.md` remains unmodified (or deviations called out in PHASE_3B_PLAN plan-sync note)
- [ ] No Claude Code / AI attribution in any commit message (`feedback_no_cc_commits`)

PR description template:

```
## Phase 3b PR #6 — C1 Staging Architecture + I1-I6 Polish

Closes the C1 trust invariant violation surfaced by PR #5's round-trip test:
regenerated-after-approval source is no longer possible because the approve
path reads staged bytes from disk (no `source` parameter in promote tool).

### What shipped
- 4 new MCP tools: stage_adaptive_script, promote_staged_script,
  reject_staged_script, sweep_stale_staging
- 2 MCP tools promoted from CLI: list_adaptive_scripts, remove_adaptive_script
- New module: src/screw_agents/adaptive/staging.py
- Shared helper: adaptive/signing.py::_sign_script_bytes (single canonical-bytes
  source for both direct-sign and promote-sign paths)
- T18b prompt rewrite across 4 per-agent subagent files (byte-identical section)
- Bundled polish: I1 plugin namespace, I2 lint __all__ validation, I3 stderr
  surfacing, I4 retention docs, I5 hallucination hardening, I6 MCP promotion
- Absorbed backlog: T-STAGING-ORPHAN-GC, T10-M1 partial, T11-N1 signature
  regression test, T11-N2 MetadataError wrapper, T3-M1 narrow exceptions
- Deleted: src/screw_agents/cli/adaptive_cleanup.py (no shell entry point)

### Test count: 771 → 820 passed, 8 skipped

### Security property restored
bytes_reviewed == bytes_signed == bytes_executed — enforced by
(a) script_name content-binding via hash6(source) and (b) sha256
registry verification at promote time. See spec §4.

### Post-merge validation
10-step manual round-trip on /tmp/screw-roundtrip-qb/ with approve flow.
Success criteria: steps 7 (trust invariant), 8 (I1 Layer 0d fires), 9
(I6 adaptive-cleanup works out of box) all pass without LLM recovery.
```

---

## Post-Merge Round-Trip Validation (T26)

Exit gate after `gh pr merge --delete-branch` (from main worktree, per `reference_claude_code_plugin_dev`):

1. `cd /home/marco/Programming/AI/screw-agents && git pull --ff-only` — main at new SHA.
2. `uv run pytest -q` — 820 passed on main.
3. `cd /tmp && rm -rf screw-roundtrip-qb && mkdir screw-roundtrip-qb && cd screw-roundtrip-qb`
4. Seed fixture with the QueryBuilder example from PR #5 round-trip (see PR #5 notes or recreate):
   ```bash
   mkdir -p src && cat > src/dao.py <<'EOF'
   class QueryBuilder:
       def execute_raw(self, sql):
           pass

   def handle(request):
       q = request.args.get('q')
       cursor.execute(q)
       self.qb.execute_raw(q)
       QueryBuilder().execute_raw(q)
   EOF
   ```
5. `screw-agents init-trust` — trust infrastructure unchanged from PR #5.
6. `claude` → `/screw:scan sqli src/ --adaptive` — scans + stages.
7. Observe 5-section review header shows `Staged: <iso>  |  Session: <id_short>  |  SHA256: <8char>`.
8. Type `approve <script-name>` — fresh subagent respawns.
9. Observe: promote_staged_script verifies sha match → signs → executes. Signed source MUST equal the source shown in Section 4 of the review (byte-identical).
10. Observe Layer 0d runs (I1 verification) — reviewer output has non-empty `risk_score`, `flagged_patterns`, NOT "not-run" or "subagent unavailable".
11. `/screw:adaptive-cleanup` — succeeds without cwd-recovery workaround (I6 verification; no ModuleNotFoundError).
12. `/screw:adaptive-cleanup stale --preview` — shows 0 stale orphans (clean slate).

**Success criteria:** steps 9 + 10 + 11 all pass without LLM recovery or manual intervention. If step 9 fails (signed source != reviewed source), C1 has regressed — do NOT merge; open regression investigation.
