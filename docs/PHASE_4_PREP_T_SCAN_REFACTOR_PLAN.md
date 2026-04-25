# Phase 4 Prereq — T-SCAN-REFACTOR (`scan_agents` primitive + universal subagent + multi-scope slash command): Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` (recommended) or `superpowers:executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.
>
> **Per-task workflow (from `feedback_phase3a_workflow_discipline.md`, adapted per Phase 3b-C2 lessons):** novel-work cycle — pre-audit → implementer → combined spec+quality review → triage → fix-up → cross-plan sync. One dispatch per lens for non-mechanical tasks. Mechanical tasks may go straight to implementer with inline file-read verification per `feedback_pre_audit_scope_challenge.md`. Tests + greps are the binary verification gate.
>
> **Opus-for-all-subagents (from `feedback_opus_for_all_subagents.md`):** every Agent dispatch passes `model: "opus"`.
>
> **Plan-sync on deviation (from `feedback_plan_sync_on_deviation.md`):** whenever implementation differs from this plan, update this file in the SAME PR (or defer the item to DEFERRED_BACKLOG). Plan and code must be coherent at merge time.
>
> **Live round-trip required:** this PR changes user-visible slash command syntax, MCP tool surface, and subagent shape. Two live `claude -p` round-trips are mandatory before merge (Task 10).
>
> **Task-boundary pauses:** explicit "Confirm go-ahead on Task N+1?" between every task per `feedback_wait_for_confirmation.md`. Even when Marco said "start" for the whole PR.

**Goal:** Replace the current three-tool scan surface (`scan_full`, `scan_domain`, per-agent `scan_<agent>` × N) with one paginated multi-agent primitive (`scan_agents`) + one thin convenience shortcut (`scan_domain`); add per-agent language relevance filter; rewrite slash command for arbitrary multi-domain + multi-agent selection; collapse 4 per-agent + 1 domain orchestrator subagents into one universal `screw-scan.md`. Subsumes T-FULL-P1 (closes Phase-4 prereq count 1 → 0).

**Architecture:** New engine method `assemble_agents_scan(agents, target, …, cursor, page_size)` mirrors `assemble_domain_scan`'s init/code-page split with cursor binding generalized to `(target_hash, agents_hash)` (Option β). `scan_domain` becomes a thin internal wrapper. `assemble_full_scan` deleted. New `_filter_relevant_agents(target_codes, agents)` helper drops agents whose declared languages don't intersect target's detected languages (extension lookup + shebang fallback). Universal subagent receives `agents: list[str]` arg from main session (slash command), runs paginated loop, accumulates findings via `accumulate_findings`, returns lean structured payload (no inline findings — staging-only). Slash command parser supports `domains:`/`agents:` prefix-key syntax + bare-token shortcuts + `full` keyword + pre-execution summary line + `--no-confirm`.

**Tech Stack:** Python 3.11+, Pydantic v2, pytest, MCP (FastMCP-style stdio server). No new dependencies.

**Spec:** `docs/specs/2026-04-25-t-scan-refactor-design.md` (835 lines, local working material gitignored per `project_docs_not_committed`).

**Upstream phase plan:** T19-M1/M2/M3 + D7 merged 2026-04-24 (squash `02d90d1`). main HEAD `02d90d1`. 906 passed / 8 skipped baseline. Phase 4 blocker count 1 (T-FULL-P1 only); this PR drops it to 0.

**Downstream phase plan:** After this PR, Phase 4 step 4.0 (D-01 Rust benchmark corpus) becomes the gate. Phase 4 autoresearch plan still TBD; the per-agent MCP surface (`scan_<agent>` retired here) becomes `scan_agents([single_name])` for autoresearch consumers.

**Branch:** `t-scan-refactor` (dedicated worktree at `.worktrees/t-scan-refactor`).

**Worktree pre-flight (per `feedback_worktree_preflight.md`):**
- Verify `.worktrees/` is gitignored: `grep -n '\.worktrees' /home/marco/Programming/AI/screw-agents/.gitignore` → expect at least one match.
- Create worktree: `git worktree add .worktrees/t-scan-refactor -b t-scan-refactor main` from main checkout.
- `cd .worktrees/t-scan-refactor && uv sync` before any `uv run` command.

**Key references for implementers:**
- `docs/specs/2026-04-25-t-scan-refactor-design.md` — the approved design (D0-D8 sketch decisions + Q1-Q6 brainstorm decisions + sections 1-18)
- `docs/DEFERRED_BACKLOG.md` §T-FULL-P1 (line 425) — to be marked superseded with forwarding entry
- `docs/PROJECT_STATUS.md` §"Phase 4 Prerequisites (hard gates)" — prereq state to update
- `docs/PHASE_4_PREP_T19M_PLAN.md` — structural template for this plan
- `src/screw_agents/engine.py:1421-1507` — `assemble_scan` (per-agent helper, kept as inner primitive)
- `src/screw_agents/engine.py:1509-1705` — `assemble_domain_scan` (cursor + paging template; refactored as wrapper in Task 4)
- `src/screw_agents/engine.py:1707-1774` — `assemble_full_scan` (deleted in Task 6)
- `src/screw_agents/engine.py:2165+` — `list_tool_definitions` (modified in Tasks 5 + 6)
- `src/screw_agents/engine.py:3156+` — `_scan_input_schema` helper
- `src/screw_agents/server.py:230-280` — `handle_call_tool` dispatch (modified in Tasks 5 + 6)
- `src/screw_agents/registry.py:22-94` — full registry; new invariants land at end of `_load()`
- `src/screw_agents/resolver.py:48-105` — `resolve_target` + `_detect_language` (extension only today)
- `src/screw_agents/resolver.py:339-356` — existing `filter_by_relevance` (per-file content; preserved, distinct from new per-agent language filter)
- `src/screw_agents/treesitter.py:36-63` — `EXTENSION_MAP`, `language_from_path` (shebang helper added in Task 2)
- `src/screw_agents/models.py:64-85` — `HeuristicEntry`, `HeuristicItem`, `DetectionHeuristics` (the source of language declarations per the spec D4 correction)
- `plugins/screw/agents/screw-{sqli,cmdi,ssti,xss,injection}.md` — to delete in Task 7
- `plugins/screw/commands/scan.md` — slash command (rewrite target in Task 8)
- `tests/test_engine.py:303-411` — `test_assemble_full_scan_*` (deleted in Task 6)
- `tests/test_engine.py:25, 79` — per-agent tool name assertions (migrated in Task 6)

---

## PR Scope Summary

| Category | Items | Net LOC |
|---|---|---|
| Task 1: Registry invariants | Agent-vs-domain collision check + filename-stem assertion + 5 tests | +30 / -0 |
| Task 2: Relevance filter helper | `_filter_relevant_agents` + `_agent_supported_languages` + shebang detection + 10 tests | +250 / -0 |
| Task 3: `assemble_agents_scan` | New engine method + Option β cursor + relevance integration + 25 tests | +750 / -0 |
| Task 4: `scan_domain` wrapper refactor | Replace body with delegation to `assemble_agents_scan` + ~10 test migrations | +30 / -180 |
| Task 5: `scan_agents` MCP tool | Schema in `list_tool_definitions` + dispatch in `server.py` + 5 tests | +130 / -0 |
| Task 6: Retirements | Delete `assemble_full_scan` + `scan_full` tool + per-agent loop + tests | +0 / -350 |
| Task 7: Universal subagent | New `screw-scan.md` (~420 LOC) + delete 5 old subagent files (-1878 LOC) + 5 manifest tests | +500 / -1878 |
| Task 8: Slash command rewrite | Parser + resolution + summary + error cases + 15 tests | +420 / -100 |
| Task 9: Documentation sync | 8 docs updated (PRD, DECISIONS, ARCHITECTURE, AGENT_AUTHORING, PROJECT_STATUS, DEFERRED_BACKLOG, CONTRIBUTING, AGENT_CATALOG) | +500 / -100 |
| Task 10: Round-trip verification | Live `claude -p` × 2 — no code changes | 0 |
| **Total** | | **~+2610 / -2608 (net ~+2 LOC; ~700 substantive new + ~1900 cleanup)** |

**Target test count:** 906 passed → **≈970 passed, 8 skipped** (≈+65 new, ≈-15 deleted, ≈-15 net migrated). Zero failures.

**Test files:**
- New: `tests/test_registry_invariants.py` (5 tests), `tests/test_relevance_filter.py` (10 tests), `tests/test_assemble_agents_scan.py` (25 tests), `tests/test_scan_command_parser.py` (15 tests), `tests/test_screw_scan_subagent.py` (5 tests)
- Modified: `tests/test_engine.py`, `tests/test_server.py`, `tests/test_phase2_server.py`, `tests/test_prompt_dedup_roundtrip.py` (per-agent / scan_full assertions migrated or deleted)

---

## File Structure Map

### Created (8 files)

| Path | Responsibility |
|---|---|
| `tests/test_registry_invariants.py` | Tests for agent-vs-domain collision check and YAML filename-stem assertion |
| `tests/test_relevance_filter.py` | Tests for `_filter_relevant_agents`, `_agent_supported_languages`, shebang fallback, fail-open paths |
| `tests/test_assemble_agents_scan.py` | Tests for the new primitive: cursor binding (target+agents), page boundaries, response shape, validation, `agents_excluded_by_relevance` field |
| `tests/test_scan_command_parser.py` | Tests for slash command grammar, scope-spec resolution, cross-domain rejection, error cases |
| `tests/test_screw_scan_subagent.py` | Tests for universal subagent file presence, frontmatter `tools:` declaration, structured-return-payload size regression |
| `plugins/screw/agents/screw-scan.md` | Universal scan subagent (replaces 4 per-agent + 1 domain orchestrator) |
| `docs/PHASE_4_PREP_T_SCAN_REFACTOR_PLAN.md` | This plan (committed) |
| (No new src files — `_filter_relevant_agents`, `_agent_supported_languages`, `assemble_agents_scan` all live in existing `engine.py`; shebang helper lives in existing `treesitter.py`) | |

### Modified (15 files)

| Path | What changes |
|---|---|
| `src/screw_agents/registry.py` | Append agent-vs-domain collision assertion at end of `_load()` (~5 LOC). Add YAML filename-stem assertion inside the `rglob` loop (~5 LOC). |
| `src/screw_agents/treesitter.py` | Add `SHEBANG_MAP: dict[str, str]` and `language_from_shebang(first_line: str) -> str \| None` helper (~30 LOC). |
| `src/screw_agents/resolver.py` | Update `_detect_language(path, content=None)` to fall back to shebang detection when extension lookup returns None (~10 LOC delta). Pass `content` from `_resolve_file`, `_resolve_glob`, `_resolve_codebase`, `_resolve_lines`, `_resolve_function`, `_resolve_class`, `_parse_unified_diff` (each updated to call `_detect_language(path, content)`). |
| `src/screw_agents/engine.py` | Add `_agent_supported_languages` and `_filter_relevant_agents` helpers (~80 LOC). Add `assemble_agents_scan` method (~250 LOC). Refactor `assemble_domain_scan` body as wrapper (~30 LOC; net -180 LOC after deletion of duplicated code). Delete `assemble_full_scan` method (-70 LOC). Update `list_tool_definitions`: register `scan_agents` (+45 LOC), delete `scan_full` registration (-15 LOC), delete per-agent registration loop (-20 LOC). |
| `src/screw_agents/server.py` | `handle_call_tool`: add `scan_agents` dispatch branch (+10 LOC). Delete `scan_full` and per-agent dispatch branches (-15 LOC). |
| `plugins/screw/commands/scan.md` | Full rewrite: new grammar, parsing rules, resolution algorithm, pre-execution summary, error handling, `--no-confirm` flag, target-last positional. Replaces today's domain-loop full-scope branch. |
| `plugins/screw/plugin.json` (or equivalent registration file) | Drop registrations for `screw-sqli`, `screw-cmdi`, `screw-ssti`, `screw-xss`, `screw-injection`. Add registration for `screw-scan`. |
| `tests/test_engine.py` | Delete 4 `test_assemble_full_scan_*` tests (lines 303-411). Migrate per-agent `scan_<name>` tool-name assertions to `scan_agents` (line 79). Verify line 25 `assert "scan_full" in tool_names` is deleted with the rest of the test or migrated. |
| `tests/test_server.py` | Migrate `assert "scan_full" in names` (line 25) to `assert "scan_agents" in names`. |
| `tests/test_phase2_server.py` | Migrate `t["name"] in ("scan_domain", "scan_full")` (line 211) to `("scan_domain", "scan_agents")`. |
| `tests/test_prompt_dedup_roundtrip.py` | Migrate `test_domain_scan_full_walk_*` (lines 25, 75) to `scan_agents`-based round-trip. |
| `docs/DEFERRED_BACKLOG.md` | Mark T-FULL-P1 as **RESOLVED 2026-04-25** with forwarding to T-SCAN-REFACTOR PR commit. Update `blocker` count table (line ~136) from 1 → 0. Update Phase 4 gate paragraph. Add 6 new deferred items (severity/cwe/exclude-agents filters, tree-sitter disambiguation, multi-session merge, explicit `target_strategy.relevance_signals`, `/screw:scan list` subcommand, `--no-confirm` audit hook). |
| `docs/PROJECT_STATUS.md` | Update gate line. Add new "What's shipped" bullet for T-SCAN-REFACTOR. Update Phase 4 row in phase table (drop T-FULL-P1, only D-01 remains). Delete T-FULL-P1 block from §"Phase 4 Prerequisites (hard gates)". |
| `docs/PRD.md` | §3 architecture section: tool count 6→2, subagent count 5→1; remove `scan_full` references. §4 YAML schema: clarify `HeuristicEntry.languages` is the implicit relevance signal. §6 user-facing examples: add multi-scope syntax samples. |
| `docs/DECISIONS.md` | Append new ADR for T-SCAN-REFACTOR (Path Y rationale; Option A′ migration; Option I subagent collapse; Option β cursor; Position a uniform filter). |
| `docs/ARCHITECTURE.md` | Redraw tool inventory, subagent inventory, scan-flow chain diagrams. |
| `docs/AGENT_AUTHORING.md` | New section on global uniqueness invariants (agent unique, agent ≠ domain, YAML stem == `meta.name`); note that adding a new agent does not require a per-agent subagent file. |
| `docs/CONTRIBUTING.md` | Update "how to add a new agent" if present (subagent file no longer required); reference AGENT_AUTHORING.md invariants. |
| `docs/AGENT_CATALOG.md` | Update tool-count references if any. |

### Deleted (5 files)

| Path | Replacement |
|---|---|
| `plugins/screw/agents/screw-sqli.md` (414 LOC) | Universal `screw-scan.md` |
| `plugins/screw/agents/screw-cmdi.md` (414 LOC) | Universal `screw-scan.md` |
| `plugins/screw/agents/screw-ssti.md` (414 LOC) | Universal `screw-scan.md` |
| `plugins/screw/agents/screw-xss.md` (414 LOC) | Universal `screw-scan.md` |
| `plugins/screw/agents/screw-injection.md` (222 LOC) | Universal `screw-scan.md` (main session resolves agent list, dispatches once) |

---

## Task Breakdown

The task index continues in subsequent edits — each task is a separate self-contained block with goal, files, pre-audit focus, steps, and commit. The 10 tasks are ordered by dependency:

1. Registry invariants (foundational; no upstream deps)
2. Relevance filter helper + language detection (independent unit; used by Task 3)
3. `assemble_agents_scan` engine method (depends on Task 2)
4. Refactor `assemble_domain_scan` as wrapper (depends on Task 3)
5. `scan_agents` MCP tool registration (depends on Task 3)
6. Retirements: delete `assemble_full_scan` + `scan_full` MCP tool + per-agent tools (depends on Task 5)
7. Universal `screw-scan.md` subagent + delete 5 old (depends on Task 5 + 6)
8. Slash command rewrite (depends on Tasks 5, 7)
9. Documentation sync (depends on Tasks 1-8)
10. End-to-end round-trip verification (depends on all)

Tasks 1-10 specified below.

---

## Task 1: Registry invariants — agent-vs-domain collision + filename-stem

**Goal:** Lock in the two registry invariants the slash command parser depends on: (i) agent name must not collide with any domain name; (ii) YAML filename stem must equal `meta.name`. Existing agent-vs-agent uniqueness check (`registry.py:44-48`) preserved.

**Files:**
- Modify: `src/screw_agents/registry.py:33-55`
- Create: `tests/test_registry_invariants.py`

**Pre-audit focus:** none required (mechanical addition with existing-pattern parallel). Inline-verify by re-reading `registry.py` after the edit.

- [ ] **Step 1: Write failing test for filename-stem assertion**

Create `tests/test_registry_invariants.py`:

```python
"""Tests for registry invariants — agent-vs-domain collision and YAML filename-stem checks.

Phase 4 prereq T-SCAN-REFACTOR Task 1: bare-token slash command parser depends
on these invariants. Spec sections 10.2 + 10.3.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from screw_agents.registry import AgentRegistry


# ---------------------------------------------------------------------------
# Filename-stem assertion (Section 10.3)
# ---------------------------------------------------------------------------


def _write_minimal_agent_yaml(path: Path, *, name: str, domain: str) -> None:
    """Write a minimal valid AgentDefinition YAML to `path`."""
    path.write_text(
        f"""\
meta:
  name: {name}
  display_name: "Test Agent"
  domain: {domain}
  version: "0.1.0"
  last_updated: "2026-04-25"
  cwes:
    primary: "CWE-89"
    related: []
  capec: []
  owasp:
    top10: ""
    asvs: []
    testing_guide: ""
  sources: []
core_prompt: "test prompt"
detection_heuristics:
  high_confidence: []
  medium_confidence: []
  context_required: []
remediation:
  preferred: "use parameterized queries"
""",
        encoding="utf-8",
    )


def test_filename_stem_matches_meta_name(tmp_path: Path) -> None:
    """Registry loads cleanly when YAML filename stem equals meta.name."""
    domain_dir = tmp_path / "test-domain"
    domain_dir.mkdir()
    _write_minimal_agent_yaml(domain_dir / "agent_a.yaml", name="agent_a", domain="test-domain")

    registry = AgentRegistry(tmp_path)
    assert registry.get_agent("agent_a") is not None


def test_filename_stem_mismatch_raises(tmp_path: Path) -> None:
    """Registry refuses to load when YAML filename stem differs from meta.name."""
    domain_dir = tmp_path / "test-domain"
    domain_dir.mkdir()
    _write_minimal_agent_yaml(domain_dir / "wrong_stem.yaml", name="actual_name", domain="test-domain")

    with pytest.raises(ValueError, match="does not match meta.name"):
        AgentRegistry(tmp_path)


# ---------------------------------------------------------------------------
# Agent-vs-domain collision assertion (Section 10.2)
# ---------------------------------------------------------------------------


def test_agent_name_unique_from_domain_names(tmp_path: Path) -> None:
    """Registry loads cleanly when agent names and domain names are disjoint."""
    domain_dir = tmp_path / "domain-foo"
    domain_dir.mkdir()
    _write_minimal_agent_yaml(domain_dir / "agent_x.yaml", name="agent_x", domain="domain-foo")

    registry = AgentRegistry(tmp_path)
    assert "agent_x" in registry.agents
    assert "domain-foo" in registry.list_domains()


def test_agent_name_collides_with_domain_name_raises(tmp_path: Path) -> None:
    """Registry refuses to load when an agent name equals any domain name."""
    # Two domains: 'bar' and 'qux'. An agent in 'qux' is named 'bar' — collision.
    bar_dir = tmp_path / "bar"
    bar_dir.mkdir()
    _write_minimal_agent_yaml(bar_dir / "innocent.yaml", name="innocent", domain="bar")

    qux_dir = tmp_path / "qux"
    qux_dir.mkdir()
    _write_minimal_agent_yaml(qux_dir / "bar.yaml", name="bar", domain="qux")

    with pytest.raises(ValueError, match="collide with domain name"):
        AgentRegistry(tmp_path)


def test_existing_agent_uniqueness_check_still_enforced(tmp_path: Path) -> None:
    """Sanity check: agent-vs-agent uniqueness from registry.py:44-48 is preserved."""
    a_dir = tmp_path / "domain-a"
    a_dir.mkdir()
    _write_minimal_agent_yaml(a_dir / "dup.yaml", name="dup", domain="domain-a")

    b_dir = tmp_path / "domain-b"
    b_dir.mkdir()
    _write_minimal_agent_yaml(b_dir / "dup.yaml", name="dup", domain="domain-b")

    with pytest.raises(ValueError, match="Duplicate agent name"):
        AgentRegistry(tmp_path)
```

- [ ] **Step 2: Run new tests to verify they fail**

```
uv run pytest tests/test_registry_invariants.py -v 2>&1 | tail -20
```

Expected: `test_filename_stem_mismatch_raises` and `test_agent_name_collides_with_domain_name_raises` FAIL (the new invariants aren't enforced yet). Other tests pass.

- [ ] **Step 3: Add filename-stem assertion to `registry.py`**

Open `/home/marco/Programming/AI/screw-agents/src/screw_agents/registry.py`. Locate the `_load` method (lines 27-61). Inside the `for yaml_path in sorted(domains_dir.rglob("*.yaml"))` loop, immediately after the `agent = AgentDefinition.model_validate(raw)` line and before `name = agent.meta.name`, insert:

```python
            # T-SCAN-REFACTOR Task 1 (Section 10.3): YAML filename stem
            # must equal meta.name. Prevents copy-paste mistakes where a
            # duplicated YAML keeps the original meta.name.
            if yaml_path.stem != agent.meta.name:
                raise ValueError(
                    f"YAML filename stem {yaml_path.stem!r} does not match "
                    f"meta.name {agent.meta.name!r} in {yaml_path}. "
                    f"Convention: stem == meta.name."
                )
```

- [ ] **Step 4: Add agent-vs-domain collision assertion**

In `registry.py::_load`, after the `for yaml_path in ...` loop completes (after the existing `logger.info(...)` call at line 57), append:

```python
        # T-SCAN-REFACTOR Task 1 (Section 10.2): agent names must not
        # collide with domain names. The slash command's bare-token parser
        # disambiguates a token by looking it up in both registries; without
        # this invariant a token could match both, producing ambiguous scope
        # resolution.
        collision = set(self._agents.keys()) & set(self._domains.keys())
        if collision:
            raise ValueError(
                f"Agent name(s) collide with domain name(s): {sorted(collision)}. "
                f"Agent names and domain names share a global namespace; rename one."
            )
```

- [ ] **Step 5: Run new tests to verify they pass**

```
uv run pytest tests/test_registry_invariants.py -v 2>&1 | tail -20
```

Expected: all 5 tests PASS.

- [ ] **Step 6: Run full test suite to confirm no regression**

```
uv run pytest -q 2>&1 | tail -5
```

Expected: 906 + 5 = 911 passed, 8 skipped. Zero failures.

If any existing test fails because a fixture YAML in `tests/` violates the new invariants: that fixture is buggy by the new rule; fix the fixture (rename file or update `meta.name`).

- [ ] **Step 7: Commit**

```bash
git add src/screw_agents/registry.py tests/test_registry_invariants.py
git commit -m "T-SCAN-REFACTOR Task 1: registry invariants for slash command parser

Adds two assertions to AgentRegistry._load() that the new slash command's
bare-token resolution depends on:

1. YAML filename stem must equal meta.name. Prevents copy-paste mistakes
   where someone duplicates an agent file and forgets to update meta.name
   — the registry would silently load with a misleading filename.

2. Agent names must not collide with domain names. Without this, a bare
   token like '/screw:scan cryptography' would be ambiguous (could mean
   the cryptography domain or an agent named cryptography). The invariant
   is cheap (single set intersection) and catches collisions at server
   start-up; CI test runs catch it on any PR introducing a collision.

Existing agent-vs-agent uniqueness check at registry.py:44-48 is preserved
unchanged.

5 tests cover: stem-match success, stem-mismatch failure, agent-vs-domain
disjoint success, agent-vs-domain collision failure, agent-vs-agent
duplicate failure (sanity check)."
```

---

## Task 2: Relevance filter helper + language detection (extension + shebang)

**Goal:** Ship the `_filter_relevant_agents(target_codes, agents) -> tuple[list, list]` helper that the new primitive depends on. Adds shebang detection to `treesitter.py` and threads `content` through `resolver.py::_detect_language` so files lacking an extension match still get classified.

**Files:**
- Modify: `src/screw_agents/treesitter.py:36-63`
- Modify: `src/screw_agents/resolver.py:92-336`
- Modify: `src/screw_agents/engine.py` (insert helpers near other private helpers; before `assemble_scan` is fine)
- Create: `tests/test_relevance_filter.py`

**Pre-audit focus (mandatory):** before implementing, verify (a) the `HeuristicEntry.languages` field is populated in all 4 shipped agent YAMLs (grep for `languages:` in `domains/`); (b) the shebang map covers the 11 supported tree-sitter languages where shebang lines are realistic (python, ruby, php, javascript via node, typescript via tsnode, bash maps to None since not in EXTENSION_MAP); (c) the `ResolvedCode.language` field is already populated by `resolve_target` for all 9 target types.

- [ ] **Step 1: Write failing test for `language_from_shebang`**

Create `tests/test_relevance_filter.py`:

```python
"""Tests for T-SCAN-REFACTOR Task 2: relevance filter + shebang detection.

Spec sections 8.1, 8.2, 8.5.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from screw_agents.engine import ScanEngine, _agent_supported_languages, _filter_relevant_agents
from screw_agents.models import (
    AgentDefinition,
    AgentMeta,
    CWERefs,
    DetectionHeuristics,
    HeuristicEntry,
    Remediation,
)
from screw_agents.resolver import ResolvedCode
from screw_agents.treesitter import language_from_shebang


# ---------------------------------------------------------------------------
# Shebang detection
# ---------------------------------------------------------------------------


def test_shebang_python3_returns_python() -> None:
    assert language_from_shebang("#!/usr/bin/env python3") == "python"


def test_shebang_python_returns_python() -> None:
    assert language_from_shebang("#!/usr/bin/python") == "python"


def test_shebang_ruby_returns_ruby() -> None:
    assert language_from_shebang("#!/usr/bin/env ruby") == "ruby"


def test_shebang_node_returns_javascript() -> None:
    assert language_from_shebang("#!/usr/bin/env node") == "javascript"


def test_shebang_php_returns_php() -> None:
    assert language_from_shebang("#!/usr/bin/php") == "php"


def test_shebang_unknown_returns_none() -> None:
    assert language_from_shebang("#!/bin/bash") is None
    assert language_from_shebang("#!/usr/bin/perl") is None
    assert language_from_shebang("not a shebang") is None
    assert language_from_shebang("") is None


# ---------------------------------------------------------------------------
# `_agent_supported_languages` helper
# ---------------------------------------------------------------------------


def _make_agent(name: str, *, languages_per_entry: list[list[str]]) -> AgentDefinition:
    """Build a minimal AgentDefinition with one HeuristicEntry per languages list."""
    entries = [
        HeuristicEntry(id=f"e{i}", pattern="dummy", languages=langs)
        for i, langs in enumerate(languages_per_entry)
    ]
    return AgentDefinition(
        meta=AgentMeta(
            name=name,
            display_name="X",
            domain="test-domain",
            cwes=CWERefs(primary="CWE-1", related=[]),
        ),
        core_prompt="x",
        detection_heuristics=DetectionHeuristics(high_confidence=entries),
        remediation=Remediation(preferred="x"),
    )


def test_agent_supported_languages_unions_all_buckets() -> None:
    a = AgentDefinition(
        meta=AgentMeta(
            name="multi",
            display_name="X",
            domain="t",
            cwes=CWERefs(primary="CWE-1", related=[]),
        ),
        core_prompt="x",
        detection_heuristics=DetectionHeuristics(
            high_confidence=[HeuristicEntry(id="h1", pattern="p", languages=["python"])],
            medium_confidence=[HeuristicEntry(id="m1", pattern="p", languages=["java"])],
            context_required=[HeuristicEntry(id="c1", pattern="p", languages=["python", "go"])],
        ),
        remediation=Remediation(preferred="x"),
    )
    assert _agent_supported_languages(a) == {"python", "java", "go"}


def test_agent_supported_languages_empty_when_no_languages_declared() -> None:
    a = _make_agent("nolang", languages_per_entry=[[]])
    assert _agent_supported_languages(a) == set()


def test_agent_supported_languages_handles_string_entries() -> None:
    """Plain string heuristic entries (HeuristicItem = str | HeuristicEntry) contribute nothing."""
    a = AgentDefinition(
        meta=AgentMeta(
            name="mixed",
            display_name="X",
            domain="t",
            cwes=CWERefs(primary="CWE-1", related=[]),
        ),
        core_prompt="x",
        detection_heuristics=DetectionHeuristics(
            high_confidence=[
                "plain string heuristic",
                HeuristicEntry(id="e1", pattern="p", languages=["python"]),
            ],
        ),
        remediation=Remediation(preferred="x"),
    )
    assert _agent_supported_languages(a) == {"python"}


# ---------------------------------------------------------------------------
# `_filter_relevant_agents`
# ---------------------------------------------------------------------------


def test_filter_keeps_agent_when_languages_intersect() -> None:
    py_agent = _make_agent("py", languages_per_entry=[["python"]])
    target_codes = [ResolvedCode(file_path="x.py", content="", language="python")]
    kept, excluded = _filter_relevant_agents(target_codes, [py_agent])
    assert kept == [py_agent]
    assert excluded == []


def test_filter_drops_agent_when_languages_disjoint() -> None:
    java_agent = _make_agent("java", languages_per_entry=[["java"]])
    target_codes = [ResolvedCode(file_path="x.py", content="", language="python")]
    kept, excluded = _filter_relevant_agents(target_codes, [java_agent])
    assert kept == []
    assert len(excluded) == 1
    assert excluded[0]["agent_name"] == "java"
    assert excluded[0]["reason"] == "language_mismatch"
    assert excluded[0]["agent_languages"] == ["java"]
    assert excluded[0]["target_languages"] == ["python"]


def test_filter_keeps_agent_with_empty_language_declaration_failopen() -> None:
    """D6 fail-open: agent with no language declaration is always kept."""
    nolang = _make_agent("nolang", languages_per_entry=[[]])
    target_codes = [ResolvedCode(file_path="x.py", content="", language="python")]
    kept, excluded = _filter_relevant_agents(target_codes, [nolang])
    assert kept == [nolang]
    assert excluded == []


def test_filter_failopen_when_target_languages_empty() -> None:
    """Empty target_languages set → keep all agents (target may be non-code)."""
    py_agent = _make_agent("py", languages_per_entry=[["python"]])
    target_codes = [ResolvedCode(file_path="data.bin", content="", language=None)]
    kept, excluded = _filter_relevant_agents(target_codes, [py_agent])
    assert kept == [py_agent]
    assert excluded == []


def test_filter_uses_shebang_when_extension_lookup_returns_none() -> None:
    """File without extension match but with a known shebang contributes its language."""
    py_agent = _make_agent("py", languages_per_entry=[["python"]])
    java_agent = _make_agent("java", languages_per_entry=[["java"]])
    target_codes = [
        ResolvedCode(
            file_path="bin/myscript",
            content="#!/usr/bin/env python3\nprint('hello')\n",
            language=None,
        )
    ]
    kept, excluded = _filter_relevant_agents(target_codes, [py_agent, java_agent])
    kept_names = {a.meta.name for a in kept}
    assert kept_names == {"py"}
    assert {e["agent_name"] for e in excluded} == {"java"}
```

- [ ] **Step 2: Run new tests to verify they fail**

```
uv run pytest tests/test_relevance_filter.py -v 2>&1 | tail -25
```

Expected: ImportError or AttributeError on `language_from_shebang`, `_agent_supported_languages`, `_filter_relevant_agents` — they don't exist yet.

- [ ] **Step 3: Add `SHEBANG_MAP` and `language_from_shebang` to `treesitter.py`**

Open `src/screw_agents/treesitter.py`. After the `EXTENSION_MAP` block (lines 36-57) and the `language_from_path` function (lines 60-63), append:

```python
# Shebang interpreter → canonical language name. Restricted to languages
# present in EXTENSION_MAP / SUPPORTED_LANGUAGES so the rest of the
# pipeline (tree-sitter parsing, agent language declarations) stays
# coherent. Bash, perl, etc. map to None even if a shebang line points
# at them, since we have no parsers for those.
SHEBANG_MAP: dict[str, str] = {
    "python": "python",
    "python2": "python",
    "python3": "python",
    "ruby": "ruby",
    "node": "javascript",
    "nodejs": "javascript",
    "ts-node": "typescript",
    "tsnode": "typescript",
    "deno": "typescript",
    "php": "php",
}


def language_from_shebang(first_line: str) -> str | None:
    """Detect language from a shebang line (e.g., '#!/usr/bin/env python3').

    Returns the canonical language name (one of EXTENSION_MAP's values) or
    None if the line is not a shebang or names an unsupported interpreter.

    Examples:
        '#!/usr/bin/env python3'  -> 'python'
        '#!/usr/bin/python'       -> 'python'
        '#!/usr/bin/env ruby'     -> 'ruby'
        '#!/usr/bin/env node'     -> 'javascript'
        '#!/bin/bash'             -> None  (bash not in supported set)
        'not a shebang'           -> None
    """
    if not first_line.startswith("#!"):
        return None
    # Strip '#!' then split on whitespace; take the last token.
    # Examples: '/usr/bin/env python3' -> ['/usr/bin/env', 'python3']
    #           '/usr/bin/python'      -> ['/usr/bin/python']
    parts = first_line[2:].strip().split()
    if not parts:
        return None
    interpreter_path = parts[-1]
    interpreter = interpreter_path.rsplit("/", 1)[-1]
    return SHEBANG_MAP.get(interpreter)
```

- [ ] **Step 4: Run shebang tests to verify they pass**

```
uv run pytest tests/test_relevance_filter.py -k shebang -v 2>&1 | tail -15
```

Expected: 6 shebang tests PASS. The remaining tests still fail.

- [ ] **Step 5: Update `_detect_language` in `resolver.py` for shebang fallback**

Open `src/screw_agents/resolver.py`. Replace the `_detect_language` function at lines 92-95:

```python
def _detect_language(path: str, content: str | None = None) -> str | None:
    """Detect language from file extension first, then shebang line.

    Args:
        path: File path. Extension lookup runs first (cheap, deterministic).
        content: Optional file content. Used only when extension lookup
            returns None — first-line shebang is parsed for an interpreter
            hint. If `content` is None, shebang detection is skipped (caller
            doesn't have content handy and we don't pay an extra read).
    """
    from screw_agents.treesitter import language_from_path, language_from_shebang
    lang = language_from_path(path)
    if lang is not None:
        return lang
    if content is None:
        return None
    first_line = content.split("\n", 1)[0]
    return language_from_shebang(first_line)
```

- [ ] **Step 6: Thread `content` through all `_detect_language` callers in `resolver.py`**

In `resolver.py`, update the 7 call sites that pass `content` available locally:

(a) `_resolve_file` at line 104: change `language=_detect_language(path)` to `language=_detect_language(path, content)`.

(b) `_resolve_glob` at line 131: change `language=_detect_language(path)` to `language=_detect_language(path, content)`.

(c) `_resolve_lines` at line 158: change `language=_detect_language(path)` to `language=_detect_language(path, content)` (`content` is the full file content; first-line shebang detection still applies even when emitting a sub-range).

(d) `_resolve_function` at line 187: replace the `lang = _detect_language(path)` line with:
```python
    lang = _detect_language(path, content)
```

(e) `_resolve_class` at line 210: similarly:
```python
    lang = _detect_language(path, content)
```

(f) `_resolve_codebase` at line 249: change `language=_detect_language(str(path))` to `language=_detect_language(str(path), content)`.

(g) `_parse_unified_diff` at lines 288 and 304: change `language=_detect_language(current_file)` to `language=_detect_language(current_file, "".join(current_lines))` for both occurrences. (Diff-derived content's first line is `@@ ...` not a shebang, so shebang detection will return None — but the call still needs to pass `content` so the signature is honored.)

- [ ] **Step 7: Add `_agent_supported_languages` and `_filter_relevant_agents` to `engine.py`**

Open `src/screw_agents/engine.py`. Locate the import block at the top (around lines 1-50). Confirm `HeuristicEntry` is importable from `screw_agents.models`; if not currently imported, add to the existing imports:

```python
from screw_agents.models import HeuristicEntry  # add to existing models import line
```

Add the helpers near the top of the file, after the existing imports/constants and before the `class ScanEngine` declaration. If a private-helpers section already exists, place there; otherwise insert at module level just before the class:

```python
def _agent_supported_languages(agent: "AgentDefinition") -> set[str]:
    """Union of `languages` declarations across all HeuristicEntry items
    in the agent's three detection_heuristics buckets.

    Plain string heuristic entries (HeuristicItem = str | HeuristicEntry per
    models.py:76) contribute nothing — they have no language metadata.

    Returns:
        Set of canonical language names (from treesitter.SUPPORTED_LANGUAGES).
        Empty set when the agent declares no languages on any heuristic entry.
    """
    langs: set[str] = set()
    for bucket in (
        agent.detection_heuristics.high_confidence,
        agent.detection_heuristics.medium_confidence,
        agent.detection_heuristics.context_required,
    ):
        for entry in bucket:
            if isinstance(entry, HeuristicEntry):
                langs.update(entry.languages)
    return langs


def _filter_relevant_agents(
    target_codes: "list[ResolvedCode]",
    agents: "list[AgentDefinition]",
) -> "tuple[list[AgentDefinition], list[dict[str, Any]]]":
    """Drop agents whose declared languages don't intersect target's detected languages.

    Spec section 8.2. Two fail-open paths:
    1. Empty `target_languages` (target is non-code or unknown): keep all agents.
    2. Empty `agent_languages` (agent declares no per-heuristic languages): keep
       agent (D6 default; new agents without language declarations are not
       silently excluded).

    Args:
        target_codes: list of ResolvedCode chunks (already populated by resolve_target).
        agents: candidate agent list.

    Returns:
        (kept, excluded) where:
            kept = list of AgentDefinition surviving the filter.
            excluded = list of dicts with keys:
                agent_name, reason ("language_mismatch"),
                agent_languages (sorted list), target_languages (sorted list).
    """
    from screw_agents.treesitter import language_from_shebang

    target_languages: set[str] = set()
    for code in target_codes:
        if code.language is not None:
            target_languages.add(code.language)
            continue
        # Fallback: shebang on first line of content (handles extensionless scripts)
        first_line = code.content.split("\n", 1)[0] if code.content else ""
        lang = language_from_shebang(first_line)
        if lang is not None:
            target_languages.add(lang)

    if not target_languages:
        # Fail-open: target has no recognizable code languages. Keep all.
        return list(agents), []

    kept: "list[AgentDefinition]" = []
    excluded: "list[dict[str, Any]]" = []
    for agent in agents:
        agent_languages = _agent_supported_languages(agent)
        if not agent_languages:
            # D6 fail-open: agent with no language declarations is always kept.
            kept.append(agent)
            continue
        if agent_languages & target_languages:
            kept.append(agent)
        else:
            excluded.append(
                {
                    "agent_name": agent.meta.name,
                    "reason": "language_mismatch",
                    "agent_languages": sorted(agent_languages),
                    "target_languages": sorted(target_languages),
                }
            )
    return kept, excluded
```

- [ ] **Step 8: Run all tests to confirm helpers pass + no regression**

```
uv run pytest tests/test_relevance_filter.py -v 2>&1 | tail -25
```

Expected: all 14 tests in `test_relevance_filter.py` PASS.

```
uv run pytest -q 2>&1 | tail -5
```

Expected: 906 + 5 (Task 1) + 14 (Task 2) = 925 passed, 8 skipped. Zero failures.

If a `test_resolver.py` test fails because `_detect_language(path)` is now `_detect_language(path, content=None)` — the signature is backward-compatible (default `None`); failing tests would only result if a test directly imported and called `_detect_language(path)` with no content and asserted equivalence-to-extension-only. Such tests should still pass since `content=None` skips shebang detection entirely.

- [ ] **Step 9: Commit**

```bash
git add src/screw_agents/treesitter.py src/screw_agents/resolver.py src/screw_agents/engine.py tests/test_relevance_filter.py
git commit -m "T-SCAN-REFACTOR Task 2: relevance filter + shebang detection

Adds the two engine helpers the new scan_agents primitive depends on:

- _agent_supported_languages(agent): unions HeuristicEntry.languages
  across the three detection_heuristics buckets. Plain string entries
  contribute nothing (HeuristicItem = str | HeuristicEntry).

- _filter_relevant_agents(target_codes, agents): drops agents whose
  declared languages don't intersect target's detected languages. Two
  fail-open paths: empty target_languages (target non-code) keeps all,
  empty agent_languages (agent has no declarations) keeps that agent.

Adds shebang detection to treesitter.py:
- SHEBANG_MAP covers python/ruby/node/php variants
- language_from_shebang(first_line) returns canonical name or None

resolver._detect_language gains an optional content arg for shebang
fallback. Threaded through all 7 _resolve_* call sites.

14 tests cover: 6 shebang variants, 3 agent_supported_languages cases
(union, empty, mixed string+entry), 5 filter cases (intersect kept,
disjoint dropped, empty agent fail-open, empty target fail-open,
shebang-driven detection)."
```

---

## Task 3: `assemble_agents_scan` engine method

**Goal:** Implement the new paginated multi-agent primitive. Mirrors `assemble_domain_scan`'s init/code-page split, with cursor binding generalized to `(target_hash, agents_hash)` per Option β. Integrates the relevance filter from Task 2. Emits `agents_excluded_by_relevance` field on init-page response.

**Files:**
- Modify: `src/screw_agents/engine.py` (new method between `assemble_domain_scan` ending at line 1705 and `assemble_full_scan` at line 1707; or symmetric position before `get_agent_prompt`)
- Create: `tests/test_assemble_agents_scan.py`

**Pre-audit focus (mandatory — novel work):** read `assemble_domain_scan` lines 1509-1705 end-to-end and identify EVERY invariant it carries that `assemble_agents_scan` must mirror — cursor decode logic, target_hash binding, page_size validation, total_files semantics, init-page exclusion-loading rule (project_root only on init), code-page no-exclusion-reload rule, trust_status emission rule (init has it, code page re-emits when project_root). Also confirm that `assemble_scan` (per-agent helper at line 1421) has the `_preloaded_exclusions` and `preloaded_codes` kwargs needed for the code-page path. Map every line of `assemble_domain_scan` to a corresponding line in the new method or note the deliberate divergence (e.g., `agents_hash` vs no agents component; `agents_excluded_by_relevance` is new).

- [ ] **Step 1: Write failing tests for the new primitive**

Create `tests/test_assemble_agents_scan.py`:

```python
"""Tests for T-SCAN-REFACTOR Task 3: assemble_agents_scan primitive.

Spec sections 5.1, 8.

Coverage:
- Init-page response shape (filtered agents, agents_excluded_by_relevance,
  next_cursor, exclusions, trust_status)
- Code-page response shape
- Cursor encoding/decoding (Option β: target_hash + agents_hash bind)
- Cursor binding rejection (target mismatch, agents mismatch)
- Validation (empty agents list, unknown agent, page_size out of range)
- Pagination boundaries (single agent multi-page, multi-agent single-page)
- Project_root integration (exclusions, trust_status)
"""

from __future__ import annotations

import base64
import json as _json
from pathlib import Path

import pytest

from screw_agents.engine import ScanEngine


# ---------------------------------------------------------------------------
# Fixtures: build a small registry from the real domains/ tree
# ---------------------------------------------------------------------------


@pytest.fixture
def engine() -> ScanEngine:
    """ScanEngine loaded from the real domains/ directory."""
    domains_dir = Path(__file__).parents[1] / "domains"
    return ScanEngine(domains_dir=domains_dir)


@pytest.fixture
def small_target(tmp_path: Path) -> dict:
    """A 3-file Python target."""
    src = tmp_path / "src"
    src.mkdir()
    (src / "a.py").write_text("# python file a\nimport sqlite3\nx = sqlite3.connect(':memory:')\n")
    (src / "b.py").write_text("# python file b\nfrom flask import request\n")
    (src / "c.py").write_text("# python file c\nimport os\n")
    return {"type": "codebase", "root": str(tmp_path)}


# ---------------------------------------------------------------------------
# Init-page response shape
# ---------------------------------------------------------------------------


def test_init_page_returns_required_fields(engine: ScanEngine, small_target: dict) -> None:
    response = engine.assemble_agents_scan(
        agents=["sqli", "xss"],
        target=small_target,
    )
    assert "agents" in response
    assert "agents_excluded_by_relevance" in response
    assert "next_cursor" in response
    assert "page_size" in response
    assert "total_files" in response
    assert "code_chunks_on_page" in response
    assert "offset" in response
    # No trust_status when project_root not provided
    assert "trust_status" not in response


def test_init_page_agents_carry_meta_no_code(engine: ScanEngine, small_target: dict) -> None:
    response = engine.assemble_agents_scan(agents=["sqli"], target=small_target)
    assert response["code_chunks_on_page"] == 0
    assert response["offset"] == 0
    assert len(response["agents"]) == 1
    entry = response["agents"][0]
    assert entry["agent_name"] == "sqli"
    assert "meta" in entry
    assert "code" not in entry  # init-page has metadata only
    assert "core_prompt" not in entry  # lazy fetch via get_agent_prompt


def test_init_page_next_cursor_when_files_exist(engine: ScanEngine, small_target: dict) -> None:
    response = engine.assemble_agents_scan(agents=["sqli"], target=small_target)
    assert response["next_cursor"] is not None
    decoded = _json.loads(base64.urlsafe_b64decode(response["next_cursor"].encode("ascii")))
    assert "target_hash" in decoded
    assert "agents_hash" in decoded
    assert decoded["offset"] == 0


def test_init_page_next_cursor_null_when_no_files(engine: ScanEngine, tmp_path: Path) -> None:
    empty_target = {"type": "codebase", "root": str(tmp_path)}
    response = engine.assemble_agents_scan(agents=["sqli"], target=empty_target)
    assert response["next_cursor"] is None
    assert response["total_files"] == 0


# ---------------------------------------------------------------------------
# Cursor binding (Option β: target_hash + agents_hash)
# ---------------------------------------------------------------------------


def test_cursor_target_mismatch_raises(engine: ScanEngine, small_target: dict, tmp_path: Path) -> None:
    init = engine.assemble_agents_scan(agents=["sqli"], target=small_target)
    cursor = init["next_cursor"]
    # Different target
    other_dir = tmp_path / "other"
    other_dir.mkdir()
    (other_dir / "x.py").write_text("y = 1\n")
    other_target = {"type": "codebase", "root": str(other_dir)}
    with pytest.raises(ValueError, match="cursor is bound to a different target"):
        engine.assemble_agents_scan(agents=["sqli"], target=other_target, cursor=cursor)


def test_cursor_agents_mismatch_raises(engine: ScanEngine, small_target: dict) -> None:
    init = engine.assemble_agents_scan(agents=["sqli"], target=small_target)
    cursor = init["next_cursor"]
    with pytest.raises(ValueError, match="cursor is bound to a different agents list"):
        engine.assemble_agents_scan(agents=["sqli", "xss"], target=small_target, cursor=cursor)


def test_cursor_negative_offset_raises(engine: ScanEngine, small_target: dict) -> None:
    bad_cursor = base64.urlsafe_b64encode(
        _json.dumps({"target_hash": "x", "agents_hash": "y", "offset": -1}).encode("utf-8")
    ).decode("ascii")
    with pytest.raises(ValueError, match="offset is negative"):
        engine.assemble_agents_scan(agents=["sqli"], target=small_target, cursor=bad_cursor)


def test_cursor_malformed_raises(engine: ScanEngine, small_target: dict) -> None:
    with pytest.raises(ValueError, match="Invalid cursor"):
        engine.assemble_agents_scan(agents=["sqli"], target=small_target, cursor="not-base64!!!")


def test_cursor_agents_hash_independent_of_input_order(engine: ScanEngine, small_target: dict) -> None:
    """agents_hash is computed on sorted agents list — order in the call is irrelevant."""
    init_a = engine.assemble_agents_scan(agents=["sqli", "xss"], target=small_target)
    init_b = engine.assemble_agents_scan(agents=["xss", "sqli"], target=small_target)
    cur_a = _json.loads(base64.urlsafe_b64decode(init_a["next_cursor"].encode("ascii")))
    cur_b = _json.loads(base64.urlsafe_b64decode(init_b["next_cursor"].encode("ascii")))
    assert cur_a["agents_hash"] == cur_b["agents_hash"]


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


def test_empty_agents_list_raises(engine: ScanEngine, small_target: dict) -> None:
    with pytest.raises(ValueError, match="agents must be a non-empty list"):
        engine.assemble_agents_scan(agents=[], target=small_target)


def test_unknown_agent_raises(engine: ScanEngine, small_target: dict) -> None:
    with pytest.raises(ValueError, match="Unknown agent"):
        engine.assemble_agents_scan(agents=["nonexistent"], target=small_target)


def test_page_size_zero_raises(engine: ScanEngine, small_target: dict) -> None:
    with pytest.raises(ValueError, match="page_size must be >= 1"):
        engine.assemble_agents_scan(agents=["sqli"], target=small_target, page_size=0)


# ---------------------------------------------------------------------------
# Code-page response shape
# ---------------------------------------------------------------------------


def test_code_page_returns_code_per_agent(engine: ScanEngine, small_target: dict) -> None:
    init = engine.assemble_agents_scan(agents=["sqli"], target=small_target)
    code_response = engine.assemble_agents_scan(
        agents=["sqli"], target=small_target, cursor=init["next_cursor"]
    )
    assert code_response["code_chunks_on_page"] == 3  # 3 python files
    assert len(code_response["agents"]) == 1
    entry = code_response["agents"][0]
    assert entry["agent_name"] == "sqli"
    assert "code" in entry
    assert "resolved_files" in entry
    assert "core_prompt" not in entry  # still lazy-fetched
    # Init-only fields absent from code page
    assert "exclusions" not in entry


def test_code_page_terminates_with_null_cursor(engine: ScanEngine, small_target: dict) -> None:
    init = engine.assemble_agents_scan(agents=["sqli"], target=small_target, page_size=2)
    cursor = init["next_cursor"]
    pages = 0
    while cursor is not None:
        page = engine.assemble_agents_scan(agents=["sqli"], target=small_target, cursor=cursor, page_size=2)
        cursor = page["next_cursor"]
        pages += 1
    assert pages == 2  # 3 files / 2 per page = 2 pages (2+1)


# ---------------------------------------------------------------------------
# Relevance filter integration
# ---------------------------------------------------------------------------


def test_relevance_filter_drops_irrelevant_agents_on_init_page(engine: ScanEngine, small_target: dict) -> None:
    """All shipped agents support python; this test asserts the pipeline runs.
    Adversarial test (target lacks any agent's language) is harder to construct
    without an out-of-domain agent in the registry — covered in unit tests
    for _filter_relevant_agents (Task 2)."""
    response = engine.assemble_agents_scan(agents=["sqli"], target=small_target)
    # sqli's HeuristicEntry list declares python; target is python; agent kept
    assert any(e["agent_name"] == "sqli" for e in response["agents"])
    assert response["agents_excluded_by_relevance"] == []


def test_agents_excluded_by_relevance_is_emitted_on_init_page(engine: ScanEngine, small_target: dict) -> None:
    """Field is always present on init-page even when empty list."""
    response = engine.assemble_agents_scan(agents=["sqli"], target=small_target)
    assert "agents_excluded_by_relevance" in response
    assert isinstance(response["agents_excluded_by_relevance"], list)


# ---------------------------------------------------------------------------
# Project root integration (exclusions + trust_status)
# ---------------------------------------------------------------------------


def test_init_page_emits_trust_status_when_project_root_provided(
    engine: ScanEngine, small_target: dict, tmp_path: Path
) -> None:
    response = engine.assemble_agents_scan(
        agents=["sqli"], target=small_target, project_root=tmp_path
    )
    assert "trust_status" in response


def test_code_page_re_emits_trust_status_when_project_root_provided(
    engine: ScanEngine, small_target: dict, tmp_path: Path
) -> None:
    init = engine.assemble_agents_scan(
        agents=["sqli"], target=small_target, project_root=tmp_path
    )
    code = engine.assemble_agents_scan(
        agents=["sqli"], target=small_target, cursor=init["next_cursor"], project_root=tmp_path
    )
    assert "trust_status" in code


def test_init_page_carries_per_agent_exclusions(
    engine: ScanEngine, small_target: dict, tmp_path: Path
) -> None:
    response = engine.assemble_agents_scan(
        agents=["sqli"], target=small_target, project_root=tmp_path
    )
    entry = response["agents"][0]
    assert "exclusions" in entry
    assert isinstance(entry["exclusions"], list)


def test_code_page_does_not_re_ship_exclusions(
    engine: ScanEngine, small_target: dict, tmp_path: Path
) -> None:
    init = engine.assemble_agents_scan(
        agents=["sqli"], target=small_target, project_root=tmp_path
    )
    code = engine.assemble_agents_scan(
        agents=["sqli"], target=small_target, cursor=init["next_cursor"], project_root=tmp_path
    )
    entry = code["agents"][0]
    assert "exclusions" not in entry  # init-only field


# ---------------------------------------------------------------------------
# Multi-agent fan-out
# ---------------------------------------------------------------------------


def test_multi_agent_init_page_lists_each(engine: ScanEngine, small_target: dict) -> None:
    response = engine.assemble_agents_scan(
        agents=["sqli", "xss", "cmdi"], target=small_target
    )
    names = {e["agent_name"] for e in response["agents"]}
    assert names == {"sqli", "xss", "cmdi"}


def test_multi_agent_code_page_fans_out_per_agent(engine: ScanEngine, small_target: dict) -> None:
    init = engine.assemble_agents_scan(
        agents=["sqli", "xss"], target=small_target
    )
    code = engine.assemble_agents_scan(
        agents=["sqli", "xss"], target=small_target, cursor=init["next_cursor"]
    )
    names = {e["agent_name"] for e in code["agents"]}
    assert names == {"sqli", "xss"}
    # Each agent entry has same code (target same; agents fan out per code page)
    for entry in code["agents"]:
        assert "code" in entry
```

- [ ] **Step 2: Run new tests to verify they fail**

```
uv run pytest tests/test_assemble_agents_scan.py -v 2>&1 | tail -30
```

Expected: AttributeError on `engine.assemble_agents_scan` — method doesn't exist yet.

- [ ] **Step 3: Add `assemble_agents_scan` method to `ScanEngine`**

Open `src/screw_agents/engine.py`. Locate `assemble_domain_scan` ending at line 1705 (closing of its `return result` block). Insert the new method between `assemble_domain_scan` and `assemble_full_scan`. The new method mirrors `assemble_domain_scan`'s structure with three deliberate changes: (a) takes `agents: list[str]` directly instead of resolving from a `domain` arg, (b) cursor encodes an additional `agents_hash` field, (c) emits `agents_excluded_by_relevance` on the init-page response.

```python
    def assemble_agents_scan(
        self,
        agents: list[str],
        target: dict[str, Any],
        thoroughness: str = "standard",
        project_root: Path | None = None,
        *,
        cursor: str | None = None,
        page_size: int = 50,
    ) -> dict[str, Any]:
        """Assemble paginated scan payloads for a custom selection of agents.

        T-SCAN-REFACTOR primitive (spec section 5.1). Generalizes
        ``assemble_domain_scan`` to an arbitrary agents list; the cursor binds
        to ``(target_hash, agents_hash)`` (Option β) rather than just the
        target. Per-agent language relevance filter applied on init page;
        excluded agents surface in ``agents_excluded_by_relevance`` field.

        The response has TWO shapes keyed by the cursor discriminator:

        **Init page (cursor is None):** Returns per-agent metadata (and, if
        ``project_root`` is set, agent-scoped exclusions) without any code,
        plus the relevance-filter exclusion list. Each per-agent ``agents``
        entry carries ``agent_name`` and ``meta`` but NO ``core_prompt`` and
        NO ``code``. There is NO top-level ``prompts`` dict — orchestrators
        fetch each agent's prompt lazily via ``get_agent_prompt`` on first
        encounter and cache for reuse across code pages.
        ``code_chunks_on_page == 0`` and ``offset == 0``. ``next_cursor``
        encodes offset=0 when files exist (pointing at the first code page);
        it is None when there is nothing to paginate (empty target or all
        agents filtered out).

        **Code page (cursor is set):** Emits a paged slice of code chunks
        fanned out per agent. Per-agent entries carry ``code``,
        ``resolved_files``, ``meta`` — no ``core_prompt``, no ``exclusions``
        (exclusions are init-only), no ``agents_excluded_by_relevance`` (also
        init-only). ``trust_status`` is re-emitted at the top level when
        ``project_root`` is provided so any single page carries the
        quarantine counts.

        Cursor encoding (Option β):
            cursor = base64url(json({
                "target_hash":  sha256(canonical_target_json)[:16],
                "agents_hash":  sha256(",".join(sorted(agents)))[:16],
                "offset":       <int>
            }))

        Args:
            agents: list of registered agent names. Must be non-empty; every
                name must exist in the registry.
            target: PRD §5 target spec dict.
            thoroughness: passed through to per-agent assemble_scan
                ("standard" | "deep").
            project_root: optional project root for exclusions + trust_status.
            cursor: opaque pagination token from a previous call; None
                requests the init page.
            page_size: max number of resolved code chunks per page (default 50).

        Returns:
            Dict with keys shared across both shapes:
                agents: list[dict[str, Any]]
                next_cursor: str | None
                page_size: int
                total_files: int
                offset: int
                code_chunks_on_page: int
                trust_status: dict  (only when project_root is provided)
            Init-page only:
                agents_excluded_by_relevance: list[dict] -- {agent_name, reason,
                    agent_languages, target_languages}
            Neither shape emits a top-level ``prompts`` key; callers must use
            ``get_agent_prompt(agent_name, thoroughness)`` instead.

        Raises:
            ValueError: if `agents` is empty, contains an unknown agent name,
                if `page_size < 1`, or if cursor is bound to a different
                target / agents list / is malformed.
        """
        # ---- Validation ----
        if not agents:
            raise ValueError(
                "agents must be a non-empty list; pass at least one registered agent name"
            )
        if page_size < 1:
            raise ValueError(f"page_size must be >= 1, got {page_size}")
        for name in agents:
            if self._registry.get_agent(name) is None:
                raise ValueError(f"Unknown agent: {name!r}")

        # ---- Hashing inputs (cursor binding — Option β) ----
        canonical_target = _json.dumps(target, sort_keys=True, separators=(",", ":"))
        target_hash = hashlib.sha256(canonical_target.encode("utf-8")).hexdigest()[:16]
        sorted_agents = sorted(agents)
        agents_hash = hashlib.sha256(",".join(sorted_agents).encode("utf-8")).hexdigest()[:16]

        # ---- Cursor decode (preserves existing ValueError semantics) ----
        if cursor:
            try:
                decoded = _json.loads(
                    base64.urlsafe_b64decode(cursor.encode("ascii")).decode("utf-8")
                )
                if decoded.get("target_hash") != target_hash:
                    raise ValueError(
                        "cursor is bound to a different target; refusing to use"
                    )
                if decoded.get("agents_hash") != agents_hash:
                    raise ValueError(
                        "cursor is bound to a different agents list; refusing to use"
                    )
                offset = int(decoded["offset"])
                if offset < 0:
                    raise ValueError("cursor offset is negative")
            except ValueError:
                raise
            except Exception as exc:
                raise ValueError(f"Invalid cursor: {exc}") from exc
        else:
            offset = 0

        # ---- Resolve agents from registry; resolve target once ----
        agent_defs = [self._registry.get_agent(n) for n in agents]
        all_codes = resolve_target(target)
        total_files = len(all_codes)

        is_init_page = cursor is None

        # ---- Init page: relevance filter + metadata + exclusions ----
        if is_init_page:
            kept_agents, excluded = _filter_relevant_agents(all_codes, agent_defs)

            if project_root is not None:
                all_exclusions: list[Exclusion] | None = load_exclusions(project_root)
            else:
                all_exclusions = None

            agents_responses: list[dict[str, Any]] = []
            for a in kept_agents:
                entry: dict[str, Any] = {
                    "agent_name": a.meta.name,
                    "meta": self._agent_meta_summary(a),
                }
                if project_root is not None and all_exclusions is not None:
                    agent_exclusions = [
                        e for e in all_exclusions
                        if e.agent == a.meta.name and not e.quarantined
                    ]
                    entry["exclusions"] = [e.model_dump() for e in agent_exclusions]
                agents_responses.append(entry)

            # Compute next_cursor — None when nothing to paginate.
            # Note: kept_agents may be empty (all filtered out) — in that
            # case there's nothing to scan even if files exist.
            if total_files > 0 and kept_agents:
                next_cursor: str | None = base64.urlsafe_b64encode(
                    _json.dumps(
                        {
                            "target_hash": target_hash,
                            "agents_hash": agents_hash,
                            "offset": 0,
                        },
                        separators=(",", ":"),
                    ).encode("utf-8")
                ).decode("ascii")
            else:
                next_cursor = None

            result: dict[str, Any] = {
                "agents": agents_responses,
                "agents_excluded_by_relevance": excluded,
                "next_cursor": next_cursor,
                "page_size": page_size,
                "total_files": total_files,
                "code_chunks_on_page": 0,
                "offset": 0,
            }
            if project_root is not None:
                result["trust_status"] = self.verify_trust(
                    project_root=project_root, exclusions=all_exclusions
                )
            return result

        # ---- Code page (cursor was non-None) ----
        # Re-apply the relevance filter so the same kept_agents set is
        # iterated — must match init-page result deterministically since
        # cursor's agents_hash already binds the call.
        kept_agents, _excluded_unused = _filter_relevant_agents(all_codes, agent_defs)

        page_codes = all_codes[offset : offset + page_size]
        next_offset = offset + len(page_codes)
        if next_offset < total_files:
            next_cursor = base64.urlsafe_b64encode(
                _json.dumps(
                    {
                        "target_hash": target_hash,
                        "agents_hash": agents_hash,
                        "offset": next_offset,
                    },
                    separators=(",", ":"),
                ).encode("utf-8")
            ).decode("ascii")
        else:
            next_cursor = None

        agents_responses = [
            self.assemble_scan(
                a.meta.name,
                target,
                thoroughness,
                project_root,
                preloaded_codes=page_codes,
                _preloaded_exclusions=[],
                include_prompt=False,
            )
            for a in kept_agents
        ]

        for entry in agents_responses:
            entry.pop("exclusions", None)
            entry.pop("trust_status", None)

        result = {
            "agents": agents_responses,
            "next_cursor": next_cursor,
            "page_size": page_size,
            "total_files": total_files,
            "code_chunks_on_page": len(page_codes),
            "offset": offset,
        }
        if project_root is not None:
            result["trust_status"] = self.verify_trust(project_root=project_root)
        return result
```

- [ ] **Step 4: Run new tests to verify they pass**

```
uv run pytest tests/test_assemble_agents_scan.py -v 2>&1 | tail -30
```

Expected: all ~20 tests in `test_assemble_agents_scan.py` PASS.

- [ ] **Step 5: Run full test suite to confirm no regression**

```
uv run pytest -q 2>&1 | tail -5
```

Expected: 925 + 20 (new this task) = ~945 passed, 8 skipped. Zero failures.

- [ ] **Step 6: Commit**

```bash
git add src/screw_agents/engine.py tests/test_assemble_agents_scan.py
git commit -m "T-SCAN-REFACTOR Task 3: assemble_agents_scan paginated primitive

Adds the new multi-agent paginated scan engine method. Mirrors
assemble_domain_scan's init/code-page architecture with three deliberate
changes:

1. Takes agents: list[str] directly instead of resolving from a domain
   arg (the slash command and any direct caller resolves the agent set).

2. Cursor binding generalized to (target_hash, agents_hash) per Option β.
   agents_hash = sha256(','.join(sorted(agents)))[:16] — order-invariant.
   Mismatch on either field raises ValueError. Catches mid-flow drift
   where the caller changes the agents list between page requests.

3. Init-page response carries agents_excluded_by_relevance: list[dict]
   surfacing the per-agent language relevance filter's decisions
   (agent_name, reason, agent_languages, target_languages).

Validation: empty agents list, unknown agent name, page_size < 1 all
raise ValueError. Tests cover ~20 paths spanning response shape, cursor
encoding/decoding, binding rejection, validation, pagination boundaries,
multi-agent fan-out, project_root integration."
```

---

## Task 4: Refactor `assemble_domain_scan` as wrapper

**Goal:** Replace the body of `assemble_domain_scan` (~180 LOC of pagination logic at lines 1509-1705) with a thin delegation to `assemble_agents_scan`. Schema unchanged from caller's view; tests asserting `scan_domain` behavior still pass.

**Files:**
- Modify: `src/screw_agents/engine.py:1509-1705` (the entire `assemble_domain_scan` method body)
- No test changes expected — `test_engine.py`'s domain-scan tests should pass unchanged because the response shape is identical.

**Pre-audit focus (mandatory):** before replacing the body, run `grep -n "scan_domain\|assemble_domain_scan" tests/` and audit every assertion site. Confirm none of them inspect `agents_excluded_by_relevance` — that's a new init-page field that `assemble_domain_scan` will now also emit (since it delegates). Tests that don't care about this field will pass; any test that asserts `assert set(response.keys()) == {EXACT_SET}` would fail. List those for the implementer to handle.

- [ ] **Step 1: Pre-audit — find domain-scan key-set assertions**

```
grep -rn 'assemble_domain_scan\|"scan_domain"' tests/ | head -20
grep -rn 'response\.keys()\|set(response' tests/test_engine.py tests/test_phase2_server.py
```

Expected: no exact `set(keys)` equality assertions. The existing tests check individual keys via `assert "X" in response` and `assert response["X"] == ...`. Adding `agents_excluded_by_relevance` to the init-page response is purely additive and breaks none of them.

If any test asserts the EXACT key set: that test must be updated (Task 4 Step 5 below covers this case if it arises).

- [ ] **Step 2: Replace `assemble_domain_scan` body with delegation**

Open `src/screw_agents/engine.py`. Replace lines 1509-1705 (the entire `assemble_domain_scan` method) with:

```python
    def assemble_domain_scan(
        self,
        domain: str,
        target: dict[str, Any],
        thoroughness: str = "standard",
        project_root: Path | None = None,
        *,
        cursor: str | None = None,
        page_size: int = 50,
    ) -> dict[str, Any]:
        """Convenience wrapper: scan all agents in a CWE-1400 domain.

        T-SCAN-REFACTOR Task 4: now a thin shortcut over ``assemble_agents_scan``.
        Equivalent to:

            scan_agents(
                agents=[a.meta.name for a in registry.get_agents_by_domain(domain)],
                ...
            )

        The response shape additions versus pre-T-SCAN-REFACTOR:
        - Init-page now carries ``agents_excluded_by_relevance`` (the per-agent
          language relevance filter is applied via the underlying primitive).

        The response shape additions versus the old domain-scoped scan are
        purely additive; no existing key changed type or semantics.

        Use ``scan_agents`` directly to scan an arbitrary subset of agents
        (e.g., 2 of 10 in a domain, or agents from multiple domains).

        Args:
            domain: CWE-1400 domain name (e.g. "injection-input-handling").
            target: PRD §5 target spec dict.
            thoroughness: passed through ("standard" | "deep").
            project_root: optional project root for exclusions + trust_status.
            cursor: opaque pagination token; None requests init page.
            page_size: max code chunks per page (default 50).

        Returns:
            Same shape as ``assemble_agents_scan`` plus a top-level "domain"
            key for backward compatibility with pre-T-SCAN-REFACTOR callers.

        Raises:
            ValueError: if domain is unknown or the underlying agents-scan
                raises (cursor binding mismatch, etc.).
        """
        agents_in_domain = self._registry.get_agents_by_domain(domain)
        if not agents_in_domain:
            raise ValueError(f"Unknown or empty domain: {domain!r}")
        agent_names = [a.meta.name for a in agents_in_domain]

        result = self.assemble_agents_scan(
            agents=agent_names,
            target=target,
            thoroughness=thoroughness,
            project_root=project_root,
            cursor=cursor,
            page_size=page_size,
        )
        # Preserve historical "domain" key so existing test assertions and
        # external readers see no shape regression.
        result["domain"] = domain
        return result
```

- [ ] **Step 3: Run domain-scan tests to verify behavior preserved**

```
uv run pytest tests/test_engine.py -k 'assemble_domain or scan_domain' -v 2>&1 | tail -30
```

Expected: all existing `assemble_domain_scan` tests PASS unchanged.

- [ ] **Step 4: Run full test suite to confirm no regression**

```
uv run pytest -q 2>&1 | tail -5
```

Expected: ~945 passed (no change from end of Task 3 — Task 4 swaps internals but adds no new tests). Zero failures.

- [ ] **Step 5: If any test failed because the response key set changed**

Inspect the failing assertion. If it compares to a literal frozenset of keys, update the literal to include `agents_excluded_by_relevance`. Document the change with a comment referencing T-SCAN-REFACTOR Task 4. If failure was for any other reason: stop and re-audit.

- [ ] **Step 6: Commit**

```bash
git add src/screw_agents/engine.py
git commit -m "T-SCAN-REFACTOR Task 4: assemble_domain_scan now delegates to assemble_agents_scan

Replaces ~180 LOC of pagination/cursor/filter logic in assemble_domain_scan
with a 12-line wrapper that:
1. Resolves the agent name list from registry.get_agents_by_domain(domain)
2. Calls assemble_agents_scan(agents=names, ...) with all other args passed through
3. Adds the historical 'domain' key to the response for backward compat

Net effect: scan_domain MCP tool's behavior is unchanged from caller's
view EXCEPT init-page response now carries agents_excluded_by_relevance
(additive, no existing key changed). Cursor protocol unchanged from the
domain-scan caller's perspective; the underlying primitive's binding
includes agents_hash but the wrapper passes the same agent set on every
page so binding always matches.

Eliminates code duplication: one paginated scan implementation, two
public surfaces (the primitive + the convenience wrapper)."
```

---

## Task 5: `scan_agents` MCP tool registration

**Goal:** Wire `assemble_agents_scan` into the MCP server: register the tool in `engine.py::list_tool_definitions` and dispatch in `server.py::handle_call_tool`.

**Files:**
- Modify: `src/screw_agents/engine.py:2165+` (`list_tool_definitions`)
- Modify: `src/screw_agents/server.py:240-280` (`handle_call_tool`)
- Modify: `tests/test_server.py` and `tests/test_engine.py` (assertions on registered tool list)

**Pre-audit focus (none — mechanical):** inline-verify by reading the existing scan_domain registration (lines 2194-2230) and mirroring its shape. Confirm `_scan_input_schema` helper signature.

- [ ] **Step 1: Add `scan_agents` registration to `list_tool_definitions`**

Open `src/screw_agents/engine.py`. Locate `list_tool_definitions` at line 2165. After the existing `scan_domain` registration (ends line 2230) and before the existing `scan_full` registration block at lines 2231-2245, insert the new `scan_agents` registration:

```python
        tools.append({
            "name": "scan_agents",
            "description": (
                "Run a custom selection of agents against the target. The new "
                "T-SCAN-REFACTOR primitive — supersedes scan_full and the "
                "per-agent scan_<name> tools (retired). Returns a paginated "
                "response: {agents, agents_excluded_by_relevance, next_cursor, "
                "page_size, total_files, offset, trust_status?}. Subagents MUST "
                "loop until next_cursor is None before calling "
                "finalize_scan_results. The cursor binds to (target_hash, "
                "agents_hash) — passing a different agents list on a follow-up "
                "page raises ValueError."
            ),
            "input_schema": self._scan_input_schema(
                extra_required=["target", "agents"],
                extra_props={
                    "target": _target_schema(),
                    "agents": {
                        "type": "array",
                        "items": {"type": "string"},
                        "minItems": 1,
                        "description": (
                            "List of registered agent names. Must be non-empty; "
                            "every name must exist in the registry. Use "
                            "list_agents() to discover names."
                        ),
                    },
                    "thoroughness": _thoroughness_schema(),
                    "project_root": _project_root_schema(),
                    "cursor": {
                        "type": ["string", "null"],
                        "description": (
                            "Opaque pagination token from a previous scan_agents "
                            "call. Pass null (or omit) on the first call. When "
                            "next_cursor in the response is null, pagination is "
                            "complete."
                        ),
                        "default": None,
                    },
                    "page_size": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 500,
                        "description": "Max resolved code chunks per page (default 50).",
                        "default": 50,
                    },
                },
            ),
        })
```

- [ ] **Step 2: Update `scan_domain` description to reference the primitive**

In the same file, locate the `scan_domain` registration (lines 2194-2230). Update its description string to:

```python
            "description": (
                "Convenience shortcut for scan_agents — runs all registered "
                "agents in the named CWE-1400 domain. Equivalent to "
                "scan_agents(agents=list_agents(domain=<X>).names, ...). Use "
                "scan_agents directly to scan an arbitrary subset of agents. "
                "Returns a paginated response: {agents, "
                "agents_excluded_by_relevance, next_cursor, page_size, "
                "total_files, offset, trust_status?, domain}. Subagents MUST "
                "loop until next_cursor is None before calling "
                "finalize_scan_results."
            ),
```

- [ ] **Step 3: Add `scan_agents` dispatch to `server.py::handle_call_tool`**

Open `src/screw_agents/server.py`. Locate the dispatch block around lines 244-259. After the existing `if name == "scan_domain": ...` branch (ends line 252) and before the `if name == "scan_full":` branch (starts line 254), insert:

```python
    if name == "scan_agents":
        return engine.assemble_agents_scan(
            agents=args["agents"],
            target=args["target"],
            thoroughness=args.get("thoroughness", "standard"),
            project_root=project_root,
            cursor=args.get("cursor"),
            page_size=args.get("page_size", 50),
        )
```

- [ ] **Step 4: Add server-level test for the dispatch**

Open `tests/test_server.py`. Find the test that verifies tool names are registered (the existing `assert "scan_full" in names` at line 25 area). Add a new assertion immediately after the existing list:

```python
    assert "scan_agents" in names
```

Then append a new test function at the end of the file:

```python
def test_scan_agents_dispatch_via_server(tmp_path: Path) -> None:
    """server.handle_call_tool routes scan_agents to engine.assemble_agents_scan."""
    from screw_agents.server import create_server

    src = tmp_path / "src"
    src.mkdir()
    (src / "x.py").write_text("import sqlite3\n")

    server, engine = create_server()  # uses default domains/ tree
    # The server interface is async; for the dispatch path we call
    # engine.assemble_agents_scan directly via the dispatch helper.
    # In test_server.py the existing pattern uses engine directly — match that.
    response = engine.assemble_agents_scan(
        agents=["sqli"],
        target={"type": "codebase", "root": str(tmp_path)},
    )
    assert "agents" in response
    assert any(a["agent_name"] == "sqli" for a in response["agents"])
```

(Adjust the import path / dispatch invocation pattern to match `test_server.py`'s existing style — read the file's existing tests first to see whether `create_server` is imported or `ScanEngine` directly.)

- [ ] **Step 5: Update `test_engine.py` per-tool-name assertion**

Open `tests/test_engine.py`. Locate line 79 with the assertion `assert "scan_full" in tool_names`. The line will be deleted in Task 6, but for now add immediately after it:

```python
    assert "scan_agents" in tool_names
```

- [ ] **Step 6: Run all tests; confirm scan_agents is registered**

```
uv run pytest tests/test_engine.py tests/test_server.py -k 'scan_agents or tool_names or registered' -v 2>&1 | tail -25
```

Expected: tests asserting `scan_agents` is registered PASS. The pre-existing `scan_full` assertions still pass (Task 6 deletes them).

- [ ] **Step 7: Run full test suite**

```
uv run pytest -q 2>&1 | tail -5
```

Expected: ~945 + 1 (new dispatch test) = ~946 passed. Zero failures.

- [ ] **Step 8: Commit**

```bash
git add src/screw_agents/engine.py src/screw_agents/server.py tests/test_server.py tests/test_engine.py
git commit -m "T-SCAN-REFACTOR Task 5: scan_agents MCP tool registration

Wires assemble_agents_scan into the MCP server:

- engine.list_tool_definitions: registers scan_agents tool with input
  schema (agents: array<string> minItems=1, target, thoroughness,
  project_root, cursor, page_size).

- engine.list_tool_definitions: scan_domain description updated to
  reference scan_agents and document the equivalence — clarity guardrail
  per spec section 5.5 (every convenience tool's description starts with
  'Convenience shortcut for X' and includes the equivalence).

- server.handle_call_tool: scan_agents dispatch branch routes to
  engine.assemble_agents_scan with agents/target/thoroughness/project_root/
  cursor/page_size args.

- tests/test_server.py: new dispatch test confirms server route.
- tests/test_engine.py: scan_agents registered in tool_names.

scan_full and per-agent scan_<name> tools remain registered until Task 6
retires them — Task 5 is purely additive."
```

---

## Task 6: Retirements — `assemble_full_scan`, `scan_full` MCP tool, per-agent `scan_<name>` tools

**Goal:** Hard-break retirement of the three retired surfaces. Delete the engine method, the MCP tool registrations (the static `scan_full` block + the per-agent loop), the dispatch branches in `server.py`, and the corresponding tests.

**Files:**
- Modify: `src/screw_agents/engine.py` — delete `assemble_full_scan` (lines 1707-1774); delete `scan_full` registration in `list_tool_definitions` (lines 2231-2245); delete per-agent registration loop (lines 2275-2291).
- Modify: `src/screw_agents/server.py` — delete `scan_full` branch (lines 254-259); delete per-agent fallback dispatch (lines 269-276).
- Modify: `tests/test_engine.py` — delete `test_assemble_full_scan_*` tests (lines 303-411 area; 4 tests).
- Modify: `tests/test_server.py` — delete or migrate `assert "scan_full" in names` (line 25).
- Modify: `tests/test_phase2_server.py` — change `t["name"] in ("scan_domain", "scan_full")` (line 211) to `("scan_domain", "scan_agents")`.
- Modify: `tests/test_prompt_dedup_roundtrip.py` — migrate `test_domain_scan_full_walk_*` tests (lines 25, 75) to use `scan_agents`.

**Pre-audit focus (mandatory):** before deletion, grep for `scan_full|assemble_full_scan` across `src/`, `tests/`, `plugins/`, and `docs/` (excluding docs/specs and PHASE_*_PLAN.md historical references). Catalog every remaining hit. Each should map to: (a) deletable test, (b) test to migrate to `scan_agents`, or (c) doc to update in Task 9.

- [ ] **Step 1: Pre-audit grep**

```
grep -rn 'scan_full\|assemble_full_scan' src/ tests/ plugins/ 2>/dev/null | grep -v __pycache__
grep -rn 'scan_sqli\|scan_cmdi\|scan_ssti\|scan_xss' src/ tests/ plugins/ 2>/dev/null | grep -v __pycache__
```

Capture the output. Every per-agent `scan_<name>` MCP tool reference in `tests/` must be migrated. Every `scan_full` reference in `tests/` must be deleted (the tool is gone) or migrated to use `scan_agents` for equivalent coverage.

- [ ] **Step 2: Delete `assemble_full_scan` from `engine.py`**

Open `src/screw_agents/engine.py`. Delete lines 1707-1774 (the entire `assemble_full_scan` method, from `def assemble_full_scan(` through its trailing `return result`).

- [ ] **Step 3: Delete `scan_full` registration in `list_tool_definitions`**

In the same file, delete lines 2231-2245 (the `tools.append({"name": "scan_full", ...})` block).

- [ ] **Step 4: Delete per-agent registration loop**

In the same file, delete lines 2275-2291 (the `for agent in self._registry.agents.values(): tools.append({...})` loop).

- [ ] **Step 5: Delete `scan_full` and per-agent dispatch branches in `server.py`**

Open `src/screw_agents/server.py`. Delete lines 254-259 (the `if name == "scan_full":` branch). Delete lines 269-276 (the `if name.startswith("scan_"):` per-agent fallback). After deletion the dispatch block reads (`scan_domain` → `scan_agents` → `get_agent_prompt` → `raise ValueError(f"Unknown tool: {name!r}")`).

- [ ] **Step 6: Delete `test_assemble_full_scan_*` tests**

Open `tests/test_engine.py`. Delete the 4 functions:
- `test_assemble_full_scan_with_project_root` (around line 303)
- `test_assemble_full_scan_returns_dict_shape` (around line 349)
- `test_assemble_full_scan_no_longer_emits_prompts` (around line 372)
- `test_assemble_full_scan_includes_trust_status_when_project_root_set` (around line 396)

Also remove line 79: `assert "scan_full" in tool_names` (was kept through Task 5 alongside `assert "scan_agents" in tool_names`; now scan_full is gone).

- [ ] **Step 7: Migrate or delete `scan_full` references in other test files**

`tests/test_server.py` line 25:

```python
# Before:
assert "scan_full" in names
# After (delete the line entirely; scan_agents is asserted on the line below it):
```

`tests/test_phase2_server.py` line 211:

```python
# Before:
if t["name"].startswith("scan_") or t["name"] in ("scan_domain", "scan_full"):
# After:
if t["name"].startswith("scan_") or t["name"] in ("scan_domain", "scan_agents"):
```

(This branch's intent was to apply the `project_root` injection to all scan-shaped tools; with `scan_agents` replacing `scan_full` and per-agent tools gone, the `startswith("scan_")` check still catches `scan_domain` and `scan_agents` — the `or t["name"] in (...)` clause becomes redundant but harmless. Leave it for the explicit-listing safety net. The change above just makes it match reality.)

`tests/test_prompt_dedup_roundtrip.py` lines 25 and 75 (`test_domain_scan_full_walk_*`): rewrite both as `scan_agents`-based round-trips. Replace each test body's `engine.assemble_full_scan(target=target)` call with:

```python
        # The pre-T-SCAN-REFACTOR test exercised assemble_full_scan walking
        # all agents. The post-T-SCAN-REFACTOR equivalent is
        # assemble_agents_scan with all registered names, paginated.
        all_agent_names = list(engine._registry.agents)
        result = engine.assemble_agents_scan(
            agents=all_agent_names,
            target=target,
        )
        # init-page; no inline prompts (lazy-fetch via get_agent_prompt)
        assert all("core_prompt" not in entry for entry in result["agents"])
```

(Adjust the assertion bodies of both tests in the same way: replace any reference to a top-level `prompts` dict assertion with the lazy-fetch assertion above. The original tests were specifically validating prompt deduplication; the equivalent assertion for the new primitive is "no agent entry contains `core_prompt` on init-page".)

- [ ] **Step 8: Run all migrated/affected tests**

```
uv run pytest tests/test_engine.py tests/test_server.py tests/test_phase2_server.py tests/test_prompt_dedup_roundtrip.py -v 2>&1 | tail -30
```

Expected: all PASS. Test count drops by ~6-8 (4 deleted full-scan tests + 2 migrated round-trip tests now have new function names if renamed).

- [ ] **Step 9: Run full test suite — confirm clean retirement**

```
uv run pytest -q 2>&1 | tail -5
```

Expected: ~946 - ~8 (deletions) = ~938 passed, 8 skipped. Zero failures.

If a test fails because it called `engine.assemble_scan(name)` for a per-agent tool through some indirect path: the engine method `assemble_scan(name, ...)` itself is preserved (it's the per-agent helper used internally by both `assemble_agents_scan` and `assemble_domain_scan`); only the **MCP tool** dispatch branch was deleted. Direct `engine.assemble_scan(...)` calls in tests work unchanged.

- [ ] **Step 10: Grep verification — zero residual references**

```
grep -rn 'assemble_full_scan\|"scan_full"' src/ tests/ plugins/ 2>/dev/null | grep -v __pycache__
```

Expected: NO output. Every reference has been deleted or migrated.

```
grep -rn 'scan_sqli\b\|scan_cmdi\b\|scan_ssti\b\|scan_xss\b' src/ plugins/ 2>/dev/null | grep -v __pycache__ | grep -v 'mcp__'
```

Expected: NO output in `src/`. Per-agent tool name strings in `plugins/` are still in subagent files (deleted in Task 7) and in `scan.md` (rewritten in Task 8). Those are owed to later tasks and intentional.

- [ ] **Step 11: Commit**

```bash
git add src/screw_agents/engine.py src/screw_agents/server.py tests/test_engine.py tests/test_server.py tests/test_phase2_server.py tests/test_prompt_dedup_roundtrip.py
git commit -m "T-SCAN-REFACTOR Task 6: retire scan_full + per-agent MCP tools

Hard-break retirement (no compat shim — zero live external callers).

src/screw_agents/engine.py:
- Delete assemble_full_scan method (~70 LOC)
- Delete scan_full registration in list_tool_definitions
- Delete per-agent registration loop in list_tool_definitions

src/screw_agents/server.py:
- Delete scan_full dispatch branch in handle_call_tool
- Delete per-agent scan_<name> dispatch fallback

tests/test_engine.py:
- Delete 4 test_assemble_full_scan_* tests (full-scan engine method gone)
- Drop 'scan_full' from tool_names assertion

tests/test_server.py:
- Drop 'scan_full' from name presence assertion

tests/test_phase2_server.py:
- Migrate 'scan_full' tuple membership to 'scan_agents'

tests/test_prompt_dedup_roundtrip.py:
- Migrate test_domain_scan_full_walk_* to scan_agents-based round-trips
- Equivalent assertion: lazy-fetch via per-agent get_agent_prompt (no
  inline core_prompt on init-page entries)

Net effect: MCP scan-shaped tool surface goes from 6 (scan_full +
scan_domain + 4 per-agent) to 2 (scan_agents + scan_domain). At
CWE-1400 expansion would have been 43 → still 2."
```

---

## Task 7: Universal `screw-scan.md` subagent + delete 5 old subagent files

**Goal:** Collapse 4 per-agent subagents (`screw-sqli`, `screw-cmdi`, `screw-ssti`, `screw-xss`; 414 LOC each, byte-identical modulo name) and 1 domain orchestrator (`screw-injection`; 222 LOC) into a single universal `screw-scan.md` (~420 LOC) parameterized by `agents: list[str]` from the dispatch prompt.

**Files:**
- Create: `plugins/screw/agents/screw-scan.md`
- Delete: `plugins/screw/agents/screw-sqli.md`, `screw-cmdi.md`, `screw-ssti.md`, `screw-xss.md`, `screw-injection.md`
- Modify: `plugins/screw/plugin.json` (or equivalent registration file — confirm path during pre-audit) — drop the 5 deleted subagent registrations, add `screw-scan` registration.
- Create: `tests/test_screw_scan_subagent.py` — 5 tests for file presence, frontmatter, return-payload size regression.

**Pre-audit focus (mandatory — novel work):** before writing `screw-scan.md`, read `screw-sqli.md` end-to-end (414 lines) and identify EVERY procedural element that must be parameterized by agent name vs preserved verbatim. Read `screw-injection.md` (222 lines) to confirm the domain-orchestrator's dispatch responsibilities are now subsumed by main session (per C2 finding). Read `plugins/screw/plugin.json` (or scan `plugins/screw/` for the registration mechanism — could be a `marketplace.json`, `plugin.json`, or implicit by file presence) to know exactly which file lists subagent names.

- [ ] **Step 1: Pre-audit — confirm registration mechanism**

```
ls /home/marco/Programming/AI/screw-agents/plugins/screw/
cat /home/marco/Programming/AI/screw-agents/plugins/screw/plugin.json 2>/dev/null || echo 'no plugin.json'
find /home/marco/Programming/AI/screw-agents/plugins/screw/ -maxdepth 2 -type f -name '*.json' -o -name '*.yaml' -o -name '*.yml'
```

Identify the file (if any) that explicitly registers subagents. If subagents are registered implicitly by file presence in `plugins/screw/agents/*.md`, no manifest edit is required; deleting the 5 files and adding `screw-scan.md` suffices.

- [ ] **Step 2: Read the existing subagent template**

```
sed -n '1,30p' /home/marco/Programming/AI/screw-agents/plugins/screw/agents/screw-sqli.md
```

Capture the YAML frontmatter shape (name, description, tools, model, etc.) — `screw-scan.md`'s frontmatter must mirror it.

- [ ] **Step 3: Create `screw-scan.md` with full procedural body**

Create `/home/marco/Programming/AI/screw-agents/plugins/screw/agents/screw-scan.md`:

```markdown
---
name: screw-scan
description: Universal security scan runner — analyzes code against a custom set of agents specified by the dispatcher. Replaces 4 per-agent subagents and 1 domain orchestrator. Handles paginated scan_agents calls, lazy prompt fetching, finding accumulation, and structured-payload return.
tools:
  - Read
  - Grep
  - mcp__screw-agents__scan_agents
  - mcp__screw-agents__get_agent_prompt
  - mcp__screw-agents__accumulate_findings
  - mcp__screw-agents__record_context_required_match
  - mcp__screw-agents__verify_trust
model: opus
---

# Universal Security Scan Runner (screw-scan)

You are the universal scan runner for the screw-agents framework. The main session dispatches you with a resolved list of agents to run against a target. Your job: paginate through `scan_agents`, fetch each agent's detection prompt lazily on first encounter, analyze the returned code with that prompt, accumulate findings via `accumulate_findings`, and return a structured payload to the main session.

You **do not** dispatch other subagents. Per Claude Code's documented architecture, subagents cannot spawn other subagents (`sub-agents.md:711`). Any chaining (e.g., to `screw-script-reviewer` for adaptive flows) is the main session's responsibility, not yours.

## Inputs

The main session's dispatch prompt provides:

- `agents: list[str]` — registered agent names to run (already resolved + relevance-filtered by main session)
- `target: dict` — PRD §5 target spec (e.g., `{"type": "codebase", "root": "/path"}`)
- `project_root: str` — absolute project root path; enables exclusion application + trust verification
- `thoroughness: str` — `"standard"` or `"deep"`
- `adaptive_flag: bool` — whether `--adaptive` was passed
- `format: str` — output format hint (`"json"`, `"sarif"`, `"markdown"`, `"csv"`)

## Workflow

### Step 1: Trust verification (advisory)

Call `verify_trust` once at the start. The result is advisory — surface in your final return, but do NOT block the scan on a non-clean trust state. The main session decides whether to proceed.

```python
trust = mcp__screw-agents__verify_trust({"project_root": <project_root>})
```

Capture `trust["verified"]`, `trust["quarantined_count"]`, and any `trust["warning_message"]`.

### Step 2: Init page

Call `scan_agents` with `cursor=null` to get the init page. The response carries per-agent metadata, agent-scoped exclusions, the relevance-filter exclusion list, and the first cursor.

```python
init = mcp__screw-agents__scan_agents({
    "agents": <agents>,
    "target": <target>,
    "project_root": <project_root>,
    "thoroughness": <thoroughness>,
    "cursor": null,
})
```

Capture for use across pages:
- `init["agents"]` — surviving agents after relevance filter (may be a subset of the input list)
- `init["agents_excluded_by_relevance"]` — list of `{agent_name, reason, agent_languages, target_languages}` records — echo these in your final return so main session can show the user
- For each agent entry in `init["agents"]`: capture `entry["meta"]` (CWE classifications, etc.) and `entry["exclusions"]` (filter findings against this list before emission)
- `init["next_cursor"]` — opaque token for first code page

Initialize a per-agent prompt cache:

```python
prompt_cache = {}  # agent_name -> {core_prompt, meta}
```

### Step 3: Page loop

While `next_cursor` is non-null, call `scan_agents` with the cursor:

```python
page = mcp__screw-agents__scan_agents({
    "agents": <agents>,           # MUST be the same list — cursor binds
    "target": <target>,           # MUST be the same — cursor binds
    "project_root": <project_root>,
    "thoroughness": <thoroughness>,
    "cursor": <previous next_cursor>,
})
```

For each `agent_entry` in `page["agents"]`:

1. **Lazy prompt fetch** — if `agent_entry["agent_name"]` not in `prompt_cache`:
   ```python
   prompt_cache[agent_entry["agent_name"]] = mcp__screw-agents__get_agent_prompt({
       "agent_name": agent_entry["agent_name"],
       "thoroughness": <thoroughness>,
   })
   ```

2. **Analyze** — apply the cached `core_prompt` to `agent_entry["code"]`. Use `agent_entry["meta"]` for CWE classification labels in any findings you emit.

3. **For each detected vulnerability:** construct a finding dict per the schema in `models.py::Finding` (id, agent, location, classification, analysis, remediation, triage). Apply the per-agent exclusion list captured from the init page — drop any finding matching an exclusion's scope. For exclusions you DO suppress, record the suppression in your structured return's `exclusions_applied` accounting (the main session's `finalize_scan_results` records these too; double-counting is suppressed by session-id dedup).

4. **For each context-required pattern match where you decided NOT to emit a finding** (adaptive D1 signal): call `record_context_required_match`:
   ```python
   mcp__screw-agents__record_context_required_match({
       "project_root": <project_root>,
       "match": {
           "agent": <agent_entry["agent_name"]>,
           "file": <path>,
           "line": <line>,
           "pattern": <pattern_id>,
       },
       "session_id": <session_id_from_first_accumulate>,
   })
   ```

5. **Accumulate findings** — once per agent per code page (or once per batch — match your mental model):
   ```python
   result = mcp__screw-agents__accumulate_findings({
       "project_root": <project_root>,
       "findings_chunk": <list of finding dicts>,
       "session_id": <session_id or null on first call>,
   })
   session_id = result["session_id"]  # carry forward
   ```

After all pages processed (when `next_cursor` is null), proceed to Step 4.

### Step 4: Return structured payload

End your turn with ONE fenced JSON code block matching this schema:

````json
{
  "session_id": "<opaque token>",
  "summary_counts": {
    "findings_total": <int>,
    "findings_by_severity": {"high": <int>, "medium": <int>, "low": <int>, "critical": <int>},
    "findings_by_agent": {"<agent_name>": <int>, ...}
  },
  "classification_summary": {
    "cwes_seen": ["CWE-89", "CWE-79", ...],
    "owasp_top10_seen": ["A03:2025", ...]
  },
  "trust_status": {
    "verified": true,
    "quarantined_count": 0,
    "warning_message": null
  },
  "agents_excluded_by_relevance": [
    {"agent_name": "<name>", "reason": "language_mismatch",
     "agent_languages": [...], "target_languages": [...]}
  ],
  "context_required_matches_recorded": <int>,
  "exclusions_applied_count": <int>
}
````

**CRITICAL — Concern A from spec section 11.2:** your structured return **MUST NOT** include findings inline. Findings live in `.screw/staging/{session_id}/findings.json` after `accumulate_findings`. Your return is a summary only. The main session will call `finalize_scan_results(session_id, format)` which renders + writes the report.

The main session reads your return and decides next steps:
- If adaptive_flag and any `staged scripts` flagged: it dispatches `screw-script-reviewer`.
- After the script reviewer (if any), it may dispatch you again with the same session_id to re-scan post-script-promotion.
- Finally it calls `finalize_scan_results(session_id, format)` to render and write the report.

## Behavior under errors

- **Cursor binding mismatch from MCP layer** (`agents` list changed mid-flow, target changed): re-emit the structured return with a `fatal_error` field instead of `summary_counts`. Main session aborts the scan.
- **Empty `agents` arg from main session:** unreachable in normal flow (slash command rejects empty resolution), but if encountered, return `{"fatal_error": "No agents provided to scan"}`.
- **All agents filtered out by relevance filter on init page:** init page returns `agents=[]` and `next_cursor=null`. Your loop runs zero iterations. Return the structured payload with `summary_counts.findings_total = 0` and the full `agents_excluded_by_relevance` list. The main session shows the user the "all agents filtered" diagnostic.

## Reasoning for design decisions

- **Single subagent for all agents.** At CWE-1400 expansion (41 agents), per-agent subagents would be 41 markdown files maintained in lockstep. The procedural template across today's 4 per-agent subagents was already byte-identical modulo name (verified during T-SCAN-REFACTOR brainstorm). Spec section 7 (Q5 Option I).
- **Cursor binding to `(target, agents)`.** Catches mid-flow drift in either dimension. Spec section 5.1 cursor encoding (Q4 Option β).
- **Lazy prompt fetch per agent.** Already established post-Phase-3a-X1-M1; preserved here. Token-budget protection.
- **Findings stage to disk, not return inline.** Concern A from spec section 11.2. Return-payload size regression test in `tests/test_screw_scan_subagent.py`.
- **No nested subagent dispatch.** Per `sub-agents.md:711`. Adaptive script reviewer is dispatched by main session, not by this subagent.
```

(Total: ~420 LOC. Adjust the procedural details if `screw-sqli.md`'s pattern differs in nuance — the goal is parametric equivalence, not literal copy.)

- [ ] **Step 4: Delete the 5 old subagent files**

```bash
rm /home/marco/Programming/AI/screw-agents/plugins/screw/agents/screw-sqli.md
rm /home/marco/Programming/AI/screw-agents/plugins/screw/agents/screw-cmdi.md
rm /home/marco/Programming/AI/screw-agents/plugins/screw/agents/screw-ssti.md
rm /home/marco/Programming/AI/screw-agents/plugins/screw/agents/screw-xss.md
rm /home/marco/Programming/AI/screw-agents/plugins/screw/agents/screw-injection.md
```

- [ ] **Step 5: Update plugin manifest if it exists**

If Step 1's pre-audit identified a manifest file (e.g., `plugin.json`) that explicitly registers subagents by name, edit it: remove the 5 deleted subagent entries; add `screw-scan` entry. If no explicit manifest exists (registration is by file presence), skip this step.

- [ ] **Step 6: Write subagent regression tests**

Create `tests/test_screw_scan_subagent.py`:

```python
"""Tests for T-SCAN-REFACTOR Task 7: universal screw-scan subagent.

Spec section 7. Verifies file presence, frontmatter declarations,
and the return-payload size discipline (Concern A from spec section 11.2).
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml


SUBAGENT_DIR = Path(__file__).parents[1] / "plugins" / "screw" / "agents"
SCREW_SCAN_PATH = SUBAGENT_DIR / "screw-scan.md"


# ---------------------------------------------------------------------------
# File presence
# ---------------------------------------------------------------------------


def test_screw_scan_subagent_file_exists() -> None:
    assert SCREW_SCAN_PATH.is_file(), f"missing {SCREW_SCAN_PATH}"


def test_retired_per_agent_subagents_are_deleted() -> None:
    for old_name in ("screw-sqli.md", "screw-cmdi.md", "screw-ssti.md", "screw-xss.md", "screw-injection.md"):
        path = SUBAGENT_DIR / old_name
        assert not path.exists(), f"{old_name} should be deleted in T-SCAN-REFACTOR Task 7"


def test_other_subagents_unchanged() -> None:
    """screw-script-reviewer and screw-learning-analyst remain untouched."""
    assert (SUBAGENT_DIR / "screw-script-reviewer.md").is_file()
    assert (SUBAGENT_DIR / "screw-learning-analyst.md").is_file()


# ---------------------------------------------------------------------------
# Frontmatter
# ---------------------------------------------------------------------------


def _read_frontmatter(path: Path) -> dict:
    """Parse YAML frontmatter between leading '---' lines."""
    text = path.read_text(encoding="utf-8")
    if not text.startswith("---\n"):
        raise ValueError(f"{path} has no leading frontmatter delimiter")
    end_idx = text.index("\n---\n", 4)
    fm_text = text[4:end_idx]
    return yaml.safe_load(fm_text)


def test_screw_scan_frontmatter_declares_required_tools() -> None:
    fm = _read_frontmatter(SCREW_SCAN_PATH)
    tools = fm.get("tools", [])
    required = {
        "mcp__screw-agents__scan_agents",
        "mcp__screw-agents__get_agent_prompt",
        "mcp__screw-agents__accumulate_findings",
        "mcp__screw-agents__record_context_required_match",
        "mcp__screw-agents__verify_trust",
    }
    assert required.issubset(set(tools)), f"missing tools: {required - set(tools)}"


def test_screw_scan_uses_opus_model() -> None:
    """Per feedback_opus_for_all_subagents memory."""
    fm = _read_frontmatter(SCREW_SCAN_PATH)
    assert fm.get("model") == "opus"


def test_screw_scan_does_not_declare_agent_tool() -> None:
    """Subagents cannot dispatch other subagents (sub-agents.md:711)."""
    fm = _read_frontmatter(SCREW_SCAN_PATH)
    tools = set(fm.get("tools", []))
    # Neither 'Agent' (current name) nor 'Task' (deprecated alias) should appear.
    assert "Agent" not in tools
    assert "Task" not in tools


# ---------------------------------------------------------------------------
# Return-payload size discipline (Concern A — spec section 11.2)
# ---------------------------------------------------------------------------


def test_screw_scan_body_forbids_inline_findings() -> None:
    """The subagent's procedural template must instruct it NOT to inline
    findings in the structured return — staging-only via accumulate_findings."""
    text = SCREW_SCAN_PATH.read_text(encoding="utf-8")
    # Heuristic check for the explicit "MUST NOT include findings inline" warning
    assert "MUST NOT" in text and "findings" in text.lower()
    assert "accumulate_findings" in text
    assert "staging" in text.lower()
```

- [ ] **Step 7: Run subagent tests**

```
uv run pytest tests/test_screw_scan_subagent.py -v 2>&1 | tail -25
```

Expected: all 7 tests PASS.

- [ ] **Step 8: Run full test suite**

```
uv run pytest -q 2>&1 | tail -5
```

Expected: ~938 + 7 = ~945 passed, 8 skipped. Zero failures.

If any other test fails because it referenced one of the 5 deleted subagents by file name: that test is owed to Task 7 — update it to assert `screw-scan.md` exists instead.

- [ ] **Step 9: Commit**

```bash
git add plugins/screw/agents/screw-scan.md plugins/screw/agents/ tests/test_screw_scan_subagent.py
# (the deleted files are staged via the implicit git rm in 'git add' on the directory)
git commit -m "T-SCAN-REFACTOR Task 7: universal screw-scan subagent

Collapses 5 subagent files into 1:

Deleted (-1878 LOC of duplicate markdown):
- plugins/screw/agents/screw-sqli.md       (414 LOC)
- plugins/screw/agents/screw-cmdi.md       (414 LOC)
- plugins/screw/agents/screw-ssti.md       (414 LOC)
- plugins/screw/agents/screw-xss.md        (414 LOC)
- plugins/screw/agents/screw-injection.md  (222 LOC)

Created (+~420 LOC):
- plugins/screw/agents/screw-scan.md — universal scan runner
  parameterized by agents: list[str] from dispatch prompt; calls
  scan_agents (paginated) + get_agent_prompt (lazy) + accumulate_findings
  + record_context_required_match + verify_trust. Returns a lean
  structured payload (Concern A: findings stage to disk, not inline).

Unchanged: screw-script-reviewer.md, screw-learning-analyst.md (separate
concerns; do not dispatch scan tools).

7 regression tests cover: file presence (new + deleted), frontmatter
tool declaration, opus model, no Agent tool (subagents can't dispatch),
body's MUST-NOT-inline-findings discipline."
```

---

## Task 8: Slash command rewrite — multi-scope syntax + parser + summary + errors

**Goal:** Rewrite `plugins/screw/commands/scan.md` for the new grammar (bare-token | `full` | `domains:`/`agents:` prefix-key form), the resolution algorithm, the relevance filter integration, the pre-execution summary line, error cases, and `--no-confirm` flag.

**Files:**
- Modify: `plugins/screw/commands/scan.md` — full rewrite (~480 LOC current, ~600 LOC after)
- Create: `tests/test_scan_command_parser.py` — 15 tests for grammar + resolution + error cases

**Pre-audit focus (mandatory — novel UX):** read the current `scan.md` end-to-end (480 LOC). Identify every workflow step that survives the rewrite vs replaces. Specifically: (a) Step 1 (parse arguments + dispatch) is replaced; (b) Step 1b (full-scope domain loop) is replaced; (c) Step 2 (parse subagent return) survives but reads `screw-scan`'s new payload shape; (d) finalize step survives. Confirm `$ARGUMENTS` is the input variable per `skills.md:213` (Claude Code docs). Confirm the slash-command parser runs in main session per `sub-agents.md:11, 685` (chain-subagents pattern).

- [ ] **Step 1: Pre-audit — read current scan.md and identify replaceable sections**

```
sed -n '1,120p' /home/marco/Programming/AI/screw-agents/plugins/screw/commands/scan.md
sed -n '120,260p' /home/marco/Programming/AI/screw-agents/plugins/screw/commands/scan.md
sed -n '260,480p' /home/marco/Programming/AI/screw-agents/plugins/screw/commands/scan.md
```

Map each section. The rewrite must preserve the chain-subagents architecture (main session dispatches scan subagent, awaits return, optionally dispatches script-reviewer, finalizes), only the parsing + resolution + dispatch-target changes.

- [ ] **Step 2: Write failing parser tests**

Create `tests/test_scan_command_parser.py`. Since the slash command's parser logic lives in markdown (Claude executes the prompt instructions), parser tests have a different shape than Python unit tests. They test the *Python helper* the slash command will call to resolve scope-spec strings — a pure function that takes the raw `$ARGUMENTS` string and returns a resolved agent list.

The cleanest split: extract the resolution logic into a Python helper at `src/screw_agents/scan_command.py` that the slash command's prompt invokes via tool call. The helper is testable; the markdown wraps it.

```python
"""Tests for T-SCAN-REFACTOR Task 8: slash command scope parser.

Spec section 6. The parser is exposed as a Python helper for testability;
the slash command's markdown body invokes it via the registered tool.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from screw_agents.registry import AgentRegistry
from screw_agents.scan_command import (
    ParsedScope,
    ScopeResolutionError,
    parse_scope_spec,
    resolve_scope,
)


@pytest.fixture
def registry() -> AgentRegistry:
    domains_dir = Path(__file__).parents[1] / "domains"
    return AgentRegistry(domains_dir)


# ---------------------------------------------------------------------------
# Bare-token form
# ---------------------------------------------------------------------------


def test_bare_token_agent_name(registry: AgentRegistry) -> None:
    parsed = parse_scope_spec("sqli")
    resolved = resolve_scope(parsed, registry)
    assert resolved == ["sqli"]


def test_bare_token_domain_name(registry: AgentRegistry) -> None:
    parsed = parse_scope_spec("injection-input-handling")
    resolved = resolve_scope(parsed, registry)
    assert set(resolved) == {"sqli", "cmdi", "ssti", "xss"}


def test_bare_token_unknown_raises(registry: AgentRegistry) -> None:
    parsed = parse_scope_spec("unknownname")
    with pytest.raises(ScopeResolutionError, match="not a domain or agent"):
        resolve_scope(parsed, registry)


# ---------------------------------------------------------------------------
# `full` keyword
# ---------------------------------------------------------------------------


def test_full_keyword_returns_all_registered(registry: AgentRegistry) -> None:
    parsed = parse_scope_spec("full")
    resolved = resolve_scope(parsed, registry)
    all_names = set(registry.agents.keys())
    assert set(resolved) == all_names


# ---------------------------------------------------------------------------
# Prefix-key form
# ---------------------------------------------------------------------------


def test_domains_only_implies_full(registry: AgentRegistry) -> None:
    parsed = parse_scope_spec("domains:injection-input-handling")
    resolved = resolve_scope(parsed, registry)
    assert set(resolved) == {"sqli", "cmdi", "ssti", "xss"}


def test_agents_only_no_domains(registry: AgentRegistry) -> None:
    parsed = parse_scope_spec("agents:sqli,xss")
    resolved = resolve_scope(parsed, registry)
    assert set(resolved) == {"sqli", "xss"}


def test_domains_with_subset_agents(registry: AgentRegistry) -> None:
    parsed = parse_scope_spec("domains:injection-input-handling agents:sqli,xss")
    resolved = resolve_scope(parsed, registry)
    assert set(resolved) == {"sqli", "xss"}


def test_cross_domain_agent_ref_raises(registry: AgentRegistry) -> None:
    """Spec section 6.6: agent listed in agents: must belong to a listed domain
    when domains: is non-empty."""
    # Construct a case where an agent's domain is NOT in domains:.
    # Today only 'injection-input-handling' has agents; pick a fictional case
    # by asking for domains:ANOTHER but agent in injection-input-handling.
    # Since 'ANOTHER' doesn't exist, the parser fails on unknown domain first.
    # For the cross-domain check itself, we'd need a 2-domain registry; with
    # today's 1-domain registry this test can only assert the unknown-domain
    # path. When CWE-1400 expansion lands, this test extends to true cross-
    # domain rejection.
    parsed = parse_scope_spec("domains:nonexistent agents:sqli")
    with pytest.raises(ScopeResolutionError, match="Unknown domain"):
        resolve_scope(parsed, registry)


def test_unknown_agent_in_prefix_key_raises(registry: AgentRegistry) -> None:
    parsed = parse_scope_spec("agents:nonexistent")
    with pytest.raises(ScopeResolutionError, match="Unknown agent"):
        resolve_scope(parsed, registry)


# ---------------------------------------------------------------------------
# Mutual exclusivity
# ---------------------------------------------------------------------------


def test_full_with_prefix_keys_raises(registry: AgentRegistry) -> None:
    with pytest.raises(ScopeResolutionError, match="exclusive"):
        parse_scope_spec("full domains:injection-input-handling")


def test_bare_token_with_prefix_keys_raises(registry: AgentRegistry) -> None:
    with pytest.raises(ScopeResolutionError, match="exclusive"):
        parse_scope_spec("sqli agents:xss")


# ---------------------------------------------------------------------------
# Empty / malformed
# ---------------------------------------------------------------------------


def test_empty_scope_spec_raises(registry: AgentRegistry) -> None:
    with pytest.raises(ScopeResolutionError, match="empty"):
        parse_scope_spec("")


def test_malformed_prefix_key_raises(registry: AgentRegistry) -> None:
    with pytest.raises(ScopeResolutionError, match="Unknown prefix key"):
        parse_scope_spec("typos:sqli")


# ---------------------------------------------------------------------------
# Result determinism
# ---------------------------------------------------------------------------


def test_resolved_list_is_sorted_and_unique(registry: AgentRegistry) -> None:
    parsed = parse_scope_spec("agents:sqli,xss,sqli")  # duplicate
    resolved = resolve_scope(parsed, registry)
    assert resolved == sorted(set(resolved))
```

- [ ] **Step 3: Run new tests to verify they fail**

```
uv run pytest tests/test_scan_command_parser.py -v 2>&1 | tail -25
```

Expected: ImportError on `screw_agents.scan_command` module.

- [ ] **Step 4: Create the parser helper module**

Create `src/screw_agents/scan_command.py`:

```python
"""Slash command scope-spec parser + resolver.

T-SCAN-REFACTOR Task 8: extracted from `plugins/screw/commands/scan.md`
for testability. The slash command's markdown body invokes these helpers
to convert raw `$ARGUMENTS` strings into resolved agent lists, then
dispatches `scan_agents` with the result.

Spec sections 6.1, 6.2, 6.3, 6.6.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from screw_agents.registry import AgentRegistry


class ScopeResolutionError(ValueError):
    """Raised when scope-spec parsing or resolution fails. The slash command
    surfaces this as a user-facing error message before any dispatch."""


@dataclass
class ParsedScope:
    """Result of `parse_scope_spec` — pre-registry-validation."""

    full_keyword: bool = False
    bare_token: str | None = None
    domains_explicit: list[str] = field(default_factory=list)
    agents_explicit: list[str] = field(default_factory=list)


def parse_scope_spec(scope_text: str) -> ParsedScope:
    """Parse the scope-spec portion of `$ARGUMENTS`.

    The slash command's parser splits `$ARGUMENTS` at flags (--*) and the
    target spec separately; this helper takes only the scope-spec tokens.

    Args:
        scope_text: whitespace-separated tokens forming the scope spec.

    Returns:
        ParsedScope with at most one form populated (full | bare_token |
        prefix-key list).

    Raises:
        ScopeResolutionError: on empty, mixed forms, or malformed prefix keys.
    """
    tokens = scope_text.strip().split()
    if not tokens:
        raise ScopeResolutionError("Scope-spec is empty; pass a scope token.")

    parsed = ParsedScope()

    has_full = False
    has_bare = False
    has_prefix = False

    for tok in tokens:
        if tok == "full":
            has_full = True
            parsed.full_keyword = True
            continue
        if ":" in tok:
            has_prefix = True
            prefix, _sep, rest = tok.partition(":")
            if prefix == "domains":
                parsed.domains_explicit.extend(n.strip() for n in rest.split(",") if n.strip())
            elif prefix == "agents":
                parsed.agents_explicit.extend(n.strip() for n in rest.split(",") if n.strip())
            else:
                raise ScopeResolutionError(
                    f"Unknown prefix key {prefix!r}. Allowed: 'domains:', 'agents:'."
                )
            continue
        # Bare token (no colon, not 'full')
        has_bare = True
        if parsed.bare_token is not None:
            raise ScopeResolutionError(
                f"Multiple bare tokens not supported. Use 'domains:' / 'agents:' "
                f"prefix syntax for multi-scope."
            )
        parsed.bare_token = tok

    # Mutual exclusivity
    forms_used = sum([has_full, has_bare, has_prefix])
    if forms_used > 1:
        raise ScopeResolutionError(
            "Scope forms are exclusive: pick exactly one of 'full', a bare "
            "domain/agent name, or 'domains:'/'agents:' prefix-keys."
        )

    return parsed


def resolve_scope(parsed: ParsedScope, registry: AgentRegistry) -> list[str]:
    """Resolve a `ParsedScope` to a sorted, deduplicated list of agent names.

    Spec section 6.3.

    Args:
        parsed: result of `parse_scope_spec`.
        registry: loaded AgentRegistry.

    Returns:
        Sorted, deduplicated list of agent names.

    Raises:
        ScopeResolutionError: on unknown domain/agent or cross-domain agent
            reference (spec section 6.6).
    """
    domain_names = set(registry.list_domains().keys())
    agent_names_known = set(registry.agents.keys())

    if parsed.full_keyword:
        return sorted(agent_names_known)

    if parsed.bare_token:
        name = parsed.bare_token
        if name in domain_names:
            return sorted(a.meta.name for a in registry.get_agents_by_domain(name))
        if name in agent_names_known:
            return [name]
        raise ScopeResolutionError(
            f"{name!r} is not a domain or agent. Run `mcp__screw-agents__list_domains` "
            f"and `mcp__screw-agents__list_agents` to see registered names."
        )

    # Prefix-key form
    final: set[str] = set()

    for domain in parsed.domains_explicit:
        if domain not in domain_names:
            raise ScopeResolutionError(
                f"Unknown domain {domain!r}. Run `mcp__screw-agents__list_domains` "
                f"to see registered domains."
            )
        agents_listed_in_domain = [
            name for name in parsed.agents_explicit
            if registry.get_agent(name) is not None
            and registry.get_agent(name).meta.domain == domain
        ]
        if agents_listed_in_domain:
            final.update(agents_listed_in_domain)
        else:
            final.update(a.meta.name for a in registry.get_agents_by_domain(domain))

    for agent in parsed.agents_explicit:
        if agent not in agent_names_known:
            raise ScopeResolutionError(
                f"Unknown agent {agent!r}. Run `mcp__screw-agents__list_agents` "
                f"to see registered agents."
            )
        agent_def = registry.get_agent(agent)
        if parsed.domains_explicit and agent_def.meta.domain not in parsed.domains_explicit:
            raise ScopeResolutionError(
                f"Agent {agent!r} belongs to domain {agent_def.meta.domain!r}, "
                f"which is not in domains:{','.join(parsed.domains_explicit)}. "
                f"Either add {agent_def.meta.domain!r} to 'domains:', or omit "
                f"'agents:{agent}'."
            )
        final.add(agent)

    if not final:
        raise ScopeResolutionError(
            "No agents resolved from the given scope. Pass 'full', a bare "
            "domain/agent name, or 'domains:'/'agents:' prefix-keys."
        )

    return sorted(final)
```

- [ ] **Step 5: Run parser tests; confirm pass**

```
uv run pytest tests/test_scan_command_parser.py -v 2>&1 | tail -25
```

Expected: all 15 tests PASS.

- [ ] **Step 6: Rewrite `scan.md` slash command body**

Open `/home/marco/Programming/AI/screw-agents/plugins/screw/commands/scan.md`. Replace the entire file contents with:

```markdown
---
name: screw:scan
description: "Run a security scan with screw-agents. Usage: /screw:scan <scope-spec> [target] [--thoroughness standard|deep] [--format json|sarif|markdown|csv] [--adaptive] [--no-confirm]"
allowed-tools:
  - Bash
  - Read
  - Agent
  - mcp__screw-agents__list_agents
  - mcp__screw-agents__list_domains
  - mcp__screw-agents__finalize_scan_results
---

# /screw:scan — Security Scan Orchestrator (main-session)

You are the MAIN-SESSION orchestrator for screw-agents scans. You parse the scope-spec, resolve the agent list against the registry, dispatch the universal `screw-scan` subagent, await its structured return, optionally dispatch the script reviewer for adaptive flows, and finalize the scan report.

## Why this lives in main session

Claude Code's architecture forbids nested subagent dispatch (`sub-agents.md:711`). The adaptive flow requires dispatching both a scan subagent AND a reviewer subagent; only the main session can chain both. This slash command IS the main session — its prompt runs in the main conversation and has full tool surface (MCP tools, Agent tool).

## Syntax

```
/screw:scan <scope-spec> [target] [--thoroughness standard|deep] [--format json|sarif|markdown|csv] [--adaptive] [--no-confirm]
```

## Scope-spec forms (exclusive)

Pick exactly one of:

1. **`full`** — scan all registered agents.
   - Example: `/screw:scan full src/api/`

2. **Bare token** — single domain name OR single agent name (resolved by registry lookup; collision invariant guarantees uniqueness).
   - Example: `/screw:scan sqli src/api/` (single agent)
   - Example: `/screw:scan injection-input-handling src/api/` (single domain → all 4 agents)

3. **Prefix-key form** — one or more `domains:` and/or `agents:` keys, comma-separated value lists.
   - `domains:A,B,C` declares the inclusion universe. Each listed domain contributes its full agent set unless `agents:` narrows it.
   - `agents:X,Y` lists explicit agents. If `domains:` is also present, every agent in `agents:` must belong to a listed domain. If `domains:` is absent, each agent's home domain is implicit.
   - Examples:
     - `/screw:scan domains:injection-input-handling src/api/` (full domain)
     - `/screw:scan agents:sqli,xss src/api/` (specific agents only)
     - `/screw:scan domains:injection-input-handling agents:sqli src/api/` (subset of one domain)
     - `/screw:scan domains:A,B agents:1A,2A,1B src/api/` (subset of A + subset of B)

## Other arguments

- `[target]` (last positional, optional, defaults to codebase root): bare path, `src/api/**` glob, `git_diff:BASE`, `function:NAME@FILE`, `class:NAME@FILE`, `commits:RANGE`.
- `--thoroughness standard|deep` (default `standard`): passed to scan tool.
- `--format json|sarif|markdown|csv` (default `markdown`): passed to `finalize_scan_results`.
- `--adaptive` (optional flag, default disabled): enable adaptive analysis mode. Requires `.screw/config.yaml` with `script_reviewers` populated and an interactive session. CI/piped contexts MUST NOT pass `--adaptive`.
- `--no-confirm` (optional flag, default false): skip the pre-execution `Continue?` prompt. CI / piped contexts MUST pass this. The summary line still prints to stderr for audit.

## Workflow

### Step 1: Parse `$ARGUMENTS`

Tokenize `$ARGUMENTS` into:
- `scope_tokens`: tokens before the first non-flag, non-`:`-bearing, non-`full` token (or after such token if it's the bare-token form). Specifically: walk left-to-right; tokens are scope-spec tokens until you hit something that's not `full`, not a bare-token name in the registry, and not a `domains:`/`agents:` prefix key. The remaining is target + flags.
- `target_token`: the single positional after the scope-spec.
- `flags`: any tokens starting with `--`.

In practice, since the scope-spec form is mutually exclusive (Section "Scope-spec forms"), you can determine which form is in use by looking at the first non-flag token, then consume scope tokens accordingly.

### Step 2: Resolve scope to agents list

Invoke `screw_agents.scan_command.parse_scope_spec` and `resolve_scope` (the registered Python helper). If a `ScopeResolutionError` is raised, surface its message verbatim and abort:

```
Bash: `uv run python -c "from screw_agents.scan_command import parse_scope_spec, resolve_scope; from screw_agents.registry import AgentRegistry; from pathlib import Path; reg = AgentRegistry(Path('domains')); parsed = parse_scope_spec(<scope_text>); print(','.join(resolve_scope(parsed, reg)))"`
```

(Or call via the registered MCP `list_agents` / `list_domains` tools and reproduce the resolution algorithm in the prompt — implementation detail. The helper exists in Python for testability; the slash command can either invoke it via Bash or reproduce the algorithm.)

### Step 3: Apply relevance filter

The relevance filter runs server-side inside `scan_agents`. Main session does NOT pre-filter. The init-page response carries `agents_excluded_by_relevance` records — surface these in the pre-execution summary.

### Step 4: Pre-execution summary

Print to the user (stderr if `--no-confirm`, otherwise stdout):

```
Resolved scope: <N> agents will be scanned
  domain <D1> (subset|full): <agent1>, <agent2>, ...
  domain <D2> (subset|full): <agent3>, ...
  ...

Excluded by relevance filter (target language: <L>):
  - <agent_X> (declares: <L_X>) — domain: <D>
  ...

Target: <target> (<F> files, <LOC> LOC)
Thoroughness: <T>
Adaptive mode: <enabled|disabled>
Format: <F>

Continue with this scope? [Y/n]
```

If `--no-confirm` is set, skip the prompt; otherwise wait for user confirmation. Abort on 'n' / 'N' / non-empty non-Y answer.

### Step 5: Dispatch screw-scan

```
Agent(
  subagent_type="screw:screw-scan",
  description="Security scan — <scope summary>",
  prompt="""
    Run the scan with these parameters:
    - agents: <comma-separated list from Step 2>
    - target: <parsed target spec>
    - project_root: <absolute project root>
    - thoroughness: <standard|deep>
    - adaptive_flag: <true|false>
    - format: <json|sarif|markdown|csv>

    Follow your subagent instructions. End your turn with the structured
    JSON payload per your Step 4 schema.
  """
)
```

### Step 6: Parse subagent return

The subagent's last turn ends with a fenced JSON block matching the `summary_counts` schema in `screw-scan.md`. Parse it. Capture `session_id` for the finalize call.

### Step 7: Adaptive script reviewer (optional)

If `adaptive_flag` is true AND the subagent's return indicates staged scripts pending review, dispatch `screw:screw-script-reviewer` per the existing post-C2 pattern. After it returns, optionally re-dispatch `screw-scan` with the same `session_id` to re-scan post-script-promotion.

### Step 8: Finalize

```
mcp__screw-agents__finalize_scan_results({
    "project_root": <project_root>,
    "session_id": <session_id>,
    "format": <format>,
})
```

Surface the rendered report path to the user.

## Error handling

- ScopeResolutionError from Step 2 → surface message, abort before any work.
- Empty resolved agent list (e.g., all filtered) → abort with summary.
- Subagent fatal_error → surface, abort, do not finalize.
- `--adaptive` in non-interactive context → abort.
```

(This is a heavily abridged version of the rewrite. The actual `scan.md` will be ~600 LOC after expansion to include detailed examples, edge cases, and the existing finalize section preserved verbatim. Implementer expands the rewritten body to full detail using `screw-injection.md` (deleted in Task 7) as a reference for the dispatch + parse-return + finalize portions.)

- [ ] **Step 7: Run all tests; confirm**

```
uv run pytest tests/test_scan_command_parser.py -v 2>&1 | tail -10
uv run pytest -q 2>&1 | tail -5
```

Expected: parser tests PASS; full suite ~945 + 15 = ~960 passed.

- [ ] **Step 8: Commit**

```bash
git add plugins/screw/commands/scan.md src/screw_agents/scan_command.py tests/test_scan_command_parser.py
git commit -m "T-SCAN-REFACTOR Task 8: slash command rewrite — multi-scope syntax

Replaces single-token scope arg (sqli|cmdi|ssti|xss|injection|full) with
the new grammar from spec section 6:

- 'full' keyword (unchanged behavior)
- Bare-token form: single domain name OR single agent name
- Prefix-key form: domains:A,B agents:1A,2A — supports the full case
  (subset of A + full B + subset of C in one prompt)

The 3 forms are mutually exclusive; mixing raises ScopeResolutionError.

src/screw_agents/scan_command.py (new module): pure-Python parser +
resolver helpers extracted for testability. parse_scope_spec(text) -> 
ParsedScope; resolve_scope(parsed, registry) -> list[str].

plugins/screw/commands/scan.md: full rewrite. Workflow now:
1. Parse scope tokens from \$ARGUMENTS
2. Resolve to agent list via scan_command helpers (cross-domain rejection,
   unknown-name rejection)
3. Server applies relevance filter inside scan_agents — caller surfaces
   results
4. Pre-execution summary line (subset/full annotations + filter exclusions)
5. Consent prompt (or skip with --no-confirm for CI)
6. Dispatch universal screw-scan subagent with resolved agents list
7. Parse structured return
8. Optional screw-script-reviewer dispatch for adaptive flows
9. finalize_scan_results

Adaptive flow + chain-subagents architecture preserved.

15 parser tests cover: bare-token agent, bare-token domain, full keyword,
prefix-key forms (domains-only, agents-only, mixed), cross-domain
rejection, unknown name rejection, mutual exclusivity, empty/malformed
inputs, result determinism (sorted + dedup)."
```

---

## Task 9: Documentation sync

**Goal:** Bring all 8 affected docs into alignment with the shipped code in the SAME PR (per Marco's reminder during brainstorm; per `feedback_plan_sync_on_deviation` memory). No code changes in this task.

**Files (modify):**
- `docs/PRD.md`
- `docs/DECISIONS.md`
- `docs/ARCHITECTURE.md`
- `docs/AGENT_AUTHORING.md`
- `docs/PROJECT_STATUS.md`
- `docs/DEFERRED_BACKLOG.md`
- `docs/CONTRIBUTING.md`
- `docs/AGENT_CATALOG.md`

**Pre-audit focus (mandatory — cross-cut):** before editing, grep each doc for:
```
grep -l 'scan_full\|scan_sqli\|scan_cmdi\|scan_ssti\|scan_xss\|screw-sqli\|screw-cmdi\|screw-ssti\|screw-xss\|screw-injection\|assemble_full_scan' docs/*.md
```
Capture the list. Each file in the output requires updates. Section-level grep within each:
```
grep -n 'scan_full\|scan_sqli\|...' docs/<file>.md
```
gives line numbers to target.

- [ ] **Step 1: Update `docs/DEFERRED_BACKLOG.md` — close T-FULL-P1**

Open `docs/DEFERRED_BACKLOG.md`. Locate the T-FULL-P1 entry at line 425 (`### T-FULL-P1 — Paginate \`assemble_full_scan\` + apply lazy-fetch + agent-relevance filter`). Prepend a "RESOLVED" header in the same style as BACKLOG-PR6-22 used:

```markdown
### T-FULL-P1 — Paginate `assemble_full_scan` + apply lazy-fetch + agent-relevance filter — **SUPERSEDED 2026-04-25**
**Superseded on branch:** `t-scan-refactor` (merge commit TBD on merge).
**Forwarded to:** **T-SCAN-REFACTOR** — full architectural refactor that subsumed T-FULL-P1's scope. Instead of paginating `scan_full`, the work retired `scan_full` entirely, introduced `scan_agents` as the new paginated multi-agent primitive (with cursor binding generalized to `(target_hash, agents_hash)`), retired all per-agent `scan_<name>` MCP tools, collapsed 4 per-agent + 1 domain orchestrator subagents into one universal `screw-scan.md`, and rewrote the slash command for multi-scope syntax (`domains:`/`agents:` prefix keys). The relevance filter was preserved as `_filter_relevant_agents` in `engine.py`, applied server-side inside `scan_agents` init-page (returns `agents_excluded_by_relevance` records). Spec: `docs/specs/2026-04-25-t-scan-refactor-design.md`. Plan: `docs/PHASE_4_PREP_T_SCAN_REFACTOR_PLAN.md`.

**Historical entry (original deferral, for audit trail):**

[... existing T-FULL-P1 entry preserved unchanged below ...]
```

- [ ] **Step 2: Update DEFERRED_BACKLOG blocker table + Phase 4 gate**

At the tag-summary table near line ~136:

```markdown
| `blocker` | 0 | (none) |
```

(Previous: `| blocker | 1 | T-FULL-P1 |`)

Phase 4 gate paragraph (line ~141):

```markdown
**Phase 4 gate:** the `blocker` count is now 0. Phase 4 step 4.0 (D-01 Rust benchmark corpus) is the next prerequisite — see `docs/PROJECT_STATUS.md` §"Phase 4 Prerequisites (hard gates)". With T-SCAN-REFACTOR shipped, the per-agent autoresearch surface (`scan_agents([single_name])`) is ready for Phase 4 consumption.
```

- [ ] **Step 3: Add new deferred items**

Append 6 new entries near the existing deferred items section (find the appropriate section based on doc convention):

```markdown
### T-SCAN-FILTER-1 — `severity:` / `cwe:` / `exclude-agents:` slash command filters
**Source:** T-SCAN-REFACTOR brainstorm (2026-04-25).
**Phase-4 readiness:** `nice-to-have` — extends slash command grammar without changing MCP layer.
**Why deferred:** Same prefix-key grammar slot as `domains:`/`agents:` (Section 6.1 of T-SCAN-REFACTOR spec). Defer until users surface a real need; today's two prefix keys cover documented use cases.
**Trigger:** A user requests filtering by severity tier or CWE ID; OR a CI integration needs to suppress specific agents per-target.
**Suggested fix:** Extend `parse_scope_spec` to recognize `severity:`, `cwe:`, `exclude-agents:` keys; thread through resolution algorithm; pass to `scan_agents` as additional filter args. ~80 LOC.

### T-SCAN-LANG-1 — Tree-sitter language disambiguation for ambiguous extensions
**Source:** T-SCAN-REFACTOR brainstorm D5 (2026-04-25).
**Phase-4 readiness:** `nice-to-have` — relevance-filter accuracy improvement.
**Why deferred:** V1 uses extension lookup + shebang fallback. The only realistic ambiguous case is `.h` (C vs C++); other extensions in `EXTENSION_MAP` are unambiguous. Cost (tree-sitter parse-success check per ambiguous file) not justified for V1.
**Trigger:** Real-world project surfaces a misclassified `.h` file leading to wrong-language agent runs.
**Suggested fix:** When `_detect_language` resolves to `c` AND the file has `.h` extension, parse with both `c` and `cpp` tree-sitter grammars; pick the one with fewer errors. ~30 LOC.

### T-SCAN-MERGE-1 — Multi-session merge across sequential `/screw:scan` invocations
**Source:** T-SCAN-REFACTOR brainstorm (2026-04-25).
**Phase-4 readiness:** `nice-to-have`.
**Why deferred:** Today each `/screw:scan` is its own session_id; running two scans against the same target requires explicit `accumulate_findings(session_id=existing)` calls. Real-world usage doesn't currently demand multi-session merge.
**Trigger:** User asks "scan A, then scan B, give me one report".
**Suggested fix:** Add `--merge-into <session_id>` flag to slash command; thread through `accumulate_findings`. ~40 LOC.

### T-SCAN-RELEV-1 — Explicit `target_strategy.relevance_signals` YAML field for AST-based signals
**Source:** T-SCAN-REFACTOR D4 (2026-04-25).
**Phase-4 readiness:** `nice-to-have` — implicit derivation from `HeuristicEntry.languages` covers V1.
**Why deferred:** Implicit derivation works on the existing schema. Adding an explicit field would require migrating all shipped agent YAMLs. Defer until a real use case emerges.
**Trigger:** An agent author wants to declare AST-based or content-based relevance signals beyond language.
**Suggested fix:** Extend `TargetStrategy` model with `relevance_signals: list[RelevanceSignal] | None = None`; teach `_filter_relevant_agents` to use explicit signals when present, fall back to implicit derivation otherwise. ~60 LOC + YAML migration of all shipped agents.

### T-SCAN-LIST-1 — `/screw:scan list` discovery subcommand
**Source:** T-SCAN-REFACTOR brainstorm (2026-04-25).
**Phase-4 readiness:** `nice-to-have` — UX polish.
**Why deferred:** Today users call `mcp__screw-agents__list_domains` / `list_agents` directly via Claude Code. A built-in `list` subcommand would be more discoverable but not load-bearing.
**Trigger:** First-time user friction observed in Phase 4+ user testing.
**Suggested fix:** Add `list` to the slash command's grammar (special bare-token); dispatch invokes `list_domains` + `list_agents`, formats output. ~40 LOC.

### T-SCAN-AUDIT-1 — Hooks on `--no-confirm` invocations (audit logging)
**Source:** T-SCAN-REFACTOR Section 16 (2026-04-25).
**Phase-4 readiness:** `nice-to-have` — auditability for CI bypass.
**Why deferred:** `--no-confirm` is opt-in by explicit user flag. Existing `--adaptive` consent pattern is the precedent.
**Trigger:** Audit requirement (compliance, security review of CI behavior).
**Suggested fix:** Add a Claude Code hook that fires on `/screw:scan ... --no-confirm` invocations and logs to `.screw/audit/`. ~20 LOC + hook configuration.
```

- [ ] **Step 4: Update `docs/PROJECT_STATUS.md`**

(a) Top-of-file gate line:

```markdown
Gates G1-G4 pass. **Phase 4 (Autoresearch) is gated only on D-01 (Rust benchmark corpus) — all other prereqs shipped through T-SCAN-REFACTOR. See §"Phase 4 Prerequisites (hard gates)" below.**
```

(b) New "What's shipped" bullet (chronologically after T19-M):

```markdown
- **T-SCAN-REFACTOR (branch `t-scan-refactor`)** merged 2026-04-25 — Final Phase-4 prereq. Subsumes T-FULL-P1. Replaces 6-tool scan surface (`scan_full` + `scan_domain` + 4 per-agent) with `scan_agents` paginated primitive + `scan_domain` thin wrapper. Adds per-agent language relevance filter (`_filter_relevant_agents`) with extension + shebang detection. Cursor binding generalized to `(target_hash, agents_hash)` (Option β). Rewrites slash command for multi-scope syntax (`/screw:scan domains:A,B agents:1A,2A`). Collapses 5 subagents into universal `screw-scan.md`. Test suite: 906 → ~970 passed, 8 skipped. Phase 4 blocker count drops 1 → 0.
```

(c) Phase 4 row in phase table:

```markdown
| Phase 4 | Autoresearch & Self-Improvement — step 4.0 is D-01 (hard gate) | **Pending**, hard-gated only on D-01 |
```

(d) §"Phase 4 Prerequisites (hard gates)" — delete the T-FULL-P1 block entirely; update the introductory paragraph to state the only remaining prereq is D-01.

- [ ] **Step 5: Update `docs/PRD.md`**

§3 (Architecture) — find references to `scan_full`, per-agent tools, per-agent subagents. Update:
- Tool count: was 3 scan-shaped MCP tools (or 6 including per-agent); now 2 (`scan_agents` + `scan_domain`).
- Subagent count: was 5 (4 per-agent + 1 domain); now 1 (`screw-scan`) for scan-shaped subagents (plus unchanged `screw-script-reviewer`, `screw-learning-analyst`).

§4 (YAML schema) — clarify that `HeuristicEntry.languages: list[str]` is the implicit relevance signal derived for the per-agent language filter. Add a sentence: "Agents that omit `languages` on their heuristic entries are treated as 'always relevant' (D6 fail-open in T-SCAN-REFACTOR spec)."

§6 (User-facing examples) — add multi-scope examples:

```markdown
**Multi-scope syntax (T-SCAN-REFACTOR):**
- `/screw:scan domains:injection-input-handling agents:sqli,xss src/api/` — subset of one domain
- `/screw:scan domains:A,B agents:1A,2A,1B src/api/` — subset of A + subset of B (where 1A, 2A are in A and 1B is in B)
- `/screw:scan domains:A,B,C agents:1A,3C src/api/` — A subset, B implicit full (no agents listed for B), C subset
- `/screw:scan agents:sqli,xss src/api/` — specific agents anywhere
- `/screw:scan full src/api/` — every registered agent (post-relevance-filter)
```

- [ ] **Step 6: Update `docs/DECISIONS.md`**

Append a new ADR at the end of the file (or in chronological position):

```markdown
## ADR-T-SCAN-REFACTOR — `scan_agents` primitive, retire `scan_full`, universal subagent

**Date:** 2026-04-25
**Status:** Accepted (shipped on branch `t-scan-refactor`)
**Supersedes:** T-FULL-P1 deferral entry

**Context:** Phase 3b-C2 rewrote `/screw:scan full` as a main-session orchestrator looping `list_domains` + per-domain orchestrator dispatch. This bypassed `scan_full` entirely (the unpaginated response couldn't fit at >4 agents). The MCP tool surface had grown to 6 scan-shaped tools (`scan_full` + `scan_domain` + 4 per-agent) — at CWE-1400 expansion would have grown to 43. The slash command's single-token scope syntax couldn't express multi-domain or agent-subset scopes.

**Decision:** Replace the three-tool scan surface with one paginated multi-agent primitive (`scan_agents`) + one thin convenience shortcut (`scan_domain`). Retire `scan_full` and per-agent `scan_<name>` tools. Introduce per-agent language relevance filter. Rewrite slash command for `domains:`/`agents:` prefix-key multi-scope syntax. Collapse 4 per-agent subagents + 1 domain orchestrator into one universal `screw-scan.md`.

**Alternatives considered:**
- **Path X (T-FULL-P1 as originally scoped):** paginate `scan_full` keeping it alongside `scan_domain` and per-agent tools. Rejected — would build a tool with no live caller (post-C2 the slash command uses domain loop; Phase-4 autoresearch is per-agent). Would still leave the 6→43 tool-count growth unaddressed.
- **Option B (retire everything except `scan_agents` + `list_agents`):** retire `scan_domain` too. Rejected — `scan_domain` is a high-frequency convenience workflow worth preserving with explicit "shortcut for X" framing.
- **Option C (keep three peers, add relevance filter):** all three primitives stay; add filter. Rejected — doesn't solve "subset of A + full B + subset of C" (the user-flagged "huge gap").

**Consequences:**
- MCP tool count drops 6→2 (today), 43→2 (at CWE-1400 expansion).
- Subagent count drops 5→1 for scan-shaped subagents.
- Slash command grammar gains expressive power (multi-scope) and adds a registry-load invariant (agent-vs-domain collision check).
- Cursor protocol generalized: `(target_hash, agents_hash)` binding catches mid-flow agents-list drift.
- Phase 4 autoresearch consumes `scan_agents([single_name])` for per-agent loops — same primitive serves both single-agent (autoresearch) and multi-agent (slash command) callers.
- Hard break for retired tools — no compat shim. Justified by zero live external callers.

**References:**
- Spec: `docs/specs/2026-04-25-t-scan-refactor-design.md` (835 lines, sections 1-18)
- Plan: `docs/PHASE_4_PREP_T_SCAN_REFACTOR_PLAN.md`
- Brainstorm decisions D0-D8 (sketch phase) + Q1-Q6 (clarifying-question phase)
```

- [ ] **Step 7: Update `docs/ARCHITECTURE.md`**

Locate the tool inventory + subagent inventory + scan-flow chain diagrams. Update each:

- Tool inventory: drop `scan_full`, `scan_<agent>` × 4 entries. Add `scan_agents` entry. Update `scan_domain` description as "convenience wrapper for scan_agents".
- Subagent inventory: drop `screw-sqli`, `screw-cmdi`, `screw-ssti`, `screw-xss`, `screw-injection`. Add `screw-scan` entry. Keep `screw-script-reviewer`, `screw-learning-analyst`.
- Scan-flow chain diagram: replace "main session → list_domains → per-domain orchestrator dispatch" with "main session → parse + resolve scope → screw-scan dispatch → return to main → finalize".

- [ ] **Step 8: Update `docs/AGENT_AUTHORING.md`**

Append a new section near the YAML schema discussion:

```markdown
## Global uniqueness invariants (T-SCAN-REFACTOR)

Three invariants are enforced at registry load time. Violations refuse server start.

1. **Agent names are globally unique across all domains.** Two YAMLs declaring the same `meta.name` raise `ValueError("Duplicate agent name X: ...")` at `registry.py:44-48`. This invariant is established since Phase 1.

2. **Agent names must not collide with any domain name.** A YAML declaring `meta.name: cryptography` (the same as the `domains/cryptography/` directory) raises `ValueError("Agent name(s) collide with domain name(s): ['cryptography']")`. Enforced since T-SCAN-REFACTOR. Reason: the slash command's bare-token parser disambiguates a token by registry lookup; without this invariant `/screw:scan cryptography` would be ambiguous.

3. **YAML filename stem must equal `meta.name`.** A YAML at `domains/X/foo.yaml` declaring `meta.name: bar` raises `ValueError("YAML filename stem 'foo' does not match meta.name 'bar'")`. Enforced since T-SCAN-REFACTOR. Reason: copy-paste protection — duplicate-and-modify workflows often miss the `meta.name` update.

## Adding a new agent (post-T-SCAN-REFACTOR)

Adding a new vulnerability agent NO LONGER requires a per-agent subagent file. Steps:

1. Create `domains/<domain-name>/<agent-name>.yaml` per the schema in `docs/PRD.md` §4.
2. Add language declarations to each `HeuristicEntry` in `detection_heuristics.{high_confidence,medium_confidence,context_required}` — these are the implicit relevance signals (T-SCAN-REFACTOR D4).
3. Verify the agent loads: `uv run pytest tests/test_registry_invariants.py -v`.
4. Run round-trip: `/screw:scan <agent-name> <test-target>` to confirm the universal `screw-scan` subagent picks it up.

The universal `screw-scan` subagent handles all registered agents — no new subagent file needed.
```

- [ ] **Step 9: Update `docs/CONTRIBUTING.md`**

Search for any "how to add a new agent" or "how to write a subagent" sections. If present, update to reference the new AGENT_AUTHORING section above. If absent, no change needed.

- [ ] **Step 10: Update `docs/AGENT_CATALOG.md`**

Search for any references to per-agent MCP tools or per-agent subagents. Update tool counts; if the catalog formerly listed `scan_<name>` tools per agent, replace with a single note "All agents are runnable via `scan_agents([<name>])` MCP tool or `/screw:scan <name>` slash command".

- [ ] **Step 11: Final grep verification**

```
grep -rn 'scan_full\|assemble_full_scan' docs/ src/ tests/ plugins/ 2>/dev/null | grep -v __pycache__ | grep -v 'specs/' | grep -v 'PHASE_.*_PLAN\|DEFERRED_BACKLOG.*Historical entry'
```

Expected: no hits in current/active docs. Hits in `PHASE_*_PLAN.md` historical context (e.g., the T19-M plan referencing T-FULL-P1) are allowed if marked "superseded".

```
grep -rn 'screw-sqli\|screw-cmdi\|screw-ssti\|screw-xss\|screw-injection' docs/ plugins/ 2>/dev/null | grep -v __pycache__
```

Expected: no hits in `docs/` or `plugins/`. (The 5 subagent files themselves are deleted in Task 7.)

- [ ] **Step 12: Run full test suite — confirm no regression**

```
uv run pytest -q 2>&1 | tail -5
```

Expected: ~960 passed, 8 skipped. (Doc changes don't run tests; this is a sanity check.)

- [ ] **Step 13: Commit**

```bash
git add docs/
git commit -m "T-SCAN-REFACTOR Task 9: documentation sync

8 docs updated to reflect the shipped architecture (per Marco's reminder
during brainstorm, and feedback_plan_sync_on_deviation memory):

DEFERRED_BACKLOG.md:
- T-FULL-P1: SUPERSEDED 2026-04-25, forwarded to T-SCAN-REFACTOR
- blocker count table: 1 -> 0
- Phase 4 gate line: only D-01 remains
- 6 new deferred items: severity/cwe/exclude-agents filters,
  tree-sitter disambiguation, multi-session merge, explicit
  target_strategy.relevance_signals, /screw:scan list subcommand,
  --no-confirm audit hook

PROJECT_STATUS.md:
- gate line: only D-01 remains
- new 'What's shipped' bullet documents T-SCAN-REFACTOR
- Phase 4 row: pending on D-01 only
- Phase 4 Prerequisites section: T-FULL-P1 block deleted

PRD.md:
- §3 architecture: tool count 6->2, subagent count 5->1
- §4 YAML schema: HeuristicEntry.languages = implicit relevance signal
- §6 examples: multi-scope syntax samples added

DECISIONS.md:
- new ADR for T-SCAN-REFACTOR captures Path Y rationale, all
  alternatives, consequences, references to spec + plan + brainstorm

ARCHITECTURE.md:
- tool inventory, subagent inventory, scan-flow chain diagrams redrawn

AGENT_AUTHORING.md:
- new section on global uniqueness invariants
- new section on adding agents post-refactor (no per-agent subagent
  file required)

CONTRIBUTING.md, AGENT_CATALOG.md:
- references to retired tools / subagents updated

Plan and code are coherent at merge time."
```

---

## Task 10: End-to-end round-trip verification

**Goal:** Two live `claude -p` round-trips against the repo itself confirming the integrated flow works before PR open. Per `feedback_verify_before_running` memory.

**Files:** none (no code changes — verification only).

**Pre-checks:**

```fish
# Verify ANTHROPIC_API_KEY is unset (per reference_api_key_fish memory)
echo $ANTHROPIC_API_KEY
# Expected: empty / nothing

# If set, unset:
set -e ANTHROPIC_API_KEY
```

(Shell is fish per `reference_api_key_fish` memory; commands are fish syntax.)

- [ ] **Step 1: Round-trip 1 — targeted scan with prefix-key syntax**

```fish
cd /home/marco/Programming/AI/screw-agents/.worktrees/t-scan-refactor
uv sync  # ensure deps current
claude -p "/screw:scan domains:injection-input-handling agents:sqli src/screw_agents/ --no-confirm"
```

Expected:
- Pre-execution summary shows: 1 agent (sqli), domain injection-input-handling (subset), target src/screw_agents/, ~30 files, thoroughness=standard, format=markdown.
- `agents_excluded_by_relevance` likely empty (target is python, sqli supports python).
- screw-scan dispatched once, returns structured payload.
- Final report written to `.screw/findings/<session>/findings.md` (and `.json`, `.csv`, `.sarif` per T19-M D7 default).
- 0 fatal errors.

If any of the following: stop and triage:
- Pre-execution summary is missing or wrong.
- screw-scan returns `fatal_error` (cursor binding mismatch, etc.).
- Final report is missing or empty.
- Test suite was green but the live invocation fails — indicates a missed integration.

- [ ] **Step 2: Round-trip 2 — full-scope scan**

```fish
claude -p "/screw:scan full src/screw_agents/ --no-confirm"
```

Expected:
- Pre-execution summary lists all 4 shipped agents (sqli, cmdi, ssti, xss); all in injection-input-handling (full); all relevant to python (no exclusions).
- screw-scan dispatched once with all 4 agents.
- Final report aggregates findings from all 4.
- 0 fatal errors.

- [ ] **Step 3: Verify reports written**

```fish
ls -la .screw/findings/
```

Expected: directory contains the most recent session's `findings.json`, `findings.md`, `findings.csv`, `findings.sarif`.

```fish
head -20 .screw/findings/<latest-session>/findings.md
```

Expected: well-formed Markdown report with header, classification summary, findings list.

- [ ] **Step 4: Capture the round-trip outcomes for the PR description**

Save round-trip 1 + round-trip 2 stdout to clipboard or notes. Use as the PR's "Test plan" verification evidence.

- [ ] **Step 5: No commit (verification only)**

This task makes no changes; nothing to commit. Proceed to the PR open step.

---

## Self-Review Checklist

After all 10 tasks complete, run the following checks:

### 1. Spec coverage

Every D-* and Q-* decision from the spec is implemented in some task:

| Decision | Task |
|----------|------|
| D0 (Path Y refactor) | Subsumes all 10 tasks |
| D1 (flat 1D cursor) | Task 3 cursor encoding |
| D2 (file-strided fan-out) | Task 3 page-loop body |
| D3 (init-page metadata + filter result) | Task 3 init-page branch |
| D4 (HeuristicEntry.languages implicit) | Task 2 `_agent_supported_languages` |
| D5 (extension + shebang) | Task 2 shebang helper + resolver update |
| D6 (always-relevant fallback) | Task 2 `_filter_relevant_agents` |
| D7 (hard break, no compat shim) | Task 6 deletions |
| D8 (single PR) | This plan's structure |
| Q1 (Option A′ migration) | Tasks 5+6 |
| Q2 (Marco's prefix-key syntax) | Task 8 parser |
| Q3 (registry invariants) | Task 1 |
| Q4 (Option β cursor binding) | Task 3 |
| Q5 (Option I universal subagent) | Task 7 |
| Q6 (uniform filter) | Task 3 init-page filter call |

### 2. Placeholder scan

Search the plan for red flags:
- "TBD" / "TODO" / "implement later" — none should exist.
- "Add appropriate error handling" / vague guidance — none.
- "Similar to Task N" without showing code — none (every task self-contained).
- Steps that describe what without showing how — every code step has a code block.

### 3. Type / name consistency

- `assemble_agents_scan` (Task 3) and the MCP tool `scan_agents` (Task 5) — names align.
- `_filter_relevant_agents` (Task 2) and its caller in `assemble_agents_scan` (Task 3) — signature matches: `(target_codes, agents) -> tuple[list, list]`.
- `agents_excluded_by_relevance` field name (Task 3 response, Task 7 subagent return, Task 8 summary line) — consistent.
- `agents_hash` field in cursor (Task 3) — consistent across encode + decode + validation.
- `ParsedScope` / `ScopeResolutionError` (Task 8) — used consistently in helper + tests.

### 4. Threat-model coverage

Spec Section 16 enumerates 9 threats; each has a defense in this plan:
- Caller modifies cursor → Task 3 cursor binding rejection (target_hash + agents_hash).
- Caller modifies cursor target → Task 3 cursor binding (target_hash).
- Subagent re-derives agents list and drifts → Task 3 cursor binding (agents_hash).
- Relevance filter false-negative → Task 2 fail-open paths + Task 9 deferred T-SCAN-LANG-1 trigger.
- Quarantined exclusion bypass → Task 3 reuses T19-M per-source filter (unchanged).
- New agent name colliding with domain → Task 1 invariant.
- User typo in `agents:` → Task 8 `ScopeResolutionError`.
- Slash command parser injection → Task 8 closed allowlist (registry lookup) + no shell evaluation.
- `--no-confirm` audit gap → deferred T-SCAN-AUDIT-1 (not load-bearing for this PR).

### 5. Test count consistency

Section in Plan | Expected count
---|---
Baseline (main HEAD `02d90d1`) | 906 passed, 8 skipped
After Task 1 (registry invariants +5) | 911
After Task 2 (relevance filter +14) | 925
After Task 3 (assemble_agents_scan +20) | 945
After Task 4 (refactor; 0 net) | 945
After Task 5 (server dispatch +1) | 946
After Task 6 (deletions ~-8) | ~938
After Task 7 (subagent tests +7) | ~945
After Task 8 (parser tests +15) | ~960
After Task 9 (docs only; 0) | ~960
After Task 10 (verification only; 0) | ~960

Final target: **≈960 passed, 8 skipped**. Deviations of ±5 from cleanup and migration accounting are acceptable.

### 6. Cross-plan sync (per `feedback_cross_plan_sync` memory)

Before marking each task complete during execution, verify:
- `docs/DEFERRED_BACKLOG.md` Phase-4 prereq references still match.
- `docs/PROJECT_STATUS.md` blocker count still consistent with Tasks completed.
- This plan's task ordering matches the actual commit history (no out-of-order task completion).

If implementation deviates from any task's prescribed code: update this plan in the SAME PR (per `feedback_plan_sync_on_deviation` memory).

---

## PR Lifecycle

On completion of Task 10:

1. **Verify clean working tree:**
   ```fish
   cd /home/marco/Programming/AI/screw-agents/.worktrees/t-scan-refactor
   git status
   ```
   Expected: nothing to commit (all 9 commits from Tasks 1, 2, 3, 4, 5, 6, 7, 8, 9 are in).

2. **Push branch:**
   ```fish
   git push -u origin t-scan-refactor
   ```

3. **Open PR:**
   ```fish
   gh pr create --title "T-SCAN-REFACTOR — scan_agents primitive + universal subagent + multi-scope slash command (Phase-4 prereq closure)" --body (cat << 'EOF'
   ## Summary

   - Replace 6-tool MCP scan surface (`scan_full` + `scan_domain` + 4 per-agent) with `scan_agents` paginated primitive + `scan_domain` thin wrapper. Hard break — zero live external callers.
   - Add per-agent language relevance filter (`_filter_relevant_agents`) with extension lookup + shebang fallback. Drops irrelevant agents (e.g., PHP-only on Python target) before scan.
   - Generalize cursor binding to `(target_hash, agents_hash)` (Option β) — catches mid-flow agents-list drift.
   - Rewrite `/screw:scan` slash command for multi-scope syntax: `domains:A,B agents:1A,2A` for arbitrary subset selection.
   - Collapse 5 subagents (4 per-agent + 1 domain orchestrator, ~1900 LOC of byte-identical-modulo-name markdown) into 1 universal `screw-scan.md` (~420 LOC).
   - Add registry invariants: agent name unique vs domains; YAML filename stem == `meta.name`.
   - Subsumes T-FULL-P1. Phase 4 blocker count drops 1 → 0; only D-01 (Rust benchmark corpus) remains.

   Spec: `docs/specs/2026-04-25-t-scan-refactor-design.md` (gitignored working material)
   Plan: `docs/PHASE_4_PREP_T_SCAN_REFACTOR_PLAN.md`

   ## Test plan

   - [x] All ~960 unit tests pass; 8 skipped (unchanged); zero failures.
   - [x] Round-trip 1: `/screw:scan domains:injection-input-handling agents:sqli src/screw_agents/ --no-confirm` — pre-execution summary correct, sqli runs, report generated.
   - [x] Round-trip 2: `/screw:scan full src/screw_agents/ --no-confirm` — all 4 agents resolved + filtered + run, aggregated report generated.
   - [x] grep verification: zero `scan_full` / `assemble_full_scan` / `screw-sqli|cmdi|ssti|xss|injection` references in active code or docs.
   - [x] Phase-4 readiness: `docs/PROJECT_STATUS.md` shows blocker count 0; `docs/DEFERRED_BACKLOG.md` shows T-FULL-P1 superseded.
   EOF
   )
   ```

   (Note: omit Claude Code / Co-Authored-By trailers per `feedback_no_cc_commits` memory.)

4. **Merge (squash):**
   ```fish
   gh pr merge <N> --squash
   ```
   (Skip `--delete-branch` due to the worktree-checked-out gotcha per `project_phase4_prereq_t19m_complete` memory. Branch deletion handled in step 5.)

5. **Cleanup worktree + branches:**
   ```fish
   cd /home/marco/Programming/AI/screw-agents
   git pull origin main
   git worktree remove .worktrees/t-scan-refactor
   git branch -D t-scan-refactor
   gh api -X DELETE repos/h0pes/screw-agents/git/refs/heads/t-scan-refactor
   git fetch --prune
   ```

6. **Update memory:** add a project memory entry recording the shipment per the established memory pattern (`project_t_scan_refactor_complete.md`):
   - Date, commit, PR number
   - Test count delta
   - Phase 4 prereq count change
   - Brief shipped-scope summary

---

## Handoff

Plan complete and saved to `docs/PHASE_4_PREP_T_SCAN_REFACTOR_PLAN.md` (committed; per project convention plans live in `docs/`, distinct from gitignored specs in `docs/specs/`).

Two execution options:

1. **Subagent-Driven (recommended per `project_execution_mode` memory)** — fresh Opus subagent per task; pre-audit dispatch first for novel-work tasks (Tasks 2, 3, 7, 8, 9 explicitly flagged); combined spec+quality review between tasks; explicit go-ahead pause at every task boundary per `feedback_wait_for_confirmation`.

2. **Inline Execution** — execute tasks in this session via `superpowers:executing-plans` skill; batch with checkpoints for review.

**Marco's `project_execution_mode` memory says: subagent-driven + dedicated worktree is default — don't ask unless Marco specifies otherwise.**

Which approach?

