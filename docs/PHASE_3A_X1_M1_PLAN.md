# Phase 3a — X1-M1 Core-Prompt Deduplication: Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.
>
> **Per-task workflow (from `feedback_phase3a_workflow_discipline.md`):** 7-step cycle — pre-audit → implementer → spec review → quality review → triage → fix-up → cross-plan sync. Non-negotiable. Every code-producing task runs the full cycle.

**Goal:** Ship X1-M1 core-prompt deduplication for `scan_domain` and `scan_full`, unblocking Phase 3b Task 3b-19 and eliminating the round-trip-observed per-page token overflow in domain orchestration.

**Architecture:** `assemble_scan` gains an explicit `include_prompt: bool = True` kwarg. `assemble_domain_scan` splits into an init page (cursor=None → `prompts` dict + per-agent metadata, zero code) and code pages (cursor set → per-agent code slices, no prompts, no exclusions). `assemble_full_scan` returns a `dict` with top-level `prompts` + per-agent `agents` list (breaking change from `list[dict]`). Both orchestrator subagents (`screw-injection.md`, `screw-full-review.md`) are updated to cache prompts from the init page and reference them by `agent_name` on code pages.

**Tech Stack:** Python 3.11+, Pydantic models (unchanged), tree-sitter (unchanged), pytest, Claude Code subagent Markdown.

**Spec:** `docs/specs/2026-04-17-prompt-dedup-x1-m1-design.md` (local, not in git)

**Upstream phase plan:** Phase 3a complete (PRs #6, #7, #8 merged). This is a focused carryover PR #9 between Phase 3a and Phase 3b.

**Downstream phase plan:** `docs/PHASE_3B_PLAN.md` — Task 10 of this plan syncs upstream-deps table rows 69 (assemble_domain_scan) and 74 (X1-M1 marker) to the new reality.

**Branch:** `phase-3a-prompt-dedup` (per `project_execution_mode.md`: subagent-driven + dedicated worktree).

**Key references for implementers:**
- `docs/specs/2026-04-17-prompt-dedup-x1-m1-design.md` — design rationale + invariants
- `src/screw_agents/engine.py` — `assemble_scan` (L190-276), `assemble_domain_scan` (L278-401), `assemble_full_scan` (L403-422), `_build_prompt` (L757)
- `tests/test_engine.py`, `tests/test_pagination.py` — existing test patterns
- `plugins/screw/agents/screw-injection.md` — domain orchestrator (baseline from PR#3)
- `plugins/screw/agents/screw-full-review.md` — full-scan orchestrator
- `docs/DEFERRED_BACKLOG.md` — X1-M1 source entry; Phase 4+ section for `T-FULL-P1`
- `docs/PHASE_3B_PLAN.md` — upstream-deps table (lines 69, 74) for cross-plan sync

---

## Upstream Dependencies (Phase 3a artifacts this plan consumes)

| Phase 3a artifact | Current shape | How this plan uses it |
|---|---|---|
| `ScanEngine.assemble_scan(agent_name, target, thoroughness, project_root, *, preloaded_codes, _preloaded_exclusions) -> dict` | Per-agent scan payload builder (engine.py:190). Returns `{agent_name, core_prompt, code, resolved_files, meta, exclusions?, trust_status?}`. | Task 1: extend with `include_prompt: bool = True` kwarg. |
| `ScanEngine.assemble_domain_scan(..., cursor, page_size)` | Paginated domain scan (engine.py:278). Returns `{domain, agents, next_cursor, page_size, total_files, offset, trust_status?}`. | Tasks 2-4: split into init-page and code-page branches. |
| `ScanEngine.assemble_full_scan(target, thoroughness, project_root) -> list[dict]` | Flat full-agent fan-out (engine.py:403). Currently returns `list[dict]`. | Task 5: change return type to `dict` with top-level `prompts`. |
| `resolve_target(target) -> list[ResolvedCode]` | File resolution (unchanged). | Used internally by init/code branches. |
| `load_exclusions(project_root) -> list[Exclusion]` | Exclusion YAML loader (unchanged). | Init page loads once; code pages receive `_preloaded_exclusions=[]`. |

---

## File Structure

Files created or modified in this PR:

| Path | Action | Responsibility |
|---|---|---|
| `src/screw_agents/engine.py` | Modify | Add `include_prompt` kwarg; branch `assemble_domain_scan`; reshape `assemble_full_scan` |
| `tests/test_engine.py` | Modify | Regression tests for `assemble_scan(include_prompt=False)` and reshaped `assemble_full_scan` |
| `tests/test_pagination.py` | Modify | Init-page shape, code-page shape, full-walk continuity, idempotent init re-entry |
| `tests/test_prompt_dedup_roundtrip.py` | Create | Integration test simulating the multi-page orchestration |
| `plugins/screw/agents/screw-injection.md` | Modify | Update Step 1 pagination loop for init/code distinction |
| `plugins/screw/agents/screw-full-review.md` | Modify | Update for new `scan_full` response shape |
| `docs/DEFERRED_BACKLOG.md` | Modify | Mark X1-M1 shipped; add `T-FULL-P1` under Phase 4+ |
| `docs/PHASE_3B_PLAN.md` | Modify | Cross-plan sync: update upstream-deps table rows 69 and 74 |

---

## Task 0: Pre-implementation audit (no commit)

**Purpose:** Ensure the implementer has full context before touching code. Per `feedback_phase3a_workflow_discipline.md`, every code task gets a pre-audit subagent dispatch.

- [ ] **Step 1: Read the spec end-to-end**

Read `docs/specs/2026-04-17-prompt-dedup-x1-m1-design.md`. Confirm understanding of:
- Init page invariants (§2): `prompts` present IFF `cursor is None`; `agents[].core_prompt` never present; `exclusions` init-only; `code_chunks_on_page == 0` on init
- Code page invariants: no `prompts`, no `exclusions`, `agents[].code` present, `agents[].core_prompt` absent
- Cursor schema UNCHANGED (still `{target_hash, offset}`)
- `assemble_full_scan` breaking change (`list[dict]` → `dict`)
- Explicit `include_prompt` kwarg (not post-hoc strip)

- [ ] **Step 2: Read the current `assemble_scan` and `assemble_domain_scan` implementations**

Read `src/screw_agents/engine.py` lines 190-422. Identify:
- Where `_build_prompt` is called (line 243) — must be gated by `include_prompt`
- Where `core_prompt` is set in the result dict (line 248) — must be conditional
- Where `_preloaded_exclusions` flows (line 260) — code pages pass `[]` explicitly
- Where `trust_status` is attached (line 273 + 397) — stays on every page

- [ ] **Step 3: Read existing pagination tests**

Read `tests/test_pagination.py` in full. Note the fixture patterns for targets, page walks, and cursor assertions. The new tests should follow the same style.

- [ ] **Step 4: Read the two subagent orchestrator prompts**

Read `plugins/screw/agents/screw-injection.md` and `plugins/screw/agents/screw-full-review.md` to understand the current pagination-loop description and the new instructions you will write.

- [ ] **Step 5: Verify baseline tests pass**

```bash
uv run pytest -q | tail -3
```

Expected: `430 passed` (or current baseline).

---

## Task 1: Add `include_prompt` kwarg to `assemble_scan`

**Files:**
- Modify: `src/screw_agents/engine.py:190-276` (`assemble_scan`)
- Modify: `tests/test_engine.py` (new test methods)

- [ ] **Step 1: Pre-audit**

Confirm the current `assemble_scan` signature and the exact line where `self._build_prompt(agent, thoroughness)` is called (engine.py:243). The new kwarg must gate BOTH the `_build_prompt` call AND the `result["core_prompt"] = prompt` assignment.

- [ ] **Step 2: Write failing test — `include_prompt=True` default preserved**

Add to `tests/test_engine.py`:

```python
from screw_agents.engine import ScanEngine


def test_assemble_scan_default_includes_core_prompt(tmp_path: Path):
    """Regression: assemble_scan's default behavior is unchanged — core_prompt
    is present in the result. Phase 3a per-agent callers (scan_sqli, scan_cmdi,
    etc.) depend on this default."""
    (tmp_path / "a.py").write_text("cursor.execute('SELECT * FROM t')\n")
    engine = ScanEngine.from_defaults()
    target = {"type": "glob", "pattern": str(tmp_path / "*.py")}

    result = engine.assemble_scan("sqli", target)

    assert "core_prompt" in result
    assert isinstance(result["core_prompt"], str)
    assert len(result["core_prompt"]) > 0


def test_assemble_scan_include_prompt_false_omits_core_prompt(tmp_path: Path):
    """When include_prompt=False, the response does not contain a core_prompt
    key at all (not empty string — absent). Used by domain-level and
    full-scan-level callers on code pages / fan-out iterations."""
    (tmp_path / "a.py").write_text("cursor.execute('SELECT * FROM t')\n")
    engine = ScanEngine.from_defaults()
    target = {"type": "glob", "pattern": str(tmp_path / "*.py")}

    result = engine.assemble_scan("sqli", target, include_prompt=False)

    assert "core_prompt" not in result
    # Other fields must still be present
    assert result["agent_name"] == "sqli"
    assert "code" in result
    assert "resolved_files" in result
    assert "meta" in result
```

- [ ] **Step 3: Run test to verify failure**

```bash
uv run pytest tests/test_engine.py::test_assemble_scan_include_prompt_false_omits_core_prompt -v
```

Expected: FAIL — `assemble_scan()` got an unexpected keyword argument 'include_prompt'.

- [ ] **Step 4: Implement `include_prompt` kwarg**

Modify `src/screw_agents/engine.py`, method `assemble_scan`. Change the signature to add the kwarg, and gate both the prompt build and the dict assignment:

```python
    def assemble_scan(
        self,
        agent_name: str,
        target: dict[str, Any],
        thoroughness: str = "standard",
        project_root: Path | None = None,
        *,
        preloaded_codes: list[ResolvedCode] | None = None,
        _preloaded_exclusions: list[Exclusion] | None = None,
        include_prompt: bool = True,
    ) -> dict[str, Any]:
        """Assemble a scan payload for a single agent.

        ... (existing docstring) ...

        Args:
            ...
            include_prompt: When True (default), the response dict contains
                ``core_prompt`` — the full assembled detection prompt. When
                False, ``core_prompt`` is omitted entirely (not empty string —
                the key is absent). Used by ``assemble_domain_scan`` on code
                pages and by ``assemble_full_scan``'s per-agent fan-out, which
                emit ``core_prompt`` once at the top level of the response
                instead of once per agent.
        """
        agent = self._registry.get_agent(agent_name)
        if agent is None:
            raise ValueError(f"Unknown agent: {agent_name!r}")

        # Resolve target to code chunks (or use pre-resolved list from domain-level caller)
        if preloaded_codes is not None:
            codes = preloaded_codes
        else:
            codes = resolve_target(target)

        # Per-agent relevance filter still applies for broad targets (including paged slices)
        target_type = target.get("type", "")
        if target_type in ("codebase", "glob"):
            signals = agent.target_strategy.relevance_signals
            codes = filter_by_relevance(codes, signals)

        code_context = self._format_code_context(codes)

        result: dict[str, Any] = {
            "agent_name": agent_name,
            "code": code_context,
            "resolved_files": [c.file_path for c in codes],
            "meta": {
                "name": agent.meta.name,
                "display_name": agent.meta.display_name,
                "domain": agent.meta.domain,
                "cwe_primary": agent.meta.cwes.primary,
                "cwe_related": agent.meta.cwes.related,
            },
        }
        if include_prompt:
            result["core_prompt"] = self._build_prompt(agent, thoroughness)

        if project_root is not None:
            all_exclusions = _preloaded_exclusions if _preloaded_exclusions is not None else load_exclusions(project_root)
            # Subagent-facing exclusions list excludes quarantined entries —
            # exposing tampered/unsigned-under-reject entries here risks the
            # subagent (or a downstream consumer) treating them as actionable.
            # trust_status (computed below from the unfiltered list) still
            # reports the quarantine count separately so the conversational
            # summary surfaces the warning.
            agent_exclusions = [
                e for e in all_exclusions
                if e.agent == agent_name and not e.quarantined
            ]
            result["exclusions"] = [e.model_dump() for e in agent_exclusions]
            # Reuse the already-loaded list to avoid a duplicate YAML parse + verify pass.
            result["trust_status"] = self.verify_trust(
                project_root=project_root, exclusions=all_exclusions
            )
        return result
```

Note: the `prompt = ...` assignment at the top of the original function body is removed. Prompt is only built inside the `if include_prompt:` branch.

- [ ] **Step 5: Run tests to verify pass**

```bash
uv run pytest tests/test_engine.py::test_assemble_scan_default_includes_core_prompt tests/test_engine.py::test_assemble_scan_include_prompt_false_omits_core_prompt -v
```

Expected: PASS (both).

Then run the full engine test module to ensure no regression:

```bash
uv run pytest tests/test_engine.py -v
```

Expected: all PASS.

- [ ] **Step 6: Commit**

```bash
git add src/screw_agents/engine.py tests/test_engine.py
git commit -m "feat(engine): add include_prompt kwarg to assemble_scan

Gates both the _build_prompt call and the core_prompt dict
assignment. Default True preserves per-agent callers (scan_sqli,
scan_cmdi, etc.). Domain-level and full-scan callers will pass
False on fan-out iterations to enable prompt deduplication at
the response top level."
```

---

## Task 2: `assemble_domain_scan` init-page branch

**Files:**
- Modify: `src/screw_agents/engine.py:278-401` (`assemble_domain_scan`)
- Modify: `tests/test_pagination.py` (new init-page tests)

- [ ] **Step 1: Pre-audit**

Re-read `assemble_domain_scan`. Identify the four sections you will modify:
1. Cursor decode block (currently L335-353) — no change
2. Code resolution + paging (L355-368) — on init page, `page_codes` must be empty (no code on init)
3. Exclusions load (L370-375) — no change
4. Per-agent fan-out (L377-387) — on init page, pass `include_prompt=True`; on code pages, pass `include_prompt=False` + `_preloaded_exclusions=[]`

Note: on the init page, `code_chunks_on_page == 0` and `offset` stays at 0. The `next_cursor` must encode `offset=0` so the next call starts the first code page at offset 0.

- [ ] **Step 2: Write failing tests — init-page shape**

Add to `tests/test_pagination.py`:

```python
def _seed_injection_fixture(root: Path, n: int = 12) -> None:
    """Helper: write n Python files with sqli-visible patterns so the
    sqli relevance filter retains them."""
    for i in range(n):
        (root / f"file_{i:02d}.py").write_text(
            f"cursor.execute('SELECT * FROM t WHERE x = ' + user_input_{i})\n"
        )


def test_domain_scan_init_page_shape(tmp_path: Path):
    """Init page (cursor=None) returns top-level `prompts` dict keyed by
    agent_name, per-agent entries without core_prompt, zero code chunks, and
    a next_cursor encoding offset=0."""
    _seed_injection_fixture(tmp_path)
    engine = ScanEngine.from_defaults()
    target = {"type": "glob", "pattern": str(tmp_path / "*.py")}

    result = engine.assemble_domain_scan(
        "injection-input-handling", target, cursor=None
    )

    # Top-level prompts dict
    assert "prompts" in result
    assert isinstance(result["prompts"], dict)
    # All injection-domain agents represented (at least sqli, cmdi, ssti, xss)
    assert {"sqli", "cmdi", "ssti", "xss"}.issubset(set(result["prompts"].keys()))
    for prompt in result["prompts"].values():
        assert isinstance(prompt, str)
        assert len(prompt) > 0

    # Per-agent entries: metadata only on init, no core_prompt, no code
    assert "agents" in result
    for agent_entry in result["agents"]:
        assert "agent_name" in agent_entry
        assert "core_prompt" not in agent_entry
        assert "meta" in agent_entry
        # Code is empty or absent on init page
        assert agent_entry.get("code", "") == "" or "code" not in agent_entry

    # Init-page metadata
    assert result["code_chunks_on_page"] == 0
    assert result["offset"] == 0
    assert result["next_cursor"] is not None  # non-empty scan → next cursor for code pages


def test_domain_scan_init_page_idempotent(tmp_path: Path):
    """Calling assemble_domain_scan with cursor=None twice returns the same
    init-page shape both times. No state change between calls."""
    _seed_injection_fixture(tmp_path)
    engine = ScanEngine.from_defaults()
    target = {"type": "glob", "pattern": str(tmp_path / "*.py")}

    r1 = engine.assemble_domain_scan("injection-input-handling", target, cursor=None)
    r2 = engine.assemble_domain_scan("injection-input-handling", target, cursor=None)

    assert r1.keys() == r2.keys()
    assert set(r1["prompts"].keys()) == set(r2["prompts"].keys())
    assert r1["code_chunks_on_page"] == r2["code_chunks_on_page"] == 0
    assert r1["next_cursor"] == r2["next_cursor"]


def test_domain_scan_init_page_empty_target(tmp_path: Path):
    """When total_files == 0, init page still ships with prompts; next_cursor
    is None (no code pages to fetch)."""
    engine = ScanEngine.from_defaults()
    target = {"type": "glob", "pattern": str(tmp_path / "*.py")}  # empty dir

    result = engine.assemble_domain_scan(
        "injection-input-handling", target, cursor=None
    )

    assert "prompts" in result
    assert result["total_files"] == 0
    assert result["code_chunks_on_page"] == 0
    assert result["next_cursor"] is None  # nothing to paginate
```

- [ ] **Step 3: Run tests to verify failure**

```bash
uv run pytest tests/test_pagination.py::test_domain_scan_init_page_shape -v
```

Expected: FAIL — `'prompts' not in result` or similar assertion failure.

- [ ] **Step 4: Implement init-page branch in `assemble_domain_scan`**

Modify `src/screw_agents/engine.py`, method `assemble_domain_scan`. Replace the body from the code-resolution section onward:

```python
        # Canonical target hash binds the cursor to the target -- rejects replay across targets
        canonical = _json.dumps(target, sort_keys=True, separators=(",", ":"))
        target_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]

        is_init_page = cursor is None

        # Decode cursor (unchanged)
        if cursor:
            try:
                decoded = _json.loads(
                    base64.urlsafe_b64decode(cursor.encode("ascii")).decode("utf-8")
                )
                if decoded.get("target_hash") != target_hash:
                    raise ValueError(
                        "cursor is bound to a different target; refusing to use"
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

        # Resolve target + compute total_files (always, both init and code pages)
        all_codes = resolve_target(target)
        total_files = len(all_codes)

        agents = self._registry.get_agents_by_domain(domain)

        # Load exclusions ONCE for the entire domain scan (init page only — code pages
        # carry empty exclusions since they are project-wide and static within a scan session)
        if project_root is not None and is_init_page:
            domain_exclusions = load_exclusions(project_root)
        else:
            domain_exclusions = None

        if is_init_page:
            # Init page: emit top-level `prompts` dict + per-agent metadata entries.
            # Zero code on this page. Exclusions included (project-wide snapshot).
            prompts_dict: dict[str, str] = {
                a.meta.name: self._build_prompt(a, thoroughness) for a in agents
            }

            agents_responses = []
            for a in agents:
                # Build minimal agent entry with metadata + (optional) exclusions. No code.
                entry: dict[str, Any] = {
                    "agent_name": a.meta.name,
                    "meta": {
                        "name": a.meta.name,
                        "display_name": a.meta.display_name,
                        "domain": a.meta.domain,
                        "cwe_primary": a.meta.cwes.primary,
                        "cwe_related": a.meta.cwes.related,
                    },
                }
                if project_root is not None and domain_exclusions is not None:
                    agent_exclusions = [
                        e for e in domain_exclusions
                        if e.agent == a.meta.name and not e.quarantined
                    ]
                    entry["exclusions"] = [e.model_dump() for e in agent_exclusions]
                agents_responses.append(entry)

            # next_cursor: if there are code pages, point to offset=0; else None
            if total_files > 0:
                next_cursor: str | None = base64.urlsafe_b64encode(
                    _json.dumps(
                        {"target_hash": target_hash, "offset": 0},
                        separators=(",", ":"),
                    ).encode("utf-8")
                ).decode("ascii")
            else:
                next_cursor = None

            result: dict[str, Any] = {
                "domain": domain,
                "prompts": prompts_dict,
                "agents": agents_responses,
                "next_cursor": next_cursor,
                "page_size": page_size,
                "total_files": total_files,
                "code_chunks_on_page": 0,
                "offset": 0,
            }
            if project_root is not None:
                result["trust_status"] = self.verify_trust(
                    project_root=project_root, exclusions=domain_exclusions
                )
            return result

        # Code-page branch (cursor was non-None) — implemented in Task 3
        raise NotImplementedError("code-page branch implemented in Task 3")
```

Note: the `NotImplementedError` placeholder is intentional — Task 3 replaces it. Keep the existing end-of-function `return result` block OUT (it will be reintroduced in Task 3).

- [ ] **Step 5: Run tests to verify init-page tests pass**

```bash
uv run pytest tests/test_pagination.py::test_domain_scan_init_page_shape tests/test_pagination.py::test_domain_scan_init_page_idempotent tests/test_pagination.py::test_domain_scan_init_page_empty_target -v
```

Expected: PASS (all three).

**Do not run the full pagination test suite yet** — existing pagination tests (walking through multiple pages) depend on the code-page branch, which is still a `NotImplementedError` stub. Task 3 will fix them.

- [ ] **Step 6: Commit**

```bash
git add src/screw_agents/engine.py tests/test_pagination.py
git commit -m "feat(engine): assemble_domain_scan init-page branch

Cursor=None now returns an init page: top-level prompts dict keyed
by agent_name, per-agent entries with metadata + exclusions (no
core_prompt, no code), code_chunks_on_page=0, next_cursor pointing
at offset=0 for the first code page. Code-page branch follows in
the next commit (placeholder NotImplementedError for now)."
```

---

## Task 3: `assemble_domain_scan` code-page branch

**Files:**
- Modify: `src/screw_agents/engine.py:278-401` (`assemble_domain_scan`)
- Modify: `tests/test_pagination.py` (new code-page tests)

- [ ] **Step 1: Pre-audit**

Re-read the stubbed code-page branch placeholder from Task 2. The code-page branch must:
- Accept a non-None cursor (already decoded in the shared block)
- Fetch `page_codes = all_codes[offset : offset + page_size]`
- Fan out `assemble_scan` with `include_prompt=False` and `_preloaded_exclusions=[]`
- Omit `prompts` from the response
- Compute `next_cursor` based on `next_offset = offset + len(page_codes)`
- Preserve `trust_status` on the response

- [ ] **Step 2: Write failing tests — code-page shape**

Add to `tests/test_pagination.py`:

```python
def test_domain_scan_code_page_shape(tmp_path: Path):
    """First code page (cursor from init): no top-level prompts, per-agent
    entries have code but no core_prompt, no exclusions (moved to init)."""
    _seed_injection_fixture(tmp_path)
    engine = ScanEngine.from_defaults()
    target = {"type": "glob", "pattern": str(tmp_path / "*.py")}

    init = engine.assemble_domain_scan("injection-input-handling", target, cursor=None)
    code_page = engine.assemble_domain_scan(
        "injection-input-handling", target, cursor=init["next_cursor"]
    )

    # No prompts on code pages
    assert "prompts" not in code_page

    # Per-agent entries: code present, no core_prompt, no exclusions
    for agent_entry in code_page["agents"]:
        assert "agent_name" in agent_entry
        assert "core_prompt" not in agent_entry
        assert "code" in agent_entry
        assert "exclusions" not in agent_entry
        assert "meta" in agent_entry

    # Code-page metadata
    assert code_page["offset"] == 0
    assert code_page["code_chunks_on_page"] > 0  # fixture has files


def test_domain_scan_code_page_cursor_replay_different_target_rejected(tmp_path: Path):
    """Replaying a cursor against a different target raises ValueError —
    existing invariant preserved."""
    _seed_injection_fixture(tmp_path)
    other = tmp_path / "other"
    other.mkdir()
    (other / "b.py").write_text("cursor.execute('SELECT 1')\n")

    engine = ScanEngine.from_defaults()
    target_a = {"type": "glob", "pattern": str(tmp_path / "*.py")}
    target_b = {"type": "glob", "pattern": str(other / "*.py")}

    init = engine.assemble_domain_scan("injection-input-handling", target_a, cursor=None)
    with pytest.raises(ValueError, match="cursor is bound to a different target"):
        engine.assemble_domain_scan(
            "injection-input-handling", target_b, cursor=init["next_cursor"]
        )


def test_domain_scan_trust_status_on_every_page(tmp_path: Path):
    """trust_status appears on init AND on every code page — subagent may
    read it from any page. When project_root is a bare tmp_path (no .screw/
    directory), trust_status reports all-zero counts but is still present."""
    _seed_injection_fixture(tmp_path)
    engine = ScanEngine.from_defaults()
    target = {"type": "glob", "pattern": str(tmp_path / "*.py")}

    init = engine.assemble_domain_scan(
        "injection-input-handling", target, project_root=tmp_path, cursor=None
    )
    code_page = engine.assemble_domain_scan(
        "injection-input-handling", target, project_root=tmp_path,
        cursor=init["next_cursor"]
    )

    assert "trust_status" in init
    assert "trust_status" in code_page
    assert init["trust_status"].keys() == code_page["trust_status"].keys()
```

- [ ] **Step 3: Run tests to verify failure**

```bash
uv run pytest tests/test_pagination.py::test_domain_scan_code_page_shape -v
```

Expected: FAIL — `NotImplementedError: code-page branch implemented in Task 3`.

- [ ] **Step 4: Implement code-page branch**

In `src/screw_agents/engine.py`, `assemble_domain_scan`, replace the `raise NotImplementedError(...)` line at the end of the init branch with the full code-page branch:

```python
        # Code-page branch (cursor was non-None)
        page_codes = all_codes[offset : offset + page_size]
        next_offset = offset + len(page_codes)
        if next_offset < total_files:
            next_cursor = base64.urlsafe_b64encode(
                _json.dumps(
                    {"target_hash": target_hash, "offset": next_offset},
                    separators=(",", ":"),
                ).encode("utf-8")
            ).decode("ascii")
        else:
            next_cursor = None

        # Code pages: fan out assemble_scan with include_prompt=False and
        # empty exclusions list (exclusions were delivered on the init page).
        agents_responses = [
            self.assemble_scan(
                a.meta.name,
                target,
                thoroughness,
                project_root,
                preloaded_codes=page_codes,
                _preloaded_exclusions=[],  # suppress exclusion re-emit on code pages
                include_prompt=False,       # no core_prompt on code pages
            )
            for a in agents
        ]

        # Drop `exclusions` and `trust_status` fields that assemble_scan may have
        # added when project_root is set — code pages carry trust_status at the
        # top level only, and exclusions are init-only by design.
        for entry in agents_responses:
            entry.pop("exclusions", None)
            entry.pop("trust_status", None)

        result = {
            "domain": domain,
            "agents": agents_responses,
            "next_cursor": next_cursor,
            "page_size": page_size,
            "total_files": total_files,
            "code_chunks_on_page": len(page_codes),
            "offset": offset,
        }
        if project_root is not None:
            # Recompute trust_status for this page — identical across pages; cheap.
            result["trust_status"] = self.verify_trust(project_root=project_root)
        return result
```

Note on the `entry.pop("exclusions", None)` line: `assemble_scan` will attach `exclusions` when `project_root is not None` even with `_preloaded_exclusions=[]` (it will filter an empty list to an empty list). This post-hoc pop is belt-and-suspenders — the list is empty anyway, but removing the key entirely keeps the code-page response schema clean.

- [ ] **Step 5: Run all pagination tests**

```bash
uv run pytest tests/test_pagination.py -v
```

Expected: all PASS (including existing pre-X1-M1 pagination tests that walk through code pages).

Some existing tests may have assertions like `assert "core_prompt" in result["agents"][0]` — those must be UPDATED as part of this task to reflect the new shape. Scan for them:

```bash
grep -n "core_prompt" tests/test_pagination.py
```

If any existing test asserts `core_prompt` in a domain-scan response, update it to assert `core_prompt not in` on code pages and `core_prompt not in` + `prompts[name] == ...` on init pages.

- [ ] **Step 6: Run full engine + pagination test modules**

```bash
uv run pytest tests/test_engine.py tests/test_pagination.py -v
```

Expected: all PASS.

- [ ] **Step 7: Commit**

```bash
git add src/screw_agents/engine.py tests/test_pagination.py
git commit -m "feat(engine): assemble_domain_scan code-page branch

Code pages (cursor!=None) fan out assemble_scan with
include_prompt=False and _preloaded_exclusions=[], strip any
lingering exclusions/trust_status from per-agent entries, and
emit trust_status once at the response top level. No top-level
prompts on code pages — orchestrator subagents cache prompts
from the init page and reference them by agent_name."
```

---

## Task 4: Full-walk integration test

**Files:**
- Create: `tests/test_prompt_dedup_roundtrip.py`

- [ ] **Step 1: Write the failing test**

Create `tests/test_prompt_dedup_roundtrip.py`:

```python
"""Integration-style tests simulating the multi-page orchestration a subagent
would run against scan_domain. Asserts structural correctness of the full
walk: prompts on init only, code on code pages only, no duplicate coverage,
all expected files processed exactly once across the walk."""

from __future__ import annotations

from pathlib import Path

import pytest

from screw_agents.engine import ScanEngine


def _seed(root: Path, n: int = 12) -> None:
    """Seed n Python files carrying sqli relevance signals so the sqli
    relevance filter retains all of them."""
    for i in range(n):
        (root / f"file_{i:02d}.py").write_text(
            f"cursor.execute('SELECT * FROM t WHERE x = ' + user_input_{i})\n"
        )


def test_domain_scan_full_walk_no_prompt_duplication(tmp_path: Path):
    """Walk the entire pagination sequence: init → code pages → null cursor.
    Assert:
      - `prompts` present exactly once (init page)
      - `core_prompt` never present in any `agents[]` entry on any page
      - Every file appears in exactly one code page's `resolved_files`
      - `agents[].code` has meaningful content on every code page
    """
    _seed(tmp_path, n=12)
    engine = ScanEngine.from_defaults()
    target = {"type": "glob", "pattern": str(tmp_path / "*.py")}

    # Init page
    init = engine.assemble_domain_scan(
        "injection-input-handling", target, cursor=None, page_size=3
    )
    assert "prompts" in init
    assert init["code_chunks_on_page"] == 0
    for agent_entry in init["agents"]:
        assert "core_prompt" not in agent_entry

    total_files_expected = init["total_files"]
    assert total_files_expected > 3  # ensure fixture produces a multi-page walk

    # Walk code pages
    cursor = init["next_cursor"]
    files_seen_per_agent: dict[str, list[str]] = {
        agent_entry["agent_name"]: [] for agent_entry in init["agents"]
    }
    code_pages_count = 0

    while cursor is not None:
        page = engine.assemble_domain_scan(
            "injection-input-handling", target, cursor=cursor, page_size=3
        )
        assert "prompts" not in page, "prompts must not appear on code pages"
        assert page["code_chunks_on_page"] > 0
        for agent_entry in page["agents"]:
            assert "core_prompt" not in agent_entry
            files_seen_per_agent[agent_entry["agent_name"]].extend(
                agent_entry["resolved_files"]
            )
        code_pages_count += 1
        cursor = page["next_cursor"]

    assert code_pages_count >= 2  # multi-page walk actually happened

    # Each agent must have seen every file exactly once
    # (relevance filtering may drop some files for some agents — expected)
    for agent_name, seen in files_seen_per_agent.items():
        # No duplicates within one agent's file list across pages
        assert len(seen) == len(set(seen)), f"agent {agent_name} saw duplicates: {seen}"


def test_domain_scan_full_walk_payload_size_regression(tmp_path: Path):
    """Smoke-check the intended token savings: prompts should appear in exactly
    one page's wire payload, not N pages."""
    _seed(tmp_path, n=12)
    engine = ScanEngine.from_defaults()
    target = {"type": "glob", "pattern": str(tmp_path / "*.py")}

    pages = []
    cursor = None
    while True:
        page = engine.assemble_domain_scan(
            "injection-input-handling", target, cursor=cursor, page_size=3
        )
        pages.append(page)
        cursor = page["next_cursor"]
        if cursor is None:
            break

    # Exactly one page has 'prompts'
    pages_with_prompts = [p for p in pages if "prompts" in p]
    assert len(pages_with_prompts) == 1
    assert pages_with_prompts[0] is pages[0]  # init page is page 0

    # No page's per-agent entry has core_prompt
    for page in pages:
        for agent_entry in page["agents"]:
            assert "core_prompt" not in agent_entry
```

Note on fixtures: no conftest.py additions required. Tests use `tmp_path` (pytest built-in) + inline seeding via the local `_seed` helper, matching the pattern already used in `tests/test_pagination.py`.

- [ ] **Step 2: Run tests to verify pass** (should pass given Tasks 1-3)

```bash
uv run pytest tests/test_prompt_dedup_roundtrip.py -v
```

Expected: PASS (both test functions).

If any fail, the cause is likely a missing fixture or an incomplete implementation in Task 2/3 — triage and fix back in the originating task.

- [ ] **Step 3: Run full test suite**

```bash
uv run pytest -q | tail -5
```

Expected: `N passed` with N ≥ 430 (existing baseline) + new tests. Typically ~440+ passed.

- [ ] **Step 4: Commit**

```bash
git add tests/test_prompt_dedup_roundtrip.py
git commit -m "test(engine): full-walk integration coverage for X1-M1

Walks the entire scan_domain pagination sequence and asserts
structural correctness: prompts present exactly once (init page),
core_prompt never in agents[] entries, files seen exactly once
per agent across the walk."
```

---

## Task 5: `assemble_full_scan` prompt dedup

**Files:**
- Modify: `src/screw_agents/engine.py:403-422` (`assemble_full_scan`)
- Modify: `tests/test_engine.py` (reshape tests)

- [ ] **Step 1: Pre-audit**

Re-read `assemble_full_scan`. Currently returns `list[dict]` (line 419-422). This is a breaking change — every existing test that asserts on the return type needs updating. Scan for them:

```bash
grep -rn "assemble_full_scan\|scan_full" tests/ src/
```

Note every location; Tasks 5 and 7 will update each.

- [ ] **Step 2: Write failing test — new dict return shape**

Add to `tests/test_engine.py`:

```python
def test_assemble_full_scan_returns_dict_with_top_level_prompts(tmp_path: Path):
    """BREAKING CHANGE: assemble_full_scan now returns a dict (not list).
    Top-level `prompts` keyed by agent_name; `agents` list carries per-agent
    entries without core_prompt."""
    (tmp_path / "a.py").write_text(
        "cursor.execute('SELECT * FROM t WHERE x = ' + user_input)\n"
    )
    engine = ScanEngine.from_defaults()
    target = {"type": "glob", "pattern": str(tmp_path / "*.py")}

    result = engine.assemble_full_scan(target)

    assert isinstance(result, dict)
    assert "prompts" in result
    assert "agents" in result
    assert isinstance(result["prompts"], dict)
    assert isinstance(result["agents"], list)

    # Every registered agent has a prompt entry
    agent_names_in_agents = {a["agent_name"] for a in result["agents"]}
    assert set(result["prompts"].keys()) == agent_names_in_agents

    # No per-agent entry carries core_prompt
    for agent_entry in result["agents"]:
        assert "core_prompt" not in agent_entry
        assert "code" in agent_entry
        assert "meta" in agent_entry


def test_assemble_full_scan_includes_trust_status_when_project_root_set(tmp_path: Path):
    """trust_status appears at the top level of the full-scan response when
    project_root is provided. Bare tmp_path (no .screw/) still yields a
    present, all-zero trust_status dict."""
    (tmp_path / "a.py").write_text("cursor.execute('SELECT 1')\n")
    engine = ScanEngine.from_defaults()
    target = {"type": "glob", "pattern": str(tmp_path / "*.py")}

    result = engine.assemble_full_scan(target, project_root=tmp_path)

    assert "trust_status" in result
    assert "exclusion_quarantine_count" in result["trust_status"]
```

- [ ] **Step 3: Run test to verify failure**

```bash
uv run pytest tests/test_engine.py::test_assemble_full_scan_returns_dict_with_top_level_prompts -v
```

Expected: FAIL — current implementation returns `list[dict]`.

- [ ] **Step 4: Implement the reshape**

Modify `src/screw_agents/engine.py`, method `assemble_full_scan`. Replace the body:

```python
    def assemble_full_scan(
        self,
        target: dict[str, Any],
        thoroughness: str = "standard",
        project_root: Path | None = None,
    ) -> dict[str, Any]:
        """Assemble scan payloads for all registered agents.

        Returns a single response dict with top-level ``prompts`` (one entry
        per agent) and ``agents`` (list of per-agent code + metadata entries,
        no core_prompt). Use ``prompts[agent_name]`` to look up the detection
        prompt for each agent.

        Args:
            target: Target spec dict.
            thoroughness: Passed through to assemble_scan.
            project_root: Optional project root for exclusion loading.

        Returns:
            Dict with keys:
                prompts: dict[str, str] -- keyed by agent_name
                agents: list[dict] -- per-agent code + meta (no core_prompt)
                trust_status: dict -- only when project_root is provided
        """
        all_agent_names = list(self._registry.agents)

        # Load exclusions once if project_root is set (mirrors assemble_domain_scan)
        if project_root is not None:
            all_exclusions = load_exclusions(project_root)
        else:
            all_exclusions = None

        # Build prompts dict (one call to _build_prompt per agent)
        prompts_dict: dict[str, str] = {}
        for name in all_agent_names:
            agent = self._registry.get_agent(name)
            prompts_dict[name] = self._build_prompt(agent, thoroughness)

        # Fan out assemble_scan with include_prompt=False on each agent
        agents_responses = [
            self.assemble_scan(
                name,
                target,
                thoroughness,
                project_root,
                _preloaded_exclusions=all_exclusions,
                include_prompt=False,
            )
            for name in all_agent_names
        ]

        # Strip per-agent trust_status — emit once at top level only
        for entry in agents_responses:
            entry.pop("trust_status", None)

        result: dict[str, Any] = {
            "prompts": prompts_dict,
            "agents": agents_responses,
        }
        if project_root is not None:
            result["trust_status"] = self.verify_trust(
                project_root=project_root, exclusions=all_exclusions
            )
        return result
```

- [ ] **Step 5: Update any legacy callers / tests**

Scan and update:

```bash
grep -rn "assemble_full_scan" tests/ src/
```

For each call site that unpacks the old `list[dict]` shape (e.g., `for entry in result: ...`), update to iterate `result["agents"]` instead. For test assertions like `assert len(result) == N`, update to `assert len(result["agents"]) == N`.

Expected locations (verify via the grep):
- `src/screw_agents/server.py` — the `scan_full` MCP tool dispatcher (if present)
- `tests/test_engine.py` — any legacy `assemble_full_scan` test

Update each site for the new shape. If the MCP server's `_dispatch_tool` for `scan_full` wraps the response, ensure the wrapper correctly handles the dict return.

- [ ] **Step 6: Run tests to verify pass**

```bash
uv run pytest tests/test_engine.py -v
uv run pytest -q | tail -5
```

Expected: all PASS. Total passing count should rise further (more new tests than regressions — regressions should all be UPDATED tests asserting the new shape).

- [ ] **Step 7: Commit**

```bash
git add src/screw_agents/engine.py tests/test_engine.py src/screw_agents/server.py
git commit -m "feat(engine): assemble_full_scan prompt dedup (breaking change)

Return type changes from list[dict] to dict with top-level prompts
+ agents list. Per-agent entries no longer carry core_prompt.
Callers must look up prompts[agent_name] instead of per-entry
core_prompt. Same structural fix as X1-M1 for scan_domain; see
DEFERRED_BACKLOG T-FULL-P1 for the follow-up pagination work."
```

---

## Task 6: Update `screw-injection.md` orchestrator subagent

**Files:**
- Modify: `plugins/screw/agents/screw-injection.md`

- [ ] **Step 1: Pre-audit**

Re-read the current `screw-injection.md`. Note that Step 1 ("Run scan_domain with pagination loop") contains JSON-shape documentation referencing the old response (with per-agent `core_prompt`). Everything after Step 2 stays unchanged.

- [ ] **Step 2: Rewrite Step 1**

Replace the "Step 1: Run scan_domain with pagination loop" section. Full replacement:

````markdown
### Step 1: Run scan_domain with pagination loop (init page + code pages)

Determine the project root and target spec (same format as individual agents). The pagination sequence is:

- **Init page** (`cursor` omitted or null): returns the top-level `prompts` dict + per-agent metadata + exclusions. **No code on this page.**
- **Code pages** (`cursor` set to the prior response's `next_cursor`): returns per-agent code slices, no prompts, no exclusions.

```json
// Init-page response (cursor=None):
{
  "domain": "injection-input-handling",
  "prompts": {
    "sqli": "<full core_prompt for sqli agent>",
    "cmdi": "<full core_prompt for cmdi agent>",
    "ssti": "<full core_prompt for ssti agent>",
    "xss":  "<full core_prompt for xss agent>"
  },
  "agents": [
    {"agent_name": "sqli", "meta": {...}, "exclusions": [...]},
    {"agent_name": "cmdi", "meta": {...}, "exclusions": [...]},
    {"agent_name": "ssti", "meta": {...}, "exclusions": [...]},
    {"agent_name": "xss",  "meta": {...}, "exclusions": [...]}
  ],
  "next_cursor": "<token for first code page>" | null,
  "code_chunks_on_page": 0,
  "offset": 0,
  "total_files": 237,
  "trust_status": {...}
}

// Code-page response (cursor=<from init>):
{
  "domain": "injection-input-handling",
  "agents": [
    {"agent_name": "sqli", "code": "<slice>", "resolved_files": [...], "meta": {...}},
    {"agent_name": "cmdi", "code": "<slice>", "resolved_files": [...], "meta": {...}},
    {"agent_name": "ssti", "code": "<slice>", "resolved_files": [...], "meta": {...}},
    {"agent_name": "xss",  "code": "<slice>", "resolved_files": [...], "meta": {...}}
  ],
  "next_cursor": "<next token>" | null,
  "code_chunks_on_page": 5,
  "offset": 0,
  "total_files": 237,
  "trust_status": {...}
}
```

**Paginate like this:**

1. **Call `scan_domain` with `cursor` omitted or null** (init page):
   ```
   mcp__screw-agents__scan_domain({
     "domain": "injection-input-handling",
     "target": <target spec>,
     "project_root": "<absolute path to project root>",
     "thoroughness": "standard"
   })
   ```
2. **Cache the `prompts` dict from the init-page response.** You will apply `prompts[agent_name]` on every subsequent code page when analyzing that agent's `code`.
3. **Save the init-page `trust_status`** — it is project-wide, identical on every page. You will reference it in Step 2b and Step 4.
4. **Save the init-page `exclusions` per agent** — they are project-wide and do not reappear on code pages. Use them to suppress findings that match a prior exclusion.
5. **If `response.next_cursor` is null**, pagination is complete (typically because `total_files == 0`). Skip ahead to Step 3.
6. **Otherwise, call `scan_domain` again** with the same `domain`/`target`/`project_root` and `cursor` set to the returned value. This returns a code page.
7. **For each `agent_entry` in the code page's `agents` list**, analyze `prompts[agent_entry.agent_name]` + `agent_entry.code` and produce findings (id prefix: sqli-001, cmdi-001, ssti-001, xss-001). **Accumulate findings — do NOT call `write_scan_results` yet.**
8. **If `response.next_cursor` is a string**, loop back to step 6. When `next_cursor` is null, pagination is complete — proceed to Step 2.

**Critical rules:**
- **Cache `prompts` from the init page exactly once.** If you fail to cache them, the code pages will have no prompts to apply — restart the scan with `cursor=None` to re-fetch the init page.
- Do NOT call `write_scan_results` per-page — it overwrites the previous page's output file. Accumulate all findings, then write once in Step 3.
- Do NOT re-resolve the target between pages — the cursor carries the binding. A cursor from one target is invalid for another.
- If `response.total_files` is 0 on the init page, `next_cursor` is null — skip the code-page loop.
````

Keep Step 2, Step 2b, Step 3, Step 4 unchanged except for any reference to per-page `core_prompt` or per-page `exclusions` (replace with "cached from init page" framing).

- [ ] **Step 3: Commit**

```bash
git add plugins/screw/agents/screw-injection.md
git commit -m "docs(plugin): update screw-injection orchestrator for X1-M1

Rewrites Step 1 pagination loop to handle init page (prompts +
metadata, no code) vs code pages (per-agent code slices, no
prompts, no exclusions). Orchestrator now caches prompts from
the init page and references them by agent_name when analyzing
each code page's agent entries."
```

---

## Task 7: Update `screw-full-review.md` orchestrator subagent

**Files:**
- Modify: `plugins/screw/agents/screw-full-review.md`

- [ ] **Step 1: Pre-audit**

Read `plugins/screw/agents/screw-full-review.md` to identify the section(s) that describe the `scan_full` response shape. Typically the scan-invocation step lists the expected JSON.

- [ ] **Step 2: Update the scan-invocation section**

Find the block that documents the `scan_full` return shape. Replace with:

````markdown
### Scan invocation

Call `mcp__screw-agents__scan_full` with the target spec and optional project_root. The response is a **dict** (breaking change — was `list[dict]` pre-X1-M1):

```json
{
  "prompts": {
    "sqli": "<core_prompt>",
    "cmdi": "<core_prompt>",
    "ssti": "<core_prompt>",
    "xss":  "<core_prompt>"
  },
  "agents": [
    {"agent_name": "sqli", "code": "<slice>", "resolved_files": [...], "meta": {...}, "exclusions": [...]},
    {"agent_name": "cmdi", "code": "<slice>", "resolved_files": [...], "meta": {...}, "exclusions": [...]},
    {"agent_name": "ssti", "code": "<slice>", "resolved_files": [...], "meta": {...}, "exclusions": [...]},
    {"agent_name": "xss",  "code": "<slice>", "resolved_files": [...], "meta": {...}, "exclusions": [...]}
  ],
  "trust_status": {...}
}
```

**For each entry in `response.agents`:** analyze `response.prompts[entry.agent_name]` + `entry.code` to produce findings. Do NOT look for `core_prompt` in the per-agent entries — it is not present.

**Note on scale:** `scan_full` returns all code for all agents in a single response. On a large codebase this may exceed the subagent's token budget. If you hit overflow, fall back to per-domain scans (`scan_domain`) or per-agent scans (`scan_sqli`, etc.). A follow-up PR (`T-FULL-P1` in DEFERRED_BACKLOG) will add pagination to `scan_full`.
````

- [ ] **Step 3: Commit**

```bash
git add plugins/screw/agents/screw-full-review.md
git commit -m "docs(plugin): update screw-full-review orchestrator for X1-M1

Documents the new scan_full response shape (dict with top-level
prompts + agents list) and adds a note about the single-response
scale limitation pointing at T-FULL-P1 for future pagination work."
```

---

## Task 8: Update `docs/DEFERRED_BACKLOG.md`

**Files:**
- Modify: `docs/DEFERRED_BACKLOG.md`

- [ ] **Step 1: Remove X1-M1 from TOP PRIORITY section**

Locate the "## **TOP PRIORITY — Must address before Phase 3b starts**" section and the `### X1-M1 — Core-prompt deduplication...` entry below it. Replace the entire section (heading + entry) with the entry moved to a new "## Shipped" section at the bottom of the file:

```markdown
## Shipped

### X1-M1 — Core-prompt deduplication in `scan_domain` paginated responses
**Source:** Phase 3a PR#3 manual round-trip test, 2026-04-17
**Shipped in:** PR #9 (`phase-3a-prompt-dedup`), merge commit `<fill in at merge time>`
**Final design:** `docs/specs/2026-04-17-prompt-dedup-x1-m1-design.md` (local, not in git)
**Plan:** `docs/PHASE_3A_X1_M1_PLAN.md`

**Solution:** Applied Option A′ (init page + code pages) to `assemble_domain_scan` and Option A (top-level `prompts` dedup) to `assemble_full_scan`. `assemble_scan` gained `include_prompt: bool = True` kwarg. Cursor schema unchanged. `assemble_full_scan` return type changed from `list[dict]` to `dict` — breaking change to `scan_full` MCP tool.

**Follow-up:** `T-FULL-P1` (Phase 4+) tracks paginating `assemble_full_scan` and applying Option A′.
```

The TOP PRIORITY section header can be removed entirely if it contains no other entries.

- [ ] **Step 2: Add `T-FULL-P1` entry under Phase 4+ section**

Locate the `## Phase 4+ (autoresearch / scale)` section. Add this entry at the top of that section (highest priority within the section):

```markdown
### T-FULL-P1 — Paginate `assemble_full_scan` + apply Option A′
**Source:** X1-M1 (PR #9, 2026-04-17) — decided to apply Option A dedup only to `assemble_full_scan`; pagination + A′ deferred.
**File:** `src/screw_agents/engine.py` `assemble_full_scan`
**Priority:** **HIGH** — must address before `scan_full` is used on a large codebase at scale.

**Why deferred:** X1-M1 shipped prompt dedup for `assemble_full_scan` (`list[dict]` → `dict` with top-level `prompts`). However, the function remains non-paginated — the single response contains all code for all files for all agents. On large codebases this will exceed the subagent's token budget on the code payload alone, regardless of the prompt dedup.

**Trigger:** Any of:
- A round-trip test confirms `scan_full` hits the subagent budget on a realistic project
- Phase 4 autoresearch begins using `scan_full` in volume
- A user reports `scan_full` failures due to payload size

**Suggested fix:**
1. Introduce cursor-based pagination over the flattened `(agent, file_chunk)` space. Cursor carries `{target_hash, agent_offset, file_offset}`.
2. Apply Option A′: init page returns `prompts` for all agents + empty code; subsequent pages return code slices.
3. Update `screw-full-review.md` orchestrator for the pagination loop.
4. Add pagination tests equivalent to `scan_domain` coverage.

**Estimated scope:** ~400-500 LOC, separate PR.
```

- [ ] **Step 3: Commit**

```bash
git add docs/DEFERRED_BACKLOG.md
git commit -m "docs(backlog): X1-M1 shipped; log T-FULL-P1 as Phase 4+ follow-up

Moves X1-M1 from TOP PRIORITY to Shipped section with final
design summary. Adds T-FULL-P1 (HIGH priority) to Phase 4+
section: paginate assemble_full_scan and apply Option A'. This
follow-up addresses the single-response-size limitation that
X1-M1's Option A dedup does not solve."
```

---

## Task 9: Cross-plan sync — `docs/PHASE_3B_PLAN.md`

**Files:**
- Modify: `docs/PHASE_3B_PLAN.md`

- [ ] **Step 1: Locate the upstream-deps table rows**

Open `docs/PHASE_3B_PLAN.md`. Two rows in the "### Dependencies on Phase 3a PR #3 (Carryover Cleanup)" table need updating:

1. Line 69 — the `assemble_domain_scan` row describing the pagination response shape
2. Line 74 — the `X1-M1 — core-prompt deduplication` marker row

- [ ] **Step 2: Update the `assemble_domain_scan` row (line 69)**

Replace with:

```markdown
| `screw_agents.engine.ScanEngine.assemble_domain_scan(domain, target, thoroughness="standard", project_root=None, *, cursor=None, page_size=50) -> dict` | Two-stage pagination (X1-M1 shipped in PR #9). **Init page** (cursor=None): returns `{"domain", "prompts" (dict agent_name→core_prompt), "agents" (metadata + exclusions, no code), "next_cursor", "page_size", "total_files", "code_chunks_on_page": 0, "offset": 0, "trust_status"?}`. **Code pages** (cursor set): returns `{"domain", "agents" (agent_name + code + meta, no core_prompt, no exclusions), "next_cursor", "page_size", "total_files", "code_chunks_on_page": N, "offset", "trust_status"?}`. Cursor schema unchanged: base64url `{"target_hash", "offset"}`. Subagents must cache `prompts` from the init page and reference by `agent_name` on code pages. | Task 3b-19 (adaptive findings must cache prompts from init page and apply `prompts[agent_name]` on each code page's `agents` entries; pagination loop prepends an init-call step before walking code pages; still iterate `response["agents"]` on each page) |
```

- [ ] **Step 3: Update the X1-M1 marker row (line 74)**

Replace with:

```markdown
| **X1-M1 — core-prompt deduplication** | **SHIPPED in PR #9** (2026-04-17 merge commit `<fill at merge time>`). Domain-scan responses now split into init page (prompts once) + code pages (code only). Full-scan response now carries `prompts` at top level. See `docs/DEFERRED_BACKLOG.md` Shipped section and `T-FULL-P1` (Phase 4+ follow-up for paginating full_scan). | Task 3b-19 unblocked — implementer must honor init-page-first pagination loop and prompt-caching pattern per the updated row above. |
```

- [ ] **Step 4: Verify the two edits did not drift the surrounding table**

```bash
grep -n "X1-M1\|assemble_domain_scan\|SHIPPED" docs/PHASE_3B_PLAN.md
```

Confirm the two updates are visible and the table structure is intact (pipe count per row, header alignment).

- [ ] **Step 5: Commit**

```bash
git add docs/PHASE_3B_PLAN.md
git commit -m "sync(phase3b): X1-M1 shipped — update upstream-deps table

Updates the assemble_domain_scan row to reflect init-page +
code-pages response shapes and the cursor-caching protocol.
Marks the X1-M1 marker row as SHIPPED with pointer to DEFERRED_BACKLOG
and the T-FULL-P1 follow-up. Task 3b-19 is now unblocked."
```

---

## Task 10: Round-trip validation (manual, fish shell)

**Purpose:** Reproduce the Phase 3a PR#3 round-trip that originally surfaced X1-M1 and confirm the fix eliminates the fallback to direct file inspection.

**This task is round-trip — one step at a time, wait for user confirmation before proceeding** (per `feedback_roundtrip_stepbystep.md`).

- [ ] **Step 1: Prepare a fixture project**

User runs (fish shell):

```fish
cd /tmp; rm -rf screw-x1m1-roundtrip; mkdir screw-x1m1-roundtrip; cd screw-x1m1-roundtrip
# Copy or generate a project with ~10-20 Python files that include obvious SQL/command/template/XSS sinks
# (Same fixture the PR#3 round-trip used, if still available)
```

Wait for user to confirm fixture is ready.

- [ ] **Step 2: Install the plugin from the worktree**

User runs (fish shell):

```fish
claude --plugin-dir /home/marco/Programming/AI/screw-agents/.worktrees/phase-3a-prompt-dedup/plugins/screw
```

Wait for user to confirm Claude Code session is running with the plugin loaded.

- [ ] **Step 3: Invoke `/screw:injection` on the fixture**

User invokes the domain orchestrator subagent on the fixture project. Expected behavior:
- Subagent calls `scan_domain` with `cursor=None` → receives init page with `prompts` dict
- Subagent caches `prompts`
- Subagent calls `scan_domain` with the returned `next_cursor` → receives first code page
- Subagent applies `prompts[agent_name]` to each agent's `code` on the code page
- Subagent loops until `next_cursor` is null
- Subagent calls `write_scan_results` once with accumulated findings
- **Subagent does NOT fall back to direct file inspection** (the PR#3 failure mode)

Wait for user to report: did the subagent complete the pagination loop as designed, or did it fall back?

- [ ] **Step 4: Validate the written report**

User confirms the JSON + Markdown + CSV output files under `.screw/reports/` are present and well-formed, findings count is reasonable, trust_status section is rendered (if applicable).

- [ ] **Step 5: Record the round-trip result**

If successful: the PR can proceed to final commit + push. If a fallback still occurred, debug with user step by step (e.g., page_size still too large, subagent prompt wording ambiguous, init-page caching bug).

No commit for this task — the round-trip is a validation checkpoint, not a code artifact.

---

## Task 11: Final verification + PR open

**Files:** none (operational task)

- [ ] **Step 1: Run the full test suite**

```bash
uv run pytest -q | tail -5
```

Expected: all PASS, total count ≥ 430 + new tests (estimate ~445-455 passing).

- [ ] **Step 2: Verify no uncommitted changes**

```bash
git status
```

Expected: working tree clean.

- [ ] **Step 3: Push the branch and open PR**

```bash
git push -u origin phase-3a-prompt-dedup
gh pr create --title "Phase 3a X1-M1: core-prompt deduplication" --body "$(cat <<'EOF'
## Summary
- Ships X1-M1: core-prompt deduplication for `scan_domain` and `scan_full`, unblocking Phase 3b Task 3b-19
- `assemble_domain_scan` now splits into init page (prompts + metadata, no code) and code pages (code only, no prompts, no exclusions)
- `assemble_full_scan` returns `dict` with top-level `prompts` (breaking change from `list[dict]`)
- `assemble_scan` gains `include_prompt: bool = True` kwarg

## Design
- Spec: `docs/specs/2026-04-17-prompt-dedup-x1-m1-design.md` (local, not in git)
- Plan: `docs/PHASE_3A_X1_M1_PLAN.md`

## Cross-plan sync
- `docs/PHASE_3B_PLAN.md` upstream-deps table updated: X1-M1 marked SHIPPED; `assemble_domain_scan` row rewritten for init/code-page shape
- `docs/DEFERRED_BACKLOG.md` updated: X1-M1 moved to Shipped section; `T-FULL-P1` (paginate scan_full + apply A′) logged under Phase 4+ with HIGH priority

## Test plan
- [x] `tests/test_engine.py::test_assemble_scan_include_prompt_false_omits_core_prompt`
- [x] `tests/test_pagination.py::test_domain_scan_init_page_shape`
- [x] `tests/test_pagination.py::test_domain_scan_code_page_shape`
- [x] `tests/test_pagination.py::test_domain_scan_trust_status_on_every_page`
- [x] `tests/test_prompt_dedup_roundtrip.py` — full-walk integration coverage
- [x] `tests/test_engine.py::test_assemble_full_scan_returns_dict_with_top_level_prompts`
- [x] Manual round-trip test on fixture project (Task 10) — subagent completed pagination loop without fallback to direct file inspection

## Breaking changes
- `scan_full` MCP tool response: `list[dict]` → `dict` with `prompts` + `agents`. `screw-full-review.md` orchestrator updated.
- `scan_domain` MCP tool response: init page vs code page distinction now visible. `screw-injection.md` orchestrator updated.
EOF
)"
```

- [ ] **Step 4: Report PR URL back to user**

---

## Exit Criteria

1. All tests in Tasks 1-5 passing; total test count ≥ 445.
2. Round-trip test (Task 10) completes without fallback to direct file inspection.
3. `docs/PHASE_3B_PLAN.md` upstream-deps rows 69 and 74 updated (Task 9).
4. `docs/DEFERRED_BACKLOG.md`: X1-M1 moved to Shipped; `T-FULL-P1` added under Phase 4+ with HIGH priority (Task 8).
5. Both orchestrator subagent prompts updated (Tasks 6, 7).
6. PR #9 opened with summary + cross-plan sync notes (Task 11).
7. No AI attribution / Co-Authored-By in any commit message (per `feedback_no_cc_commits.md`).

---

## Cross-Plan Synchronization Summary (for auditor convenience)

The following downstream-plan entries are affected by this PR:

| Downstream plan | Entry | Action in this PR | Task |
|---|---|---|---|
| `docs/PHASE_3B_PLAN.md` line 69 | `assemble_domain_scan` upstream-deps row | Rewrite for init/code-page shape; note prompt-caching protocol | Task 9 Step 2 |
| `docs/PHASE_3B_PLAN.md` line 74 | `X1-M1 — core-prompt deduplication` marker row | Mark SHIPPED; point to DEFERRED_BACKLOG | Task 9 Step 3 |
| `docs/DEFERRED_BACKLOG.md` TOP PRIORITY section | `X1-M1 — Core-prompt deduplication` | Move to Shipped section | Task 8 Step 1 |
| `docs/DEFERRED_BACKLOG.md` Phase 4+ section | `T-FULL-P1` (new) | Add with HIGH priority | Task 8 Step 2 |

Phase 3b Task 3b-19 implementation body does NOT reference `agents[].core_prompt` directly (verified via grep), so no Phase 3b task code needs in-plan editing. The upstream-deps table update is sufficient for the 3b-19 implementer to know to prepend an init-page call before walking code pages.
