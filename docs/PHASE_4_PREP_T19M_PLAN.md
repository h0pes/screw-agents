# Phase 4 Prereq — T19-M1/M2/M3 Bundled (SARIF + CSV + per-source exclusion): Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` (recommended) or `superpowers:executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.
>
> **Per-task workflow (from `feedback_phase3a_workflow_discipline.md`, adapted per Phase 3b-C2 lessons):** novel-work cycle — pre-audit → implementer → combined spec+quality review → triage → fix-up → cross-plan sync. One dispatch per lens for non-mechanical tasks. Tests + greps are the binary verification gate.
>
> **Opus-for-all-subagents (from `feedback_opus_for_all_subagents.md`):** every Agent dispatch passes `model: "opus"`.
>
> **Plan-sync on deviation (from `feedback_plan_sync_on_deviation.md`):** whenever implementation differs from this plan, update this file in the SAME PR (or defer the item to DEFERRED_BACKLOG). Plan and code must be coherent at merge time.
>
> **No live round-trip required:** this PR does not change prompts, subagent behavior, or user-visible slash-command flow. Static tests + greps are sufficient.

**Goal:** Close the three T19-M* Phase-4 hard prereqs in one PR: migrate `merged_from_sources` from `list[str]` to `list[MergedSource]` (M3), surface the structured format in SARIF and CSV output (M1), and teach the exclusion matcher to iterate all merged sources (M2). Also flip the default output-format list to include CSV (D7).

**Architecture:** Pydantic schema change at `models.py` propagates to three consumer sites (merge function, Markdown renderer, JSON via model_dump). SARIF gains a `properties.mergedFromSources` extension per SARIF 2.1.0 §3.8. CSV gains one appended column. The exclusion-matching loop in `results.py::render_and_write` iterates primary + merged sources in deterministic order; `exclusions_applied` entries carry `matched_via_agent` for audit trail. No changes to MCP tool signatures, subagent prompts, or any plugin markdown.

**Tech Stack:** Python 3.11+, Pydantic v2, pytest. No new dependencies.

**Spec:** `docs/specs/2026-04-24-phase-4-prereq-t19-m-design.md` (local working material, gitignored per `project_docs_not_committed`).

**Upstream phase plan:** BACKLOG-PR6-22 merged 2026-04-24 (squash `d4dbb2b`). main HEAD `d4dbb2b`. 898 passed / 8 skipped baseline. Phase 4 blocker count 4 → 3 after BACKLOG-PR6-22; this PR drops it 3 → 2.

**Downstream phase plan:** After this PR, remaining Phase-4 blockers are **T-FULL-P1** (paginate `scan_full`, ~500-700 LOC, separate focused PR) + **D-01** (Rust benchmark corpus — Phase 4 step 4.0 itself). Phase 4 gates on both → 0.

**Branch:** `phase-4-prep-t19m` (dedicated worktree at `.worktrees/phase-4-prep-t19m`).

**Key references for implementers:**
- `docs/specs/2026-04-24-phase-4-prereq-t19-m-design.md` — design decisions D1-D7 + threat model + contracts
- `docs/DEFERRED_BACKLOG.md` §§T19-M1, T19-M2, T19-M3 — canonical scope entries (line ~267, 296, 354)
- `docs/PROJECT_STATUS.md` §"Phase 4 Prerequisites (hard gates)" — prereq state
- `src/screw_agents/models.py:385-407` — current `Finding` class + `merged_from_sources` field
- `src/screw_agents/results.py:55-105` — `_merge_findings_augmentatively`
- `src/screw_agents/results.py:140-220` — `render_and_write` exclusion-matching loop
- `src/screw_agents/formatter.py:101-141` — `format_csv` + `_CSV_COLUMNS`
- `src/screw_agents/formatter.py:160-260` — `_format_sarif` + `_sarif_result`
- `src/screw_agents/formatter.py:425-435` — Markdown `**Sources:**` line emission
- `src/screw_agents/learning.py:340-370` — `match_exclusions`
- `tests/test_results.py` — 16 assertion sites on `merged_from_sources` (lines 594, 608, 621, 654, 684, 729, 822, 827, 870, 927, 939, 942, 943, 964, 969 — plus docstring at 536)

---

## PR Scope Summary

| Category | Items | Net LOC |
|---|---|---|
| M3 schema migration | New `MergedSource` model; `Finding.merged_from_sources` type change; merge-fn emit update; Markdown renderer format-on-fly | +25 / -10 |
| M3 test sweep | 3 list-literal assertions in `test_results.py` updated to `MergedSource` objects (lines 654, 729, 822); 1 error-message at line 827; 4 docstring wordings at lines 536, 594, 621, 943; `is None` assertions unchanged | +20 / -8 |
| M1 SARIF | `_sarif_result` conditional `properties.mergedFromSources` emission + 1 new test | +12 |
| M1 CSV | `_CSV_COLUMNS` appended column + `format_csv` loop cell + 2 new tests | +20 |
| D7 CSV default flip | `formats = ["json", "markdown"]` → `["json", "markdown", "csv"]` + 1 new test | +8 / -1 |
| M2 per-source matching | `render_and_write` candidate-agent iteration + `exclusions_applied` schema extension + 4 new tests | +40 |
| Cross-plan updates | `DEFERRED_BACKLOG.md` (T19-M1/M2/M3 resolved), `PROJECT_STATUS.md` (blocker count 3 → 2) | +12 / -8 |
| **Total** | | **~+147 / -29 (net +118 LOC, ≈ ~170 gross per backlog estimate)** |

**Target test count:** 898 passed → **≈912 passed, 8 skipped** (7 new test functions; 4 test-site updates). Zero failures.

---

## File Structure Map

### Created (0 files)

### Modified (9 files)

| Path | What changes |
|---|---|
| `src/screw_agents/models.py` | Add `class MergedSource(BaseModel)` with `agent: str` + `severity: str`. Change `Finding.merged_from_sources: list[str] \| None` → `list[MergedSource] \| None`. Update the inline doc comment to describe the new shape. |
| `src/screw_agents/results.py` | `_merge_findings_augmentatively` (line 103): emit `MergedSource(...)` objects instead of formatted strings. `render_and_write` (lines 200-220): iterate `candidate_agents` (primary + sources), call `match_exclusions` per candidate, break on first match, record `matched_via_agent`. Extend `exclusions_applied.append(...)` shape with `matched_via_agent` key. Flip `formats = ["json", "markdown"]` → `["json", "markdown", "csv"]` at line 156. Update the module-level docstring comments (lines 55, 64, 163) to describe the new shape. |
| `src/screw_agents/formatter.py` | Markdown renderer (lines 430-431): format `", ".join(f"{s.agent} ({s.severity})" for s in f.merged_from_sources)` inline. `_CSV_COLUMNS`: append `"merged_sources"`. `format_csv` loop: emit `"; "`-joined formatted cell (empty string for unmerged), wrapped in `_sanitize_csv_cell`. `_sarif_result`: if `finding.merged_from_sources` is non-None, add `result["properties"] = {"mergedFromSources": [s.model_dump() for s in finding.merged_from_sources]}`. |
| `src/screw_agents/learning.py` | **NO CHANGES** — `match_exclusions` signature + behavior unchanged. Per-source broadening is orchestrated at `results.py`, NOT in the matching primitive. |
| `tests/test_results.py` | Update 3 list-literal assertions (lines 654, 729, 822) to expect `MergedSource` objects. Update 1 error message (line 827) whose format depends on the list shape. Update 4 docstring wordings (lines 536, 594, 621, 943) to describe the new shape. `is None` assertions (lines 608, 684, 969) are type-agnostic — NO CHANGE. Markdown `**Sources:**` assertions (lines 870, 927, 939, 964) query rendered strings — NO CHANGE. Add `from screw_agents.models import MergedSource` to the existing import at line 17. |
| `tests/test_formatter.py` (or equivalent) | Add 3 new tests: (a) SARIF merged finding carries `properties.mergedFromSources`; (b) CSV merged row has populated last column; (c) CSV unmerged row has empty last column. |
| `tests/test_results.py` | Add 4 new M2 regression tests for per-source exclusion matching + `matched_via_agent` carry. Add 1 new D7 test: `write_scan_results(formats=None)` writes CSV by default. Total 5 new tests in this file. |
| `docs/DEFERRED_BACKLOG.md` | Mark T19-M1/M2/M3 entries as **RESOLVED 2026-04-24** with branch/commit reference (per BACKLOG-PR6-22 precedent). Update blocker-count table (line ~136) from 3 → 2. Update `blocker` entries list to drop T19-M1/M2/M3. |
| `docs/PROJECT_STATUS.md` | Update "Phase 4 (Autoresearch) is gated on..." line (line ~31) to drop T19-M1/M2/M3. Update Phase 4 row in the Phase table (~line 420). Drop the T19-M1/M2/M3 block from §"Phase 4 Prerequisites (hard gates)" (lines ~441-444). Add a new bullet to the top-of-file "What's shipped" list documenting the bundle. |

### Deleted (0 files)

---

## Task Breakdown

### Task 1: M3 — `MergedSource` schema migration + consumer sweep

**Goal:** Replace `list[str]` with `list[MergedSource]` atomically across models, merge function, Markdown renderer, and all test assertions. Tests remain green at the end of this task.

**Files:**
- Modify: `src/screw_agents/models.py:385-407`
- Modify: `src/screw_agents/results.py:55,64,103,163`
- Modify: `src/screw_agents/formatter.py:430-431`
- Modify: `tests/test_results.py` (16 assertion sites + 2 docstrings)

**Pre-audit focus:** confirm the 16 test-site list is exhaustive via `grep -n "merged_from_sources" tests/`. Identify any auxiliary test helpers that build expected `list[str]` values. Verify no other src/ file constructs `merged_from_sources` values — grep for the construction pattern `f"{...} ({...})"` near merge contexts.

- [ ] **Step 1: Write failing test for `MergedSource` roundtrip**

Add to `tests/test_models.py` (the file already exists; 842 lines). Append the new test function at the end of the file, preserving the existing 2-blank-line separator between top-level functions:

```python
def test_merged_source_roundtrip_via_model_dump() -> None:
    """MergedSource(agent, severity) must model_dump to {agent, severity}."""
    from screw_agents.models import MergedSource

    ms = MergedSource(agent="sqli", severity="high")
    assert ms.model_dump() == {"agent": "sqli", "severity": "high"}
```

- [ ] **Step 2: Run test to verify it fails**

```
uv run pytest tests/test_models.py::test_merged_source_roundtrip_via_model_dump -v
```
Expected: `ImportError: cannot import name 'MergedSource' from 'screw_agents.models'`

- [ ] **Step 3: Add `MergedSource` model to `models.py`**

Insert immediately BEFORE `class Finding(BaseModel):` (currently at line 385):

```python
class MergedSource(BaseModel):
    """A source agent + severity pair in a merged finding's provenance list.

    Populated as entries in `Finding.merged_from_sources` when
    augmentative merge collapses multiple scan-source detections of the
    same `(file, line_start, cwe)` tuple into a single primary finding.

    The list contains ALL bucket entries in input order, INCLUDING the
    primary's own detection — consumers iterating the list see the
    complete provenance without needing to separately append the primary.
    The primary's `agent` + `classification.severity` top-level fields
    are therefore ALSO present as one `MergedSource` entry in the list;
    the two surfaces are complementary.

    Severity strings preserve input case verbatim (no lowercasing) —
    see `tests/test_results.py:822` for the capitalization round-trip
    assertion.
    """

    agent: str
    severity: str
```

- [ ] **Step 4: Change `Finding.merged_from_sources` field type**

Replace the existing line at `src/screw_agents/models.py:407`:

```python
    merged_from_sources: list[str] | None = None
```

with:

```python
    # Phase 3b T19 / T19-M3 (2026-04-24): populated when this finding is
    # the result of an augmentative merge across multiple scan sources.
    # None for unmerged findings. Contains ALL bucket entries in input
    # order (including the primary's own detection — the primary's
    # agent + severity also appear as one MergedSource in this list;
    # top-level `agent` + `classification.severity` carry the same
    # information). Markdown renders a "**Sources:**" line on the fly;
    # JSON/SARIF consumers see structured {agent, severity} dicts via
    # model_dump.
    merged_from_sources: list[MergedSource] | None = None
```

- [ ] **Step 5: Run the MergedSource test**

```
uv run pytest tests/test_models.py::test_merged_source_roundtrip_via_model_dump -v
```
Expected: PASS.

- [ ] **Step 6: Update `_merge_findings_augmentatively` to emit `MergedSource`**

The current emission at `src/screw_agents/results.py:98-100` is (verbatim):

```python
        sources = [
            f"{f.agent} ({f.classification.severity})" for f in group
        ]
```

Where `group` is the bucket list (NOT the post-primary subset — every entry in the bucket is in the source list, including the one promoted to primary). Replace with:

```python
        sources = [
            MergedSource(agent=f.agent, severity=f.classification.severity)
            for f in group
        ]
```

Extend the existing module-level import at `src/screw_agents/results.py:20` from `from screw_agents.models import Finding` to `from screw_agents.models import Finding, MergedSource` (module-level style consistent with the rest of the file; no inline imports).

- [ ] **Step 7: Update Markdown renderer to format on the fly**

In `src/screw_agents/formatter.py:430-431`, replace:

```python
    if f.merged_from_sources:
        sources_str = ", ".join(f.merged_from_sources)
```

with:

```python
    if f.merged_from_sources:
        sources_str = ", ".join(
            f"{s.agent} ({s.severity})" for s in f.merged_from_sources
        )
```

- [ ] **Step 8: Run the full merge test file to see what breaks**

```
uv run pytest tests/test_results.py -v 2>&1 | tail -60
```

Expected: several assertion failures where tests expect `["sqli (high)", "adaptive_script:qb-check (high)"]` but now see `[MergedSource(agent="sqli", severity="high"), ...]`.

- [ ] **Step 9: Sweep the `test_results.py` assertion + docstring sites**

Running `grep -n "merged_from_sources" tests/test_results.py` returns exactly 11 hits. Process each:

**Code changes required (3 sites, list-literal assertions):**

- **Line ~654** — change the expected list literal from `list[str]` to `list[MergedSource]`. Current code (paraphrased):
  ```python
  assert merged.merged_from_sources == [
      "sqli (medium)",
      "adaptive_script:qb-check (high)",
  ]
  ```
  becomes:
  ```python
  assert merged.merged_from_sources == [
      MergedSource(agent="sqli", severity="medium"),
      MergedSource(agent="adaptive_script:qb-check", severity="high"),
  ]
  ```
  (Preserve the exact agent names + severities from the current assertion — read the file and copy verbatim, then switch type.)
- **Line ~729** — same pattern; convert list[str] → list[MergedSource] preserving the existing agents + severities.
- **Line ~822** — same pattern. This test enforces severity CASE preservation (e.g., `"High"` with capital H survives unchanged). Your replacement MUST preserve that: `MergedSource(agent="...", severity="High")` — do NOT lowercase the severity string.

**Related site (1, error-message formatting):**

- **Line ~827** — the f-string error message interpolates `primary.merged_from_sources` into the failure text. Pydantic v2 BaseModel `__repr__` produces `MergedSource(agent='...', severity='...')` format; the error message will still be meaningful without edits. Read the f-string; if the expected vs actual comparison still prints usefully, leave unchanged. If the error text explicitly mentions the string format (e.g., "expected normalized list like `['agent (sev)']`"), rewrite to describe the structured shape.

**Docstring wording updates (4 sites, no code changes):**

- **Line ~536** — class-level or section docstring may describe the old string format. Update to mention `MergedSource` objects.
- **Line ~594** — test-function docstring. Update to describe the new shape.
- **Line ~621** — test-function docstring with example `"agent1 (sev1)"` → update example to `MergedSource(agent="agent1", severity="sev1")`.
- **Line ~943** — test-function docstring referring to `list[str]` or string-format output. Update to mention `list[MergedSource]` / structured objects. The surrounding test asserts on the rendered MARKDOWN (line 927) or JSON null (line 969), which are type-agnostic — only the prose docstring needs updating.

**Sites NOT requiring any changes (4 `is None` checks + 4 Markdown-renderer queries):**

- Line ~608: `assert result[0].merged_from_sources is None` — unchanged.
- Line ~684: `assert finding.merged_from_sources is None` — unchanged.
- Line ~969: `assert findings_json[0]["merged_from_sources"] is None` — unchanged (None serializes as null regardless of type).
- Lines ~870, ~927, ~939, ~964: `"**Sources:**" in md_content` / `not in md_content` / `"**Sources:** sqli (high), ..." in md_content` — these assert on RENDERED MARKDOWN strings, and the renderer's output is unchanged by M3 (Task 1 Step 7 updates the renderer to format on the fly, preserving the byte-identical `"sqli (high)"` substring).

**Required import update** at `tests/test_results.py:17` (current: `from screw_agents.models import Finding`):

```python
from screw_agents.models import Finding, MergedSource
```

- [ ] **Step 10: Update the `_merge_findings_augmentatively` docstring + `render_and_write` comment**

The current docstring at `src/screw_agents/results.py:55-59` (verbatim) is:

```
    2. Attaches a populated ``merged_from_sources`` list to the primary,
       formatted as ``["<agent> (<severity>)", ...]`` for all sources in
       the bucket (including the primary itself). Order follows the
       ORIGINAL input order of the bucket, not sorted order — downstream
       consumers see the natural insertion ordering.
```

Replace with:

```
    2. Attaches a populated ``merged_from_sources`` list to the primary,
       typed as ``list[MergedSource]`` where each entry carries an
       ``agent`` + ``severity`` pair. The list includes ALL entries in
       the bucket — the primary's own detection is also represented as
       one ``MergedSource`` entry, so the list is the complete
       provenance of this merged finding. Order follows the ORIGINAL
       input order of the bucket, not sorted order — downstream
       consumers see the natural insertion ordering.
```

Line 64 (`merged_from_sources = None`) — NO CHANGE (shape-agnostic).

Line 163 (inline comment in `render_and_write`: "finding with `merged_from_sources` populated. Exclusion matching runs...") — NO CHANGE (shape-agnostic).

- [ ] **Step 11: Run full test suite**

```
uv run pytest -q 2>&1 | tail -5
```

Expected: 899 passed, 8 skipped (baseline +1 for the new MergedSource roundtrip test). Zero failures.

- [ ] **Step 12: Commit**

```bash
git add src/screw_agents/models.py src/screw_agents/results.py src/screw_agents/formatter.py tests/test_results.py tests/test_models.py
git commit -m "T19-M3: migrate merged_from_sources to list[MergedSource]

Replace the list[str] (\"agent (severity)\") format with a Pydantic
MergedSource BaseModel carrying agent + severity as structured fields.
Propagates through _merge_findings_augmentatively (emit structured
objects) and the Markdown renderer (format on the fly so the rendered
Sources line is unchanged).

test_results.py: 3 list-literal assertions updated to use
MergedSource objects (lines 654, 729, 822), plus docstring wording
refreshes at 4 other sites. is-None assertions and Markdown-render
assertions unchanged (type-agnostic). Rendered Markdown + JSON
bytes unchanged.

Prepares M1 (SARIF/CSV surface) and M2 (per-source exclusion matching)
to iterate structured sources without string parsing."
```

---

### Task 2: M1 — SARIF `properties.mergedFromSources` emission

**Goal:** Merged findings emit a `properties.mergedFromSources` key in their SARIF result object. Unmerged findings emit no `properties` key (or an empty one if already populated for another reason — the existing code does not populate it).

**Files:**
- Modify: `src/screw_agents/formatter.py` `_sarif_result` (around line 219-260)
- Test: `tests/test_formatter.py` (new test, or append to existing SARIF test file)

**Pre-audit focus:** confirm `_sarif_result` does NOT currently populate `properties` anywhere (grep `result\["properties"\]` inside `formatter.py`). Identify whether the SARIF test file already exists; the file name may be `test_formatter.py`, `test_sarif.py`, or assertions may live in `test_results.py`.

- [ ] **Step 1: Locate or create the SARIF test file**

Run:
```bash
grep -rln "_format_sarif\|\"sarif\"" tests/
```

If a SARIF test file exists (e.g., `tests/test_formatter.py`), append new tests there. If none exists, create `tests/test_sarif.py` with appropriate imports.

- [ ] **Step 2: Write failing test for merged-finding SARIF properties bag**

```python
def test_sarif_merged_finding_emits_properties_merged_from_sources(tmp_path: Path) -> None:
    """A merged Finding's SARIF result must carry properties.mergedFromSources
    with a list of {agent, severity} dicts. Unmerged findings emit no such key.
    """
    from screw_agents.formatter import _format_sarif
    from screw_agents.models import (
        Finding, FindingLocation, FindingClassification,
        FindingAnalysis, FindingRemediation, MergedSource,
    )
    import json

    merged_finding = Finding(
        id="f1",
        agent="sqli",
        domain="injection-input-handling",
        timestamp="2026-04-24T00:00:00Z",
        location=FindingLocation(file="dao.py", line_start=13),
        classification=FindingClassification(
            cwe="CWE-89", cwe_name="SQL Injection",
            severity="high", confidence="medium",
        ),
        analysis=FindingAnalysis(description="test"),
        remediation=FindingRemediation(recommendation="test"),
        merged_from_sources=[
            MergedSource(agent="adaptive_script:qb-check", severity="high"),
        ],
    )
    unmerged_finding = merged_finding.model_copy(
        update={"id": "f2", "merged_from_sources": None}
    )

    sarif_str = _format_sarif(
        [merged_finding, unmerged_finding], metadata={}, agent_registry=None
    )
    doc = json.loads(sarif_str)
    results = doc["runs"][0]["results"]

    # Merged finding: properties bag present with mergedFromSources
    assert "properties" in results[0], (
        "Merged finding's SARIF result missing properties bag"
    )
    assert results[0]["properties"]["mergedFromSources"] == [
        {"agent": "adaptive_script:qb-check", "severity": "high"},
    ]

    # Unmerged finding: no properties bag (or no mergedFromSources key)
    assert (
        "properties" not in results[1]
        or "mergedFromSources" not in results[1].get("properties", {})
    )
```

- [ ] **Step 3: Run test to verify it fails**

```
uv run pytest tests/test_formatter.py::test_sarif_merged_finding_emits_properties_merged_from_sources -v
```
Expected: FAIL with `KeyError: 'properties'` or `AssertionError`.

- [ ] **Step 4: Implement the properties bag emission**

In `src/screw_agents/formatter.py::_sarif_result`, AFTER the existing `result: dict[str, Any] = { ... }` block and BEFORE the `if loc.data_flow is not None:` block (currently around line 237-239), insert:

```python
    # T19-M1: surface merged_from_sources via the SARIF properties bag
    # (SARIF 2.1.0 §3.8 tool-specific extensions). Consumers that read the
    # bag see multi-source attribution; consumers that don't still see the
    # primary's `agent` via ruleId + tool driver metadata.
    if finding.merged_from_sources:
        result["properties"] = {
            "mergedFromSources": [
                s.model_dump() for s in finding.merged_from_sources
            ],
        }
```

- [ ] **Step 5: Run test to verify it passes**

```
uv run pytest tests/test_formatter.py::test_sarif_merged_finding_emits_properties_merged_from_sources -v
```
Expected: PASS.

- [ ] **Step 6: Run full test suite**

```
uv run pytest -q 2>&1 | tail -5
```

Expected: 900 passed, 8 skipped. Zero failures.

- [ ] **Step 7: Commit**

```bash
git add src/screw_agents/formatter.py tests/test_formatter.py
git commit -m "T19-M1 (SARIF): emit merged_from_sources via properties bag

SARIF 2.1.0 §3.8 allows tool-specific extensions via the result
object's properties bag. When a finding's merged_from_sources is
non-None, add result.properties.mergedFromSources as a list of
{agent, severity} dicts (from MergedSource.model_dump()).

Consumers that read the properties bag (screw-agents-aware tooling,
Phase 4 autoresearch) surface the data; consumers that don't
(GitHub Code Scanning, SonarQube default) see no change — they
fall back to the primary agent via ruleId + tool driver."
```

---

### Task 3: M1 — CSV `merged_sources` column + D7 default-format flip

**Goal:** Append a `merged_sources` column to the CSV output (empty for unmerged, `"; "`-joined for merged) AND flip `write_scan_results`'s default formats list to include `"csv"`.

**Files:**
- Modify: `src/screw_agents/formatter.py` `_CSV_COLUMNS` (around line 82) + `format_csv` loop (line 126-139)
- Modify: `src/screw_agents/results.py:156` (default formats)
- Modify: `tests/test_csv_format.py` — there is a **mirror constant** `_EXPECTED_COLUMNS` at line 18-22 that MUST be kept in sync with `_CSV_COLUMNS`. The header-assertion at line 30 (`rows[0] == _EXPECTED_COLUMNS`) will fail otherwise. The existing zip-based tests at lines 39, 60, 72 silently drop the new column if the mirror isn't updated — update it.
- New tests: add to `tests/test_csv_format.py` (dedicated CSV test file; has the appropriate imports + `_make_finding` re-export pattern from `test_formatter.py`).
- D7 test: add to `tests/test_results.py` (near existing `render_and_write` tests).

**Pre-audit verified:** `tests/test_csv_format.py` exists with 109 lines. `_EXPECTED_COLUMNS` at line 18-22 is the test-side mirror. Four sites depend on it: line 30 (positional header assertion — WILL BREAK if not updated), lines 39/60/72 (`dict(zip(_EXPECTED_COLUMNS, rows[1]))` — zip truncates silently; update to exercise the new column). `_sanitize_csv_cell` is at formatter.py line 93-98 and IS the right wrapper for the new cell.

- [ ] **Step 1: Write failing test for CSV merged row (merged finding)**

Append to **`tests/test_csv_format.py`** (the dedicated CSV test file). Use the file-idiomatic `_make_finding` helper (re-imported from `tests.test_formatter` at line 15) and the file's existing import style. Place the new test AFTER the last existing test:

```python
def test_format_csv_merged_finding_populates_merged_sources_column():
    """A merged Finding's CSV row must carry a `"; "`-joined merged_sources
    cell in the last column; unmerged findings emit an empty last cell
    (T19-M1 D4).
    """
    from screw_agents.models import MergedSource

    merged = _make_finding(
        id="f1",
        merged_from_sources=[
            MergedSource(agent="adaptive_script:qb-check", severity="high"),
            MergedSource(agent="xss", severity="medium"),
        ],
    )
    unmerged = _make_finding(id="f2", merged_from_sources=None)

    out = format_csv([merged, unmerged])
    rows = list(csv.reader(io.StringIO(out)))

    # Header must include merged_sources as the LAST column.
    assert rows[0][-1] == "merged_sources"
    # Merged row: last cell is "; "-joined "<agent> (<severity>)".
    assert rows[1][-1] == "adaptive_script:qb-check (high); xss (medium)"
    # Unmerged row: last cell is empty.
    assert rows[2][-1] == ""
```

- [ ] **Step 2: Run test to verify it fails**

```
uv run pytest tests/test_csv_format.py::test_format_csv_merged_finding_populates_merged_sources_column -v
```
Expected: FAIL (column not yet present; header will still be 12 cols + `rows[0][-1] == "exclusion_ref"` instead of `"merged_sources"`).

- [ ] **Step 3: Append column to `_CSV_COLUMNS`**

In `src/screw_agents/formatter.py` around line 82-91, extend `_CSV_COLUMNS` (the existing list constant). Find the closing bracket of the list and add `"merged_sources"` as the last entry:

```python
_CSV_COLUMNS = [
    "id",
    "file",
    "line",
    "cwe",
    "cwe_name",
    "agent",
    "severity",
    "confidence",
    "description",
    "code_snippet",
    "excluded",
    "exclusion_ref",
    "merged_sources",  # T19-M1 (2026-04-24): structured-list joined by "; "
]
```

(Preserve the exact existing entries — they are canonical; only the new one is added.)

- [ ] **Step 4: Update `format_csv` row emission to emit the new cell**

In `src/screw_agents/formatter.py::format_csv` at the `writer.writerow([...])` call (lines ~126-139), append the new cell as the LAST element:

```python
        merged_sources_cell = ""
        if f.merged_from_sources:
            merged_sources_cell = "; ".join(
                f"{s.agent} ({s.severity})" for s in f.merged_from_sources
            )

        writer.writerow([
            f.id,
            f.location.file,
            str(f.location.line_start),
            f.classification.cwe,
            f.classification.cwe_name,
            f.agent,
            f.classification.severity,
            f.classification.confidence,
            _sanitize_csv_cell(f.analysis.description),
            _sanitize_csv_cell(f.location.code_snippet or ""),
            excluded,
            _sanitize_csv_cell(exclusion_ref),
            _sanitize_csv_cell(merged_sources_cell),  # T19-M1
        ])
```

- [ ] **Step 5: Run test to verify new test passes; confirm mirror-drift**

```
uv run pytest tests/test_csv_format.py -v 2>&1 | tail -30
```

Expected: `test_format_csv_merged_finding_populates_merged_sources_column` PASSES. `test_format_csv_empty_findings` (at line 25) FAILS because `rows[0]` is now 13 columns but `_EXPECTED_COLUMNS` is still 12 — the positional assertion `rows[0] == _EXPECTED_COLUMNS` fails. This is the expected mirror-drift signal.

- [ ] **Step 5b: Update `_EXPECTED_COLUMNS` mirror in `tests/test_csv_format.py`**

At line 18-22 of `tests/test_csv_format.py`, extend the constant to include the new column:

```python
_EXPECTED_COLUMNS = [
    "id", "file", "line", "cwe", "cwe_name", "agent",
    "severity", "confidence", "description", "code_snippet",
    "excluded", "exclusion_ref", "merged_sources",
]
```

- [ ] **Step 5c: Re-run to verify both pass**

```
uv run pytest tests/test_csv_format.py -v 2>&1 | tail -20
```

Expected: all tests in `tests/test_csv_format.py` PASS (original 4-5 tests + the new merged-column test). The zip-based dict-builders at lines 39/60/72 now correctly include `merged_sources` key (defaulting to empty string for unmerged fixtures).

- [ ] **Step 6: Write failing test for D7 — CSV in default formats**

Append to `tests/test_results.py` (near existing `render_and_write` tests):

```python
def test_render_and_write_default_formats_includes_csv(tmp_path: Path) -> None:
    """write_scan_results with formats=None must write a .csv file alongside
    .json + .md (D7: T19-M1 default-format flip).
    """
    from screw_agents.results import render_and_write

    project = tmp_path / "project"
    project.mkdir()

    finding = {
        "id": "f1",
        "agent": "sqli",
        "domain": "injection-input-handling",
        "timestamp": "2026-04-24T00:00:00Z",
        "location": {"file": "dao.py", "line_start": 13},
        "classification": {
            "cwe": "CWE-89", "cwe_name": "SQL Injection",
            "severity": "high", "confidence": "medium",
        },
        "analysis": {"description": "test"},
        "remediation": {"recommendation": "test"},
    }

    result = render_and_write(
        project_root=project,
        findings_raw=[finding],
        scan_metadata={"target": "dao.py", "timestamp": "2026-04-24T00:00:00Z"},
        formats=None,  # exercise the default
    )

    assert "csv" in result["files_written"], (
        f"default formats list must include csv; got "
        f"{list(result['files_written'].keys())}"
    )
    assert "json" in result["files_written"]
    assert "markdown" in result["files_written"]
```

- [ ] **Step 7: Run test to verify it fails**

```
uv run pytest tests/test_results.py::test_render_and_write_default_formats_includes_csv -v
```
Expected: FAIL (`"csv" not in result["files_written"]`).

- [ ] **Step 8: Flip the default formats list**

In `src/screw_agents/results.py:156`:

```python
    if formats is None:
        formats = ["json", "markdown", "csv"]  # T19-M1 D7 (2026-04-24)
```

- [ ] **Step 9: Run test to verify it passes**

```
uv run pytest tests/test_results.py::test_render_and_write_default_formats_includes_csv -v
```
Expected: PASS.

- [ ] **Step 10: Run full test suite**

```
uv run pytest -q 2>&1 | tail -5
```

Expected: 902 passed, 8 skipped (baseline +3 from T19-M1 SARIF + M1 CSV merged + D7). Zero failures.

- [ ] **Step 11: Commit**

```bash
git add src/screw_agents/formatter.py src/screw_agents/results.py tests/test_csv_format.py tests/test_results.py
git commit -m "T19-M1 (CSV) + D7: add merged_sources column; include CSV in defaults

T19-M1: _CSV_COLUMNS appends merged_sources column (last position; positional
parsers reading by index up to the old column count are unaffected).
format_csv emits \"; \"-joined \"<agent> (<severity>)\" for merged findings,
empty string for unmerged. _sanitize_csv_cell guards against spreadsheet
formula injection.

D7: write_scan_results default formats flips from [\"json\", \"markdown\"] to
[\"json\", \"markdown\", \"csv\"] per Marco's long-standing CSV-by-default
preference (project_csv_output memory). Explicit format lists are
unchanged."
```

---

### Task 4: M2 — per-source exclusion matching + `matched_via_agent`

**Goal:** `render_and_write`'s per-finding match loop iterates primary + merged source agents in deterministic order; first match wins; `exclusions_applied` entries carry `matched_via_agent` identifying which source triggered the suppression.

**Files:**
- Modify: `src/screw_agents/results.py:207-224` (the `for finding in findings:` match loop — plan-fix updated from earlier `:200-220` range after T3 line shifts)
- Modify: `src/screw_agents/results.py:151` (update the docstring that describes `exclusions_applied` shape to mention `matched_via_agent`)
- Test: `tests/test_results.py` — add 4 new regression tests as methods of `TestRenderAndWriteExclusions` (line 180) to leverage the class-scoped `_setup_exclusion` helper pattern

**Pre-audit verified (orchestrator, 2026-04-24):**

1. `match_exclusions` (`learning.py:340-370`) takes single `agent` kwarg; broadening happens at caller site. No change to that primitive.
2. Existing consumers of `exclusions_applied` (3 sites): `tests/test_accumulate_finalize.py:248` (isinstance check — unaffected), `tests/test_results.py:236` (`len() == 2` — unaffected), `tests/test_results.py:371` (`== []` — unaffected). NO positional dict-equality assertions. Extending the dict shape with a new key is safe.
3. **`ExclusionInput` / `record_exclusion` path is NOT the project-idiomatic test pattern.** `ExclusionInput` (models.py:254-268) has NO `id` field (that's on child `Exclusion`) and takes `reason: str` (not dict). The existing `TestRenderAndWriteExclusions._setup_exclusion` helper at `tests/test_results.py:183-222` writes `.screw/learning/exclusions.yaml` DIRECTLY with `config.yaml: legacy_unsigned_exclusions: warn` (bypasses signing pipeline). Use THIS pattern for new M2 tests — do NOT use `record_exclusion` or `run_init_trust`.
4. `_make_finding_dict` helper at `tests/test_results.py:543-582` builds raw dicts for `findings_raw`. Two findings sharing `(file, line_start, cwe)` trigger `_merge_findings_augmentatively` INSIDE `render_and_write` — use this for merged-input scenarios (don't hand-craft merged Finding objects).
5. New helper `_setup_exclusions_multi(tmp_path, entries)` needed for the 2-exclusion test (Step 3): write N exclusions to the same YAML. Keep `_setup_exclusion` untouched for the existing tests.

- [ ] **Step 1: Add the multi-exclusion test helper to `TestRenderAndWriteExclusions`**

The existing class has `_setup_exclusion(tmp_path, scope_type, **scope_kwargs)` which writes a single exclusion dict. Tests 2-4 need multiple exclusions in one YAML file. Add a sibling helper (as a static method or nested in the class):

```python
    def _setup_exclusions_multi(self, tmp_path, entries):
        """Write multiple exclusions to `.screw/learning/exclusions.yaml`.

        entries: list of dicts, each with keys:
          - id (str, unique)
          - agent (str)
          - file (str)
          - line (int)
          - cwe (str)
          - scope_type (str)  # "exact_line" | "file" | "directory" | ...
          - scope_kwargs (dict)  # e.g. {"path": "dao.py"}

        Mirrors `_setup_exclusion`'s config-file + unsigned-warn setup
        so the trust pipeline does NOT quarantine the entries.
        """
        screw_dir = tmp_path / ".screw"
        screw_dir.mkdir(exist_ok=True)
        (screw_dir / "config.yaml").write_text(
            "version: 1\n"
            "exclusion_reviewers: []\n"
            "script_reviewers: []\n"
            "legacy_unsigned_exclusions: warn\n"
        )
        learning_dir = screw_dir / "learning"
        learning_dir.mkdir(exist_ok=True)
        exclusions_list = []
        for e in entries:
            exclusions_list.append({
                "id": e["id"],
                "created": "2026-04-24T10:00:00Z",
                "agent": e["agent"],
                "finding": {
                    "file": e["file"],
                    "line": e["line"],
                    "code_pattern": "(any)",
                    "cwe": e["cwe"],
                },
                "reason": "T19-M2 test fixture",
                "scope": {"type": e["scope_type"], **e["scope_kwargs"]},
                "times_suppressed": 0,
                "last_suppressed": None,
            })
        (learning_dir / "exclusions.yaml").write_text(
            yaml.dump({"exclusions": exclusions_list})
        )
```

- [ ] **Step 2: Add 4 failing M2 regression tests as methods of `TestRenderAndWriteExclusions`**

Place these AFTER the existing tests in the class (after `test_quarantined_exclusion_does_not_suppress_findings` at line ~319). All use `_make_finding_dict` (already defined at module scope, line 543-582) to build `findings_raw` and either `_setup_exclusion` or `_setup_exclusions_multi`:

```python
    # ------------------------------------------------------------------
    # T19-M2: per-source exclusion matching for merged findings
    # ------------------------------------------------------------------

    def test_matched_via_agent_carries_primary_agent_for_unmerged(
        self, tmp_path
    ):
        """T19-M2: an unmerged finding suppressed by its own agent's exclusion
        carries matched_via_agent = finding.agent in exclusions_applied.
        """
        self._setup_exclusion(tmp_path, "exact_line", path="dao.py")
        finding = _make_finding_dict(
            finding_id="f1", agent="sqli", file="dao.py",
            line_start=42, cwe="CWE-89", severity="high",
            description="unmerged SQLi finding",
        )
        result = render_and_write(
            project_root=tmp_path, findings_raw=[finding],
            agent_names=["sqli"],
        )
        assert result["summary"]["suppressed"] == 1
        assert result["exclusions_applied"] == [{
            "finding_id": "f1",
            "exclusion_ref": "fp-2026-04-11-001",
            "matched_via_agent": "sqli",
        }]

    def test_merged_finding_primary_exclusion_match_wins(self, tmp_path):
        """T19-M2: when both the primary AND a merged source have matching
        exclusions, the PRIMARY's match wins (deterministic primary-first).
        """
        self._setup_exclusions_multi(tmp_path, [
            {"id": "exc-sqli", "agent": "sqli",
             "file": "dao.py", "line": 42, "cwe": "CWE-89",
             "scope_type": "exact_line", "scope_kwargs": {"path": "dao.py"}},
            {"id": "exc-adaptive", "agent": "adaptive_script:qb-check",
             "file": "dao.py", "line": 42, "cwe": "CWE-89",
             "scope_type": "exact_line", "scope_kwargs": {"path": "dao.py"}},
        ])
        # Two findings at same (file, line_start, cwe) => merge inside
        # render_and_write. sqli (high) vs adaptive (medium) => sqli
        # wins primary on severity.
        yaml_finding = _make_finding_dict(
            finding_id="f-yaml", agent="sqli", file="dao.py",
            line_start=42, cwe="CWE-89", severity="high",
            description="YAML SQLi",
        )
        adaptive_finding = _make_finding_dict(
            finding_id="f-adapt", agent="adaptive_script:qb-check",
            file="dao.py", line_start=42, cwe="CWE-89", severity="medium",
            description="adaptive SQLi",
        )
        result = render_and_write(
            project_root=tmp_path,
            findings_raw=[yaml_finding, adaptive_finding],
            agent_names=["sqli"],
        )
        assert result["summary"]["suppressed"] == 1
        # Primary-first: sqli's exc-sqli must win, NOT exc-adaptive.
        assert len(result["exclusions_applied"]) == 1
        applied = result["exclusions_applied"][0]
        assert applied["exclusion_ref"] == "exc-sqli"
        assert applied["matched_via_agent"] == "sqli"

    def test_merged_finding_source_exclusion_suppresses(self, tmp_path):
        """T19-M2: a merged finding whose PRIMARY agent has no matching
        exclusion but whose MERGED SOURCE does, is still suppressed with
        matched_via_agent = the source agent.
        """
        # Only exclusion is on adaptive_script:qb-check; primary sqli has
        # no matching exclusion.
        self._setup_exclusions_multi(tmp_path, [
            {"id": "exc-adaptive", "agent": "adaptive_script:qb-check",
             "file": "dao.py", "line": 42, "cwe": "CWE-89",
             "scope_type": "exact_line", "scope_kwargs": {"path": "dao.py"}},
        ])
        yaml_finding = _make_finding_dict(
            finding_id="f-yaml", agent="sqli", file="dao.py",
            line_start=42, cwe="CWE-89", severity="high",
            description="YAML SQLi",
        )
        adaptive_finding = _make_finding_dict(
            finding_id="f-adapt", agent="adaptive_script:qb-check",
            file="dao.py", line_start=42, cwe="CWE-89", severity="medium",
            description="adaptive SQLi",
        )
        result = render_and_write(
            project_root=tmp_path,
            findings_raw=[yaml_finding, adaptive_finding],
            agent_names=["sqli"],
        )
        # Merged finding (primary=sqli after severity comparison) is
        # suppressed via the adaptive-source exclusion.
        assert result["summary"]["suppressed"] == 1
        assert len(result["exclusions_applied"]) == 1
        applied = result["exclusions_applied"][0]
        assert applied["exclusion_ref"] == "exc-adaptive"
        assert applied["matched_via_agent"] == "adaptive_script:qb-check"

    def test_merged_finding_no_source_match_remains_active(self, tmp_path):
        """T19-M2: if NEITHER primary NOR any merged source has a matching
        exclusion, the merged finding is NOT suppressed.
        """
        # Exclusion is on an unrelated agent — neither primary (sqli) nor
        # source (adaptive_script:qb-check) matches.
        self._setup_exclusions_multi(tmp_path, [
            {"id": "exc-unrelated", "agent": "xss",
             "file": "dao.py", "line": 42, "cwe": "CWE-89",
             "scope_type": "exact_line", "scope_kwargs": {"path": "dao.py"}},
        ])
        yaml_finding = _make_finding_dict(
            finding_id="f-yaml", agent="sqli", file="dao.py",
            line_start=42, cwe="CWE-89", severity="high",
            description="YAML SQLi",
        )
        adaptive_finding = _make_finding_dict(
            finding_id="f-adapt", agent="adaptive_script:qb-check",
            file="dao.py", line_start=42, cwe="CWE-89", severity="medium",
            description="adaptive SQLi",
        )
        result = render_and_write(
            project_root=tmp_path,
            findings_raw=[yaml_finding, adaptive_finding],
            agent_names=["sqli"],
        )
        assert result["summary"]["suppressed"] == 0
        assert result["summary"]["active"] == 1  # merged to 1 finding
        assert result["exclusions_applied"] == []
```

Note: the agent name `adaptive_script:qb-check` includes a colon. Nothing in `match_exclusions` or the scope-matching logic treats this specially (it's a plain string compare). Preserves realism since the colon-suffix `adaptive_script:<meta.name>` is the real adaptive-script agent label.

- [ ] **Step 3: Run the 4 tests to verify they fail**

```
uv run pytest tests/test_results.py -k "matched_via_agent or primary_exclusion_match_wins or source_exclusion_suppresses or no_source_match" -v
```

Expected: ALL FAIL. Failure shapes:

- `test_matched_via_agent_carries_primary_agent_for_unmerged`: fails because `exclusions_applied[0]` is `{"finding_id": ..., "exclusion_ref": ...}` (no `matched_via_agent` key yet).
- `test_merged_finding_primary_exclusion_match_wins`: may fail on either count or on the missing `matched_via_agent`; `exc-adaptive` might win if current code matches on primary (sqli) — sqli's exc matches, so suppressed count is 1, but dict shape is missing the key.
- `test_merged_finding_source_exclusion_suppresses`: FAILS on suppression count (current code only checks primary=sqli which has no matching exclusion; suppressed count is 0, should be 1).
- `test_merged_finding_no_source_match_remains_active`: may PASS already (unrelated exclusion doesn't match sqli or adaptive) — confirm via run. Included for completeness and regression safety.

- [ ] **Step 4: Rewrite the match loop in `render_and_write`**

In `src/screw_agents/results.py:207-224`, replace:

```python
    for finding in findings:
        matches = match_exclusions(
            exclusions,
            file=finding.location.file,
            line=finding.location.line_start,
            code=finding.location.code_snippet or "",
            agent=finding.agent,
            function=finding.location.function,
        )
        if matches:
            finding.triage.excluded = True
            finding.triage.exclusion_ref = matches[0].id
            finding.triage.status = "suppressed"
            suppressed_count += 1
            exclusions_applied.append({
                "finding_id": finding.id,
                "exclusion_ref": matches[0].id,
            })
```

with:

```python
    for finding in findings:
        # T19-M2 (2026-04-24): per-source exclusion matching. Iterate
        # primary agent first, then merged_from_sources in emitted
        # order. First match wins (deterministic, audit-friendly).
        # See DEFERRED_BACKLOG.md §T19-M2 for the pre-existing limitation
        # this addresses (primary-only matching silently missed merged
        # findings where user's exclusion targeted a non-primary source).
        candidate_agents: list[str] = [finding.agent]
        if finding.merged_from_sources:
            candidate_agents.extend(
                s.agent for s in finding.merged_from_sources
            )

        matched_agent: str | None = None
        matched_ref: str | None = None
        for candidate in candidate_agents:
            matches = match_exclusions(
                exclusions,
                file=finding.location.file,
                line=finding.location.line_start,
                code=finding.location.code_snippet or "",
                agent=candidate,
                function=finding.location.function,
            )
            if matches:
                matched_agent = candidate
                matched_ref = matches[0].id
                break

        if matched_ref is not None:
            finding.triage.excluded = True
            finding.triage.exclusion_ref = matched_ref
            finding.triage.status = "suppressed"
            suppressed_count += 1
            exclusions_applied.append({
                "finding_id": finding.id,
                "exclusion_ref": matched_ref,
                "matched_via_agent": matched_agent,
            })
```

- [ ] **Step 5: Run the 4 tests to verify they pass**

```
uv run pytest tests/test_results.py -k "matched_via_agent or primary_exclusion_match_wins or source_exclusion_suppresses or no_source_match" -v
```
Expected: ALL PASS.

- [ ] **Step 5b: Update the `exclusions_applied` docstring in `render_and_write`**

At `src/screw_agents/results.py:151`, the docstring currently reads:

```
            - exclusions_applied: list[dict] -- finding_id + exclusion_ref pairs
```

Replace with:

```
            - exclusions_applied: list[dict] -- each entry has finding_id,
              exclusion_ref, and matched_via_agent (the source agent whose
              exclusion triggered the suppression; for unmerged findings
              or primary-agent matches this equals finding.agent)
```

- [ ] **Step 6: Run full test suite**

```
uv run pytest -q 2>&1 | tail -5
```

Expected: 906 passed, 8 skipped (baseline +4 for M2 tests). Zero failures.

**Drift check:** if any EXISTING `exclusions_applied` test fails because it expected the old 2-key shape, update those tests to include `matched_via_agent`. Per the orchestrator pre-audit (2026-04-24), none of the 3 known consumer sites should break (isinstance + length + empty-list comparisons only). If the full-suite run surfaces an unexpected failure in this category, handle it in place with a dated comment analogous to T3's D7 drift fixes.

- [ ] **Step 7: Commit**

```bash
git add src/screw_agents/results.py tests/test_results.py
git commit -m "T19-M2: per-source exclusion matching for merged findings

render_and_write now iterates candidate agents in deterministic order
(primary first, then merged_from_sources in emit order) and suppresses
the finding on first match. exclusions_applied entries gain a
matched_via_agent key identifying which source's exclusion triggered
the suppression — critical for Phase 4 autoresearch's FP-learning
correlation.

Security posture: semantic broadening is intended (user excluded this
pattern regardless of augmentation source); NO false-positive
introduction (exclusions are user-authored). Primary-first
deterministic order is audit-friendly.

4 regression tests cover: unmerged (matched_via_agent = primary),
merged-primary-wins, merged-source-match, merged-no-match-active."
```

---

### Task 5: Cross-plan sync + final verification

**Goal:** `docs/DEFERRED_BACKLOG.md` reflects T19-M1/M2/M3 shipped; `docs/PROJECT_STATUS.md` reflects new blocker state (3 → 2); full test pass + grep-cleanness audit.

**Files:**
- Modify: `docs/DEFERRED_BACKLOG.md`
- Modify: `docs/PROJECT_STATUS.md`

No source changes in this task.

- [ ] **Step 1: Update `DEFERRED_BACKLOG.md` — mark T19-M1/M2/M3 resolved**

For each of the three entries at lines ~267 (T19-M1), ~296 (T19-M2), ~354 (T19-M3), prepend a "**RESOLVED 2026-04-24**" status block in the same style used for BACKLOG-PR6-22:

```markdown
### T19-M1 — Surface `merged_from_sources` in SARIF and CSV output — **RESOLVED 2026-04-24**
**Shipped on branch:** `phase-4-prep-t19m` (merge commit TBD on merge).
**What shipped:** SARIF `_sarif_result` emits `properties.mergedFromSources` (a list of `{agent, severity}` dicts) for merged findings; unmerged findings emit no properties bag. CSV `_CSV_COLUMNS` appended `merged_sources` as the last column (positional parsers unaffected); merged rows emit `"; "`-joined `"<agent> (<severity>)"` strings, unmerged rows emit empty string. D7 flipped `write_scan_results` default formats list from `["json", "markdown"]` to `["json", "markdown", "csv"]`.

**Historical entry (original deferral, for audit trail):**
[... existing entry content preserved ...]
```

Repeat for T19-M2 (what shipped: per-source match loop; `matched_via_agent` carried in exclusions_applied; 4 regression tests) and T19-M3 (what shipped: `MergedSource` model, schema migration, renderer updates).

- [ ] **Step 2: Update DEFERRED_BACKLOG blocker table + gate line**

At line ~136 (tag summary table):

```markdown
| `blocker` | 1 | T-FULL-P1 (scan_full scale) |
```

(Was: `| blocker | 4 | T-FULL-P1 ... T19-M1 / T19-M2 / T19-M3 ... |`)

At line ~141 (Phase 4 gate paragraph):

```markdown
**Phase 4 gate:** the `blocker` count must drop to 0 before Phase 4's step 4.0 (D-01 Rust benchmark corpus) can start. Current blocker: T-FULL-P1 (paginate `scan_full` + agent-relevance filter — Phase 4 autoresearch uses it in volume at 41-agent expansion). See `docs/PROJECT_STATUS.md` §"Phase 4 Prerequisites (hard gates)" for scheduling + estimated scope.
```

At line ~765 (the BACKLOG-PR6-22 post-scripsum):

```markdown
**Phase-4 impact:** hard prereq count drops 5 → 4. Remaining Phase-4 blockers: D-01 (Rust benchmark corpus), T-FULL-P1 (paginate scan_full), T19-M1/M2/M3 (SARIF/CSV surface polish), BACKLOG-PR6-22 (`sign_adaptive_script` retirement). *(Post-scripsum: BACKLOG-PR6-22 resolved on branch `retire-sign-adaptive-script`, 2026-04-24 — prereq count 3; T19-M1/M2/M3 resolved on branch `phase-4-prep-t19m`, 2026-04-24 — prereq count now 2.)*
```

- [ ] **Step 3: Update `PROJECT_STATUS.md`**

(a) Line ~31 gating statement:

```markdown
Gates G1-G4 pass. **Phase 4 (Autoresearch) is gated on D-01 + T-FULL-P1 — see §"Phase 4 Prerequisites (hard gates)" below.**
```

(b) Add a new bullet to the "What's shipped" list near lines ~28-29 (between Phase 3b-C2 and the BACKLOG-PR6-22 entry, OR chronologically after BACKLOG-PR6-22 — pick by merge date):

```markdown
- **T19-M1/M2/M3 (branch `phase-4-prep-t19m`)** merged 2026-04-24 — Phase-4 prereq bundle. M3 migrates `Finding.merged_from_sources` from `list[str]` to `list[MergedSource]` (structured agent + severity). M1 surfaces the structured format in SARIF (`properties.mergedFromSources` per SARIF 2.1.0 §3.8) and CSV (appended `merged_sources` column, `"; "`-joined). M2 teaches the exclusion matcher to iterate primary + merged sources in deterministic order; `exclusions_applied` entries gain `matched_via_agent` for audit trail. D7 flips default format list to include CSV. Test suite: 898 → ~912 passed, 8 skipped. Phase 4 blocker count drops 3 → 2.
```

(c) Line ~420 — Phase 4 row in the Phase table:

```markdown
| Phase 4 | Autoresearch & Self-Improvement — step 4.0 is D-01 (hard gate) | **Pending**, hard-gated on D-01 + T-FULL-P1 (see "Phase 4 Prerequisites" below) |
```

(d) §"Phase 4 Prerequisites (hard gates)" (lines ~427-455) — delete the T19-M1/M2/M3 block:

The section currently contains: D-01, T-FULL-P1, T19-M1/M2/M3, D-02, and the "When returning to Phase 4" paragraph. Remove the `### T19-M1 / T19-M2 / T19-M3` block entirely. Update the "When returning to Phase 4" paragraph to drop T19-M1/M2/M3 from the status-refresh list.

- [ ] **Step 4: Grep verification**

```bash
grep -rn 'list\[str\]' src/screw_agents/models.py
```
Expected: NO match mentioning `merged_from_sources` context.

```bash
grep -rn 'mergedFromSources' src/
```
Expected: exactly ONE hit (in `formatter.py` SARIF emitter).

```bash
grep -rn 'matched_via_agent' src/
```
Expected: exactly ONE hit (in `results.py` match loop).

```bash
grep -rn 'list\[MergedSource\]' src/
```
Expected: exactly ONE hit (in `models.py` `Finding` field declaration).

- [ ] **Step 5: Full-suite verification**

```
uv run pytest -q 2>&1 | tail -5
```
Expected: ~912 passed / 8 skipped / 0 failures.

- [ ] **Step 6: Commit**

```bash
git add docs/DEFERRED_BACKLOG.md docs/PROJECT_STATUS.md
git commit -m "docs: mark T19-M1/M2/M3 resolved; Phase 4 blocker count 3 -> 2

DEFERRED_BACKLOG.md:
- T19-M1, T19-M2, T19-M3 entries gain RESOLVED 2026-04-24 header
  blocks with shipped-scope descriptions
- blocker-count table: 4 -> 1 (only T-FULL-P1 remains)
- BACKLOG-PR6-22 post-scripsum updated to note T19-M* also resolved

PROJECT_STATUS.md:
- Phase 4 gate line drops T19-M1/M2/M3
- new 'What's shipped' bullet documents the T19-M bundle
- Phase table Phase 4 row updated (D-01 + T-FULL-P1 only)
- Phase 4 Prerequisites section: T19-M1/M2/M3 block deleted

Plan and code are coherent at merge time (feedback_plan_sync_on_deviation)."
```

---

## Self-Review Checklist

After all 5 tasks complete, run the following checks:

1. **Spec coverage** — every D1-D7 from the spec is implemented in some task:
   - D1 (bundled PR, M3→M1→M2 ordering): task sequencing ✓
   - D2 (MergedSource shape): Task 1 Step 3 ✓
   - D3 (SARIF properties bag): Task 2 Step 4 ✓
   - D4 (CSV append at end + "; "): Task 3 Steps 3-4 ✓
   - D5 (matched_via_agent): Task 4 Step 6 ✓
   - D6 (primary-first, first-match-wins): Task 4 Step 6 ✓
   - D7 (CSV default flip): Task 3 Step 8 ✓

2. **Placeholder scan** — no "TBD", "implement later", "similar to Task N" in this plan. All code blocks contain actual code.

3. **Type consistency** — `MergedSource` field names (`agent`, `severity`) consistent across Task 1 Step 3, Task 2 Step 2, Task 3 Step 1, Task 4 test bodies. `matched_via_agent` key name consistent across Task 4 Step 6 + tests.

4. **Threat-model coverage** — T-SEC-1 (widened suppression) covered by Task 4 Step 4 test (no_source_match stays active) + Step 3 (source_exclusion suppresses). T-SEC-2 (attribution leak) is informational — no test needed. T-SEC-3 (SARIF properties leak) covered by Task 2 Step 2 test asserting structured shape.

---

## PR Lifecycle

On completion of Task 5:

1. Push branch: `git push -u origin phase-4-prep-t19m`
2. Open PR: `gh pr create --title "T19-M1/M2/M3 bundle — SARIF/CSV/per-source exclusion + D7 CSV default" --body <prepared body>`
3. Merge (squash): `gh pr merge <N> --squash --delete-branch`
4. Cleanup worktree + local + remote branch (per BACKLOG-PR6-22 playbook: `git pull`, `git worktree remove`, `git branch -D`, `gh api -X DELETE refs/heads/<branch>`, `git fetch --prune`).
5. Update memory with shipment record.

---

## Handoff

**Plan ready for review + implementation dispatch.** Execution mode: subagent-driven per `project_execution_mode.md` — fresh Opus subagent per task, review between tasks (one combined spec+quality review for non-mechanical tasks; tests-are-the-gate for mechanical fix-ups).
