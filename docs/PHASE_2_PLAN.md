# Phase 2: Claude Code Integration — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the Phase 1 MCP server usable as a real security review tool inside Claude Code — subagent markdown files, auto-invocation skill, slash command, filesystem output (`.screw/`), and persistent false-positive learning.

**Architecture:** MCP server assembles knowledge + resolves code (Phase 1, unchanged). Claude Code subagents ARE the analyzer — they call MCP scan tools, receive detection knowledge + code, analyze directly, then format and write output via MCP + Write tool. New `learning.py` module handles exclusion storage and pre-scan filtering. See `docs/specs/2026-04-11-phase-2-claude-code-integration-design.md` for the full design spec.

**Tech Stack:** Python 3.11+ (Pydantic, PyYAML), Markdown (Claude Code agents/skills/commands), `uv` for package management, `pytest` for testing.

**Spec:** `docs/specs/2026-04-11-phase-2-claude-code-integration-design.md`

**Key references for implementers:**
- `src/screw_agents/models.py` — existing Pydantic models (Finding, FindingTriage, etc.)
- `src/screw_agents/engine.py` — ScanEngine with assemble_scan, format_output
- `src/screw_agents/server.py` — MCP server with _dispatch_tool, list_tool_definitions
- `src/screw_agents/formatter.py` — format_findings (json/sarif/markdown)
- `tests/conftest.py` — shared fixtures (domains_dir, fixtures_dir)
- `plugins/screw/skills/screw-research/SKILL.md` — reference for skill format

---

## File Map

### New files

| File | Responsibility |
|---|---|
| `src/screw_agents/learning.py` | Exclusion YAML I/O, scope matching logic |
| `tests/test_learning.py` | Unit tests for learning module |
| `tests/test_phase2_server.py` | Tests for new MCP tools + project_root in scan tools |
| `plugins/screw/agents/screw-sqli.md` | SQLi subagent (workflow orchestrator) |
| `plugins/screw/agents/screw-cmdi.md` | CmdI subagent |
| `plugins/screw/agents/screw-ssti.md` | SSTI subagent |
| `plugins/screw/agents/screw-xss.md` | XSS subagent |
| `plugins/screw/agents/screw-injection.md` | Injection domain orchestrator |
| `plugins/screw/agents/screw-full-review.md` | Full-review orchestrator (dispatches domain orchestrators) |
| `plugins/screw/skills/screw-review/SKILL.md` | Auto-invocation skill (replaces .gitkeep) |
| `plugins/screw/commands/scan.md` | `/screw:scan` slash command (replaces .gitkeep) |
| `plugins/screw/CLAUDE.md.template` | Template for user projects |
| `docs/PHASE_2_E2E_TEST.md` | End-to-end smoke test checklist |

### Modified files

| File | Change |
|---|---|
| `src/screw_agents/models.py:188-209` | Add `excluded`, `exclusion_ref` to `FindingTriage`; add `Exclusion*` models |
| `src/screw_agents/engine.py:37-131` | Add optional `project_root` param to `assemble_scan`, `assemble_domain_scan`, `assemble_full_scan`; add `project_root` to tool schemas |
| `src/screw_agents/server.py:73-122` | Wire 3 new tools in `_dispatch_tool`; pass `project_root` through scan tools |

---

## Dependency Graph

```
Task 1 (models) ──────────────────────────────────────────────┐
    │                                                          │
    ▼                                                          │
Task 2 (learning.py) ──► Task 3 (engine project_root)         │
                              │                                │
                              ▼                                │
                         Task 4 (server: new tools + project_root)
                              │                                │
                              ▼                                │
                     Task 5 (subagent template) ◄──────────────┘
                              │
            ┌─────────────────┼─────────────────┐
            ▼                 ▼                  ▼
    Task 6 (4 agents)  Task 7 (orchestrators)  Task 8 (skill)
                                                 │
                                                 ▼
                                          Task 9 (slash cmd)
                                                 │
                                                 ▼
                                        Task 10 (CLAUDE.md template)
                                                 │
                                                 ▼
                                         Task 11 (E2E doc + cleanup)
```

---

## Task 1: Exclusion Pydantic Models + FindingTriage Update

**Files:**
- Modify: `src/screw_agents/models.py:188-209`
- Test: `tests/test_models.py` (extend existing)

- [ ] **Step 1: Write failing tests for new models**

Add to `tests/test_models.py`:

```python
from screw_agents.models import (
    Exclusion,
    ExclusionFinding,
    ExclusionInput,
    ExclusionScope,
    FindingTriage,
)


class TestExclusionModels:
    def test_exclusion_scope_pattern(self):
        scope = ExclusionScope(type="pattern", pattern="db.text_search(*)")
        assert scope.type == "pattern"
        assert scope.pattern == "db.text_search(*)"

    def test_exclusion_scope_exact_line(self):
        scope = ExclusionScope(type="exact_line", path="src/api.py")
        assert scope.type == "exact_line"

    def test_exclusion_scope_directory(self):
        scope = ExclusionScope(type="directory", path="test/")
        assert scope.type == "directory"

    def test_exclusion_scope_function(self):
        scope = ExclusionScope(type="function", path="src/api.py", name="get_user")
        assert scope.type == "function"
        assert scope.name == "get_user"

    def test_exclusion_scope_file(self):
        scope = ExclusionScope(type="file", path="src/generated.py")
        assert scope.type == "file"

    def test_exclusion_finding(self):
        ef = ExclusionFinding(
            file="src/api.py", line=42, code_pattern="db.text_search(*)", cwe="CWE-89"
        )
        assert ef.file == "src/api.py"
        assert ef.line == 42

    def test_exclusion_input(self):
        ei = ExclusionInput(
            agent="sqli",
            finding=ExclusionFinding(
                file="src/api.py", line=42, code_pattern="db.query(*)", cwe="CWE-89"
            ),
            reason="uses parameterized queries",
            scope=ExclusionScope(type="pattern", pattern="db.query(*)"),
        )
        assert ei.agent == "sqli"
        assert ei.reason == "uses parameterized queries"

    def test_exclusion_full(self):
        exc = Exclusion(
            id="fp-2026-04-11-001",
            created="2026-04-11T14:35:00Z",
            agent="sqli",
            finding=ExclusionFinding(
                file="src/api.py", line=42, code_pattern="db.query(*)", cwe="CWE-89"
            ),
            reason="parameterized",
            scope=ExclusionScope(type="pattern", pattern="db.query(*)"),
            times_suppressed=0,
            last_suppressed=None,
        )
        assert exc.id == "fp-2026-04-11-001"
        assert exc.times_suppressed == 0

    def test_exclusion_defaults(self):
        exc = Exclusion(
            id="fp-2026-04-11-001",
            created="2026-04-11T14:35:00Z",
            agent="sqli",
            finding=ExclusionFinding(
                file="src/api.py", line=42, code_pattern="db.query(*)", cwe="CWE-89"
            ),
            reason="safe",
            scope=ExclusionScope(type="file", path="src/api.py"),
        )
        assert exc.times_suppressed == 0
        assert exc.last_suppressed is None


class TestFindingTriageExclusionFields:
    def test_triage_default_not_excluded(self):
        t = FindingTriage()
        assert t.excluded is False
        assert t.exclusion_ref is None

    def test_triage_excluded(self):
        t = FindingTriage(excluded=True, exclusion_ref="fp-2026-04-11-001")
        assert t.excluded is True
        assert t.exclusion_ref == "fp-2026-04-11-001"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_models.py::TestExclusionModels -v && uv run pytest tests/test_models.py::TestFindingTriageExclusionFields -v`
Expected: ImportError or AttributeError — models don't exist yet.

- [ ] **Step 3: Add exclusion models to models.py**

Add after the `FindingTriage` class (after line 209) in `src/screw_agents/models.py`:

```python
# ---------------------------------------------------------------------------
# Exclusion Models (Phase 2 — persistent FP learning, spec §8)
# ---------------------------------------------------------------------------


class ExclusionScope(BaseModel):
    """Scope rule for an exclusion — determines how broadly it applies."""

    type: str  # "exact_line" | "pattern" | "function" | "file" | "directory"
    pattern: str | None = None  # for "pattern" scope
    path: str | None = None  # for "exact_line", "file", "directory", "function"
    name: str | None = None  # for "function" scope


class ExclusionFinding(BaseModel):
    """The original finding that was marked as a false positive."""

    file: str
    line: int
    code_pattern: str
    cwe: str


class ExclusionInput(BaseModel):
    """Input for recording a new exclusion (subagent sends this)."""

    agent: str
    finding: ExclusionFinding
    reason: str
    scope: ExclusionScope


class Exclusion(ExclusionInput):
    """A stored exclusion with generated metadata."""

    id: str
    created: str  # ISO8601
    times_suppressed: int = 0
    last_suppressed: str | None = None
```

- [ ] **Step 4: Add excluded/exclusion_ref to FindingTriage**

In `src/screw_agents/models.py`, modify the `FindingTriage` class (lines 190-195):

```python
class FindingTriage(BaseModel):
    status: str = "pending"
    triaged_by: str | None = None
    triaged_at: str | None = None
    notes: str | None = None
    excluded: bool = False
    exclusion_ref: str | None = None
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `uv run pytest tests/test_models.py -v`
Expected: All pass, including existing tests (backwards compat — new fields have defaults).

- [ ] **Step 6: Run full test suite to check nothing broke**

Run: `uv run pytest tests/ -v`
Expected: All existing tests pass. The new `excluded`/`exclusion_ref` fields have defaults so existing Finding construction is unaffected.

- [ ] **Step 7: Commit**

```bash
git add src/screw_agents/models.py tests/test_models.py
git commit -m "feat(models): add exclusion models and FindingTriage exclusion fields

Phase 2 step 1: Pydantic models for FP exclusion storage.
ExclusionScope (5 scope types), ExclusionFinding, ExclusionInput,
Exclusion. FindingTriage gains excluded + exclusion_ref fields
with backwards-compatible defaults."
```

---

## Task 2: Learning Module — Exclusion Storage + Matching

**Files:**
- Create: `src/screw_agents/learning.py`
- Create: `tests/test_learning.py`

- [ ] **Step 1: Write failing tests for load_exclusions**

Create `tests/test_learning.py`:

```python
"""Tests for the learning module — exclusion storage and matching."""

import pytest
import yaml
from pathlib import Path

from screw_agents.learning import load_exclusions, record_exclusion, match_exclusions
from screw_agents.models import Exclusion, ExclusionInput, ExclusionFinding, ExclusionScope


@pytest.fixture
def project_root(tmp_path):
    """A temporary project root with .screw/learning/ directory."""
    return tmp_path


@pytest.fixture
def exclusion_input_pattern():
    """A sample ExclusionInput with pattern scope."""
    return ExclusionInput(
        agent="sqli",
        finding=ExclusionFinding(
            file="src/api.py", line=42, code_pattern="db.text_search(*)", cwe="CWE-89"
        ),
        reason="db.text_search() uses parameterized queries internally",
        scope=ExclusionScope(type="pattern", pattern="db.text_search(*)"),
    )


@pytest.fixture
def exclusion_input_file():
    """A sample ExclusionInput with file scope."""
    return ExclusionInput(
        agent="xss",
        finding=ExclusionFinding(
            file="src/generated.py", line=10, code_pattern="render(*)", cwe="CWE-79"
        ),
        reason="generated code, not user-facing",
        scope=ExclusionScope(type="file", path="src/generated.py"),
    )


class TestLoadExclusions:
    def test_load_nonexistent_returns_empty(self, project_root):
        result = load_exclusions(project_root)
        assert result == []

    def test_load_empty_file(self, project_root):
        learning_dir = project_root / ".screw" / "learning"
        learning_dir.mkdir(parents=True)
        (learning_dir / "exclusions.yaml").write_text("exclusions: []\n")
        result = load_exclusions(project_root)
        assert result == []

    def test_load_valid_exclusions(self, project_root):
        learning_dir = project_root / ".screw" / "learning"
        learning_dir.mkdir(parents=True)
        data = {
            "exclusions": [
                {
                    "id": "fp-2026-04-11-001",
                    "created": "2026-04-11T14:35:00Z",
                    "agent": "sqli",
                    "finding": {
                        "file": "src/api.py",
                        "line": 42,
                        "code_pattern": "db.query(*)",
                        "cwe": "CWE-89",
                    },
                    "reason": "safe",
                    "scope": {"type": "pattern", "pattern": "db.query(*)"},
                    "times_suppressed": 0,
                    "last_suppressed": None,
                }
            ]
        }
        (learning_dir / "exclusions.yaml").write_text(yaml.dump(data))
        result = load_exclusions(project_root)
        assert len(result) == 1
        assert result[0].id == "fp-2026-04-11-001"
        assert result[0].agent == "sqli"

    def test_load_malformed_yaml_raises(self, project_root):
        learning_dir = project_root / ".screw" / "learning"
        learning_dir.mkdir(parents=True)
        (learning_dir / "exclusions.yaml").write_text(": : invalid yaml [[[")
        with pytest.raises(ValueError, match="[Mm]alformed"):
            load_exclusions(project_root)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_learning.py::TestLoadExclusions -v`
Expected: ImportError — `learning` module doesn't exist.

- [ ] **Step 3: Implement load_exclusions**

Create `src/screw_agents/learning.py`:

```python
"""Persistent false-positive learning — exclusion storage and matching.

Phase 2 implements layers 1-2 of PRD §11.2:
  Layer 1: Exclusion storage in .screw/learning/exclusions.yaml
  Layer 2: Pre-scan filtering via scope-based matching

Layers 3 (aggregation) and 4 (feedback loop) are Phase 3 scope.
"""

from __future__ import annotations

import fnmatch
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from screw_agents.models import Exclusion, ExclusionInput

_EXCLUSIONS_PATH = Path(".screw") / "learning" / "exclusions.yaml"


def load_exclusions(project_root: Path) -> list[Exclusion]:
    """Read exclusions from .screw/learning/exclusions.yaml.

    Args:
        project_root: Project root directory.

    Returns:
        List of Exclusion objects. Empty list if file doesn't exist.

    Raises:
        ValueError: If the YAML is malformed or unparseable.
    """
    path = project_root / _EXCLUSIONS_PATH
    if not path.exists():
        return []

    try:
        raw = yaml.safe_load(path.read_text())
    except yaml.YAMLError as exc:
        raise ValueError(f"Malformed exclusions YAML at {path}: {exc}") from exc

    if raw is None or not isinstance(raw, dict):
        return []

    entries = raw.get("exclusions", [])
    if not entries:
        return []

    return [Exclusion(**entry) for entry in entries]
```

- [ ] **Step 4: Run load tests to verify they pass**

Run: `uv run pytest tests/test_learning.py::TestLoadExclusions -v`
Expected: All 4 tests pass.

- [ ] **Step 5: Write failing tests for record_exclusion**

Add to `tests/test_learning.py`:

```python
class TestRecordExclusion:
    def test_record_creates_file_and_dirs(self, project_root, exclusion_input_pattern):
        result = record_exclusion(project_root, exclusion_input_pattern)
        assert result.id.startswith("fp-")
        assert result.agent == "sqli"
        assert result.times_suppressed == 0
        # File was created
        path = project_root / ".screw" / "learning" / "exclusions.yaml"
        assert path.exists()
        loaded = load_exclusions(project_root)
        assert len(loaded) == 1
        assert loaded[0].id == result.id

    def test_record_appends_to_existing(self, project_root, exclusion_input_pattern, exclusion_input_file):
        first = record_exclusion(project_root, exclusion_input_pattern)
        second = record_exclusion(project_root, exclusion_input_file)
        assert first.id != second.id
        loaded = load_exclusions(project_root)
        assert len(loaded) == 2

    def test_record_sequential_ids_same_day(self, project_root, exclusion_input_pattern, exclusion_input_file):
        first = record_exclusion(project_root, exclusion_input_pattern)
        second = record_exclusion(project_root, exclusion_input_file)
        # Both recorded same day — sequential NNN suffix
        first_seq = int(first.id.split("-")[-1])
        second_seq = int(second.id.split("-")[-1])
        assert second_seq == first_seq + 1

    def test_record_sets_created_timestamp(self, project_root, exclusion_input_pattern):
        result = record_exclusion(project_root, exclusion_input_pattern)
        # Should be a valid ISO8601 timestamp
        assert "T" in result.created
        assert result.created.endswith("Z")
```

- [ ] **Step 6: Run tests to verify they fail**

Run: `uv run pytest tests/test_learning.py::TestRecordExclusion -v`
Expected: NameError or AttributeError — `record_exclusion` not implemented.

- [ ] **Step 7: Implement record_exclusion**

Add to `src/screw_agents/learning.py`:

```python
def record_exclusion(project_root: Path, exclusion: ExclusionInput) -> Exclusion:
    """Record a new exclusion in .screw/learning/exclusions.yaml.

    Creates the directory and file if they don't exist. Assigns a unique
    ID with format fp-YYYY-MM-DD-NNN (sequential per day).

    Args:
        project_root: Project root directory.
        exclusion: The exclusion input from the subagent.

    Returns:
        The saved Exclusion with generated id and created timestamp.
    """
    path = project_root / _EXCLUSIONS_PATH
    path.parent.mkdir(parents=True, exist_ok=True)

    existing = load_exclusions(project_root) if path.exists() else []

    now = datetime.now(timezone.utc)
    date_str = now.strftime("%Y-%m-%d")
    today_prefix = f"fp-{date_str}-"
    today_ids = [e.id for e in existing if e.id.startswith(today_prefix)]
    next_seq = len(today_ids) + 1
    exclusion_id = f"{today_prefix}{next_seq:03d}"

    saved = Exclusion(
        id=exclusion_id,
        created=now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        agent=exclusion.agent,
        finding=exclusion.finding,
        reason=exclusion.reason,
        scope=exclusion.scope,
        times_suppressed=0,
        last_suppressed=None,
    )

    existing.append(saved)
    data = {"exclusions": [e.model_dump() for e in existing]}
    path.write_text(yaml.dump(data, default_flow_style=False, sort_keys=False))

    return saved
```

- [ ] **Step 8: Run record tests to verify they pass**

Run: `uv run pytest tests/test_learning.py::TestRecordExclusion -v`
Expected: All 4 tests pass.

- [ ] **Step 9: Write failing tests for match_exclusions**

Add to `tests/test_learning.py`:

```python
class TestMatchExclusions:
    def _make_exclusion(self, scope_type, agent="sqli", **scope_kwargs):
        return Exclusion(
            id="fp-2026-04-11-001",
            created="2026-04-11T14:35:00Z",
            agent=agent,
            finding=ExclusionFinding(
                file="src/api.py", line=42, code_pattern="db.query(*)", cwe="CWE-89"
            ),
            reason="test",
            scope=ExclusionScope(type=scope_type, **scope_kwargs),
        )

    def test_exact_line_match(self):
        exc = self._make_exclusion("exact_line", path="src/api.py")
        # The finding line in the exclusion is 42
        matches = match_exclusions([exc], file="src/api.py", line=42, code="db.query(x)", agent="sqli")
        assert len(matches) == 1

    def test_exact_line_no_match_different_line(self):
        exc = self._make_exclusion("exact_line", path="src/api.py")
        matches = match_exclusions([exc], file="src/api.py", line=99, code="db.query(x)", agent="sqli")
        assert len(matches) == 0

    def test_exact_line_no_match_different_file(self):
        exc = self._make_exclusion("exact_line", path="src/api.py")
        matches = match_exclusions([exc], file="src/other.py", line=42, code="db.query(x)", agent="sqli")
        assert len(matches) == 0

    def test_pattern_match(self):
        exc = self._make_exclusion("pattern", pattern="db.text_search(*)")
        matches = match_exclusions([exc], file="src/any.py", line=10, code="result = db.text_search(user_input)", agent="sqli")
        assert len(matches) == 1

    def test_pattern_no_match(self):
        exc = self._make_exclusion("pattern", pattern="db.text_search(*)")
        matches = match_exclusions([exc], file="src/any.py", line=10, code="cursor.execute(query)", agent="sqli")
        assert len(matches) == 0

    def test_file_match(self):
        exc = self._make_exclusion("file", path="src/generated.py")
        matches = match_exclusions([exc], file="src/generated.py", line=1, code="anything", agent="sqli")
        assert len(matches) == 1

    def test_file_no_match(self):
        exc = self._make_exclusion("file", path="src/generated.py")
        matches = match_exclusions([exc], file="src/other.py", line=1, code="anything", agent="sqli")
        assert len(matches) == 0

    def test_directory_match(self):
        exc = self._make_exclusion("directory", path="test/")
        matches = match_exclusions([exc], file="test/test_api.py", line=1, code="anything", agent="sqli")
        assert len(matches) == 1

    def test_directory_nested_match(self):
        exc = self._make_exclusion("directory", path="test/")
        matches = match_exclusions([exc], file="test/unit/test_deep.py", line=1, code="anything", agent="sqli")
        assert len(matches) == 1

    def test_directory_no_match(self):
        exc = self._make_exclusion("directory", path="test/")
        matches = match_exclusions([exc], file="src/api.py", line=1, code="anything", agent="sqli")
        assert len(matches) == 0

    def test_function_match(self):
        exc = self._make_exclusion("function", path="src/api.py", name="get_user")
        matches = match_exclusions(
            [exc], file="src/api.py", line=42, code="anything", agent="sqli", function="get_user"
        )
        assert len(matches) == 1

    def test_function_no_match_different_function(self):
        exc = self._make_exclusion("function", path="src/api.py", name="get_user")
        matches = match_exclusions(
            [exc], file="src/api.py", line=42, code="anything", agent="sqli", function="delete_user"
        )
        assert len(matches) == 0

    def test_wrong_agent_no_match(self):
        exc = self._make_exclusion("file", path="src/api.py", agent="sqli")
        matches = match_exclusions([exc], file="src/api.py", line=1, code="anything", agent="xss")
        assert len(matches) == 0

    def test_multiple_exclusions_partial_match(self):
        exc1 = self._make_exclusion("file", path="src/api.py")
        exc2 = self._make_exclusion("file", path="src/other.py")
        matches = match_exclusions([exc1, exc2], file="src/api.py", line=1, code="anything", agent="sqli")
        assert len(matches) == 1
```

- [ ] **Step 10: Run tests to verify they fail**

Run: `uv run pytest tests/test_learning.py::TestMatchExclusions -v`
Expected: ImportError or NameError — `match_exclusions` not implemented.

- [ ] **Step 11: Implement match_exclusions**

Add to `src/screw_agents/learning.py`:

```python
def match_exclusions(
    exclusions: list[Exclusion],
    *,
    file: str,
    line: int,
    code: str,
    agent: str,
    function: str | None = None,
) -> list[Exclusion]:
    """Return exclusions that match a finding's context.

    Args:
        exclusions: All loaded exclusions.
        file: File path of the finding.
        line: Line number of the finding.
        code: Code content at the finding location.
        agent: Agent name that produced the finding.
        function: Optional function name containing the finding.

    Returns:
        List of matching Exclusion objects.
    """
    matches: list[Exclusion] = []
    for exc in exclusions:
        if exc.agent != agent:
            continue
        if _scope_matches(exc, file=file, line=line, code=code, function=function):
            matches.append(exc)
    return matches


def _scope_matches(
    exc: Exclusion,
    *,
    file: str,
    line: int,
    code: str,
    function: str | None,
) -> bool:
    """Check if an exclusion's scope matches the given finding context."""
    scope = exc.scope
    scope_type = scope.type

    if scope_type == "exact_line":
        return scope.path == file and exc.finding.line == line

    if scope_type == "pattern":
        if scope.pattern is None:
            return False
        return fnmatch.fnmatch(code, f"*{scope.pattern}*")

    if scope_type == "file":
        return scope.path == file

    if scope_type == "directory":
        if scope.path is None:
            return False
        dir_path = scope.path.rstrip("/") + "/"
        return file.startswith(dir_path)

    if scope_type == "function":
        return scope.path == file and scope.name == function

    return False
```

- [ ] **Step 12: Run all learning tests to verify they pass**

Run: `uv run pytest tests/test_learning.py -v`
Expected: All tests pass.

- [ ] **Step 13: Run full test suite**

Run: `uv run pytest tests/ -v`
Expected: All tests pass (no regressions).

- [ ] **Step 14: Commit**

```bash
git add src/screw_agents/learning.py tests/test_learning.py
git commit -m "feat(learning): exclusion storage, loading, and scope matching

Phase 2 step 2: learning.py with load_exclusions, record_exclusion,
match_exclusions. Supports 5 scope types: exact_line, pattern,
function, file, directory. Creates .screw/learning/ on first write.
Schema matches PRD §11.2 exactly (frozen for Phase 3)."
```

---

## Task 3: Engine — Exclusion-Aware Assembly

**Files:**
- Modify: `src/screw_agents/engine.py:37-131`
- Test: `tests/test_engine.py` (extend)

- [ ] **Step 1: Write failing tests for project_root parameter**

Add to `tests/test_engine.py`:

```python
import yaml


class TestAssembleScanExclusions:
    def test_assemble_scan_no_project_root_no_exclusions_key(self, engine, fixtures_dir):
        """Backwards compat: no project_root means no exclusions in payload."""
        vuln_dir = fixtures_dir / "sqli" / "vulnerable"
        py_files = list(vuln_dir.glob("*.py"))
        if not py_files:
            pytest.skip("no Python fixtures")
        target = {"type": "file", "path": str(py_files[0])}
        result = engine.assemble_scan(agent_name="sqli", target=target)
        assert "exclusions" not in result

    def test_assemble_scan_with_project_root_no_file(self, engine, fixtures_dir, tmp_path):
        """project_root with no exclusions file → empty exclusions list."""
        vuln_dir = fixtures_dir / "sqli" / "vulnerable"
        py_files = list(vuln_dir.glob("*.py"))
        if not py_files:
            pytest.skip("no Python fixtures")
        target = {"type": "file", "path": str(py_files[0])}
        result = engine.assemble_scan(agent_name="sqli", target=target, project_root=tmp_path)
        assert "exclusions" in result
        assert result["exclusions"] == []

    def test_assemble_scan_with_exclusions(self, engine, fixtures_dir, tmp_path):
        """project_root with exclusions file → filtered exclusions in payload."""
        vuln_dir = fixtures_dir / "sqli" / "vulnerable"
        py_files = list(vuln_dir.glob("*.py"))
        if not py_files:
            pytest.skip("no Python fixtures")

        # Write an exclusion for sqli agent
        learning_dir = tmp_path / ".screw" / "learning"
        learning_dir.mkdir(parents=True)
        data = {
            "exclusions": [
                {
                    "id": "fp-2026-04-11-001",
                    "created": "2026-04-11T14:35:00Z",
                    "agent": "sqli",
                    "finding": {"file": "src/api.py", "line": 42, "code_pattern": "db.query(*)", "cwe": "CWE-89"},
                    "reason": "safe",
                    "scope": {"type": "pattern", "pattern": "db.query(*)"},
                    "times_suppressed": 0,
                    "last_suppressed": None,
                },
                {
                    "id": "fp-2026-04-11-002",
                    "created": "2026-04-11T14:36:00Z",
                    "agent": "xss",
                    "finding": {"file": "src/api.py", "line": 50, "code_pattern": "render(*)", "cwe": "CWE-79"},
                    "reason": "safe",
                    "scope": {"type": "file", "path": "src/api.py"},
                    "times_suppressed": 0,
                    "last_suppressed": None,
                },
            ]
        }
        (learning_dir / "exclusions.yaml").write_text(yaml.dump(data))

        target = {"type": "file", "path": str(py_files[0])}
        result = engine.assemble_scan(agent_name="sqli", target=target, project_root=tmp_path)
        assert "exclusions" in result
        # Only the sqli exclusion should be included, not the xss one
        assert len(result["exclusions"]) == 1
        assert result["exclusions"][0]["agent"] == "sqli"

    def test_assemble_domain_scan_with_project_root(self, engine, fixtures_dir, tmp_path):
        """Domain scan passes project_root through to each agent scan."""
        vuln_dir = fixtures_dir / "sqli" / "vulnerable"
        py_files = list(vuln_dir.glob("*.py"))
        if not py_files:
            pytest.skip("no Python fixtures")
        target = {"type": "file", "path": str(py_files[0])}
        results = engine.assemble_domain_scan(
            domain="injection-input-handling", target=target, project_root=tmp_path,
        )
        for r in results:
            assert "exclusions" in r

    def test_assemble_full_scan_with_project_root(self, engine, fixtures_dir, tmp_path):
        """Full scan passes project_root through."""
        vuln_dir = fixtures_dir / "sqli" / "vulnerable"
        py_files = list(vuln_dir.glob("*.py"))
        if not py_files:
            pytest.skip("no Python fixtures")
        target = {"type": "file", "path": str(py_files[0])}
        results = engine.assemble_full_scan(target=target, project_root=tmp_path)
        for r in results:
            assert "exclusions" in r
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_engine.py::TestAssembleScanExclusions -v`
Expected: TypeError — `assemble_scan` doesn't accept `project_root`.

- [ ] **Step 3: Modify engine.py to accept project_root**

In `src/screw_agents/engine.py`, add the import at the top (after line 11):

```python
from pathlib import Path

from screw_agents.learning import load_exclusions
```

Modify `assemble_scan` signature and body (replace lines 37-90):

```python
    def assemble_scan(
        self,
        agent_name: str,
        target: dict[str, Any],
        thoroughness: str = "standard",
        project_root: Path | None = None,
    ) -> dict[str, Any]:
        """Assemble a scan payload for a single agent.

        Args:
            agent_name: Registered agent identifier (e.g. "sqli").
            target: Target spec dict (PRD §5 format).
            thoroughness: One of "standard", "deep". Controls which
                heuristic tiers are included in the prompt.
            project_root: Optional project root for exclusion loading.
                When provided, exclusions from .screw/learning/exclusions.yaml
                are filtered by agent and included in the payload.

        Returns:
            Dict with keys:
                - agent_name: str
                - core_prompt: str  (assembled prompt)
                - code: str         (formatted code context)
                - resolved_files: list[str]
                - meta: dict        (agent metadata summary)
                - exclusions: list[dict]  (only when project_root is provided)

        Raises:
            ValueError: If agent_name is not registered.
        """
        agent = self._registry.get_agent(agent_name)
        if agent is None:
            raise ValueError(f"Unknown agent: {agent_name!r}")

        # Resolve target to code chunks
        codes = resolve_target(target)

        # For broad targets, filter by agent relevance signals
        target_type = target.get("type", "")
        if target_type in ("codebase", "glob"):
            signals = agent.target_strategy.relevance_signals
            codes = filter_by_relevance(codes, signals)

        prompt = self._build_prompt(agent, thoroughness)
        code_context = self._format_code_context(codes)

        result: dict[str, Any] = {
            "agent_name": agent_name,
            "core_prompt": prompt,
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

        if project_root is not None:
            all_exclusions = load_exclusions(project_root)
            agent_exclusions = [e for e in all_exclusions if e.agent == agent_name]
            result["exclusions"] = [e.model_dump() for e in agent_exclusions]

        return result
```

Modify `assemble_domain_scan` (replace lines 92-112):

```python
    def assemble_domain_scan(
        self,
        domain: str,
        target: dict[str, Any],
        thoroughness: str = "standard",
        project_root: Path | None = None,
    ) -> list[dict[str, Any]]:
        """Assemble scan payloads for every agent in a domain.

        Args:
            domain: Domain name (e.g. "injection-input-handling").
            target: Target spec dict.
            thoroughness: Passed through to assemble_scan.
            project_root: Optional project root for exclusion loading.

        Returns:
            List of assemble_scan results, one per agent in the domain.
        """
        agents = self._registry.get_agents_by_domain(domain)
        return [
            self.assemble_scan(a.meta.name, target, thoroughness, project_root)
            for a in agents
        ]
```

Modify `assemble_full_scan` (replace lines 114-131):

```python
    def assemble_full_scan(
        self,
        target: dict[str, Any],
        thoroughness: str = "standard",
        project_root: Path | None = None,
    ) -> list[dict[str, Any]]:
        """Assemble scan payloads for all registered agents.

        Args:
            target: Target spec dict.
            thoroughness: Passed through to assemble_scan.
            project_root: Optional project root for exclusion loading.

        Returns:
            List of assemble_scan results for every registered agent.
        """
        return [
            self.assemble_scan(name, target, thoroughness, project_root)
            for name in self._registry.agents
        ]
```

Add `project_root` to the tool schemas. In `list_tool_definitions`, add to every scan tool's `extra_props` dict. Create a helper function after `_thoroughness_schema()`:

```python
def _project_root_schema() -> dict[str, Any]:
    """JSON Schema for the optional 'project_root' parameter."""
    return {
        "type": "string",
        "description": (
            "Absolute path to the project root directory. When provided, "
            "exclusions from .screw/learning/exclusions.yaml are loaded "
            "and included in the scan payload."
        ),
    }
```

Then add `"project_root": _project_root_schema()` to the `extra_props` dict for `scan_domain`, `scan_full`, and the per-agent scan tools in `list_tool_definitions`. Do NOT add it to `extra_required` — it remains optional.

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_engine.py -v`
Expected: All tests pass, including existing ones (project_root defaults to None).

- [ ] **Step 5: Run full test suite**

Run: `uv run pytest tests/ -v`
Expected: All pass.

- [ ] **Step 6: Commit**

```bash
git add src/screw_agents/engine.py tests/test_engine.py
git commit -m "feat(engine): exclusion-aware scan assembly with project_root

Phase 2 step 3: assemble_scan/domain/full gain optional project_root
parameter. When provided, loads exclusions from .screw/learning/ and
includes agent-filtered exclusions in payload. Default None preserves
Phase 1 backwards compat (benchmark evaluator unaffected)."
```

---

## Task 4: Server — New MCP Tools + project_root Passthrough

**Files:**
- Modify: `src/screw_agents/server.py:73-122`
- Create: `tests/test_phase2_server.py`

- [ ] **Step 1: Write failing tests for new tools and project_root passthrough**

Create `tests/test_phase2_server.py`:

```python
"""Tests for Phase 2 MCP server changes: new tools + project_root."""

import json
import yaml
import pytest
from pathlib import Path

from screw_agents.server import create_server, _dispatch_tool


@pytest.fixture
def engine(domains_dir):
    _, engine = create_server(domains_dir)
    return engine


class TestFormatOutputTool:
    def test_dispatch_format_output_json(self, engine):
        findings = [
            {
                "id": "test-001",
                "agent": "sqli",
                "domain": "injection-input-handling",
                "timestamp": "2026-04-11T14:30:00Z",
                "location": {"file": "src/api.py", "line_start": 42},
                "classification": {
                    "cwe": "CWE-89",
                    "cwe_name": "SQL Injection",
                    "severity": "high",
                    "confidence": "high",
                },
                "analysis": {"description": "SQL injection found"},
                "remediation": {"recommendation": "Use parameterized queries"},
            }
        ]
        result = _dispatch_tool(engine, "format_output", {
            "findings": findings,
            "format": "json",
        })
        assert "formatted" in result
        parsed = json.loads(result["formatted"])
        assert len(parsed) == 1
        assert parsed[0]["id"] == "test-001"

    def test_dispatch_format_output_markdown(self, engine):
        result = _dispatch_tool(engine, "format_output", {
            "findings": [],
            "format": "markdown",
            "scan_metadata": {"target": "src/api/", "agents": ["sqli"]},
        })
        assert "formatted" in result
        assert "Security Scan Report" in result["formatted"]

    def test_dispatch_format_output_sarif(self, engine):
        result = _dispatch_tool(engine, "format_output", {
            "findings": [],
            "format": "sarif",
        })
        assert "formatted" in result
        parsed = json.loads(result["formatted"])
        assert parsed["version"] == "2.1.0"


class TestExclusionTools:
    def test_dispatch_record_exclusion(self, engine, tmp_path):
        result = _dispatch_tool(engine, "record_exclusion", {
            "project_root": str(tmp_path),
            "exclusion": {
                "agent": "sqli",
                "finding": {"file": "src/api.py", "line": 42, "code_pattern": "db.query(*)", "cwe": "CWE-89"},
                "reason": "safe",
                "scope": {"type": "pattern", "pattern": "db.query(*)"},
            },
        })
        assert "exclusion" in result
        assert result["exclusion"]["id"].startswith("fp-")
        assert result["exclusion"]["agent"] == "sqli"

    def test_dispatch_check_exclusions_empty(self, engine, tmp_path):
        result = _dispatch_tool(engine, "check_exclusions", {
            "project_root": str(tmp_path),
            "agent": "sqli",
        })
        assert "exclusions" in result
        assert result["exclusions"] == []

    def test_dispatch_check_exclusions_filtered(self, engine, tmp_path):
        # Record two exclusions for different agents
        _dispatch_tool(engine, "record_exclusion", {
            "project_root": str(tmp_path),
            "exclusion": {
                "agent": "sqli",
                "finding": {"file": "a.py", "line": 1, "code_pattern": "x", "cwe": "CWE-89"},
                "reason": "safe",
                "scope": {"type": "file", "path": "a.py"},
            },
        })
        _dispatch_tool(engine, "record_exclusion", {
            "project_root": str(tmp_path),
            "exclusion": {
                "agent": "xss",
                "finding": {"file": "b.py", "line": 2, "code_pattern": "y", "cwe": "CWE-79"},
                "reason": "safe",
                "scope": {"type": "file", "path": "b.py"},
            },
        })
        result = _dispatch_tool(engine, "check_exclusions", {
            "project_root": str(tmp_path),
            "agent": "sqli",
        })
        assert len(result["exclusions"]) == 1
        assert result["exclusions"][0]["agent"] == "sqli"


class TestScanToolProjectRoot:
    def test_scan_tool_accepts_project_root(self, engine, domains_dir, tmp_path):
        """scan_* tools pass project_root through to engine."""
        fixtures_dir = Path(__file__).resolve().parent.parent / "benchmarks" / "fixtures"
        vuln_dir = fixtures_dir / "sqli" / "vulnerable"
        py_files = list(vuln_dir.glob("*.py"))
        if not py_files:
            pytest.skip("no Python fixtures")
        result = _dispatch_tool(engine, "scan_sqli", {
            "target": {"type": "file", "path": str(py_files[0])},
            "project_root": str(tmp_path),
        })
        assert "exclusions" in result

    def test_scan_tool_without_project_root(self, engine, domains_dir):
        """scan_* tools without project_root → no exclusions key (backwards compat)."""
        fixtures_dir = Path(__file__).resolve().parent.parent / "benchmarks" / "fixtures"
        vuln_dir = fixtures_dir / "sqli" / "vulnerable"
        py_files = list(vuln_dir.glob("*.py"))
        if not py_files:
            pytest.skip("no Python fixtures")
        result = _dispatch_tool(engine, "scan_sqli", {
            "target": {"type": "file", "path": str(py_files[0])},
        })
        assert "exclusions" not in result


class TestNewToolsRegistered:
    def test_format_output_in_tool_list(self, domains_dir):
        _, engine = create_server(domains_dir)
        tools = engine.list_tool_definitions()
        names = {t["name"] for t in tools}
        assert "format_output" in names
        assert "record_exclusion" in names
        assert "check_exclusions" in names

    def test_scan_tools_have_project_root(self, domains_dir):
        _, engine = create_server(domains_dir)
        tools = engine.list_tool_definitions()
        for t in tools:
            if t["name"].startswith("scan_") or t["name"] in ("scan_domain", "scan_full"):
                props = t["input_schema"].get("properties", {})
                assert "project_root" in props, f"{t['name']} missing project_root"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_phase2_server.py -v`
Expected: Failures — tools not yet wired.

- [ ] **Step 3: Modify server.py — add new tools and project_root passthrough**

In `src/screw_agents/server.py`, add imports (after line 15):

```python
from screw_agents.learning import load_exclusions, record_exclusion
from screw_agents.models import ExclusionInput, ExclusionScope, ExclusionFinding, Finding
```

Replace `_dispatch_tool` (lines 73-122) with:

```python
def _dispatch_tool(
    engine: ScanEngine, name: str, args: dict[str, Any]
) -> Any:
    """Synchronous dispatcher — routes MCP tool calls to engine methods."""

    if name == "list_domains":
        return engine.list_domains()

    if name == "list_agents":
        return engine.list_agents(domain=args.get("domain"))

    # --- Phase 2: new tools ---

    if name == "format_output":
        findings_raw = args.get("findings", [])
        output_format = args.get("format", "json")
        scan_metadata = args.get("scan_metadata")
        findings = [Finding(**f) for f in findings_raw]
        formatted = engine.format_output(findings, output_format, scan_metadata)
        return {"formatted": formatted}

    if name == "record_exclusion":
        project_root = Path(args["project_root"])
        exc_data = args["exclusion"]
        exc_input = ExclusionInput(**exc_data)
        saved = record_exclusion(project_root, exc_input)
        return {"exclusion": saved.model_dump()}

    if name == "check_exclusions":
        project_root = Path(args["project_root"])
        agent_filter = args.get("agent")
        all_exc = load_exclusions(project_root)
        if agent_filter:
            all_exc = [e for e in all_exc if e.agent == agent_filter]
        return {"exclusions": [e.model_dump() for e in all_exc]}

    # --- Scan tools (Phase 1 + Phase 2 project_root) ---

    project_root = Path(args["project_root"]) if args.get("project_root") else None

    if name == "scan_domain":
        return engine.assemble_domain_scan(
            domain=args["domain"],
            target=args["target"],
            thoroughness=args.get("thoroughness", "standard"),
            project_root=project_root,
        )

    if name == "scan_full":
        return engine.assemble_full_scan(
            target=args["target"],
            thoroughness=args.get("thoroughness", "standard"),
            project_root=project_root,
        )

    # Per-agent scan tools: scan_{agent_name}
    if name.startswith("scan_"):
        agent_name = name[len("scan_"):]
        return engine.assemble_scan(
            agent_name=agent_name,
            target=args["target"],
            thoroughness=args.get("thoroughness", "standard"),
            project_root=project_root,
        )

    raise ValueError(f"Unknown tool: {name!r}")
```

Add new tool definitions to `list_tool_definitions` in `engine.py`. After the per-agent scan tool loop (after line 228), add these three tool definitions. Also add `"project_root": _project_root_schema()` to `extra_props` for `scan_domain`, `scan_full`, and each per-agent scan tool.

In `src/screw_agents/engine.py`, update the `list_tool_definitions` method. The `scan_domain` tool definition (lines 180-196) gets `_project_root_schema()` added:

```python
        tools.append({
            "name": "scan_domain",
            "description": (
                "Run all agents in a vulnerability domain against the target. "
                "Returns assembled prompt payloads for each agent."
            ),
            "input_schema": self._scan_input_schema(
                extra_required=["target", "domain"],
                extra_props={
                    "target": _target_schema(),
                    "domain": {
                        "type": "string",
                        "description": "Domain name (e.g. 'injection-input-handling').",
                    },
                    "thoroughness": _thoroughness_schema(),
                    "project_root": _project_root_schema(),
                },
            ),
        })
```

Same for `scan_full` and per-agent tools — add `"project_root": _project_root_schema()` to their `extra_props`.

Then add the 3 new tool definitions after the per-agent loop:

```python
        # Phase 2: format_output
        tools.append({
            "name": "format_output",
            "description": (
                "Format scan findings as JSON, SARIF 2.1.0, or Markdown report. "
                "Pass the structured findings array from your analysis."
            ),
            "input_schema": {
                "type": "object",
                "properties": {
                    "findings": {
                        "type": "array",
                        "description": "Array of Finding objects (see models.py Finding schema).",
                    },
                    "format": {
                        "type": "string",
                        "enum": ["json", "sarif", "markdown"],
                        "description": "Output format.",
                        "default": "json",
                    },
                    "scan_metadata": {
                        "type": "object",
                        "description": "Optional metadata (target, agents, timestamp) for report header.",
                    },
                },
                "required": ["findings"],
            },
        })

        # Phase 2: record_exclusion
        tools.append({
            "name": "record_exclusion",
            "description": (
                "Record a false positive exclusion in .screw/learning/exclusions.yaml. "
                "Call this when the user marks a finding as a false positive."
            ),
            "input_schema": {
                "type": "object",
                "properties": {
                    "project_root": {
                        "type": "string",
                        "description": "Absolute path to the project root directory.",
                    },
                    "exclusion": {
                        "type": "object",
                        "description": "Exclusion data: agent, finding, reason, scope.",
                        "properties": {
                            "agent": {"type": "string"},
                            "finding": {
                                "type": "object",
                                "properties": {
                                    "file": {"type": "string"},
                                    "line": {"type": "integer"},
                                    "code_pattern": {"type": "string"},
                                    "cwe": {"type": "string"},
                                },
                                "required": ["file", "line", "code_pattern", "cwe"],
                            },
                            "reason": {"type": "string"},
                            "scope": {
                                "type": "object",
                                "properties": {
                                    "type": {
                                        "type": "string",
                                        "enum": ["exact_line", "pattern", "function", "file", "directory"],
                                    },
                                    "pattern": {"type": "string"},
                                    "path": {"type": "string"},
                                    "name": {"type": "string"},
                                },
                                "required": ["type"],
                            },
                        },
                        "required": ["agent", "finding", "reason", "scope"],
                    },
                },
                "required": ["project_root", "exclusion"],
            },
        })

        # Phase 2: check_exclusions
        tools.append({
            "name": "check_exclusions",
            "description": (
                "Load exclusions from .screw/learning/exclusions.yaml, "
                "optionally filtered by agent name."
            ),
            "input_schema": {
                "type": "object",
                "properties": {
                    "project_root": {
                        "type": "string",
                        "description": "Absolute path to the project root directory.",
                    },
                    "agent": {
                        "type": "string",
                        "description": "Filter exclusions to this agent (optional).",
                    },
                },
                "required": ["project_root"],
            },
        })
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_phase2_server.py -v`
Expected: All pass.

- [ ] **Step 5: Run full test suite (check existing server tests still pass)**

Run: `uv run pytest tests/ -v`
Expected: All pass. Existing `test_server.py` tests remain green — new tools are additive.

- [ ] **Step 6: Commit**

```bash
git add src/screw_agents/engine.py src/screw_agents/server.py tests/test_phase2_server.py
git commit -m "feat(server): wire format_output, record/check_exclusion MCP tools

Phase 2 step 4: three new MCP tools (format_output, record_exclusion,
check_exclusions). All scan_* tools gain optional project_root param
for exclusion loading. format_output parses Finding JSON via Pydantic.
Backwards compat preserved — project_root defaults to None."
```

---

## Task 5: Individual Agent Subagent Template

**Files:**
- Create: `plugins/screw/agents/screw-sqli.md` (the reference implementation)

This task builds one subagent as the template. Task 6 replicates it for the other 3.

- [ ] **Step 1: Write screw-sqli.md**

Create `plugins/screw/agents/screw-sqli.md`:

```markdown
---
name: screw-sqli
description: SQL injection security reviewer — detects CWE-89 vulnerabilities via screw-agents MCP server
tools:
  - mcp__screw-agents__scan_sqli
  - mcp__screw-agents__format_output
  - mcp__screw-agents__record_exclusion
  - mcp__screw-agents__check_exclusions
  - Read
  - Glob
  - Grep
  - Write
  - Edit
---

# SQL Injection Security Reviewer

You are a SQL injection specialist performing security code review. You detect CWE-89 (SQL Injection) and related vulnerabilities (CWE-564, CWE-566, CWE-943).

## Important: You Do NOT Carry Detection Knowledge

Your detection knowledge comes from the MCP server. When you call `scan_sqli`, the server returns a `core_prompt` field containing expert-curated detection heuristics, bypass techniques, and examples. Use that knowledge to analyze the code — do not rely on your general training for detection patterns.

## Workflow

Follow these steps exactly for every scan:

### Step 1: Determine the Target

Translate the user's request into a target specification:

| User says | Target spec |
|---|---|
| "check src/auth.rs" | `{ "type": "file", "path": "src/auth.rs" }` |
| "review src/api/" | `{ "type": "glob", "pattern": "src/api/**" }` |
| "look at lines 40-80 in auth.rs" | `{ "type": "lines", "file": "src/auth.rs", "start": 40, "end": 80 }` |
| "check the authenticate function in src/auth.rs" | `{ "type": "function", "file": "src/auth.rs", "name": "authenticate" }` |
| "review the User model in src/models.py" | `{ "type": "class", "file": "src/models.py", "name": "User" }` |
| "scan the whole project" | `{ "type": "codebase", "root": "." }` |
| "review my PR" / "check my changes" | `{ "type": "git_diff", "base": "main", "head": "HEAD" }` |
| "review the last 3 commits" | `{ "type": "git_commits", "range": "HEAD~3..HEAD" }` |
| "scan the feature/auth PR" | `{ "type": "pull_request", "base": "main", "head": "feature/auth" }` |

If the target is ambiguous, ask the user to clarify. Do not guess.

If no specific target is mentioned, use Glob and Grep to discover relevant files first, then construct an appropriate target.

### Step 2: Call the Scan Tool

Determine the project root (the directory containing `.git/` or the working directory) and call:

```
mcp__screw-agents__scan_sqli({
  "target": <target spec from step 1>,
  "project_root": "<absolute path to project root>"
})
```

The server returns:
- `core_prompt`: Detection knowledge — READ THIS CAREFULLY before analyzing
- `code`: The resolved source code to analyze
- `resolved_files`: Which files were included
- `meta`: Agent metadata (CWE, domain)
- `exclusions`: Previously recorded false positive patterns (may be empty)

### Step 3: Analyze the Code

Read the `core_prompt` thoroughly — it contains expert detection heuristics, bypass techniques, and examples specific to SQL injection. Then analyze the `code` using that knowledge.

For each potential vulnerability found, determine:
- **File and line location** (exact line numbers from the code)
- **CWE** (CWE-89 for standard SQLi, or related CWEs)
- **Severity** (critical/high/medium/low)
- **Confidence** (high/medium/low)
- **Description** of the vulnerability
- **Data flow** from source to sink where applicable
- **Remediation** with corrected code

Check each finding against the `exclusions` list. If a finding matches an exclusion pattern, mark it with `"excluded": true` and `"exclusion_ref": "<exclusion id>"` in the triage field.

### Step 4: Format the Output

Call the format tool with your findings:

```
mcp__screw-agents__format_output({
  "findings": [<your findings array>],
  "format": "markdown",
  "scan_metadata": {
    "target": "<what was scanned>",
    "agents": ["sqli"],
    "timestamp": "<current ISO8601 timestamp>"
  }
})
```

Also prepare the JSON version with `"format": "json"`.

### Step 5: Present Results and Write Files

1. Present a conversational summary to the user: how many findings, severity breakdown, key highlights.

2. Create the `.screw/` directory structure if it doesn't exist:
   - `.screw/findings/`
   - `.screw/learning/`
   - `.screw/.gitignore` with content:
     ```
     # Scan results are point-in-time — don't track in version control
     findings/
     # Exclusions are curated team knowledge — DO track
     !learning/
     ```
   - Tell the user: "Created `.screw/` directory for scan results. Findings are gitignored; exclusion patterns are tracked."

3. Write findings to:
   - `.screw/findings/sqli-<YYYY-MM-DDTHH-MM-SS>.json` (raw findings)
   - `.screw/findings/sqli-<YYYY-MM-DDTHH-MM-SS>.md` (formatted report)

### Step 6: Offer Follow-Up Actions

After presenting results, offer:
- "Want me to apply the suggested fix for any finding?"
- "Mark any findings as false positive?" — If yes, ask for the reason, determine the appropriate scope (exact_line, pattern, function, file, directory), and call `record_exclusion`.
- "Run another agent against the same target?"

## Finding JSON Schema

Each finding must follow this structure:

```json
{
  "id": "sqli-001",
  "agent": "sqli",
  "domain": "injection-input-handling",
  "timestamp": "<ISO8601>",
  "location": {
    "file": "<path>",
    "line_start": 42,
    "line_end": 45,
    "function": "<name or null>",
    "class_name": "<name or null>",
    "code_snippet": "<the vulnerable code>",
    "data_flow": {
      "source": "<tainted input>",
      "source_location": "<file:line>",
      "sink": "<dangerous function>",
      "sink_location": "<file:line>"
    }
  },
  "classification": {
    "cwe": "CWE-89",
    "cwe_name": "SQL Injection",
    "capec": "CAPEC-66",
    "owasp_top10": "A05:2025",
    "severity": "high",
    "confidence": "high"
  },
  "analysis": {
    "description": "<what and why>",
    "impact": "<consequence>",
    "exploitability": "<how easy>",
    "false_positive_reasoning": null
  },
  "remediation": {
    "recommendation": "<what to do>",
    "fix_code": "<corrected code>",
    "references": ["<url>"]
  },
  "triage": {
    "status": "pending",
    "excluded": false,
    "exclusion_ref": null
  }
}
```

## Confidence Calibration

- **High confidence**: Direct string concatenation/interpolation into SQL queries with user-controlled input and no parameterization
- **Medium confidence**: Dynamic query construction where parameterization status is unclear, or input passes through a wrapper whose safety is unknown
- **Low confidence**: Patterns that resemble SQLi but may be safe due to framework guarantees or input validation not visible in the current scope
```

- [ ] **Step 2: Remove the .gitkeep stub**

```bash
rm plugins/screw/agents/.gitkeep
```

- [ ] **Step 3: Commit**

```bash
git add plugins/screw/agents/screw-sqli.md
git rm plugins/screw/agents/.gitkeep 2>/dev/null; true
git commit -m "feat(agents): add screw-sqli subagent — reference template

Phase 2 step 5: SQLi subagent with 6-step workflow (target → scan →
analyze → format → write → follow-up). Detection knowledge comes from
MCP, not the prompt. Full Finding JSON schema documented. This is the
template for all individual agent subagents."
```

---

## Task 6: Remaining Individual Agent Subagents

**Files:**
- Create: `plugins/screw/agents/screw-cmdi.md`
- Create: `plugins/screw/agents/screw-ssti.md`
- Create: `plugins/screw/agents/screw-xss.md`

Each follows the screw-sqli.md template with these substitutions:

| Field | sqli | cmdi | ssti | xss |
|---|---|---|---|---|
| Agent name | sqli | cmdi | ssti | xss |
| Display name | SQL Injection | Command Injection | Server-Side Template Injection | Cross-Site Scripting |
| Primary CWE | CWE-89 | CWE-78 | CWE-1336 | CWE-79 |
| Related CWEs | CWE-564, CWE-566, CWE-943 | CWE-77, CWE-88 | CWE-94, CWE-1336 | CWE-80, CWE-87 |
| OWASP | A05:2025 | A05:2025 | A05:2025 | A05:2025 |
| CAPEC | CAPEC-66 | CAPEC-88 | CAPEC-242 | CAPEC-86 |
| MCP tool | scan_sqli | scan_cmdi | scan_ssti | scan_xss |
| High confidence | Direct SQL concat | Direct shell exec | Direct template render | Direct HTML output |
| Findings prefix | sqli-001 | cmdi-001 | ssti-001 | xss-001 |
| File prefix | sqli- | cmdi- | ssti- | xss- |

- [ ] **Step 1: Create screw-cmdi.md**

Copy the screw-sqli.md template and apply the cmdi substitutions from the table above. The structure is identical — only the agent-specific values change (name, CWE, CAPEC, tool name, confidence descriptions, finding ID prefix).

The confidence calibration section for cmdi:
```markdown
## Confidence Calibration

- **High confidence**: User input passed directly to os.system(), subprocess.call(shell=True), exec(), or equivalent with no sanitization
- **Medium confidence**: User input flows into command construction through intermediate variables or wrappers whose safety is unclear
- **Low confidence**: Patterns that resemble command injection but may be safe due to allow-listing, input validation, or non-shell execution
```

- [ ] **Step 2: Create screw-ssti.md**

Apply ssti substitutions. Confidence calibration for ssti:
```markdown
## Confidence Calibration

- **High confidence**: User input passed directly to template.render(), Template(user_input), or Jinja2/Twig/Freemarker render with no sandboxing
- **Medium confidence**: User input reaches template engine through indirect paths or with partial sanitization
- **Low confidence**: Template rendering with user data but sandbox/autoescape likely enabled
```

- [ ] **Step 3: Create screw-xss.md**

Apply xss substitutions. Confidence calibration for xss:
```markdown
## Confidence Calibration

- **High confidence**: User input written directly to HTML response without encoding, or into innerHTML/document.write with no sanitization
- **Medium confidence**: User input reaches output through framework rendering where auto-escaping status is unclear, or raw/safe filters used
- **Low confidence**: Patterns that resemble XSS but may be safe due to Content-Security-Policy, framework auto-escaping, or DOMPurify
```

- [ ] **Step 4: Commit**

```bash
git add plugins/screw/agents/screw-cmdi.md plugins/screw/agents/screw-ssti.md plugins/screw/agents/screw-xss.md
git commit -m "feat(agents): add cmdi, ssti, xss subagents

Phase 2 step 6: three remaining individual agent subagents, all
following the screw-sqli.md template with agent-specific CWEs,
CAPEC mappings, and confidence calibration."
```

---

## Task 7: Orchestrator Subagents

**Files:**
- Create: `plugins/screw/agents/screw-injection.md`
- Create: `plugins/screw/agents/screw-full-review.md`

- [ ] **Step 1: Create screw-injection.md**

Create `plugins/screw/agents/screw-injection.md`:

```markdown
---
name: screw-injection
description: "Injection & input handling domain orchestrator — runs all injection agents (sqli, cmdi, ssti, xss)"
tools:
  - mcp__screw-agents__scan_domain
  - mcp__screw-agents__format_output
  - mcp__screw-agents__record_exclusion
  - mcp__screw-agents__check_exclusions
  - Read
  - Glob
  - Grep
  - Write
---

# Injection & Input Handling Domain Orchestrator

You orchestrate all injection vulnerability agents in the `injection-input-handling` domain: SQL injection (CWE-89), command injection (CWE-78), server-side template injection (CWE-1336), and cross-site scripting (CWE-79).

## Important: You Do NOT Carry Detection Knowledge

Detection knowledge comes from the MCP server via the `scan_domain` tool. Each agent's payload includes its own `core_prompt` with expert-curated heuristics. Use each agent's knowledge to analyze the code — do not rely on your general training.

## Workflow

### Step 1: Determine the Target

Same target interpretation as individual agents. See the target spec table:

| User says | Target spec |
|---|---|
| "check src/auth.rs" | `{ "type": "file", "path": "src/auth.rs" }` |
| "review src/api/" | `{ "type": "glob", "pattern": "src/api/**" }` |
| "scan the whole project" | `{ "type": "codebase", "root": "." }` |
| "review my PR" | `{ "type": "git_diff", "base": "main", "head": "HEAD" }` |

If the target is ambiguous, ask the user to clarify.

### Step 2: Call scan_domain

```
mcp__screw-agents__scan_domain({
  "domain": "injection-input-handling",
  "target": <target spec>,
  "project_root": "<absolute path to project root>"
})
```

The server returns a list of payloads — one per agent (sqli, cmdi, ssti, xss). Each payload contains `agent_name`, `core_prompt`, `code`, `resolved_files`, `meta`, and `exclusions`.

### Step 3: Analyze Each Payload

For each agent payload in the list:
1. Read the agent's `core_prompt` (detection knowledge)
2. Analyze the `code` using that knowledge
3. Check findings against that agent's `exclusions`
4. Produce findings following the Finding JSON schema (same as individual agents)

Analyze all 4 agents sequentially. Keep findings tagged by agent.

### Step 4: Merge and Format

Combine all findings into a single list. Call format_output:

```
mcp__screw-agents__format_output({
  "findings": [<all findings from all agents>],
  "format": "markdown",
  "scan_metadata": {
    "target": "<what was scanned>",
    "agents": ["sqli", "cmdi", "ssti", "xss"],
    "timestamp": "<ISO8601>"
  }
})
```

### Step 5: Present and Write

1. Present a summary: total findings, breakdown by agent and severity
2. Create `.screw/` structure if needed (same as individual agents)
3. Write:
   - `.screw/findings/injection-<YYYY-MM-DDTHH-MM-SS>.json`
   - `.screw/findings/injection-<YYYY-MM-DDTHH-MM-SS>.md`

### Step 6: Offer Follow-Up

Same as individual agents: offer fixes, FP recording, further scans.

## Finding JSON Schema

Same schema as individual agents — see screw-sqli.md for the full structure.
```

- [ ] **Step 2: Create screw-full-review.md**

Create `plugins/screw/agents/screw-full-review.md`:

```markdown
---
name: screw-full-review
description: "Comprehensive security review — dispatches all available domain orchestrators in parallel"
tools:
  - mcp__screw-agents__list_domains
  - Agent
  - Read
  - Write
---

# Full Security Review Orchestrator

You coordinate a comprehensive security review by dispatching domain orchestrator subagents in parallel. You do NOT analyze code directly — each domain orchestrator handles its own analysis in an isolated context window.

## Workflow

### Step 1: Determine the Target

Same target interpretation as other agents. The most common trigger is a broad request: "full security review", "security audit", "scan everything".

### Step 2: Discover Available Domains

Call `list_domains` to see which domains have agents:

```
mcp__screw-agents__list_domains({})
```

Returns a mapping of domain names to agent counts. In Phase 2, only `injection-input-handling` has agents.

### Step 3: Dispatch Domain Orchestrators

For each domain with agents, dispatch the corresponding domain orchestrator subagent via the Agent tool. Run them in parallel when possible.

Currently available:
- `injection-input-handling` → dispatch `screw-injection` subagent

Pass the user's target specification and project root to each orchestrator.

For domains without an orchestrator subagent yet, skip them and note in the report: "Domain X has N agents but no orchestrator — skipped."

### Step 4: Collect and Consolidate

After all domain orchestrators return:
1. Read the findings files they wrote to `.screw/findings/`
2. Write a consolidated executive report:
   - `.screw/findings/full-review-<YYYY-MM-DDTHH-MM-SS>.md`
3. The executive report includes:
   - Overview: which domains were scanned, which were skipped
   - Total finding count by severity across all domains
   - Per-domain summary (link to domain-level reports)
   - Cross-domain observations (e.g., injection + access control issues in the same module)

### Step 5: Present to User

Summarize: domains scanned, total findings, severity breakdown, key risks. Point the user to the full report and per-domain reports.

Offer: "Want to dig into any specific finding or domain?"
```

- [ ] **Step 3: Commit**

```bash
git add plugins/screw/agents/screw-injection.md plugins/screw/agents/screw-full-review.md
git commit -m "feat(agents): add injection orchestrator and full-review orchestrator

Phase 2 step 7: screw-injection.md (domain orchestrator, calls
scan_domain, analyzes all 4 agents sequentially) and
screw-full-review.md (dispatches domain orchestrators via Agent
tool for context window scalability per D6)."
```

---

## Task 8: Auto-Invocation Skill

**Files:**
- Create: `plugins/screw/skills/screw-review/SKILL.md` (replaces .gitkeep)

- [ ] **Step 1: Write SKILL.md**

Create `plugins/screw/skills/screw-review/SKILL.md`:

```markdown
---
name: screw-review
description: >
  Use when the user asks for security review, vulnerability scanning, or security audit.
  Recognizes security review intent and delegates to the appropriate screw-agents subagent.
---

# Security Review Skill

You recognize security review requests and delegate to the appropriate screw-agents subagent.

## When This Skill Activates

- User asks for security review: "review for vulnerabilities", "security audit", "check for security issues"
- User mentions specific vulnerability types: "check for SQL injection", "is this vulnerable to XSS?", "look for command injection"
- User asks to scan code: "scan src/api/", "review my PR for security", "audit this file"

## What to Do

### 1. Determine Scope

Based on the user's request, decide which subagent to dispatch:

| User intent | Subagent |
|---|---|
| Specific vulnerability: "SQL injection", "SQLi" | `screw-sqli` |
| Specific vulnerability: "command injection", "CmdI" | `screw-cmdi` |
| Specific vulnerability: "template injection", "SSTI" | `screw-ssti` |
| Specific vulnerability: "XSS", "cross-site scripting" | `screw-xss` |
| Domain: "injection vulnerabilities", "input validation" | `screw-injection` |
| Broad: "security review", "security audit", "full scan" | `screw-full-review` |

### 2. Check for Existing Findings

Before dispatching, check if `.screw/findings/` contains recent reports for the same target and agent. If a report exists from the current day, mention it: "There's already a scan from today — want me to re-scan or would you like to review the existing report?"

### 3. Delegate

Dispatch the chosen subagent via the Agent tool. Pass along the user's target description so the subagent can interpret it.

### 4. Summarize

After the subagent completes, briefly summarize what was found and where the reports were written.

## Unavailable Agents

If the user asks about a vulnerability type without a dedicated agent, respond with what's available:

"No dedicated agent for [requested type] yet. Available agents: **sqli** (SQL injection), **cmdi** (command injection), **ssti** (template injection), **xss** (cross-site scripting). The **injection** domain orchestrator runs all four. Want me to run one of these?"

## What NOT to Do

- Do NOT auto-trigger on code changes — only activate when the user explicitly requests security review
- Do NOT analyze code yourself — always delegate to subagents
- Do NOT attempt ad-hoc security review without the MCP tools
```

- [ ] **Step 2: Remove the .gitkeep stub**

```bash
rm plugins/screw/skills/screw-review/.gitkeep
```

- [ ] **Step 3: Commit**

```bash
git add plugins/screw/skills/screw-review/SKILL.md
git rm plugins/screw/skills/screw-review/.gitkeep 2>/dev/null; true
git commit -m "feat(skill): add screw-review auto-invocation skill

Phase 2 step 8: SKILL.md teaches Claude Code main agent to recognize
security review requests and delegate to the right subagent. Includes
routing table, duplicate scan detection, and fallback for unavailable
agents."
```

---

## Task 9: Slash Command

**Files:**
- Create: `plugins/screw/commands/scan.md` (replaces .gitkeep)

- [ ] **Step 1: Write scan.md**

Create `plugins/screw/commands/scan.md`:

```markdown
---
name: screw:scan
description: "Run a security scan with screw-agents. Usage: /screw:scan <agent|domain|full> [target] [--thoroughness standard|deep] [--format json|sarif|markdown]"
---

# /screw:scan — Security Scan Command

Parse the arguments and dispatch to the appropriate screw-agents subagent.

## Syntax

```
/screw:scan <scope> [target] [--thoroughness standard|deep] [--format json|sarif|markdown]
```

## Arguments

**scope** (required): What to scan with.
- Agent name: `sqli`, `cmdi`, `ssti`, `xss`
- Domain name: `injection`
- `full` for comprehensive review

**target** (optional, defaults to codebase root):
- Bare path: `src/api/auth.rs` (file) or `src/api/**` (glob — auto-detected by presence of `*`)
- `git_diff:BASE` → `{ "type": "git_diff", "base": "BASE", "head": "HEAD" }`
- `function:NAME@FILE` → `{ "type": "function", "file": "FILE", "name": "NAME" }`
- `class:NAME@FILE` → `{ "type": "class", "file": "FILE", "name": "NAME" }`
- `commits:RANGE` → `{ "type": "git_commits", "range": "RANGE" }`

**--thoroughness** (optional, default `standard`): `standard` or `deep`. Passed to the scan tool.

**--format** (optional, default `markdown`): `json`, `sarif`, or `markdown`. Passed to format_output.

## Dispatch

After parsing, delegate to the appropriate subagent via the Agent tool:

| Scope | Subagent |
|---|---|
| `sqli` | `screw-sqli` |
| `cmdi` | `screw-cmdi` |
| `ssti` | `screw-ssti` |
| `xss` | `screw-xss` |
| `injection` | `screw-injection` |
| `full` | `screw-full-review` |

Pass the parsed target, thoroughness, and format to the subagent so it can use them.

## Examples

```
/screw:scan sqli src/api/auth.rs
/screw:scan injection --target git_diff:main
/screw:scan full --thoroughness deep
/screw:scan xss src/components/**
/screw:scan sqli function:get_user@src/api/users.py
```
```

- [ ] **Step 2: Remove the .gitkeep stub**

```bash
rm plugins/screw/commands/.gitkeep
```

- [ ] **Step 3: Commit**

```bash
git add plugins/screw/commands/scan.md
git rm plugins/screw/commands/.gitkeep 2>/dev/null; true
git commit -m "feat(commands): add /screw:scan slash command

Phase 2 step 9: parameterized scan command with target shorthand
syntax (git_diff:, function:, class:, commits:), thoroughness and
format options. Dispatches to same subagents as the skill."
```

---

## Task 10: CLAUDE.md Template

**Files:**
- Create: `plugins/screw/CLAUDE.md.template`

- [ ] **Step 1: Write the template**

Create `plugins/screw/CLAUDE.md.template`:

```markdown
## Security Review

This project uses screw security agents via the screw-agents MCP server.

### How to run scans

- Ask naturally: "review src/api/ for injection vulnerabilities"
- Or use the slash command: `/screw:scan <agent|domain|full> [target]`
- Available agents: `sqli` (SQL injection), `cmdi` (command injection), `ssti` (template injection), `xss` (cross-site scripting)
- Available domains: `injection` (runs all injection agents)
- Use `full` for a comprehensive security review across all domains

### Findings

- Scan results are stored in `.screw/findings/` (JSON + Markdown reports)
- Check existing findings before re-scanning to avoid duplicates
- Use the screw MCP tools for analysis — don't attempt ad-hoc security review

### False positives

- Mark findings as false positives during review to improve future scans
- Exclusions are stored in `.screw/learning/exclusions.yaml`
- Exclusions are project-scoped and can be committed to share with the team

### .screw/ directory

- `.screw/findings/` — scan results (gitignored by default)
- `.screw/learning/` — exclusion patterns (tracked by default)
```

- [ ] **Step 2: Commit**

```bash
git add plugins/screw/CLAUDE.md.template
git commit -m "docs: add CLAUDE.md template for projects using screw-agents

Phase 2 step 10: template users copy into their project CLAUDE.md.
Documents scan usage, findings location, FP exclusions, and .screw/
directory structure."
```

---

## Task 11: E2E Test Checklist + Final Cleanup

**Files:**
- Create: `docs/PHASE_2_E2E_TEST.md`
- Modify: `docs/PROJECT_STATUS.md` (update current phase)

- [ ] **Step 1: Write E2E smoke test checklist**

Create `docs/PHASE_2_E2E_TEST.md`:

```markdown
# Phase 2 End-to-End Smoke Test Checklist

Manual integration test for Claude Code. Run after all code is merged.

## Prerequisites

1. MCP server configured in Claude Code:
   ```bash
   claude mcp add screw-agents -- uv run --directory /path/to/screw-agents python -m screw_agents.server
   ```
2. Subagent and skill files installed (or symlinked from `plugins/screw/`)
3. A test project with known-vulnerable code (use `benchmarks/fixtures/`)

## Test Cases

### TC-1: Individual agent scan (natural language)

- [ ] Open Claude Code in a project directory
- [ ] Say: "review benchmarks/fixtures/sqli/vulnerable/ for SQL injection"
- [ ] Verify: screw-review skill activates, delegates to screw-sqli subagent
- [ ] Verify: subagent calls scan_sqli MCP tool
- [ ] Verify: subagent presents findings conversationally
- [ ] Verify: `.screw/findings/sqli-*.json` and `.screw/findings/sqli-*.md` files created
- [ ] Verify: `.screw/.gitignore` created with correct content

### TC-2: Individual agent scan (slash command)

- [ ] Run: `/screw:scan sqli benchmarks/fixtures/sqli/vulnerable/`
- [ ] Verify: same pipeline as TC-1
- [ ] Verify: `--thoroughness deep` flag works

### TC-3: Domain scan

- [ ] Say: "review benchmarks/fixtures/sqli/vulnerable/ for injection vulnerabilities"
- [ ] Verify: screw-injection orchestrator dispatched
- [ ] Verify: all 4 agents analyzed (sqli, cmdi, ssti, xss findings in report)
- [ ] Verify: `.screw/findings/injection-*.md` written

### TC-4: Full review

- [ ] Say: "full security review of benchmarks/fixtures/"
- [ ] Verify: screw-full-review dispatched → screw-injection dispatched
- [ ] Verify: `.screw/findings/full-review-*.md` written

### TC-5: False positive recording

- [ ] Run a scan that produces findings
- [ ] Say: "finding #1 is a false positive because [reason]"
- [ ] Verify: subagent calls record_exclusion MCP tool
- [ ] Verify: `.screw/learning/exclusions.yaml` created/updated
- [ ] Verify: exclusion has correct id, agent, scope

### TC-6: Exclusion applied on re-scan

- [ ] Re-run the same scan from TC-5
- [ ] Verify: the excluded finding is annotated or suppressed
- [ ] Verify: markdown report includes "Suppressed Findings" section

### TC-7: Unavailable agent fallback

- [ ] Say: "check for SSRF vulnerabilities"
- [ ] Verify: skill responds with available agents, does not crash

### TC-8: format_output tool

- [ ] Verify: JSON format produces valid JSON array
- [ ] Verify: SARIF format produces valid SARIF 2.1.0
- [ ] Verify: Markdown format produces readable report

## Expected Results

All test cases should pass without errors. The MCP server should handle all tool calls. Subagent prompts should produce structured findings matching the Finding JSON schema.
```

- [ ] **Step 2: Update PROJECT_STATUS.md**

Update the "Current Phase" line in `docs/PROJECT_STATUS.md` to reflect Phase 2 in progress. Update the "What's NOT Done" section. Add a Phase 2 section similar to the Phase 1 section with task completion tracking.

The exact edits depend on what was completed vs. what remains — update this after all tasks are merged, just before the final commit.

- [ ] **Step 3: Run full test suite one last time**

Run: `uv run pytest tests/ -v`
Expected: All tests pass.

- [ ] **Step 4: Commit**

```bash
git add docs/PHASE_2_E2E_TEST.md docs/PROJECT_STATUS.md
git commit -m "docs: add Phase 2 E2E test checklist, update project status

Phase 2 step 11: manual smoke test checklist (8 test cases) and
project status update for Phase 2 completion."
```

---

## Self-Review Notes

**Spec coverage verified:**
- Spec §2 (architectural decision) → documented in spec, implemented by subagent design (Task 5-7)
- Spec §3 (pipeline) → Task 5 (screw-sqli.md workflow)
- Spec §4 (subagent design) → Tasks 5-7
- Spec §5 (skill) → Task 8
- Spec §6 (slash command) → Task 9
- Spec §7 (filesystem output) → Task 5 step 1 (subagent handles .screw/ creation)
- Spec §8 (exclusion learning) → Tasks 1-4
- Spec §9 (MCP changes) → Tasks 1-4
- Spec §10 (skill + command files) → Tasks 8-9
- Spec §11 (testing) → Tests in Tasks 1-4, E2E in Task 11
- Spec §12 (deliverables) → all 15 new files + 3 modified files accounted for
- Spec §13 (downstream decisions) → D1-D8 all implemented as specified

**Type consistency checked:**
- `Exclusion`, `ExclusionInput`, `ExclusionScope`, `ExclusionFinding` — consistent naming across models.py, learning.py, server.py
- `load_exclusions`, `record_exclusion`, `match_exclusions` — consistent signatures across learning.py, test_learning.py, server.py dispatch
- `project_root: Path | None = None` — consistent across engine.py methods
- `Finding` schema in subagent prompts matches models.py
- MCP tool names match between server.py dispatch, engine.py tool definitions, and subagent `.md` tool lists
