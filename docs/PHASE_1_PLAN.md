# Phase 1: Core Infrastructure — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the MCP server infrastructure that dynamically loads 4 agent YAML definitions, resolves code targets via tree-sitter, and formats findings as JSON/SARIF/Markdown — validated against real-CVE benchmarks.

**Architecture:** A Python MCP server (`src/screw_agents/`) using the low-level `mcp.Server` API (not FastMCP) with three parallel subsystems: agent registry (YAML → MCP tools), target resolver (tree-sitter AST + git diff + file discovery), and output formatter (JSON + SARIF 2.1.0 + Markdown). The server provides detection knowledge + resolved code to Claude (the host LLM) which performs the actual analysis.

**Tech Stack:**
- Python 3.11+ with `uv` for dependency management (ADR-011)
- `mcp` 1.27+ (low-level `Server` class, stdio + streamable HTTP transports)
- `tree-sitter` 0.25+ with 11 individual grammar packages (replacing abandoned `tree-sitter-languages`)
- Pydantic 2.x for YAML schema validation and finding models
- PyYAML 6.x for YAML parsing

**Decisions referenced:** ADR-002 (CWE-1400 backbone), ADR-011 (uv), ADR-013 (CWE-1400-native evaluator), ADR-014 (Rust corpus deferred)

**Design spec:** `docs/specs/phase-1-design.md` (gitignored)

---

## Quick Reference — Task List

| # | Task | Depends on | Parallel with |
|---|---|---|---|
| 1 | Migrate tree-sitter dependencies in `pyproject.toml` | — | — |
| 2 | Shared tree-sitter module (`treesitter.py`) | 1 | — |
| 3 | Update Phase 0.5 `primevul.py` to use shared tree-sitter module | 2 | — |
| 4 | Pydantic models — YAML agent schema (`models.py`) | 1 | 2 |
| 5 | Pydantic models — finding output schema (`models.py`) | 4 | — |
| 6 | Agent registry (`registry.py`) | 4 | 5 |
| 7 | Target resolver — file, glob, lines targets (`resolver.py`) | 2 | 6 |
| 8 | Target resolver — tree-sitter function/class extraction (`resolver.py`) | 7 | — |
| 9 | Target resolver — git diff parsing (`resolver.py`) | 7 | 8 |
| 10 | Target resolver — codebase, git_commits, pull_request targets (`resolver.py`) | 9 | — |
| 11 | Target resolver — relevance filtering and thoroughness (`resolver.py`) | 10 | — |
| 12 | Output formatter — JSON (`formatter.py`) | 5 | 11 |
| 13 | Output formatter — SARIF 2.1.0 (`formatter.py`) | 12 | — |
| 14 | Output formatter — Markdown (`formatter.py`) | 12 | — |
| 15 | Scan engine (`engine.py`) | 6, 11, 12 | — |
| 16 | MCP server skeleton + stdio transport (`server.py`) | 15 | — |
| 17 | MCP server — HTTP transport (`server.py`) | 16 | — |
| 18 | Integration tests — full scan pipeline | 17 | — |
| 19 | Smoke test with `claude --mcp-config` | 18 | — |
| 20 | Benchmark validation (Phase 1.7 gates) | 19 | — |

**Critical path:** 1 → 2 → 3 → 4 → 6 → 15 → 16 → 18 → 19 → 20

Tasks 7-11 (resolver) and 12-14 (formatter) can proceed in parallel with Task 6 (registry) once their dependencies are met.

---

## Prerequisites

Before Task 1, confirm the local environment:

```bash
python3 --version     # expect 3.11+
uv --version          # expect present
git --version         # expect present
```

Key files to read before starting:
- `docs/specs/phase-1-design.md` — approved design spec
- `docs/PRD.md` §4 (YAML schema), §5 (target spec), §6 (MCP tools), §8 (output schema)
- `domains/injection-input-handling/sqli.yaml` — reference agent YAML (956 lines)
- `benchmarks/runner/primevul.py:23-75` — existing tree-sitter ctypes hack to replace

---

## Directory Layout

Phase 1 creates these new files:

```
src/screw_agents/
├── __init__.py          # existing — no changes
├── server.py            # Task 16-17
├── registry.py          # Task 6
├── models.py            # Task 4-5
├── engine.py            # Task 15
├── resolver.py          # Task 7-11
├── formatter.py         # Task 12-14
└── treesitter.py        # Task 2

tests/
├── __init__.py          # Task 2
├── conftest.py          # Task 4
├── test_treesitter.py   # Task 2
├── test_models.py       # Task 4-5
├── test_registry.py     # Task 6
├── test_resolver.py     # Task 7-11
├── test_formatter.py    # Task 12-14
├── test_engine.py       # Task 15
└── test_server.py       # Task 16-17
```

Modified existing files:
- `pyproject.toml` — Task 1
- `.gitignore` — already updated (docs/specs/)
- `benchmarks/runner/primevul.py` — Task 3

---

## Task 1: Migrate tree-sitter dependencies in `pyproject.toml`

**Files:**
- Modify: `pyproject.toml`

**Context:** `tree-sitter-languages` is abandoned (no maintainer since Feb 2024, no Python 3.13/3.14 wheels). The official tree-sitter recommendation is individual grammar packages with stable ABI wheels (cp310-abi3).

- [ ] **Step 1: Read current `pyproject.toml`**

Read `pyproject.toml` to understand the current dependency layout. Note:
- `dependencies` has `tree-sitter>=0.23`
- `[dependency-groups] dev` has `tree-sitter-languages>=1.10`

- [ ] **Step 2: Update dependencies**

In `pyproject.toml`, make these changes:

In `[project] dependencies`, change `"tree-sitter>=0.23"` to `"tree-sitter>=0.25"` and add the 11 individual grammar packages:

```toml
dependencies = [
    "mcp",
    "tree-sitter>=0.25",
    "tree-sitter-python>=0.23",
    "tree-sitter-javascript>=0.23",
    "tree-sitter-typescript>=0.23",
    "tree-sitter-go>=0.23",
    "tree-sitter-rust>=0.23",
    "tree-sitter-java>=0.23",
    "tree-sitter-ruby>=0.23",
    "tree-sitter-php>=0.23",
    "tree-sitter-c>=0.23",
    "tree-sitter-cpp>=0.23",
    "tree-sitter-c-sharp>=0.23",
    "pyyaml>=6.0",
    "pydantic>=2.0",
]
```

In `[dependency-groups] dev`, remove `"tree-sitter-languages>=1.10"`:

```toml
[dependency-groups]
dev = [
    "psycopg[binary]>=3.1",
    "pytest>=8.0",
    "pytest-cov>=5.0",
]
```

- [ ] **Step 3: Sync the virtual environment**

Run: `uv sync`
Expected: all 11 grammar packages install successfully, `tree-sitter-languages` is removed.

- [ ] **Step 4: Verify imports work**

Run: `uv run python -c "import tree_sitter_python; from tree_sitter import Language; lang = Language(tree_sitter_python.language()); print(f'Python grammar loaded: {lang}')"`
Expected: prints language object without error.

- [ ] **Step 5: Commit**

```bash
git add pyproject.toml uv.lock
git commit -m "chore: migrate from tree-sitter-languages to individual grammar packages

tree-sitter-languages is abandoned (no maintainer since Feb 2024, no
3.13/3.14 wheels). Switch to official individual grammar packages which
use stable ABI wheels (cp310-abi3). Bump tree-sitter minimum to 0.25."
```

---

## Task 2: Shared tree-sitter module (`treesitter.py`)

**Files:**
- Create: `src/screw_agents/treesitter.py`
- Create: `tests/__init__.py`
- Create: `tests/test_treesitter.py`

**Context:** This module provides language loading, parser creation, and AST queries shared by both the Phase 1 target resolver and the Phase 0.5 benchmark code. It replaces the ctypes hack in `benchmarks/runner/primevul.py`.

- [ ] **Step 1: Create `tests/__init__.py`**

Create an empty `tests/__init__.py`:

```python
```

- [ ] **Step 2: Write failing tests for language loading**

Create `tests/test_treesitter.py`:

```python
"""Tests for the shared tree-sitter module."""

import pytest

from screw_agents.treesitter import get_language, get_parser, SUPPORTED_LANGUAGES


def test_supported_languages_contains_all_eleven():
    expected = {
        "python", "javascript", "typescript", "go", "rust",
        "java", "ruby", "php", "c", "cpp", "c_sharp",
    }
    assert set(SUPPORTED_LANGUAGES) == expected


def test_get_language_python():
    lang = get_language("python")
    assert lang is not None


def test_get_language_all_supported():
    for name in SUPPORTED_LANGUAGES:
        lang = get_language(name)
        assert lang is not None, f"Failed to load language: {name}"


def test_get_language_unsupported_raises():
    with pytest.raises(ValueError, match="Unsupported language"):
        get_language("haskell")


def test_get_language_caching():
    lang1 = get_language("python")
    lang2 = get_language("python")
    assert lang1 is lang2


def test_get_parser_python():
    parser = get_parser("python")
    assert parser is not None


def test_get_parser_parses_python_code():
    parser = get_parser("python")
    tree = parser.parse(b"def foo():\n    pass\n")
    root = tree.root_node
    assert root.type == "module"
    assert root.children[0].type == "function_definition"


def test_get_parser_parses_rust_code():
    parser = get_parser("rust")
    tree = parser.parse(b"fn main() {}\n")
    root = tree.root_node
    assert root.type == "source_file"
    assert root.children[0].type == "function_item"


def test_get_parser_parses_javascript_code():
    parser = get_parser("javascript")
    tree = parser.parse(b"function foo() {}\n")
    root = tree.root_node
    assert root.type == "program"
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `uv run pytest tests/test_treesitter.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'screw_agents.treesitter'`

- [ ] **Step 4: Implement `treesitter.py`**

Create `src/screw_agents/treesitter.py`:

```python
"""Shared tree-sitter language loading, parser creation, and AST queries.

Used by both the MCP server target resolver (Phase 1) and the benchmark
runner's PrimeVul dedup (Phase 0.5). Replaces the ctypes hack in
benchmarks/runner/primevul.py with the official individual grammar
package API (tree-sitter 0.25+).
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from tree_sitter import Language, Parser

# Lazy imports — each grammar package is imported only when needed.
# This dict maps our canonical language names to (module_name, ts_function_name) pairs.
_GRAMMAR_REGISTRY: dict[str, tuple[str, str]] = {
    "python": ("tree_sitter_python", "language"),
    "javascript": ("tree_sitter_javascript", "language"),
    "typescript": ("tree_sitter_typescript", "language_typescript"),
    "go": ("tree_sitter_go", "language"),
    "rust": ("tree_sitter_rust", "language"),
    "java": ("tree_sitter_java", "language"),
    "ruby": ("tree_sitter_ruby", "language"),
    "php": ("tree_sitter_php", "language_php"),
    "c": ("tree_sitter_c", "language"),
    "cpp": ("tree_sitter_cpp", "language"),
    "c_sharp": ("tree_sitter_c_sharp", "language"),
}

SUPPORTED_LANGUAGES: tuple[str, ...] = tuple(_GRAMMAR_REGISTRY.keys())

# File extension → language name mapping.
EXTENSION_MAP: dict[str, str] = {
    ".py": "python",
    ".js": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".go": "go",
    ".rs": "rust",
    ".java": "java",
    ".rb": "ruby",
    ".php": "php",
    ".c": "c",
    ".h": "c",
    ".cpp": "cpp",
    ".cc": "cpp",
    ".cxx": "cpp",
    ".hpp": "cpp",
    ".hh": "cpp",
    ".cs": "c_sharp",
}


def language_from_path(path: str | Path) -> str | None:
    """Detect language from file extension. Returns None if unsupported."""
    suffix = Path(path).suffix.lower()
    return EXTENSION_MAP.get(suffix)


@lru_cache(maxsize=None)
def get_language(name: str) -> Language:
    """Return a tree-sitter Language for the given canonical name.

    Raises ValueError if the language is not supported.
    """
    if name not in _GRAMMAR_REGISTRY:
        raise ValueError(
            f"Unsupported language: {name!r}. "
            f"Supported: {', '.join(SUPPORTED_LANGUAGES)}"
        )
    module_name, func_name = _GRAMMAR_REGISTRY[name]
    import importlib
    mod = importlib.import_module(module_name)
    lang_func = getattr(mod, func_name)
    return Language(lang_func())


@lru_cache(maxsize=None)
def get_parser(name: str) -> Parser:
    """Return a configured tree-sitter Parser for the given language."""
    lang = get_language(name)
    return Parser(lang)
```

**Note on `typescript` and `php`:** The `tree-sitter-typescript` package exports `language_typescript()` (not `language()`), and `tree-sitter-php` exports `language_php()`. These are the actual function names in those packages. If this turns out to be wrong at runtime, adjust the `_GRAMMAR_REGISTRY` entries — the test in Step 2 (`test_get_language_all_supported`) will catch any mismatch.

- [ ] **Step 5: Run tests to verify they pass**

Run: `uv run pytest tests/test_treesitter.py -v`
Expected: all tests PASS.

- [ ] **Step 6: Commit**

```bash
git add src/screw_agents/treesitter.py tests/__init__.py tests/test_treesitter.py
git commit -m "feat: add shared tree-sitter module with 11 language grammars

Provides get_language(), get_parser(), language_from_path(), and
EXTENSION_MAP. Uses official individual grammar packages (no ctypes
hack). Shared by MCP target resolver and benchmark PrimeVul dedup."
```

---

## Task 3: Update Phase 0.5 `primevul.py` to use shared tree-sitter module

**Files:**
- Modify: `benchmarks/runner/primevul.py`

**Context:** Replace the ctypes workaround (`_get_lang_lib`, `_get_language`, `_get_parser`, `_TS_LANG_NAMES`) with imports from the new shared module.

- [ ] **Step 1: Run existing Phase 0.5 tests as baseline**

Run: `uv run pytest benchmarks/tests/test_primevul_dedup.py -v`
Expected: all tests PASS (baseline before refactoring).

- [ ] **Step 2: Read `benchmarks/runner/primevul.py`**

Read the full file, focusing on lines 1-75 (imports, ctypes hack, `_TS_LANG_NAMES`, `_get_lang_lib`, `_get_language`, `_get_parser`).

- [ ] **Step 3: Replace ctypes hack with shared module imports**

In `benchmarks/runner/primevul.py`:

Remove these imports (they're only needed by the ctypes hack):
```python
import ctypes
import os
import warnings
```

Remove the entire block from the comment `# tree-sitter-languages 1.10.x was compiled against...` through the end of the `_get_parser` function. This includes:
- The comment (lines 23-27)
- `_TS_LANG_NAMES` dict
- `_get_lang_lib()` function
- `_get_language()` function
- `_get_parser()` function

Replace with:

```python
from screw_agents.treesitter import get_parser, SUPPORTED_LANGUAGES

# Language name mapping — bridges benchmarks/runner/models.py Language enum
# to the canonical names used by screw_agents.treesitter.
_LANG_TO_TS_NAME: dict[Language, str] = {
    Language.PYTHON: "python",
    Language.JAVASCRIPT: "javascript",
    Language.TYPESCRIPT: "typescript",
    Language.JAVA: "java",
    Language.GO: "go",
    Language.RUBY: "ruby",
    Language.PHP: "php",
    Language.CSHARP: "c_sharp",
    Language.RUST: "rust",
    Language.C: "c",
    Language.CPP: "cpp",
}
```

Then update all call sites in the file that call `_get_parser(language)` — they should still work because `_get_parser` took a `Language` enum and internally did the name lookup. Now the call sites need to do: `get_parser(_LANG_TO_TS_NAME[language])`.

Search for `_get_parser(` in the file and replace each occurrence. The typical pattern will be:

```python
# Before:
parser = _get_parser(language)

# After:
ts_name = _LANG_TO_TS_NAME.get(language)
if ts_name is None:
    return source  # unsupported language, return as-is
parser = get_parser(ts_name)
```

Also keep any `os` import that's used elsewhere in the file (not just by the ctypes hack). Check carefully.

- [ ] **Step 4: Run Phase 0.5 tests to verify no regressions**

Run: `uv run pytest benchmarks/tests/test_primevul_dedup.py -v`
Expected: all tests PASS — identical behavior to baseline.

- [ ] **Step 5: Run the full benchmark test suite**

Run: `uv run pytest benchmarks/tests/ -v`
Expected: all 81 tests PASS.

- [ ] **Step 6: Commit**

```bash
git add benchmarks/runner/primevul.py
git commit -m "refactor: replace tree-sitter ctypes hack with shared module

primevul.py now imports from screw_agents.treesitter instead of using
ctypes to load languages.so directly. The ctypes workaround was needed
for the tree-sitter-languages 0.20→0.23 API mismatch; individual
grammar packages use the clean 0.25 API natively."
```

---

## Task 4: Pydantic models — YAML agent schema (`models.py`)

**Files:**
- Create: `src/screw_agents/models.py`
- Create: `tests/conftest.py`
- Create: `tests/test_models.py`

**Context:** These models validate the agent YAML definitions (PRD §4). The actual YAMLs in `domains/` have some field variations (e.g., `sans_top25` vs `cwe_top25`, flexible `bypass_techniques` entries with varying extra fields). Models must be strict on required fields but flexible on optional/extra metadata.

- [ ] **Step 1: Write failing tests for YAML schema models**

Create `tests/conftest.py`:

```python
"""Shared fixtures for Phase 1 tests."""

from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
DOMAINS_DIR = REPO_ROOT / "domains"
FIXTURES_DIR = REPO_ROOT / "benchmarks" / "fixtures"


@pytest.fixture
def domains_dir():
    return DOMAINS_DIR


@pytest.fixture
def sqli_yaml_path():
    return DOMAINS_DIR / "injection-input-handling" / "sqli.yaml"


@pytest.fixture
def fixtures_dir():
    return FIXTURES_DIR
```

Create `tests/test_models.py`:

```python
"""Tests for Pydantic models — YAML agent schema."""

import yaml
import pytest

from screw_agents.models import AgentDefinition, AgentMeta, CWEs


def test_cwes_model():
    cwes = CWEs(primary="CWE-89", related=["CWE-564", "CWE-566"])
    assert cwes.primary == "CWE-89"
    assert len(cwes.related) == 2


def test_cwes_requires_primary():
    with pytest.raises(Exception):
        CWEs(related=["CWE-564"])


def test_agent_meta_minimal():
    meta = AgentMeta(
        name="test",
        display_name="Test Agent",
        domain="test-domain",
        version="1.0.0",
        last_updated="2026-04-10",
        cwes=CWEs(primary="CWE-89"),
        capec=["CAPEC-66"],
        owasp={"top10": "A05:2025"},
        sources=[],
    )
    assert meta.name == "test"


def test_agent_definition_from_real_yaml(sqli_yaml_path):
    with open(sqli_yaml_path) as f:
        data = yaml.safe_load(f)
    agent = AgentDefinition.model_validate(data)
    assert agent.meta.name == "sqli"
    assert agent.meta.cwes.primary == "CWE-89"
    assert agent.core_prompt is not None
    assert len(agent.core_prompt) > 100
    assert agent.detection_heuristics.high_confidence is not None
    assert len(agent.detection_heuristics.high_confidence) > 0
    assert len(agent.bypass_techniques) > 0
    assert agent.target_strategy.scope == "function"


def test_all_phase1_yamls_validate(domains_dir):
    yaml_dir = domains_dir / "injection-input-handling"
    for yaml_path in yaml_dir.glob("*.yaml"):
        with open(yaml_path) as f:
            data = yaml.safe_load(f)
        agent = AgentDefinition.model_validate(data)
        assert agent.meta.name in ("sqli", "cmdi", "ssti", "xss")
        assert agent.meta.domain == "injection-input-handling"


def test_agent_definition_missing_core_prompt_fails():
    data = {
        "meta": {
            "name": "bad",
            "display_name": "Bad",
            "domain": "test",
            "version": "1.0.0",
            "last_updated": "2026-01-01",
            "cwes": {"primary": "CWE-89"},
            "capec": [],
            "owasp": {"top10": "A05:2025"},
            "sources": [],
        },
        "detection_heuristics": {"high_confidence": ["pattern"]},
        "bypass_techniques": [],
        "remediation": {"preferred": "fix it"},
        "few_shot_examples": {"vulnerable": [], "safe": []},
        "target_strategy": {"scope": "function", "file_patterns": ["**/*.py"]},
    }
    with pytest.raises(Exception):
        AgentDefinition.model_validate(data)


def test_agent_definition_missing_detection_heuristics_fails():
    data = {
        "meta": {
            "name": "bad",
            "display_name": "Bad",
            "domain": "test",
            "version": "1.0.0",
            "last_updated": "2026-01-01",
            "cwes": {"primary": "CWE-89"},
            "capec": [],
            "owasp": {"top10": "A05:2025"},
            "sources": [],
        },
        "core_prompt": "You are a test agent.",
        "bypass_techniques": [],
        "remediation": {"preferred": "fix it"},
        "few_shot_examples": {"vulnerable": [], "safe": []},
        "target_strategy": {"scope": "function", "file_patterns": ["**/*.py"]},
    }
    with pytest.raises(Exception):
        AgentDefinition.model_validate(data)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_models.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'screw_agents.models'`

- [ ] **Step 3: Implement YAML schema models**

Create `src/screw_agents/models.py`:

```python
"""Pydantic models for agent YAML definitions and scan findings.

YAML schema follows PRD §4. The actual agent YAMLs have some field
variations (e.g., sans_top25 vs cwe_top25, flexible bypass_techniques
entries). Models are strict on required fields, flexible on optional
metadata.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict


# ---------------------------------------------------------------------------
# YAML Agent Definition Schema (PRD §4)
# ---------------------------------------------------------------------------


class CWEs(BaseModel):
    primary: str
    related: list[str] = []


class OWASPMapping(BaseModel):
    model_config = ConfigDict(extra="allow")

    top10: str
    asvs: list[str] = []
    testing_guide: str = ""


class Source(BaseModel):
    model_config = ConfigDict(extra="allow")

    url: str
    last_checked: str
    note: str = ""


class AgentMeta(BaseModel):
    """Agent metadata block — required fields plus flexible extras."""

    model_config = ConfigDict(extra="allow")

    name: str
    display_name: str
    domain: str
    version: str
    last_updated: str
    cwes: CWEs
    capec: list[str] = []
    owasp: OWASPMapping
    sources: list[Source] = []
    # Optional — some agents use sans_top25, others cwe_top25
    sans_top25: dict[str, Any] | None = None
    cwe_top25: dict[str, Any] | None = None


class DetectionHeuristics(BaseModel):
    model_config = ConfigDict(extra="allow")

    high_confidence: list[str] = []
    medium_confidence: list[str] = []
    context_required: list[str] = []


class BypassTechnique(BaseModel):
    """A single bypass technique. Has required name/description + flexible extras."""

    model_config = ConfigDict(extra="allow")

    name: str
    description: str
    detection_hint: str = ""


class CommonMistake(BaseModel):
    mistake: str
    why_insufficient: str = ""


class Remediation(BaseModel):
    model_config = ConfigDict(extra="allow")

    preferred: str
    common_mistakes: list[CommonMistake] = []


class CodeExample(BaseModel):
    model_config = ConfigDict(extra="allow")

    language: str
    code: str
    explanation: str = ""
    label: str = ""


class FewShotExamples(BaseModel):
    vulnerable: list[CodeExample] = []
    safe: list[CodeExample] = []


class TargetStrategy(BaseModel):
    model_config = ConfigDict(extra="allow")

    scope: str = "function"
    include_imports: bool = True
    include_type_defs: bool = True
    file_patterns: list[str] = []
    relevance_signals: list[str] = []
    adaptive_depth: dict[str, str] | None = None


class AgentDefinition(BaseModel):
    """Complete agent YAML definition — validated at registry load time."""

    meta: AgentMeta
    core_prompt: str
    detection_heuristics: DetectionHeuristics
    bypass_techniques: list[BypassTechnique] = []
    remediation: Remediation
    few_shot_examples: FewShotExamples = FewShotExamples()
    target_strategy: TargetStrategy = TargetStrategy()
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_models.py -v`
Expected: all tests PASS.

- [ ] **Step 5: Commit**

```bash
git add src/screw_agents/models.py tests/conftest.py tests/test_models.py
git commit -m "feat: add Pydantic models for agent YAML schema validation

Models mirror PRD §4 with flexibility for field variations across
agent YAMLs (sans_top25 vs cwe_top25, extra bypass_techniques fields).
All 4 Phase 1 YAMLs validate successfully."
```

---

## Task 5: Pydantic models — finding output schema (`models.py`)

**Files:**
- Modify: `src/screw_agents/models.py`
- Modify: `tests/test_models.py`

**Context:** Finding output models follow PRD §8, with the addition of `data_flow` (source→sink tracing for injection agents). These models are used by the formatter.

- [ ] **Step 1: Write failing tests for finding models**

Append to `tests/test_models.py`:

```python
from screw_agents.models import (
    Finding, FindingLocation, DataFlow, FindingClassification,
    FindingAnalysis, FindingRemediation, FindingTriage,
)


def test_finding_location_minimal():
    loc = FindingLocation(
        file="src/api/users.py",
        line_start=42,
    )
    assert loc.file == "src/api/users.py"
    assert loc.data_flow is None


def test_finding_location_with_data_flow():
    loc = FindingLocation(
        file="src/api/users.py",
        line_start=42,
        line_end=48,
        function="get_user",
        data_flow=DataFlow(
            source="request.getParameter('username')",
            source_location="UserController.java:42",
            sink="stmt.executeQuery(query)",
            sink_location="UserController.java:48",
        ),
    )
    assert loc.data_flow.source == "request.getParameter('username')"


def test_finding_complete():
    finding = Finding(
        id="sqli-001-abc123",
        agent="sqli",
        domain="injection-input-handling",
        timestamp="2026-04-10T14:30:00Z",
        location=FindingLocation(file="test.py", line_start=10),
        classification=FindingClassification(
            cwe="CWE-89",
            cwe_name="SQL Injection",
            severity="high",
            confidence="high",
        ),
        analysis=FindingAnalysis(
            description="SQL injection via f-string",
            impact="Data exfiltration",
            exploitability="Trivially exploitable",
        ),
        remediation=FindingRemediation(
            recommendation="Use parameterized queries",
        ),
    )
    assert finding.id == "sqli-001-abc123"
    assert finding.triage.status == "pending"


def test_finding_requires_location():
    with pytest.raises(Exception):
        Finding(
            id="test",
            agent="sqli",
            domain="test",
            timestamp="2026-01-01T00:00:00Z",
            classification=FindingClassification(
                cwe="CWE-89", cwe_name="SQLi",
                severity="high", confidence="high",
            ),
            analysis=FindingAnalysis(description="test"),
            remediation=FindingRemediation(recommendation="fix"),
        )
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_models.py::test_finding_location_minimal -v`
Expected: FAIL — `ImportError: cannot import name 'Finding'`

- [ ] **Step 3: Add finding models to `models.py`**

Append to `src/screw_agents/models.py`:

```python
# ---------------------------------------------------------------------------
# Finding Output Schema (PRD §8 + data_flow extension)
# ---------------------------------------------------------------------------


class DataFlow(BaseModel):
    """Source-to-sink data flow tracing for injection findings."""

    source: str
    source_location: str = ""
    sink: str
    sink_location: str = ""


class FindingLocation(BaseModel):
    file: str
    line_start: int
    line_end: int | None = None
    function: str | None = None
    class_name: str | None = None
    code_snippet: str | None = None
    data_flow: DataFlow | None = None


class FindingClassification(BaseModel):
    cwe: str
    cwe_name: str
    capec: str | None = None
    owasp_top10: str | None = None
    severity: str  # critical, high, medium, low
    confidence: str  # high, medium, low


class FindingAnalysis(BaseModel):
    description: str
    impact: str = ""
    exploitability: str = ""
    false_positive_reasoning: str | None = None


class FindingRemediation(BaseModel):
    recommendation: str
    fix_code: str | None = None
    references: list[str] = []


class FindingTriage(BaseModel):
    status: str = "pending"
    triaged_by: str | None = None
    triaged_at: str | None = None
    notes: str | None = None


class Finding(BaseModel):
    """A single scan finding — the core output unit."""

    id: str
    agent: str
    domain: str
    timestamp: str
    location: FindingLocation
    classification: FindingClassification
    analysis: FindingAnalysis
    remediation: FindingRemediation
    triage: FindingTriage = FindingTriage()
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_models.py -v`
Expected: all tests PASS.

- [ ] **Step 5: Commit**

```bash
git add src/screw_agents/models.py tests/test_models.py
git commit -m "feat: add Pydantic models for scan finding output schema

Follows PRD §8 with data_flow extension (source/sink tracing for
injection agents). Models enforce required fields while allowing
optional enrichment (CAPEC, OWASP mapping, data flow, fix code)."
```

---

## Task 6: Agent registry (`registry.py`)

**Files:**
- Create: `src/screw_agents/registry.py`
- Create: `tests/test_registry.py`

**Context:** The registry loads agent YAML files from `domains/`, validates them with the Pydantic models from Task 4, and provides lookup by name and domain. It does NOT register MCP tools itself — that happens in `server.py` (Task 16) which reads the registry.

- [ ] **Step 1: Write failing tests**

Create `tests/test_registry.py`:

```python
"""Tests for the agent registry."""

import pytest

from screw_agents.registry import AgentRegistry


def test_registry_loads_from_domains_dir(domains_dir):
    registry = AgentRegistry(domains_dir)
    assert len(registry.agents) >= 4


def test_registry_agents_by_name(domains_dir):
    registry = AgentRegistry(domains_dir)
    sqli = registry.get_agent("sqli")
    assert sqli is not None
    assert sqli.meta.name == "sqli"
    assert sqli.meta.cwes.primary == "CWE-89"


def test_registry_agents_by_domain(domains_dir):
    registry = AgentRegistry(domains_dir)
    agents = registry.get_agents_by_domain("injection-input-handling")
    names = {a.meta.name for a in agents}
    assert names == {"sqli", "cmdi", "ssti", "xss"}


def test_registry_list_domains(domains_dir):
    registry = AgentRegistry(domains_dir)
    domains = registry.list_domains()
    assert "injection-input-handling" in domains
    assert domains["injection-input-handling"] >= 4


def test_registry_list_agents(domains_dir):
    registry = AgentRegistry(domains_dir)
    agents = registry.list_agents()
    assert len(agents) >= 4
    names = {a["name"] for a in agents}
    assert {"sqli", "cmdi", "ssti", "xss"} <= names


def test_registry_get_nonexistent_agent(domains_dir):
    registry = AgentRegistry(domains_dir)
    assert registry.get_agent("nonexistent") is None


def test_registry_empty_dir(tmp_path):
    registry = AgentRegistry(tmp_path)
    assert len(registry.agents) == 0


def test_registry_malformed_yaml_raises(tmp_path):
    bad_dir = tmp_path / "bad-domain"
    bad_dir.mkdir()
    (bad_dir / "broken.yaml").write_text("meta:\n  name: broken\n")
    with pytest.raises(Exception):
        AgentRegistry(tmp_path)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_registry.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'screw_agents.registry'`

- [ ] **Step 3: Implement `registry.py`**

Create `src/screw_agents/registry.py`:

```python
"""Agent registry — loads and validates YAML agent definitions.

Scans a domains directory for *.yaml files, validates each against the
AgentDefinition Pydantic model, and provides lookup by name and domain.
"""

from __future__ import annotations

import logging
from pathlib import Path

import yaml

from screw_agents.models import AgentDefinition

logger = logging.getLogger(__name__)


class AgentRegistry:
    """Registry of validated agent definitions loaded from YAML files."""

    def __init__(self, domains_dir: Path) -> None:
        self._agents: dict[str, AgentDefinition] = {}
        self._domains: dict[str, list[str]] = {}
        self._load(domains_dir)

    def _load(self, domains_dir: Path) -> None:
        """Recursively load and validate all YAML files under domains_dir."""
        if not domains_dir.is_dir():
            logger.warning("Domains directory does not exist: %s", domains_dir)
            return

        for yaml_path in sorted(domains_dir.rglob("*.yaml")):
            logger.debug("Loading agent definition: %s", yaml_path)
            with open(yaml_path) as f:
                raw = yaml.safe_load(f)

            if raw is None:
                continue

            agent = AgentDefinition.model_validate(raw)
            name = agent.meta.name

            if name in self._agents:
                raise ValueError(
                    f"Duplicate agent name {name!r}: "
                    f"already loaded, conflict with {yaml_path}"
                )

            self._agents[name] = agent

            domain = agent.meta.domain
            if domain not in self._domains:
                self._domains[domain] = []
            self._domains[domain].append(name)

        logger.info(
            "Loaded %d agents across %d domains",
            len(self._agents),
            len(self._domains),
        )

    @property
    def agents(self) -> dict[str, AgentDefinition]:
        return self._agents

    def get_agent(self, name: str) -> AgentDefinition | None:
        return self._agents.get(name)

    def get_agents_by_domain(self, domain: str) -> list[AgentDefinition]:
        names = self._domains.get(domain, [])
        return [self._agents[n] for n in names]

    def list_domains(self) -> dict[str, int]:
        """Return domain names with agent counts."""
        return {domain: len(names) for domain, names in self._domains.items()}

    def list_agents(self, domain: str | None = None) -> list[dict]:
        """Return agent metadata summaries, optionally filtered by domain."""
        agents = (
            self.get_agents_by_domain(domain)
            if domain
            else list(self._agents.values())
        )
        return [
            {
                "name": a.meta.name,
                "display_name": a.meta.display_name,
                "domain": a.meta.domain,
                "cwe_primary": a.meta.cwes.primary,
                "cwe_related": a.meta.cwes.related,
            }
            for a in agents
        ]
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_registry.py -v`
Expected: all tests PASS.

- [ ] **Step 5: Commit**

```bash
git add src/screw_agents/registry.py tests/test_registry.py
git commit -m "feat: add agent registry with YAML loading and validation

Recursively loads domains/*.yaml, validates against Pydantic models,
provides lookup by name/domain. Fails loudly on malformed YAML or
duplicate agent names."
```

---

## Task 7: Target resolver — file, glob, lines targets (`resolver.py`)

**Files:**
- Create: `src/screw_agents/resolver.py`
- Create: `tests/test_resolver.py`

**Context:** The resolver takes a target spec dict (PRD §5) and returns resolved code content. This task implements the three simplest target types. Later tasks add tree-sitter, git, and filtering.

- [ ] **Step 1: Write failing tests**

Create `tests/test_resolver.py`:

```python
"""Tests for the target resolver."""

import pytest

from screw_agents.resolver import resolve_target, ResolvedCode


def test_resolve_file_target(fixtures_dir):
    target = {"type": "file", "path": str(fixtures_dir / "sqli" / "vulnerable" / "python_fstring.py")}
    result = resolve_target(target)
    assert isinstance(result, list)
    assert len(result) == 1
    assert isinstance(result[0], ResolvedCode)
    assert "SELECT" in result[0].content or "select" in result[0].content.lower()
    assert result[0].file_path.endswith(".py")


def test_resolve_file_target_nonexistent():
    target = {"type": "file", "path": "/nonexistent/file.py"}
    with pytest.raises(FileNotFoundError):
        resolve_target(target)


def test_resolve_glob_target(fixtures_dir):
    target = {
        "type": "glob",
        "pattern": str(fixtures_dir / "sqli" / "vulnerable" / "*.py"),
    }
    result = resolve_target(target)
    assert len(result) >= 1
    assert all(r.file_path.endswith(".py") for r in result)


def test_resolve_glob_with_exclude(fixtures_dir):
    target = {
        "type": "glob",
        "pattern": str(fixtures_dir / "sqli" / "**" / "*.py"),
        "exclude": ["**/safe/**"],
    }
    result = resolve_target(target)
    assert all("safe" not in r.file_path for r in result)


def test_resolve_lines_single_line(tmp_path):
    f = tmp_path / "test.py"
    f.write_text("line1\nline2\nline3\nline4\nline5\n")
    target = {"type": "lines", "file": str(f), "range": 3}
    result = resolve_target(target)
    assert len(result) == 1
    assert result[0].content.strip() == "line3"


def test_resolve_lines_range(tmp_path):
    f = tmp_path / "test.py"
    f.write_text("line1\nline2\nline3\nline4\nline5\n")
    target = {"type": "lines", "file": str(f), "range": [2, 4]}
    result = resolve_target(target)
    assert len(result) == 1
    assert "line2" in result[0].content
    assert "line4" in result[0].content


def test_resolve_unsupported_type():
    target = {"type": "unknown_type"}
    with pytest.raises(ValueError, match="Unsupported target type"):
        resolve_target(target)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_resolver.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'screw_agents.resolver'`

- [ ] **Step 3: Implement `resolver.py` with file, glob, lines**

Create `src/screw_agents/resolver.py`:

```python
"""Target resolver — resolves target specs to code content.

Supports all target types from PRD §5: file, glob, lines, function,
class, codebase, git_diff, git_commits, pull_request.
"""

from __future__ import annotations

import glob as globlib
import subprocess
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class ResolvedCode:
    """A resolved chunk of code from a target."""

    file_path: str
    content: str
    language: str | None = None
    line_start: int | None = None
    line_end: int | None = None
    metadata: dict = field(default_factory=dict)


def resolve_target(target: dict) -> list[ResolvedCode]:
    """Resolve a target spec dict to code content.

    Args:
        target: A target specification dict following PRD §5.

    Returns:
        List of ResolvedCode chunks.

    Raises:
        ValueError: If the target type is unsupported.
        FileNotFoundError: If a specified file does not exist.
    """
    target_type = target.get("type")
    if target_type == "file":
        return _resolve_file(target)
    elif target_type == "glob":
        return _resolve_glob(target)
    elif target_type == "lines":
        return _resolve_lines(target)
    elif target_type == "function":
        return _resolve_function(target)
    elif target_type == "class":
        return _resolve_class(target)
    elif target_type == "codebase":
        return _resolve_codebase(target)
    elif target_type == "git_diff":
        return _resolve_git_diff(target)
    elif target_type == "git_commits":
        return _resolve_git_commits(target)
    elif target_type == "pull_request":
        return _resolve_pull_request(target)
    else:
        raise ValueError(f"Unsupported target type: {target_type!r}")


def _read_file(path: str) -> str:
    """Read a file, raising FileNotFoundError if missing."""
    p = Path(path)
    if not p.is_file():
        raise FileNotFoundError(f"File not found: {path}")
    return p.read_text(encoding="utf-8", errors="replace")


def _detect_language(path: str) -> str | None:
    """Detect language from file extension."""
    from screw_agents.treesitter import language_from_path
    return language_from_path(path)


def _resolve_file(target: dict) -> list[ResolvedCode]:
    path = target["path"]
    content = _read_file(path)
    return [ResolvedCode(
        file_path=path,
        content=content,
        language=_detect_language(path),
    )]


def _resolve_glob(target: dict) -> list[ResolvedCode]:
    pattern = target["pattern"]
    exclude = target.get("exclude", [])

    matches = sorted(globlib.glob(pattern, recursive=True))

    if exclude:
        filtered = []
        for m in matches:
            if Path(m).is_file() and not any(
                globlib.fnmatch.fnmatch(m, ex) for ex in exclude
            ):
                filtered.append(m)
        matches = filtered
    else:
        matches = [m for m in matches if Path(m).is_file()]

    results = []
    for path in matches:
        content = Path(path).read_text(encoding="utf-8", errors="replace")
        results.append(ResolvedCode(
            file_path=path,
            content=content,
            language=_detect_language(path),
        ))
    return results


def _resolve_lines(target: dict) -> list[ResolvedCode]:
    path = target["file"]
    line_spec = target["range"]
    content = _read_file(path)
    lines = content.splitlines(keepends=True)

    if isinstance(line_spec, int):
        # Single line (1-indexed)
        idx = line_spec - 1
        if 0 <= idx < len(lines):
            selected = lines[idx]
        else:
            selected = ""
        start = end = line_spec
    else:
        # Range [start, end] (1-indexed, inclusive)
        start, end = line_spec
        selected = "".join(lines[start - 1 : end])

    return [ResolvedCode(
        file_path=path,
        content=selected,
        language=_detect_language(path),
        line_start=start,
        line_end=end,
    )]


# Stub implementations — filled in by later tasks.

def _resolve_function(target: dict) -> list[ResolvedCode]:
    raise NotImplementedError("function target — implemented in Task 8")


def _resolve_class(target: dict) -> list[ResolvedCode]:
    raise NotImplementedError("class target — implemented in Task 8")


def _resolve_codebase(target: dict) -> list[ResolvedCode]:
    raise NotImplementedError("codebase target — implemented in Task 10")


def _resolve_git_diff(target: dict) -> list[ResolvedCode]:
    raise NotImplementedError("git_diff target — implemented in Task 9")


def _resolve_git_commits(target: dict) -> list[ResolvedCode]:
    raise NotImplementedError("git_commits target — implemented in Task 10")


def _resolve_pull_request(target: dict) -> list[ResolvedCode]:
    raise NotImplementedError("pull_request target — implemented in Task 10")
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_resolver.py -v`
Expected: all tests PASS.

- [ ] **Step 5: Commit**

```bash
git add src/screw_agents/resolver.py tests/test_resolver.py
git commit -m "feat: add target resolver with file, glob, lines support

Implements the three simplest target types from PRD §5. Stubs for
function, class, git_diff, codebase, git_commits, pull_request to
be filled in subsequent tasks."
```

---

## Task 8: Target resolver — tree-sitter function/class extraction

**Files:**
- Modify: `src/screw_agents/resolver.py`
- Modify: `tests/test_resolver.py`

**Context:** The `function` and `class` target types use tree-sitter to extract named code elements from a file.

- [ ] **Step 1: Write failing tests**

Append to `tests/test_resolver.py`:

```python
def test_resolve_function_target(tmp_path):
    f = tmp_path / "example.py"
    f.write_text(
        "import os\n\n"
        "def foo():\n"
        "    return 1\n\n"
        "def bar():\n"
        "    return 2\n"
    )
    target = {"type": "function", "file": str(f), "name": "foo"}
    result = resolve_target(target)
    assert len(result) == 1
    assert "def foo" in result[0].content
    assert "def bar" not in result[0].content


def test_resolve_function_not_found(tmp_path):
    f = tmp_path / "example.py"
    f.write_text("def foo():\n    pass\n")
    target = {"type": "function", "file": str(f), "name": "nonexistent"}
    with pytest.raises(ValueError, match="not found"):
        resolve_target(target)


def test_resolve_class_target(tmp_path):
    f = tmp_path / "example.py"
    f.write_text(
        "class Foo:\n"
        "    def method(self):\n"
        "        pass\n\n"
        "class Bar:\n"
        "    pass\n"
    )
    target = {"type": "class", "file": str(f), "name": "Foo"}
    result = resolve_target(target)
    assert len(result) == 1
    assert "class Foo" in result[0].content
    assert "class Bar" not in result[0].content


def test_resolve_function_javascript(tmp_path):
    f = tmp_path / "example.js"
    f.write_text(
        "function greet(name) {\n"
        "  return 'Hello ' + name;\n"
        "}\n\n"
        "function farewell() {\n"
        "  return 'Bye';\n"
        "}\n"
    )
    target = {"type": "function", "file": str(f), "name": "greet"}
    result = resolve_target(target)
    assert len(result) == 1
    assert "greet" in result[0].content
    assert "farewell" not in result[0].content
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_resolver.py::test_resolve_function_target -v`
Expected: FAIL — `NotImplementedError: function target — implemented in Task 8`

- [ ] **Step 3: Implement function and class extraction**

In `src/screw_agents/resolver.py`, replace the `_resolve_function` and `_resolve_class` stubs:

```python
def _resolve_function(target: dict) -> list[ResolvedCode]:
    path = target["file"]
    name = target["name"]
    content = _read_file(path)
    lang = _detect_language(path)

    if lang is None:
        raise ValueError(f"Cannot detect language for {path}")

    node = _find_named_node(content, lang, name, node_types=_FUNCTION_NODE_TYPES)
    if node is None:
        raise ValueError(f"Function {name!r} not found in {path}")

    extracted = content.encode("utf-8")[node.start_byte:node.end_byte].decode("utf-8")
    return [ResolvedCode(
        file_path=path,
        content=extracted,
        language=lang,
        line_start=node.start_point[0] + 1,
        line_end=node.end_point[0] + 1,
    )]


def _resolve_class(target: dict) -> list[ResolvedCode]:
    path = target["file"]
    name = target["name"]
    content = _read_file(path)
    lang = _detect_language(path)

    if lang is None:
        raise ValueError(f"Cannot detect language for {path}")

    node = _find_named_node(content, lang, name, node_types=_CLASS_NODE_TYPES)
    if node is None:
        raise ValueError(f"Class {name!r} not found in {path}")

    extracted = content.encode("utf-8")[node.start_byte:node.end_byte].decode("utf-8")
    return [ResolvedCode(
        file_path=path,
        content=extracted,
        language=lang,
        line_start=node.start_point[0] + 1,
        line_end=node.end_point[0] + 1,
    )]
```

Also add these helpers near the top of the file (after imports):

```python
from screw_agents.treesitter import get_parser

# tree-sitter node types for function/method definitions across languages.
_FUNCTION_NODE_TYPES = {
    "function_definition",      # Python
    "function_declaration",     # JS, Go, C, C++
    "method_definition",        # JS class methods, Ruby
    "method_declaration",       # Java, C#
    "function_item",            # Rust
    "function",                 # PHP
}

_CLASS_NODE_TYPES = {
    "class_definition",         # Python
    "class_declaration",        # JS, Java, C#, C++
    "class",                    # PHP, Ruby
    "struct_item",              # Rust (closest equivalent)
    "impl_item",                # Rust impl blocks
}


def _find_named_node(content: str, language: str, name: str, node_types: set[str]):
    """Walk the AST to find a node of the given types with the given name."""
    parser = get_parser(language)
    tree = parser.parse(content.encode("utf-8"))

    def walk(node):
        if node.type in node_types:
            name_node = node.child_by_field_name("name")
            if name_node and name_node.text.decode("utf-8") == name:
                return node
        for child in node.children:
            result = walk(child)
            if result is not None:
                return result
        return None

    return walk(tree.root_node)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_resolver.py -v -k "function or class"` 
Expected: all function/class tests PASS.

- [ ] **Step 5: Commit**

```bash
git add src/screw_agents/resolver.py tests/test_resolver.py
git commit -m "feat: add tree-sitter function/class extraction to resolver

Uses AST walking to find named functions and classes across all
supported languages. Extracts the full node text with line numbers."
```

---

## Task 9: Target resolver — git diff parsing

**Files:**
- Modify: `src/screw_agents/resolver.py`
- Modify: `tests/test_resolver.py`

**Context:** `git_diff` is the most common real-world target type (PRD §5). The resolver runs `git diff`, parses the unified diff output, and returns affected file chunks with surrounding context.

- [ ] **Step 1: Write failing tests**

Append to `tests/test_resolver.py`:

```python
import subprocess


def test_resolve_git_diff_unstaged(tmp_path):
    """Test git_diff with uncommitted changes in a temp git repo."""
    # Set up a temp git repo
    subprocess.run(["git", "init"], cwd=tmp_path, capture_output=True, check=True)
    subprocess.run(
        ["git", "config", "user.email", "test@test.com"],
        cwd=tmp_path, capture_output=True, check=True,
    )
    subprocess.run(
        ["git", "config", "user.name", "Test"],
        cwd=tmp_path, capture_output=True, check=True,
    )

    # Create initial commit
    f = tmp_path / "app.py"
    f.write_text("def safe():\n    return 1\n")
    subprocess.run(["git", "add", "."], cwd=tmp_path, capture_output=True, check=True)
    subprocess.run(
        ["git", "commit", "-m", "init"],
        cwd=tmp_path, capture_output=True, check=True,
    )

    # Make a change
    f.write_text("def safe():\n    return 1\n\ndef vuln():\n    query = f'SELECT {x}'\n")

    target = {"type": "git_diff", "cwd": str(tmp_path)}
    result = resolve_target(target)
    assert len(result) >= 1
    assert any("vuln" in r.content for r in result)


def test_resolve_git_diff_staged(tmp_path):
    """Test git_diff with staged_only=true."""
    subprocess.run(["git", "init"], cwd=tmp_path, capture_output=True, check=True)
    subprocess.run(
        ["git", "config", "user.email", "test@test.com"],
        cwd=tmp_path, capture_output=True, check=True,
    )
    subprocess.run(
        ["git", "config", "user.name", "Test"],
        cwd=tmp_path, capture_output=True, check=True,
    )

    f = tmp_path / "app.py"
    f.write_text("x = 1\n")
    subprocess.run(["git", "add", "."], cwd=tmp_path, capture_output=True, check=True)
    subprocess.run(
        ["git", "commit", "-m", "init"],
        cwd=tmp_path, capture_output=True, check=True,
    )

    # Stage a change
    f.write_text("x = 1\ny = 2\n")
    subprocess.run(["git", "add", "."], cwd=tmp_path, capture_output=True, check=True)

    # Also make an unstaged change
    f.write_text("x = 1\ny = 2\nz = 3\n")

    target = {"type": "git_diff", "staged_only": True, "cwd": str(tmp_path)}
    result = resolve_target(target)
    assert len(result) >= 1
    # Should see y=2 (staged) but context may include z=3
    assert any("y = 2" in r.content for r in result)


def test_resolve_git_diff_base_head(tmp_path):
    """Test git_diff with base..head comparison."""
    subprocess.run(["git", "init"], cwd=tmp_path, capture_output=True, check=True)
    subprocess.run(
        ["git", "config", "user.email", "test@test.com"],
        cwd=tmp_path, capture_output=True, check=True,
    )
    subprocess.run(
        ["git", "config", "user.name", "Test"],
        cwd=tmp_path, capture_output=True, check=True,
    )

    f = tmp_path / "app.py"
    f.write_text("original\n")
    subprocess.run(["git", "add", "."], cwd=tmp_path, capture_output=True, check=True)
    subprocess.run(
        ["git", "commit", "-m", "init"],
        cwd=tmp_path, capture_output=True, check=True,
    )

    # Get the initial commit hash for base
    result_hash = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=tmp_path, capture_output=True, text=True, check=True,
    )
    base = result_hash.stdout.strip()

    # Make a change and commit
    f.write_text("modified\n")
    subprocess.run(["git", "add", "."], cwd=tmp_path, capture_output=True, check=True)
    subprocess.run(
        ["git", "commit", "-m", "change"],
        cwd=tmp_path, capture_output=True, check=True,
    )

    target = {"type": "git_diff", "base": base, "head": "HEAD", "cwd": str(tmp_path)}
    result = resolve_target(target)
    assert len(result) >= 1
    assert any("modified" in r.content for r in result)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_resolver.py::test_resolve_git_diff_unstaged -v`
Expected: FAIL — `NotImplementedError: git_diff target`

- [ ] **Step 3: Implement git_diff resolution**

In `src/screw_agents/resolver.py`, replace the `_resolve_git_diff` stub:

```python
def _resolve_git_diff(target: dict) -> list[ResolvedCode]:
    cwd = target.get("cwd", ".")
    context_lines = target.get("context_lines", 10)

    if "base" in target and "head" in target:
        # Compare two refs
        cmd = [
            "git", "diff",
            f"-U{context_lines}",
            f"{target['base']}...{target['head']}",
        ]
    elif target.get("staged_only"):
        cmd = ["git", "diff", "--staged", f"-U{context_lines}"]
    else:
        cmd = ["git", "diff", f"-U{context_lines}"]

    result = subprocess.run(
        cmd, cwd=cwd, capture_output=True, text=True, check=True,
    )

    if not result.stdout.strip():
        return []

    return _parse_unified_diff(result.stdout, cwd)


def _parse_unified_diff(diff_text: str, cwd: str) -> list[ResolvedCode]:
    """Parse unified diff output into ResolvedCode chunks per file."""
    results = []
    current_file = None
    current_lines: list[str] = []

    for line in diff_text.splitlines(keepends=True):
        if line.startswith("diff --git"):
            # Flush previous file
            if current_file and current_lines:
                results.append(ResolvedCode(
                    file_path=current_file,
                    content="".join(current_lines),
                    language=_detect_language(current_file),
                    metadata={"source": "git_diff"},
                ))
            current_lines = []
            current_file = None
        elif line.startswith("+++ b/"):
            current_file = str(Path(cwd) / line[6:].strip())
        elif line.startswith("--- "):
            continue  # skip old file header
        elif current_file is not None:
            # Include hunk headers and content lines
            current_lines.append(line)

    # Flush last file
    if current_file and current_lines:
        results.append(ResolvedCode(
            file_path=current_file,
            content="".join(current_lines),
            language=_detect_language(current_file),
            metadata={"source": "git_diff"},
        ))

    return results
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_resolver.py -v -k "git_diff"`
Expected: all git_diff tests PASS.

- [ ] **Step 5: Commit**

```bash
git add src/screw_agents/resolver.py tests/test_resolver.py
git commit -m "feat: add git diff parsing to target resolver

Supports unstaged changes, staged-only, and base..head comparisons.
Parses unified diff output into per-file ResolvedCode chunks with
configurable context lines."
```

---

## Task 10: Target resolver — codebase, git_commits, pull_request targets

**Files:**
- Modify: `src/screw_agents/resolver.py`
- Modify: `tests/test_resolver.py`

**Context:** These three target types build on the file/glob and git_diff implementations.

- [ ] **Step 1: Write failing tests**

Append to `tests/test_resolver.py`:

```python
def test_resolve_codebase(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.py").write_text("x = 1\n")
    (tmp_path / "src" / "util.js").write_text("const y = 2;\n")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "pkg.js").write_text("ignored\n")

    target = {
        "type": "codebase",
        "root": str(tmp_path),
        "exclude": ["node_modules"],
    }
    result = resolve_target(target)
    paths = {r.file_path for r in result}
    assert any("app.py" in p for p in paths)
    assert any("util.js" in p for p in paths)
    assert not any("node_modules" in p for p in paths)


def test_resolve_git_commits(tmp_path):
    subprocess.run(["git", "init"], cwd=tmp_path, capture_output=True, check=True)
    subprocess.run(
        ["git", "config", "user.email", "test@test.com"],
        cwd=tmp_path, capture_output=True, check=True,
    )
    subprocess.run(
        ["git", "config", "user.name", "Test"],
        cwd=tmp_path, capture_output=True, check=True,
    )

    f = tmp_path / "app.py"
    f.write_text("v1\n")
    subprocess.run(["git", "add", "."], cwd=tmp_path, capture_output=True, check=True)
    subprocess.run(
        ["git", "commit", "-m", "v1"],
        cwd=tmp_path, capture_output=True, check=True,
    )
    c1 = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=tmp_path, capture_output=True, text=True, check=True,
    ).stdout.strip()

    f.write_text("v2\n")
    subprocess.run(["git", "add", "."], cwd=tmp_path, capture_output=True, check=True)
    subprocess.run(
        ["git", "commit", "-m", "v2"],
        cwd=tmp_path, capture_output=True, check=True,
    )

    target = {"type": "git_commits", "range": f"{c1}..HEAD", "cwd": str(tmp_path)}
    result = resolve_target(target)
    assert len(result) >= 1


def test_resolve_pull_request(tmp_path):
    subprocess.run(["git", "init"], cwd=tmp_path, capture_output=True, check=True)
    subprocess.run(
        ["git", "config", "user.email", "test@test.com"],
        cwd=tmp_path, capture_output=True, check=True,
    )
    subprocess.run(
        ["git", "config", "user.name", "Test"],
        cwd=tmp_path, capture_output=True, check=True,
    )

    f = tmp_path / "app.py"
    f.write_text("main\n")
    subprocess.run(["git", "add", "."], cwd=tmp_path, capture_output=True, check=True)
    subprocess.run(
        ["git", "commit", "-m", "init"],
        cwd=tmp_path, capture_output=True, check=True,
    )

    subprocess.run(
        ["git", "checkout", "-b", "feature"],
        cwd=tmp_path, capture_output=True, check=True,
    )
    f.write_text("feature\n")
    subprocess.run(["git", "add", "."], cwd=tmp_path, capture_output=True, check=True)
    subprocess.run(
        ["git", "commit", "-m", "feature"],
        cwd=tmp_path, capture_output=True, check=True,
    )

    target = {
        "type": "pull_request",
        "base": "main",
        "head": "feature",
        "cwd": str(tmp_path),
    }
    result = resolve_target(target)
    assert len(result) >= 1
    assert any("feature" in r.content for r in result)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_resolver.py::test_resolve_codebase -v`
Expected: FAIL — `NotImplementedError: codebase target`

- [ ] **Step 3: Implement codebase, git_commits, pull_request**

In `src/screw_agents/resolver.py`, replace the three stubs:

```python
def _resolve_codebase(target: dict) -> list[ResolvedCode]:
    root = Path(target.get("root", "."))
    exclude = target.get("exclude", [])
    # Default exclusions for common non-source directories
    default_exclude = {"node_modules", ".venv", "venv", ".git", "__pycache__", "vendor", ".tox"}
    exclude_set = default_exclude | set(exclude)

    from screw_agents.treesitter import EXTENSION_MAP

    results = []
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        # Check exclusions against any path component
        if any(ex in path.parts for ex in exclude_set):
            continue
        # Only include files with recognized extensions
        if path.suffix.lower() not in EXTENSION_MAP:
            continue
        content = path.read_text(encoding="utf-8", errors="replace")
        results.append(ResolvedCode(
            file_path=str(path),
            content=content,
            language=_detect_language(str(path)),
        ))
    return results


def _resolve_git_commits(target: dict) -> list[ResolvedCode]:
    cwd = target.get("cwd", ".")
    commit_range = target["range"]
    context_lines = target.get("context_lines", 10)

    result = subprocess.run(
        ["git", "diff", f"-U{context_lines}", commit_range],
        cwd=cwd, capture_output=True, text=True, check=True,
    )

    if not result.stdout.strip():
        return []

    return _parse_unified_diff(result.stdout, cwd)


def _resolve_pull_request(target: dict) -> list[ResolvedCode]:
    # PR resolution is a git_diff between base and head branches.
    return _resolve_git_diff({
        "base": target["base"],
        "head": target["head"],
        "cwd": target.get("cwd", "."),
        "context_lines": target.get("context_lines", 10),
    })
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_resolver.py -v`
Expected: all tests PASS.

- [ ] **Step 5: Commit**

```bash
git add src/screw_agents/resolver.py tests/test_resolver.py
git commit -m "feat: add codebase, git_commits, pull_request target types

Codebase scans all source files with recognized extensions, excluding
common non-source dirs. git_commits and pull_request delegate to the
unified diff parser."
```

---

## Task 11: Target resolver — relevance filtering and thoroughness

**Files:**
- Modify: `src/screw_agents/resolver.py`
- Modify: `tests/test_resolver.py`

**Context:** For broad targets (codebase, glob), filter files by agent relevance signals. Thoroughness controls how much context is included.

- [ ] **Step 1: Write failing tests**

Append to `tests/test_resolver.py`:

```python
from screw_agents.resolver import filter_by_relevance


def test_filter_by_relevance_keeps_matching(tmp_path):
    f1 = tmp_path / "db.py"
    f1.write_text("cursor.execute('SELECT * FROM users')\n")
    f2 = tmp_path / "ui.py"
    f2.write_text("print('hello')\n")

    codes = [
        ResolvedCode(file_path=str(f1), content=f1.read_text(), language="python"),
        ResolvedCode(file_path=str(f2), content=f2.read_text(), language="python"),
    ]
    signals = ["cursor.execute", "SELECT"]
    filtered = filter_by_relevance(codes, signals)
    assert len(filtered) == 1
    assert "db.py" in filtered[0].file_path


def test_filter_by_relevance_empty_signals_passes_all(tmp_path):
    f1 = tmp_path / "a.py"
    f1.write_text("x = 1\n")
    codes = [ResolvedCode(file_path=str(f1), content=f1.read_text(), language="python")]
    filtered = filter_by_relevance(codes, [])
    assert len(filtered) == 1


def test_filter_by_relevance_no_matches_returns_empty(tmp_path):
    f1 = tmp_path / "a.py"
    f1.write_text("x = 1\n")
    codes = [ResolvedCode(file_path=str(f1), content=f1.read_text(), language="python")]
    filtered = filter_by_relevance(codes, ["subprocess", "os.system"])
    assert len(filtered) == 0
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_resolver.py::test_filter_by_relevance_keeps_matching -v`
Expected: FAIL — `ImportError: cannot import name 'filter_by_relevance'`

- [ ] **Step 3: Implement relevance filtering**

Add to `src/screw_agents/resolver.py`:

```python
def filter_by_relevance(
    codes: list[ResolvedCode],
    relevance_signals: list[str],
) -> list[ResolvedCode]:
    """Filter resolved code chunks by agent relevance signals.

    A file is kept if its content contains at least one signal string.
    If signals is empty, all files pass through.
    """
    if not relevance_signals:
        return codes

    filtered = []
    for code in codes:
        content_lower = code.content.lower()
        if any(signal.lower() in content_lower for signal in relevance_signals):
            filtered.append(code)
    return filtered
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_resolver.py -v`
Expected: all tests PASS.

- [ ] **Step 5: Commit**

```bash
git add src/screw_agents/resolver.py tests/test_resolver.py
git commit -m "feat: add relevance filtering to target resolver

Pre-filters resolved code by agent relevance_signals for broad targets
(codebase, glob). Case-insensitive substring matching. Empty signals
passes everything through."
```

---

## Task 12: Output formatter — JSON

**Files:**
- Create: `src/screw_agents/formatter.py`
- Create: `tests/test_formatter.py`

**Context:** Formats findings as JSON following PRD §8. Uses the Finding Pydantic model for serialization.

- [ ] **Step 1: Write failing tests**

Create `tests/test_formatter.py`:

```python
"""Tests for the output formatter."""

import json

import pytest

from screw_agents.formatter import format_findings
from screw_agents.models import (
    Finding, FindingLocation, FindingClassification,
    FindingAnalysis, FindingRemediation, DataFlow,
)


def _make_finding(**overrides) -> Finding:
    defaults = dict(
        id="sqli-001",
        agent="sqli",
        domain="injection-input-handling",
        timestamp="2026-04-10T14:30:00Z",
        location=FindingLocation(file="test.py", line_start=10),
        classification=FindingClassification(
            cwe="CWE-89", cwe_name="SQL Injection",
            severity="high", confidence="high",
        ),
        analysis=FindingAnalysis(
            description="SQL injection via f-string",
            impact="Data exfiltration",
            exploitability="Trivially exploitable",
        ),
        remediation=FindingRemediation(recommendation="Use parameterized queries"),
    )
    defaults.update(overrides)
    return Finding(**defaults)


def test_format_json_single_finding():
    findings = [_make_finding()]
    output = format_findings(findings, format="json")
    parsed = json.loads(output)
    assert isinstance(parsed, list)
    assert len(parsed) == 1
    assert parsed[0]["id"] == "sqli-001"
    assert parsed[0]["classification"]["cwe"] == "CWE-89"
    assert parsed[0]["triage"]["status"] == "pending"


def test_format_json_empty():
    output = format_findings([], format="json")
    parsed = json.loads(output)
    assert parsed == []


def test_format_json_with_data_flow():
    finding = _make_finding(
        location=FindingLocation(
            file="test.py",
            line_start=10,
            line_end=15,
            data_flow=DataFlow(
                source="request.args.get('id')",
                source_location="test.py:10",
                sink="cursor.execute(query)",
                sink_location="test.py:15",
            ),
        ),
    )
    output = format_findings([finding], format="json")
    parsed = json.loads(output)
    assert parsed[0]["location"]["data_flow"]["source"] == "request.args.get('id')"


def test_format_json_multiple_findings():
    findings = [
        _make_finding(id="sqli-001", classification=FindingClassification(
            cwe="CWE-89", cwe_name="SQL Injection",
            severity="high", confidence="high",
        )),
        _make_finding(id="xss-001", agent="xss", classification=FindingClassification(
            cwe="CWE-79", cwe_name="XSS",
            severity="medium", confidence="medium",
        )),
    ]
    output = format_findings(findings, format="json")
    parsed = json.loads(output)
    assert len(parsed) == 2
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_formatter.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'screw_agents.formatter'`

- [ ] **Step 3: Implement JSON formatter**

Create `src/screw_agents/formatter.py`:

```python
"""Output formatter — renders findings as JSON, SARIF 2.1.0, or Markdown.

All findings are validated Finding Pydantic models. The formatter
serializes them to the requested output format.
"""

from __future__ import annotations

import json
from typing import Any

from screw_agents.models import Finding


def format_findings(
    findings: list[Finding],
    format: str = "json",
    scan_metadata: dict[str, Any] | None = None,
) -> str:
    """Format findings into the requested output format.

    Args:
        findings: List of validated Finding models.
        format: One of "json", "sarif", "markdown".
        scan_metadata: Optional metadata (agents used, target, duration, etc.)

    Returns:
        Formatted string output.
    """
    if format == "json":
        return _format_json(findings)
    elif format == "sarif":
        return _format_sarif(findings, scan_metadata or {})
    elif format == "markdown":
        return _format_markdown(findings, scan_metadata or {})
    else:
        raise ValueError(f"Unsupported output format: {format!r}")


def _format_json(findings: list[Finding]) -> str:
    data = [f.model_dump(mode="json", exclude_none=True) for f in findings]
    return json.dumps(data, indent=2)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_formatter.py -v`
Expected: all JSON tests PASS.

- [ ] **Step 5: Commit**

```bash
git add src/screw_agents/formatter.py tests/test_formatter.py
git commit -m "feat: add JSON output formatter for scan findings

Serializes Finding Pydantic models to JSON following PRD §8 schema.
Stubs for SARIF and Markdown formatters."
```

---

## Task 13: Output formatter — SARIF 2.1.0

**Files:**
- Modify: `src/screw_agents/formatter.py`
- Modify: `tests/test_formatter.py`

**Context:** SARIF output follows the same 2.1.0 subset used by `benchmarks/runner/sarif.py` (bentoo-compatible). This enables GitHub Security tab integration and benchmark evaluation interop.

- [ ] **Step 1: Write failing tests**

Append to `tests/test_formatter.py`:

```python
def test_format_sarif_structure():
    findings = [_make_finding()]
    output = format_findings(findings, format="sarif", scan_metadata={"agents": ["sqli"]})
    sarif = json.loads(output)
    assert sarif["$schema"] == "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json"
    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"]) == 1
    run = sarif["runs"][0]
    assert "tool" in run
    assert "results" in run


def test_format_sarif_results():
    findings = [_make_finding()]
    output = format_findings(findings, format="sarif", scan_metadata={"agents": ["sqli"]})
    sarif = json.loads(output)
    results = sarif["runs"][0]["results"]
    assert len(results) == 1
    r = results[0]
    assert r["ruleId"] == "CWE-89"
    assert r["level"] == "error"  # high severity → error
    assert r["message"]["text"] == "SQL injection via f-string"
    locs = r["locations"]
    assert len(locs) == 1
    assert locs[0]["physicalLocation"]["artifactLocation"]["uri"] == "test.py"
    assert locs[0]["physicalLocation"]["region"]["startLine"] == 10


def test_format_sarif_severity_mapping():
    finding_medium = _make_finding(
        classification=FindingClassification(
            cwe="CWE-79", cwe_name="XSS",
            severity="medium", confidence="medium",
        ),
    )
    output = format_findings([finding_medium], format="sarif")
    sarif = json.loads(output)
    assert sarif["runs"][0]["results"][0]["level"] == "warning"


def test_format_sarif_empty():
    output = format_findings([], format="sarif")
    sarif = json.loads(output)
    assert sarif["runs"][0]["results"] == []
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_formatter.py::test_format_sarif_structure -v`
Expected: FAIL (SARIF not implemented yet)

- [ ] **Step 3: Implement SARIF formatter**

Add to `src/screw_agents/formatter.py`:

```python
_SEVERITY_TO_SARIF_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
}


def _format_sarif(findings: list[Finding], metadata: dict[str, Any]) -> str:
    rules: dict[str, dict] = {}
    results = []

    for f in findings:
        rule_id = f.classification.cwe
        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": f.classification.cwe_name,
                "shortDescription": {"text": f.classification.cwe_name},
            }

        result: dict[str, Any] = {
            "ruleId": rule_id,
            "level": _SEVERITY_TO_SARIF_LEVEL.get(
                f.classification.severity, "warning"
            ),
            "message": {"text": f.analysis.description},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": f.location.file},
                        "region": {
                            "startLine": f.location.line_start,
                            **(
                                {"endLine": f.location.line_end}
                                if f.location.line_end
                                else {}
                            ),
                        },
                    }
                }
            ],
        }

        if f.remediation.fix_code:
            result["fixes"] = [
                {
                    "description": {"text": f.remediation.recommendation},
                }
            ]

        results.append(result)

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "screw-agents",
                        "informationUri": "https://github.com/h0pes/screw-agents",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(sarif, indent=2)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_formatter.py -v`
Expected: all tests PASS.

- [ ] **Step 5: Commit**

```bash
git add src/screw_agents/formatter.py tests/test_formatter.py
git commit -m "feat: add SARIF 2.1.0 output formatter

bentoo-compatible SARIF output for GitHub Security tab, CI/CD, and
benchmark evaluation interop. Maps severity to SARIF levels."
```

---

## Task 14: Output formatter — Markdown

**Files:**
- Modify: `src/screw_agents/formatter.py`
- Modify: `tests/test_formatter.py`

**Context:** Human-readable report with severity summary table, findings overview, and detailed per-finding sections (PRD §7.1 + secure code review template elements).

- [ ] **Step 1: Write failing tests**

Append to `tests/test_formatter.py`:

```python
def test_format_markdown_structure():
    findings = [
        _make_finding(id="sqli-001"),
        _make_finding(
            id="xss-001", agent="xss",
            classification=FindingClassification(
                cwe="CWE-79", cwe_name="XSS",
                severity="medium", confidence="high",
            ),
            analysis=FindingAnalysis(description="Reflected XSS"),
            remediation=FindingRemediation(recommendation="Encode output"),
        ),
    ]
    output = format_findings(
        findings,
        format="markdown",
        scan_metadata={"agents": ["sqli", "xss"], "target": "src/api/"},
    )
    # Check structural elements
    assert "# Security Scan Report" in output
    assert "## Summary" in output
    assert "| Severity" in output  # severity table
    assert "| High" in output
    assert "| Medium" in output
    assert "## Findings Overview" in output
    assert "sqli-001" in output
    assert "xss-001" in output
    assert "## Detailed Findings" in output
    assert "CWE-89" in output
    assert "CWE-79" in output


def test_format_markdown_empty():
    output = format_findings([], format="markdown")
    assert "No findings" in output or "0" in output


def test_format_markdown_with_data_flow():
    finding = _make_finding(
        location=FindingLocation(
            file="test.py",
            line_start=10,
            data_flow=DataFlow(
                source="request.args['id']",
                source_location="test.py:10",
                sink="cursor.execute(q)",
                sink_location="test.py:15",
            ),
        ),
    )
    output = format_findings([finding], format="markdown")
    assert "Source" in output
    assert "Sink" in output
    assert "request.args" in output


def test_format_markdown_with_fix_code():
    finding = _make_finding(
        remediation=FindingRemediation(
            recommendation="Use parameterized queries",
            fix_code="cursor.execute('SELECT * FROM users WHERE id = %s', (uid,))",
        ),
    )
    output = format_findings([finding], format="markdown")
    assert "cursor.execute" in output
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_formatter.py::test_format_markdown_structure -v`
Expected: FAIL (markdown not implemented yet)

- [ ] **Step 3: Implement Markdown formatter**

Add to `src/screw_agents/formatter.py`:

```python
from collections import Counter


def _format_markdown(findings: list[Finding], metadata: dict[str, Any]) -> str:
    lines: list[str] = []

    lines.append("# Security Scan Report\n")
    lines.append("")

    # Metadata
    if metadata.get("target"):
        lines.append(f"**Target:** `{metadata['target']}`  ")
    if metadata.get("agents"):
        lines.append(f"**Agents:** {', '.join(metadata['agents'])}  ")
    if metadata.get("timestamp"):
        lines.append(f"**Date:** {metadata['timestamp']}  ")
    lines.append("")

    # Summary
    lines.append("## Summary\n")

    if not findings:
        lines.append("No findings reported.\n")
        return "\n".join(lines)

    severity_counts = Counter(f.classification.severity for f in findings)
    lines.append("| Severity | Count |")
    lines.append("|----------|-------|")
    for sev in ("critical", "high", "medium", "low"):
        count = severity_counts.get(sev, 0)
        if count > 0:
            lines.append(f"| {sev.capitalize()} | {count} |")
    lines.append("")

    # Findings overview table
    lines.append("## Findings Overview\n")
    lines.append("| ID | Severity | Agent | CWE | File | Line |")
    lines.append("|----|----------|-------|-----|------|------|")
    for f in findings:
        lines.append(
            f"| {f.id} | {f.classification.severity.capitalize()} "
            f"| {f.agent} | {f.classification.cwe} "
            f"| `{f.location.file}` | {f.location.line_start} |"
        )
    lines.append("")

    # Detailed findings
    lines.append("## Detailed Findings\n")
    for f in findings:
        lines.append(f"### {f.id} — {f.classification.cwe_name}\n")
        lines.append(f"**Severity:** {f.classification.severity.capitalize()}  ")
        lines.append(f"**Confidence:** {f.classification.confidence.capitalize()}  ")
        lines.append(
            f"**CWE:** [{f.classification.cwe}]"
            f"(https://cwe.mitre.org/data/definitions/"
            f"{f.classification.cwe.split('-')[1]}.html)  "
        )
        if f.classification.owasp_top10:
            lines.append(f"**OWASP:** {f.classification.owasp_top10}  ")
        lines.append("")
        lines.append(f"**File:** `{f.location.file}:{f.location.line_start}`  ")
        if f.location.function:
            lines.append(f"**Function:** `{f.location.function}`  ")
        lines.append("")

        # Description
        lines.append(f"{f.analysis.description}\n")

        if f.analysis.impact:
            lines.append(f"**Impact:** {f.analysis.impact}\n")

        # Data flow
        if f.location.data_flow:
            df = f.location.data_flow
            lines.append("**Data Flow:**\n")
            lines.append("| | Location | Expression |")
            lines.append("|---|---|---|")
            lines.append(f"| Source | `{df.source_location}` | `{df.source}` |")
            lines.append(f"| Sink | `{df.sink_location}` | `{df.sink}` |")
            lines.append("")

        # Code snippet
        if f.location.code_snippet:
            lines.append("**Vulnerable Code:**\n")
            lines.append(f"```\n{f.location.code_snippet}\n```\n")

        # Remediation
        lines.append(f"**Remediation:** {f.remediation.recommendation}\n")
        if f.remediation.fix_code:
            lines.append("**Suggested Fix:**\n")
            lines.append(f"```\n{f.remediation.fix_code}\n```\n")

        # FP reasoning
        if f.analysis.false_positive_reasoning:
            lines.append(
                f"**False Positive Reasoning:** {f.analysis.false_positive_reasoning}\n"
            )

        lines.append("---\n")

    return "\n".join(lines)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_formatter.py -v`
Expected: all tests PASS.

- [ ] **Step 5: Commit**

```bash
git add src/screw_agents/formatter.py tests/test_formatter.py
git commit -m "feat: add Markdown output formatter with severity summary

Human-readable report with severity count table, findings overview,
detailed per-finding sections with data flow tracing and fix code."
```

---

## Task 15: Scan engine (`engine.py`)

**Files:**
- Create: `src/screw_agents/engine.py`
- Create: `tests/test_engine.py`

**Context:** The engine ties registry, resolver, and formatter together. It assembles the detection prompt from agent YAML + resolved code, and formats the output. It does NOT call Claude — the MCP tool returns the assembled prompt for Claude to process.

- [ ] **Step 1: Write failing tests**

Create `tests/test_engine.py`:

```python
"""Tests for the scan engine."""

import pytest
from pathlib import Path

from screw_agents.engine import ScanEngine
from screw_agents.registry import AgentRegistry


@pytest.fixture
def engine(domains_dir):
    registry = AgentRegistry(domains_dir)
    return ScanEngine(registry)


def test_engine_assemble_prompt(engine, fixtures_dir):
    vuln_file = fixtures_dir / "sqli" / "vulnerable" / "python_fstring.py"
    if not vuln_file.exists():
        pytest.skip("fixture not found")

    target = {"type": "file", "path": str(vuln_file)}
    result = engine.assemble_scan(agent_name="sqli", target=target)

    assert "core_prompt" in result
    assert "code" in result
    assert "agent_name" in result
    assert result["agent_name"] == "sqli"
    # core_prompt should contain the agent's detection knowledge
    assert "SQL injection" in result["core_prompt"].lower() or "sql" in result["core_prompt"].lower()
    # code should contain the resolved file content
    assert len(result["code"]) > 0


def test_engine_assemble_prompt_unknown_agent(engine):
    target = {"type": "file", "path": "/dev/null"}
    with pytest.raises(ValueError, match="Unknown agent"):
        engine.assemble_scan(agent_name="nonexistent", target=target)


def test_engine_assemble_domain_scan(engine, fixtures_dir):
    vuln_file = fixtures_dir / "sqli" / "vulnerable" / "python_fstring.py"
    if not vuln_file.exists():
        pytest.skip("fixture not found")

    target = {"type": "file", "path": str(vuln_file)}
    results = engine.assemble_domain_scan(
        domain="injection-input-handling",
        target=target,
    )
    assert len(results) == 4
    agent_names = {r["agent_name"] for r in results}
    assert agent_names == {"sqli", "cmdi", "ssti", "xss"}


def test_engine_prompt_includes_heuristics(engine, fixtures_dir):
    vuln_file = fixtures_dir / "sqli" / "vulnerable" / "python_fstring.py"
    if not vuln_file.exists():
        pytest.skip("fixture not found")

    target = {"type": "file", "path": str(vuln_file)}
    result = engine.assemble_scan(agent_name="sqli", target=target)
    prompt = result["core_prompt"]
    # Should include detection heuristics and bypass techniques
    assert "detection_heuristics" in result or "heuristic" in prompt.lower() or "high_confidence" in prompt.lower()


def test_engine_list_tools(engine):
    tools = engine.list_tool_definitions()
    tool_names = {t["name"] for t in tools}
    assert "scan_sqli" in tool_names
    assert "scan_cmdi" in tool_names
    assert "list_domains" in tool_names
    assert "list_agents" in tool_names
    assert "scan_domain" in tool_names
    assert "scan_full" in tool_names
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_engine.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'screw_agents.engine'`

- [ ] **Step 3: Implement `engine.py`**

Create `src/screw_agents/engine.py`:

```python
"""Scan engine — orchestrates registry, resolver, and formatter.

Assembles detection prompts from agent YAML definitions and resolved
code targets. The MCP server returns these assembled prompts to Claude
(the host LLM) which performs the actual security analysis.
"""

from __future__ import annotations

from typing import Any

import yaml

from screw_agents.formatter import format_findings
from screw_agents.models import AgentDefinition, Finding
from screw_agents.registry import AgentRegistry
from screw_agents.resolver import ResolvedCode, filter_by_relevance, resolve_target


class ScanEngine:
    """Orchestrates agent scanning: target resolution, prompt assembly, formatting."""

    def __init__(self, registry: AgentRegistry) -> None:
        self._registry = registry

    def assemble_scan(
        self,
        agent_name: str,
        target: dict,
        thoroughness: str = "standard",
    ) -> dict[str, Any]:
        """Assemble a scan prompt for a single agent.

        Returns a dict with agent_name, core_prompt, code, and metadata
        that the MCP tool handler sends back to Claude.
        """
        agent = self._registry.get_agent(agent_name)
        if agent is None:
            raise ValueError(f"Unknown agent: {agent_name!r}")

        # Resolve target to code
        codes = resolve_target(target)

        # Apply relevance filtering for broad targets
        target_type = target.get("type")
        if target_type in ("codebase", "glob"):
            codes = filter_by_relevance(
                codes, agent.target_strategy.relevance_signals
            )

        # Assemble the prompt
        prompt = _build_prompt(agent, thoroughness)
        code_text = _format_code_context(codes)

        return {
            "agent_name": agent_name,
            "core_prompt": prompt,
            "code": code_text,
            "resolved_files": [c.file_path for c in codes],
            "meta": {
                "cwe_primary": agent.meta.cwes.primary,
                "domain": agent.meta.domain,
                "thoroughness": thoroughness,
            },
        }

    def assemble_domain_scan(
        self,
        domain: str,
        target: dict,
        thoroughness: str = "standard",
    ) -> list[dict[str, Any]]:
        """Assemble scan prompts for all agents in a domain."""
        agents = self._registry.get_agents_by_domain(domain)
        return [
            self.assemble_scan(a.meta.name, target, thoroughness)
            for a in agents
        ]

    def assemble_full_scan(
        self,
        target: dict,
        thoroughness: str = "standard",
    ) -> list[dict[str, Any]]:
        """Assemble scan prompts for all agents across all domains."""
        results = []
        for name in self._registry.agents:
            results.append(self.assemble_scan(name, target, thoroughness))
        return results

    def format_output(
        self,
        findings: list[Finding],
        output_format: str = "json",
        scan_metadata: dict[str, Any] | None = None,
    ) -> str:
        """Format findings into the requested output format."""
        return format_findings(findings, format=output_format, scan_metadata=scan_metadata)

    def list_tool_definitions(self) -> list[dict[str, Any]]:
        """Return MCP tool definitions for all registered agents + static tools."""
        tools: list[dict[str, Any]] = []

        # Static tools
        tools.append({
            "name": "list_domains",
            "description": "List available security review domains with agent counts.",
            "input_schema": {"type": "object", "properties": {}},
        })
        tools.append({
            "name": "list_agents",
            "description": "List available security review agents, optionally filtered by domain.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "domain": {
                        "type": "string",
                        "description": "Optional domain filter",
                    },
                },
            },
        })
        tools.append({
            "name": "scan_domain",
            "description": "Run all agents in a security domain against a target.",
            "input_schema": _scan_input_schema(
                extra_required=["domain"],
                extra_props={
                    "domain": {"type": "string", "description": "Domain name"},
                },
            ),
        })
        tools.append({
            "name": "scan_full",
            "description": "Run all security agents across all domains against a target.",
            "input_schema": _scan_input_schema(),
        })

        # Per-agent scan tools
        for name, agent in self._registry.agents.items():
            tools.append({
                "name": f"scan_{name}",
                "description": (
                    f"{agent.meta.display_name} — "
                    f"scan for {agent.meta.cwes.primary} vulnerabilities."
                ),
                "input_schema": _scan_input_schema(),
            })

        return tools


def _scan_input_schema(
    extra_required: list[str] | None = None,
    extra_props: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build the JSON Schema for scan tool inputs."""
    props: dict[str, Any] = {
        "target": {
            "type": "object",
            "description": "Target specification (see PRD §5). Must include 'type' field.",
        },
        "thoroughness": {
            "type": "string",
            "enum": ["quick", "standard", "deep"],
            "description": "How much context to include. Default: standard.",
        },
        "output_format": {
            "type": "string",
            "enum": ["json", "sarif", "markdown"],
            "description": "Output format. Default: json.",
        },
    }
    required = ["target"]

    if extra_props:
        props.update(extra_props)
    if extra_required:
        required.extend(extra_required)

    return {
        "type": "object",
        "properties": props,
        "required": required,
    }


def _build_prompt(agent: AgentDefinition, thoroughness: str) -> str:
    """Build the detection prompt from agent definition."""
    parts: list[str] = []

    parts.append(agent.core_prompt)
    parts.append("")

    # Detection heuristics
    parts.append("## Detection Heuristics")
    if agent.detection_heuristics.high_confidence:
        parts.append("\n### High Confidence")
        for h in agent.detection_heuristics.high_confidence:
            parts.append(f"- {h}")
    if agent.detection_heuristics.medium_confidence:
        parts.append("\n### Medium Confidence")
        for m in agent.detection_heuristics.medium_confidence:
            parts.append(f"- {m}")
    if thoroughness == "deep" and agent.detection_heuristics.context_required:
        parts.append("\n### Context Required (deep scan)")
        for c in agent.detection_heuristics.context_required:
            parts.append(f"- {c}")
    parts.append("")

    # Bypass techniques
    if agent.bypass_techniques:
        parts.append("## Bypass Techniques to Watch For")
        for bt in agent.bypass_techniques:
            parts.append(f"\n### {bt.name}")
            parts.append(bt.description)
            if bt.detection_hint:
                parts.append(f"**Detection hint:** {bt.detection_hint}")
        parts.append("")

    # Few-shot examples
    if agent.few_shot_examples.vulnerable or agent.few_shot_examples.safe:
        parts.append("## Reference Examples")
        if agent.few_shot_examples.vulnerable:
            parts.append("\n### Vulnerable Patterns")
            for ex in agent.few_shot_examples.vulnerable[:3]:
                label = ex.label or f"{ex.language} example"
                parts.append(f"\n**{label}:**")
                parts.append(f"```{ex.language}")
                parts.append(ex.code.rstrip())
                parts.append("```")
                if ex.explanation:
                    parts.append(f"_{ex.explanation}_")
        if agent.few_shot_examples.safe:
            parts.append("\n### Safe Patterns")
            for ex in agent.few_shot_examples.safe[:3]:
                label = ex.label or f"{ex.language} example"
                parts.append(f"\n**{label}:**")
                parts.append(f"```{ex.language}")
                parts.append(ex.code.rstrip())
                parts.append("```")
                if ex.explanation:
                    parts.append(f"_{ex.explanation}_")
        parts.append("")

    return "\n".join(parts)


def _format_code_context(codes: list[ResolvedCode]) -> str:
    """Format resolved code chunks into a single text block for Claude."""
    parts: list[str] = []
    for code in codes:
        header = f"## File: {code.file_path}"
        if code.language:
            header += f" ({code.language})"
        if code.line_start:
            header += f" [lines {code.line_start}"
            if code.line_end and code.line_end != code.line_start:
                header += f"-{code.line_end}"
            header += "]"
        parts.append(header)
        lang = code.language or ""
        parts.append(f"```{lang}")
        parts.append(code.content.rstrip())
        parts.append("```")
        parts.append("")
    return "\n".join(parts)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_engine.py -v`
Expected: all tests PASS.

- [ ] **Step 5: Commit**

```bash
git add src/screw_agents/engine.py tests/test_engine.py
git commit -m "feat: add scan engine orchestrating registry, resolver, formatter

Assembles detection prompts from agent YAML + resolved code. Provides
tool definitions for MCP registration. Supports single-agent, domain,
and full scans with thoroughness control."
```

---

## Task 16: MCP server skeleton + stdio transport (`server.py`)

**Files:**
- Create: `src/screw_agents/server.py`
- Create: `tests/test_server.py`

**Context:** The MCP server uses the low-level `mcp.server.lowlevel.Server` API. It registers handlers for `list_tools` and `call_tool` that delegate to the scan engine. This task implements stdio transport (for Claude Code).

- [ ] **Step 1: Write failing tests**

Create `tests/test_server.py`:

```python
"""Tests for MCP server initialization and tool registration."""

import pytest

from screw_agents.server import create_server


def test_create_server(domains_dir):
    server, engine = create_server(domains_dir)
    assert server is not None
    assert engine is not None


def test_server_tool_definitions(domains_dir):
    _, engine = create_server(domains_dir)
    tools = engine.list_tool_definitions()
    names = {t["name"] for t in tools}
    assert "scan_sqli" in names
    assert "scan_cmdi" in names
    assert "scan_ssti" in names
    assert "scan_xss" in names
    assert "list_domains" in names
    assert "list_agents" in names
    assert "scan_domain" in names
    assert "scan_full" in names
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_server.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'screw_agents.server'` or import error

- [ ] **Step 3: Implement `server.py`**

Create `src/screw_agents/server.py`:

```python
"""MCP server for screw-agents — security code review tools.

Uses the low-level mcp.Server API for dynamic YAML-driven tool
registration. Supports stdio (Claude Code) and HTTP (screw.nvim, CI/CD)
transports.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
from pathlib import Path
from typing import Any

import mcp.types as types
from mcp.server.lowlevel import NotificationOptions, Server
from mcp.server.models import InitializationOptions

from screw_agents.engine import ScanEngine
from screw_agents.registry import AgentRegistry

logger = logging.getLogger(__name__)

# Default domains directory — relative to package install location.
_DEFAULT_DOMAINS_DIR = Path(__file__).resolve().parent.parent.parent / "domains"


def create_server(
    domains_dir: Path | None = None,
) -> tuple[Server, ScanEngine]:
    """Create and configure the MCP server with scan tools.

    Returns the Server instance and the ScanEngine for testing.
    """
    if domains_dir is None:
        domains_dir = _DEFAULT_DOMAINS_DIR

    registry = AgentRegistry(domains_dir)
    engine = ScanEngine(registry)

    server = Server("screw-agents")

    @server.list_tools()
    async def handle_list_tools() -> list[types.Tool]:
        tool_defs = engine.list_tool_definitions()
        return [
            types.Tool(
                name=t["name"],
                description=t.get("description", ""),
                inputSchema=t["input_schema"],
            )
            for t in tool_defs
        ]

    @server.call_tool()
    async def handle_call_tool(
        name: str, arguments: dict | None
    ) -> list[types.TextContent]:
        args = arguments or {}
        try:
            result = _dispatch_tool(engine, name, args)
            return [types.TextContent(type="text", text=result)]
        except Exception as e:
            logger.exception("Tool call failed: %s", name)
            return [types.TextContent(type="text", text=f"Error: {e}")]

    return server, engine


def _dispatch_tool(engine: ScanEngine, name: str, args: dict) -> str:
    """Dispatch a tool call to the appropriate engine method."""
    if name == "list_domains":
        domains = engine._registry.list_domains()
        return json.dumps(domains, indent=2)

    elif name == "list_agents":
        agents = engine._registry.list_agents(domain=args.get("domain"))
        return json.dumps(agents, indent=2)

    elif name == "scan_domain":
        target = args["target"]
        domain = args["domain"]
        thoroughness = args.get("thoroughness", "standard")
        output_format = args.get("output_format", "json")
        results = engine.assemble_domain_scan(domain, target, thoroughness)
        return _format_scan_results(results, output_format)

    elif name == "scan_full":
        target = args["target"]
        thoroughness = args.get("thoroughness", "standard")
        output_format = args.get("output_format", "json")
        results = engine.assemble_full_scan(target, thoroughness)
        return _format_scan_results(results, output_format)

    elif name.startswith("scan_"):
        agent_name = name[5:]  # strip "scan_" prefix
        target = args["target"]
        thoroughness = args.get("thoroughness", "standard")
        result = engine.assemble_scan(agent_name, target, thoroughness)
        return json.dumps(result, indent=2)

    else:
        raise ValueError(f"Unknown tool: {name!r}")


def _format_scan_results(results: list[dict[str, Any]], output_format: str) -> str:
    """Format assembled scan results."""
    # For now, return the assembled prompts as JSON.
    # When Claude processes these and returns findings, the formatter kicks in.
    return json.dumps(results, indent=2)


async def run_stdio(domains_dir: Path | None = None) -> None:
    """Run the MCP server over stdio transport."""
    from mcp.server.stdio import stdio_server

    server, _ = create_server(domains_dir)

    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            InitializationOptions(
                server_name="screw-agents",
                server_version="0.1.0",
                capabilities=server.get_capabilities(
                    notification_options=NotificationOptions(),
                    experimental_capabilities={},
                ),
            ),
        )


def main() -> None:
    """CLI entry point for screw-agents MCP server."""
    parser = argparse.ArgumentParser(description="screw-agents MCP server")
    parser.add_argument(
        "--transport",
        choices=["stdio", "http"],
        default="stdio",
        help="Transport type (default: stdio)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8080,
        help="HTTP port (only for --transport http)",
    )
    parser.add_argument(
        "--domains-dir",
        type=Path,
        default=None,
        help="Path to domains/ directory (default: auto-detect)",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
    )
    args = parser.parse_args()

    logging.basicConfig(level=getattr(logging, args.log_level))

    if args.transport == "stdio":
        asyncio.run(run_stdio(args.domains_dir))
    elif args.transport == "http":
        asyncio.run(run_http(args.domains_dir, args.port))


if __name__ == "__main__":
    main()
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_server.py -v`
Expected: all tests PASS.

- [ ] **Step 5: Commit**

```bash
git add src/screw_agents/server.py tests/test_server.py
git commit -m "feat: add MCP server with stdio transport and tool registration

Low-level mcp.Server with dynamic tool registration from agent YAML
definitions. Handles list_tools, call_tool dispatching to scan engine.
CLI entry point: screw-agents --transport stdio"
```

---

## Task 17: MCP server — HTTP transport

**Files:**
- Modify: `src/screw_agents/server.py`

**Context:** HTTP transport enables screw.nvim (Phase 7) and CI/CD integration. Uses the MCP SDK's Streamable HTTP support via Starlette/uvicorn (already dependencies of `mcp`).

- [ ] **Step 1: Write a test for HTTP server creation**

Append to `tests/test_server.py`:

```python
def test_create_http_app(domains_dir):
    from screw_agents.server import create_http_app
    app = create_http_app(domains_dir)
    assert app is not None
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_server.py::test_create_http_app -v`
Expected: FAIL — `ImportError: cannot import name 'create_http_app'`

- [ ] **Step 3: Implement HTTP transport**

Add to `src/screw_agents/server.py`:

```python
from mcp.server.streamable_http import StreamableHTTPServerTransport
from starlette.applications import Starlette
from starlette.routing import Mount


def create_http_app(
    domains_dir: Path | None = None,
    path: str = "/mcp",
) -> Starlette:
    """Create a Starlette app serving the MCP server over Streamable HTTP."""
    server, _ = create_server(domains_dir)

    transport = StreamableHTTPServerTransport(
        mcp_session_timeout=300,
    )

    async def handle_mcp(scope, receive, send):
        await transport.handle(scope, receive, send)

    app = Starlette(
        routes=[Mount(path, app=transport.handle)],
    )

    # Wire the server to the transport on startup
    @app.on_event("startup")
    async def startup():
        # The transport connects to the server when requests arrive
        pass

    return app


async def run_http(domains_dir: Path | None = None, port: int = 8080) -> None:
    """Run the MCP server over HTTP transport."""
    import uvicorn

    app = create_http_app(domains_dir)
    config = uvicorn.Config(app, host="0.0.0.0", port=port, log_level="info")
    server = uvicorn.Server(config)
    await server.serve()
```

**Note:** The Streamable HTTP transport API may need adjustment based on the exact `mcp` 1.27 SDK surface. The implementer should read `mcp/server/streamable_http.py` and adjust the wiring if needed. The key constraint is: same `Server` instance, different transport.

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_server.py -v`
Expected: all tests PASS.

- [ ] **Step 5: Commit**

```bash
git add src/screw_agents/server.py tests/test_server.py
git commit -m "feat: add HTTP transport for MCP server

Streamable HTTP via Starlette/uvicorn for screw.nvim and CI/CD
integration. Same Server instance, different transport. Activated
via screw-agents --transport http --port 8080"
```

---

## Task 18: Integration tests — full scan pipeline

**Files:**
- Modify: `tests/test_engine.py`

**Context:** End-to-end tests that load a real agent YAML, resolve a real fixture file, assemble the prompt, and verify the full pipeline works.

- [ ] **Step 1: Write integration tests**

Append to `tests/test_engine.py`:

```python
import json


def test_full_pipeline_sqli(engine, fixtures_dir):
    """Integration: load sqli agent → resolve fixture → assemble → verify structure."""
    vuln_dir = fixtures_dir / "sqli" / "vulnerable"
    if not vuln_dir.exists():
        pytest.skip("fixtures not found")

    # Pick any Python fixture
    py_files = list(vuln_dir.glob("*.py"))
    if not py_files:
        pytest.skip("no Python fixtures")

    target = {"type": "file", "path": str(py_files[0])}
    result = engine.assemble_scan(agent_name="sqli", target=target)

    # Verify prompt structure
    assert result["agent_name"] == "sqli"
    assert "SQL" in result["core_prompt"] or "sql" in result["core_prompt"].lower()
    assert len(result["code"]) > 0
    assert result["meta"]["cwe_primary"] == "CWE-89"
    assert result["meta"]["domain"] == "injection-input-handling"


def test_full_pipeline_all_agents(engine, fixtures_dir):
    """Integration: verify all 4 Phase 1 agents can scan their own fixtures."""
    agents = ["sqli", "cmdi", "ssti", "xss"]
    for agent_name in agents:
        vuln_dir = fixtures_dir / agent_name / "vulnerable"
        if not vuln_dir.exists():
            continue
        py_files = list(vuln_dir.glob("*.py"))
        if not py_files:
            continue

        target = {"type": "file", "path": str(py_files[0])}
        result = engine.assemble_scan(agent_name=agent_name, target=target)
        assert result["agent_name"] == agent_name
        assert len(result["core_prompt"]) > 100
        assert len(result["code"]) > 0


def test_full_pipeline_domain_scan(engine, fixtures_dir):
    """Integration: domain scan assembles prompts for all 4 agents."""
    vuln_file = fixtures_dir / "sqli" / "vulnerable" / "python_fstring.py"
    if not vuln_file.exists():
        pytest.skip("fixture not found")

    target = {"type": "file", "path": str(vuln_file)}
    results = engine.assemble_domain_scan(
        domain="injection-input-handling", target=target,
    )
    assert len(results) == 4
    # Each result should have a different agent
    agent_names = {r["agent_name"] for r in results}
    assert agent_names == {"sqli", "cmdi", "ssti", "xss"}
    # Each should have code content
    for r in results:
        assert len(r["code"]) > 0


def test_tool_definitions_json_schema_valid(engine):
    """Verify tool definitions produce valid JSON Schema for inputs."""
    tools = engine.list_tool_definitions()
    for t in tools:
        schema = t["input_schema"]
        assert schema["type"] == "object"
        assert "properties" in schema
        # scan tools should require "target"
        if t["name"].startswith("scan_"):
            assert "target" in schema["properties"]
```

- [ ] **Step 2: Run integration tests**

Run: `uv run pytest tests/test_engine.py -v`
Expected: all tests PASS.

- [ ] **Step 3: Run the full test suite**

Run: `uv run pytest tests/ -v`
Expected: all Phase 1 tests PASS.

- [ ] **Step 4: Run Phase 0.5 tests to verify no regressions**

Run: `uv run pytest benchmarks/tests/ -v`
Expected: all 81 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add tests/test_engine.py
git commit -m "test: add integration tests for full scan pipeline

End-to-end tests: real agent YAML → real fixture file → assembled
prompt verification. Covers single agent, domain scan, and tool
definition validation."
```

---

## Task 19: Smoke test with `claude --mcp-config`

**Files:**
- Create: `.mcp.json` (MCP configuration for Claude Code)

**Context:** Manual interactive testing — verify the MCP server works with Claude Code. This is NOT a pytest task; it's a manual verification step.

- [ ] **Step 1: Create MCP configuration file**

Create `.mcp.json` at the repository root:

```json
{
  "mcpServers": {
    "screw-agents": {
      "command": "uv",
      "args": [
        "run",
        "--directory", ".",
        "screw-agents",
        "--transport", "stdio"
      ]
    }
  }
}
```

- [ ] **Step 2: Verify MCP server starts**

Run: `uv run screw-agents --transport stdio --log-level DEBUG`
Expected: server starts without errors and waits for input on stdin. Ctrl+C to exit.

- [ ] **Step 3: Manual test with Claude Code**

Start a Claude Code session that picks up `.mcp.json`:

```bash
claude --mcp-config .mcp.json
```

Then test interactively:
1. Ask Claude to "list available security scan tools" — should show scan_sqli, scan_cmdi, etc.
2. Ask Claude to "scan benchmarks/fixtures/sqli/vulnerable/python_fstring.py for SQL injection" — should invoke scan_sqli tool.
3. Verify the tool returns the assembled prompt with detection knowledge and code.
4. Ask Claude to analyze the code using the returned knowledge — should identify the vulnerability.

- [ ] **Step 4: Commit MCP config**

```bash
git add .mcp.json
git commit -m "feat: add MCP configuration for Claude Code integration

.mcp.json configures Claude Code to use the screw-agents MCP server
via stdio transport for interactive security scanning."
```

---

## Task 20: Benchmark validation (Phase 1.7 gates)

**Files:** No new code — this is a validation step.

**Context:** Run the Phase 0.5 benchmark infrastructure against real CVE data to validate agent detection rates. This task has a pre-requisite: downloading benchmark data via ingest scripts.

**Important:** This task involves downloading external datasets (some large) and running benchmarks. It may take significant time and requires network access.

- [ ] **Step 1: Run ingest scripts to download benchmark data**

Run each ingest script. These download external datasets into `benchmarks/external/` (gitignored):

```bash
uv run python -m benchmarks.scripts.ingest_ossf
uv run python -m benchmarks.scripts.ingest_reality_check_csharp
uv run python -m benchmarks.scripts.ingest_reality_check_python
uv run python -m benchmarks.scripts.ingest_reality_check_java
uv run python -m benchmarks.scripts.ingest_go_sec_code
uv run python -m benchmarks.scripts.ingest_skf_labs
uv run python -m benchmarks.scripts.ingest_crossvul
uv run python -m benchmarks.scripts.ingest_vul4j
```

Expected: each script reports ingested case counts. Verify `case_count > 0` for all.

**MoreFixes (requires Docker + 16 GB):**

MoreFixes is NOT optional — `sqli` validation gate G5 requires `morefixes-extract` TPR >= 50%.

```bash
# Deploy the Postgres dump
bash benchmarks/scripts/deploy_morefixes.sh
```

After the DB is up, **verify the speculative schema** before running extraction. The column names in `benchmarks/scripts/morefixes_extract.py` `SCHEMA_CONFIG` (lines 74-95) are SPECULATIVE — based on MoreFixes documentation, never verified against the actual dump.

```bash
# Inspect actual table names
docker compose -f benchmarks/external/morefixes/docker-compose.yml \
    exec morefixes-db psql -U morefixes -d morefixes -c "\dt"

# Inspect actual column names for each table
docker compose -f benchmarks/external/morefixes/docker-compose.yml \
    exec morefixes-db psql -U morefixes -d morefixes -c "\d fixes"
docker compose -f benchmarks/external/morefixes/docker-compose.yml \
    exec morefixes-db psql -U morefixes -d morefixes -c "\d commits"
docker compose -f benchmarks/external/morefixes/docker-compose.yml \
    exec morefixes-db psql -U morefixes -d morefixes -c "\d method_change"
```

Compare actual column names against `SCHEMA_CONFIG` in `benchmarks/scripts/morefixes_extract.py`. If they differ, update `SCHEMA_CONFIG` and the `build_query()` JOIN conditions to match the real schema. The speculative JOIN `USING (cve_id)` may need a different foreign key column.

Only after schema verification:

```bash
uv run python -m benchmarks.scripts.morefixes_extract
```

- [ ] **Step 2: Apply deduplication and splits**

```bash
uv run python -m benchmarks.scripts.apply_dedup
uv run python -m benchmarks.scripts.apply_splits
```

Expected: `_deduplicated.manifest.json` and `_chrono_split.manifest.json` files created.

- [ ] **Step 3: Run benchmark validation**

Run the benchmark evaluator against agent output:

```bash
uv run python -m benchmarks.runner --help
```

Follow the CLI instructions to run evaluation for each agent against its assigned benchmarks (see `PHASE_0_5_VALIDATION_GATES.md` for the exact thresholds).

- [ ] **Step 4: Verify all gates pass**

Check the benchmark report against Phase 1.7 gates:

| Gate | Check | Threshold |
|---|---|---|
| G1 | `uv run pytest benchmarks/tests/ -v` passes | All green |
| G2 | All benchmarks have data | case_count > 0 |
| G3 | Dedup manifests exist | `_deduplicated.manifest.json` present |
| G4 | Split manifests exist | `_chrono_split.manifest.json` present |
| G5 | Detection rates meet thresholds | See table below |
| G6 | Report says "Rust not benchmarked" | Per ADR-014 |
| G7 | Failure dump for misses | First 10 missed CVEs |

**G5 thresholds:**

| Agent | Dataset | Metric | Threshold |
|---|---|---|---|
| xss | ossf-cve-benchmark (XSS) | TPR | >= 70% |
| xss | ossf-cve-benchmark (patched) | FPR | <= 25% |
| cmdi | ossf-cve-benchmark (CmdI) | TPR | >= 60% |
| sqli | morefixes-extract | TPR on CWE-89 | >= 50% |
| ssti | go-sec-code-mutated | TPR on CWE-1336 | >= 70% |
| ssti | skf-labs-mutated | TPR on CWE-1336 | >= 70% |

- [ ] **Step 5: Commit benchmark results**

```bash
git add docs/
git commit -m "docs: Phase 1.7 benchmark validation results

[Include pass/fail summary and any threshold adjustments needed]"
```

---

## Post-Plan Self-Review

**Spec coverage check:**
- MCP server skeleton (§1) → Task 16
- Agent registry (§2) → Tasks 4, 6
- Target resolver (§3) → Tasks 7-11
- Output formatter (§4) → Tasks 12-14
- Scan engine (§5) → Task 15
- Tree-sitter migration (§6) → Tasks 1-3
- Smoke test (§7) → Task 19
- Benchmark validation (§7) → Task 20
- Finding models with data_flow (§4) → Task 5
- All 3 output formats → Tasks 12-14

**Placeholder scan:** No TBDs, TODOs, or "fill in later" found. Task 17 (HTTP transport) notes that the Streamable HTTP API may need adjustment — this is a genuine runtime uncertainty, not a placeholder.

**Type consistency check:** `AgentDefinition`, `Finding`, `ResolvedCode`, `ScanEngine`, `AgentRegistry`, `format_findings` — all names consistent across tasks. `_GRAMMAR_REGISTRY` keys in Task 2 match `_LANG_TO_TS_NAME` in Task 3.
