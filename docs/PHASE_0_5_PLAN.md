# Phase 0.5 Benchmark Infrastructure Sprint — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stand up a CWE-1400-native real-CVE benchmark harness that ingests 8 external datasets, applies PrimeVul methodology (dedup + chronological + pair-based eval), and produces bentoo-compatible TPR/FPR/F1 metrics — gating Phase 1 validation.

**Architecture:** A standalone Python package `benchmarks/runner/` (pure stdlib + pydantic + tree-sitter + pyyaml) that reads bentoo-sarif ground-truth files, walks the CWE-1400 hierarchy, dedupes via tree-sitter AST normalization, splits benchmarks chronologically, and scores agent output against vulnerable/patched pairs. External benchmarks live in `benchmarks/external/` (gitignored except manifests); MoreFixes runs in a local Docker container and produces a filtered extract. The runner is invoked via `python -m benchmarks.runner` today and will be wired into the MCP server in Phase 1.

**Tech Stack:**
- Python 3.11+ (already the project target)
- uv for dep management (ADR-011)
- Pydantic 2.x for typed models
- tree-sitter (Python bindings, already declared in `pyproject.toml`) for AST normalization in PrimeVul dedup
- PyYAML (already declared) for ground-truth labels and CWE hierarchy storage
- Docker + docker-compose for MoreFixes Postgres deployment
- pytest for meta-tests
- MITRE CWE XML (downloaded once, parsed to YAML, committed)

**Decisions referenced:** ADR-002 (CWE-1400 backbone), ADR-006 (autoresearch), ADR-011 (uv), ADR-013 (CWE-1400-native evaluator, reject bentoo), ADR-014 (Rust corpus deferred)

---

## Quick Reference — Task List

| # | Task | Depends on | Parallel with |
|---|---|---|---|
| 1 | Scaffold `benchmarks/` tree, update `pyproject.toml` and `.gitignore` | — | — |
| 2 | Clone `flawgarden/reality-check/scripts/` into `benchmarks/cve-ingest/` | 1 | 3 |
| 3 | Extract CWE-1400 hierarchy from MITRE XML → commit YAML | 1 | 2 |
| 4 | Pydantic models (`runner/models.py`) | 1 | 2, 3 |
| 5 | bentoo-sarif parser (`runner/sarif.py`) | 4 | 6, 7 |
| 6 | CWE-1400 hierarchy traversal (`runner/cwe.py`) | 3, 4 | 5, 7 |
| 7 | Metrics computation (`runner/metrics.py`) | 4 | 5, 6 |
| 8 | PrimeVul dedup via tree-sitter AST normalization (`runner/primevul.py`) | 4 | 9 |
| 9 | Chronological + pair-based evaluation (`runner/primevul.py` cont.) | 8 | — |
| 10 | CLI entry point (`runner/cli.py`, `runner/__main__.py`) | 5, 6, 7, 9 | 11 |
| 11 | Markdown report generator (`runner/report.py`) | 4, 7 | 10 |
| 12 | Reusable ingest harness base class (`scripts/ingest_base.py`) | 5 | — |
| 13 | Ingest OpenSSF CVE benchmark (JS/TS, 218 CVEs) | 12 | 14-20 |
| 14 | Ingest `reality-check` C# subset (9 XSS + 1 SQLi + 1 CmdI) | 12 | 13, 15-20 |
| 15 | Ingest `reality-check` Python subset (4 XSS + CWE-94) | 12 | 13, 14, 16-20 |
| 16 | Ingest `reality-check` Java subset (5 XSS + 3 CmdI) | 12 | 13-15, 17-20 |
| 17 | Ingest `go-sec-code-mutated` (SSTI via Sprig) | 12 | 13-16, 18-20 |
| 18 | Ingest `skf-labs-mutated` (Python Flask/Jinja2 SSTI) | 12 | 13-17, 19-20 |
| 19 | Ingest `CrossVul` (PHP/Ruby) | 12 | 13-18, 20 |
| 20 | Ingest `Vul4J` (Java precision) | 12 | 13-19 |
| 21 | Deploy MoreFixes Postgres dump via docker-compose | 1 | 13-20 |
| 22 | Write MoreFixes extraction query + filter script | 21 | — |
| 23 | Run PrimeVul dedup across all ingested benchmarks | 8, 13-20, 22 | — |
| 24 | Generate chronological + cross-project splits | 9, 23 | — |
| 25 | End-to-end smoke test with synthetic mock agent output | 10, 24 | 26 |
| 26 | Demote self-authored Rust fixtures to smoke tests, add provenance headers | 1 | 25 |
| 27 | Document Phase 0.5 validation gates (Phase 1.7 acceptance criteria) | 24 | — |
| 28 | Final Phase 0.5 retrospective — refresh `PROJECT_STATUS.md`, tag sprint commit | 1-27 | — |

**Critical path:** 1 → 3/4 → 5/6/7 → 8/9 → 10 → 12 → 22 → 23 → 24 → 25 → 27 → 28

Tasks 13-20 are eight parallelizable benchmark-specific ingest scripts that all share Task 12's base class. They can be done in any order once Task 12 lands.

---

## Prerequisites

Before Task 1, confirm the local environment:

```bash
python --version       # expect 3.11 or newer
uv --version           # expect present
docker --version       # expect present (Task 21)
docker compose version # expect v2 syntax (Task 21)
gh --version           # expect present (Phase 5 cross-reference, but useful earlier)
git --version          # expect present
```

If `docker compose` is v1-style (`docker-compose` as separate binary), use that invocation throughout Task 21.

---

## Directory Layout (created in Task 1)

```
benchmarks/
├── data/
│   ├── cwe-1400-source.xml            # MITRE download (committed, audit trail)
│   └── cwe-1400-hierarchy.yaml        # Parsed output (committed)
├── scripts/
│   ├── __init__.py
│   ├── extract_cwe_1400.py            # Task 3: MITRE XML → YAML
│   ├── ingest_base.py                 # Task 12: reusable harness
│   ├── ingest_ossf.py                 # Task 13
│   ├── ingest_reality_check_csharp.py # Task 14
│   ├── ingest_reality_check_python.py # Task 15
│   ├── ingest_reality_check_java.py   # Task 16
│   ├── ingest_go_sec_code.py          # Task 17
│   ├── ingest_skf_labs.py             # Task 18
│   ├── ingest_crossvul.py             # Task 19
│   ├── ingest_vul4j.py                # Task 20
│   └── morefixes_extract.py           # Task 22
├── cve-ingest/                        # Task 2: cloned flawgarden/reality-check/scripts
│   └── (apache-2.0 licensed files)
├── external/                          # Downloaded benchmarks (gitignored)
│   ├── .gitkeep
│   └── manifests/                     # Committed provenance files (JSON)
│       ├── ossf-cve-benchmark.manifest.json
│       ├── reality-check.manifest.json
│       ├── go-sec-code-mutated.manifest.json
│       ├── skf-labs-mutated.manifest.json
│       ├── crossvul.manifest.json
│       ├── vul4j.manifest.json
│       └── morefixes-extract.manifest.json
├── fixtures/                          # Pre-existing self-authored (smoke tests only)
│   ├── sqli/   cmdi/   ssti/   xss/
│   └── README.md                      # Updated in Task 26 with explicit smoke-test scope
├── runner/                            # Python evaluator (Task 4-11)
│   ├── __init__.py
│   ├── __main__.py                    # python -m benchmarks.runner
│   ├── cli.py                         # Task 10
│   ├── models.py                      # Task 4: Finding, BenchmarkCase, Summary, ...
│   ├── sarif.py                       # Task 5: bentoo-sarif parser
│   ├── cwe.py                         # Task 6: CWE-1400 hierarchy traversal
│   ├── metrics.py                     # Task 7: TPR/FPR/precision/recall/F1
│   ├── primevul.py                    # Task 8-9: dedup, chrono split, pair eval
│   └── report.py                      # Task 11: Markdown report
└── tests/                             # Meta-tests for the runner
    ├── __init__.py
    ├── conftest.py
    ├── test_sarif.py
    ├── test_cwe.py
    ├── test_metrics.py
    ├── test_primevul.py
    ├── test_cli.py
    └── fixtures/
        ├── mini_truth.sarif           # Synthetic ground truth (3 vulnerable, 2 safe)
        ├── mini_agent_perfect.sarif   # Agent that finds everything correctly
        ├── mini_agent_partial.sarif   # Agent that finds 2/3 TP, 1/2 FP
        └── expected_metrics.yaml      # Known-correct metrics for both mini agents
```

**Gitignore additions (Task 1):**
- `benchmarks/external/**` except `benchmarks/external/manifests/` and `benchmarks/external/.gitkeep`
- `benchmarks/cve-ingest/` stays out (it's a third-party clone; we vendor it but don't track the snapshot — the manifest records the commit SHA we pinned)

**pyproject.toml additions (Task 1):**
- Add `benchmarks` to `tool.pytest.ini_options.pythonpath` so `pytest benchmarks/tests/` works
- Add pydantic >=2.0 to dependencies
- Add pytest, pytest-cov to dev dependencies (`[dependency-groups.dev]`)

---

## File Responsibilities (what each file owns)

| File | Responsibility | Lines (est.) |
|---|---|---|
| `benchmarks/runner/models.py` | Pydantic types — `Language`, `FindingKind`, `CodeLocation`, `Finding`, `BenchmarkCase`, `AgentRun`, `MetricSet`, `Summary` | 150 |
| `benchmarks/runner/sarif.py` | Read/write bentoo-sarif files. `load_bentoo_sarif(path) → list[Finding]`, `write_bentoo_sarif(path, findings) → None` | 120 |
| `benchmarks/runner/cwe.py` | `Cwe1400Hierarchy` with `ancestors_of()`, `descendants_of()`, `broad_match()`, `category_of()`. Loads from YAML | 100 |
| `benchmarks/runner/metrics.py` | `compute_metrics(ground_truth, agent_findings, hierarchy) → list[MetricSet]`. TPR/FPR/precision/recall/F1/accuracy | 180 |
| `benchmarks/runner/primevul.py` | `dedupe(cases) → cases`, `chronological_split(cases, cutoff_date) → (train, test)`, `pair_evaluate(case, findings) → (tp, fp, tn, fn)`, `ast_normalize(code, language) → str` | 200 |
| `benchmarks/runner/cli.py` | `argparse`-based CLI: `run`, `list`, `validate` subcommands | 120 |
| `benchmarks/runner/report.py` | `render_markdown(summary) → str`. Per-CWE, per-language breakdown tables, failure dump section | 130 |
| `benchmarks/scripts/extract_cwe_1400.py` | One-time script: download MITRE XML, parse, emit YAML | 80 |
| `benchmarks/scripts/ingest_base.py` | `IngestBase` abstract class: `clone()`, `extract_cases()`, `materialize()`, `write_manifest()` | 120 |

**Estimated total hand-written Python:** ~1,200 lines core + ~800 lines ingest scripts (8 × 100 avg) + ~600 lines tests = ~2,600 lines. Within ADR-013's tradeoff envelope.

---

## Dependency Graph — Explicit Parallelization Flags

```
Task 1 (scaffold) ─┬─► Task 2 (flawgarden clone) ─────────► (used by Tasks 13-16)
                   │
                   ├─► Task 3 (CWE-1400 extraction) ───────► Task 6 (cwe.py)
                   │
                   ├─► Task 4 (models.py) ───┬─► Task 5 (sarif.py) ───┬─► Task 10 (cli)
                   │                         │                        │
                   │                         ├─► Task 6 (cwe.py) ─────┤
                   │                         │                        │
                   │                         ├─► Task 7 (metrics) ────┤
                   │                         │                        │
                   │                         └─► Task 8 (primevul) ─► Task 9 (splits/pairs)
                   │                                                  │
                   │                         Task 11 (report) ────────┤
                   │                                                  │
                   │                                                  └─► Task 25 (smoke test)
                   │
                   ├─► Task 21 (MoreFixes Docker) ──► Task 22 (extract)
                   │                                   │
                   │                                   ├─► Task 23 (dedup all)
                   │                                   │
                   ├─► Task 12 (ingest base) ──┬─► Tasks 13-20 (parallel) ──┤
                   │                           │                            │
                   │                                                        ├─► Task 24 (splits)
                   │                                                        │
                   └─► Task 26 (Rust demotion) ────────────────────────────┘
                                                                            │
                                                                            └─► Task 27 (gates doc)
                                                                                │
                                                                                └─► Task 28 (retrospective)
```

**Key parallelization opportunities:**
- Tasks 2/3/4 run in parallel after Task 1
- Tasks 5/6/7 run in parallel after Task 4
- Tasks 13-20 run in parallel after Task 12
- Task 21 runs in parallel with core runner development (2-11)
- Task 26 can run any time after Task 1

Sequential bottleneck: Task 8 → Task 9 → (Tasks 23, 24) → Task 25 → Tasks 27, 28

---

## Task 1: Scaffold `benchmarks/` tree, update `pyproject.toml` and `.gitignore`

**Files:**
- Create: `benchmarks/data/.gitkeep`
- Create: `benchmarks/scripts/__init__.py`
- Create: `benchmarks/external/.gitkeep`
- Create: `benchmarks/external/manifests/.gitkeep`
- Create: `benchmarks/runner/__init__.py`
- Create: `benchmarks/runner/__main__.py`
- Create: `benchmarks/tests/__init__.py`
- Create: `benchmarks/tests/conftest.py`
- Create: `benchmarks/tests/fixtures/.gitkeep`
- Modify: `pyproject.toml`
- Modify: `.gitignore`

- [ ] **Step 1: Create directory tree**

```bash
cd /home/marco/Programming/AI/screw-agents
mkdir -p benchmarks/data benchmarks/scripts benchmarks/external/manifests benchmarks/runner benchmarks/tests/fixtures benchmarks/cve-ingest
touch benchmarks/data/.gitkeep benchmarks/external/.gitkeep benchmarks/external/manifests/.gitkeep benchmarks/tests/fixtures/.gitkeep
```

- [ ] **Step 2: Create empty Python package markers**

```bash
cat > benchmarks/scripts/__init__.py <<'EOF'
"""Benchmark ingestion and maintenance scripts for screw-agents Phase 0.5."""
EOF

cat > benchmarks/runner/__init__.py <<'EOF'
"""CWE-1400-native benchmark evaluator for screw-agents.

See ADR-013 in docs/DECISIONS.md for the design rationale.
"""
from benchmarks.runner import models, sarif, cwe, metrics, primevul, report  # noqa: F401
EOF

cat > benchmarks/runner/__main__.py <<'EOF'
"""Entry point: python -m benchmarks.runner ..."""
from benchmarks.runner.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
EOF

cat > benchmarks/tests/__init__.py <<'EOF'
"""Meta-tests for benchmarks.runner — verifies the evaluator is correct."""
EOF
```

- [ ] **Step 3: Create pytest conftest with path setup**

```bash
cat > benchmarks/tests/conftest.py <<'EOF'
"""Shared pytest fixtures for benchmark runner tests."""
from pathlib import Path

import pytest


@pytest.fixture
def fixtures_dir() -> Path:
    """Directory containing synthetic SARIF test fixtures."""
    return Path(__file__).parent / "fixtures"
EOF
```

- [ ] **Step 4: Update `.gitignore` with benchmark-specific entries**

Edit `.gitignore` — add after the existing `docs/research/*` block:

```
# Benchmark external datasets (large, downloaded, reproducible from manifests)
benchmarks/external/**
!benchmarks/external/.gitkeep
!benchmarks/external/manifests/
!benchmarks/external/manifests/**

# flawgarden/reality-check vendor clone (pinned via manifest, not tracked)
benchmarks/cve-ingest/
```

- [ ] **Step 5: Update `pyproject.toml` — add pydantic, pytest dev deps, pytest path**

Edit `pyproject.toml`:

1. In `[project]` dependencies, add `"pydantic>=2.0"` after the existing `"pyyaml>=6.0"` line
2. Add a new `[dependency-groups]` section:

```toml
[dependency-groups]
dev = [
    "pytest>=8.0",
    "pytest-cov>=5.0",
]
```

3. Add a `[tool.pytest.ini_options]` section:

```toml
[tool.pytest.ini_options]
pythonpath = [".", "benchmarks"]
testpaths = ["tests", "benchmarks/tests"]
```

- [ ] **Step 6: Run `uv sync` to install pydantic and pytest**

```bash
uv sync
```

Expected: `pydantic`, `pytest`, `pytest-cov` installed. No errors.

- [ ] **Step 7: Verify scaffold with a trivial import test**

```bash
uv run python -c "from benchmarks.runner import models, sarif, cwe, metrics, primevul, report"
```

Expected: `ModuleNotFoundError: No module named 'benchmarks.runner.models'` — this is expected and proves the import path works; the modules don't exist yet (Tasks 4-11 create them). We catch the error inside `__init__.py` later but for now we confirm the path resolves.

Actually, fix `benchmarks/runner/__init__.py` to defer the imports:

```bash
cat > benchmarks/runner/__init__.py <<'EOF'
"""CWE-1400-native benchmark evaluator for screw-agents.

See ADR-013 in docs/DECISIONS.md for the design rationale.

Submodules are loaded lazily to avoid import errors during scaffolding:
    from benchmarks.runner.models import Finding, BenchmarkCase
"""

__version__ = "0.1.0"
EOF
```

Re-run:
```bash
uv run python -c "import benchmarks.runner; print(benchmarks.runner.__version__)"
```

Expected output: `0.1.0`

- [ ] **Step 8: Verify pytest collection**

```bash
uv run pytest benchmarks/tests/ --collect-only
```

Expected: `no tests ran` or `collected 0 items` — no errors, confirms pytest finds the directory.

- [ ] **Step 9: Commit scaffold**

```bash
git add benchmarks/ pyproject.toml .gitignore
git commit -m "Phase 0.5 Task 1: scaffold benchmarks/ tree and tooling"
```

---

## Task 2: Clone `flawgarden/reality-check/scripts/` into `benchmarks/cve-ingest/`

**Files:**
- Create: `benchmarks/cve-ingest/` (vendor clone, not tracked)
- Create: `benchmarks/external/manifests/cve-ingest-pin.json`

**Rationale:** We vendor the Apache-2.0 `reality-check/scripts/` pipeline (per ADR-013) but don't track the clone itself. Instead, we pin to a commit SHA in a manifest so the clone is reproducible.

- [ ] **Step 1: Clone shallow and identify the commit**

```bash
cd /home/marco/Programming/AI/screw-agents
git clone --depth 1 https://github.com/flawgarden/reality-check.git /tmp/reality-check-clone
PINNED_SHA=$(cd /tmp/reality-check-clone && git rev-parse HEAD)
echo "Pinned SHA: $PINNED_SHA"
```

Expected: a 40-char hex SHA printed.

- [ ] **Step 2: Copy only the `scripts/` subdirectory**

```bash
rm -rf benchmarks/cve-ingest
mkdir -p benchmarks/cve-ingest
cp -r /tmp/reality-check-clone/scripts/* benchmarks/cve-ingest/
cp /tmp/reality-check-clone/LICENSE benchmarks/cve-ingest/LICENSE.reality-check
ls benchmarks/cve-ingest/
```

Expected to see: `bootstrap.sh`, `bootstrap_all.sh`, `collect_cve_benchmark.py`, `build_and_clean_benchmark.py`, `markup_benchmark.py`, and related files, plus `LICENSE.reality-check`.

- [ ] **Step 3: Write the pin manifest**

```bash
cat > benchmarks/external/manifests/cve-ingest-pin.json <<EOF
{
  "tool": "flawgarden/reality-check scripts",
  "source_repo": "https://github.com/flawgarden/reality-check",
  "pinned_commit": "$PINNED_SHA",
  "vendored_path": "benchmarks/cve-ingest/",
  "license": "Apache-2.0",
  "license_file": "benchmarks/cve-ingest/LICENSE.reality-check",
  "notes": "Vendor clone of reality-check/scripts/ per ADR-013. Reproduce with: git clone --depth 1 <source_repo> /tmp/c && git -C /tmp/c checkout <pinned_commit> && cp -r /tmp/c/scripts/* benchmarks/cve-ingest/"
}
EOF
```

- [ ] **Step 4: Clean up the temp clone**

```bash
rm -rf /tmp/reality-check-clone
```

- [ ] **Step 5: Verify gitignore correctly excludes the vendor dir**

```bash
git status benchmarks/cve-ingest/ benchmarks/external/manifests/
```

Expected: `benchmarks/cve-ingest/` does NOT appear in git status (gitignored from Task 1). `benchmarks/external/manifests/cve-ingest-pin.json` DOES appear as untracked.

- [ ] **Step 6: Commit the manifest**

```bash
git add benchmarks/external/manifests/cve-ingest-pin.json
git commit -m "Phase 0.5 Task 2: vendor-pin flawgarden/reality-check scripts"
```

---

## Task 3: Extract CWE-1400 hierarchy from MITRE XML → commit YAML

**Files:**
- Create: `benchmarks/scripts/extract_cwe_1400.py`
- Create: `benchmarks/data/cwe-1400-source.xml` (downloaded, committed)
- Create: `benchmarks/data/cwe-1400-hierarchy.yaml` (generated, committed)
- Create: `benchmarks/tests/test_extract_cwe_1400.py`

**Rationale:** Download the MITRE CWE view 1400 XML once, parse it to a YAML hierarchy, and commit both the source XML (audit trail) and the parsed YAML (runtime artifact). The runner loads YAML, never XML. Re-extraction is a conscious one-shot maintenance operation, not a runtime dependency.

- [ ] **Step 1: Write a failing smoke test**

```bash
cat > benchmarks/tests/test_extract_cwe_1400.py <<'EOF'
"""Test the CWE-1400 extraction script produces expected YAML structure."""
from pathlib import Path

import pytest
import yaml


REPO_ROOT = Path(__file__).parent.parent.parent
HIERARCHY_YAML = REPO_ROOT / "benchmarks" / "data" / "cwe-1400-hierarchy.yaml"


def test_hierarchy_yaml_exists():
    """The extracted YAML must be present (committed to the repo)."""
    assert HIERARCHY_YAML.exists(), (
        "Run `python benchmarks/scripts/extract_cwe_1400.py` to regenerate."
    )


def test_hierarchy_contains_phase1_cwes():
    """CWE-1400 view must contain all Phase 1 agent CWEs."""
    data = yaml.safe_load(HIERARCHY_YAML.read_text())
    nodes = data["nodes"]
    for cwe_id in ("CWE-79", "CWE-78", "CWE-89", "CWE-1336"):
        assert cwe_id in nodes, f"{cwe_id} missing from CWE-1400 hierarchy"


def test_hierarchy_has_category_1406():
    """CWE-1406 is the Injection category our Phase 1 agents all live under."""
    data = yaml.safe_load(HIERARCHY_YAML.read_text())
    assert "CWE-1406" in data["nodes"]
    assert data["nodes"]["CWE-1406"]["abstraction"] == "Category"


def test_hierarchy_view_members_listed():
    """Top-level view_members list must contain CWE-1406 (Injection category)."""
    data = yaml.safe_load(HIERARCHY_YAML.read_text())
    assert "CWE-1406" in data["view_members"]
EOF
```

- [ ] **Step 2: Run test to verify it fails**

```bash
uv run pytest benchmarks/tests/test_extract_cwe_1400.py -v
```

Expected: `FAILED ... assert ... HIERARCHY_YAML.exists()`

- [ ] **Step 3: Write the extraction script**

```bash
cat > benchmarks/scripts/extract_cwe_1400.py <<'EOF'
"""Download CWE-1400 view XML from MITRE and emit a YAML hierarchy file.

Run once per CWE release (MITRE updates quarterly). Outputs are committed:
  - benchmarks/data/cwe-1400-source.xml (audit trail)
  - benchmarks/data/cwe-1400-hierarchy.yaml (runtime artifact)

See ADR-013 for why we use CWE-1400 (not CWE-1000).
"""
from __future__ import annotations

import sys
import urllib.request
import xml.etree.ElementTree as ET
import zipfile
from io import BytesIO
from pathlib import Path
from typing import Any

import yaml


CWE_VIEW_URL = "https://cwe.mitre.org/data/xml/views/1400.xml.zip"
REPO_ROOT = Path(__file__).resolve().parent.parent.parent
DATA_DIR = REPO_ROOT / "benchmarks" / "data"
SOURCE_XML = DATA_DIR / "cwe-1400-source.xml"
HIERARCHY_YAML = DATA_DIR / "cwe-1400-hierarchy.yaml"

# CWE XML uses this default namespace
NS = {"cwe": "http://cwe.mitre.org/cwe-7"}


def download_cwe_xml() -> bytes:
    """Fetch the CWE-1400 zipped XML from MITRE and return the inner XML bytes."""
    print(f"Downloading {CWE_VIEW_URL} ...")
    with urllib.request.urlopen(CWE_VIEW_URL) as response:
        zip_bytes = response.read()
    with zipfile.ZipFile(BytesIO(zip_bytes)) as zf:
        xml_name = next(n for n in zf.namelist() if n.endswith(".xml"))
        return zf.read(xml_name)


def parse_cwe_xml(xml_bytes: bytes) -> dict[str, Any]:
    """Parse the CWE XML into a hierarchy dict suitable for YAML serialization."""
    root = ET.fromstring(xml_bytes)

    nodes: dict[str, dict[str, Any]] = {}
    view_members: list[str] = []

    # Parse Weaknesses (base, variant, class entries)
    for weakness in root.iter("{http://cwe.mitre.org/cwe-7}Weakness"):
        cwe_id = f"CWE-{weakness.get('ID')}"
        nodes[cwe_id] = {
            "cwe_id": cwe_id,
            "name": weakness.get("Name", ""),
            "abstraction": weakness.get("Abstraction", ""),
            "parents": [],
            "children": [],
        }
        for rel in weakness.iter("{http://cwe.mitre.org/cwe-7}Related_Weakness"):
            nature = rel.get("Nature", "")
            target_id = f"CWE-{rel.get('CWE_ID')}"
            if nature == "ChildOf":
                nodes[cwe_id]["parents"].append(target_id)
            elif nature == "ParentOf":
                nodes[cwe_id]["children"].append(target_id)

    # Parse Categories (the CWE-14xx grouping entries)
    for cat in root.iter("{http://cwe.mitre.org/cwe-7}Category"):
        cwe_id = f"CWE-{cat.get('ID')}"
        nodes[cwe_id] = {
            "cwe_id": cwe_id,
            "name": cat.get("Name", ""),
            "abstraction": "Category",
            "parents": [],
            "children": [],
        }
        for member in cat.iter("{http://cwe.mitre.org/cwe-7}Has_Member"):
            member_id = f"CWE-{member.get('CWE_ID')}"
            nodes[cwe_id]["children"].append(member_id)
            if member_id in nodes:
                nodes[member_id]["parents"].append(cwe_id)

    # Parse the top-level View for CWE-1400 itself
    for view in root.iter("{http://cwe.mitre.org/cwe-7}View"):
        if view.get("ID") == "1400":
            for member in view.iter("{http://cwe.mitre.org/cwe-7}Has_Member"):
                view_members.append(f"CWE-{member.get('CWE_ID')}")

    return {
        "view_id": "CWE-1400",
        "view_name": "Comprehensive Categorization",
        "source_url": CWE_VIEW_URL,
        "extracted_at": _now_iso(),
        "node_count": len(nodes),
        "view_members": sorted(view_members),
        "nodes": nodes,
    }


def _now_iso() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def main() -> int:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    xml_bytes = download_cwe_xml()
    SOURCE_XML.write_bytes(xml_bytes)
    print(f"Wrote {SOURCE_XML} ({len(xml_bytes):,} bytes)")

    hierarchy = parse_cwe_xml(xml_bytes)
    with HIERARCHY_YAML.open("w") as f:
        yaml.safe_dump(hierarchy, f, sort_keys=False, width=100)
    print(f"Wrote {HIERARCHY_YAML} ({hierarchy['node_count']} nodes, "
          f"{len(hierarchy['view_members'])} view members)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
EOF
```

- [ ] **Step 4: Run the script to download and parse**

```bash
uv run python benchmarks/scripts/extract_cwe_1400.py
```

Expected output includes: `Downloading https://cwe.mitre.org/data/xml/views/1400.xml.zip ...`, `Wrote .../cwe-1400-source.xml`, `Wrote .../cwe-1400-hierarchy.yaml (<N> nodes, <M> view members)`.

If this fails due to network error, retry. If it fails parsing, inspect `cwe-1400-source.xml` and adjust the namespace URI (MITRE occasionally bumps the minor version).

- [ ] **Step 5: Verify the YAML contents**

```bash
uv run python -c "
import yaml
from pathlib import Path
data = yaml.safe_load(Path('benchmarks/data/cwe-1400-hierarchy.yaml').read_text())
print('Nodes:', data['node_count'])
print('View members:', len(data['view_members']))
print('CWE-79 present:', 'CWE-79' in data['nodes'])
print('CWE-78 present:', 'CWE-78' in data['nodes'])
print('CWE-89 present:', 'CWE-89' in data['nodes'])
print('CWE-1336 present:', 'CWE-1336' in data['nodes'])
print('CWE-1406 present:', 'CWE-1406' in data['nodes'])
"
```

Expected: all four Phase 1 CWEs and CWE-1406 present.

- [ ] **Step 6: Re-run the test — should now pass**

```bash
uv run pytest benchmarks/tests/test_extract_cwe_1400.py -v
```

Expected: all 4 tests PASS.

- [ ] **Step 7: Commit the extraction script and its output**

```bash
git add benchmarks/scripts/extract_cwe_1400.py benchmarks/data/cwe-1400-source.xml benchmarks/data/cwe-1400-hierarchy.yaml benchmarks/tests/test_extract_cwe_1400.py
git commit -m "Phase 0.5 Task 3: extract CWE-1400 hierarchy from MITRE XML"
```

---

## Task 4: Pydantic models (`benchmarks/runner/models.py`)

**Files:**
- Create: `benchmarks/runner/models.py`
- Create: `benchmarks/tests/test_models.py`

**Rationale:** A single source-of-truth for all the types the rest of the runner passes around. Defining them upfront (before sarif/cwe/metrics/primevul modules) prevents the type-drift problem the writing-plans skill warns about.

- [ ] **Step 1: Write failing tests for the core types**

```bash
cat > benchmarks/tests/test_models.py <<'EOF'
"""Unit tests for benchmarks.runner.models — typed domain objects."""
from datetime import date

import pytest
from pydantic import ValidationError

from benchmarks.runner.models import (
    AgentRun,
    BenchmarkCase,
    CodeLocation,
    Finding,
    FindingKind,
    Language,
    MetricSet,
    Summary,
)


def test_code_location_requires_file_and_lines():
    loc = CodeLocation(file="src/api.py", start_line=10, end_line=20)
    assert loc.file == "src/api.py"
    assert loc.start_line == 10
    assert loc.end_line == 20
    assert loc.function_name is None


def test_finding_kind_is_constrained_enum():
    with pytest.raises(ValidationError):
        Finding(
            cwe_id="CWE-89",
            kind="maybe",  # invalid — must be fail or pass
            location=CodeLocation(file="x", start_line=1, end_line=1),
        )


def test_finding_accepts_fail_and_pass():
    Finding(cwe_id="CWE-89", kind=FindingKind.FAIL,
            location=CodeLocation(file="x", start_line=1, end_line=1))
    Finding(cwe_id="CWE-89", kind=FindingKind.PASS,
            location=CodeLocation(file="x", start_line=1, end_line=1))


def test_benchmark_case_pair_has_both_kinds():
    case = BenchmarkCase(
        case_id="test-1",
        project="acme/widget",
        language=Language.PYTHON,
        vulnerable_version="1.0.0",
        patched_version="1.0.1",
        ground_truth=[
            Finding(cwe_id="CWE-89", kind=FindingKind.FAIL,
                    location=CodeLocation(file="src/db.py", start_line=10, end_line=12)),
            Finding(cwe_id="CWE-89", kind=FindingKind.PASS,
                    location=CodeLocation(file="src/db.py", start_line=10, end_line=14)),
        ],
        published_date=date(2024, 5, 1),
        source_dataset="reality-check",
    )
    assert len(case.ground_truth) == 2
    kinds = {f.kind for f in case.ground_truth}
    assert kinds == {FindingKind.FAIL, FindingKind.PASS}


def test_metric_set_accuracy_formula():
    m = MetricSet(
        agent_name="xss",
        dataset="ossf-cve-benchmark",
        cwe_id="CWE-79",
        language=Language.JAVASCRIPT,
        true_positives=15, false_positives=3, true_negatives=12, false_negatives=5,
        tpr=0.75, fpr=0.20,
        precision=0.833, f1=0.789, accuracy=0.55,
    )
    assert round(m.accuracy, 3) == 0.550
    assert m.tpr - m.fpr == pytest.approx(m.accuracy, abs=0.001)


def test_summary_round_trips_json():
    summary = Summary(
        run_id="test-run",
        agent_name="xss",
        dataset="ossf-cve-benchmark",
        methodology={"dedup": True, "chrono_split": True, "pair_based": True},
        metrics=[],
        generated_at="2026-04-09T12:00:00Z",
    )
    js = summary.model_dump_json()
    restored = Summary.model_validate_json(js)
    assert restored.run_id == "test-run"
EOF
```

- [ ] **Step 2: Run the tests — verify they fail with `ModuleNotFoundError`**

```bash
uv run pytest benchmarks/tests/test_models.py -v
```

Expected: `ModuleNotFoundError: No module named 'benchmarks.runner.models'`

- [ ] **Step 3: Write the models module**

```bash
cat > benchmarks/runner/models.py <<'EOF'
"""Typed domain objects for the screw-agents benchmark runner.

Every type the runner passes between modules is defined here. Keep this file
SMALL and authoritative — other modules import from here, they do not define
their own domain types.

See ADR-013 for design rationale.
"""
from __future__ import annotations

from datetime import date
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class Language(str, Enum):
    PYTHON = "python"
    JAVASCRIPT = "javascript"
    TYPESCRIPT = "typescript"
    JAVA = "java"
    GO = "go"
    RUBY = "ruby"
    PHP = "php"
    CSHARP = "csharp"
    RUST = "rust"
    C = "c"
    CPP = "cpp"


class FindingKind(str, Enum):
    """Whether a finding indicates a vulnerable code point (fail) or a safe
    one (pass).

    From bentoo-sarif: kind=fail marks the vulnerable method in the vulnerable
    version of a project. kind=pass marks the same location in the patched
    version — a true-positive agent MUST find kind=fail findings and MUST NOT
    flag kind=pass findings at the same location.
    """
    FAIL = "fail"
    PASS = "pass"


class CodeLocation(BaseModel):
    """A region of source code. Bentoo-sarif is method-granular."""
    file: str
    start_line: int
    end_line: int
    function_name: str | None = None


class Finding(BaseModel):
    """A single vulnerability finding — from ground truth OR from an agent."""
    cwe_id: str              # e.g., "CWE-89"
    kind: FindingKind
    location: CodeLocation
    cve_id: str | None = None          # e.g., "CVE-2024-12345"
    agent_name: str | None = None      # None for ground truth
    confidence: float | None = None    # None for ground truth; 0.0-1.0 otherwise
    message: str | None = None


class BenchmarkCase(BaseModel):
    """One entry in a benchmark — pairs a vulnerable and patched version."""
    case_id: str                       # stable across runs, e.g., "ossf-lodash-CVE-2018-16487"
    project: str                       # e.g., "lodash/lodash"
    language: Language
    vulnerable_version: str
    patched_version: str
    ground_truth: list[Finding]        # kind=fail for vuln, kind=pass for patched
    published_date: date | None = None  # For chronological splits
    source_dataset: str                # e.g., "ossf-cve-benchmark", "reality-check"


class AgentRun(BaseModel):
    """An agent's findings on one benchmark case."""
    case_id: str
    agent_name: str
    findings: list[Finding]
    runtime_seconds: float


class MetricSet(BaseModel):
    """Per-(agent, dataset, CWE, language) metrics.

    Multiple MetricSet entries roll up a single Summary — one for the overall
    result, one per CWE, one per language, and optional cross-dimensions.
    """
    agent_name: str
    dataset: str
    cwe_id: str | None = None          # None = aggregate across all CWEs
    language: Language | None = None   # None = aggregate across all languages

    true_positives: int
    false_positives: int
    true_negatives: int
    false_negatives: int

    tpr: float                         # recall on vulnerable versions
    fpr: float                         # false positive rate on patched versions
    precision: float
    f1: float
    accuracy: float                    # TPR - FPR (standard SAST benchmark metric per ADR-013)


class Summary(BaseModel):
    """Top-level benchmark run output. Schema is bentoo-compatible."""
    run_id: str                        # e.g., "20260409-093215"
    agent_name: str
    dataset: str
    methodology: dict[str, Any]        # {"dedup": bool, "chrono_split": bool, "pair_based": bool, ...}
    metrics: list[MetricSet]
    generated_at: str                  # ISO 8601 UTC
EOF
```

- [ ] **Step 4: Re-run tests — expect all to pass**

```bash
uv run pytest benchmarks/tests/test_models.py -v
```

Expected: 6 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add benchmarks/runner/models.py benchmarks/tests/test_models.py
git commit -m "Phase 0.5 Task 4: Pydantic models for runner (Finding, BenchmarkCase, MetricSet, Summary)"
```

---

## Task 5: bentoo-sarif parser (`benchmarks/runner/sarif.py`)

**Files:**
- Create: `benchmarks/runner/sarif.py`
- Create: `benchmarks/tests/test_sarif.py`
- Create: `benchmarks/tests/fixtures/mini_truth.sarif` (hand-authored)

**Rationale:** bentoo-sarif is plain SARIF 2.1.0 with a minimal subset: `runs[0].results[*]` each with `ruleId`, `kind` (fail/pass), `message.text`, `locations[*].physicalLocation.{artifactLocation.uri, region.{startLine, endLine}}`, optional `locations[*].logicalLocations[*].name`. Parse and emit with the stdlib `json` module + pydantic models, no external SARIF library.

- [ ] **Step 1: Create a synthetic ground-truth fixture**

```bash
cat > benchmarks/tests/fixtures/mini_truth.sarif <<'EOF'
{
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
  "version": "2.1.0",
  "runs": [
    {
      "tool": {"driver": {"name": "screw-agents-mini-benchmark"}},
      "results": [
        {
          "kind": "fail",
          "message": {"text": "CVE-2024-99999"},
          "ruleId": "CWE-89",
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": {"uri": "src/api/users.py"},
                "region": {"startLine": 42, "endLine": 50}
              },
              "logicalLocations": [{"name": "get_user_by_id", "kind": "function"}]
            }
          ]
        },
        {
          "kind": "pass",
          "message": {"text": "CVE-2024-99999"},
          "ruleId": "CWE-89",
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": {"uri": "src/api/users.py"},
                "region": {"startLine": 42, "endLine": 54}
              },
              "logicalLocations": [{"name": "get_user_by_id", "kind": "function"}]
            }
          ]
        },
        {
          "kind": "fail",
          "message": {"text": "CVE-2024-99998"},
          "ruleId": "CWE-79",
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": {"uri": "src/views/profile.py"},
                "region": {"startLine": 100, "endLine": 115}
              },
              "logicalLocations": [{"name": "render_profile", "kind": "function"}]
            }
          ]
        }
      ]
    }
  ]
}
EOF
```

- [ ] **Step 2: Write failing tests**

```bash
cat > benchmarks/tests/test_sarif.py <<'EOF'
"""Tests for benchmarks.runner.sarif — bentoo-sarif round-trip."""
import json
from pathlib import Path

import pytest

from benchmarks.runner.models import CodeLocation, Finding, FindingKind
from benchmarks.runner.sarif import load_bentoo_sarif, write_bentoo_sarif


def test_load_mini_truth_returns_three_findings(fixtures_dir: Path):
    findings = load_bentoo_sarif(fixtures_dir / "mini_truth.sarif")
    assert len(findings) == 3


def test_load_preserves_cwe_and_kind(fixtures_dir: Path):
    findings = load_bentoo_sarif(fixtures_dir / "mini_truth.sarif")
    cwes = {f.cwe_id for f in findings}
    kinds = [f.kind for f in findings]
    assert cwes == {"CWE-89", "CWE-79"}
    assert kinds.count(FindingKind.FAIL) == 2
    assert kinds.count(FindingKind.PASS) == 1


def test_load_extracts_file_lines_and_function(fixtures_dir: Path):
    findings = load_bentoo_sarif(fixtures_dir / "mini_truth.sarif")
    sqli_fail = next(f for f in findings if f.cwe_id == "CWE-89" and f.kind == FindingKind.FAIL)
    assert sqli_fail.location.file == "src/api/users.py"
    assert sqli_fail.location.start_line == 42
    assert sqli_fail.location.end_line == 50
    assert sqli_fail.location.function_name == "get_user_by_id"
    assert sqli_fail.cve_id == "CVE-2024-99999"


def test_load_rejects_missing_rule_id(fixtures_dir: Path, tmp_path: Path):
    bad = tmp_path / "bad.sarif"
    bad.write_text(json.dumps({
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "t"}},
                  "results": [{"kind": "fail", "message": {"text": "x"}, "locations": []}]}]
    }))
    with pytest.raises(ValueError, match="ruleId"):
        load_bentoo_sarif(bad)


def test_write_then_load_round_trips(tmp_path: Path):
    original = [
        Finding(cwe_id="CWE-78", kind=FindingKind.FAIL,
                location=CodeLocation(file="a.py", start_line=1, end_line=2, function_name="f"),
                cve_id="CVE-2024-1"),
        Finding(cwe_id="CWE-78", kind=FindingKind.PASS,
                location=CodeLocation(file="a.py", start_line=1, end_line=3, function_name="f"),
                cve_id="CVE-2024-1"),
    ]
    out = tmp_path / "roundtrip.sarif"
    write_bentoo_sarif(out, original, tool_name="test-driver")
    loaded = load_bentoo_sarif(out)
    assert len(loaded) == 2
    assert loaded[0].cwe_id == "CWE-78"
    assert loaded[0].kind == FindingKind.FAIL
    assert loaded[1].kind == FindingKind.PASS
EOF
```

- [ ] **Step 3: Run tests — verify import failure**

```bash
uv run pytest benchmarks/tests/test_sarif.py -v
```

Expected: `ModuleNotFoundError: No module named 'benchmarks.runner.sarif'`

- [ ] **Step 4: Write the sarif module**

```bash
cat > benchmarks/runner/sarif.py <<'EOF'
"""bentoo-sarif read/write.

bentoo-sarif is plain SARIF 2.1.0 with a minimal subset:
    runs[0].results[*] each with:
        ruleId       — "CWE-<id>"
        kind         — "fail" or "pass"
        message.text — CVE ID or free-form
        locations[*].physicalLocation.artifactLocation.uri
        locations[*].physicalLocation.region.{startLine, endLine}
        locations[*].logicalLocations[*].name   (function name, optional)

We parse/emit with stdlib json + pydantic models, no external SARIF library
(sarif-om on PyPI is unmaintained; hand-roll is 120 lines).
"""
from __future__ import annotations

import json
from pathlib import Path

from benchmarks.runner.models import CodeLocation, Finding, FindingKind


def load_bentoo_sarif(path: Path) -> list[Finding]:
    """Parse a bentoo-sarif file into a flat list of Finding objects.

    Raises ValueError on malformed input (missing ruleId, unknown kind, etc.).
    """
    raw = json.loads(Path(path).read_text())
    findings: list[Finding] = []
    runs = raw.get("runs", [])
    for run in runs:
        for result in run.get("results", []):
            findings.extend(_result_to_findings(result))
    return findings


def _result_to_findings(result: dict) -> list[Finding]:
    """Convert one SARIF result (may have multiple locations) to Findings."""
    rule_id = result.get("ruleId")
    if not rule_id:
        raise ValueError("SARIF result missing ruleId")
    kind_str = result.get("kind", "fail")
    try:
        kind = FindingKind(kind_str)
    except ValueError as exc:
        raise ValueError(f"Unknown SARIF kind: {kind_str!r}") from exc

    message_text = result.get("message", {}).get("text", "")
    cve_id = message_text if message_text.startswith("CVE-") else None

    findings: list[Finding] = []
    for loc in result.get("locations", []):
        phys = loc.get("physicalLocation", {})
        art = phys.get("artifactLocation", {})
        region = phys.get("region", {})
        logical = loc.get("logicalLocations") or []
        function_name = logical[0].get("name") if logical else None

        findings.append(Finding(
            cwe_id=rule_id,
            kind=kind,
            cve_id=cve_id,
            message=message_text or None,
            location=CodeLocation(
                file=art.get("uri", "<unknown>"),
                start_line=int(region.get("startLine", 0)),
                end_line=int(region.get("endLine", region.get("startLine", 0))),
                function_name=function_name,
            ),
        ))
    return findings


def write_bentoo_sarif(
    path: Path,
    findings: list[Finding],
    *,
    tool_name: str = "screw-agents",
) -> None:
    """Serialize Findings as a bentoo-sarif document."""
    results = [_finding_to_result(f) for f in findings]
    doc = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": tool_name}},
                "results": results,
            }
        ],
    }
    Path(path).write_text(json.dumps(doc, indent=2))


def _finding_to_result(f: Finding) -> dict:
    logical = []
    if f.location.function_name:
        logical.append({"name": f.location.function_name, "kind": "function"})
    result = {
        "kind": f.kind.value,
        "message": {"text": f.message or f.cve_id or ""},
        "ruleId": f.cwe_id,
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": f.location.file},
                    "region": {
                        "startLine": f.location.start_line,
                        "endLine": f.location.end_line,
                    },
                },
                **({"logicalLocations": logical} if logical else {}),
            }
        ],
    }
    return result
EOF
```

- [ ] **Step 5: Run tests — verify all pass**

```bash
uv run pytest benchmarks/tests/test_sarif.py -v
```

Expected: 5 tests PASS.

- [ ] **Step 6: Verify round-trip against a real flawgarden truth.sarif**

If you have `benchmarks/cve-ingest/` populated from Task 2, you can cross-check against a real file. This is optional validation:

```bash
uv run python -c "
from pathlib import Path
from benchmarks.runner.sarif import load_bentoo_sarif
# Find any truth.sarif from reality-check
for p in Path('benchmarks/cve-ingest').rglob('truth.sarif'):
    fs = load_bentoo_sarif(p)
    print(f'{p}: {len(fs)} findings, CWEs={sorted({f.cwe_id for f in fs})}')
    break
else:
    print('No real truth.sarif available yet — skipped.')
"
```

- [ ] **Step 7: Commit**

```bash
git add benchmarks/runner/sarif.py benchmarks/tests/test_sarif.py benchmarks/tests/fixtures/mini_truth.sarif
git commit -m "Phase 0.5 Task 5: bentoo-sarif parser with round-trip tests"
```

---

## Task 6: CWE-1400 hierarchy traversal (`benchmarks/runner/cwe.py`)

**Files:**
- Create: `benchmarks/runner/cwe.py`
- Create: `benchmarks/tests/test_cwe.py`

**Rationale:** The metrics module (Task 7) needs two distinct CWE comparison modes per ADR-013: **strict** (exact match or agent_cwe is a descendant of truth_cwe) and **broad** (both CWEs share a CWE-1400 category ancestor). This module loads `benchmarks/data/cwe-1400-hierarchy.yaml` once and exposes traversal helpers.

- [ ] **Step 1: Write failing tests**

```bash
cat > benchmarks/tests/test_cwe.py <<'EOF'
"""Tests for benchmarks.runner.cwe — CWE-1400 hierarchy traversal."""
import pytest

from benchmarks.runner.cwe import Cwe1400Hierarchy, load_hierarchy


@pytest.fixture(scope="module")
def hierarchy() -> Cwe1400Hierarchy:
    return load_hierarchy()


def test_phase1_cwes_present(hierarchy: Cwe1400Hierarchy):
    for cwe in ("CWE-79", "CWE-78", "CWE-89", "CWE-1336"):
        assert cwe in hierarchy.nodes, f"{cwe} missing from hierarchy"


def test_category_1406_has_injection_children(hierarchy: Cwe1400Hierarchy):
    assert "CWE-1406" in hierarchy.nodes
    cat = hierarchy.nodes["CWE-1406"]
    assert cat.abstraction == "Category"
    # CWE-1406 "Injection" is the parent category; should reach CWE-79/78/89 via descendants
    descendants = hierarchy.descendants_of("CWE-1406")
    assert "CWE-74" in descendants or "CWE-79" in descendants, \
        "Expected CWE-1406 to reach injection CWEs transitively"


def test_broad_match_same_category(hierarchy: Cwe1400Hierarchy):
    """CWE-79 and CWE-89 are both in the injection category — broad match."""
    assert hierarchy.broad_match("CWE-79", "CWE-89") is True


def test_broad_match_different_category(hierarchy: Cwe1400Hierarchy):
    """CWE-79 (injection) and CWE-327 (crypto) should NOT broad-match."""
    if "CWE-327" in hierarchy.nodes:
        assert hierarchy.broad_match("CWE-79", "CWE-327") is False


def test_strict_match_exact(hierarchy: Cwe1400Hierarchy):
    assert hierarchy.strict_match("CWE-89", "CWE-89") is True


def test_strict_match_descendant(hierarchy: Cwe1400Hierarchy):
    """CWE-564 (Hibernate SQLi) is a variant of CWE-89 — agent CWE-89 strict-
    matches truth CWE-564 (agent is equal-or-more-general)? No: strict means
    agent CWE must be equal or MORE specific than truth. CWE-89 is less
    specific than CWE-564, so this should NOT match."""
    if "CWE-564" in hierarchy.nodes:
        # agent=CWE-564 (more specific) vs truth=CWE-89 (parent) — matches
        assert hierarchy.strict_match(agent_cwe="CWE-564", truth_cwe="CWE-89") is True
        # agent=CWE-89 (parent) vs truth=CWE-564 (child) — does NOT match
        assert hierarchy.strict_match(agent_cwe="CWE-89", truth_cwe="CWE-564") is False


def test_unknown_cwe_returns_false(hierarchy: Cwe1400Hierarchy):
    assert hierarchy.broad_match("CWE-999999", "CWE-89") is False
    assert hierarchy.strict_match("CWE-999999", "CWE-89") is False


def test_category_of_phase1_cwes(hierarchy: Cwe1400Hierarchy):
    """All four Phase 1 CWEs should resolve to a CWE-14xx category."""
    for cwe in ("CWE-79", "CWE-78", "CWE-89", "CWE-1336"):
        cat = hierarchy.category_of(cwe)
        assert cat is not None, f"{cwe} has no CWE-1400 category"
        assert cat.startswith("CWE-14"), f"{cwe} category {cat} is not CWE-14xx"
EOF
```

- [ ] **Step 2: Run tests — verify import failure**

```bash
uv run pytest benchmarks/tests/test_cwe.py -v
```

Expected: `ModuleNotFoundError: No module named 'benchmarks.runner.cwe'`

- [ ] **Step 3: Write the cwe module**

```bash
cat > benchmarks/runner/cwe.py <<'EOF'
"""CWE-1400 hierarchy traversal for the benchmark evaluator.

Loads `benchmarks/data/cwe-1400-hierarchy.yaml` (extracted from MITRE XML by
scripts/extract_cwe_1400.py) and exposes two comparison modes:

  strict_match(agent_cwe, truth_cwe) -- True if agent_cwe == truth_cwe OR
                                        agent_cwe is a descendant of truth_cwe.
                                        I.e., the agent reported the same-or-
                                        more-specific CWE.

  broad_match(agent_cwe, truth_cwe)  -- True if both CWEs share a CWE-1400
                                        category (CWE-14xx) ancestor.
                                        I.e., the agent is at least in the
                                        right general class.

See ADR-013 for why we use CWE-1400 (not CWE-1000 as bentoo does).
"""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Iterable

import yaml
from pydantic import BaseModel, Field


REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_HIERARCHY_PATH = REPO_ROOT / "benchmarks" / "data" / "cwe-1400-hierarchy.yaml"


class CweNode(BaseModel):
    cwe_id: str
    name: str
    abstraction: str  # "Base", "Variant", "Class", "Category"
    parents: list[str] = Field(default_factory=list)
    children: list[str] = Field(default_factory=list)


class Cwe1400Hierarchy(BaseModel):
    """In-memory CWE-1400 hierarchy with traversal helpers."""
    view_id: str
    view_name: str
    nodes: dict[str, CweNode]
    view_members: list[str]

    def ancestors_of(self, cwe_id: str) -> set[str]:
        """All transitive parents of cwe_id (not including cwe_id itself)."""
        seen: set[str] = set()
        stack = [cwe_id]
        while stack:
            current = stack.pop()
            node = self.nodes.get(current)
            if node is None:
                continue
            for p in node.parents:
                if p not in seen:
                    seen.add(p)
                    stack.append(p)
        return seen

    def descendants_of(self, cwe_id: str) -> set[str]:
        """All transitive children of cwe_id (not including cwe_id itself)."""
        seen: set[str] = set()
        stack = [cwe_id]
        while stack:
            current = stack.pop()
            node = self.nodes.get(current)
            if node is None:
                continue
            for c in node.children:
                if c not in seen:
                    seen.add(c)
                    stack.append(c)
        return seen

    def category_of(self, cwe_id: str) -> str | None:
        """Return the first CWE-14xx category ancestor of cwe_id, or None.

        Walks ancestors breadth-first and returns the first one whose abstraction
        is 'Category' AND whose ID is in the CWE-1400 view members list.
        """
        if cwe_id not in self.nodes:
            return None
        if self._is_view_category(cwe_id):
            return cwe_id
        # BFS through ancestors
        queue = list(self.nodes[cwe_id].parents)
        seen = set(queue)
        while queue:
            current = queue.pop(0)
            if self._is_view_category(current):
                return current
            node = self.nodes.get(current)
            if node is None:
                continue
            for p in node.parents:
                if p not in seen:
                    seen.add(p)
                    queue.append(p)
        return None

    def _is_view_category(self, cwe_id: str) -> bool:
        node = self.nodes.get(cwe_id)
        return (
            node is not None
            and node.abstraction == "Category"
            and cwe_id in self.view_members
        )

    def strict_match(self, agent_cwe: str, truth_cwe: str) -> bool:
        """True if agent_cwe == truth_cwe OR agent_cwe is a descendant of truth_cwe.

        Semantics: the agent reported an equal-or-more-specific CWE than the
        ground truth. E.g., truth=CWE-89 (SQLi), agent=CWE-564 (Hibernate
        SQLi, a variant of CWE-89) — strict match True.
        """
        if agent_cwe not in self.nodes or truth_cwe not in self.nodes:
            return False
        if agent_cwe == truth_cwe:
            return True
        return agent_cwe in self.descendants_of(truth_cwe)

    def broad_match(self, agent_cwe: str, truth_cwe: str) -> bool:
        """True if both CWEs share a CWE-1400 category (CWE-14xx) ancestor."""
        if agent_cwe not in self.nodes or truth_cwe not in self.nodes:
            return False
        agent_cat = self.category_of(agent_cwe)
        truth_cat = self.category_of(truth_cwe)
        if agent_cat is None or truth_cat is None:
            return False
        return agent_cat == truth_cat


@lru_cache(maxsize=1)
def load_hierarchy(path: Path | None = None) -> Cwe1400Hierarchy:
    """Load CWE-1400 hierarchy YAML. Cached — loads once per process."""
    yaml_path = Path(path) if path else DEFAULT_HIERARCHY_PATH
    data = yaml.safe_load(yaml_path.read_text())
    return Cwe1400Hierarchy.model_validate(data)
EOF
```

- [ ] **Step 4: Run tests — verify all pass**

```bash
uv run pytest benchmarks/tests/test_cwe.py -v
```

Expected: 8 tests PASS. If `test_category_of_phase1_cwes` fails because a Phase 1 CWE doesn't resolve to a CWE-14xx category, inspect the hierarchy YAML — it may indicate the MITRE XML structure changed. The fix is usually to adjust the parent walk order.

- [ ] **Step 5: Commit**

```bash
git add benchmarks/runner/cwe.py benchmarks/tests/test_cwe.py
git commit -m "Phase 0.5 Task 6: CWE-1400 hierarchy traversal with strict/broad match"
```

---

## Task 7: Metrics computation (`benchmarks/runner/metrics.py`)

**Files:**
- Create: `benchmarks/runner/metrics.py`
- Create: `benchmarks/tests/test_metrics.py`

**Rationale:** Given a list of `BenchmarkCase` (ground truth) and a list of `AgentRun` (agent findings), compute per-CWE per-language MetricSet entries plus an aggregate rollup. ADR-013 mandates TPR/FPR/precision/recall/F1/accuracy in CWE-1400 semantics.

**Scoring semantics (critical — pair-based per PRD §11.3):**

For each `BenchmarkCase` there's a vulnerable version and a patched version. Ground truth has `kind=fail` findings at the vulnerable location and `kind=pass` findings at the same location on the patched version.

- **TP (true positive):** Agent flags a `kind=fail` location on the vulnerable version AND does NOT flag the same location on the patched version. (Pair-based — both halves required.)
- **FP (false positive):** Agent flags a `kind=pass` location on the patched version, OR flags a location on the vulnerable version that doesn't correspond to any `kind=fail` ground truth.
- **TN (true negative):** Agent does NOT flag a `kind=pass` location on the patched version.
- **FN (false negative):** Agent does NOT flag a `kind=fail` location on the vulnerable version.

A location "matches" when: (a) same file URI, (b) start_line overlap ≥1 line, (c) `strict_match` OR `broad_match` on the CWE (configurable).

- [ ] **Step 1: Write failing tests**

```bash
cat > benchmarks/tests/test_metrics.py <<'EOF'
"""Tests for benchmarks.runner.metrics — pair-based TPR/FPR/precision."""
from datetime import date

import pytest

from benchmarks.runner.cwe import load_hierarchy
from benchmarks.runner.metrics import compute_metrics, locations_match
from benchmarks.runner.models import (
    AgentRun,
    BenchmarkCase,
    CodeLocation,
    Finding,
    FindingKind,
    Language,
)


@pytest.fixture
def hierarchy():
    return load_hierarchy()


def _make_case(case_id: str, cwe: str, file: str, lines: tuple[int, int]) -> BenchmarkCase:
    return BenchmarkCase(
        case_id=case_id,
        project="test/project",
        language=Language.PYTHON,
        vulnerable_version="1.0.0",
        patched_version="1.0.1",
        ground_truth=[
            Finding(cwe_id=cwe, kind=FindingKind.FAIL,
                    location=CodeLocation(file=file, start_line=lines[0], end_line=lines[1])),
            Finding(cwe_id=cwe, kind=FindingKind.PASS,
                    location=CodeLocation(file=file, start_line=lines[0], end_line=lines[1] + 2)),
        ],
        published_date=date(2024, 1, 1),
        source_dataset="test",
    )


def _agent_find(case_id: str, cwe: str, file: str, lines: tuple[int, int], agent: str = "test") -> Finding:
    # A single agent Finding — does NOT have a kind attached because agents don't
    # know vulnerable vs patched; the metrics module decides based on which
    # version the agent was running on.
    return Finding(
        cwe_id=cwe, kind=FindingKind.FAIL, agent_name=agent, confidence=0.9,
        location=CodeLocation(file=file, start_line=lines[0], end_line=lines[1]),
    )


def test_perfect_agent_all_true_positives(hierarchy):
    cases = [_make_case("c1", "CWE-89", "a.py", (10, 15))]
    # Agent runs on vulnerable version — flags c1's FAIL location
    runs_vuln = [AgentRun(case_id="c1", agent_name="perfect",
                          findings=[_agent_find("c1", "CWE-89", "a.py", (10, 15))],
                          runtime_seconds=0.1)]
    # Agent runs on patched version — flags NOTHING
    runs_patched = [AgentRun(case_id="c1", agent_name="perfect",
                             findings=[], runtime_seconds=0.1)]
    summary = compute_metrics(cases, runs_vuln, runs_patched, hierarchy,
                              agent_name="perfect", dataset="test")
    overall = next(m for m in summary.metrics if m.cwe_id is None and m.language is None)
    assert overall.true_positives == 1
    assert overall.false_positives == 0
    assert overall.false_negatives == 0
    assert overall.tpr == 1.0
    assert overall.fpr == 0.0


def test_missed_vulnerability_counts_false_negative(hierarchy):
    cases = [_make_case("c1", "CWE-89", "a.py", (10, 15))]
    runs_vuln = [AgentRun(case_id="c1", agent_name="blind", findings=[], runtime_seconds=0.1)]
    runs_patched = [AgentRun(case_id="c1", agent_name="blind", findings=[], runtime_seconds=0.1)]
    summary = compute_metrics(cases, runs_vuln, runs_patched, hierarchy,
                              agent_name="blind", dataset="test")
    overall = next(m for m in summary.metrics if m.cwe_id is None and m.language is None)
    assert overall.true_positives == 0
    assert overall.false_negatives == 1
    assert overall.tpr == 0.0


def test_flagging_patched_counts_false_positive(hierarchy):
    cases = [_make_case("c1", "CWE-89", "a.py", (10, 15))]
    # Agent flags BOTH vulnerable AND patched at the same location
    runs_vuln = [AgentRun(case_id="c1", agent_name="noisy",
                          findings=[_agent_find("c1", "CWE-89", "a.py", (10, 15))],
                          runtime_seconds=0.1)]
    runs_patched = [AgentRun(case_id="c1", agent_name="noisy",
                             findings=[_agent_find("c1", "CWE-89", "a.py", (10, 15))],
                             runtime_seconds=0.1)]
    summary = compute_metrics(cases, runs_vuln, runs_patched, hierarchy,
                              agent_name="noisy", dataset="test")
    overall = next(m for m in summary.metrics if m.cwe_id is None and m.language is None)
    # Pair-based: NOT a TP because patched also flagged
    assert overall.true_positives == 0
    assert overall.false_positives == 1
    assert overall.false_negatives == 1  # vulnerable version was missed as a pair


def test_wrong_file_not_a_match(hierarchy):
    cases = [_make_case("c1", "CWE-89", "a.py", (10, 15))]
    runs_vuln = [AgentRun(case_id="c1", agent_name="confused",
                          findings=[_agent_find("c1", "CWE-89", "b.py", (10, 15))],
                          runtime_seconds=0.1)]
    runs_patched = [AgentRun(case_id="c1", agent_name="confused",
                             findings=[], runtime_seconds=0.1)]
    summary = compute_metrics(cases, runs_vuln, runs_patched, hierarchy,
                              agent_name="confused", dataset="test")
    overall = next(m for m in summary.metrics if m.cwe_id is None and m.language is None)
    assert overall.true_positives == 0
    assert overall.false_positives == 1  # flagged b.py — a spurious location
    assert overall.false_negatives == 1  # missed a.py


def test_locations_match_line_overlap():
    a = CodeLocation(file="x.py", start_line=10, end_line=20)
    b = CodeLocation(file="x.py", start_line=15, end_line=25)
    assert locations_match(a, b) is True

    c = CodeLocation(file="x.py", start_line=30, end_line=40)
    assert locations_match(a, c) is False

    d = CodeLocation(file="y.py", start_line=10, end_line=20)
    assert locations_match(a, d) is False


def test_per_cwe_breakdown(hierarchy):
    cases = [
        _make_case("c1", "CWE-89", "a.py", (10, 15)),
        _make_case("c2", "CWE-79", "b.py", (30, 40)),
    ]
    # Perfect on SQLi, miss XSS
    runs_vuln = [
        AgentRun(case_id="c1", agent_name="a", runtime_seconds=0.1,
                 findings=[_agent_find("c1", "CWE-89", "a.py", (10, 15))]),
        AgentRun(case_id="c2", agent_name="a", runtime_seconds=0.1, findings=[]),
    ]
    runs_patched = [
        AgentRun(case_id="c1", agent_name="a", runtime_seconds=0.1, findings=[]),
        AgentRun(case_id="c2", agent_name="a", runtime_seconds=0.1, findings=[]),
    ]
    summary = compute_metrics(cases, runs_vuln, runs_patched, hierarchy,
                              agent_name="a", dataset="test")
    cwe89 = next(m for m in summary.metrics if m.cwe_id == "CWE-89" and m.language is None)
    cwe79 = next(m for m in summary.metrics if m.cwe_id == "CWE-79" and m.language is None)
    assert cwe89.tpr == 1.0
    assert cwe79.tpr == 0.0
EOF
```

- [ ] **Step 2: Run tests — verify import failure**

```bash
uv run pytest benchmarks/tests/test_metrics.py -v
```

Expected: `ModuleNotFoundError: No module named 'benchmarks.runner.metrics'`

- [ ] **Step 3: Write the metrics module**

```bash
cat > benchmarks/runner/metrics.py <<'EOF'
"""Pair-based TPR/FPR/precision/recall/F1/accuracy computation.

Scoring semantics per ADR-013 and PRD §11.3:

For each BenchmarkCase, the agent is run TWICE — once on the vulnerable
version, once on the patched version. A finding is only counted as a TRUE
POSITIVE if the agent flagged the vulnerable location AND did NOT flag the
same location on the patched version.

This prevents the common failure mode where an SAST tool is not
"vulnerability-sensitive" (it flags the same pattern in both versions).
"""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
from typing import Iterable

from benchmarks.runner.cwe import Cwe1400Hierarchy
from benchmarks.runner.models import (
    AgentRun,
    BenchmarkCase,
    CodeLocation,
    Finding,
    FindingKind,
    Language,
    MetricSet,
    Summary,
)


def locations_match(a: CodeLocation, b: CodeLocation) -> bool:
    """True if both locations reference the same file and overlap on at least one line."""
    if a.file != b.file:
        return False
    # Ranges overlap iff start <= other.end AND end >= other.start
    return a.start_line <= b.end_line and a.end_line >= b.start_line


def _cwe_match(agent_cwe: str, truth_cwe: str, hierarchy: Cwe1400Hierarchy,
               mode: str) -> bool:
    if mode == "strict":
        return hierarchy.strict_match(agent_cwe, truth_cwe)
    elif mode == "broad":
        return hierarchy.broad_match(agent_cwe, truth_cwe)
    else:
        raise ValueError(f"Unknown match mode: {mode!r}")


def _score_case(
    case: BenchmarkCase,
    vuln_findings: list[Finding],
    patched_findings: list[Finding],
    hierarchy: Cwe1400Hierarchy,
    match_mode: str = "broad",
) -> tuple[int, int, int, int]:
    """Return (tp, fp, tn, fn) for a single case.

    - For each FAIL ground-truth location:
        If agent flagged it on vuln AND did NOT flag it on patched → TP
        If agent flagged it on vuln AND ALSO flagged it on patched → FN + FP
        If agent did NOT flag it on vuln                            → FN
    - For each PASS ground-truth location:
        If agent flagged it on patched → FP
        Else                           → TN
    - Any agent finding on vuln that doesn't correspond to a FAIL truth → FP
      (only if it also doesn't correspond to a PASS location — else it's
       already counted above)
    """
    fail_truths = [f for f in case.ground_truth if f.kind == FindingKind.FAIL]
    pass_truths = [f for f in case.ground_truth if f.kind == FindingKind.PASS]

    tp = fp = tn = fn = 0

    # Track which vuln/patched findings we've "consumed" against ground truth,
    # so leftover unmatched findings count as extra FPs.
    consumed_vuln: set[int] = set()
    consumed_patched: set[int] = set()

    for truth in fail_truths:
        agent_vuln = _find_match(truth, vuln_findings, hierarchy, match_mode, consumed_vuln)
        agent_patched = _find_match(truth, patched_findings, hierarchy, match_mode, consumed_patched)
        if agent_vuln is not None and agent_patched is None:
            tp += 1
        elif agent_vuln is not None and agent_patched is not None:
            fn += 1  # not vulnerability-sensitive — miss
            fp += 1  # flagged the patched version spuriously
        else:
            fn += 1

    for truth in pass_truths:
        agent_patched = _find_match(truth, patched_findings, hierarchy, match_mode, consumed_patched)
        if agent_patched is not None:
            # Only count if we haven't already counted this as a FN+FP pair above
            # (which happens for truths that have both a fail and pass ground truth at same loc)
            pass  # already counted in fail_truths loop
        else:
            tn += 1

    # Count leftover agent findings on vulnerable version that matched nothing
    for i, f in enumerate(vuln_findings):
        if i in consumed_vuln:
            continue
        fp += 1

    return tp, fp, tn, fn


def _find_match(
    truth: Finding,
    agent_findings: list[Finding],
    hierarchy: Cwe1400Hierarchy,
    match_mode: str,
    consumed: set[int],
) -> Finding | None:
    for i, af in enumerate(agent_findings):
        if i in consumed:
            continue
        if not locations_match(truth.location, af.location):
            continue
        if not _cwe_match(af.cwe_id, truth.cwe_id, hierarchy, match_mode):
            continue
        consumed.add(i)
        return af
    return None


def compute_metrics(
    cases: list[BenchmarkCase],
    runs_vulnerable: list[AgentRun],
    runs_patched: list[AgentRun],
    hierarchy: Cwe1400Hierarchy,
    *,
    agent_name: str,
    dataset: str,
    match_mode: str = "broad",
) -> Summary:
    """Compute a Summary with per-CWE, per-language, and overall MetricSets."""
    # Index runs by case_id for quick lookup
    vuln_by_case = {r.case_id: r for r in runs_vulnerable}
    patched_by_case = {r.case_id: r for r in runs_patched}

    # Bucketed accumulators
    buckets: dict[tuple[str | None, Language | None], list[int]] = defaultdict(
        lambda: [0, 0, 0, 0]  # tp, fp, tn, fn
    )

    for case in cases:
        vuln_run = vuln_by_case.get(case.case_id)
        patched_run = patched_by_case.get(case.case_id)
        vuln_findings = vuln_run.findings if vuln_run else []
        patched_findings = patched_run.findings if patched_run else []
        tp, fp, tn, fn = _score_case(case, vuln_findings, patched_findings, hierarchy, match_mode)

        # Determine the canonical CWE for this case (most specific FAIL truth)
        fail_truths = [f for f in case.ground_truth if f.kind == FindingKind.FAIL]
        case_cwe = fail_truths[0].cwe_id if fail_truths else None

        for key in (
            (None, None),               # Overall
            (case_cwe, None),           # Per-CWE
            (None, case.language),      # Per-language
            (case_cwe, case.language),  # Per-CWE per-language
        ):
            buckets[key][0] += tp
            buckets[key][1] += fp
            buckets[key][2] += tn
            buckets[key][3] += fn

    metrics: list[MetricSet] = []
    for (cwe, lang), (tp, fp, tn, fn) in buckets.items():
        metrics.append(_build_metric_set(
            agent_name=agent_name, dataset=dataset,
            cwe_id=cwe, language=lang,
            tp=tp, fp=fp, tn=tn, fn=fn,
        ))

    return Summary(
        run_id=datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S"),
        agent_name=agent_name,
        dataset=dataset,
        methodology={
            "dedup": False,  # overridden by caller when primevul applied
            "chrono_split": False,
            "pair_based": True,
            "match_mode": match_mode,
        },
        metrics=metrics,
        generated_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
    )


def _build_metric_set(
    *, agent_name: str, dataset: str,
    cwe_id: str | None, language: Language | None,
    tp: int, fp: int, tn: int, fn: int,
) -> MetricSet:
    tpr = tp / (tp + fn) if (tp + fn) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tpr
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    accuracy = tpr - fpr  # ADR-013 / SAST convention
    return MetricSet(
        agent_name=agent_name, dataset=dataset,
        cwe_id=cwe_id, language=language,
        true_positives=tp, false_positives=fp,
        true_negatives=tn, false_negatives=fn,
        tpr=tpr, fpr=fpr, precision=precision, f1=f1, accuracy=accuracy,
    )
EOF
```

- [ ] **Step 4: Run tests — verify all pass**

```bash
uv run pytest benchmarks/tests/test_metrics.py -v
```

Expected: 6 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add benchmarks/runner/metrics.py benchmarks/tests/test_metrics.py
git commit -m "Phase 0.5 Task 7: pair-based TPR/FPR/F1 metrics computation"
```

---

## Task 8: PrimeVul dedup via tree-sitter AST normalization (`benchmarks/runner/primevul.py`)

**Files:**
- Create: `benchmarks/runner/primevul.py`
- Create: `benchmarks/tests/test_primevul_dedup.py`

**Rationale:** PrimeVul paper (Ding et al. 2024) showed LLM F1 dropping from 68% to 3% after proper deduplication. Our dedup strategy: tokenize with tree-sitter, strip comments, normalize whitespace, hash the result. Any two samples with identical hashes are duplicates — we keep the one with the earliest `published_date`.

**tree-sitter language binding approach:** The `tree-sitter` package requires per-language grammars. For Phase 0.5 dedup we need all 8 ingest target languages (Python, JS, TS, Java, Go, Ruby, PHP, C#). Use `tree-sitter-languages` on PyPI which ships pre-built grammars for ~40 languages in a single wheel.

- [ ] **Step 1: Add `tree-sitter-languages` to dev dependencies**

Edit `pyproject.toml`, in the `[dependency-groups.dev]` block:

```toml
[dependency-groups]
dev = [
    "pytest>=8.0",
    "pytest-cov>=5.0",
    "tree-sitter-languages>=1.10",
]
```

Then:

```bash
uv sync
```

Expected: `tree-sitter-languages` installed without errors.

- [ ] **Step 2: Write failing tests**

```bash
cat > benchmarks/tests/test_primevul_dedup.py <<'EOF'
"""Tests for benchmarks.runner.primevul dedup."""
from datetime import date

import pytest

from benchmarks.runner.models import (
    BenchmarkCase,
    CodeLocation,
    Finding,
    FindingKind,
    Language,
)
from benchmarks.runner.primevul import ast_normalize, dedupe, hash_normalized


def _case(case_id: str, code: str, lang: Language, published: date) -> BenchmarkCase:
    return BenchmarkCase(
        case_id=case_id,
        project="test/proj",
        language=lang,
        vulnerable_version="1.0.0",
        patched_version="1.0.1",
        ground_truth=[
            Finding(
                cwe_id="CWE-89", kind=FindingKind.FAIL,
                location=CodeLocation(file="src/a.py", start_line=1, end_line=len(code.splitlines())),
                message=code,  # we stash the code in message for this test
            ),
        ],
        published_date=published,
        source_dataset="test",
    )


def test_ast_normalize_strips_comments_python():
    code1 = "def f(x):\n    # this is a comment\n    return x + 1\n"
    code2 = "def f(x):\n    return x + 1\n"
    n1 = ast_normalize(code1, Language.PYTHON)
    n2 = ast_normalize(code2, Language.PYTHON)
    assert n1 == n2


def test_ast_normalize_whitespace_insensitive():
    code1 = "def   f(x):\n    return     x+1\n"
    code2 = "def f(x):\n    return x + 1\n"
    n1 = ast_normalize(code1, Language.PYTHON)
    n2 = ast_normalize(code2, Language.PYTHON)
    assert n1 == n2


def test_hash_normalized_is_deterministic():
    code = "def f(x): return x"
    h1 = hash_normalized(code, Language.PYTHON)
    h2 = hash_normalized(code, Language.PYTHON)
    assert h1 == h2
    assert len(h1) == 64  # SHA-256 hex


def test_dedupe_keeps_earliest_published():
    c1 = _case("early", "def f(x): return x", Language.PYTHON, date(2024, 1, 1))
    c2 = _case("late", "def f(x): return x # different comment", Language.PYTHON, date(2024, 6, 1))
    result = dedupe([c1, c2])
    assert len(result) == 1
    assert result[0].case_id == "early"


def test_dedupe_preserves_distinct_cases():
    c1 = _case("a", "def f(x): return x", Language.PYTHON, date(2024, 1, 1))
    c2 = _case("b", "def g(x): return x * 2", Language.PYTHON, date(2024, 6, 1))
    result = dedupe([c1, c2])
    assert len(result) == 2


def test_dedupe_different_languages_never_match():
    c_py = _case("py", "def f(x): return x", Language.PYTHON, date(2024, 1, 1))
    c_js = _case("js", "function f(x) { return x; }", Language.JAVASCRIPT, date(2024, 1, 1))
    result = dedupe([c_py, c_js])
    assert len(result) == 2
EOF
```

- [ ] **Step 3: Run tests — verify import failure**

```bash
uv run pytest benchmarks/tests/test_primevul_dedup.py -v
```

Expected: `ModuleNotFoundError: No module named 'benchmarks.runner.primevul'`

- [ ] **Step 4: Write the primevul module (dedup half)**

```bash
cat > benchmarks/runner/primevul.py <<'EOF'
"""PrimeVul methodology: dedup, chronological splits, pair-based evaluation.

Based on Ding et al. 2024 ("Vulnerability Detection with Code Language Models:
How Far Are We?"). The paper showed that LLM-based vulnerability detection
models drop from 68% F1 on Big-Vul to 3% F1 on PrimeVul after proper
deduplication and chronological splits. This module implements the same
hygiene so our autoresearch loop does not silently overfit to duplicate data.

Approach:
  dedupe(cases) — group cases by SHA-256 hash of AST-normalized code;
                  within each group, keep the earliest-published case,
                  discard the rest.

  ast_normalize(code, language) — use tree-sitter to tokenize, strip
                                  comments, normalize whitespace, lowercase
                                  keywords (no identifier rewriting — we
                                  want semantic-equivalent dedup, not rename
                                  invariance).

  Chronological splits and pair-based evaluation are in Task 9 (separate
  functions in this same module).
"""
from __future__ import annotations

import hashlib
from collections import defaultdict
from typing import Iterable

from benchmarks.runner.models import BenchmarkCase, Language


# Map our Language enum to tree-sitter-languages identifiers.
_TS_LANG_NAMES: dict[Language, str] = {
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


def _get_parser(language: Language):
    """Lazy-load tree-sitter parser for the given language. Cached per process."""
    from tree_sitter_languages import get_parser  # imported lazily — dev dep
    ts_name = _TS_LANG_NAMES.get(language)
    if ts_name is None:
        raise ValueError(f"No tree-sitter mapping for {language}")
    return get_parser(ts_name)


def ast_normalize(code: str, language: Language) -> str:
    """Strip comments and normalize whitespace using tree-sitter.

    Walks the CST, skips comment nodes, emits terminal token text separated
    by single spaces. The result is deterministic for semantically identical
    code that differs only in whitespace and comments.
    """
    parser = _get_parser(language)
    tree = parser.parse(code.encode("utf-8"))
    tokens: list[str] = []
    _collect_tokens(tree.root_node, code.encode("utf-8"), tokens)
    return " ".join(tokens)


def _collect_tokens(node, source: bytes, out: list[str]) -> None:
    """Recursive walk of the CST, collecting non-comment leaf tokens."""
    # Skip comment nodes — each language has its own type name, but they all
    # contain "comment" in the node type.
    if "comment" in node.type:
        return
    if node.child_count == 0:
        text = source[node.start_byte:node.end_byte].decode("utf-8", errors="replace").strip()
        if text:
            out.append(text)
        return
    for child in node.children:
        _collect_tokens(child, source, out)


def hash_normalized(code: str, language: Language) -> str:
    """SHA-256 hex digest of the AST-normalized code."""
    normalized = ast_normalize(code, language)
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def dedupe(cases: Iterable[BenchmarkCase]) -> list[BenchmarkCase]:
    """Remove duplicate cases, keeping the earliest-published one in each group.

    Two cases are considered duplicates if:
      - same language AND
      - all their FAIL ground-truth findings' code snippets have the same
        AST-normalized SHA-256 hash

    If `published_date` is None, that case is considered "unknown age" and
    loses to any dated case.
    """
    cases_list = list(cases)
    groups: dict[tuple[Language, str], list[BenchmarkCase]] = defaultdict(list)

    for case in cases_list:
        # Concatenate all FAIL-truth code snippets (stored in message for now;
        # real ingestion will populate this from the source file).
        fail_code = "\n".join(
            f.message for f in case.ground_truth
            if f.kind.value == "fail" and f.message
        )
        if not fail_code:
            # No code to hash — treat as unique by case_id
            groups[(case.language, case.case_id)].append(case)
            continue
        h = hash_normalized(fail_code, case.language)
        groups[(case.language, h)].append(case)

    # In each group, keep the earliest-published
    result: list[BenchmarkCase] = []
    for group in groups.values():
        group.sort(key=lambda c: (c.published_date is None, c.published_date or None))
        result.append(group[0])

    # Sort output by case_id for determinism
    result.sort(key=lambda c: c.case_id)
    return result
EOF
```

- [ ] **Step 5: Run tests — verify all pass**

```bash
uv run pytest benchmarks/tests/test_primevul_dedup.py -v
```

Expected: 6 tests PASS. If a tree-sitter grammar is missing, `tree-sitter-languages` may require a specific version — try `uv add --dev "tree-sitter-languages==1.10.2"`.

- [ ] **Step 6: Commit**

```bash
git add benchmarks/runner/primevul.py benchmarks/tests/test_primevul_dedup.py pyproject.toml
git commit -m "Phase 0.5 Task 8: PrimeVul dedup via tree-sitter AST normalization"
```

---

## Task 9: Chronological splits + pair-based evaluation helpers (`benchmarks/runner/primevul.py` cont.)

**Files:**
- Modify: `benchmarks/runner/primevul.py`
- Create: `benchmarks/tests/test_primevul_splits.py`

**Rationale:** Task 8 gave us dedup. Task 9 adds the other two PrimeVul controls: **chronological split** (train on older CVEs, test on newer — prevents future-leakage during autoresearch) and **cross-project split** (hold out all cases from a single project, prevents project-specific overfitting).

- [ ] **Step 1: Write failing tests**

```bash
cat > benchmarks/tests/test_primevul_splits.py <<'EOF'
"""Tests for chronological and cross-project splits."""
from datetime import date

import pytest

from benchmarks.runner.models import (
    BenchmarkCase,
    CodeLocation,
    Finding,
    FindingKind,
    Language,
)
from benchmarks.runner.primevul import chronological_split, cross_project_split


def _case(case_id: str, project: str, published: date) -> BenchmarkCase:
    return BenchmarkCase(
        case_id=case_id,
        project=project,
        language=Language.PYTHON,
        vulnerable_version="1.0",
        patched_version="1.1",
        ground_truth=[
            Finding(cwe_id="CWE-89", kind=FindingKind.FAIL,
                    location=CodeLocation(file="a.py", start_line=1, end_line=5)),
        ],
        published_date=published,
        source_dataset="test",
    )


def test_chronological_split_by_cutoff():
    cases = [
        _case("old1", "p1", date(2022, 1, 1)),
        _case("old2", "p2", date(2023, 6, 1)),
        _case("new1", "p1", date(2024, 5, 1)),
        _case("new2", "p3", date(2025, 1, 1)),
    ]
    train, test = chronological_split(cases, cutoff=date(2024, 1, 1))
    assert {c.case_id for c in train} == {"old1", "old2"}
    assert {c.case_id for c in test} == {"new1", "new2"}


def test_chronological_split_undated_go_to_train():
    cases = [
        _case("dated", "p1", date(2024, 1, 1)),
    ]
    undated = BenchmarkCase(
        case_id="undated", project="p2", language=Language.PYTHON,
        vulnerable_version="1.0", patched_version="1.1",
        ground_truth=[Finding(cwe_id="CWE-89", kind=FindingKind.FAIL,
                              location=CodeLocation(file="a.py", start_line=1, end_line=5))],
        published_date=None, source_dataset="test",
    )
    train, test = chronological_split([cases[0], undated], cutoff=date(2024, 6, 1))
    # Both go to train (dated is before cutoff; undated defaults to train)
    assert {c.case_id for c in train} == {"dated", "undated"}
    assert test == []


def test_cross_project_split_holds_out_one_project():
    cases = [
        _case("c1", "p1", date(2024, 1, 1)),
        _case("c2", "p1", date(2024, 2, 1)),
        _case("c3", "p2", date(2024, 3, 1)),
        _case("c4", "p3", date(2024, 4, 1)),
    ]
    train, test = cross_project_split(cases, holdout_project="p1")
    assert {c.case_id for c in train} == {"c3", "c4"}
    assert {c.case_id for c in test} == {"c1", "c2"}
EOF
```

- [ ] **Step 2: Run tests — verify import failure**

```bash
uv run pytest benchmarks/tests/test_primevul_splits.py -v
```

Expected: `ImportError: cannot import name 'chronological_split'`

- [ ] **Step 3: Append split functions to primevul.py**

Use `Edit` on `benchmarks/runner/primevul.py` to append at end of file:

```python


from datetime import date  # already imported indirectly via models


def chronological_split(
    cases: list[BenchmarkCase],
    cutoff: date,
) -> tuple[list[BenchmarkCase], list[BenchmarkCase]]:
    """Split cases into (train, test) by published_date.

    Cases with published_date < cutoff go to train.
    Cases with published_date >= cutoff go to test.
    Cases with no date default to train (conservative — they lose ambiguity
    to the training set rather than leak into test).
    """
    train: list[BenchmarkCase] = []
    test: list[BenchmarkCase] = []
    for case in cases:
        if case.published_date is None or case.published_date < cutoff:
            train.append(case)
        else:
            test.append(case)
    return train, test


def cross_project_split(
    cases: list[BenchmarkCase],
    holdout_project: str,
) -> tuple[list[BenchmarkCase], list[BenchmarkCase]]:
    """Hold out all cases from a single project.

    Returns (train, test) where test contains every case whose project ==
    holdout_project. Used for autoresearch to prevent project-specific
    heuristic overfitting.
    """
    train = [c for c in cases if c.project != holdout_project]
    test = [c for c in cases if c.project == holdout_project]
    return train, test
```

Apply via Edit tool targeting the end of the file.

- [ ] **Step 4: Run tests — verify all pass**

```bash
uv run pytest benchmarks/tests/test_primevul_splits.py -v
```

Expected: 3 tests PASS.

- [ ] **Step 5: Run the full test suite so far as a sanity check**

```bash
uv run pytest benchmarks/tests/ -v
```

Expected: All tests from Tasks 1-9 PASS (ballpark: 20+ tests).

- [ ] **Step 6: Commit**

```bash
git add benchmarks/runner/primevul.py benchmarks/tests/test_primevul_splits.py
git commit -m "Phase 0.5 Task 9: chronological and cross-project splits"
```

---

## Task 10: CLI entry point (`benchmarks/runner/cli.py`)

**Files:**
- Create: `benchmarks/runner/cli.py`
- Create: `benchmarks/tests/test_cli.py`

**Rationale:** Wire up the modules from Tasks 4-9 into a runnable CLI. Three subcommands:
- `python -m benchmarks.runner list` — list available datasets and agents
- `python -m benchmarks.runner validate <ground-truth-path>` — sanity-check a SARIF file
- `python -m benchmarks.runner run --agent <name> --dataset <name> [--match-mode strict|broad] [--chrono-cutoff YYYY-MM-DD] [--dedup]` — run evaluation

For Phase 0.5 we have no real agents yet (Phase 1 builds those). The `run` subcommand reads ground truth AND synthetic agent SARIF files from `benchmarks/external/` and produces a Summary + Markdown report. Phase 1 will replace synthetic agent output with real MCP agent runs.

- [ ] **Step 1: Write failing tests**

```bash
cat > benchmarks/tests/test_cli.py <<'EOF'
"""Smoke tests for the runner CLI."""
import subprocess
import sys
from pathlib import Path


def test_cli_help_exits_zero():
    result = subprocess.run(
        [sys.executable, "-m", "benchmarks.runner", "--help"],
        capture_output=True, text=True,
    )
    assert result.returncode == 0
    assert "run" in result.stdout
    assert "list" in result.stdout
    assert "validate" in result.stdout


def test_cli_validate_rejects_bad_sarif(tmp_path: Path):
    bad = tmp_path / "bad.sarif"
    bad.write_text("not json at all")
    result = subprocess.run(
        [sys.executable, "-m", "benchmarks.runner", "validate", str(bad)],
        capture_output=True, text=True,
    )
    assert result.returncode != 0


def test_cli_validate_accepts_mini_truth(fixtures_dir: Path):
    truth = fixtures_dir / "mini_truth.sarif"
    result = subprocess.run(
        [sys.executable, "-m", "benchmarks.runner", "validate", str(truth)],
        capture_output=True, text=True,
    )
    assert result.returncode == 0, f"stderr: {result.stderr}"
    assert "valid" in result.stdout.lower() or "ok" in result.stdout.lower()
EOF
```

- [ ] **Step 2: Run tests — expect failure (no CLI yet)**

```bash
uv run pytest benchmarks/tests/test_cli.py -v
```

Expected: `ModuleNotFoundError: No module named 'benchmarks.runner.cli'`

- [ ] **Step 3: Write the CLI module**

```bash
cat > benchmarks/runner/cli.py <<'EOF'
"""Command-line interface for the benchmark runner.

Subcommands:
    list                  — list datasets and agents
    validate <path>       — validate a bentoo-sarif file
    run --agent <n> --dataset <n> [opts] — run evaluation
"""
from __future__ import annotations

import argparse
import sys
from datetime import date
from pathlib import Path

from benchmarks.runner.sarif import load_bentoo_sarif


def cmd_list(args: argparse.Namespace) -> int:
    """List available datasets and agents."""
    manifests_dir = Path("benchmarks/external/manifests")
    print("Datasets:")
    if manifests_dir.exists():
        for m in sorted(manifests_dir.glob("*.manifest.json")):
            print(f"  {m.stem.replace('.manifest', '')}")
    else:
        print("  (no manifests directory found)")

    domains_dir = Path("domains")
    print("\nAgents:")
    if domains_dir.exists():
        for yaml_file in sorted(domains_dir.rglob("*.yaml")):
            print(f"  {yaml_file.stem}")
    else:
        print("  (no domains directory found)")
    return 0


def cmd_validate(args: argparse.Namespace) -> int:
    """Validate that a SARIF file parses as bentoo-sarif."""
    try:
        findings = load_bentoo_sarif(Path(args.path))
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    print(f"OK: {args.path} is a valid bentoo-sarif file with {len(findings)} findings")
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    """Run a benchmark evaluation.

    Phase 0.5 stub: reads ground truth + a synthetic agent SARIF file from
    disk and emits a Summary. Phase 1 will replace the synthetic agent source
    with live MCP agent invocations.
    """
    print(f"[stub] Would run agent={args.agent} on dataset={args.dataset}")
    print(f"  match_mode={args.match_mode}")
    print(f"  chrono_cutoff={args.chrono_cutoff}")
    print(f"  dedup={args.dedup}")
    print("Full implementation in Task 25 (smoke test).")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="benchmarks.runner",
        description="CWE-1400-native benchmark evaluator for screw-agents",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_list = sub.add_parser("list", help="list datasets and agents")
    p_list.set_defaults(func=cmd_list)

    p_validate = sub.add_parser("validate", help="validate a bentoo-sarif file")
    p_validate.add_argument("path", help="path to a .sarif file")
    p_validate.set_defaults(func=cmd_validate)

    p_run = sub.add_parser("run", help="run a benchmark evaluation")
    p_run.add_argument("--agent", required=True, help="agent name (e.g., xss)")
    p_run.add_argument("--dataset", required=True, help="dataset name")
    p_run.add_argument("--match-mode", choices=["strict", "broad"], default="broad")
    p_run.add_argument("--chrono-cutoff", type=date.fromisoformat, default=None,
                       help="YYYY-MM-DD — train/test split date")
    p_run.add_argument("--dedup", action="store_true", help="apply PrimeVul dedup")
    p_run.set_defaults(func=cmd_run)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
EOF
```

- [ ] **Step 4: Run CLI tests**

```bash
uv run pytest benchmarks/tests/test_cli.py -v
```

Expected: 3 tests PASS.

- [ ] **Step 5: Manual smoke test**

```bash
uv run python -m benchmarks.runner --help
uv run python -m benchmarks.runner list
uv run python -m benchmarks.runner validate benchmarks/tests/fixtures/mini_truth.sarif
```

Expected: clean help text; `list` shows the four Phase 1 agents (sqli, cmdi, ssti, xss); `validate` prints `OK: ... is a valid bentoo-sarif file with 3 findings`.

- [ ] **Step 6: Commit**

```bash
git add benchmarks/runner/cli.py benchmarks/tests/test_cli.py
git commit -m "Phase 0.5 Task 10: CLI entry point with list/validate/run subcommands"
```

---

## Task 11: Markdown report generator (`benchmarks/runner/report.py`)

**Files:**
- Create: `benchmarks/runner/report.py`
- Create: `benchmarks/tests/test_report.py`

**Rationale:** Render a `Summary` as a human-readable Markdown report. Per-CWE tables, per-language tables, overall summary at the top, failure dump (missed CVEs + false flags) at the bottom.

- [ ] **Step 1: Write failing tests**

```bash
cat > benchmarks/tests/test_report.py <<'EOF'
"""Tests for the Markdown report renderer."""
from benchmarks.runner.models import Language, MetricSet, Summary
from benchmarks.runner.report import render_markdown


def _make_summary() -> Summary:
    return Summary(
        run_id="test-run-001",
        agent_name="xss",
        dataset="ossf-cve-benchmark",
        methodology={"dedup": True, "chrono_split": True, "pair_based": True},
        metrics=[
            MetricSet(agent_name="xss", dataset="ossf-cve-benchmark",
                      cwe_id=None, language=None,
                      true_positives=20, false_positives=5,
                      true_negatives=15, false_negatives=10,
                      tpr=0.667, fpr=0.25, precision=0.80, f1=0.727, accuracy=0.417),
            MetricSet(agent_name="xss", dataset="ossf-cve-benchmark",
                      cwe_id="CWE-79", language=None,
                      true_positives=18, false_positives=4,
                      true_negatives=14, false_negatives=8,
                      tpr=0.692, fpr=0.222, precision=0.818, f1=0.750, accuracy=0.470),
            MetricSet(agent_name="xss", dataset="ossf-cve-benchmark",
                      cwe_id=None, language=Language.JAVASCRIPT,
                      true_positives=15, false_positives=3,
                      true_negatives=10, false_negatives=7,
                      tpr=0.682, fpr=0.231, precision=0.833, f1=0.750, accuracy=0.451),
        ],
        generated_at="2026-04-09T12:00:00+00:00",
    )


def test_report_contains_run_header():
    md = render_markdown(_make_summary())
    assert "xss" in md
    assert "ossf-cve-benchmark" in md
    assert "test-run-001" in md


def test_report_contains_overall_table():
    md = render_markdown(_make_summary())
    assert "Overall" in md
    assert "TPR" in md
    assert "66.7%" in md or "0.667" in md


def test_report_contains_per_cwe_section():
    md = render_markdown(_make_summary())
    assert "CWE-79" in md


def test_report_contains_per_language_section():
    md = render_markdown(_make_summary())
    assert "JavaScript" in md or "javascript" in md


def test_report_contains_methodology_block():
    md = render_markdown(_make_summary())
    assert "dedup" in md.lower()
    assert "pair" in md.lower()
EOF
```

- [ ] **Step 2: Run tests — expect failure**

```bash
uv run pytest benchmarks/tests/test_report.py -v
```

Expected: `ModuleNotFoundError: No module named 'benchmarks.runner.report'`

- [ ] **Step 3: Write the report module**

```bash
cat > benchmarks/runner/report.py <<'EOF'
"""Markdown report rendering for benchmark runs."""
from __future__ import annotations

from io import StringIO

from benchmarks.runner.models import MetricSet, Summary


def render_markdown(summary: Summary) -> str:
    """Render a Summary as a Markdown report."""
    out = StringIO()

    _write_header(out, summary)
    _write_overall(out, summary)
    _write_per_cwe(out, summary)
    _write_per_language(out, summary)
    _write_methodology(out, summary)

    return out.getvalue()


def _write_header(out: StringIO, summary: Summary) -> None:
    out.write(f"# Benchmark Run `{summary.run_id}`\n\n")
    out.write(f"- **Agent:** `{summary.agent_name}`\n")
    out.write(f"- **Dataset:** `{summary.dataset}`\n")
    out.write(f"- **Generated:** {summary.generated_at}\n\n")


def _write_overall(out: StringIO, summary: Summary) -> None:
    overall = next(
        (m for m in summary.metrics if m.cwe_id is None and m.language is None),
        None,
    )
    if overall is None:
        out.write("## Overall\n\n_(no overall metric)_\n\n")
        return
    out.write("## Overall\n\n")
    out.write("| Metric | Value |\n|---|---|\n")
    out.write(f"| TPR (recall) | {_pct(overall.tpr)} |\n")
    out.write(f"| FPR | {_pct(overall.fpr)} |\n")
    out.write(f"| Precision | {_pct(overall.precision)} |\n")
    out.write(f"| F1 | {_pct(overall.f1)} |\n")
    out.write(f"| Accuracy (TPR - FPR) | {_pct(overall.accuracy)} |\n")
    out.write(f"| TP / FP / TN / FN | "
              f"{overall.true_positives} / {overall.false_positives} / "
              f"{overall.true_negatives} / {overall.false_negatives} |\n\n")


def _write_per_cwe(out: StringIO, summary: Summary) -> None:
    per_cwe = [m for m in summary.metrics if m.cwe_id is not None and m.language is None]
    if not per_cwe:
        return
    out.write("## Per CWE\n\n")
    out.write("| CWE | TPR | FPR | Precision | F1 | TP | FP | FN |\n")
    out.write("|---|---|---|---|---|---|---|---|\n")
    for m in sorted(per_cwe, key=lambda x: x.cwe_id or ""):
        out.write(f"| {m.cwe_id} | {_pct(m.tpr)} | {_pct(m.fpr)} | "
                  f"{_pct(m.precision)} | {_pct(m.f1)} | "
                  f"{m.true_positives} | {m.false_positives} | {m.false_negatives} |\n")
    out.write("\n")


def _write_per_language(out: StringIO, summary: Summary) -> None:
    per_lang = [m for m in summary.metrics if m.language is not None and m.cwe_id is None]
    if not per_lang:
        return
    out.write("## Per Language\n\n")
    out.write("| Language | TPR | FPR | Precision | F1 | TP | FP | FN |\n")
    out.write("|---|---|---|---|---|---|---|---|\n")
    for m in sorted(per_lang, key=lambda x: x.language.value if x.language else ""):
        name = m.language.value.capitalize() if m.language else "—"
        out.write(f"| {name} | {_pct(m.tpr)} | {_pct(m.fpr)} | "
                  f"{_pct(m.precision)} | {_pct(m.f1)} | "
                  f"{m.true_positives} | {m.false_positives} | {m.false_negatives} |\n")
    out.write("\n")


def _write_methodology(out: StringIO, summary: Summary) -> None:
    out.write("## Methodology\n\n")
    for key, value in sorted(summary.methodology.items()):
        out.write(f"- **{key}**: `{value}`\n")
    out.write("\n")


def _pct(value: float) -> str:
    return f"{value * 100:.1f}%"
EOF
```

- [ ] **Step 4: Run tests — verify all pass**

```bash
uv run pytest benchmarks/tests/test_report.py -v
```

Expected: 5 tests PASS.

- [ ] **Step 5: Run the entire test suite to confirm Tasks 1-11 cohere**

```bash
uv run pytest benchmarks/tests/ -v
```

Expected: all ~30+ tests PASS. No deprecation warnings, no collection errors.

- [ ] **Step 6: Commit**

```bash
git add benchmarks/runner/report.py benchmarks/tests/test_report.py
git commit -m "Phase 0.5 Task 11: Markdown report renderer"
```

---

## Task 12: Reusable ingest harness base class (`benchmarks/scripts/ingest_base.py`)

**Files:**
- Create: `benchmarks/scripts/ingest_base.py`
- Create: `benchmarks/tests/test_ingest_base.py`

**Rationale:** Tasks 13-20 all follow the same pattern: download a dataset, parse its native format, convert to `BenchmarkCase` objects, write bentoo-sarif ground-truth files, and emit a manifest. DRY this into a single base class and make each ingest task a ~40-line subclass.

**Pattern:**
```python
class IngestBase(ABC):
    dataset_name: str
    source_url: str

    def run(self) -> None:
        self.ensure_downloaded()
        cases = self.extract_cases()
        self.materialize(cases)
        self.write_manifest(cases)

    @abstractmethod
    def ensure_downloaded(self) -> None: ...

    @abstractmethod
    def extract_cases(self) -> list[BenchmarkCase]: ...

    def materialize(self, cases) -> None:
        # Write one bentoo-sarif truth file per case
        ...

    def write_manifest(self, cases) -> None:
        # Write manifest JSON with provenance
        ...
```

- [ ] **Step 1: Write failing tests**

```bash
cat > benchmarks/tests/test_ingest_base.py <<'EOF'
"""Tests for benchmarks.scripts.ingest_base."""
from datetime import date
from pathlib import Path

import pytest

from benchmarks.runner.models import (
    BenchmarkCase,
    CodeLocation,
    Finding,
    FindingKind,
    Language,
)
from benchmarks.scripts.ingest_base import IngestBase


class _FakeIngest(IngestBase):
    dataset_name = "fake-dataset"
    source_url = "https://example.com/fake"

    def __init__(self, root: Path) -> None:
        super().__init__(root)
        self.downloaded = False

    def ensure_downloaded(self) -> None:
        self.downloaded = True

    def extract_cases(self) -> list[BenchmarkCase]:
        return [
            BenchmarkCase(
                case_id="fake-case-1",
                project="acme/thing",
                language=Language.PYTHON,
                vulnerable_version="1.0.0",
                patched_version="1.0.1",
                ground_truth=[
                    Finding(
                        cwe_id="CWE-89", kind=FindingKind.FAIL, cve_id="CVE-2024-0",
                        location=CodeLocation(file="src/a.py", start_line=10, end_line=15,
                                              function_name="query"),
                    ),
                    Finding(
                        cwe_id="CWE-89", kind=FindingKind.PASS, cve_id="CVE-2024-0",
                        location=CodeLocation(file="src/a.py", start_line=10, end_line=17,
                                              function_name="query"),
                    ),
                ],
                published_date=date(2024, 3, 1),
                source_dataset="fake-dataset",
            ),
        ]


def test_run_invokes_all_phases(tmp_path: Path):
    ingest = _FakeIngest(root=tmp_path)
    ingest.run()
    assert ingest.downloaded is True

    # Materialized SARIF file should exist
    sarif_path = tmp_path / "external" / "fake-dataset" / "fake-case-1" / "truth.sarif"
    assert sarif_path.exists()

    # Manifest should exist and list 1 case
    manifest_path = tmp_path / "external" / "manifests" / "fake-dataset.manifest.json"
    assert manifest_path.exists()
    import json
    data = json.loads(manifest_path.read_text())
    assert data["dataset_name"] == "fake-dataset"
    assert data["case_count"] == 1
    assert data["source_url"] == "https://example.com/fake"
EOF
```

- [ ] **Step 2: Run tests — verify import failure**

```bash
uv run pytest benchmarks/tests/test_ingest_base.py -v
```

Expected: `ModuleNotFoundError: No module named 'benchmarks.scripts.ingest_base'`

- [ ] **Step 3: Write the base class**

```bash
cat > benchmarks/scripts/ingest_base.py <<'EOF'
"""Base class for benchmark ingestion scripts.

Tasks 13-20 all subclass this and override `ensure_downloaded()` and
`extract_cases()`. The base handles the common "write bentoo-sarif truth
files + manifest" logic.

Usage:
    class MyIngest(IngestBase):
        dataset_name = "ossf-cve-benchmark"
        source_url = "https://github.com/ossf-cve-benchmark/ossf-cve-benchmark"

        def ensure_downloaded(self) -> None:
            # Clone or download into self.download_dir
            ...

        def extract_cases(self) -> list[BenchmarkCase]:
            # Parse the dataset and return BenchmarkCase objects
            ...

    if __name__ == "__main__":
        MyIngest(root=Path("benchmarks")).run()
"""
from __future__ import annotations

import json
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from pathlib import Path

from benchmarks.runner.models import BenchmarkCase
from benchmarks.runner.sarif import write_bentoo_sarif


class IngestBase(ABC):
    """Abstract base for benchmark ingestion scripts."""

    dataset_name: str  # override in subclass
    source_url: str    # override in subclass

    def __init__(self, root: Path) -> None:
        self.root = Path(root)
        self.download_dir = self.root / "external" / self.dataset_name
        self.manifest_dir = self.root / "external" / "manifests"

    @abstractmethod
    def ensure_downloaded(self) -> None:
        """Download or clone the dataset into self.download_dir.

        Must be idempotent — if data is already present, no-op.
        """

    @abstractmethod
    def extract_cases(self) -> list[BenchmarkCase]:
        """Parse the downloaded dataset and return a list of BenchmarkCase."""

    def run(self) -> None:
        print(f"[{self.dataset_name}] Ensuring download ...")
        self.download_dir.mkdir(parents=True, exist_ok=True)
        self.manifest_dir.mkdir(parents=True, exist_ok=True)
        self.ensure_downloaded()

        print(f"[{self.dataset_name}] Extracting cases ...")
        cases = self.extract_cases()
        print(f"[{self.dataset_name}] Extracted {len(cases)} cases")

        self.materialize(cases)
        self.write_manifest(cases)
        print(f"[{self.dataset_name}] Done.")

    def materialize(self, cases: list[BenchmarkCase]) -> None:
        """Write one bentoo-sarif truth file per case."""
        for case in cases:
            case_dir = self.download_dir / case.case_id
            case_dir.mkdir(parents=True, exist_ok=True)
            truth_path = case_dir / "truth.sarif"
            write_bentoo_sarif(truth_path, case.ground_truth,
                               tool_name=f"{self.dataset_name}-{case.case_id}")

    def write_manifest(self, cases: list[BenchmarkCase]) -> None:
        """Write a provenance manifest JSON for this dataset."""
        manifest = {
            "dataset_name": self.dataset_name,
            "source_url": self.source_url,
            "case_count": len(cases),
            "ingested_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "cases": [
                {
                    "case_id": c.case_id,
                    "project": c.project,
                    "language": c.language.value,
                    "vulnerable_version": c.vulnerable_version,
                    "patched_version": c.patched_version,
                    "published_date": c.published_date.isoformat() if c.published_date else None,
                    "fail_count": sum(1 for f in c.ground_truth if f.kind.value == "fail"),
                    "pass_count": sum(1 for f in c.ground_truth if f.kind.value == "pass"),
                }
                for c in cases
            ],
        }
        out_path = self.manifest_dir / f"{self.dataset_name}.manifest.json"
        out_path.write_text(json.dumps(manifest, indent=2))
EOF
```

- [ ] **Step 4: Run tests — expect pass**

```bash
uv run pytest benchmarks/tests/test_ingest_base.py -v
```

Expected: 1 test PASS.

- [ ] **Step 5: Commit**

```bash
git add benchmarks/scripts/ingest_base.py benchmarks/tests/test_ingest_base.py
git commit -m "Phase 0.5 Task 12: reusable ingest harness base class"
```

---

## Task 13: Ingest OpenSSF CVE benchmark (`benchmarks/scripts/ingest_ossf.py`)

**Files:**
- Create: `benchmarks/scripts/ingest_ossf.py`
- Create: `benchmarks/tests/test_ingest_ossf.py`

**Rationale:** OpenSSF CVE Benchmark (`github.com/ossf-cve-benchmark/ossf-cve-benchmark`) carries 218 real JS/TS CVEs with verified CWE-78, CWE-79, and CWE-94 (parent of CWE-1336) presence. Single biggest data source for our XSS and CmdI agents. Dataset structure: per-CVE JSON files with `cve`, `cwe` (list), pre/post-patch SHAs, and file-level ground truth.

**Approach:**
1. Clone the repo into `benchmarks/external/ossf-cve-benchmark/repo/`
2. Walk the `CVEs/` directory (one subdirectory per CVE)
3. For each CVE with CWE ∈ {CWE-78, CWE-79, CWE-89, CWE-94, CWE-1336}, build a `BenchmarkCase`
4. Materialize truth.sarif files + manifest

- [ ] **Step 1: Write a failing smoke test**

```bash
cat > benchmarks/tests/test_ingest_ossf.py <<'EOF'
"""Tests for the OpenSSF CVE Benchmark ingest script."""
from pathlib import Path

import pytest

from benchmarks.scripts.ingest_ossf import OssfCveBenchmarkIngest, PHASE1_CWE_FILTER


def test_cwe_filter_covers_phase1_targets():
    """We must filter for the four Phase 1 CWEs plus CWE-94 (SSTI parent)."""
    for cwe in ("CWE-79", "CWE-78", "CWE-89", "CWE-94", "CWE-1336"):
        assert cwe in PHASE1_CWE_FILTER


def test_ingest_has_correct_dataset_name():
    ingest = OssfCveBenchmarkIngest(root=Path("/tmp/test-root"))
    assert ingest.dataset_name == "ossf-cve-benchmark"
    assert "ossf-cve-benchmark" in ingest.source_url
EOF
```

- [ ] **Step 2: Write the ingest script**

```bash
cat > benchmarks/scripts/ingest_ossf.py <<'EOF'
"""Ingest the OpenSSF CVE Benchmark for JavaScript/TypeScript.

Repo: https://github.com/ossf-cve-benchmark/ossf-cve-benchmark
Contains 218 real JS/TS CVEs with CWE tags and pre/post-patch commits.
"""
from __future__ import annotations

import json
import subprocess
import sys
from datetime import date, datetime
from pathlib import Path

from benchmarks.runner.models import (
    BenchmarkCase,
    CodeLocation,
    Finding,
    FindingKind,
    Language,
)
from benchmarks.scripts.ingest_base import IngestBase


PHASE1_CWE_FILTER = {"CWE-78", "CWE-79", "CWE-89", "CWE-94", "CWE-1336"}


class OssfCveBenchmarkIngest(IngestBase):
    dataset_name = "ossf-cve-benchmark"
    source_url = "https://github.com/ossf-cve-benchmark/ossf-cve-benchmark"

    def ensure_downloaded(self) -> None:
        repo_dir = self.download_dir / "repo"
        if repo_dir.exists() and (repo_dir / "CVEs").exists():
            print(f"  already cloned: {repo_dir}")
            return
        print(f"  cloning {self.source_url} ...")
        subprocess.run(
            ["git", "clone", "--depth", "1", self.source_url, str(repo_dir)],
            check=True,
        )

    def extract_cases(self) -> list[BenchmarkCase]:
        repo_dir = self.download_dir / "repo"
        cves_dir = repo_dir / "CVEs"
        if not cves_dir.exists():
            # Alternate paths used by the repo over time
            for alt in ("cves", "data/CVEs", "data/cves"):
                if (repo_dir / alt).exists():
                    cves_dir = repo_dir / alt
                    break
            else:
                raise RuntimeError(f"Cannot locate CVEs dir under {repo_dir}")

        cases: list[BenchmarkCase] = []
        for cve_dir in sorted(cves_dir.iterdir()):
            if not cve_dir.is_dir():
                continue
            case = self._build_case(cve_dir)
            if case is not None:
                cases.append(case)
        return cases

    def _build_case(self, cve_dir: Path) -> BenchmarkCase | None:
        metadata_candidates = list(cve_dir.glob("*.json")) + [cve_dir / "metadata.json"]
        metadata_path = next((p for p in metadata_candidates if p.exists()), None)
        if metadata_path is None:
            return None

        try:
            meta = json.loads(metadata_path.read_text())
        except Exception:
            return None

        # CWE field may be a list like ["CWE-079", "CWE-094"] or string "CWE-79"
        raw_cwes = meta.get("cwe") or meta.get("cwes") or []
        if isinstance(raw_cwes, str):
            raw_cwes = [raw_cwes]
        cwes = {_normalize_cwe(c) for c in raw_cwes}
        phase1_cwes = cwes & PHASE1_CWE_FILTER
        if not phase1_cwes:
            return None

        canonical_cwe = sorted(phase1_cwes)[0]

        cve_id = meta.get("cve") or meta.get("cveId") or cve_dir.name
        project = meta.get("project") or meta.get("repo") or "unknown"

        vulnerable_files = meta.get("vulnerable_files") or meta.get("vulnerableFiles") or []
        if not vulnerable_files:
            # Fall back to a single placeholder location — OSSF format varies
            vulnerable_files = [{"path": meta.get("file", "<unknown>"),
                                 "start_line": meta.get("line", 1),
                                 "end_line": meta.get("line", 1)}]

        ground_truth: list[Finding] = []
        for vf in vulnerable_files:
            location = CodeLocation(
                file=vf.get("path", "<unknown>"),
                start_line=int(vf.get("start_line") or vf.get("startLine") or 1),
                end_line=int(vf.get("end_line") or vf.get("endLine") or 1),
                function_name=vf.get("function") or vf.get("method") or None,
            )
            ground_truth.append(Finding(
                cwe_id=canonical_cwe, kind=FindingKind.FAIL, cve_id=cve_id,
                location=location, message=cve_id,
            ))
            ground_truth.append(Finding(
                cwe_id=canonical_cwe, kind=FindingKind.PASS, cve_id=cve_id,
                location=location, message=cve_id,
            ))

        # Language detection — OSSF is JS/TS but some entries are .ts
        lang = Language.TYPESCRIPT if any(
            vf.get("path", "").endswith(".ts") for vf in vulnerable_files
        ) else Language.JAVASCRIPT

        published = _parse_date(meta.get("published") or meta.get("publishedDate"))

        return BenchmarkCase(
            case_id=f"ossf-{cve_id}",
            project=project,
            language=lang,
            vulnerable_version=meta.get("vulnerable_version")
                              or meta.get("vulnerableVersion")
                              or "pre-patch",
            patched_version=meta.get("patched_version")
                           or meta.get("patchedVersion")
                           or "post-patch",
            ground_truth=ground_truth,
            published_date=published,
            source_dataset=self.dataset_name,
        )


def _normalize_cwe(raw: str) -> str:
    """Normalize 'CWE-079' / '79' / 'cwe79' to 'CWE-79'."""
    digits = "".join(ch for ch in raw if ch.isdigit())
    if not digits:
        return raw
    return f"CWE-{int(digits)}"


def _parse_date(raw) -> date | None:
    if not raw:
        return None
    for fmt in ("%Y-%m-%d", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%SZ"):
        try:
            return datetime.strptime(str(raw)[: len(fmt)], fmt).date()
        except ValueError:
            continue
    return None


def main() -> int:
    OssfCveBenchmarkIngest(root=Path("benchmarks")).run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
EOF
```

- [ ] **Step 3: Run the unit tests**

```bash
uv run pytest benchmarks/tests/test_ingest_ossf.py -v
```

Expected: 2 tests PASS.

- [ ] **Step 4: Run the ingest end-to-end (network required)**

```bash
uv run python -m benchmarks.scripts.ingest_ossf
```

Expected: clones repo, extracts cases, prints `[ossf-cve-benchmark] Extracted N cases` where N should be in the range 50-220 depending on how many CVEs match our Phase 1 filter.

If the OSSF repo layout has drifted (paths or JSON keys), the script logs a warning but does not fail — inspect `benchmarks/external/manifests/ossf-cve-benchmark.manifest.json` to see which cases landed. If zero cases extracted, iterate on the `_build_case` heuristics (the repo's JSON schema is loosely documented and varies across entries).

- [ ] **Step 5: Verify manifest and truth files**

```bash
cat benchmarks/external/manifests/ossf-cve-benchmark.manifest.json | head -40
ls benchmarks/external/ossf-cve-benchmark/ | head -10
```

Expected: manifest lists cases; each case has a `truth.sarif` file.

- [ ] **Step 6: Spot-check one truth.sarif**

```bash
ls benchmarks/external/ossf-cve-benchmark/ | head -1 | xargs -I {} uv run python -m benchmarks.runner validate benchmarks/external/ossf-cve-benchmark/{}/truth.sarif
```

Expected: `OK: ... is a valid bentoo-sarif file with N findings`.

- [ ] **Step 7: Commit**

```bash
git add benchmarks/scripts/ingest_ossf.py benchmarks/tests/test_ingest_ossf.py benchmarks/external/manifests/ossf-cve-benchmark.manifest.json
git commit -m "Phase 0.5 Task 13: ingest OpenSSF CVE Benchmark (JS/TS)"
```

Note: `benchmarks/external/ossf-cve-benchmark/` itself is gitignored (only manifest commits).

---

## Task 14: Ingest `reality-check` C# subset (`benchmarks/scripts/ingest_reality_check_csharp.py`)

**Files:**
- Create: `benchmarks/scripts/ingest_reality_check_csharp.py`
- Create: `benchmarks/tests/test_ingest_reality_check_csharp.py`

**Rationale:** `flawgarden/reality-check` C# subset has **9 XSS CVEs + 1 SQLi + 1 CmdI** — the strongest single (language × CWE) cell in the entire flawgarden ecosystem for our Phase 1 agents. Reality-check already publishes bentoo-sarif ground truth, so our ingest script is almost a pass-through.

**Approach:**
1. Reuse Task 2's vendored `flawgarden/reality-check/scripts/` OR clone reality-check again
2. Parse `csharp/cves_db.csv` to enumerate cases
3. For each CVE, load the existing `csharp/markup/<Project>/<Project-Version>/truth.sarif` and convert via `load_bentoo_sarif()`
4. Filter to Phase 1 CWEs, emit manifest

- [ ] **Step 1: Write failing test**

```bash
cat > benchmarks/tests/test_ingest_reality_check_csharp.py <<'EOF'
"""Tests for reality-check C# ingest."""
from pathlib import Path

from benchmarks.scripts.ingest_reality_check_csharp import (
    PHASE1_CWE_FILTER,
    RealityCheckCsharpIngest,
)


def test_phase1_filter_contains_expected_cwes():
    # C# reality-check has 9 XSS, 1 SQLi, 1 CmdI matching Phase 1
    for cwe in ("CWE-79", "CWE-89", "CWE-78"):
        assert cwe in PHASE1_CWE_FILTER


def test_ingest_has_correct_metadata():
    ingest = RealityCheckCsharpIngest(root=Path("/tmp/test-root"))
    assert ingest.dataset_name == "reality-check-csharp"
    assert "reality-check" in ingest.source_url
EOF
```

- [ ] **Step 2: Write the ingest script**

```bash
cat > benchmarks/scripts/ingest_reality_check_csharp.py <<'EOF'
"""Ingest the flawgarden/reality-check C# subset.

This is a bentoo-sarif passthrough: reality-check already publishes
truth.sarif files per CVE/version. We just need to walk the csharp/
directory, filter to Phase 1 CWEs, and emit a manifest.
"""
from __future__ import annotations

import csv
import subprocess
import sys
from datetime import date
from pathlib import Path

from benchmarks.runner.models import (
    BenchmarkCase,
    Finding,
    FindingKind,
    Language,
)
from benchmarks.runner.sarif import load_bentoo_sarif
from benchmarks.scripts.ingest_base import IngestBase


PHASE1_CWE_FILTER = {"CWE-78", "CWE-79", "CWE-89", "CWE-94", "CWE-1336"}


class RealityCheckCsharpIngest(IngestBase):
    dataset_name = "reality-check-csharp"
    source_url = "https://github.com/flawgarden/reality-check"

    def ensure_downloaded(self) -> None:
        repo_dir = self.download_dir / "repo"
        if repo_dir.exists() and (repo_dir / "csharp").exists():
            print(f"  already cloned: {repo_dir}")
            return
        print(f"  cloning {self.source_url} ...")
        subprocess.run(
            ["git", "clone", "--depth", "1", self.source_url, str(repo_dir)],
            check=True,
        )

    def extract_cases(self) -> list[BenchmarkCase]:
        repo_dir = self.download_dir / "repo"
        csv_path = repo_dir / "csharp" / "cves_db.csv"
        if not csv_path.exists():
            raise RuntimeError(f"cves_db.csv not found at {csv_path}")

        cases: list[BenchmarkCase] = []
        with csv_path.open() as f:
            reader = csv.DictReader(f)
            for row in reader:
                case = self._build_case(row, repo_dir)
                if case is not None:
                    cases.append(case)
        return cases

    def _build_case(self, row: dict, repo_dir: Path) -> BenchmarkCase | None:
        cwe = _normalize_cwe(row.get("cwe", ""))
        if cwe not in PHASE1_CWE_FILTER:
            return None

        project = row.get("project", "unknown")
        cve = row.get("cve", "UNKNOWN")
        vul_version = row.get("vul_version", "")
        patch_version = row.get("patch_version", "")

        # Ground truth is in csharp/markup/<Project>/<Project-vul_version>/truth.sarif
        markup_path = (
            repo_dir / "csharp" / "markup"
            / project / f"{project}-{vul_version}" / "truth.sarif"
        )
        if not markup_path.exists():
            print(f"  WARN: missing truth.sarif for {project} {vul_version}: {markup_path}")
            return None

        fail_findings = load_bentoo_sarif(markup_path)
        # Build matching PASS findings at the same locations (patched version)
        pass_findings = [
            Finding(
                cwe_id=f.cwe_id, kind=FindingKind.PASS, cve_id=cve,
                location=f.location, message=cve,
            )
            for f in fail_findings
        ]

        return BenchmarkCase(
            case_id=f"rc-csharp-{project}-{cve}",
            project=project,
            language=Language.CSHARP,
            vulnerable_version=vul_version,
            patched_version=patch_version,
            ground_truth=fail_findings + pass_findings,
            published_date=None,  # reality-check CSV doesn't carry dates
            source_dataset=self.dataset_name,
        )


def _normalize_cwe(raw: str) -> str:
    digits = "".join(ch for ch in raw if ch.isdigit())
    return f"CWE-{int(digits)}" if digits else raw


def main() -> int:
    RealityCheckCsharpIngest(root=Path("benchmarks")).run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
EOF
```

- [ ] **Step 3: Run tests**

```bash
uv run pytest benchmarks/tests/test_ingest_reality_check_csharp.py -v
```

Expected: 2 tests PASS.

- [ ] **Step 4: Run the ingest**

```bash
uv run python -m benchmarks.scripts.ingest_reality_check_csharp
```

Expected: `[reality-check-csharp] Extracted 11 cases` (9 XSS + 1 SQLi + 1 CmdI).

- [ ] **Step 5: Verify the manifest**

```bash
cat benchmarks/external/manifests/reality-check-csharp.manifest.json | python -m json.tool | head -20
```

Expected: 11 cases listed with CWE-79/89/78 distribution.

- [ ] **Step 6: Commit**

```bash
git add benchmarks/scripts/ingest_reality_check_csharp.py benchmarks/tests/test_ingest_reality_check_csharp.py benchmarks/external/manifests/reality-check-csharp.manifest.json
git commit -m "Phase 0.5 Task 14: ingest reality-check C# subset (9 XSS + 1 SQLi + 1 CmdI)"
```

---

## Task 15: Ingest `reality-check` Python subset

**Files:**
- Create: `benchmarks/scripts/ingest_reality_check_python.py`
- Create: `benchmarks/tests/test_ingest_reality_check_python.py`

**Rationale:** 4 XSS CVEs + 1 CWE-94 (SSTI parent) + path-traversal adjacency. Same structure as Task 14 but targets `python/` subdirectory.

- [ ] **Step 1: Copy Task 14's ingest script, adjust directory and language**

Create the file by applying the diff against `ingest_reality_check_csharp.py`:

```bash
cp benchmarks/scripts/ingest_reality_check_csharp.py benchmarks/scripts/ingest_reality_check_python.py
```

Then edit `benchmarks/scripts/ingest_reality_check_python.py` with these exact replacements:

- Class name: `RealityCheckCsharpIngest` → `RealityCheckPythonIngest`
- `dataset_name = "reality-check-csharp"` → `dataset_name = "reality-check-python"`
- `repo_dir / "csharp"` → `repo_dir / "python"` (2 occurrences)
- `Language.CSHARP` → `Language.PYTHON`
- Case ID prefix: `"rc-csharp-{..."` → `"rc-python-{..."`

- [ ] **Step 2: Create the test file**

```bash
cat > benchmarks/tests/test_ingest_reality_check_python.py <<'EOF'
"""Tests for reality-check Python ingest."""
from pathlib import Path

from benchmarks.scripts.ingest_reality_check_python import (
    PHASE1_CWE_FILTER,
    RealityCheckPythonIngest,
)


def test_phase1_filter_contains_expected_cwes():
    # Python reality-check has 4 XSS + 1 CWE-94 matching Phase 1
    assert "CWE-79" in PHASE1_CWE_FILTER
    assert "CWE-94" in PHASE1_CWE_FILTER


def test_ingest_has_correct_metadata():
    ingest = RealityCheckPythonIngest(root=Path("/tmp/test-root"))
    assert ingest.dataset_name == "reality-check-python"
EOF
```

- [ ] **Step 3: Run tests and ingest**

```bash
uv run pytest benchmarks/tests/test_ingest_reality_check_python.py -v
uv run python -m benchmarks.scripts.ingest_reality_check_python
```

Expected: tests pass; ingest extracts ~5 cases (4 XSS + 1 CWE-94).

- [ ] **Step 4: Commit**

```bash
git add benchmarks/scripts/ingest_reality_check_python.py benchmarks/tests/test_ingest_reality_check_python.py benchmarks/external/manifests/reality-check-python.manifest.json
git commit -m "Phase 0.5 Task 15: ingest reality-check Python subset (4 XSS + 1 CWE-94)"
```

---

## Task 16: Ingest `reality-check` Java subset

**Files:**
- Create: `benchmarks/scripts/ingest_reality_check_java.py`
- Create: `benchmarks/tests/test_ingest_reality_check_java.py`

**Rationale:** Java reality-check has 165 CVEs but is dominated by CWE-502 deserialization. We extract only the Phase 1-relevant subset: **5 XSS + 3 CmdI = 8 cases**. Same ingest pattern as Tasks 14-15.

- [ ] **Step 1: Copy from Task 14, adjust directory and language**

```bash
cp benchmarks/scripts/ingest_reality_check_csharp.py benchmarks/scripts/ingest_reality_check_java.py
```

Edit the new file with replacements analogous to Task 15:
- Class: `RealityCheckJavaIngest`
- `dataset_name = "reality-check-java"`
- `repo_dir / "csharp"` → `repo_dir / "java"` (2 occurrences)
- `Language.CSHARP` → `Language.JAVA`
- Case ID prefix: `"rc-java-..."`

- [ ] **Step 2: Create the test file**

```bash
cat > benchmarks/tests/test_ingest_reality_check_java.py <<'EOF'
"""Tests for reality-check Java ingest."""
from pathlib import Path

from benchmarks.scripts.ingest_reality_check_java import (
    PHASE1_CWE_FILTER,
    RealityCheckJavaIngest,
)


def test_phase1_filter_contains_xss_and_cmdi():
    assert "CWE-79" in PHASE1_CWE_FILTER
    assert "CWE-78" in PHASE1_CWE_FILTER


def test_ingest_has_correct_metadata():
    ingest = RealityCheckJavaIngest(root=Path("/tmp/test-root"))
    assert ingest.dataset_name == "reality-check-java"
EOF
```

- [ ] **Step 3: Run tests and ingest**

```bash
uv run pytest benchmarks/tests/test_ingest_reality_check_java.py -v
uv run python -m benchmarks.scripts.ingest_reality_check_java
```

Expected: 2 tests pass; ingest extracts ~8 cases.

- [ ] **Step 4: Commit**

```bash
git add benchmarks/scripts/ingest_reality_check_java.py benchmarks/tests/test_ingest_reality_check_java.py benchmarks/external/manifests/reality-check-java.manifest.json
git commit -m "Phase 0.5 Task 16: ingest reality-check Java subset (5 XSS + 3 CmdI)"
```

---

## Task 17: Ingest `go-sec-code-mutated` (Go SSTI + CmdI/XSS/SQLi)

**Files:**
- Create: `benchmarks/scripts/ingest_go_sec_code.py`
- Create: `benchmarks/tests/test_ingest_go_sec_code.py`

**Rationale:** `flawgarden/go-sec-code-mutated` is the **only flawgarden asset that covers CWE-1336 (SSTI)** — specifically Go Sprig template injection. It also covers CWE-78 (Beego), CWE-79 (reflected/stored/SVG/PDF), CWE-89 (numeric + string + ORM misuse). This is our Go benchmark for all four Phase 1 CWEs.

**Approach:** go-sec-code-mutated is a fork of `cokeBeer/go-sec-code` — an educational Go vulnerability playground where each vulnerability is a separate Beego controller. The flawgarden fork adds `truth.sarif` files. We walk the module tree and ingest each.

- [ ] **Step 1: Write failing test**

```bash
cat > benchmarks/tests/test_ingest_go_sec_code.py <<'EOF'
"""Tests for go-sec-code-mutated ingest."""
from pathlib import Path

from benchmarks.scripts.ingest_go_sec_code import GoSecCodeIngest, PHASE1_CWE_FILTER


def test_covers_all_phase1_cwes():
    for cwe in ("CWE-78", "CWE-79", "CWE-89", "CWE-1336"):
        assert cwe in PHASE1_CWE_FILTER


def test_ingest_metadata():
    ingest = GoSecCodeIngest(root=Path("/tmp/test-root"))
    assert ingest.dataset_name == "go-sec-code-mutated"
    assert "go-sec-code-mutated" in ingest.source_url
EOF
```

- [ ] **Step 2: Write the ingest script**

```bash
cat > benchmarks/scripts/ingest_go_sec_code.py <<'EOF'
"""Ingest the flawgarden/go-sec-code-mutated benchmark.

Forks cokeBeer/go-sec-code (Beego educational vuln playground) and adds
bentoo-sarif truth files. Primary Phase 1 value: CWE-1336 SSTI via Sprig.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from benchmarks.runner.models import (
    BenchmarkCase,
    Finding,
    FindingKind,
    Language,
)
from benchmarks.runner.sarif import load_bentoo_sarif
from benchmarks.scripts.ingest_base import IngestBase


PHASE1_CWE_FILTER = {"CWE-78", "CWE-79", "CWE-89", "CWE-94", "CWE-1336"}


class GoSecCodeIngest(IngestBase):
    dataset_name = "go-sec-code-mutated"
    source_url = "https://github.com/flawgarden/go-sec-code-mutated"

    def ensure_downloaded(self) -> None:
        repo_dir = self.download_dir / "repo"
        if repo_dir.exists():
            print(f"  already cloned: {repo_dir}")
            return
        print(f"  cloning {self.source_url} ...")
        subprocess.run(
            ["git", "clone", "--depth", "1", self.source_url, str(repo_dir)],
            check=True,
        )

    def extract_cases(self) -> list[BenchmarkCase]:
        repo_dir = self.download_dir / "repo"
        cases: list[BenchmarkCase] = []
        for truth_path in sorted(repo_dir.rglob("truth.sarif")):
            case = self._build_case(truth_path, repo_dir)
            if case is not None:
                cases.append(case)
        return cases

    def _build_case(self, truth_path: Path, repo_dir: Path) -> BenchmarkCase | None:
        fail_findings = load_bentoo_sarif(truth_path)
        phase1 = [f for f in fail_findings if f.cwe_id in PHASE1_CWE_FILTER]
        if not phase1:
            return None

        # Derive a case ID from the directory path relative to repo root
        rel = truth_path.parent.relative_to(repo_dir)
        case_id = f"gosec-{str(rel).replace('/', '-')}"

        pass_findings = [
            Finding(cwe_id=f.cwe_id, kind=FindingKind.PASS, cve_id=f.cve_id,
                    location=f.location, message=f.message)
            for f in phase1
        ]

        return BenchmarkCase(
            case_id=case_id,
            project=str(rel.parts[0]) if rel.parts else "go-sec-code",
            language=Language.GO,
            vulnerable_version="HEAD",
            patched_version="HEAD-patched",
            ground_truth=phase1 + pass_findings,
            published_date=None,  # mutated synthetic — no real CVE date
            source_dataset=self.dataset_name,
        )


def main() -> int:
    GoSecCodeIngest(root=Path("benchmarks")).run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
EOF
```

- [ ] **Step 3: Run tests and ingest**

```bash
uv run pytest benchmarks/tests/test_ingest_go_sec_code.py -v
uv run python -m benchmarks.scripts.ingest_go_sec_code
```

Expected: 2 tests pass; ingest extracts cases covering CWE-78/79/89/1336. Count will depend on how many modules the mutated fork has truth.sarif files for — ballpark 15-40 cases.

- [ ] **Step 4: Commit**

```bash
git add benchmarks/scripts/ingest_go_sec_code.py benchmarks/tests/test_ingest_go_sec_code.py benchmarks/external/manifests/go-sec-code-mutated.manifest.json
git commit -m "Phase 0.5 Task 17: ingest go-sec-code-mutated (SSTI via Sprig, plus CmdI/XSS/SQLi)"
```

---

## Task 18: Ingest `skf-labs-mutated` (Python Flask/Jinja2 SSTI)

**Files:**
- Create: `benchmarks/scripts/ingest_skf_labs.py`
- Create: `benchmarks/tests/test_ingest_skf_labs.py`

**Rationale:** Second flawgarden asset with CWE-1336 coverage — Python Flask/Jinja2 SSTI via OWASP SKF labs. Same shape as Task 17 but targets the `skf-labs-mutated` repo and Python.

- [ ] **Step 1: Copy Task 17's script**

```bash
cp benchmarks/scripts/ingest_go_sec_code.py benchmarks/scripts/ingest_skf_labs.py
```

Edit the new file with these exact replacements:
- Class name: `GoSecCodeIngest` → `SkfLabsIngest`
- `dataset_name = "go-sec-code-mutated"` → `dataset_name = "skf-labs-mutated"`
- `source_url = "https://github.com/flawgarden/go-sec-code-mutated"` → `"https://github.com/flawgarden/skf-labs-mutated"`
- `Language.GO` → `Language.PYTHON`
- Case ID prefix: `"gosec-..."` → `"skf-..."`
- Project fallback: `"go-sec-code"` → `"skf-labs"`

- [ ] **Step 2: Test file**

```bash
cat > benchmarks/tests/test_ingest_skf_labs.py <<'EOF'
"""Tests for skf-labs-mutated ingest."""
from pathlib import Path

from benchmarks.scripts.ingest_skf_labs import PHASE1_CWE_FILTER, SkfLabsIngest


def test_covers_ssti():
    assert "CWE-1336" in PHASE1_CWE_FILTER


def test_ingest_metadata():
    ingest = SkfLabsIngest(root=Path("/tmp/test-root"))
    assert ingest.dataset_name == "skf-labs-mutated"
EOF
```

- [ ] **Step 3: Run and commit**

```bash
uv run pytest benchmarks/tests/test_ingest_skf_labs.py -v
uv run python -m benchmarks.scripts.ingest_skf_labs

git add benchmarks/scripts/ingest_skf_labs.py benchmarks/tests/test_ingest_skf_labs.py benchmarks/external/manifests/skf-labs-mutated.manifest.json
git commit -m "Phase 0.5 Task 18: ingest skf-labs-mutated (Python Flask/Jinja2 SSTI)"
```

---

## Task 19: Ingest `CrossVul` (PHP/Ruby real CVEs)

**Files:**
- Create: `benchmarks/scripts/ingest_crossvul.py`
- Create: `benchmarks/tests/test_ingest_crossvul.py`

**Rationale:** CrossVul (ESEC/FSE 2021, Nikitopoulos et al.) is the **only benchmark with substantial real PHP and Ruby coverage**. 40+ languages, 168 CWEs, derived from NVD + real project commits. No other source gives us real PHP/Ruby CVEs for injection classes.

**Approach:** CrossVul is distributed as a tarball on Zenodo (https://doi.org/10.5281/zenodo.4734050). Structure is one directory per CWE, with subdirectories per CVE containing `vuln/` and `fix/` code snapshots. We download the tarball, walk the tree, filter to Phase 1 CWEs × {PHP, Ruby}, and build cases.

- [ ] **Step 1: Write failing test**

```bash
cat > benchmarks/tests/test_ingest_crossvul.py <<'EOF'
"""Tests for CrossVul ingest."""
from pathlib import Path

from benchmarks.scripts.ingest_crossvul import CrossVulIngest, PHASE1_LANGUAGES


def test_targets_php_and_ruby():
    assert "php" in PHASE1_LANGUAGES
    assert "ruby" in PHASE1_LANGUAGES


def test_ingest_metadata():
    ingest = CrossVulIngest(root=Path("/tmp/test-root"))
    assert ingest.dataset_name == "crossvul"
    assert "zenodo.org" in ingest.source_url
EOF
```

- [ ] **Step 2: Write the ingest script**

```bash
cat > benchmarks/scripts/ingest_crossvul.py <<'EOF'
"""Ingest CrossVul (ESEC/FSE 2021) — real PHP and Ruby CVEs.

Source: https://zenodo.org/record/4734050
Publication: Nikitopoulos et al., "CrossVul: A Cross-Language Vulnerability
Dataset with Commit Data", ESEC/FSE 2021.

Dataset structure: tarball with one directory per CWE, subdirectories per CVE
containing `vuln/` (pre-fix) and `fix/` (post-fix) code snapshots. File
extensions determine the language.
"""
from __future__ import annotations

import sys
import tarfile
import urllib.request
from pathlib import Path

from benchmarks.runner.models import (
    BenchmarkCase,
    CodeLocation,
    Finding,
    FindingKind,
    Language,
)
from benchmarks.scripts.ingest_base import IngestBase


PHASE1_CWES = {"79", "78", "89", "94", "1336"}
PHASE1_LANGUAGES = {"php", "ruby"}

# Zenodo API record ID for CrossVul v2.1 (most recent as of 2026-04-09)
ZENODO_RECORD = "4734050"
TARBALL_URL = f"https://zenodo.org/record/{ZENODO_RECORD}/files/CrossVul.tar.gz"


class CrossVulIngest(IngestBase):
    dataset_name = "crossvul"
    source_url = f"https://zenodo.org/record/{ZENODO_RECORD}"

    def ensure_downloaded(self) -> None:
        extract_dir = self.download_dir / "CrossVul"
        if extract_dir.exists():
            print(f"  already extracted: {extract_dir}")
            return

        tarball = self.download_dir / "CrossVul.tar.gz"
        if not tarball.exists():
            print(f"  downloading {TARBALL_URL} ...")
            urllib.request.urlretrieve(TARBALL_URL, tarball)

        print(f"  extracting {tarball} ...")
        with tarfile.open(tarball, "r:gz") as tf:
            tf.extractall(self.download_dir)

    def extract_cases(self) -> list[BenchmarkCase]:
        crossvul_root = self.download_dir / "CrossVul"
        if not crossvul_root.exists():
            raise RuntimeError(f"CrossVul not extracted to {crossvul_root}")

        cases: list[BenchmarkCase] = []
        # Walk CrossVul/CWE-<id>/<CVE-id>/
        for cwe_dir in crossvul_root.iterdir():
            if not cwe_dir.is_dir():
                continue
            cwe_id = _extract_cwe_id(cwe_dir.name)
            if cwe_id not in PHASE1_CWES:
                continue
            for cve_dir in cwe_dir.iterdir():
                if not cve_dir.is_dir():
                    continue
                case = self._build_case(cve_dir, cwe_id)
                if case is not None:
                    cases.append(case)
        return cases

    def _build_case(self, cve_dir: Path, cwe_id: str) -> BenchmarkCase | None:
        vuln_dir = cve_dir / "vuln"
        fix_dir = cve_dir / "fix"
        if not vuln_dir.exists() or not fix_dir.exists():
            return None

        # Determine language from first vulnerable file extension
        lang = _detect_language(vuln_dir)
        if lang is None:
            return None

        fail_findings: list[Finding] = []
        pass_findings: list[Finding] = []
        for vuln_file in sorted(vuln_dir.rglob("*")):
            if not vuln_file.is_file():
                continue
            rel = vuln_file.relative_to(vuln_dir)
            code = vuln_file.read_text(errors="replace")
            line_count = len(code.splitlines())
            loc = CodeLocation(
                file=str(rel), start_line=1, end_line=max(line_count, 1),
            )
            fail_findings.append(Finding(
                cwe_id=f"CWE-{cwe_id}", kind=FindingKind.FAIL,
                cve_id=cve_dir.name, location=loc, message=cve_dir.name,
            ))
            pass_findings.append(Finding(
                cwe_id=f"CWE-{cwe_id}", kind=FindingKind.PASS,
                cve_id=cve_dir.name, location=loc, message=cve_dir.name,
            ))

        if not fail_findings:
            return None

        return BenchmarkCase(
            case_id=f"crossvul-{cwe_id}-{cve_dir.name}",
            project=cve_dir.name,
            language=lang,
            vulnerable_version="vuln",
            patched_version="fix",
            ground_truth=fail_findings + pass_findings,
            published_date=None,
            source_dataset=self.dataset_name,
        )


def _extract_cwe_id(name: str) -> str:
    digits = "".join(ch for ch in name if ch.isdigit())
    return digits


def _detect_language(vuln_dir: Path) -> Language | None:
    for f in vuln_dir.rglob("*"):
        if not f.is_file():
            continue
        suffix = f.suffix.lower()
        if suffix in (".php",):
            return Language.PHP
        if suffix in (".rb",):
            return Language.RUBY
    return None


def main() -> int:
    CrossVulIngest(root=Path("benchmarks")).run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
EOF
```

- [ ] **Step 3: Run tests and ingest**

```bash
uv run pytest benchmarks/tests/test_ingest_crossvul.py -v
uv run python -m benchmarks.scripts.ingest_crossvul
```

Expected: tests pass; ingest downloads ~100 MB tarball and extracts. Case count depends on CrossVul's Phase 1 × {PHP, Ruby} intersection — expect 20-80 cases.

If the tarball URL has moved (Zenodo versions data occasionally), update `TARBALL_URL` to the current record version from `https://zenodo.org/record/4734050`.

- [ ] **Step 4: Commit**

```bash
git add benchmarks/scripts/ingest_crossvul.py benchmarks/tests/test_ingest_crossvul.py benchmarks/external/manifests/crossvul.manifest.json
git commit -m "Phase 0.5 Task 19: ingest CrossVul PHP/Ruby real CVEs"
```

---

## Task 20: Ingest `Vul4J` (Java precision benchmark)

**Files:**
- Create: `benchmarks/scripts/ingest_vul4j.py`
- Create: `benchmarks/tests/test_ingest_vul4j.py`

**Rationale:** Vul4J ships **79 Java CVEs with reproducible Proof-of-Vulnerability (PoV) test cases**. Smaller than reality-check Java but uniquely valuable because each vulnerability comes with an executable test that confirms exploitability — excellent for precision benchmarks.

**Repo:** https://github.com/tuhh-softsec/vul4j (or https://github.com/serval-snt-uni-lu/vul4j — the active fork).

**Approach:** Clone the repo, parse `vul4j/data/vulnerability_list.csv` (or `data/vulnerability_data.csv`), filter to Phase 1 CWEs, and for each CVE record file paths from the CSV. Note: Vul4J's ground truth is coarser than reality-check (project-level, not method-level) — we record file-level locations only.

- [ ] **Step 1: Write failing test**

```bash
cat > benchmarks/tests/test_ingest_vul4j.py <<'EOF'
"""Tests for Vul4J ingest."""
from pathlib import Path

from benchmarks.scripts.ingest_vul4j import PHASE1_CWE_FILTER, Vul4JIngest


def test_filter_covers_phase1():
    for cwe in ("CWE-78", "CWE-79", "CWE-89"):
        assert cwe in PHASE1_CWE_FILTER


def test_ingest_metadata():
    ingest = Vul4JIngest(root=Path("/tmp/test-root"))
    assert ingest.dataset_name == "vul4j"
    assert "vul4j" in ingest.source_url.lower()
EOF
```

- [ ] **Step 2: Write the ingest script**

```bash
cat > benchmarks/scripts/ingest_vul4j.py <<'EOF'
"""Ingest Vul4J — 79 Java CVEs with reproducible PoV test cases.

Source: https://github.com/tuhh-softsec/vul4j (or the active fork)
Each CVE includes a build script and a failing test that passes after the
fix. Provides precision evaluation — we know the exact file was exploitable.
"""
from __future__ import annotations

import csv
import subprocess
import sys
from pathlib import Path

from benchmarks.runner.models import (
    BenchmarkCase,
    CodeLocation,
    Finding,
    FindingKind,
    Language,
)
from benchmarks.scripts.ingest_base import IngestBase


PHASE1_CWE_FILTER = {"CWE-78", "CWE-79", "CWE-89", "CWE-94", "CWE-1336"}


class Vul4JIngest(IngestBase):
    dataset_name = "vul4j"
    source_url = "https://github.com/tuhh-softsec/vul4j"

    def ensure_downloaded(self) -> None:
        repo_dir = self.download_dir / "repo"
        if repo_dir.exists():
            print(f"  already cloned: {repo_dir}")
            return
        print(f"  cloning {self.source_url} ...")
        subprocess.run(
            ["git", "clone", "--depth", "1", self.source_url, str(repo_dir)],
            check=True,
        )

    def extract_cases(self) -> list[BenchmarkCase]:
        repo_dir = self.download_dir / "repo"
        # Vul4J's vulnerability list has lived at a few paths over time.
        candidates = [
            repo_dir / "vul4j" / "data" / "vulnerability_list.csv",
            repo_dir / "data" / "vulnerability_list.csv",
            repo_dir / "vul4j" / "data" / "vulnerability_data.csv",
            repo_dir / "data" / "vulnerability_data.csv",
        ]
        csv_path = next((p for p in candidates if p.exists()), None)
        if csv_path is None:
            print(f"  WARN: vulnerability CSV not found; tried {candidates}")
            return []

        cases: list[BenchmarkCase] = []
        with csv_path.open() as f:
            reader = csv.DictReader(f)
            for row in reader:
                case = self._build_case(row, repo_dir)
                if case is not None:
                    cases.append(case)
        return cases

    def _build_case(self, row: dict, repo_dir: Path) -> BenchmarkCase | None:
        # Row columns vary across forks; try common names.
        cwe_raw = row.get("cwe_id") or row.get("cwe") or row.get("CWE") or ""
        cwe_id = _normalize_cwe(cwe_raw)
        if cwe_id not in PHASE1_CWE_FILTER:
            return None

        cve = row.get("cve_id") or row.get("cve") or row.get("CVE") or "UNKNOWN"
        project = row.get("project_id") or row.get("project") or row.get("repo") or "unknown"
        files_raw = row.get("human_patch") or row.get("files") or row.get("modified_files") or ""

        # human_patch is often a semicolon-separated list of file paths
        files = [p.strip() for p in files_raw.replace(",", ";").split(";") if p.strip()]
        if not files:
            files = ["<unknown>"]

        fail_findings: list[Finding] = []
        pass_findings: list[Finding] = []
        for path in files:
            loc = CodeLocation(file=path, start_line=1, end_line=1)
            fail_findings.append(Finding(
                cwe_id=cwe_id, kind=FindingKind.FAIL, cve_id=cve,
                location=loc, message=cve,
            ))
            pass_findings.append(Finding(
                cwe_id=cwe_id, kind=FindingKind.PASS, cve_id=cve,
                location=loc, message=cve,
            ))

        return BenchmarkCase(
            case_id=f"vul4j-{cve}",
            project=project,
            language=Language.JAVA,
            vulnerable_version=row.get("buggy_commit") or "buggy",
            patched_version=row.get("fixed_commit") or "fixed",
            ground_truth=fail_findings + pass_findings,
            published_date=None,
            source_dataset=self.dataset_name,
        )


def _normalize_cwe(raw: str) -> str:
    digits = "".join(ch for ch in raw if ch.isdigit())
    return f"CWE-{int(digits)}" if digits else raw


def main() -> int:
    Vul4JIngest(root=Path("benchmarks")).run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
EOF
```

- [ ] **Step 3: Run tests and ingest**

```bash
uv run pytest benchmarks/tests/test_ingest_vul4j.py -v
uv run python -m benchmarks.scripts.ingest_vul4j
```

Expected: tests pass; ingest extracts a small number of cases (Vul4J's 79 CVEs, filtered to Phase 1 CWEs → probably 5-15 cases).

- [ ] **Step 4: Commit**

```bash
git add benchmarks/scripts/ingest_vul4j.py benchmarks/tests/test_ingest_vul4j.py benchmarks/external/manifests/vul4j.manifest.json
git commit -m "Phase 0.5 Task 20: ingest Vul4J (Java CVEs with PoV test cases)"
```

---

## Task 21: Deploy MoreFixes Postgres dump via docker-compose

**Files:**
- Create: `benchmarks/external/morefixes/docker-compose.yml`
- Create: `benchmarks/scripts/deploy_morefixes.sh`
- Create: `benchmarks/external/manifests/morefixes-deployment.manifest.json`

**Rationale:** MoreFixes (JafarAkhondali/Morefixes, PROMISE 2024) is a strict superset of CVEfixes with GHSA ingestion — critical for multi-language coverage. 29,203 unique CVEs, 16 GB Postgres dump, 2024-09-26 cutoff. Dataset is distributed as a SQL dump on Zenodo (https://doi.org/10.5281/zenodo.13983082).

**Deployment approach:** Docker container running Postgres with the dump auto-loaded at startup via `docker-entrypoint-initdb.d/`. This keeps our runtime environment clean — no Postgres install on the host.

- [ ] **Step 1: Create the docker-compose file**

```bash
mkdir -p benchmarks/external/morefixes
cat > benchmarks/external/morefixes/docker-compose.yml <<'EOF'
# MoreFixes Postgres deployment for screw-agents Phase 0.5
# Automatically loads postgrescvedumper-2024-09-26.sql at container startup

services:
  morefixes-db:
    image: postgres:16-alpine
    container_name: morefixes-db
    restart: unless-stopped
    environment:
      POSTGRES_USER: morefixes
      POSTGRES_PASSWORD: morefixes
      POSTGRES_DB: morefixes
    ports:
      - "54321:5432"  # Non-standard port to avoid host conflicts
    volumes:
      - ./dump:/docker-entrypoint-initdb.d:ro
      - morefixes_data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U morefixes -d morefixes"]
      interval: 10s
      timeout: 5s
      retries: 30
      start_period: 120s  # First-time dump load takes a while

volumes:
  morefixes_data:
EOF
```

- [ ] **Step 2: Create the deployment helper script**

```bash
cat > benchmarks/scripts/deploy_morefixes.sh <<'EOF'
#!/usr/bin/env bash
# Deploy MoreFixes Postgres dump via docker-compose.
# Idempotent — skips download if dump already present.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
DUMP_DIR="$ROOT_DIR/external/morefixes/dump"
DUMP_FILE="$DUMP_DIR/postgrescvedumper-2024-09-26.sql"
ZENODO_URL="https://zenodo.org/record/13983082/files/postgrescvedumper-2024-09-26.sql"
COMPOSE_FILE="$ROOT_DIR/external/morefixes/docker-compose.yml"

mkdir -p "$DUMP_DIR"

if [ ! -f "$DUMP_FILE" ]; then
    echo "Downloading MoreFixes dump from $ZENODO_URL ..."
    echo "(This is a 16 GB file — be patient)"
    curl -L --output "$DUMP_FILE" "$ZENODO_URL"
else
    echo "Dump already present: $DUMP_FILE"
fi

echo "Starting docker-compose ..."
docker compose -f "$COMPOSE_FILE" up -d

echo ""
echo "Waiting for Postgres to finish loading the dump ..."
echo "(First-time load may take 10-20 minutes for 16 GB.)"

for i in {1..120}; do
    if docker compose -f "$COMPOSE_FILE" exec -T morefixes-db pg_isready -U morefixes -d morefixes >/dev/null 2>&1; then
        echo "Database is ready."
        break
    fi
    sleep 15
    if [ $i -eq 120 ]; then
        echo "ERROR: database did not become ready after 30 minutes" >&2
        exit 1
    fi
done

echo ""
echo "Verify with: docker compose -f $COMPOSE_FILE exec morefixes-db psql -U morefixes -d morefixes -c '\\dt'"
EOF
chmod +x benchmarks/scripts/deploy_morefixes.sh
```

- [ ] **Step 3: Verify docker is available, then run the deployment**

```bash
docker --version
docker compose version

# Run the deployment (this downloads 16 GB and takes 10-20 minutes)
bash benchmarks/scripts/deploy_morefixes.sh
```

Expected: docker downloads the dump, starts the container, waits for readiness, prints "Database is ready."

If you want to skip the download and use a locally-cached dump, place `postgrescvedumper-2024-09-26.sql` into `benchmarks/external/morefixes/dump/` before running the script.

- [ ] **Step 4: Introspect the schema (discovery — column names are not documented)**

```bash
docker compose -f benchmarks/external/morefixes/docker-compose.yml exec morefixes-db \
    psql -U morefixes -d morefixes -c "\dt"

docker compose -f benchmarks/external/morefixes/docker-compose.yml exec morefixes-db \
    psql -U morefixes -d morefixes -c "\d fixes"

docker compose -f benchmarks/external/morefixes/docker-compose.yml exec morefixes-db \
    psql -U morefixes -d morefixes -c "\d method_change"
```

Expected: lists tables including `fixes`, `commits`, `file_change`, `method_change`. Record the exact column names for language, CWE, and pre/post code — these feed Task 22.

- [ ] **Step 5: Write the deployment manifest with discovered schema**

Edit `benchmarks/external/manifests/morefixes-deployment.manifest.json` (fill in the column names you discovered in Step 4):

```bash
cat > benchmarks/external/manifests/morefixes-deployment.manifest.json <<'EOF'
{
  "dataset_name": "morefixes",
  "source_zenodo": "https://doi.org/10.5281/zenodo.13983082",
  "source_code": "https://github.com/JafarAkhondali/Morefixes",
  "dump_file": "postgrescvedumper-2024-09-26.sql",
  "deployment": {
    "compose_file": "benchmarks/external/morefixes/docker-compose.yml",
    "db_host": "localhost",
    "db_port": 54321,
    "db_name": "morefixes",
    "db_user": "morefixes"
  },
  "schema_discovery_date": "REPLACE_WITH_TODAY",
  "key_tables": {
    "fixes": {"purpose": "CVE fix metadata with score column"},
    "commits": {"purpose": "Commits with score >= 65 (filtered)"},
    "file_change": {"purpose": "File-level code modifications"},
    "method_change": {"purpose": "Method-level code modifications"}
  },
  "notes": "Column names for language/CWE vary by table — see extraction query in benchmarks/scripts/morefixes_extract.py for the canonical query"
}
EOF
```

Update `schema_discovery_date` to the current date.

- [ ] **Step 6: Commit the deployment scaffolding**

```bash
git add benchmarks/external/morefixes/docker-compose.yml benchmarks/scripts/deploy_morefixes.sh benchmarks/external/manifests/morefixes-deployment.manifest.json
git commit -m "Phase 0.5 Task 21: deploy MoreFixes Postgres dump via docker-compose"
```

---

## Task 22: Write MoreFixes extraction query and filter script (`benchmarks/scripts/morefixes_extract.py`)

**Files:**
- Create: `benchmarks/scripts/morefixes_extract.py`
- Create: `benchmarks/tests/test_morefixes_extract.py`

**Rationale:** With MoreFixes deployed (Task 21), write a script that queries the Postgres database, filters to our Phase 1 CWEs × 8 target languages, extracts pre/post code pairs with method-level locations, applies confidence threshold ≥65, and materializes into bentoo-sarif ground-truth files.

**Constraint:** We depend on the exact schema discovered in Task 21 Step 4. The script uses a configurable column-name mapping so it survives minor MoreFixes schema drift.

- [ ] **Step 1: Add `psycopg2-binary` (or `psycopg[binary]`) to dev deps**

Edit `pyproject.toml`:

```toml
[dependency-groups]
dev = [
    "pytest>=8.0",
    "pytest-cov>=5.0",
    "tree-sitter-languages>=1.10",
    "psycopg[binary]>=3.1",
]
```

Then:

```bash
uv sync
```

- [ ] **Step 2: Write a failing smoke test**

```bash
cat > benchmarks/tests/test_morefixes_extract.py <<'EOF'
"""Smoke tests for MoreFixes extract — no DB connection required."""
from pathlib import Path

from benchmarks.scripts.morefixes_extract import (
    MoreFixesExtractor,
    PHASE1_CWES,
    PHASE1_LANGUAGES,
    build_query,
)


def test_phase1_cwes_present():
    for cwe in (79, 78, 89, 94, 1336):
        assert cwe in PHASE1_CWES


def test_phase1_languages_all_present():
    for lang in ("python", "javascript", "typescript", "java", "go", "ruby", "php", "csharp"):
        assert lang in PHASE1_LANGUAGES


def test_build_query_has_cwe_and_language_filters():
    q = build_query(min_score=65)
    assert "cwe" in q.lower()
    assert "language" in q.lower() or "programming_language" in q.lower()
    assert "65" in q
EOF
```

- [ ] **Step 3: Write the extraction script**

```bash
cat > benchmarks/scripts/morefixes_extract.py <<'EOF'
"""Extract filtered CVE fixes from the MoreFixes Postgres dump.

Requires Task 21 deployment (docker-compose up running on localhost:54321).

Query logic:
  - Select fixes where CWE ∈ Phase 1 CWEs and language ∈ 8 target languages
  - Require score >= 65 (MoreFixes confidence threshold)
  - Join with method_change to get pre/post function code
  - Emit one BenchmarkCase per distinct (CVE, file, method) tuple

Schema assumptions (adjust the CONFIG dict to match your Task 21 Step 4
schema discovery if column names differ):
"""
from __future__ import annotations

import sys
from datetime import date
from pathlib import Path

from benchmarks.runner.models import (
    BenchmarkCase,
    CodeLocation,
    Finding,
    FindingKind,
    Language,
)
from benchmarks.scripts.ingest_base import IngestBase


PHASE1_CWES = {79, 78, 89, 94, 1336}
PHASE1_LANGUAGES = {
    "python", "javascript", "typescript", "java", "go", "ruby", "php", "csharp",
}

# Adjust this mapping if the MoreFixes schema differs from your discovery in Task 21.
SCHEMA_CONFIG = {
    "fixes_table": "fixes",
    "method_change_table": "method_change",
    "cve_id_column": "cve_id",
    "cwe_column": "cwe_id",
    "language_column": "programming_language",
    "score_column": "score",
    "file_path_column": "filename",
    "method_name_column": "method_name",
    "pre_code_column": "before_change",
    "post_code_column": "after_change",
    "start_line_column": "start_line",
    "end_line_column": "end_line",
    "published_date_column": "published_date",
    "project_column": "repo_name",
}

LANGUAGE_MAP = {
    "python": Language.PYTHON,
    "javascript": Language.JAVASCRIPT,
    "typescript": Language.TYPESCRIPT,
    "java": Language.JAVA,
    "go": Language.GO,
    "ruby": Language.RUBY,
    "php": Language.PHP,
    "csharp": Language.CSHARP,
    "c#": Language.CSHARP,
}


def build_query(min_score: int = 65) -> str:
    """Produce the SQL query to extract Phase 1-relevant fixes."""
    c = SCHEMA_CONFIG
    cwe_list = ",".join(str(x) for x in sorted(PHASE1_CWES))
    lang_list = ",".join(f"'{x}'" for x in sorted(PHASE1_LANGUAGES))
    return f"""
    SELECT
        f.{c["cve_id_column"]} AS cve_id,
        f.{c["cwe_column"]} AS cwe,
        f.{c["language_column"]} AS language,
        f.{c["project_column"]} AS project,
        f.{c["published_date_column"]} AS published_date,
        m.{c["file_path_column"]} AS file_path,
        m.{c["method_name_column"]} AS method_name,
        m.{c["start_line_column"]} AS start_line,
        m.{c["end_line_column"]} AS end_line
    FROM {c["fixes_table"]} f
    JOIN {c["method_change_table"]} m USING ({c["cve_id_column"]})
    WHERE f.{c["score_column"]} >= {min_score}
      AND f.{c["cwe_column"]} IN ({cwe_list})
      AND LOWER(f.{c["language_column"]}) IN ({lang_list})
    ORDER BY f.{c["cve_id_column"]}, m.{c["file_path_column"]}, m.{c["start_line_column"]};
    """


class MoreFixesExtractor(IngestBase):
    dataset_name = "morefixes-extract"
    source_url = "https://doi.org/10.5281/zenodo.13983082"

    def __init__(self, root: Path, min_score: int = 65) -> None:
        super().__init__(root)
        self.min_score = min_score

    def ensure_downloaded(self) -> None:
        # The dump is deployed by Task 21. We just verify the DB is reachable.
        try:
            import psycopg  # noqa: F401
        except ImportError:
            raise RuntimeError(
                "psycopg not installed. Run `uv sync` to install dev deps."
            )
        # Ping the DB
        conn = self._connect()
        conn.close()

    def extract_cases(self) -> list[BenchmarkCase]:
        conn = self._connect()
        cur = conn.cursor()
        query = build_query(min_score=self.min_score)
        try:
            cur.execute(query)
        except Exception as exc:
            print(f"  ERROR running query: {exc}", file=sys.stderr)
            print("  SCHEMA MISMATCH — adjust SCHEMA_CONFIG in "
                  "benchmarks/scripts/morefixes_extract.py to match your "
                  "Task 21 Step 4 discovery.", file=sys.stderr)
            return []

        cases: list[BenchmarkCase] = []
        for row in cur.fetchall():
            case = self._row_to_case(row)
            if case is not None:
                cases.append(case)
        conn.close()
        return cases

    def _connect(self):
        import psycopg
        return psycopg.connect(
            host="localhost",
            port=54321,
            dbname="morefixes",
            user="morefixes",
            password="morefixes",
        )

    def _row_to_case(self, row) -> BenchmarkCase | None:
        cve_id, cwe, language, project, published, file_path, method, start_line, end_line = row
        lang_enum = LANGUAGE_MAP.get((language or "").strip().lower())
        if lang_enum is None:
            return None

        cwe_str = f"CWE-{cwe}" if isinstance(cwe, int) else str(cwe)
        loc = CodeLocation(
            file=file_path or "<unknown>",
            start_line=int(start_line or 1),
            end_line=int(end_line or start_line or 1),
            function_name=method,
        )
        published_date = published if isinstance(published, date) else None

        return BenchmarkCase(
            case_id=f"mf-{cve_id}-{hash(file_path)%10000:04d}",
            project=project or "unknown",
            language=lang_enum,
            vulnerable_version="pre-fix",
            patched_version="post-fix",
            ground_truth=[
                Finding(cwe_id=cwe_str, kind=FindingKind.FAIL, cve_id=cve_id,
                        location=loc, message=cve_id),
                Finding(cwe_id=cwe_str, kind=FindingKind.PASS, cve_id=cve_id,
                        location=loc, message=cve_id),
            ],
            published_date=published_date,
            source_dataset=self.dataset_name,
        )


def main() -> int:
    MoreFixesExtractor(root=Path("benchmarks")).run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
EOF
```

- [ ] **Step 4: Run unit tests**

```bash
uv run pytest benchmarks/tests/test_morefixes_extract.py -v
```

Expected: 3 tests PASS (unit tests don't need DB connection).

- [ ] **Step 5: Run the extraction against the live Postgres container**

```bash
uv run python -m benchmarks.scripts.morefixes_extract
```

Expected: `[morefixes-extract] Extracted N cases` where N is likely in the hundreds-to-thousands range across the 8 target languages.

If the query fails with column errors, go back to Task 21 Step 4, record the actual column names, and update `SCHEMA_CONFIG` at the top of `morefixes_extract.py`.

- [ ] **Step 6: Verify manifest**

```bash
cat benchmarks/external/manifests/morefixes-extract.manifest.json | python -m json.tool | head -30
```

Expected: manifest with a `case_count` in the hundreds+ and per-language distribution via the `cases` array.

- [ ] **Step 7: Commit**

```bash
git add benchmarks/scripts/morefixes_extract.py benchmarks/tests/test_morefixes_extract.py benchmarks/external/manifests/morefixes-extract.manifest.json pyproject.toml
git commit -m "Phase 0.5 Task 22: MoreFixes extraction query + filter script"
```

---

## Task 23: Apply PrimeVul dedup across all ingested benchmarks

**Files:**
- Create: `benchmarks/scripts/apply_dedup.py`
- Create: `benchmarks/tests/test_apply_dedup.py`

**Rationale:** Tasks 13-22 produced ingested benchmarks but each dataset has its own duplicates AND there are likely cross-dataset duplicates (the same CVE may appear in reality-check, CrossVul, AND MoreFixes). Task 23 loads all ingested cases, applies `primevul.dedupe()` from Task 8, and writes a deduplicated manifest.

- [ ] **Step 1: Write failing test**

```bash
cat > benchmarks/tests/test_apply_dedup.py <<'EOF'
"""Tests for apply_dedup.py."""
import json
from pathlib import Path

import pytest

from benchmarks.scripts.apply_dedup import load_all_cases


def test_load_all_cases_handles_empty(tmp_path: Path):
    # No manifests present → empty list
    (tmp_path / "external" / "manifests").mkdir(parents=True)
    cases = load_all_cases(tmp_path)
    assert cases == []
EOF
```

- [ ] **Step 2: Write the dedup script**

```bash
cat > benchmarks/scripts/apply_dedup.py <<'EOF'
"""Apply PrimeVul dedup across all ingested benchmarks.

Reads every *.manifest.json in benchmarks/external/manifests/, reconstructs
the BenchmarkCase objects (by re-loading each case's truth.sarif), runs
dedupe() from benchmarks.runner.primevul, and writes a unified deduplicated
manifest to benchmarks/external/manifests/_deduplicated.manifest.json.
"""
from __future__ import annotations

import json
import sys
from datetime import date, datetime, timezone
from pathlib import Path

from benchmarks.runner.models import BenchmarkCase, Language
from benchmarks.runner.primevul import dedupe
from benchmarks.runner.sarif import load_bentoo_sarif


def load_all_cases(root: Path) -> list[BenchmarkCase]:
    """Reconstruct all ingested BenchmarkCase objects from their manifests."""
    manifests_dir = root / "external" / "manifests"
    if not manifests_dir.exists():
        return []

    cases: list[BenchmarkCase] = []
    for manifest_file in sorted(manifests_dir.glob("*.manifest.json")):
        if manifest_file.name.startswith("_"):
            continue  # skip derived manifests
        if manifest_file.name == "cve-ingest-pin.json":
            continue  # not a benchmark manifest
        if manifest_file.name == "morefixes-deployment.manifest.json":
            continue  # deployment metadata, not cases

        try:
            data = json.loads(manifest_file.read_text())
        except Exception as exc:
            print(f"  skipping {manifest_file}: {exc}")
            continue

        dataset_name = data.get("dataset_name", manifest_file.stem.replace(".manifest", ""))
        dataset_dir = root / "external" / dataset_name
        for case_meta in data.get("cases", []):
            case = _rehydrate_case(case_meta, dataset_dir, dataset_name)
            if case is not None:
                cases.append(case)
    return cases


def _rehydrate_case(meta: dict, dataset_dir: Path, dataset_name: str) -> BenchmarkCase | None:
    case_id = meta.get("case_id")
    if not case_id:
        return None
    truth_path = dataset_dir / case_id / "truth.sarif"
    if not truth_path.exists():
        return None
    try:
        findings = load_bentoo_sarif(truth_path)
    except Exception:
        return None

    lang_str = meta.get("language", "python")
    try:
        language = Language(lang_str)
    except ValueError:
        return None

    published_raw = meta.get("published_date")
    published = None
    if published_raw:
        try:
            published = date.fromisoformat(published_raw)
        except ValueError:
            pass

    return BenchmarkCase(
        case_id=case_id,
        project=meta.get("project", "unknown"),
        language=language,
        vulnerable_version=meta.get("vulnerable_version", ""),
        patched_version=meta.get("patched_version", ""),
        ground_truth=findings,
        published_date=published,
        source_dataset=dataset_name,
    )


def main() -> int:
    root = Path("benchmarks")
    print("Loading all ingested cases ...")
    all_cases = load_all_cases(root)
    print(f"  loaded {len(all_cases)} cases from all manifests")

    print("Applying PrimeVul dedup ...")
    deduped = dedupe(all_cases)
    print(f"  {len(all_cases)} → {len(deduped)} after dedup "
          f"({len(all_cases) - len(deduped)} duplicates removed)")

    # Write the deduplicated union manifest
    manifest = {
        "dataset_name": "_deduplicated",
        "union_of": [c.source_dataset for c in deduped],
        "pre_dedup_count": len(all_cases),
        "post_dedup_count": len(deduped),
        "dedup_method": "primevul-sha256-ast-normalized",
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "cases": [
            {
                "case_id": c.case_id,
                "source_dataset": c.source_dataset,
                "project": c.project,
                "language": c.language.value,
                "published_date": c.published_date.isoformat() if c.published_date else None,
            }
            for c in deduped
        ],
    }
    out_path = root / "external" / "manifests" / "_deduplicated.manifest.json"
    out_path.write_text(json.dumps(manifest, indent=2))
    print(f"Wrote {out_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
EOF
```

- [ ] **Step 3: Run unit tests**

```bash
uv run pytest benchmarks/tests/test_apply_dedup.py -v
```

Expected: 1 test PASS.

- [ ] **Step 4: Run dedup against all ingested benchmarks**

```bash
uv run python -m benchmarks.scripts.apply_dedup
```

Expected: `loaded N cases from all manifests; N → M after dedup (K duplicates removed)`. Observe how many duplicates were found — if the number is suspicious (e.g., ALL cases are duplicates), inspect by sampling a few from the dedup log.

- [ ] **Step 5: Commit**

```bash
git add benchmarks/scripts/apply_dedup.py benchmarks/tests/test_apply_dedup.py benchmarks/external/manifests/_deduplicated.manifest.json
git commit -m "Phase 0.5 Task 23: apply PrimeVul dedup across all ingested benchmarks"
```

---

## Task 24: Generate chronological and cross-project splits

**Files:**
- Create: `benchmarks/scripts/apply_splits.py`
- Create: `benchmarks/tests/test_apply_splits.py`

**Rationale:** With dedup done (Task 23), now generate the training/test splits per PrimeVul methodology. Two split types:
- **Chronological** — one cutoff date (default: 2024-01-01). Everything before goes to training; everything at/after goes to test.
- **Cross-project** — one project ID per holdout. Generates one split per distinct project in the dedup set; each holds out ONE project from training.

- [ ] **Step 1: Write the script**

```bash
cat > benchmarks/scripts/apply_splits.py <<'EOF'
"""Generate chronological and cross-project splits from the dedup manifest.

Outputs:
  benchmarks/external/manifests/_chrono_split.manifest.json
  benchmarks/external/manifests/_cross_project_splits.manifest.json

The chrono split has one cutoff date. The cross-project split enumerates
every project and generates a holdout entry per project.
"""
from __future__ import annotations

import json
import sys
from datetime import date, datetime, timezone
from pathlib import Path


DEFAULT_CUTOFF = date(2024, 1, 1)


def apply_chrono_split(cases: list[dict], cutoff: date) -> dict:
    train: list[dict] = []
    test: list[dict] = []
    for case in cases:
        published_raw = case.get("published_date")
        if not published_raw:
            train.append(case)
            continue
        try:
            case_date = date.fromisoformat(published_raw)
        except ValueError:
            train.append(case)
            continue
        if case_date < cutoff:
            train.append(case)
        else:
            test.append(case)
    return {
        "split_type": "chronological",
        "cutoff": cutoff.isoformat(),
        "train_count": len(train),
        "test_count": len(test),
        "train_case_ids": [c["case_id"] for c in train],
        "test_case_ids": [c["case_id"] for c in test],
    }


def apply_cross_project_splits(cases: list[dict]) -> dict:
    projects = sorted({c.get("project", "unknown") for c in cases})
    splits = []
    for holdout in projects:
        train = [c for c in cases if c.get("project") != holdout]
        test = [c for c in cases if c.get("project") == holdout]
        splits.append({
            "holdout_project": holdout,
            "train_count": len(train),
            "test_count": len(test),
            "train_case_ids": [c["case_id"] for c in train],
            "test_case_ids": [c["case_id"] for c in test],
        })
    return {
        "split_type": "cross_project",
        "total_projects": len(projects),
        "splits": splits,
    }


def main() -> int:
    root = Path("benchmarks")
    dedup_path = root / "external" / "manifests" / "_deduplicated.manifest.json"
    if not dedup_path.exists():
        print(f"ERROR: {dedup_path} not found. Run Task 23 first.", file=sys.stderr)
        return 1

    data = json.loads(dedup_path.read_text())
    cases = data.get("cases", [])
    print(f"Loaded {len(cases)} deduplicated cases")

    # Chronological split
    chrono = apply_chrono_split(cases, DEFAULT_CUTOFF)
    chrono["generated_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    chrono_path = root / "external" / "manifests" / "_chrono_split.manifest.json"
    chrono_path.write_text(json.dumps(chrono, indent=2))
    print(f"Chrono split: train={chrono['train_count']}, test={chrono['test_count']}")
    print(f"Wrote {chrono_path}")

    # Cross-project splits
    cross = apply_cross_project_splits(cases)
    cross["generated_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    cross_path = root / "external" / "manifests" / "_cross_project_splits.manifest.json"
    cross_path.write_text(json.dumps(cross, indent=2))
    print(f"Cross-project: {cross['total_projects']} splits generated")
    print(f"Wrote {cross_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
EOF
```

- [ ] **Step 2: Write a smoke test**

```bash
cat > benchmarks/tests/test_apply_splits.py <<'EOF'
"""Tests for apply_splits.py."""
from datetime import date

from benchmarks.scripts.apply_splits import apply_chrono_split, apply_cross_project_splits


def test_chrono_split_by_date():
    cases = [
        {"case_id": "old", "project": "p1", "published_date": "2023-06-01"},
        {"case_id": "new", "project": "p2", "published_date": "2024-06-01"},
        {"case_id": "undated", "project": "p3", "published_date": None},
    ]
    result = apply_chrono_split(cases, cutoff=date(2024, 1, 1))
    assert "old" in result["train_case_ids"]
    assert "new" in result["test_case_ids"]
    assert "undated" in result["train_case_ids"]


def test_cross_project_split_yields_one_per_project():
    cases = [
        {"case_id": "a", "project": "p1"},
        {"case_id": "b", "project": "p1"},
        {"case_id": "c", "project": "p2"},
    ]
    result = apply_cross_project_splits(cases)
    assert result["total_projects"] == 2
    p1_split = next(s for s in result["splits"] if s["holdout_project"] == "p1")
    assert {"a", "b"} == set(p1_split["test_case_ids"])
    assert ["c"] == p1_split["train_case_ids"]
EOF
```

- [ ] **Step 3: Run tests and the script**

```bash
uv run pytest benchmarks/tests/test_apply_splits.py -v
uv run python -m benchmarks.scripts.apply_splits
```

Expected: 2 tests pass; script prints train/test counts and cross-project split count.

- [ ] **Step 4: Commit**

```bash
git add benchmarks/scripts/apply_splits.py benchmarks/tests/test_apply_splits.py benchmarks/external/manifests/_chrono_split.manifest.json benchmarks/external/manifests/_cross_project_splits.manifest.json
git commit -m "Phase 0.5 Task 24: generate chronological and cross-project splits"
```

---

## Task 25: End-to-end smoke test with synthetic mock agent output

**Files:**
- Create: `benchmarks/scripts/generate_mock_agent_output.py`
- Create: `benchmarks/tests/test_end_to_end.py`

**Rationale:** Phase 1 doesn't exist yet, so we can't run real agents against the ingested benchmarks. But we CAN verify the full pipeline works end-to-end by generating synthetic mock agent output — an agent that finds 60% of TPs, flags 20% of patched versions as FPs. Feed it into the runner, confirm metrics compute correctly, and verify the report looks right. Phase 1.7 will replace the mock with real MCP agent output.

- [ ] **Step 1: Write the mock output generator**

```bash
cat > benchmarks/scripts/generate_mock_agent_output.py <<'EOF'
"""Generate synthetic mock agent output for Phase 0.5 smoke testing.

Creates two SARIF files per ingested benchmark case:
  <case>/mock_agent_vuln.sarif     — findings produced running on vulnerable version
  <case>/mock_agent_patched.sarif  — findings produced running on patched version

The mock agent:
  - Finds 60% of FAIL ground-truth locations on the vulnerable version (TP)
  - Flags 20% of PASS ground-truth locations on the patched version (FP)
  - Uses CWE exactly matching the ground truth (100% strict match)

Phase 1 replaces this with real MCP agent invocations.
"""
from __future__ import annotations

import json
import random
import sys
from pathlib import Path

from benchmarks.runner.models import Finding, FindingKind
from benchmarks.runner.sarif import load_bentoo_sarif, write_bentoo_sarif


TPR_RATE = 0.6
FPR_RATE = 0.2


def mock_agent_for_case(truth_path: Path) -> tuple[list[Finding], list[Finding]]:
    """Return (vulnerable_version_findings, patched_version_findings)."""
    rng = random.Random(hash(str(truth_path)) & 0xFFFFFFFF)
    truth = load_bentoo_sarif(truth_path)
    fail_truths = [f for f in truth if f.kind == FindingKind.FAIL]
    pass_truths = [f for f in truth if f.kind == FindingKind.PASS]

    vuln_findings: list[Finding] = []
    for t in fail_truths:
        if rng.random() < TPR_RATE:
            vuln_findings.append(Finding(
                cwe_id=t.cwe_id, kind=FindingKind.FAIL, cve_id=t.cve_id,
                location=t.location, agent_name="mock-agent", confidence=0.9,
                message=f"mock detection of {t.cve_id}",
            ))

    patched_findings: list[Finding] = []
    for t in pass_truths:
        if rng.random() < FPR_RATE:
            patched_findings.append(Finding(
                cwe_id=t.cwe_id, kind=FindingKind.FAIL,  # mock reports as FAIL
                cve_id=t.cve_id, location=t.location,
                agent_name="mock-agent", confidence=0.7,
                message=f"mock false positive on patched {t.cve_id}",
            ))

    return vuln_findings, patched_findings


def main() -> int:
    root = Path("benchmarks/external")
    count = 0
    for truth_path in sorted(root.rglob("truth.sarif")):
        case_dir = truth_path.parent
        vuln, patched = mock_agent_for_case(truth_path)
        write_bentoo_sarif(case_dir / "mock_agent_vuln.sarif", vuln, tool_name="mock-agent-vuln")
        write_bentoo_sarif(case_dir / "mock_agent_patched.sarif", patched, tool_name="mock-agent-patched")
        count += 1
    print(f"Generated mock agent output for {count} cases")
    return 0


if __name__ == "__main__":
    sys.exit(main())
EOF
```

- [ ] **Step 2: Write the end-to-end test**

```bash
cat > benchmarks/tests/test_end_to_end.py <<'EOF'
"""End-to-end smoke test: ingested benchmark + mock agent → metrics + report."""
import json
from datetime import date
from pathlib import Path

import pytest

from benchmarks.runner.cwe import load_hierarchy
from benchmarks.runner.metrics import compute_metrics
from benchmarks.runner.models import (
    AgentRun,
    BenchmarkCase,
    CodeLocation,
    Finding,
    FindingKind,
    Language,
)
from benchmarks.runner.report import render_markdown


@pytest.fixture
def mini_case():
    return BenchmarkCase(
        case_id="e2e-1",
        project="e2e/proj",
        language=Language.JAVASCRIPT,
        vulnerable_version="1.0.0",
        patched_version="1.0.1",
        ground_truth=[
            Finding(cwe_id="CWE-79", kind=FindingKind.FAIL,
                    location=CodeLocation(file="src/view.js", start_line=42, end_line=55,
                                          function_name="render")),
            Finding(cwe_id="CWE-79", kind=FindingKind.PASS,
                    location=CodeLocation(file="src/view.js", start_line=42, end_line=58,
                                          function_name="render")),
        ],
        published_date=date(2024, 5, 1),
        source_dataset="e2e-test",
    )


def test_end_to_end_pipeline_produces_markdown(mini_case):
    hierarchy = load_hierarchy()
    # Mock agent: finds the vulnerability perfectly, doesn't flag the patched
    vuln_run = AgentRun(
        case_id=mini_case.case_id, agent_name="mock", runtime_seconds=0.1,
        findings=[
            Finding(cwe_id="CWE-79", kind=FindingKind.FAIL,
                    location=CodeLocation(file="src/view.js", start_line=42, end_line=55,
                                          function_name="render"),
                    agent_name="mock", confidence=0.95),
        ],
    )
    patched_run = AgentRun(
        case_id=mini_case.case_id, agent_name="mock", runtime_seconds=0.1, findings=[],
    )

    summary = compute_metrics(
        cases=[mini_case], runs_vulnerable=[vuln_run], runs_patched=[patched_run],
        hierarchy=hierarchy, agent_name="mock", dataset="e2e-test",
    )

    overall = next(m for m in summary.metrics if m.cwe_id is None and m.language is None)
    assert overall.true_positives == 1
    assert overall.false_positives == 0
    assert overall.tpr == 1.0
    assert overall.fpr == 0.0

    md = render_markdown(summary)
    assert "e2e-test" in md
    assert "mock" in md
    assert "100.0%" in md
EOF
```

- [ ] **Step 3: Run the end-to-end test**

```bash
uv run pytest benchmarks/tests/test_end_to_end.py -v
```

Expected: 1 test PASS.

- [ ] **Step 4: (Optional) run the full ingestion → mock agent → metrics chain**

```bash
uv run python -m benchmarks.scripts.generate_mock_agent_output
```

Expected: `Generated mock agent output for N cases` where N is the total ingested case count from Tasks 13-22.

At this point Phase 0.5 has:
- All ingested benchmarks materialized
- Mock agent output files per case
- A working runner CLI that can validate SARIF files and produce reports
- Dedup + chrono + cross-project splits computed

Phase 1.7 will add the MCP agent invocation layer and replace the mock SARIF files with real agent output.

- [ ] **Step 5: Run the full benchmark runner test suite**

```bash
uv run pytest benchmarks/tests/ -v
```

Expected: all tests from Tasks 1-25 PASS (~45+ tests).

- [ ] **Step 6: Commit**

```bash
git add benchmarks/scripts/generate_mock_agent_output.py benchmarks/tests/test_end_to_end.py
git commit -m "Phase 0.5 Task 25: end-to-end smoke test with mock agent output"
```

---

## Task 26: Demote self-authored Rust fixtures to smoke tests with provenance

**Files:**
- Modify: `benchmarks/fixtures/README.md` (create if absent)
- Modify: each Rust fixture file in `benchmarks/fixtures/{xss,sqli,cmdi,ssti}/*/rust_*.rs` — add a provenance header

**Rationale:** Per ADR-014, Rust fixtures stay as smoke tests (not validation). Each Rust fixture file needs a clear header explaining it does not claim detection accuracy, and where an analog real CVE exists (from `docs/research/benchmark-tier4-rust-modern.md`), the header references it.

- [ ] **Step 1: Create `benchmarks/fixtures/README.md`**

```bash
cat > benchmarks/fixtures/README.md <<'EOF'
# Self-Authored Benchmark Fixtures

These fixtures are **smoke tests only**, not validation datasets.

## Purpose
- Verify the MCP agent plumbing works end-to-end (tree-sitter loads a Rust file,
  an agent YAML resolves to an MCP tool, a finding flows back out)
- Provide realistic code samples for few-shot examples during agent authoring
- Serve as regression fixtures — if an agent stops finding these patterns,
  we've broken something fundamental

## Non-Purpose
- **These files do NOT measure detection accuracy.** Phase 1 validation runs
  against real-world CVE benchmarks from `benchmarks/external/` (see
  `benchmarks/external/manifests/*.manifest.json`).
- **Rust fixtures carry special notes** — per ADR-014, Rust benchmark corpus
  construction is deferred to Phase 5 because there are insufficient verified
  real Rust CVEs for our Phase 1 injection CWEs. The Rust fixtures here model
  real Rust web framework patterns but the detection quality is not benchmarked.

## Layout
- `sqli/vulnerable/` + `sqli/safe/` — SQL injection smoke cases
- `cmdi/vulnerable/` + `cmdi/safe/` — OS command injection smoke cases
- `ssti/vulnerable/` + `ssti/safe/` — server-side template injection smoke cases
- `xss/vulnerable/` + `xss/safe/` — cross-site scripting smoke cases

## Language coverage (smoke)
Python, Java, JavaScript, TypeScript, Go, Ruby, PHP, C#, **Rust** (smoke only).

## References
- ADR-013: CWE-1400-native benchmark evaluator (why our own runner)
- ADR-014: Rust benchmark corpus deferred to Phase 5 (why Rust fixtures are smoke-only)
- `docs/research/benchmark-tier4-rust-modern.md`: Phase 5 Rust corpus seed
EOF
```

- [ ] **Step 2: Add provenance headers to each Rust fixture**

For each `benchmarks/fixtures/{xss,sqli,cmdi,ssti}/{vulnerable,safe}/rust_*.rs` file, prepend this header after any existing first-line comment marker:

```rust
// --- screw-agents smoke-test fixture (not for detection benchmarking) ---
// Per ADR-014 (docs/DECISIONS.md), Rust benchmark corpus is DEFERRED to Phase 5.
// This file verifies MCP plumbing + tree-sitter loading + agent-YAML resolution.
// Detection accuracy against this file is NOT part of any Phase 1 validation gate.
// Phase 5 corpus seed: docs/research/benchmark-tier4-rust-modern.md
// -----------------------------------------------------------------------
```

Do this with a Bash loop:

```bash
HEADER='// --- screw-agents smoke-test fixture (not for detection benchmarking) ---
// Per ADR-014 (docs/DECISIONS.md), Rust benchmark corpus is DEFERRED to Phase 5.
// This file verifies MCP plumbing + tree-sitter loading + agent-YAML resolution.
// Detection accuracy against this file is NOT part of any Phase 1 validation gate.
// Phase 5 corpus seed: docs/research/benchmark-tier4-rust-modern.md
// -----------------------------------------------------------------------
'

for f in benchmarks/fixtures/*/vulnerable/rust_*.rs benchmarks/fixtures/*/safe/rust_*.rs; do
    if ! grep -q "screw-agents smoke-test fixture" "$f"; then
        # Prepend the header
        printf '%s\n%s' "$HEADER" "$(cat "$f")" > "$f.tmp"
        mv "$f.tmp" "$f"
        echo "updated: $f"
    else
        echo "already headed: $f"
    fi
done
```

- [ ] **Step 3: Spot-check three Rust fixtures**

```bash
head -8 benchmarks/fixtures/xss/vulnerable/rust_axum_html_format.rs
head -8 benchmarks/fixtures/sqli/vulnerable/rust_sqlx_format.rs
head -8 benchmarks/fixtures/ssti/safe/rust_askama_compile_time.rs
```

Expected: all three start with the "screw-agents smoke-test fixture" header.

- [ ] **Step 4: Commit**

```bash
git add benchmarks/fixtures/README.md benchmarks/fixtures/**/*.rs
git commit -m "Phase 0.5 Task 26: demote Rust fixtures to smoke-test status with provenance headers"
```

---

## Task 27: Document Phase 0.5 validation gates

**Files:**
- Create: `docs/PHASE_0_5_VALIDATION_GATES.md`

**Rationale:** Once Phase 0.5 implementation is complete, we need a single canonical document that Phase 1.7 will reference to determine whether Phase 1 can close. This is the acceptance criteria extracted from `docs/PROJECT_STATUS.md` Step 0.5.7, expanded with the specific command invocations and thresholds.

- [ ] **Step 1: Write the gates document**

```bash
cat > docs/PHASE_0_5_VALIDATION_GATES.md <<'EOF'
# Phase 0.5 → Phase 1 Validation Gates

> Authoritative acceptance criteria for Phase 1.7 (benchmark validation run).
> Phase 1 cannot close until all gates below are satisfied OR explicitly waived
> in a PR comment with ADR reference.

## Gate 1: Runner infrastructure passes its own tests

```bash
uv run pytest benchmarks/tests/ -v
```
**Required:** all tests green; no skipped tests; no deprecation warnings.

## Gate 2: All 8 ingested benchmarks report non-zero case counts

```bash
uv run python -m benchmarks.runner list
for manifest in benchmarks/external/manifests/*.manifest.json; do
    python -c "import json; d=json.load(open('$manifest')); print(f\"{d.get('dataset_name','?'):30} {d.get('case_count','?')} cases\")"
done
```
**Required:** ossf-cve-benchmark, reality-check-csharp, reality-check-python, reality-check-java, go-sec-code-mutated, skf-labs-mutated, crossvul, vul4j, morefixes-extract — ALL report `case_count > 0`.

## Gate 3: Deduplication applied

```bash
test -f benchmarks/external/manifests/_deduplicated.manifest.json
python -c "import json; d=json.load(open('benchmarks/external/manifests/_deduplicated.manifest.json')); print(f\"pre={d['pre_dedup_count']} post={d['post_dedup_count']}\")"
```
**Required:** `_deduplicated.manifest.json` exists; `post_dedup_count > 0`.

## Gate 4: Chronological and cross-project splits generated

```bash
test -f benchmarks/external/manifests/_chrono_split.manifest.json
test -f benchmarks/external/manifests/_cross_project_splits.manifest.json
```
**Required:** both split manifests present.

## Gate 5: Phase 1 agent detection rates (executed in Phase 1.7)

Once Phase 1 MCP agents exist, run:

```bash
uv run python -m benchmarks.runner run --agent xss --dataset ossf-cve-benchmark --dedup --chrono-cutoff 2024-01-01
```

**Required thresholds (ADR-013 derived):**

| Agent | Dataset | Gate | Metric | Threshold |
|---|---|---|---|---|
| xss | ossf-cve-benchmark (XSS subset) | G5.1 | TPR | ≥ 70% |
| xss | ossf-cve-benchmark (patched) | G5.2 | FPR | ≤ 25% |
| xss | reality-check-csharp | G5.3 | TPR on CWE-79 | ≥ 60% |
| xss | reality-check-python | G5.4 | TPR on CWE-79 | ≥ 60% |
| cmdi | ossf-cve-benchmark (CmdI subset) | G5.5 | TPR | ≥ 60% |
| cmdi | reality-check-java | G5.6 | TPR on CWE-78 | ≥ 50% |
| sqli | reality-check-csharp | G5.7 | TPR on CWE-89 | ≥ 50% |
| sqli | morefixes-extract | G5.8 | TPR on CWE-89 | ≥ 50% |
| ssti | go-sec-code-mutated | G5.9 | TPR on CWE-1336 | ≥ 70% |
| ssti | skf-labs-mutated | G5.10 | TPR on CWE-1336 | ≥ 70% |

**Rationale for sub-80% thresholds:** The SMU paper (Li et al. ESEC/FSE 2023)
showed that the best Java SAST tool (Horusec) hit only 12.7% TPR on real-world
Java CVEs. A 70% TPR on real-world XSS CVEs would be a significant result
relative to that baseline, and an 80% TPR would be unrealistic given
current-state SAST performance. We calibrate our gates to be rigorous but
achievable.

## Gate 6: No Rust claims in the Phase 1.7 report

Per ADR-014, the Phase 1.7 report MUST explicitly state:
> Rust detection quality not benchmarked — see ADR-014. Rust corpus construction
> is deferred to Phase 5 (step 5.0).

The report generator (`benchmarks/runner/report.py`) must emit this line when
the run summary does not include any Rust-language cases.

## Gate 7: Failure dump for each gate below threshold

For any gate in G5.* that falls below threshold, the report must list the
first 10 missed CVEs or false-flag cases so Phase 1 engineers can diagnose.
EOF
```

- [ ] **Step 2: Commit**

```bash
git add docs/PHASE_0_5_VALIDATION_GATES.md
git commit -m "Phase 0.5 Task 27: document Phase 1.7 validation gates"
```

---

## Task 28: Phase 0.5 retrospective — PROJECT_STATUS.md refresh + sprint tag

**Files:**
- Modify: `docs/PROJECT_STATUS.md`

**Rationale:** Once Tasks 1-27 are complete, update `PROJECT_STATUS.md` to reflect the done state, mark Phase 0.5 as complete, and unblock Phase 1.

- [ ] **Step 1: Edit `docs/PROJECT_STATUS.md`**

Open `docs/PROJECT_STATUS.md` and make these changes:

1. Update the `> Last updated:` line to the current date (format: `YYYY-MM-DD`).
2. Change the top header from `## Current Phase: Phase 0 Complete — Phase 0.5 Active` to `## Current Phase: Phase 0.5 Complete — Phase 1 Next`.
3. In the "What's Done" section, add under the Phase 0 table:

```markdown
**Phase 0.5 — Benchmark Infrastructure Sprint (complete):**

| Task | Deliverable |
|---|---|
| 1-11 | `benchmarks/runner/` — CWE-1400-native Python evaluator (~1,200 LOC) |
| 12-20 | 8 ingest scripts via reusable `IngestBase` harness |
| 21-22 | MoreFixes Postgres deployment (docker-compose) + extraction pipeline |
| 23-24 | PrimeVul dedup + chronological + cross-project splits |
| 25 | End-to-end smoke test with mock agent output |
| 26 | Rust fixtures demoted to smoke tests with provenance headers (ADR-014) |
| 27 | Phase 1.7 validation gates documented (`docs/PHASE_0_5_VALIDATION_GATES.md`) |

All decisions tracked: ADR-013 (CWE-1400-native evaluator), ADR-014 (Rust deferred to Phase 5).
Deferred Obligation D-01 (Rust corpus) still active — see "Deferred Obligations" table above.
```

4. Change the "What's NOT Done" bullet `- Phase 0.5 implementation (not just research) — active` to `- Phase 1 (Core Infrastructure) — next up, blocked on no external prerequisites`.
5. In the Full Phase Plan table, change Phase 0.5 status from `**ACTIVE**` to `**Complete**` and change Phase 1 status from `Pending (blocked on Phase 0.5)` to `**NEXT**`.

- [ ] **Step 2: Verify the updates**

```bash
grep -A 2 "Current Phase" docs/PROJECT_STATUS.md | head -5
grep "Phase 0.5" docs/PROJECT_STATUS.md | head -5
```

Expected: "Phase 0.5 Complete — Phase 1 Next"; Phase 0.5 marked as Complete in the plan table.

- [ ] **Step 3: Run the full test suite one final time**

```bash
uv run pytest benchmarks/tests/ -v
```

Expected: all tests PASS. This is the Phase 0.5 sprint acceptance — if anything is broken, fix it before commit.

- [ ] **Step 4: Commit and tag**

```bash
git add docs/PROJECT_STATUS.md
git commit -m "Phase 0.5 Task 28: sprint retrospective — Phase 0.5 complete, Phase 1 next"
git tag phase-0.5-complete
```

- [ ] **Step 5: Push**

```bash
git push origin main
git push origin phase-0.5-complete
```

---

## Self-Review Checklist

After completing Tasks 1-28, verify against the spec:

### Spec coverage

- [ ] **Decision 1** (full sprint scope, no cuts) — Tasks 1-28 cover everything from `docs/PROJECT_STATUS.md` Phase 0.5 steps 0.5.1-0.5.7
- [ ] **Decision 2** (PrimeVul methodology mandatory) — Tasks 8 (dedup), 9 (splits), 23 (apply dedup), 24 (apply splits), ADR-013 reference
- [ ] **Decision 3** (CWE-1400-native Python evaluator) — Tasks 3, 4, 5, 6, 7, 10, 11 implement the full evaluator in Python with CWE-1400 semantics; bentoo kept as optional cross-check via `summary.json` schema compatibility
- [ ] **Decision 4** (Rust corpus deferred) — Task 26 demotes fixtures; Task 27 gate 6 enforces the "Rust not benchmarked" statement; ADR-014 tracks deferral; PROJECT_STATUS D-01 visible
- [ ] **Decision 5** (MCP library low-level) — not touched in Phase 0.5; belongs to Phase 1

### Dataset coverage

- [ ] **ossf-cve-benchmark** — Task 13
- [ ] **reality-check C#** — Task 14
- [ ] **reality-check Python** — Task 15
- [ ] **reality-check Java** — Task 16
- [ ] **go-sec-code-mutated** — Task 17
- [ ] **skf-labs-mutated** — Task 18
- [ ] **CrossVul** — Task 19
- [ ] **Vul4J** — Task 20
- [ ] **MoreFixes** — Tasks 21, 22

### Methodology coverage

- [ ] Deduplication — Tasks 8, 23
- [ ] Chronological splits — Tasks 9, 24
- [ ] Cross-project splits — Tasks 9, 24
- [ ] Pair-based evaluation — Task 7 (`_score_case` uses both vuln + patched runs)

### Validation gate coverage

- [ ] TPR threshold on OSSF XSS subset — Gate G5.1 (≥70%)
- [ ] FPR threshold on OSSF patched — Gate G5.2 (≤25%)
- [ ] Per-(agent, dataset) TPR tables — Gates G5.3-G5.10
- [ ] No Rust gate — enforced by Gate G6
- [ ] Failure dump — Gate G7

### Placeholder scan

- [ ] No "TBD", "TODO", "fill in" strings in any Task step
- [ ] Every Python snippet is complete and runnable (no `...` stubs inside implementation bodies)
- [ ] Every shell command has expected output described
- [ ] Every file creation uses a heredoc or explicit content
- [ ] No "Similar to Task N" references — each task is self-contained

### Type consistency

Cross-checked types:
- `Finding` used in `models.py`, `sarif.py`, `metrics.py`, `primevul.py`, `cli.py`, `report.py`, all ingest scripts — same signature everywhere
- `BenchmarkCase` used identically across all tasks
- `MetricSet` field names (`true_positives`, `false_positives`, `true_negatives`, `false_negatives`, `tpr`, `fpr`, `precision`, `f1`, `accuracy`) consistent between models.py and metrics.py
- `Summary` schema used in both `metrics.py` (constructor) and `report.py` (reader)
- `Language` enum values match between `models.py`, `primevul.py` (TS_LANG_NAMES map), `ingest_ossf.py`, and all other ingest scripts
- `FindingKind.FAIL` / `FindingKind.PASS` used consistently — no string literals
- `load_hierarchy()` signature is `(path: Path | None = None) -> Cwe1400Hierarchy` — called without args by metrics tests and end-to-end test

### Execution handoff

**Plan complete and saved to `docs/PHASE_0_5_PLAN.md`. Two execution options:**

**1. Subagent-Driven (recommended)** — I dispatch a fresh subagent per task, review between tasks, fast iteration. Uses `superpowers:subagent-driven-development` sub-skill.

**2. Inline Execution** — Execute tasks in this session using `superpowers:executing-plans`. Batch execution with checkpoints for review.

**Which approach?**



