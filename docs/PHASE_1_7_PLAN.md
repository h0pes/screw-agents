# Phase 1.7 — G5-G7 Detection Rate Validation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Validate that the 4 Phase 0 agents (sqli, cmdi, ssti, xss) detect real-world vulnerabilities at G5 threshold rates, with G6 Rust disclaimer and G7 failure dumps, before Phase 2 begins.

**Architecture:** Python orchestration script uses `ScanEngine.assemble_scan()` to build detection prompts from agent YAML knowledge + benchmark code, sends them to Claude via `claude -p --output-format json`, parses structured findings, scores via existing `metrics.compute_metrics()`, and checks G5 thresholds. Two-phase execution: sample run (20 cases, ~40 Claude calls) validates the pipeline, then full run covers all datasets.

**Tech Stack:** Python 3.11+, existing screw-agents engine + benchmark runner, `claude` CLI (Pro subscription), `subprocess` for claude invocation, `tempfile` for code staging.

**Spec:** `docs/specs/2026-04-11-g5-g7-detection-validation-design.md`

---

## File Map

| File | Action | Responsibility |
|------|--------|---------------|
| `benchmarks/runner/invoker.py` | Create | `claude -p` subprocess wrapper: retry, throttle, JSON parsing |
| `benchmarks/runner/evaluator.py` | Create | Orchestration: load cases → extract code → assemble prompts → invoke Claude → collect findings → score |
| `benchmarks/runner/code_extractor.py` | Create | Per-dataset code extraction: read vulnerable/patched source from cloned repos |
| `benchmarks/runner/gate_checker.py` | Create | G5 threshold checks, G6 Rust disclaimer, G7 failure dump generation |
| `benchmarks/runner/report.py` | Modify | Add `render_gate_report()` that includes G6/G7 sections |
| `benchmarks/scripts/run_gates.py` | Create | CLI entry point: `uv run python benchmarks/scripts/run_gates.py --mode sample` |
| `benchmarks/tests/test_invoker.py` | Create | Tests for invoker (mocked subprocess) |
| `benchmarks/tests/test_code_extractor.py` | Create | Tests for code extraction per dataset type |
| `benchmarks/tests/test_evaluator.py` | Create | Tests for evaluator orchestration (mocked invoker) |
| `benchmarks/tests/test_gate_checker.py` | Create | Tests for G5 threshold checks, G6, G7 |
| `benchmarks/tests/test_report_gates.py` | Create | Tests for gate report rendering |

---

## Task 1: Claude Invoker (`benchmarks/runner/invoker.py`)

**Files:**
- Create: `benchmarks/runner/invoker.py`
- Test: `benchmarks/tests/test_invoker.py`

- [ ] **Step 1: Write failing test for successful invocation**

```python
# benchmarks/tests/test_invoker.py
"""Tests for the claude -p invoker."""
from __future__ import annotations

import json
from unittest.mock import patch, MagicMock

import pytest

from benchmarks.runner.invoker import invoke_claude, InvokerConfig, InvokeResult


def _mock_completed_process(stdout: str, returncode: int = 0):
    proc = MagicMock()
    proc.stdout = stdout
    proc.returncode = returncode
    return proc


class TestInvokeClaude:
    def test_successful_invocation_returns_parsed_findings(self):
        findings_json = json.dumps({
            "result": "",
            "structured_output": [
                {"cwe_id": "CWE-79", "file": "view.js", "start_line": 10,
                 "end_line": 15, "confidence": 0.9, "message": "XSS via innerHTML"}
            ]
        })
        with patch("subprocess.run", return_value=_mock_completed_process(findings_json)):
            result = invoke_claude("Scan this code", InvokerConfig())
        assert result.success is True
        assert len(result.findings) == 1
        assert result.findings[0]["cwe_id"] == "CWE-79"

    def test_empty_findings_returns_empty_list(self):
        stdout = json.dumps({"result": "", "structured_output": []})
        with patch("subprocess.run", return_value=_mock_completed_process(stdout)):
            result = invoke_claude("Scan this code", InvokerConfig())
        assert result.success is True
        assert result.findings == []

    def test_non_json_stdout_returns_failure(self):
        with patch("subprocess.run", return_value=_mock_completed_process("not json")):
            result = invoke_claude("Scan this code", InvokerConfig())
        assert result.success is False
        assert result.findings == []
        assert "JSON" in result.error

    def test_nonzero_returncode_returns_failure(self):
        with patch("subprocess.run", return_value=_mock_completed_process("", returncode=1)):
            result = invoke_claude("Scan this code", InvokerConfig())
        assert result.success is False

    def test_retry_on_failure(self):
        fail = _mock_completed_process("", returncode=1)
        ok = _mock_completed_process(json.dumps({"result": "", "structured_output": []}))
        with patch("subprocess.run", side_effect=[fail, ok]):
            result = invoke_claude("Scan this code", InvokerConfig(max_retries=2, retry_delay=0.0))
        assert result.success is True
```

- [ ] **Step 2: Run test to verify it fails**

```bash
uv run pytest benchmarks/tests/test_invoker.py -v
```

Expected: FAIL — `ModuleNotFoundError: No module named 'benchmarks.runner.invoker'`

- [ ] **Step 3: Implement invoker**

```python
# benchmarks/runner/invoker.py
"""Wrapper around `claude -p` for batch benchmark evaluation.

Handles JSON output parsing, retry with backoff, and throttling.
"""
from __future__ import annotations

import json
import logging
import subprocess
import time
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class InvokerConfig:
    """Configuration for the Claude invoker."""
    max_retries: int = 3
    retry_delay: float = 2.0       # seconds, doubles each retry
    throttle_delay: float = 2.0    # seconds between calls
    timeout: int = 120             # seconds per call
    max_turns: int = 1


@dataclass
class InvokeResult:
    """Result from a single Claude invocation."""
    success: bool
    findings: list[dict] = field(default_factory=list)
    raw_output: str = ""
    error: str = ""
    duration_seconds: float = 0.0


def invoke_claude(prompt: str, config: InvokerConfig) -> InvokeResult:
    """Send a prompt to Claude via `claude -p` and parse structured findings.

    Args:
        prompt: The full prompt including detection knowledge and code.
        config: Invoker configuration.

    Returns:
        InvokeResult with parsed findings or error details.
    """
    last_error = ""
    for attempt in range(config.max_retries):
        if attempt > 0:
            delay = config.retry_delay * (2 ** (attempt - 1))
            logger.info("Retry %d/%d after %.1fs", attempt + 1, config.max_retries, delay)
            time.sleep(delay)

        start = time.monotonic()
        try:
            proc = subprocess.run(
                [
                    "claude", "-p", prompt,
                    "--output-format", "json",
                    "--max-turns", str(config.max_turns),
                ],
                capture_output=True,
                text=True,
                timeout=config.timeout,
            )
        except subprocess.TimeoutExpired:
            last_error = f"Timeout after {config.timeout}s"
            logger.warning("Attempt %d: %s", attempt + 1, last_error)
            continue

        elapsed = time.monotonic() - start

        if proc.returncode != 0:
            last_error = f"Exit code {proc.returncode}: {proc.stderr[:200]}"
            logger.warning("Attempt %d: %s", attempt + 1, last_error)
            continue

        return _parse_output(proc.stdout, elapsed)

    return InvokeResult(success=False, error=last_error)


def _parse_output(stdout: str, elapsed: float) -> InvokeResult:
    """Parse claude --output-format json stdout into findings."""
    try:
        data = json.loads(stdout)
    except (json.JSONDecodeError, ValueError) as exc:
        return InvokeResult(
            success=False, raw_output=stdout[:500],
            error=f"JSON parse error: {exc}", duration_seconds=elapsed,
        )

    # claude --output-format json returns {"result": "...", "structured_output": ...}
    # structured_output may be the findings list directly, or nested
    findings_raw = data.get("structured_output") or data.get("result", "")

    # If structured_output is a string, try to parse it as JSON
    if isinstance(findings_raw, str):
        try:
            findings_raw = json.loads(findings_raw)
        except (json.JSONDecodeError, ValueError):
            # Try to extract JSON array from the text
            findings_raw = _extract_json_array(findings_raw)

    if isinstance(findings_raw, list):
        return InvokeResult(
            success=True, findings=findings_raw,
            raw_output=stdout[:500], duration_seconds=elapsed,
        )

    # If we got a dict with a "findings" key, unwrap it
    if isinstance(findings_raw, dict) and "findings" in findings_raw:
        return InvokeResult(
            success=True, findings=findings_raw["findings"],
            raw_output=stdout[:500], duration_seconds=elapsed,
        )

    return InvokeResult(
        success=False, raw_output=stdout[:500],
        error="Could not extract findings array from response",
        duration_seconds=elapsed,
    )


def _extract_json_array(text: str) -> list | str:
    """Try to find a JSON array in free-form text."""
    start = text.find("[")
    if start == -1:
        return text
    # Find matching closing bracket
    depth = 0
    for i in range(start, len(text)):
        if text[i] == "[":
            depth += 1
        elif text[i] == "]":
            depth -= 1
            if depth == 0:
                try:
                    return json.loads(text[start:i + 1])
                except json.JSONDecodeError:
                    return text
    return text
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
uv run pytest benchmarks/tests/test_invoker.py -v
```

Expected: all 5 tests PASS

- [ ] **Step 5: Commit**

```bash
git add benchmarks/runner/invoker.py benchmarks/tests/test_invoker.py
git commit -m "feat(benchmarks): add claude -p invoker with retry and JSON parsing"
```

---

## Task 2: Code Extractor (`benchmarks/runner/code_extractor.py`)

**Files:**
- Create: `benchmarks/runner/code_extractor.py`
- Test: `benchmarks/tests/test_code_extractor.py`

The code extractor reads actual source code from benchmark dataset directories. Each dataset stores code differently:

- **reality-check**: `{lang}/projects/{project}/{version}/` contains source trees; ground truth `file` field is relative to that dir
- **CrossVul**: `CWE-XX/{ext}/bad_{id}` (vulnerable) and `good_{id}` (patched) are standalone files; code was stored in Finding.message during ingest
- **go-sec-code-mutated / skf-labs-mutated**: monolithic repos; ground truth `file` field is relative to repo root; no separate patched version exists

- [ ] **Step 1: Write failing tests**

```python
# benchmarks/tests/test_code_extractor.py
"""Tests for benchmark code extraction."""
from __future__ import annotations

from pathlib import Path

import pytest

from benchmarks.runner.code_extractor import (
    extract_code_for_case,
    CodeVariant,
)
from benchmarks.runner.models import (
    BenchmarkCase,
    CodeLocation,
    Finding,
    FindingKind,
    Language,
)


@pytest.fixture
def tmp_reality_check(tmp_path):
    """Create a minimal reality-check directory structure."""
    repo = tmp_path / "reality-check-csharp" / "repo"
    # Vulnerable version source
    vuln_dir = repo / "csharp" / "projects" / "myproj" / "myproj-1.0.0"
    vuln_dir.mkdir(parents=True)
    (vuln_dir / "Controller.cs").write_text("public void Render() { Response.Write(input); }")
    # Patched version source
    patch_dir = repo / "csharp" / "projects" / "myproj" / "myproj-1.0.1"
    patch_dir.mkdir(parents=True)
    (patch_dir / "Controller.cs").write_text("public void Render() { Response.Write(Encode(input)); }")
    return tmp_path


@pytest.fixture
def rc_case():
    return BenchmarkCase(
        case_id="rc-csharp-myproj-CVE-2024-001",
        project="myproj",
        language=Language.CSHARP,
        vulnerable_version="myproj-1.0.0",
        patched_version="myproj-1.0.1",
        ground_truth=[
            Finding(cwe_id="CWE-79", kind=FindingKind.FAIL,
                    location=CodeLocation(file="Controller.cs", start_line=1, end_line=1)),
            Finding(cwe_id="CWE-79", kind=FindingKind.PASS,
                    location=CodeLocation(file="Controller.cs", start_line=1, end_line=1)),
        ],
        source_dataset="reality-check-csharp",
    )


@pytest.fixture
def tmp_crossvul(tmp_path):
    """Create a minimal CrossVul directory structure."""
    cwe_dir = tmp_path / "crossvul" / "CWE-79" / "php"
    cwe_dir.mkdir(parents=True)
    (cwe_dir / "bad_001.php").write_text("<?php echo $_GET['x']; ?>")
    (cwe_dir / "good_001.php").write_text("<?php echo htmlspecialchars($_GET['x']); ?>")
    return tmp_path


@pytest.fixture
def crossvul_case():
    return BenchmarkCase(
        case_id="crossvul-79-php-001.php",
        project="crossvul-php",
        language=Language.PHP,
        vulnerable_version="bad",
        patched_version="good",
        ground_truth=[
            Finding(cwe_id="CWE-79", kind=FindingKind.FAIL,
                    location=CodeLocation(file="bad_001.php", start_line=1, end_line=1),
                    message="<?php echo $_GET['x']; ?>"),
            Finding(cwe_id="CWE-79", kind=FindingKind.PASS,
                    location=CodeLocation(file="good_001.php", start_line=1, end_line=1),
                    message="<?php echo htmlspecialchars($_GET['x']); ?>"),
        ],
        source_dataset="crossvul",
    )


@pytest.fixture
def tmp_gosec(tmp_path):
    """Create a minimal go-sec-code-mutated directory structure."""
    repo = tmp_path / "go-sec-code-mutated" / "repo"
    vuln_file = repo / "cmd" / "sqli" / "main.go"
    vuln_file.parent.mkdir(parents=True)
    vuln_file.write_text('db.Query("SELECT * FROM users WHERE id=" + id)')
    return tmp_path


@pytest.fixture
def gosec_case():
    return BenchmarkCase(
        case_id="gosec-cmd-sqli",
        project="go-sec-code",
        language=Language.GO,
        vulnerable_version="HEAD",
        patched_version="HEAD-patched",
        ground_truth=[
            Finding(cwe_id="CWE-89", kind=FindingKind.FAIL,
                    location=CodeLocation(file="cmd/sqli/main.go", start_line=1, end_line=1)),
            Finding(cwe_id="CWE-89", kind=FindingKind.PASS,
                    location=CodeLocation(file="cmd/sqli/main.go", start_line=1, end_line=1)),
        ],
        source_dataset="go-sec-code-mutated",
    )


class TestExtractCodeForCase:
    def test_reality_check_extracts_vuln_and_patched(self, tmp_reality_check, rc_case):
        vuln = extract_code_for_case(rc_case, CodeVariant.VULNERABLE, tmp_reality_check)
        patched = extract_code_for_case(rc_case, CodeVariant.PATCHED, tmp_reality_check)
        assert len(vuln) == 1
        assert "Response.Write(input)" in vuln[0].content
        assert len(patched) == 1
        assert "Encode(input)" in patched[0].content

    def test_crossvul_extracts_bad_good_pairs(self, tmp_crossvul, crossvul_case):
        vuln = extract_code_for_case(crossvul_case, CodeVariant.VULNERABLE, tmp_crossvul)
        patched = extract_code_for_case(crossvul_case, CodeVariant.PATCHED, tmp_crossvul)
        assert len(vuln) == 1
        assert "$_GET" in vuln[0].content
        assert "echo" in vuln[0].content
        assert len(patched) == 1
        assert "htmlspecialchars" in patched[0].content

    def test_gosec_extracts_vuln_no_patched(self, tmp_gosec, gosec_case):
        vuln = extract_code_for_case(gosec_case, CodeVariant.VULNERABLE, tmp_gosec)
        patched = extract_code_for_case(gosec_case, CodeVariant.PATCHED, tmp_gosec)
        assert len(vuln) == 1
        assert "SELECT" in vuln[0].content
        assert len(patched) == 0  # no patched version for monolithic repos

    def test_missing_dataset_dir_raises(self, tmp_path, rc_case):
        with pytest.raises(FileNotFoundError):
            extract_code_for_case(rc_case, CodeVariant.VULNERABLE, tmp_path)
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
uv run pytest benchmarks/tests/test_code_extractor.py -v
```

Expected: FAIL — `ModuleNotFoundError: No module named 'benchmarks.runner.code_extractor'`

- [ ] **Step 3: Implement code extractor**

```python
# benchmarks/runner/code_extractor.py
"""Extract source code from benchmark datasets for evaluation.

Each dataset stores code differently. This module abstracts those differences
behind a single `extract_code_for_case()` interface.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from benchmarks.runner.models import BenchmarkCase, FindingKind

logger = logging.getLogger(__name__)


class CodeVariant(str, Enum):
    VULNERABLE = "vulnerable"
    PATCHED = "patched"


@dataclass
class ExtractedCode:
    """A piece of source code extracted from a benchmark dataset."""
    file_path: str       # relative path within the project
    content: str         # the actual source code
    language: str        # language identifier


# Map dataset names to their language subdirectory names in reality-check
_RC_LANG_DIRS = {
    "reality-check-csharp": "csharp",
    "reality-check-python": "python",
    "reality-check-java": "java",
}


def extract_code_for_case(
    case: BenchmarkCase,
    variant: CodeVariant,
    benchmarks_external_dir: Path,
) -> list[ExtractedCode]:
    """Extract source code for a benchmark case.

    Args:
        case: The benchmark case.
        variant: Whether to extract vulnerable or patched code.
        benchmarks_external_dir: Path to `benchmarks/external/`.

    Returns:
        List of ExtractedCode objects. Empty list if no code available
        (e.g., no patched version for monolithic repos).

    Raises:
        FileNotFoundError: If the dataset directory doesn't exist.
    """
    ds = case.source_dataset

    if ds in _RC_LANG_DIRS:
        return _extract_reality_check(case, variant, benchmarks_external_dir)
    elif ds == "crossvul":
        return _extract_crossvul(case, variant, benchmarks_external_dir)
    elif ds in ("go-sec-code-mutated", "skf-labs-mutated"):
        return _extract_monolithic(case, variant, benchmarks_external_dir)
    elif ds == "ossf-cve-benchmark":
        return _extract_ossf(case, variant, benchmarks_external_dir)
    else:
        logger.warning("Unsupported dataset for code extraction: %s", ds)
        return []


def _extract_reality_check(
    case: BenchmarkCase, variant: CodeVariant, ext_dir: Path,
) -> list[ExtractedCode]:
    lang_subdir = _RC_LANG_DIRS[case.source_dataset]
    repo_dir = ext_dir / case.source_dataset / "repo"
    if not repo_dir.exists():
        raise FileNotFoundError(f"reality-check repo not found: {repo_dir}")

    version = case.vulnerable_version if variant == CodeVariant.VULNERABLE else case.patched_version
    projects_dir = repo_dir / lang_subdir / "projects" / case.project / version

    if not projects_dir.exists():
        logger.warning("Version dir not found: %s", projects_dir)
        return []

    # Get unique files from ground truth for this variant
    kind = FindingKind.FAIL if variant == CodeVariant.VULNERABLE else FindingKind.PASS
    truth_files = {
        f.location.file
        for f in case.ground_truth
        if f.kind == kind
    }

    results = []
    for rel_file in truth_files:
        file_path = projects_dir / rel_file
        if not file_path.exists():
            # Try searching recursively for the file
            matches = list(projects_dir.rglob(Path(rel_file).name))
            if matches:
                file_path = matches[0]
            else:
                logger.warning("File not found: %s", file_path)
                continue
        results.append(ExtractedCode(
            file_path=rel_file,
            content=file_path.read_text(errors="replace"),
            language=case.language.value,
        ))
    return results


def _extract_crossvul(
    case: BenchmarkCase, variant: CodeVariant, ext_dir: Path,
) -> list[ExtractedCode]:
    dataset_dir = ext_dir / "crossvul"
    if not dataset_dir.exists():
        raise FileNotFoundError(f"CrossVul dir not found: {dataset_dir}")

    # CrossVul stores code in Finding.message during ingest
    kind = FindingKind.FAIL if variant == CodeVariant.VULNERABLE else FindingKind.PASS
    results = []
    for f in case.ground_truth:
        if f.kind != kind:
            continue
        if f.message:
            results.append(ExtractedCode(
                file_path=f.location.file,
                content=f.message,
                language=case.language.value,
            ))
            continue
        # Fallback: try to read from disk
        # case_id format: crossvul-{cwe_digits}-{ext}-{pair_id}
        parts = case.case_id.split("-")
        if len(parts) >= 4:
            cwe_digits = parts[1]
            ext = parts[2]
            pair_id = "-".join(parts[3:])
            prefix = "bad_" if variant == CodeVariant.VULNERABLE else "good_"
            file_path = _find_crossvul_root(dataset_dir) / f"CWE-{cwe_digits}" / ext / f"{prefix}{pair_id}"
            if file_path.exists():
                results.append(ExtractedCode(
                    file_path=f.location.file,
                    content=file_path.read_text(errors="replace"),
                    language=case.language.value,
                ))
    return results


def _find_crossvul_root(dataset_dir: Path) -> Path:
    """Locate the CrossVul root after extraction (same logic as ingest)."""
    for name in ("CrossVul", "dataset", "crossvul", "dataset_final_sorted"):
        candidate = dataset_dir / name
        if candidate.is_dir():
            return candidate
    for child in dataset_dir.iterdir():
        if child.is_dir() and child.name.upper().startswith("CWE"):
            return dataset_dir
    return dataset_dir


def _extract_monolithic(
    case: BenchmarkCase, variant: CodeVariant, ext_dir: Path,
) -> list[ExtractedCode]:
    """Extract from monolithic repos (go-sec-code, skf-labs).

    These repos only have the vulnerable version. Patched code doesn't
    exist as separate files, so we return empty for PATCHED variant.
    """
    if variant == CodeVariant.PATCHED:
        return []

    repo_dir = ext_dir / case.source_dataset / "repo"
    if not repo_dir.exists():
        raise FileNotFoundError(f"Monolithic repo not found: {repo_dir}")

    fail_files = {
        f.location.file
        for f in case.ground_truth
        if f.kind == FindingKind.FAIL
    }

    results = []
    for rel_file in fail_files:
        file_path = repo_dir / rel_file
        if not file_path.exists():
            logger.warning("File not found in monolithic repo: %s", file_path)
            continue
        results.append(ExtractedCode(
            file_path=rel_file,
            content=file_path.read_text(errors="replace"),
            language=case.language.value,
        ))
    return results


def _extract_ossf(
    case: BenchmarkCase, variant: CodeVariant, ext_dir: Path,
) -> list[ExtractedCode]:
    """Extract from OSSF CVE benchmark.

    OSSF cases reference npm package files. The repo has CVE JSON metadata
    but the actual vulnerable code requires npm install of specific versions.
    For now, try to find the file in the repo's node_modules or source tree.
    """
    repo_dir = ext_dir / "ossf-cve-benchmark" / "repo"
    if not repo_dir.exists():
        raise FileNotFoundError(f"OSSF repo not found: {repo_dir}")

    kind = FindingKind.FAIL if variant == CodeVariant.VULNERABLE else FindingKind.PASS
    truth_files = {
        f.location.file
        for f in case.ground_truth
        if f.kind == kind
    }

    results = []
    for rel_file in truth_files:
        # Try direct path first, then search
        file_path = repo_dir / rel_file
        if not file_path.exists():
            matches = list(repo_dir.rglob(Path(rel_file).name))
            if matches:
                file_path = matches[0]
            else:
                logger.warning("OSSF file not found: %s", rel_file)
                continue
        results.append(ExtractedCode(
            file_path=rel_file,
            content=file_path.read_text(errors="replace"),
            language=case.language.value,
        ))
    return results
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
uv run pytest benchmarks/tests/test_code_extractor.py -v
```

Expected: all 4 tests PASS

- [ ] **Step 5: Commit**

```bash
git add benchmarks/runner/code_extractor.py benchmarks/tests/test_code_extractor.py
git commit -m "feat(benchmarks): add per-dataset code extractor for evaluation"
```

---

## Task 3: Gate Checker (`benchmarks/runner/gate_checker.py`)

**Files:**
- Create: `benchmarks/runner/gate_checker.py`
- Test: `benchmarks/tests/test_gate_checker.py`

- [ ] **Step 1: Write failing tests**

```python
# benchmarks/tests/test_gate_checker.py
"""Tests for G5-G7 gate checking."""
from __future__ import annotations

import pytest

from benchmarks.runner.gate_checker import (
    G5_GATES,
    GateResult,
    check_g5_gates,
    check_g6_rust_disclaimer,
    build_g7_failure_dump,
)
from benchmarks.runner.models import (
    CodeLocation,
    Finding,
    FindingKind,
    Language,
    MetricSet,
    Summary,
)


def _make_summary(agent: str, dataset: str, tpr: float, fpr: float,
                  cwe_id: str | None = None) -> Summary:
    ms = MetricSet(
        agent_name=agent, dataset=dataset,
        cwe_id=cwe_id, language=None,
        true_positives=int(tpr * 10), false_positives=int(fpr * 10),
        true_negatives=int((1 - fpr) * 10), false_negatives=int((1 - tpr) * 10),
        tpr=tpr, fpr=fpr,
        precision=0.5, f1=0.5, accuracy=tpr - fpr,
    )
    return Summary(
        run_id="test", agent_name=agent, dataset=dataset,
        methodology={"pair_based": True, "match_mode": "broad"},
        metrics=[ms], generated_at="2026-04-11T00:00:00Z",
    )


class TestCheckG5Gates:
    def test_all_gates_pass(self):
        summaries = [
            _make_summary("xss", "ossf-cve-benchmark", tpr=0.75, fpr=0.20),
            _make_summary("xss", "reality-check-csharp", tpr=0.65, fpr=0.10, cwe_id="CWE-79"),
            _make_summary("xss", "reality-check-python", tpr=0.65, fpr=0.10, cwe_id="CWE-79"),
            _make_summary("cmdi", "ossf-cve-benchmark", tpr=0.65, fpr=0.10),
            _make_summary("cmdi", "reality-check-java", tpr=0.55, fpr=0.10, cwe_id="CWE-78"),
            _make_summary("sqli", "reality-check-csharp", tpr=0.55, fpr=0.10, cwe_id="CWE-89"),
            _make_summary("sqli", "morefixes-extract", tpr=0.55, fpr=0.10, cwe_id="CWE-89"),
            _make_summary("ssti", "go-sec-code-mutated", tpr=0.75, fpr=0.10, cwe_id="CWE-1336"),
            _make_summary("ssti", "skf-labs-mutated", tpr=0.75, fpr=0.10, cwe_id="CWE-1336"),
        ]
        results = check_g5_gates(summaries)
        assert all(r.passed for r in results)

    def test_gate_fails_below_threshold(self):
        summaries = [_make_summary("xss", "ossf-cve-benchmark", tpr=0.50, fpr=0.20)]
        results = check_g5_gates(summaries)
        xss_ossf = [r for r in results if r.gate_id == "G5.1"]
        assert len(xss_ossf) == 1
        assert xss_ossf[0].passed is False

    def test_missing_summary_reports_not_run(self):
        results = check_g5_gates([])  # no summaries
        assert any(not r.passed for r in results)


class TestG6:
    def test_rust_disclaimer_present(self):
        languages_in_run = [Language.JAVASCRIPT, Language.PYTHON]
        assert check_g6_rust_disclaimer(languages_in_run) is True

    def test_rust_disclaimer_fails_if_rust_present(self):
        languages_in_run = [Language.JAVASCRIPT, Language.RUST]
        assert check_g6_rust_disclaimer(languages_in_run) is False


class TestG7:
    def test_failure_dump_lists_missed_cases(self):
        missed = [
            Finding(cwe_id="CWE-79", kind=FindingKind.FAIL,
                    location=CodeLocation(file="a.js", start_line=1, end_line=5),
                    cve_id="CVE-2024-001"),
        ]
        dump = build_g7_failure_dump(missed_findings=missed, false_flags=[], max_items=10)
        assert len(dump["missed"]) == 1
        assert dump["missed"][0]["cve_id"] == "CVE-2024-001"
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
uv run pytest benchmarks/tests/test_gate_checker.py -v
```

Expected: FAIL — `ModuleNotFoundError`

- [ ] **Step 3: Implement gate checker**

```python
# benchmarks/runner/gate_checker.py
"""G5-G7 gate checking for Phase 1.7 validation.

G5: Detection rate thresholds per (agent, dataset) pair.
G6: Rust disclaimer must be present when no Rust cases are in the run.
G7: Failure dump for any gate below threshold.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Sequence

from benchmarks.runner.models import Finding, Language, MetricSet, Summary


@dataclass
class GateDefinition:
    """A single G5.* gate threshold."""
    gate_id: str
    agent: str
    dataset: str
    metric: str          # "tpr" or "fpr"
    threshold: float
    comparison: str      # "gte" (>=) or "lte" (<=)
    cwe_filter: str | None = None  # if set, use the per-CWE metric


G5_GATES: list[GateDefinition] = [
    GateDefinition("G5.1", "xss", "ossf-cve-benchmark", "tpr", 0.70, "gte"),
    GateDefinition("G5.2", "xss", "ossf-cve-benchmark", "fpr", 0.25, "lte"),
    GateDefinition("G5.3", "xss", "reality-check-csharp", "tpr", 0.60, "gte", "CWE-79"),
    GateDefinition("G5.4", "xss", "reality-check-python", "tpr", 0.60, "gte", "CWE-79"),
    GateDefinition("G5.5", "cmdi", "ossf-cve-benchmark", "tpr", 0.60, "gte"),
    GateDefinition("G5.6", "cmdi", "reality-check-java", "tpr", 0.50, "gte", "CWE-78"),
    GateDefinition("G5.7", "sqli", "reality-check-csharp", "tpr", 0.50, "gte", "CWE-89"),
    GateDefinition("G5.8", "sqli", "morefixes-extract", "tpr", 0.50, "gte", "CWE-89"),
    GateDefinition("G5.9", "ssti", "go-sec-code-mutated", "tpr", 0.70, "gte", "CWE-1336"),
    GateDefinition("G5.10", "ssti", "skf-labs-mutated", "tpr", 0.70, "gte", "CWE-1336"),
]


@dataclass
class GateResult:
    """Result of checking one gate."""
    gate_id: str
    passed: bool
    actual_value: float | None = None
    threshold: float = 0.0
    comparison: str = "gte"
    agent: str = ""
    dataset: str = ""
    note: str = ""


def check_g5_gates(summaries: list[Summary]) -> list[GateResult]:
    """Check all G5.* gates against the provided summaries.

    Args:
        summaries: List of Summary objects from benchmark runs.

    Returns:
        One GateResult per G5.* gate definition.
    """
    results: list[GateResult] = []
    for gate in G5_GATES:
        metric_set = _find_metric(summaries, gate)
        if metric_set is None:
            results.append(GateResult(
                gate_id=gate.gate_id, passed=False,
                threshold=gate.threshold, comparison=gate.comparison,
                agent=gate.agent, dataset=gate.dataset,
                note="Not run — no matching summary found",
            ))
            continue

        actual = getattr(metric_set, gate.metric)
        if gate.comparison == "gte":
            passed = actual >= gate.threshold
        else:
            passed = actual <= gate.threshold

        results.append(GateResult(
            gate_id=gate.gate_id, passed=passed,
            actual_value=actual, threshold=gate.threshold,
            comparison=gate.comparison,
            agent=gate.agent, dataset=gate.dataset,
        ))
    return results


def _find_metric(summaries: list[Summary], gate: GateDefinition) -> MetricSet | None:
    """Find the MetricSet matching a gate's agent, dataset, and optional CWE filter."""
    for s in summaries:
        if s.agent_name != gate.agent or s.dataset != gate.dataset:
            continue
        for m in s.metrics:
            if gate.cwe_filter:
                if m.cwe_id == gate.cwe_filter and m.language is None:
                    return m
            else:
                if m.cwe_id is None and m.language is None:
                    return m
    return None


def check_g6_rust_disclaimer(languages_in_run: Sequence[Language]) -> bool:
    """G6 passes if no Rust cases were included in the run.

    If Rust IS present, the gate fails — Rust detection quality is
    not benchmarked per ADR-014.
    """
    return Language.RUST not in languages_in_run


def build_g7_failure_dump(
    missed_findings: list[Finding],
    false_flags: list[Finding],
    max_items: int = 10,
) -> dict:
    """Build the G7 failure dump for a gate that missed its threshold.

    Args:
        missed_findings: Ground truth findings the agent failed to detect.
        false_flags: Agent findings on patched code (false positives).
        max_items: Maximum items to include per category.

    Returns:
        Dict with "missed" and "false_flags" lists.
    """
    def _serialize(f: Finding) -> dict:
        return {
            "cwe_id": f.cwe_id,
            "cve_id": f.cve_id,
            "file": f.location.file,
            "start_line": f.location.start_line,
            "end_line": f.location.end_line,
            "message": f.message,
        }

    return {
        "missed": [_serialize(f) for f in missed_findings[:max_items]],
        "false_flags": [_serialize(f) for f in false_flags[:max_items]],
    }
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
uv run pytest benchmarks/tests/test_gate_checker.py -v
```

Expected: all 5 tests PASS

- [ ] **Step 5: Commit**

```bash
git add benchmarks/runner/gate_checker.py benchmarks/tests/test_gate_checker.py
git commit -m "feat(benchmarks): add G5-G7 gate checker with thresholds from validation gates doc"
```

---

## Task 4: Gate Report Rendering (`benchmarks/runner/report.py`)

**Files:**
- Modify: `benchmarks/runner/report.py`
- Test: `benchmarks/tests/test_report_gates.py`

- [ ] **Step 1: Write failing tests for gate report**

```python
# benchmarks/tests/test_report_gates.py
"""Tests for gate report rendering (G5/G6/G7 sections)."""
from __future__ import annotations

import pytest

from benchmarks.runner.gate_checker import GateResult
from benchmarks.runner.report import render_gate_report


class TestRenderGateReport:
    def test_g5_pass_renders_checkmarks(self):
        gate_results = [
            GateResult(gate_id="G5.1", passed=True, actual_value=0.75,
                       threshold=0.70, comparison="gte", agent="xss",
                       dataset="ossf-cve-benchmark"),
        ]
        md = render_gate_report(gate_results, g6_passed=True, g7_dumps={})
        assert "PASS" in md
        assert "G5.1" in md

    def test_g5_fail_renders_crosses(self):
        gate_results = [
            GateResult(gate_id="G5.1", passed=False, actual_value=0.50,
                       threshold=0.70, comparison="gte", agent="xss",
                       dataset="ossf-cve-benchmark"),
        ]
        md = render_gate_report(gate_results, g6_passed=True, g7_dumps={})
        assert "FAIL" in md

    def test_g6_rust_disclaimer_present(self):
        md = render_gate_report([], g6_passed=True, g7_dumps={})
        assert "Rust detection quality not benchmarked" in md
        assert "ADR-014" in md

    def test_g7_failure_dump_included(self):
        dumps = {
            "G5.1": {
                "missed": [{"cwe_id": "CWE-79", "cve_id": "CVE-2024-001",
                            "file": "a.js", "start_line": 1, "end_line": 5,
                            "message": "XSS"}],
                "false_flags": [],
            }
        }
        md = render_gate_report([], g6_passed=True, g7_dumps=dumps)
        assert "CVE-2024-001" in md
        assert "a.js" in md
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
uv run pytest benchmarks/tests/test_report_gates.py -v
```

Expected: FAIL — `ImportError: cannot import name 'render_gate_report'`

- [ ] **Step 3: Add `render_gate_report` to report.py**

Add the following to the end of `benchmarks/runner/report.py`:

```python
def render_gate_report(
    gate_results: list["GateResult"],
    g6_passed: bool,
    g7_dumps: dict[str, dict],
) -> str:
    """Render G5/G6/G7 gate results as Markdown."""
    from benchmarks.runner.gate_checker import GateResult

    out = StringIO()

    # G5 results table
    out.write("## G5: Detection Rate Gates\n\n")
    out.write("| Gate | Agent | Dataset | Threshold | Actual | Result |\n")
    out.write("|------|-------|---------|-----------|--------|--------|\n")
    for r in gate_results:
        actual_str = _pct(r.actual_value) if r.actual_value is not None else "N/A"
        op = ">=" if r.comparison == "gte" else "<="
        result_str = "PASS" if r.passed else "FAIL"
        out.write(
            f"| {r.gate_id} | {r.agent} | {r.dataset} | "
            f"{op} {_pct(r.threshold)} | {actual_str} | {result_str} |\n"
        )

    passed = sum(1 for r in gate_results if r.passed)
    total = len(gate_results)
    out.write(f"\n**G5 overall: {passed}/{total} gates passed.**\n\n")

    # G6 Rust disclaimer
    out.write("## G6: Rust Disclaimer\n\n")
    if g6_passed:
        out.write("> Rust detection quality not benchmarked — see ADR-014. "
                  "Rust corpus construction is deferred to Phase 4 (step 4.0).\n\n")
        out.write("**G6: PASS**\n\n")
    else:
        out.write("**G6: FAIL** — Rust cases were included but should not have been. "
                  "See ADR-014.\n\n")

    # G7 failure dumps
    if g7_dumps:
        out.write("## G7: Failure Dumps\n\n")
        for gate_id, dump in sorted(g7_dumps.items()):
            out.write(f"### {gate_id}\n\n")
            if dump.get("missed"):
                out.write("**Missed vulnerabilities:**\n\n")
                out.write("| CWE | CVE | File | Lines | Message |\n")
                out.write("|-----|-----|------|-------|---------|\n")
                for m in dump["missed"]:
                    out.write(f"| {m['cwe_id']} | {m.get('cve_id', 'N/A')} | "
                              f"{m['file']} | {m['start_line']}-{m['end_line']} | "
                              f"{(m.get('message') or '')[:60]} |\n")
                out.write("\n")
            if dump.get("false_flags"):
                out.write("**False flags (flagged on patched code):**\n\n")
                out.write("| CWE | File | Lines | Message |\n")
                out.write("|-----|------|-------|---------|\n")
                for ff in dump["false_flags"]:
                    out.write(f"| {ff['cwe_id']} | {ff['file']} | "
                              f"{ff['start_line']}-{ff['end_line']} | "
                              f"{(ff.get('message') or '')[:60]} |\n")
                out.write("\n")
    else:
        out.write("## G7: Failure Dumps\n\nNo failure dumps required — "
                  "all evaluated gates passed or were not run.\n\n")

    return out.getvalue()
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
uv run pytest benchmarks/tests/test_report_gates.py -v
```

Expected: all 4 tests PASS

- [ ] **Step 5: Run existing report tests to verify no regression**

```bash
uv run pytest benchmarks/tests/test_report.py -v
```

Expected: all existing tests still PASS

- [ ] **Step 6: Commit**

```bash
git add benchmarks/runner/report.py benchmarks/tests/test_report_gates.py
git commit -m "feat(benchmarks): add G5/G6/G7 gate report rendering"
```

---

## Task 5: Evaluator (`benchmarks/runner/evaluator.py`)

**Files:**
- Create: `benchmarks/runner/evaluator.py`
- Test: `benchmarks/tests/test_evaluator.py`

This is the core orchestration module. It loads cases from manifests, maps them to agents, extracts code, assembles prompts, invokes Claude, parses findings, and scores results.

- [ ] **Step 1: Write failing tests with mocked invoker**

```python
# benchmarks/tests/test_evaluator.py
"""Tests for the evaluation orchestrator."""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from benchmarks.runner.evaluator import (
    Evaluator,
    EvalConfig,
    load_cases_from_manifest,
    map_case_to_agent,
    build_prompt,
    parse_findings_response,
)
from benchmarks.runner.invoker import InvokeResult
from benchmarks.runner.models import (
    BenchmarkCase,
    CodeLocation,
    Finding,
    FindingKind,
    Language,
)


@pytest.fixture
def sample_manifest(tmp_path):
    manifest = {
        "dataset_name": "test-dataset",
        "source_url": "https://example.com",
        "case_count": 2,
        "cases": [
            {
                "case_id": "test-1",
                "project": "proj",
                "language": "python",
                "vulnerable_version": "v1",
                "patched_version": "v2",
                "published_date": None,
                "fail_count": 1,
                "pass_count": 1,
            },
            {
                "case_id": "test-2",
                "project": "proj2",
                "language": "go",
                "vulnerable_version": "v1",
                "patched_version": "v2",
                "published_date": None,
                "fail_count": 1,
                "pass_count": 1,
            },
        ],
    }
    path = tmp_path / "test.manifest.json"
    path.write_text(json.dumps(manifest))
    return path


class TestLoadCases:
    def test_loads_cases_from_manifest(self, sample_manifest):
        cases = load_cases_from_manifest(sample_manifest)
        assert len(cases) == 2
        assert cases[0]["case_id"] == "test-1"
        assert cases[0]["language"] == "python"


CWE_TO_AGENT = {
    "CWE-79": "xss",
    "CWE-78": "cmdi",
    "CWE-89": "sqli",
    "CWE-1336": "ssti",
    "CWE-94": "ssti",
}


class TestMapCaseToAgent:
    def test_maps_xss_case(self):
        case = BenchmarkCase(
            case_id="t", project="p", language=Language.PYTHON,
            vulnerable_version="v1", patched_version="v2",
            ground_truth=[
                Finding(cwe_id="CWE-79", kind=FindingKind.FAIL,
                        location=CodeLocation(file="a.py", start_line=1, end_line=1)),
            ],
            source_dataset="test",
        )
        assert map_case_to_agent(case) == "xss"

    def test_returns_none_for_unknown_cwe(self):
        case = BenchmarkCase(
            case_id="t", project="p", language=Language.PYTHON,
            vulnerable_version="v1", patched_version="v2",
            ground_truth=[
                Finding(cwe_id="CWE-502", kind=FindingKind.FAIL,
                        location=CodeLocation(file="a.py", start_line=1, end_line=1)),
            ],
            source_dataset="test",
        )
        assert map_case_to_agent(case) is None


class TestBuildPrompt:
    def test_includes_instructions_and_code(self):
        prompt = build_prompt(
            core_prompt="Detect XSS vulnerabilities.",
            code="var x = document.innerHTML;",
            file_path="view.js",
        )
        assert "Detect XSS" in prompt
        assert "document.innerHTML" in prompt
        assert "JSON" in prompt  # must instruct JSON output


class TestParseFindingsResponse:
    def test_parses_valid_findings(self):
        raw = [
            {"cwe_id": "CWE-79", "file": "a.js", "start_line": 10,
             "end_line": 15, "confidence": 0.9, "message": "XSS"}
        ]
        findings = parse_findings_response(raw, agent_name="xss")
        assert len(findings) == 1
        assert findings[0].cwe_id == "CWE-79"
        assert findings[0].agent_name == "xss"

    def test_skips_malformed_entries(self):
        raw = [
            {"cwe_id": "CWE-79"},  # missing required fields
            {"cwe_id": "CWE-79", "file": "a.js", "start_line": 1,
             "end_line": 5, "confidence": 0.8, "message": "ok"},
        ]
        findings = parse_findings_response(raw, agent_name="xss")
        assert len(findings) == 1
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
uv run pytest benchmarks/tests/test_evaluator.py -v
```

Expected: FAIL — `ModuleNotFoundError`

- [ ] **Step 3: Implement evaluator**

```python
# benchmarks/runner/evaluator.py
"""Benchmark evaluation orchestrator.

Loads cases from manifests, maps them to agents, extracts code from
benchmark datasets, assembles detection prompts via ScanEngine, invokes
Claude, and scores results through the metrics pipeline.
"""
from __future__ import annotations

import json
import logging
import tempfile
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from benchmarks.runner.code_extractor import CodeVariant, ExtractedCode, extract_code_for_case
from benchmarks.runner.cwe import Cwe1400Hierarchy, load_hierarchy
from benchmarks.runner.invoker import InvokeResult, InvokerConfig, invoke_claude
from benchmarks.runner.metrics import compute_metrics
from benchmarks.runner.models import (
    AgentRun,
    BenchmarkCase,
    CodeLocation,
    Finding,
    FindingKind,
    Language,
    Summary,
)
from benchmarks.runner.sarif import load_bentoo_sarif

logger = logging.getLogger(__name__)

# Maps ground-truth CWE IDs to agent names
_CWE_TO_AGENT: dict[str, str] = {
    "CWE-79": "xss",
    "CWE-78": "cmdi",
    "CWE-89": "sqli",
    "CWE-94": "ssti",
    "CWE-1336": "ssti",
}

REPO_ROOT = Path(__file__).resolve().parents[2]


@dataclass
class EvalConfig:
    """Configuration for an evaluation run."""
    mode: str = "sample"                          # "sample" or "full"
    results_dir: Path = field(default_factory=lambda: REPO_ROOT / "benchmarks" / "results")
    benchmarks_external_dir: Path = field(default_factory=lambda: REPO_ROOT / "benchmarks" / "external")
    domains_dir: Path = field(default_factory=lambda: REPO_ROOT / "domains")
    invoker_config: InvokerConfig = field(default_factory=InvokerConfig)
    sample_max_per_agent: int = 5


def load_cases_from_manifest(manifest_path: Path) -> list[dict]:
    """Load case metadata from a manifest JSON file."""
    data = json.loads(manifest_path.read_text())
    return data.get("cases", [])


def load_full_cases_from_manifest(
    manifest_path: Path,
    truth_dir: Path,
) -> list[BenchmarkCase]:
    """Load BenchmarkCases with full ground truth from manifest + truth.sarif files.

    Args:
        manifest_path: Path to the dataset manifest JSON.
        truth_dir: Path to the dataset directory containing per-case truth.sarif files.

    Returns:
        List of BenchmarkCase objects with ground truth populated.
    """
    data = json.loads(manifest_path.read_text())
    dataset_name = data["dataset_name"]
    cases = []
    for raw in data.get("cases", []):
        case_id = raw["case_id"]
        truth_path = truth_dir / case_id / "truth.sarif"
        if truth_path.exists():
            ground_truth = load_bentoo_sarif(truth_path)
        else:
            ground_truth = []
            logger.warning("No truth.sarif for case %s at %s", case_id, truth_path)

        try:
            lang = Language(raw["language"])
        except ValueError:
            logger.warning("Unknown language %s for case %s, skipping", raw["language"], case_id)
            continue

        cases.append(BenchmarkCase(
            case_id=case_id,
            project=raw["project"],
            language=lang,
            vulnerable_version=raw["vulnerable_version"],
            patched_version=raw["patched_version"],
            ground_truth=ground_truth,
            published_date=None,
            source_dataset=dataset_name,
        ))
    return cases


def map_case_to_agent(case: BenchmarkCase) -> str | None:
    """Determine which agent should scan this case based on ground truth CWE."""
    for f in case.ground_truth:
        if f.kind == FindingKind.FAIL and f.cwe_id in _CWE_TO_AGENT:
            return _CWE_TO_AGENT[f.cwe_id]
    return None


def build_prompt(core_prompt: str, code: str, file_path: str) -> str:
    """Build the full prompt sent to Claude.

    Combines the agent's detection knowledge with the code to analyze
    and instructions for structured JSON output.
    """
    return f"""{core_prompt}

## Code to Analyze

**File:** `{file_path}`

```
{code}
```

## Instructions

Analyze the code above using the detection knowledge provided. Return your findings as a JSON array. Each finding must have exactly these fields:
- "cwe_id": string (e.g., "CWE-79")
- "file": string (the file path given above)
- "start_line": integer (1-based line number where the vulnerability starts)
- "end_line": integer (1-based line number where the vulnerability ends)
- "confidence": float between 0.0 and 1.0
- "message": string (brief explanation of the vulnerability)

If no vulnerabilities are found, return an empty array: []

Return ONLY the JSON array, no other text."""


def parse_findings_response(
    raw_findings: list[dict],
    agent_name: str,
) -> list[Finding]:
    """Convert raw finding dicts from Claude's response into Finding objects.

    Silently skips malformed entries.
    """
    findings = []
    for item in raw_findings:
        try:
            findings.append(Finding(
                cwe_id=item["cwe_id"],
                kind=FindingKind.FAIL,
                location=CodeLocation(
                    file=item["file"],
                    start_line=int(item["start_line"]),
                    end_line=int(item["end_line"]),
                ),
                confidence=float(item.get("confidence", 0.5)),
                message=item.get("message"),
                agent_name=agent_name,
            ))
        except (KeyError, ValueError, TypeError) as exc:
            logger.debug("Skipping malformed finding: %s — %s", item, exc)
    return findings


class Evaluator:
    """Orchestrates benchmark evaluation runs."""

    def __init__(self, config: EvalConfig) -> None:
        self.config = config
        self.run_id = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        self._run_dir = config.results_dir / self.run_id
        self._cases_dir = self._run_dir / "cases"

    def run(
        self,
        cases: list[BenchmarkCase],
        engine: "ScanEngine",
    ) -> list[Summary]:
        """Run evaluation on the given cases.

        Args:
            cases: Benchmark cases to evaluate.
            engine: ScanEngine instance for prompt assembly.

        Returns:
            List of Summary objects, one per (agent, dataset) pair.
        """
        self._run_dir.mkdir(parents=True, exist_ok=True)
        self._cases_dir.mkdir(exist_ok=True)

        # Group cases by (agent, dataset)
        grouped: dict[tuple[str, str], list[BenchmarkCase]] = {}
        for case in cases:
            agent = map_case_to_agent(case)
            if agent is None:
                logger.info("Skipping case %s — no matching agent", case.case_id)
                continue
            key = (agent, case.source_dataset)
            grouped.setdefault(key, []).append(case)

        # Evaluate each group
        hierarchy = load_hierarchy()
        summaries = []
        for (agent_name, dataset), group_cases in grouped.items():
            logger.info("Evaluating %s on %s (%d cases)", agent_name, dataset, len(group_cases))
            summary = self._evaluate_group(agent_name, dataset, group_cases, engine, hierarchy)
            summaries.append(summary)

        return summaries

    def _evaluate_group(
        self,
        agent_name: str,
        dataset: str,
        cases: list[BenchmarkCase],
        engine: "ScanEngine",
        hierarchy: Cwe1400Hierarchy,
    ) -> Summary:
        """Evaluate one (agent, dataset) group."""
        vuln_runs: list[AgentRun] = []
        patched_runs: list[AgentRun] = []

        for case in cases:
            vuln_run, patched_run = self._evaluate_case(case, agent_name, engine)
            vuln_runs.append(vuln_run)
            patched_runs.append(patched_run)

            # Throttle between cases
            time.sleep(self.config.invoker_config.throttle_delay)

        return compute_metrics(
            cases=cases,
            runs_vulnerable=vuln_runs,
            runs_patched=patched_runs,
            hierarchy=hierarchy,
            agent_name=agent_name,
            dataset=dataset,
        )

    def _evaluate_case(
        self,
        case: BenchmarkCase,
        agent_name: str,
        engine: "ScanEngine",
    ) -> tuple[AgentRun, AgentRun]:
        """Evaluate a single case (vulnerable + patched scans).

        Returns (vuln_run, patched_run). Uses checkpoint files to skip
        already-evaluated cases.
        """
        vuln_result_path = self._cases_dir / f"{case.case_id}_vuln.json"
        patched_result_path = self._cases_dir / f"{case.case_id}_patched.json"

        # Vulnerable scan
        if vuln_result_path.exists():
            logger.info("  [cached] %s vuln", case.case_id)
            vuln_findings = self._load_cached_findings(vuln_result_path)
        else:
            logger.info("  [scan] %s vuln", case.case_id)
            vuln_findings = self._scan_variant(case, agent_name, CodeVariant.VULNERABLE, engine)
            self._save_findings(vuln_result_path, vuln_findings)

        # Patched scan
        if patched_result_path.exists():
            logger.info("  [cached] %s patched", case.case_id)
            patched_findings = self._load_cached_findings(patched_result_path)
        else:
            logger.info("  [scan] %s patched", case.case_id)
            patched_findings = self._scan_variant(case, agent_name, CodeVariant.PATCHED, engine)
            self._save_findings(patched_result_path, patched_findings)

        vuln_run = AgentRun(
            case_id=case.case_id, agent_name=agent_name,
            findings=vuln_findings, runtime_seconds=0.0,
        )
        patched_run = AgentRun(
            case_id=case.case_id, agent_name=agent_name,
            findings=patched_findings, runtime_seconds=0.0,
        )
        return vuln_run, patched_run

    def _scan_variant(
        self,
        case: BenchmarkCase,
        agent_name: str,
        variant: CodeVariant,
        engine: "ScanEngine",
    ) -> list[Finding]:
        """Extract code, assemble prompt, invoke Claude, parse findings."""
        code_pieces = extract_code_for_case(
            case, variant, self.config.benchmarks_external_dir,
        )
        if not code_pieces:
            return []

        all_findings: list[Finding] = []
        for piece in code_pieces:
            # Write code to temp file for assemble_scan
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=f".{piece.language}", delete=False,
            ) as tmp:
                tmp.write(piece.content)
                tmp_path = tmp.name

            try:
                payload = engine.assemble_scan(
                    agent_name=agent_name,
                    target={"type": "file", "path": tmp_path},
                )
                prompt = build_prompt(
                    core_prompt=payload["core_prompt"],
                    code=payload["code"],
                    file_path=piece.file_path,
                )
                result = invoke_claude(prompt, self.config.invoker_config)
                if result.success:
                    findings = parse_findings_response(result.findings, agent_name)
                    all_findings.extend(findings)
                else:
                    logger.warning("Claude invocation failed for %s: %s",
                                   case.case_id, result.error)
            finally:
                Path(tmp_path).unlink(missing_ok=True)

        return all_findings

    def _save_findings(self, path: Path, findings: list[Finding]) -> None:
        data = [
            {
                "cwe_id": f.cwe_id,
                "kind": f.kind.value,
                "file": f.location.file,
                "start_line": f.location.start_line,
                "end_line": f.location.end_line,
                "confidence": f.confidence,
                "message": f.message,
                "agent_name": f.agent_name,
            }
            for f in findings
        ]
        path.write_text(json.dumps(data, indent=2))

    def _load_cached_findings(self, path: Path) -> list[Finding]:
        data = json.loads(path.read_text())
        findings = []
        for item in data:
            findings.append(Finding(
                cwe_id=item["cwe_id"],
                kind=FindingKind(item["kind"]),
                location=CodeLocation(
                    file=item["file"],
                    start_line=item["start_line"],
                    end_line=item["end_line"],
                ),
                confidence=item.get("confidence"),
                message=item.get("message"),
                agent_name=item.get("agent_name"),
            ))
        return findings
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
uv run pytest benchmarks/tests/test_evaluator.py -v
```

Expected: all 6 tests PASS

- [ ] **Step 5: Commit**

```bash
git add benchmarks/runner/evaluator.py benchmarks/tests/test_evaluator.py
git commit -m "feat(benchmarks): add evaluation orchestrator with checkpoint/resume"
```

---

## Task 6: CLI Entry Point (`benchmarks/scripts/run_gates.py`)

**Files:**
- Create: `benchmarks/scripts/run_gates.py`

- [ ] **Step 1: Implement the CLI entry point**

```python
# benchmarks/scripts/run_gates.py
"""CLI entry point for G5-G7 gate validation.

Usage:
    # Sample run (20 cases, validates pipeline)
    uv run python benchmarks/scripts/run_gates.py --mode sample

    # Full run (all filtered cases)
    uv run python benchmarks/scripts/run_gates.py --mode full

    # Resume a previous run
    uv run python benchmarks/scripts/run_gates.py --mode full --resume <run_id>
"""
from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

from benchmarks.runner.code_extractor import CodeVariant, extract_code_for_case
from benchmarks.runner.evaluator import (
    Evaluator,
    EvalConfig,
    load_full_cases_from_manifest,
    map_case_to_agent,
)
from benchmarks.runner.gate_checker import (
    build_g7_failure_dump,
    check_g5_gates,
    check_g6_rust_disclaimer,
)
from benchmarks.runner.invoker import InvokerConfig
from benchmarks.runner.models import Language
from benchmarks.runner.report import render_gate_report, render_markdown

REPO_ROOT = Path(__file__).resolve().parents[2]
MANIFESTS_DIR = REPO_ROOT / "benchmarks" / "external" / "manifests"
EXTERNAL_DIR = REPO_ROOT / "benchmarks" / "external"

# Datasets to use for sample run (easy to materialize, no Docker/npm)
SAMPLE_DATASETS = [
    "reality-check-csharp",
    "reality-check-python",
    "reality-check-java",
    "go-sec-code-mutated",
    "skf-labs-mutated",
    "crossvul",
]


def collect_cases(mode: str) -> list:
    """Load and filter benchmark cases from manifests."""
    from benchmarks.runner.models import BenchmarkCase

    datasets = SAMPLE_DATASETS if mode == "sample" else None
    all_cases: list[BenchmarkCase] = []

    for manifest_path in sorted(MANIFESTS_DIR.glob("*.manifest.json")):
        ds_name = manifest_path.stem.replace(".manifest", "")

        # Skip internal manifests
        if ds_name.startswith("_"):
            continue

        # Filter datasets for sample mode
        if datasets is not None and ds_name not in datasets:
            continue

        truth_dir = EXTERNAL_DIR / ds_name
        if not truth_dir.exists():
            logging.warning("Dataset dir missing for %s — skipping. Run ingest first.", ds_name)
            continue

        cases = load_full_cases_from_manifest(manifest_path, truth_dir)
        # Filter to cases with matching agents
        cases = [c for c in cases if map_case_to_agent(c) is not None]
        all_cases.extend(cases)

    return all_cases


def select_sample(cases: list, max_per_agent: int = 5) -> list:
    """Select a representative sample: up to max_per_agent cases per agent."""
    from collections import defaultdict

    by_agent: dict[str, list] = defaultdict(list)
    for case in cases:
        agent = map_case_to_agent(case)
        if agent:
            by_agent[agent].append(case)

    selected = []
    for agent, agent_cases in by_agent.items():
        selected.extend(agent_cases[:max_per_agent])

    return selected


def ensure_datasets_downloaded(datasets: list[str]) -> None:
    """Re-clone/download datasets that aren't on disk."""
    # Import ingest classes lazily
    ingest_map = {
        "reality-check-csharp": "benchmarks.scripts.ingest_reality_check_csharp",
        "reality-check-python": "benchmarks.scripts.ingest_reality_check_python",
        "reality-check-java": "benchmarks.scripts.ingest_reality_check_java",
        "go-sec-code-mutated": "benchmarks.scripts.ingest_go_sec_code",
        "skf-labs-mutated": "benchmarks.scripts.ingest_skf_labs",
        "crossvul": "benchmarks.scripts.ingest_crossvul",
    }
    import importlib

    for ds in datasets:
        ds_dir = EXTERNAL_DIR / ds
        # Check if repo/data already exists
        has_data = (ds_dir / "repo").exists() or any(
            d.is_dir() for d in ds_dir.iterdir()
            if d.name not in ("truth.sarif",) and not d.name.endswith(".manifest.json")
        ) if ds_dir.exists() else False

        if has_data:
            print(f"  {ds}: already present")
            continue

        module_name = ingest_map.get(ds)
        if module_name is None:
            print(f"  {ds}: no ingest module, skipping download")
            continue

        print(f"  {ds}: downloading...")
        mod = importlib.import_module(module_name)
        mod.main()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run G5-G7 detection rate validation gates",
    )
    parser.add_argument(
        "--mode", choices=["sample", "full"], default="sample",
        help="'sample' runs ~20 cases to validate pipeline; 'full' runs all filtered cases",
    )
    parser.add_argument(
        "--resume", type=str, default=None,
        help="Resume a previous run by run_id (reads cached results)",
    )
    parser.add_argument(
        "--throttle", type=float, default=2.0,
        help="Seconds between Claude calls (default: 2.0)",
    )
    parser.add_argument(
        "--max-retries", type=int, default=3,
        help="Max retries per Claude call (default: 3)",
    )
    parser.add_argument(
        "--log-level", choices=["DEBUG", "INFO", "WARNING"], default="INFO",
    )
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    # Step 1: Ensure datasets are downloaded
    print(f"\n=== Phase 1.7: G5-G7 Gate Validation ({args.mode} mode) ===\n")
    print("Step 1: Checking dataset availability...")
    datasets = SAMPLE_DATASETS if args.mode == "sample" else None
    if datasets:
        ensure_datasets_downloaded(datasets)

    # Step 2: Load and filter cases
    print("\nStep 2: Loading benchmark cases...")
    cases = collect_cases(args.mode)
    if args.mode == "sample":
        cases = select_sample(cases, max_per_agent=5)
    print(f"  {len(cases)} cases selected")

    if not cases:
        print("ERROR: No cases found. Run ingest scripts first.")
        return 1

    # Step 3: Initialize engine and evaluator
    print("\nStep 3: Initializing scan engine...")
    from screw_agents.engine import ScanEngine
    from screw_agents.registry import AgentRegistry

    registry = AgentRegistry(REPO_ROOT / "domains")
    engine = ScanEngine(registry)

    invoker_config = InvokerConfig(
        throttle_delay=args.throttle,
        max_retries=args.max_retries,
    )
    eval_config = EvalConfig(
        mode=args.mode,
        invoker_config=invoker_config,
    )
    evaluator = Evaluator(eval_config)

    if args.resume:
        evaluator.run_id = args.resume
        evaluator._run_dir = eval_config.results_dir / args.resume
        evaluator._cases_dir = evaluator._run_dir / "cases"

    # Step 4: Run evaluation
    print(f"\nStep 4: Running evaluation (run_id: {evaluator.run_id})...")
    summaries = evaluator.run(cases, engine)

    # Step 5: Check gates
    print("\nStep 5: Checking gates...")
    gate_results = check_g5_gates(summaries)
    languages_seen = {case.language for case in cases}
    g6_passed = check_g6_rust_disclaimer(list(languages_seen))

    # Build G7 failure dumps for failed gates
    g7_dumps: dict[str, dict] = {}
    for gr in gate_results:
        if not gr.passed and gr.note != "Not run — no matching summary found":
            g7_dumps[gr.gate_id] = {"missed": [], "false_flags": []}

    # Step 6: Generate report
    print("\nStep 6: Generating report...")
    run_dir = eval_config.results_dir / evaluator.run_id
    run_dir.mkdir(parents=True, exist_ok=True)

    # Per-summary reports
    for s in summaries:
        md = render_markdown(s)
        (run_dir / f"summary_{s.agent_name}_{s.dataset}.md").write_text(md)

    # Gate report
    gate_md = render_gate_report(gate_results, g6_passed, g7_dumps)
    (run_dir / "gate_report.md").write_text(gate_md)

    # Machine-readable gate results
    gate_json = {
        "run_id": evaluator.run_id,
        "mode": args.mode,
        "g5": [
            {
                "gate_id": r.gate_id, "passed": r.passed,
                "actual": r.actual_value, "threshold": r.threshold,
                "agent": r.agent, "dataset": r.dataset, "note": r.note,
            }
            for r in gate_results
        ],
        "g6_passed": g6_passed,
        "g7_dumps": g7_dumps,
    }
    (run_dir / "gate_results.json").write_text(json.dumps(gate_json, indent=2))

    # Print summary
    print(f"\n=== Results (run_id: {evaluator.run_id}) ===\n")
    passed = sum(1 for r in gate_results if r.passed)
    total = len(gate_results)
    for r in gate_results:
        status = "PASS" if r.passed else "FAIL"
        actual = f"{r.actual_value:.1%}" if r.actual_value is not None else "N/A"
        op = ">=" if r.comparison == "gte" else "<="
        print(f"  {r.gate_id}: {status}  {r.agent}/{r.dataset}  {actual} ({op} {r.threshold:.0%})")

    print(f"\nG5: {passed}/{total} gates passed")
    print(f"G6 (Rust disclaimer): {'PASS' if g6_passed else 'FAIL'}")
    print(f"G7 (Failure dumps): {len(g7_dumps)} dumps generated")
    print(f"\nFull report: {run_dir / 'gate_report.md'}")

    return 0 if (passed == total and g6_passed) else 1


if __name__ == "__main__":
    sys.exit(main())
```

- [ ] **Step 2: Verify the script parses args correctly (dry run)**

```bash
uv run python benchmarks/scripts/run_gates.py --help
```

Expected: prints help text with `--mode`, `--resume`, `--throttle`, `--log-level` options.

- [ ] **Step 3: Commit**

```bash
git add benchmarks/scripts/run_gates.py
git commit -m "feat(benchmarks): add G5-G7 gate validation CLI entry point"
```

---

## Task 7: Gitignore Results Directory

**Files:**
- Modify: `.gitignore`

- [ ] **Step 1: Add results directory to gitignore**

Add to `.gitignore`:

```
# Benchmark evaluation results (large, machine-generated)
benchmarks/results/
```

- [ ] **Step 2: Commit**

```bash
git add .gitignore
git commit -m "chore: gitignore benchmark evaluation results"
```

---

## Task 8: Integration Smoke Test

**Files:**
- Create: `benchmarks/tests/test_evaluator_integration.py`

This test verifies the full pipeline with a mocked invoker — no actual Claude calls.

- [ ] **Step 1: Write integration test**

```python
# benchmarks/tests/test_evaluator_integration.py
"""Integration test: full pipeline with mocked Claude invoker."""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from benchmarks.runner.code_extractor import CodeVariant, ExtractedCode
from benchmarks.runner.evaluator import Evaluator, EvalConfig
from benchmarks.runner.invoker import InvokeResult, InvokerConfig
from benchmarks.runner.models import (
    BenchmarkCase,
    CodeLocation,
    Finding,
    FindingKind,
    Language,
)

from screw_agents.engine import ScanEngine
from screw_agents.registry import AgentRegistry


REPO_ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def engine():
    return ScanEngine(AgentRegistry(REPO_ROOT / "domains"))


@pytest.fixture
def xss_case():
    return BenchmarkCase(
        case_id="integration-xss-1",
        project="test-proj",
        language=Language.PYTHON,
        vulnerable_version="v1",
        patched_version="v2",
        ground_truth=[
            Finding(cwe_id="CWE-79", kind=FindingKind.FAIL,
                    location=CodeLocation(file="view.py", start_line=5, end_line=10)),
            Finding(cwe_id="CWE-79", kind=FindingKind.PASS,
                    location=CodeLocation(file="view.py", start_line=5, end_line=10)),
        ],
        source_dataset="reality-check-python",
    )


def _mock_extract(case, variant, ext_dir):
    if variant == CodeVariant.VULNERABLE:
        return [ExtractedCode(
            file_path="view.py",
            content='from flask import request, Markup\n\n@app.route("/")\ndef index():\n    name = request.args.get("name")\n    return Markup(f"<h1>Hello {name}</h1>")',
            language="python",
        )]
    return [ExtractedCode(
        file_path="view.py",
        content='from flask import request, escape\n\n@app.route("/")\ndef index():\n    name = escape(request.args.get("name"))\n    return f"<h1>Hello {name}</h1>"',
        language="python",
    )]


def _mock_invoke_vuln(prompt, config):
    """Mock Claude finding a vulnerability in the vulnerable version."""
    return InvokeResult(
        success=True,
        findings=[{
            "cwe_id": "CWE-79",
            "file": "view.py",
            "start_line": 5,
            "end_line": 6,
            "confidence": 0.95,
            "message": "User input rendered without escaping via Markup()",
        }],
    )


def _mock_invoke_patched(prompt, config):
    """Mock Claude finding nothing in the patched version."""
    return InvokeResult(success=True, findings=[])


class TestIntegrationPipeline:
    def test_full_pipeline_produces_summary(self, engine, xss_case, tmp_path):
        config = EvalConfig(
            results_dir=tmp_path / "results",
            invoker_config=InvokerConfig(throttle_delay=0.0),
        )
        evaluator = Evaluator(config)

        call_count = 0

        def mock_invoke(prompt, cfg):
            nonlocal call_count
            call_count += 1
            # First call = vulnerable, second = patched
            if call_count % 2 == 1:
                return _mock_invoke_vuln(prompt, cfg)
            return _mock_invoke_patched(prompt, cfg)

        with patch("benchmarks.runner.evaluator.extract_code_for_case", side_effect=_mock_extract), \
             patch("benchmarks.runner.evaluator.invoke_claude", side_effect=mock_invoke):
            summaries = evaluator.run([xss_case], engine)

        assert len(summaries) == 1
        s = summaries[0]
        assert s.agent_name == "xss"
        overall = next(m for m in s.metrics if m.cwe_id is None and m.language is None)
        assert overall.true_positives >= 1
        assert overall.tpr > 0.0

        # Check that checkpoint files were written
        cases_dir = config.results_dir / evaluator.run_id / "cases"
        assert (cases_dir / "integration-xss-1_vuln.json").exists()
        assert (cases_dir / "integration-xss-1_patched.json").exists()
```

- [ ] **Step 2: Run integration test**

```bash
uv run pytest benchmarks/tests/test_evaluator_integration.py -v
```

Expected: PASS

- [ ] **Step 3: Run the full test suite to check for regressions**

```bash
uv run pytest tests/ benchmarks/tests/ -v
```

Expected: all existing tests + new tests PASS

- [ ] **Step 4: Commit**

```bash
git add benchmarks/tests/test_evaluator_integration.py
git commit -m "test(benchmarks): add integration test for evaluation pipeline"
```

---

## Task 9: Sample Run Execution

This is the actual execution step — not automated, requires user interaction.

- [ ] **Step 1: Ensure benchmark datasets are downloaded**

```bash
cd /home/marco/Programming/AI/screw-agents
uv run python benchmarks/scripts/run_gates.py --mode sample --log-level INFO
```

This will:
1. Clone/download missing datasets (reality-check, go-sec-code, skf-labs, CrossVul)
2. Load and filter cases
3. Select sample (up to 5 per agent)
4. Run each case through Claude
5. Score and generate gate report

If cloning fails due to network issues, run the individual ingest scripts manually:

```bash
uv run python -m benchmarks.scripts.ingest_reality_check_csharp
uv run python -m benchmarks.scripts.ingest_reality_check_python
uv run python -m benchmarks.scripts.ingest_reality_check_java
uv run python -m benchmarks.scripts.ingest_go_sec_code
uv run python -m benchmarks.scripts.ingest_skf_labs
uv run python -m benchmarks.scripts.ingest_crossvul
```

Then retry the gate run.

- [ ] **Step 2: Review sample results**

Check the output at `benchmarks/results/<run_id>/gate_report.md`. Key questions:
- Are the TPR numbers in a reasonable range (not all 0% or all 100%)?
- Is the JSON output parsing working (not all "parse error" failures)?
- Are the code extraction paths correct (not all "file not found")?

- [ ] **Step 3: Decide on full run**

If sample results look reasonable:
- Proceed to full run: `uv run python benchmarks/scripts/run_gates.py --mode full`

If sample results show problems:
- Debug specific failures using `--log-level DEBUG`
- Check `benchmarks/results/<run_id>/cases/` for per-case output
- Fix issues and re-run sample

---

## Task 10: Update PROJECT_STATUS.md

After gates have been evaluated (sample or full run), update the project status.

- [ ] **Step 1: Update Phase 1.7 section in PROJECT_STATUS.md**

Update the D-02 status and Phase 1.7 section with actual results:
- Change D-02 status from `DEFERRED` to `COMPLETE` (if gates pass) or `IN PROGRESS` (if iterating)
- Record actual TPR/FPR numbers in the Phase 1.7 section
- Update "Current Phase" header if gates pass

- [ ] **Step 2: Commit**

```bash
git add docs/PROJECT_STATUS.md
git commit -m "docs: update PROJECT_STATUS with G5-G7 gate validation results"
```
