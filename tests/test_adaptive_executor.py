"""Unit tests for the sandbox backend dispatcher + (future) executor pipeline.

Task 10 populates this file with the backend-dispatch test. Task 11 will
extend it with executor pipeline tests.
"""

from __future__ import annotations

import sys

import pytest


def test_backend_dispatch_returns_correct_module():
    """`get_backend()` returns the linux module on Linux, macos on Darwin,
    raises UnsupportedPlatformError elsewhere."""
    from screw_agents.adaptive.sandbox import get_backend, UnsupportedPlatformError

    if sys.platform == "linux":
        backend = get_backend()
        assert backend.__name__.endswith("linux")
    elif sys.platform == "darwin":
        backend = get_backend()
        assert backend.__name__.endswith("macos")
    else:
        with pytest.raises(UnsupportedPlatformError):
            get_backend()


def test_run_in_sandbox_dispatches_to_backend(tmp_path):
    """`run_in_sandbox(**kwargs)` delegates to the platform backend. On Linux
    this exercises the bwrap backend end-to-end with a minimal valid script."""
    if sys.platform not in ("linux", "darwin"):
        pytest.skip("Adaptive sandbox not supported on this platform")

    from screw_agents.adaptive.sandbox import run_in_sandbox
    from screw_agents.models import SandboxResult

    script_path = tmp_path / "probe.py"
    script_path.write_text("def analyze(project):\n    pass\nanalyze(None)\n")
    findings_path = tmp_path / "findings"
    findings_path.mkdir()
    project_path = tmp_path / "project"
    project_path.mkdir()

    # Skip if platform tool is missing (Linux without bwrap, macOS without sandbox-exec)
    import shutil
    tool = "bwrap" if sys.platform == "linux" else "sandbox-exec"
    if shutil.which(tool) is None:
        pytest.skip(f"{tool} not installed")

    result = run_in_sandbox(
        script_path=script_path,
        project_root=project_path,
        findings_path=findings_path,
        wall_clock_s=10,
    )
    assert isinstance(result, SandboxResult)
    assert result.returncode == 0


def test_get_backend_raises_on_unsupported_platform(monkeypatch):
    """If sys.platform is not linux or darwin, get_backend raises
    UnsupportedPlatformError with a clear message."""
    from screw_agents.adaptive.sandbox import get_backend, UnsupportedPlatformError

    monkeypatch.setattr(sys, "platform", "win32")
    with pytest.raises(UnsupportedPlatformError, match="not supported"):
        get_backend()


# -------------------------------------------------------------------------
# Task 11 — executor pipeline tests
# -------------------------------------------------------------------------


from pathlib import Path


def test_executor_runs_valid_script_end_to_end(tmp_path: Path):
    """Happy path: valid script -> lint passes -> (trust checks skipped) ->
    not stale (empty target_patterns) -> wrapped + sandboxed -> findings lifted
    into proper Finding objects."""
    import shutil
    if shutil.which("bwrap") is None and shutil.which("sandbox-exec") is None:
        pytest.skip("no sandbox backend available on this platform")

    from screw_agents.adaptive.executor import execute_script
    from screw_agents.models import Finding

    script_source = (
        "from screw_agents.adaptive import emit_finding\n"
        "def analyze(project):\n"
        "    emit_finding(cwe='CWE-89', file='x.py', line=1, message='test', severity='high')\n"
    )
    script_path = tmp_path / "custom-scripts" / "test.py"
    script_path.parent.mkdir(parents=True)
    script_path.write_text(script_source)

    meta_path = tmp_path / "custom-scripts" / "test.meta.yaml"
    meta_path.write_text(
        "name: test\n"
        "created: '2026-04-14T10:00:00Z'\n"
        "created_by: marco@example.com\n"
        "domain: injection-input-handling\n"
        "description: test\n"
        "target_patterns: []\n"  # empty -> not stale
        "sha256: stub\n"
    )

    project_root = tmp_path / "project"
    project_root.mkdir()

    result = execute_script(
        script_path=script_path,
        meta_path=meta_path,
        project_root=project_root,
        skip_trust_checks=True,
        wall_clock_s=30,
    )

    assert result.stale is False
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert isinstance(finding, Finding)
    assert finding.classification.cwe == "CWE-89"
    assert finding.classification.severity == "high"
    assert finding.location.file == "x.py"
    assert finding.location.line_start == 1
    assert finding.analysis.description == "test"
    assert finding.agent == "adaptive_script:test"
    assert finding.domain == "injection-input-handling"


def test_executor_rejects_script_that_fails_lint(tmp_path: Path):
    """Layer 1 lint rejects a script with a forbidden import. LintFailure
    is raised BEFORE any sandbox work."""
    from screw_agents.adaptive.executor import execute_script, LintFailure

    script_path = tmp_path / "custom-scripts" / "bad.py"
    script_path.parent.mkdir(parents=True)
    script_path.write_text("import os\ndef analyze(project): pass\n")
    meta_path = tmp_path / "custom-scripts" / "bad.meta.yaml"
    meta_path.write_text(
        "name: bad\ncreated: '2026-04-14T10:00:00Z'\ncreated_by: m@e\n"
        "domain: injection-input-handling\ndescription: bad\n"
        "target_patterns: []\nsha256: stub\n"
    )
    project_path = tmp_path / "project"
    project_path.mkdir()

    with pytest.raises(LintFailure):
        execute_script(
            script_path=script_path,
            meta_path=meta_path,
            project_root=project_path,
            skip_trust_checks=True,
        )


def test_executor_marks_script_stale_when_pattern_missing(tmp_path: Path):
    """Stale check: target_patterns specified but NONE match anything in the
    project. Executor returns early with stale=True and no sandbox work."""
    from screw_agents.adaptive.executor import execute_script

    script_source = (
        "from screw_agents.adaptive import emit_finding\n"
        "def analyze(project):\n"
        "    pass\n"
    )
    script_path = tmp_path / "custom-scripts" / "stale.py"
    script_path.parent.mkdir(parents=True)
    script_path.write_text(script_source)
    meta_path = tmp_path / "custom-scripts" / "stale.meta.yaml"
    meta_path.write_text(
        "name: stale\ncreated: '2026-04-14T10:00:00Z'\ncreated_by: m@e\n"
        "domain: injection-input-handling\ndescription: stale\n"
        "target_patterns:\n"
        "  - NonExistent.method_that_is_not_in_project\n"
        "sha256: stub\n"
    )

    # Empty project -> no matches for the target_pattern -> stale
    project_root = tmp_path / "project"
    project_root.mkdir()

    result = execute_script(
        script_path=script_path,
        meta_path=meta_path,
        project_root=project_root,
        skip_trust_checks=True,
    )

    assert result.stale is True
    assert result.findings == []
    # Sentinel SandboxResult — no actual execution happened
    assert result.sandbox_result.returncode == 0
    assert result.sandbox_result.wall_clock_s == 0.0
    assert result.sandbox_result.findings_json is None


def test_executor_hash_mismatch_raises(tmp_path: Path):
    """Layer 2 hash pin: computed SHA-256 must match meta.sha256 when
    skip_trust_checks=False. Mismatch raises HashMismatch before sandbox."""
    from screw_agents.adaptive.executor import execute_script, HashMismatch

    script_path = tmp_path / "custom-scripts" / "test.py"
    script_path.parent.mkdir(parents=True)
    script_path.write_text(
        "from screw_agents.adaptive import emit_finding\n"
        "def analyze(project):\n"
        "    pass\n"
    )
    meta_path = tmp_path / "custom-scripts" / "test.meta.yaml"
    meta_path.write_text(
        "name: test\ncreated: '2026-04-14T10:00:00Z'\ncreated_by: m@e\n"
        "domain: injection-input-handling\ndescription: test\n"
        "target_patterns: []\n"
        "sha256: '0000000000000000000000000000000000000000000000000000000000000000'\n"  # wrong
    )
    project_root = tmp_path / "project"
    project_root.mkdir()

    with pytest.raises(HashMismatch, match="hash mismatch"):
        execute_script(
            script_path=script_path,
            meta_path=meta_path,
            project_root=project_root,
            skip_trust_checks=False,  # engage hash check
            wall_clock_s=10,
        )
