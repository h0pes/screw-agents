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


def test_executor_uses_opaque_script_path_in_sandbox(tmp_path: Path, monkeypatch):
    """M2 regression: the script_path passed to run_in_sandbox must be an
    opaque tempfile.mkdtemp path (prefix=screw_), NOT the user's
    custom-scripts/<name>.py host path. Closes the T8-deferred
    /proc/1/cmdline path-leak vector — the sandbox's bwrap argv would
    otherwise embed the user's worktree + custom-script name.
    """
    from screw_agents.adaptive import executor as executor_module
    from screw_agents.models import SandboxResult

    captured_kwargs = {}

    def fake_run_in_sandbox(**kwargs):
        captured_kwargs.update(kwargs)
        return SandboxResult(
            stdout=b"", stderr=b"", returncode=0, wall_clock_s=0.01,
            killed_by_timeout=False, findings_json="[]",
        )

    monkeypatch.setattr(executor_module, "run_in_sandbox", fake_run_in_sandbox)

    script_path = tmp_path / "custom-scripts" / "secret-script-name.py"
    script_path.parent.mkdir(parents=True)
    script_path.write_text(
        "from screw_agents.adaptive import emit_finding\n"
        "def analyze(project): pass\n"
    )
    meta_path = tmp_path / "custom-scripts" / "secret-script-name.meta.yaml"
    meta_path.write_text(
        "name: secret-script-name\ncreated: '2026-04-14T10:00:00Z'\n"
        "created_by: m@e\ndomain: injection-input-handling\n"
        "description: test\ntarget_patterns: []\nsha256: stub\n"
    )
    project_root = tmp_path / "project"
    project_root.mkdir()

    executor_module.execute_script(
        script_path=script_path,
        meta_path=meta_path,
        project_root=project_root,
        skip_trust_checks=True,
    )

    # script_path passed to run_in_sandbox must be an opaque mkdtemp path,
    # NOT the user's original custom-scripts path
    sandbox_script = captured_kwargs.get("script_path")
    assert sandbox_script is not None
    sandbox_script_str = str(sandbox_script)
    assert "screw_" in sandbox_script_str, (
        f"script_path {sandbox_script_str} does not use opaque prefix"
    )
    assert "secret-script-name" not in sandbox_script_str, (
        f"script_path {sandbox_script_str} leaks the user's script name"
    )
    assert "custom-scripts" not in sandbox_script_str, (
        f"script_path {sandbox_script_str} leaks the custom-scripts directory name"
    )


def test_executor_normalizes_info_severity_to_low(tmp_path: Path, monkeypatch):
    """M1 regression: emit_finding accepts {high,medium,low,info}; Finding expects
    {critical,high,medium,low}. The executor must map `info` → `low` per the
    contract documented in findings.py's module docstring."""
    from screw_agents.adaptive import executor as executor_module
    from screw_agents.models import SandboxResult
    import json

    findings_payload = [
        {"cwe": "CWE-200", "file": "a.py", "line": 10,
         "message": "info finding", "severity": "info", "code_snippet": "", "column": 0}
    ]

    def fake_run_in_sandbox(**kwargs):
        return SandboxResult(
            stdout=b"", stderr=b"", returncode=0, wall_clock_s=0.01,
            killed_by_timeout=False,
            findings_json=json.dumps(findings_payload),
        )

    monkeypatch.setattr(executor_module, "run_in_sandbox", fake_run_in_sandbox)

    script_path = tmp_path / "s.py"
    script_path.write_text("from screw_agents.adaptive import emit_finding\ndef analyze(project): pass\n")
    meta_path = tmp_path / "s.meta.yaml"
    meta_path.write_text(
        "name: s\ncreated: '2026-04-14T10:00:00Z'\ncreated_by: m@e\n"
        "domain: injection-input-handling\ndescription: t\ntarget_patterns: []\nsha256: stub\n"
    )
    project_root = tmp_path / "project"
    project_root.mkdir()

    result = executor_module.execute_script(
        script_path=script_path, meta_path=meta_path,
        project_root=project_root, skip_trust_checks=True,
    )

    assert len(result.findings) == 1
    # info → low per the contract
    assert result.findings[0].classification.severity == "low"


def test_executor_lifts_multiple_findings_with_stable_ids(tmp_path: Path, monkeypatch):
    """N4: emit_finding can fire multiple times; each finding must become a
    distinct Finding object with a stable content-hash ID. Different columns
    on the same line must produce distinct IDs (N5 regression)."""
    from screw_agents.adaptive import executor as executor_module
    from screw_agents.models import SandboxResult
    import json

    # Three findings: two on same (file, line, cwe, message) but different columns;
    # one entirely distinct. IDs must all differ.
    findings_payload = [
        {"cwe": "CWE-89", "file": "a.py", "line": 10, "column": 5,
         "message": "sqli via .execute()", "severity": "high", "code_snippet": ""},
        {"cwe": "CWE-89", "file": "a.py", "line": 10, "column": 42,
         "message": "sqli via .execute()", "severity": "high", "code_snippet": ""},
        {"cwe": "CWE-78", "file": "b.py", "line": 20, "column": 0,
         "message": "cmd injection", "severity": "medium", "code_snippet": ""},
    ]

    def fake_run_in_sandbox(**kwargs):
        return SandboxResult(
            stdout=b"", stderr=b"", returncode=0, wall_clock_s=0.01,
            killed_by_timeout=False,
            findings_json=json.dumps(findings_payload),
        )

    monkeypatch.setattr(executor_module, "run_in_sandbox", fake_run_in_sandbox)

    script_path = tmp_path / "s.py"
    script_path.write_text("from screw_agents.adaptive import emit_finding\ndef analyze(project): pass\n")
    meta_path = tmp_path / "s.meta.yaml"
    meta_path.write_text(
        "name: multi\ncreated: '2026-04-14T10:00:00Z'\ncreated_by: m@e\n"
        "domain: injection-input-handling\ndescription: t\ntarget_patterns: []\nsha256: stub\n"
    )
    project_root = tmp_path / "project"
    project_root.mkdir()

    result = executor_module.execute_script(
        script_path=script_path, meta_path=meta_path,
        project_root=project_root, skip_trust_checks=True,
    )

    assert len(result.findings) == 3
    ids = {f.id for f in result.findings}
    assert len(ids) == 3, f"expected 3 distinct IDs; got {len(ids)}: {ids}"


def test_executor_handles_malformed_findings_json_gracefully(tmp_path: Path, monkeypatch):
    """N2: the executor must drop malformed entries (missing keys, wrong types,
    invalid JSON) without crashing. Covers the three except branches in
    _parse_findings."""
    from screw_agents.adaptive import executor as executor_module
    from screw_agents.models import SandboxResult
    import json

    # Mix of valid + malformed entries. Valid entries should survive; malformed
    # should be dropped silently.
    valid = {"cwe": "CWE-89", "file": "a.py", "line": 1,
             "message": "valid", "severity": "high", "code_snippet": "", "column": 0}
    malformed_missing_cwe = {"file": "b.py", "line": 2, "message": "m", "severity": "high"}
    malformed_wrong_type = {"cwe": "CWE-89", "file": "c.py", "line": "not-an-int",
                            "message": "m", "severity": "high"}
    non_dict = "a string instead of a dict"

    payload_cases = [
        ("mix", [valid, malformed_missing_cwe, malformed_wrong_type, non_dict], 1),
        ("invalid-json", "not json at all", 0),
        ("non-list-top", {"foo": "bar"}, 0),
        ("null", None, 0),
    ]

    for case_name, payload, expected_count in payload_cases:
        if isinstance(payload, str):
            findings_json = payload  # raw string (invalid JSON)
        elif payload is None:
            findings_json = None
        else:
            findings_json = json.dumps(payload)

        def make_fake(fj):
            def fake_run_in_sandbox(**kwargs):
                return SandboxResult(
                    stdout=b"", stderr=b"", returncode=0, wall_clock_s=0.01,
                    killed_by_timeout=False, findings_json=fj,
                )
            return fake_run_in_sandbox

        monkeypatch.setattr(executor_module, "run_in_sandbox", make_fake(findings_json))

        script_path = tmp_path / f"s_{case_name}.py"
        script_path.write_text("from screw_agents.adaptive import emit_finding\ndef analyze(project): pass\n")
        meta_path = tmp_path / f"s_{case_name}.meta.yaml"
        meta_path.write_text(
            f"name: s_{case_name}\ncreated: '2026-04-14T10:00:00Z'\ncreated_by: m@e\n"
            "domain: injection-input-handling\ndescription: t\ntarget_patterns: []\nsha256: stub\n"
        )
        project_root = tmp_path / f"project_{case_name}"
        project_root.mkdir()

        result = executor_module.execute_script(
            script_path=script_path, meta_path=meta_path,
            project_root=project_root, skip_trust_checks=True,
        )

        assert len(result.findings) == expected_count, (
            f"case {case_name!r}: expected {expected_count} findings, got {len(result.findings)}"
        )


def test_executor_returns_empty_findings_on_sandbox_timeout(tmp_path: Path, monkeypatch):
    """N3: sandbox timeout (wall-clock kill) returns killed_by_timeout=True +
    findings_json=None. Executor must return an AdaptiveScriptResult with
    empty findings list, not raise."""
    from screw_agents.adaptive import executor as executor_module
    from screw_agents.models import SandboxResult

    def fake_run_in_sandbox(**kwargs):
        return SandboxResult(
            stdout=b"", stderr=b"partial",
            returncode=-1, wall_clock_s=3.0,
            killed_by_timeout=True, findings_json=None,
        )

    monkeypatch.setattr(executor_module, "run_in_sandbox", fake_run_in_sandbox)

    script_path = tmp_path / "s.py"
    script_path.write_text("from screw_agents.adaptive import emit_finding\ndef analyze(project): pass\n")
    meta_path = tmp_path / "s.meta.yaml"
    meta_path.write_text(
        "name: timeout-test\ncreated: '2026-04-14T10:00:00Z'\ncreated_by: m@e\n"
        "domain: injection-input-handling\ndescription: t\ntarget_patterns: []\nsha256: stub\n"
    )
    project_root = tmp_path / "project"
    project_root.mkdir()

    result = executor_module.execute_script(
        script_path=script_path, meta_path=meta_path,
        project_root=project_root, skip_trust_checks=True,
    )

    assert result.stale is False
    assert result.findings == []
    assert result.sandbox_result.killed_by_timeout is True
    assert result.sandbox_result.returncode == -1
