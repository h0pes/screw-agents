"""Unit tests for the sandbox backend dispatcher + (future) executor pipeline.

Task 10 populates this file with the backend-dispatch test. Task 11 will
extend it with executor pipeline tests.
"""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path

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


# -------------------------------------------------------------------------
# T11-N1 — signature-path regression tests
#
# Layer 3 (Ed25519 signature verification) is currently tested only via
# `skip_trust_checks=True` bypass. These tests exercise the REAL signed
# path end-to-end: generate an ephemeral Ed25519 key, sign a script via
# the shared `build_signed_script_meta` helper (so sign-side and
# verify-side never drift), register the public key in
# `.screw/config.yaml`'s `script_reviewers`, then run `execute_script`
# with `skip_trust_checks=False`. Closes the end-to-end gap.
# -------------------------------------------------------------------------


def _build_signed_script_fixture(
    tmp_path: Path,
    *,
    source: str,
    signer_email: str = "marco@example.com",
    script_name: str = "signed_test",
) -> tuple[Path, Path, Path]:
    """Construct a signed script + meta + project_root fixture.

    Generates an ephemeral Ed25519 keypair, writes the public key into
    `.screw/config.yaml`'s `script_reviewers`, and signs the meta via the
    shared `build_signed_script_meta` helper — guaranteeing the fixture,
    the `validate-script` CLI, and the `sign_adaptive_script` MCP tool
    can never drift. Returns ``(script_path, meta_path, project_root)``.
    """
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
    )

    from screw_agents.adaptive.signing import build_signed_script_meta
    from screw_agents.trust import _public_key_to_openssh_line

    project_root = tmp_path / "project"
    project_root.mkdir()
    screw_dir = project_root / ".screw"
    screw_dir.mkdir()

    priv = Ed25519PrivateKey.generate()
    pub_line = _public_key_to_openssh_line(
        priv.public_key(), comment=signer_email
    )

    import yaml as _yaml

    (screw_dir / "config.yaml").write_text(
        _yaml.dump(
            {
                "version": 1,
                "exclusion_reviewers": [],
                "script_reviewers": [
                    {
                        "name": "Tester",
                        "email": signer_email,
                        "key": pub_line,
                    }
                ],
                "adaptive": False,
                "legacy_unsigned_exclusions": "reject",
                "trusted_reviewers_file": None,
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )

    script_dir = tmp_path / "custom-scripts"
    script_dir.mkdir()
    script_path = script_dir / f"{script_name}.py"
    script_path.write_text(source, encoding="utf-8")

    sha256 = hashlib.sha256(source.encode("utf-8")).hexdigest()

    # Route through the shared CLI helper so sign-side canonicalization in
    # this fixture matches byte-for-byte what `validate-script` produces,
    # which in turn matches what the executor canonicalizes on verify. Any
    # future refactor of the signing canonicalization only needs to update
    # one place.
    meta_raw = {
        "name": script_name,
        "created": "2026-04-19T10:00:00Z",
        "created_by": signer_email,
        "domain": "injection-input-handling",
        "description": "T11-N1 signed-path regression fixture",
        "target_patterns": [],
    }
    meta_dict = build_signed_script_meta(
        meta_raw=meta_raw,
        source=source,
        current_sha256=sha256,
        signer_email=signer_email,
        private_key=priv,
    )

    meta_path = script_dir / f"{script_name}.meta.yaml"
    meta_path.write_text(
        _yaml.dump(meta_dict, sort_keys=False), encoding="utf-8"
    )

    return script_path, meta_path, project_root


def test_execute_script_valid_signature_path(tmp_path: Path):
    """T11-N1: a legitimately signed script runs end-to-end under
    `skip_trust_checks=False`. Layer 2 hash pin + Layer 3 signature both
    succeed, the sandbox runs, findings are lifted into Finding objects.

    Linux-only assertion path (macOS sandbox-exec isn't available on
    Marco's Arch dev hardware); skips if no sandbox backend is on PATH.
    """
    import shutil

    if shutil.which("bwrap") is None and shutil.which("sandbox-exec") is None:
        pytest.skip("no sandbox backend available on this platform")

    from screw_agents.adaptive.executor import execute_script
    from screw_agents.models import Finding

    source = (
        "from screw_agents.adaptive import emit_finding\n"
        "def analyze(project):\n"
        "    emit_finding(cwe='CWE-89', file='x.py', line=1,"
        " message='signed-path ok', severity='high')\n"
    )
    script_path, meta_path, project_root = _build_signed_script_fixture(
        tmp_path, source=source, script_name="signed_ok"
    )

    result = execute_script(
        script_path=script_path,
        meta_path=meta_path,
        project_root=project_root,
        skip_trust_checks=False,  # engage Layer 2 + Layer 3
        wall_clock_s=30,
    )

    assert result.stale is False
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert isinstance(finding, Finding)
    assert finding.classification.cwe == "CWE-89"
    assert finding.analysis.description == "signed-path ok"
    assert finding.agent == "adaptive_script:signed_ok"


def test_execute_script_tampered_signature_raises_signature_failure(
    tmp_path: Path,
):
    """T11-N1: flipping a byte in the stored signature breaks Layer 3.
    `execute_script` must raise `SignatureFailure` (NOT silently run,
    NOT raise the generic RuntimeError). Layer 2 hash pin is untouched,
    so it passes, and Layer 3 is the failing gate.
    """
    from screw_agents.adaptive.executor import (
        SignatureFailure,
        execute_script,
    )

    source = (
        "from screw_agents.adaptive import emit_finding\n"
        "def analyze(project):\n"
        "    pass\n"
    )
    script_path, meta_path, project_root = _build_signed_script_fixture(
        tmp_path, source=source, script_name="tampered_sig"
    )

    # Flip one byte in the signature field while keeping the source (and
    # therefore sha256) intact — Layer 2 will pass, Layer 3 will fail.
    import yaml as _yaml

    meta = _yaml.safe_load(meta_path.read_text(encoding="utf-8"))
    sig = meta["signature"]
    assert len(sig) > 0, "fixture should have signed the meta"
    # Swap the first character for a different (still base64-valid) one.
    new_first = "A" if sig[0] != "A" else "B"
    meta["signature"] = new_first + sig[1:]
    meta_path.write_text(_yaml.dump(meta, sort_keys=False), encoding="utf-8")

    # Match the specific Layer 3 failure reason (content/signature mismatch),
    # NOT the generic "signature verification failed" wrapper — tightens the
    # test to verify we hit the right failure branch.
    with pytest.raises(
        SignatureFailure, match="signature invalid or content mismatch"
    ):
        execute_script(
            script_path=script_path,
            meta_path=meta_path,
            project_root=project_root,
            skip_trust_checks=False,
            wall_clock_s=10,
        )


# -------------------------------------------------------------------------
# Task 11 — I3: engine.execute_adaptive_script surfaces sandbox stderr
# -------------------------------------------------------------------------


def test_execute_surfaces_stderr_on_nonzero_return(tmp_path: Path) -> None:
    """A script raising RuntimeError inside analyze() yields sandbox
    returncode != 0. engine.execute_adaptive_script MUST surface stderr
    AND set status='sandbox_failure' so the T18b failure-render path has
    something to show the user. T11 plan-fix #5: use a runtime raise
    rather than a hallucinated import — T10's unknown_symbol rule now
    rejects hallucinated imports at Layer 1 before the sandbox runs."""
    import shutil

    if shutil.which("bwrap") is None and shutil.which("sandbox-exec") is None:
        pytest.skip("requires sandbox backend")

    from screw_agents.engine import ScanEngine

    script_dir = tmp_path / ".screw" / "custom-scripts"
    script_dir.mkdir(parents=True)

    # Valid-linting script that raises at runtime inside analyze(). Uses
    # ProjectRoot (an allowed import) so Layer 1 lint passes; the failure
    # happens in the sandbox.
    script_path = script_dir / "t11-failing.py"
    script_path.write_text(
        "from screw_agents.adaptive import ProjectRoot\n"
        "def analyze(project: ProjectRoot) -> None:\n"
        "    raise RuntimeError('intentional T11 test failure')\n"
    )
    meta_path = script_dir / "t11-failing.meta.yaml"
    meta_path.write_text(
        "name: t11-failing\n"
        "created: '2026-04-22T10:00:00Z'\n"
        "created_by: marco@example.com\n"
        "domain: injection-input-handling\n"
        "description: T11 stderr surfacing test\n"
        "target_patterns: []\n"  # empty -> not stale, sandbox runs
        "sha256: stub\n"
    )

    engine = ScanEngine.from_defaults()
    result = engine.execute_adaptive_script(
        project_root=tmp_path,
        script_name="t11-failing",
        wall_clock_s=15,
        skip_trust_checks=True,
    )

    assert result["status"] == "sandbox_failure"
    assert "RuntimeError" in result["stderr"]
    assert "intentional T11 test failure" in result["stderr"]
    assert result["sandbox_result"]["returncode"] != 0
    # Alias consistency: top-level stderr == inner stderr (plan-fix #4)
    assert result["stderr"] == result["sandbox_result"]["stderr"]


def test_execute_stderr_empty_on_success(tmp_path: Path) -> None:
    """Happy path: status='ok' and stderr is empty string. Well-behaved
    scripts don't write to stderr; don't clutter success payloads. T11
    plan-fix #4: empty string rather than omitted field — keeps the dict
    shape stable so the subagent's failure-render branch can always test
    result["stderr"] without a .get() dance."""
    import shutil

    if shutil.which("bwrap") is None and shutil.which("sandbox-exec") is None:
        pytest.skip("requires sandbox backend")

    from screw_agents.engine import ScanEngine

    script_dir = tmp_path / ".screw" / "custom-scripts"
    script_dir.mkdir(parents=True)

    # Benign passing script — imports only allowed names, emits no findings,
    # never raises. Sandbox returncode must be 0 and stderr empty.
    script_path = script_dir / "t11-ok.py"
    script_path.write_text(
        "from screw_agents.adaptive import ProjectRoot\n"
        "def analyze(project: ProjectRoot) -> None:\n"
        "    pass\n"
    )
    meta_path = script_dir / "t11-ok.meta.yaml"
    meta_path.write_text(
        "name: t11-ok\n"
        "created: '2026-04-22T10:00:00Z'\n"
        "created_by: marco@example.com\n"
        "domain: injection-input-handling\n"
        "description: T11 stderr-empty-on-success test\n"
        "target_patterns: []\n"
        "sha256: stub\n"
    )

    engine = ScanEngine.from_defaults()
    result = engine.execute_adaptive_script(
        project_root=tmp_path,
        script_name="t11-ok",
        wall_clock_s=15,
        skip_trust_checks=True,
    )

    assert result["status"] == "ok"
    assert result["stderr"] == ""
    assert result["sandbox_result"]["returncode"] == 0


# -------------------------------------------------------------------------
# Task 12 — T11-N2 MetadataError wrapper
# -------------------------------------------------------------------------


def test_executor_wraps_yaml_error_as_metadata_error(tmp_path: Path) -> None:
    """Invalid YAML in .meta.yaml -> MetadataError (not bare yaml.YAMLError).
    Plan-fix #1 + #2 + #3: uses correct execute_script signature,
    valid-lint script body (so Layer 1 doesn't short-circuit to
    LintFailure), and skip_trust_checks=True to bypass Layer 2+3."""
    from screw_agents.adaptive.executor import MetadataError, execute_script

    script_dir = tmp_path / ".screw" / "custom-scripts"
    script_dir.mkdir(parents=True)
    script_path = script_dir / "test-yaml-001.py"
    meta_path = script_dir / "test-yaml-001.meta.yaml"

    # Valid-lint body so Layer 1 passes and execution reaches the meta load.
    script_path.write_text(
        "from screw_agents.adaptive import ProjectRoot\n"
        "def analyze(project: ProjectRoot) -> None:\n"
        "    pass\n",
        encoding="utf-8",
    )
    # Malformed YAML — unclosed quote is a guaranteed yaml.YAMLError.
    meta_path.write_text("name: test\ncreated: \"unclosed\n", encoding="utf-8")

    with pytest.raises(MetadataError, match="invalid YAML"):
        execute_script(
            script_path=script_path,
            meta_path=meta_path,
            project_root=tmp_path,
            wall_clock_s=5,
            skip_trust_checks=True,
        )


def test_executor_wraps_validation_error_as_metadata_error(tmp_path: Path) -> None:
    """Malformed meta dict (missing required fields) -> MetadataError.
    Plan-fix #1 + #2 + #3: same shape as the YAMLError test but with a
    parseable YAML that fails Pydantic schema validation."""
    from screw_agents.adaptive.executor import MetadataError, execute_script

    script_dir = tmp_path / ".screw" / "custom-scripts"
    script_dir.mkdir(parents=True)
    script_path = script_dir / "test-yaml-002.py"
    meta_path = script_dir / "test-yaml-002.meta.yaml"

    script_path.write_text(
        "from screw_agents.adaptive import ProjectRoot\n"
        "def analyze(project: ProjectRoot) -> None:\n"
        "    pass\n",
        encoding="utf-8",
    )
    # Parseable YAML, but missing required AdaptiveScriptMeta fields
    # (created_by, domain, description, target_patterns, sha256).
    meta_path.write_text("name: test-yaml-002\n", encoding="utf-8")

    with pytest.raises(MetadataError, match="malformed metadata"):
        execute_script(
            script_path=script_path,
            meta_path=meta_path,
            project_root=tmp_path,
            wall_clock_s=5,
            skip_trust_checks=True,
        )


# --- Task 14 — T11-N1 E2E signature-path regression ---

@pytest.fixture
def signed_script_setup(tmp_path: Path):
    """Yields a (project_root, script_name, source, meta_dict) tuple where
    the script + meta are fully signed and verifiable via Layer 3.

    Used by T11-N1's end-to-end signature-path tests to exercise the real
    sign -> verify round-trip (`skip_trust_checks=False`), not just the
    skip_trust_checks=True shortcuts other tests use.

    Plan-fix #2 + #7: session_id is a real string ("t14-sess");
    target_patterns=[] so _is_stale returns False (`executor.py:246-247`)
    and the sandbox actually runs, exercising the full round-trip rather
    than short-circuiting at the stale sentinel.
    """
    from screw_agents.cli.init_trust import run_init_trust
    from screw_agents.engine import ScanEngine

    project = tmp_path / "project"
    project.mkdir()
    run_init_trust(project_root=project, name="T11N1", email="sig@example.com")
    engine = ScanEngine.from_defaults()

    source = (
        "from screw_agents.adaptive import ProjectRoot\n"
        "\n"
        "def analyze(project: ProjectRoot) -> None:\n"
        "    pass\n"
    )
    meta = {
        "name": "test-sig-e2e",
        "created": "2026-04-20T10:00:00Z",
        "created_by": "sig@example.com",
        "domain": "injection-input-handling",
        "description": "T11-N1 fixture",
        "target_patterns": [],  # plan-fix #7: full round-trip, not stale sentinel
    }

    r = engine.sign_adaptive_script(
        project_root=project,
        script_name="test-sig-e2e",
        source=source,
        meta=meta,
        session_id="t14-sess",  # plan-fix #2: required string
    )
    assert r["status"] == "signed"

    yield (project, "test-sig-e2e", source, meta)


def test_execute_adaptive_script_verifies_layer3_signature_happy_path(
    signed_script_setup,
) -> None:
    """Full sign -> verify round-trip with skip_trust_checks=False.

    T11-N1: end-to-end Layer 3 coverage that was not exercised before.
    Uses engine.execute_adaptive_script (the MCP-boundary entry point)
    per plan-fix #1 — not the internal execute_script which takes
    script_path/meta_path, not script_name.
    """
    from screw_agents.engine import ScanEngine

    project, script_name, _, _ = signed_script_setup

    engine = ScanEngine.from_defaults()
    result = engine.execute_adaptive_script(
        project_root=project,
        script_name=script_name,
        wall_clock_s=5,
        skip_trust_checks=False,
    )

    # Plan-fix #3: simplified assertion. Post-T11 (I3), engine returns
    # status="ok" on returncode==0, "sandbox_failure" otherwise.
    assert result["status"] == "ok"


def test_execute_adaptive_script_rejects_tampered_source(
    signed_script_setup,
) -> None:
    """Tamper the .py source after signing. Layer 2 hash pin MUST fail.

    Plan-fix #4 + #8 + #9 (Option C): Layer 1 (lint) and Layer 2 (hash
    pin) BOTH run before Layer 3 (signature) in executor.execute_script.
    A source-byte tamper is caught by Layer 2 via HashMismatch — Layer 3
    never runs. This test locks the Layer-2 rejection path specifically.
    The companion test_execute_adaptive_script_rejects_tampered_signature
    exercises Layer 3 by flipping the signature field instead.

    Tampered content stays lint-valid (preserves import + def analyze)
    to prove the rejection comes from Layer 2's SHA-256 check, NOT Layer
    1's lint. If this test ever starts raising LintFailure, the tamper
    somehow broke the lint — investigate before assuming the hash check
    is broken.
    """
    from screw_agents.adaptive.executor import HashMismatch
    from screw_agents.engine import ScanEngine

    project, script_name, _, _ = signed_script_setup
    py_path = project / ".screw" / "custom-scripts" / f"{script_name}.py"

    # Tamper while preserving lint-validity — add a comment line BEFORE
    # the analyze def so Layer 1 sees valid structure but the SHA-256
    # changes (and so Layer 2 hash pin fails).
    py_path.write_text(
        "from screw_agents.adaptive import ProjectRoot\n"
        "\n"
        "# TAMPERED — this line changes the sha256\n"
        "def analyze(project: ProjectRoot) -> None:\n"
        "    pass\n",
        encoding="utf-8",
    )

    engine = ScanEngine.from_defaults()
    with pytest.raises(HashMismatch):
        engine.execute_adaptive_script(
            project_root=project,
            script_name=script_name,
            wall_clock_s=5,
            skip_trust_checks=False,
        )


def test_execute_adaptive_script_rejects_tampered_signature(
    signed_script_setup,
) -> None:
    """Tamper .meta.yaml's signature field after signing. Layer 3 MUST fail.

    Plan-fix #9 (Option C): Layer 2 hash pin passes because we leave the
    .py source untouched (and its sha256 stays in meta.sha256). But we
    flip a byte in the base64 signature field, so Ed25519 verification
    at Layer 3 fails with SignatureFailure. This is the T11-N1 flagship
    test that locks Layer 3 coverage — the rationale for bundling T11-N1
    in PR #6 in the first place.

    If meta_path's signature field shape ever changes (e.g., moved under
    a nested key, renamed), this test will break — find the new path
    and update. The invariant being tested is: ANY byte-change in the
    on-disk signature post-sign must be rejected at Layer 3.
    """
    import base64

    import yaml

    from screw_agents.adaptive.executor import SignatureFailure
    from screw_agents.engine import ScanEngine

    project, script_name, _, _ = signed_script_setup
    meta_path = project / ".screw" / "custom-scripts" / f"{script_name}.meta.yaml"

    meta_dict = yaml.safe_load(meta_path.read_text(encoding="utf-8"))
    assert "signature" in meta_dict, (
        f"meta at {meta_path} is missing 'signature' field — "
        f"shape changed? keys present: {sorted(meta_dict.keys())}"
    )

    # Decode, flip one byte in the middle (avoid padding), re-encode.
    sig_bytes = bytearray(base64.b64decode(meta_dict["signature"]))
    assert len(sig_bytes) >= 16, f"Ed25519 signature too short: {len(sig_bytes)} bytes"
    # Flip a byte at a safe offset — Ed25519 signatures are 64 bytes;
    # offset 10 is well clear of padding and structural bits.
    sig_bytes[10] ^= 0xFF
    meta_dict["signature"] = base64.b64encode(bytes(sig_bytes)).decode("ascii")
    meta_path.write_text(yaml.safe_dump(meta_dict), encoding="utf-8")

    engine = ScanEngine.from_defaults()
    with pytest.raises(SignatureFailure):
        engine.execute_adaptive_script(
            project_root=project,
            script_name=script_name,
            wall_clock_s=5,
            skip_trust_checks=False,
        )
