"""Unit tests for adaptive/staging.py — filesystem + registry ops.

Scope: staging path resolution, file writes, registry append/query, fallback
walk, stale sweep. Signing is NOT tested here — that's test_adaptive_signing.py.
The full stage→promote→execute integration is test_adaptive_workflow_staged.py.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest


def test_resolve_staging_dir_creates_session_scoped_path(tmp_path: Path) -> None:
    from screw_agents.adaptive.staging import resolve_staging_dir

    project = tmp_path / "project"
    project.mkdir()
    session_id = "sess-abc123"

    staging_dir = resolve_staging_dir(project, session_id)

    assert staging_dir == project / ".screw" / "staging" / session_id / "adaptive-scripts"
    # Function resolves path but does NOT create (caller decides when to mkdir).
    assert not staging_dir.exists()


def test_resolve_staging_dir_rejects_empty_session_id(tmp_path: Path) -> None:
    from screw_agents.adaptive.staging import resolve_staging_dir

    project = tmp_path / "project"
    project.mkdir()

    with pytest.raises(ValueError, match="session_id"):
        resolve_staging_dir(project, "")


def test_resolve_staging_dir_rejects_dot_session_ids(tmp_path: Path) -> None:
    from screw_agents.adaptive.staging import resolve_staging_dir

    project = tmp_path / "project"
    project.mkdir()

    for bad in (".", ".."):
        with pytest.raises(ValueError, match="does not match"):
            resolve_staging_dir(project, bad)


def test_resolve_staging_dir_rejects_path_traversal_chars(tmp_path: Path) -> None:
    from screw_agents.adaptive.staging import resolve_staging_dir

    project = tmp_path / "project"
    project.mkdir()

    for bad in ("a/b", "a\\b", "a\x00b"):
        with pytest.raises(ValueError, match="does not match"):
            resolve_staging_dir(project, bad)


def test_resolve_staging_dir_rejects_dots_within_session_id(tmp_path: Path) -> None:
    """I-opus-1/2 regression: dots in session_id (except the previously-
    rejected bare `"."` / `".."`) are now also rejected by the tightened
    allowlist. `"a..b"` was accepted pre-Opus as a regression guard against
    substring over-matching of `".."`; that guard is obsolete under an
    allowlist-not-denylist validator.
    """
    from screw_agents.adaptive.staging import resolve_staging_dir

    project = tmp_path / "project"
    project.mkdir()

    for bad in ("a..b", ".hidden", "trailing.", "has.dots"):
        with pytest.raises(ValueError, match="does not match"):
            resolve_staging_dir(project, bad)


def test_resolve_staging_dir_rejects_newline_and_cr_in_session_id(tmp_path: Path) -> None:
    """I-opus-1 regression: newlines in session_id are a JSONL-injection
    primitive. Under the tightened regex, they are rejected."""
    from screw_agents.adaptive.staging import resolve_staging_dir

    project = tmp_path / "project"
    project.mkdir()

    for bad in ("foo\nbar", "foo\rbar", "foo\r\nbar", "trailing\n", "\nleading"):
        with pytest.raises(ValueError, match="does not match"):
            resolve_staging_dir(project, bad)


def test_resolve_staging_dir_rejects_whitespace_and_colon_in_session_id(tmp_path: Path) -> None:
    """I-opus-1 regression: whitespace, tab, colon (NTFS ADS primitive),
    and other control characters are rejected."""
    from screw_agents.adaptive.staging import resolve_staging_dir

    project = tmp_path / "project"
    project.mkdir()

    for bad in ("foo bar", "foo\tbar", "foo:bar", "foo ", " foo", "foo;bar"):
        with pytest.raises(ValueError, match="does not match"):
            resolve_staging_dir(project, bad)


def test_resolve_staging_dir_rejects_high_bit_bytes_in_session_id(tmp_path: Path) -> None:
    """I-opus-1 regression: high-bit bytes (unicode homoglyphs, terminal
    control) are rejected."""
    from screw_agents.adaptive.staging import resolve_staging_dir

    project = tmp_path / "project"
    project.mkdir()

    for bad in ("\xff", "foo\xffbar", "café", "foo​bar"):  # includes zero-width space
        with pytest.raises(ValueError, match="does not match"):
            resolve_staging_dir(project, bad)


def test_resolve_staging_dir_rejects_over_length_session_id(tmp_path: Path) -> None:
    """I-opus-1 regression: session_id >64 chars is rejected (bounds check
    was absent pre-Opus; added for defense-in-depth)."""
    from screw_agents.adaptive.staging import resolve_staging_dir

    project = tmp_path / "project"
    project.mkdir()

    with pytest.raises(ValueError, match="does not match"):
        resolve_staging_dir(project, "a" * 65)


def test_resolve_staging_dir_accepts_valid_session_id_edge_cases(tmp_path: Path) -> None:
    """Regression coverage for valid session_ids: boundary lengths + all
    allowed character classes."""
    from screw_agents.adaptive.staging import resolve_staging_dir

    project = tmp_path / "project"
    project.mkdir()

    for good in (
        "a",                       # min length
        "a" * 64,                  # max length
        "sess-abc",                # dash
        "sess_abc",                # underscore
        "SESS-ABC-123",            # uppercase + dash + digit
        "0123456789",              # digits only
        "mixed-Case_123",          # combined
    ):
        # Should not raise.
        result = resolve_staging_dir(project, good)
        assert good in str(result)


def test_resolve_registry_path(tmp_path: Path) -> None:
    from screw_agents.adaptive.staging import resolve_registry_path

    project = tmp_path / "project"
    project.mkdir()

    registry = resolve_registry_path(project)

    assert registry == project / ".screw" / "local" / "pending-approvals.jsonl"


def test_write_staged_files_atomic_writes_both_files(tmp_path: Path) -> None:
    from screw_agents.adaptive.staging import write_staged_files

    project = tmp_path / "project"
    project.mkdir()
    source = "from screw_agents.adaptive import emit_finding\n\ndef analyze(project):\n    pass\n"
    meta_yaml = "name: test-script\ntarget_patterns: [foo]\n"

    paths = write_staged_files(
        project_root=project,
        script_name="test-script",
        source=source,
        meta_yaml=meta_yaml,
        session_id="sess-abc",
    )

    assert paths.py_path.exists()
    assert paths.meta_path.exists()
    assert paths.py_path.read_text(encoding="utf-8") == source
    assert paths.meta_path.read_text(encoding="utf-8") == meta_yaml


def test_write_staged_files_rolls_back_py_on_meta_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from screw_agents.adaptive import staging

    project = tmp_path / "project"
    project.mkdir()

    # Force the meta write to fail on os.replace (after tmp write succeeded).
    original_replace = os.replace
    call_count = {"n": 0}

    def flaky_replace(src, dst):
        call_count["n"] += 1
        # First call is .py replace (success), second is .meta.yaml (fail).
        if call_count["n"] == 2:
            raise PermissionError("simulated meta-write failure")
        return original_replace(src, dst)

    monkeypatch.setattr(os, "replace", flaky_replace)

    with pytest.raises(ValueError, match="PermissionError"):
        staging.write_staged_files(
            project_root=project,
            script_name="test-script",
            source="print('hi')\n",
            meta_yaml="name: test\n",
            session_id="sess-abc",
        )

    # Rollback: .py should have been unlinked.
    stage_dir = staging.resolve_staging_dir(project, "sess-abc")
    assert not (stage_dir / "test-script.py").exists()


def test_read_staged_files_returns_str_roundtrip(tmp_path: Path) -> None:
    from screw_agents.adaptive.staging import read_staged_files, write_staged_files

    project = tmp_path / "project"
    project.mkdir()
    source = "print('hello')\n"
    meta_yaml = "name: test\n"
    write_staged_files(
        project_root=project,
        script_name="test-script",
        source=source,
        meta_yaml=meta_yaml,
        session_id="sess-abc",
    )

    read_source, read_meta = read_staged_files(
        project_root=project,
        script_name="test-script",
        session_id="sess-abc",
    )

    assert read_source == source
    assert read_meta == meta_yaml


def test_read_staged_files_raises_on_missing(tmp_path: Path) -> None:
    from screw_agents.adaptive.staging import read_staged_files

    project = tmp_path / "project"
    project.mkdir()

    with pytest.raises(FileNotFoundError):
        read_staged_files(
            project_root=project,
            script_name="nope",
            session_id="sess-abc",
        )


def test_delete_staged_files_removes_both(tmp_path: Path) -> None:
    from screw_agents.adaptive.staging import (
        delete_staged_files,
        resolve_staging_dir,
        write_staged_files,
    )

    project = tmp_path / "project"
    project.mkdir()
    write_staged_files(
        project_root=project,
        script_name="test-script",
        source="x\n",
        meta_yaml="y\n",
        session_id="sess-abc",
    )

    delete_staged_files(
        project_root=project,
        script_name="test-script",
        session_id="sess-abc",
    )

    stage_dir = resolve_staging_dir(project, "sess-abc")
    assert not (stage_dir / "test-script.py").exists()
    assert not (stage_dir / "test-script.meta.yaml").exists()


def test_write_staged_files_rollback_unlink_failure_does_not_mask_value_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """C-2 regression: if rollback unlink raises PermissionError, the
    user still sees the informative ValueError about the meta failure."""
    from screw_agents.adaptive import staging

    project = tmp_path / "project"
    project.mkdir()

    # Make the second os.replace (meta) fail.
    original_replace = os.replace
    call_count = {"n": 0}

    def flaky_replace(src, dst):
        call_count["n"] += 1
        if call_count["n"] == 2:
            raise PermissionError("simulated meta-write failure")
        return original_replace(src, dst)

    monkeypatch.setattr(os, "replace", flaky_replace)

    # Make the rollback unlink on py_path ALSO fail.
    from pathlib import Path as _Path
    original_unlink = _Path.unlink

    def flaky_unlink(self, missing_ok=False):
        if self.name == "test-script.py":
            raise PermissionError("simulated rollback-unlink failure")
        return original_unlink(self, missing_ok=missing_ok)

    monkeypatch.setattr(_Path, "unlink", flaky_unlink)

    with pytest.raises(ValueError, match="failed to write staged meta"):
        staging.write_staged_files(
            project_root=project,
            script_name="test-script",
            source="print('hi')\n",
            meta_yaml="name: test\n",
            session_id="sess-abc",
        )


def test_delete_staged_files_idempotent_on_missing(tmp_path: Path) -> None:
    from screw_agents.adaptive.staging import delete_staged_files

    project = tmp_path / "project"
    project.mkdir()
    # Should not raise.
    delete_staged_files(
        project_root=project,
        script_name="nope",
        session_id="sess-abc",
    )


def test_write_staged_files_rejects_path_traversal_script_name(tmp_path: Path) -> None:
    from screw_agents.adaptive.staging import write_staged_files

    project = tmp_path / "project"
    project.mkdir()

    with pytest.raises(ValueError, match="script_name"):
        write_staged_files(
            project_root=project,
            script_name="../../../etc/shadow",
            source="pass\n",
            meta_yaml="name: x\n",
            session_id="sess-abc",
        )


def test_write_staged_files_rejects_uppercase_script_name(tmp_path: Path) -> None:
    from screw_agents.adaptive.staging import write_staged_files

    project = tmp_path / "project"
    project.mkdir()

    with pytest.raises(ValueError, match="script_name"):
        write_staged_files(
            project_root=project,
            script_name="Foo-Bar",
            source="pass\n",
            meta_yaml="name: x\n",
            session_id="sess-abc",
        )


def test_write_staged_files_rejects_too_short_script_name(tmp_path: Path) -> None:
    from screw_agents.adaptive.staging import write_staged_files

    project = tmp_path / "project"
    project.mkdir()

    with pytest.raises(ValueError, match="script_name"):
        write_staged_files(
            project_root=project,
            script_name="ab",  # only 2 chars, regex requires >= 3
            source="pass\n",
            meta_yaml="name: x\n",
            session_id="sess-abc",
        )


def test_read_staged_files_rejects_invalid_script_name(tmp_path: Path) -> None:
    from screw_agents.adaptive.staging import read_staged_files

    project = tmp_path / "project"
    project.mkdir()

    with pytest.raises(ValueError, match="script_name"):
        read_staged_files(
            project_root=project,
            script_name="../secrets",
            session_id="sess-abc",
        )


def test_delete_staged_files_rejects_invalid_script_name(tmp_path: Path) -> None:
    from screw_agents.adaptive.staging import delete_staged_files

    project = tmp_path / "project"
    project.mkdir()

    with pytest.raises(ValueError, match="script_name"):
        delete_staged_files(
            project_root=project,
            script_name="../secrets",
            session_id="sess-abc",
        )


def test_write_staged_files_accepts_valid_script_name_edge_cases(tmp_path: Path) -> None:
    """Regression: exactly 3 chars + exactly 63 chars + all-digits + with dashes."""
    from screw_agents.adaptive.staging import write_staged_files

    project = tmp_path / "project"
    project.mkdir()
    common = dict(source="pass\n", meta_yaml="name: x\n", session_id="sess-abc")

    for name in ("abc", "0" * 63, "test-script-001", "9abc"):
        paths = write_staged_files(
            project_root=project,
            script_name=name,
            **common,
        )
        assert paths.py_path.exists()


def test_staging_imports_from_shared_script_name_module() -> None:
    """Locking: after T2, staging.py must NOT have a local _SCRIPT_NAME_RE.

    The regex lives in adaptive.script_name; staging.py imports the
    validator from there. If this test breaks, the T2 consolidation
    regressed.
    """
    import screw_agents.adaptive.staging as staging_module

    # Local constant must be gone (moved to script_name.py).
    assert not hasattr(staging_module, "_SCRIPT_NAME_RE"), (
        "staging.py still has a local _SCRIPT_NAME_RE — T2 consolidation "
        "failed. The regex must live only in adaptive.script_name."
    )
    # The shared validator must be reachable (either as a re-export or
    # via direct import at call sites — both are acceptable).
    from screw_agents.adaptive.script_name import validate_script_name

    assert callable(validate_script_name)


# =====================================================================
# Phase 3b T3: stage_adaptive_script MCP tool + I-opus-3 validator tests
# =====================================================================


# --- I-opus-3: PendingApproval runtime per-event-type validator -------


def test_validate_pending_approval_accepts_valid_staged_entry() -> None:
    """I-opus-3: a staged entry with all required fields should pass."""
    from screw_agents.adaptive.staging import validate_pending_approval

    entry = {
        "event": "staged",
        "script_name": "test-001",
        "session_id": "sess-abc",
        "script_sha256": "a" * 64,
        "target_gap": {},
        "staged_at": "2026-04-20T10:00:00Z",
        "schema_version": 1,
    }
    # Should not raise.
    validate_pending_approval(entry)


def test_validate_pending_approval_rejects_staged_missing_sha256() -> None:
    """I-opus-3: missing per-event required field must raise ValueError."""
    from screw_agents.adaptive.staging import validate_pending_approval

    with pytest.raises(ValueError, match="script_sha256"):
        validate_pending_approval({"event": "staged"})


def test_validate_pending_approval_rejects_unknown_event_type() -> None:
    """I-opus-3: unknown event types must raise (new types require opt-in)."""
    from screw_agents.adaptive.staging import validate_pending_approval

    with pytest.raises(ValueError, match="unknown event type"):
        validate_pending_approval({"event": "blorp"})


def test_validate_pending_approval_rejects_tamper_missing_evidence_path() -> None:
    """I-opus-3: per-event validation catches missing `evidence_path`
    on tamper_detected, ensuring forensic-audit JSONL remains analyzable.
    """
    from screw_agents.adaptive.staging import validate_pending_approval

    entry = {
        "event": "tamper_detected",
        "script_name": "test-001",
        "session_id": "sess-abc",
        "expected_sha256": "a" * 64,
        "actual_sha256": "b" * 64,
        "tampered_at": "2026-04-20T10:00:00Z",
        "schema_version": 1,
        # evidence_path intentionally missing
    }
    with pytest.raises(ValueError, match="evidence_path"):
        validate_pending_approval(entry)


# --- Stage-flow tests (plan §T3 Step 1) -------------------------------


def test_stage_adaptive_script_writes_files_and_registry(tmp_path: Path) -> None:
    from screw_agents.adaptive.staging import resolve_registry_path, resolve_staging_dir
    from screw_agents.engine import ScanEngine

    project = tmp_path / "project"
    project.mkdir()
    engine = ScanEngine.from_defaults()
    source = (
        "from screw_agents.adaptive import emit_finding, find_calls\n"
        "\n"
        "def analyze(project):\n"
        "    for call in find_calls(project, 'foo.bar'):\n"
        "        emit_finding(cwe='CWE-89', file=call.file, line=call.line,\n"
        "                     message='stub', severity='high')\n"
    )
    meta = {
        "name": "test-stage-001",
        "created": "2026-04-20T10:00:00Z",
        "created_by": "tester@example.com",
        "domain": "injection-input-handling",
        "description": "fixture for stage test",
        "target_patterns": ["foo.bar"],
    }

    response = engine.stage_adaptive_script(
        project_root=project,
        script_name="test-stage-001",
        source=source,
        meta=meta,
        session_id="sess-abc",
        target_gap={"type": "unresolved_sink", "file": "dao.py", "line": 13, "agent": "sqli"},
    )

    assert response["status"] == "staged"
    assert response["script_name"] == "test-stage-001"
    assert response["session_id"] == "sess-abc"
    assert len(response["script_sha256"]) == 64
    assert response["script_sha256_prefix"] == response["script_sha256"][:8]
    assert response["session_id_short"].startswith("sess-abc")

    stage_dir = resolve_staging_dir(project, "sess-abc")
    assert (stage_dir / "test-stage-001.py").read_text() == source

    # Registry entry exists.
    registry_path = resolve_registry_path(project)
    assert registry_path.exists()
    entries = [json.loads(line) for line in registry_path.read_text().splitlines() if line.strip()]
    assert len(entries) == 1
    entry = entries[0]
    assert entry["event"] == "staged"
    assert entry["script_name"] == "test-stage-001"
    assert entry["session_id"] == "sess-abc"
    assert entry["script_sha256"] == response["script_sha256"]
    assert entry["target_gap"]["file"] == "dao.py"
    assert entry["schema_version"] == 1


def test_stage_adaptive_script_rejects_invalid_script_name(tmp_path: Path) -> None:
    from screw_agents.engine import ScanEngine

    project = tmp_path / "project"
    project.mkdir()
    engine = ScanEngine.from_defaults()

    response = engine.stage_adaptive_script(
        project_root=project,
        script_name="AA",  # too short (regex requires len 3-63)
        source="pass\n",
        meta={"name": "AA", "created": "2026-04-20T10:00:00Z",
              "created_by": "t@e.co", "domain": "injection-input-handling",
              "description": "d", "target_patterns": ["x"]},
        session_id="sess-abc",
        target_gap=None,
    )

    assert response["status"] == "error"
    assert response["error"] == "invalid_script_name"
    assert "AA" in response["message"]


def test_stage_adaptive_script_rejects_empty_session_id(tmp_path: Path) -> None:
    from screw_agents.engine import ScanEngine

    project = tmp_path / "project"
    project.mkdir()
    engine = ScanEngine.from_defaults()

    response = engine.stage_adaptive_script(
        project_root=project,
        script_name="test-001",
        source="pass\n",
        meta={"name": "test-001", "created": "2026-04-20T10:00:00Z",
              "created_by": "t@e.co", "domain": "injection-input-handling",
              "description": "d", "target_patterns": ["x"]},
        session_id="",
        target_gap=None,
    )

    assert response["status"] == "error"
    assert response["error"] == "invalid_session_id"


@pytest.mark.parametrize(
    "bad_session_id",
    [
        "foo\nbar",        # newline — I-opus-1 JSONL injection
        "foo:bar",         # colon — NTFS ADS primitive
        ".hidden",         # leading dot — hidden-dir bypass
        "foo\xff",         # high-bit byte — homoglyph primitive
        "foo bar",         # space
        "foo\tbar",        # tab
        "a" * 65,          # over-length
        "../etc/passwd",   # path traversal
        "foo/bar",         # slash
        "foo\\bar",        # backslash
        ".",               # bare dot
        "..",              # bare dots
    ],
)
def test_stage_adaptive_script_rejects_threat_session_ids(
    tmp_path: Path, bad_session_id: str
) -> None:
    """P2 regression: the engine-layer error-dict conversion fires for
    all session_id threat vectors closed by the T1-part-4 allowlist
    (I-opus-1 + I-opus-2). Validates the ValueError → error-dict path
    in `stage_adaptive_script` rather than just `resolve_staging_dir`.
    """
    from screw_agents.engine import ScanEngine

    project = tmp_path / "project"
    project.mkdir()
    engine = ScanEngine.from_defaults()

    response = engine.stage_adaptive_script(
        project_root=project,
        script_name="test-001",
        source="pass\n",
        meta={"name": "test-001", "created": "2026-04-20T10:00:00Z",
              "created_by": "t@e.co", "domain": "injection-input-handling",
              "description": "d", "target_patterns": ["x"]},
        session_id=bad_session_id,
        target_gap=None,
    )

    assert response["status"] == "error"
    assert response["error"] == "invalid_session_id"


def test_stage_adaptive_script_idempotent_on_same_content(tmp_path: Path) -> None:
    from screw_agents.adaptive.staging import resolve_registry_path, resolve_staging_dir
    from screw_agents.engine import ScanEngine

    project = tmp_path / "project"
    project.mkdir()
    engine = ScanEngine.from_defaults()
    common = dict(
        project_root=project,
        script_name="test-idem-001",
        source="pass\n",
        meta={"name": "test-idem-001", "created": "2026-04-20T10:00:00Z",
              "created_by": "t@e.co", "domain": "injection-input-handling",
              "description": "d", "target_patterns": ["x"]},
        session_id="sess-abc",
        target_gap=None,
    )

    r1 = engine.stage_adaptive_script(**common)
    r2 = engine.stage_adaptive_script(**common)

    assert r1["status"] == "staged"
    assert r2["status"] == "staged"
    # P4: `sha256(same source) == sha256(same source)` is tautological;
    # assert FILESYSTEM + REGISTRY state to prove idempotency actually
    # worked end-to-end.
    stage_dir = resolve_staging_dir(project, "sess-abc")
    assert (stage_dir / "test-idem-001.py").read_text(encoding="utf-8") == "pass\n"
    assert (stage_dir / "test-idem-001.meta.yaml").exists()

    # Registry gets TWO entries even on idempotent re-stage (each event is recorded).
    # The LOOKUP path uses "most-recent" semantics so this is fine.
    entries = [
        json.loads(line)
        for line in resolve_registry_path(project).read_text().splitlines()
        if line.strip()
    ]
    assert len(entries) == 2
    assert all(e["event"] == "staged" for e in entries)
    assert all(e["script_sha256"] == r1["script_sha256"] for e in entries)
    # Second entry's staged_at >= first entry's staged_at (monotonic).
    assert entries[1]["staged_at"] >= entries[0]["staged_at"]


def test_stage_adaptive_script_collision_on_same_name_different_content(
    tmp_path: Path,
) -> None:
    from screw_agents.engine import ScanEngine

    project = tmp_path / "project"
    project.mkdir()
    engine = ScanEngine.from_defaults()

    r1 = engine.stage_adaptive_script(
        project_root=project,
        script_name="test-coll-001",
        source="pass\n",
        meta={"name": "test-coll-001", "created": "2026-04-20T10:00:00Z",
              "created_by": "t@e.co", "domain": "injection-input-handling",
              "description": "d", "target_patterns": ["x"]},
        session_id="sess-abc",
        target_gap=None,
    )
    assert r1["status"] == "staged"

    r2 = engine.stage_adaptive_script(
        project_root=project,
        script_name="test-coll-001",
        source="print('different')\n",  # different bytes, same name
        meta={"name": "test-coll-001", "created": "2026-04-20T10:00:00Z",
              "created_by": "t@e.co", "domain": "injection-input-handling",
              "description": "d", "target_patterns": ["x"]},
        session_id="sess-abc",
        target_gap=None,
    )

    assert r2["status"] == "error"
    assert r2["error"] == "stage_name_collision"
    assert "existing_sha256_prefix" in r2
    assert r2["existing_sha256_prefix"] == r1["script_sha256"][:8]


def test_stage_adaptive_script_wraps_permission_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from screw_agents.engine import ScanEngine

    project = tmp_path / "project"
    project.mkdir()
    engine = ScanEngine.from_defaults()

    def boom(*args, **kwargs):
        raise PermissionError("simulated")

    monkeypatch.setattr(Path, "mkdir", boom)

    with pytest.raises(ValueError, match="PermissionError"):
        engine.stage_adaptive_script(
            project_root=project,
            script_name="test-perm-001",
            source="pass\n",
            meta={"name": "test-perm-001", "created": "2026-04-20T10:00:00Z",
                  "created_by": "t@e.co", "domain": "injection-input-handling",
                  "description": "d", "target_patterns": ["x"]},
            session_id="sess-abc",
            target_gap=None,
        )
