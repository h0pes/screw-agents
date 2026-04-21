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


# --- I2: direct unit tests for registry helpers (Opus re-review) ------


def test_query_registry_most_recent_tolerates_corrupt_lines(tmp_path: Path) -> None:
    """query_registry_most_recent must skip corrupt JSONL lines silently
    and still return valid matches. A crash mid-write or a stray edit
    should not lose preceding valid entries."""
    import json
    from screw_agents.adaptive.staging import (
        query_registry_most_recent,
        resolve_registry_path,
    )

    project = tmp_path / "project"
    project.mkdir()
    registry = resolve_registry_path(project)
    registry.parent.mkdir(parents=True, exist_ok=True)

    valid_entry = {
        "event": "staged",
        "script_name": "test-script",
        "session_id": "sess-abc",
        "script_sha256": "a" * 64,
    }
    # Line 1: corrupt (missing closing brace)
    # Line 2: valid matching entry
    # Line 3: empty
    # Line 4: another corrupt line (invalid JSON)
    registry.write_text(
        '{"event": "staged", "script_name": "truncated"\n'
        + json.dumps(valid_entry) + "\n"
        + "\n"
        + "not-json-at-all garbage{}\n",
        encoding="utf-8",
    )

    result = query_registry_most_recent(
        project, script_name="test-script", session_id="sess-abc"
    )
    assert result is not None
    assert result["script_name"] == "test-script"
    assert result["script_sha256"] == "a" * 64


def test_query_registry_most_recent_returns_last_matching(tmp_path: Path) -> None:
    """When multiple entries match (script_name, session_id), return the
    LAST one in the file. Locks the position-based most-recent contract."""
    import json
    from screw_agents.adaptive.staging import (
        query_registry_most_recent,
        resolve_registry_path,
    )

    project = tmp_path / "project"
    project.mkdir()
    registry = resolve_registry_path(project)
    registry.parent.mkdir(parents=True, exist_ok=True)

    e1 = {"event": "staged", "script_name": "foo", "session_id": "s",
          "script_sha256": "1" * 64, "staged_at": "2026-04-21T10:00:00Z"}
    e2 = {"event": "staged", "script_name": "foo", "session_id": "s",
          "script_sha256": "2" * 64, "staged_at": "2026-04-21T10:00:05Z"}
    registry.write_text(json.dumps(e1) + "\n" + json.dumps(e2) + "\n",
                        encoding="utf-8")

    result = query_registry_most_recent(project, script_name="foo", session_id="s")
    assert result is not None
    assert result["script_sha256"] == "2" * 64  # second entry wins


def test_fallback_walk_skips_non_directory_entries(tmp_path: Path) -> None:
    """fallback_walk_for_script must tolerate stray files in the staging
    root (e.g., accidental user writes) and skip them without error."""
    from screw_agents.adaptive.staging import fallback_walk_for_script

    project = tmp_path / "project"
    project.mkdir()
    staging_root = project / ".screw" / "staging"
    staging_root.mkdir(parents=True)
    # Plant a stray file (not a directory) at the staging root.
    (staging_root / "stray.txt").write_text("garbage", encoding="utf-8")
    # And a legitimate session dir with the target script.
    legit = staging_root / "sess-abc" / "adaptive-scripts"
    legit.mkdir(parents=True)
    (legit / "my-script.py").write_text("pass\n", encoding="utf-8")

    matches = fallback_walk_for_script(project, script_name="my-script")
    assert len(matches) == 1
    session_id, py_path = matches[0]
    assert session_id == "sess-abc"


def test_fallback_walk_returns_empty_on_missing_staging_root(tmp_path: Path) -> None:
    """Empty list when .screw/staging/ doesn't exist (fresh project)."""
    from screw_agents.adaptive.staging import fallback_walk_for_script

    project = tmp_path / "project"
    project.mkdir()
    # Do NOT create .screw/staging/

    matches = fallback_walk_for_script(project, script_name="anything")
    assert matches == []


def test_append_registry_entry_wraps_permission_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """T13-C1 discipline: filesystem errors during append must wrap to
    ValueError with the exception type in the message."""
    from screw_agents.adaptive import staging

    project = tmp_path / "project"
    project.mkdir()

    original_open = os.open

    def boom(path, flags, mode=0o777):
        if "pending-approvals.jsonl" in str(path):
            raise PermissionError("simulated EACCES on registry")
        return original_open(path, flags, mode)

    monkeypatch.setattr(os, "open", boom)

    valid_entry = {
        "event": "staged",
        "script_name": "test-script",
        "session_id": "sess-abc",
        "script_sha256": "a" * 64,
        "target_gap": {},
        "staged_at": "2026-04-21T10:00:00Z",
        "schema_version": 1,
    }
    with pytest.raises(ValueError, match="PermissionError"):
        staging.append_registry_entry(project, valid_entry)


# --- I4: UnicodeDecodeError wrap in stage_adaptive_script collision check ---


def test_stage_adaptive_script_rejects_corrupted_utf8_existing(tmp_path: Path) -> None:
    """I4 regression: if the staged .py file on disk contains non-UTF-8
    bytes (filesystem corruption or attacker plant), the engine returns
    an error-dict rather than an uncaught UnicodeDecodeError."""
    from screw_agents.engine import ScanEngine
    from screw_agents.adaptive.staging import resolve_staging_dir

    project = tmp_path / "project"
    project.mkdir()
    engine = ScanEngine.from_defaults()

    # Pre-plant a staged .py with non-UTF-8 bytes.
    stage_dir = resolve_staging_dir(project, "sess-abc")
    stage_dir.mkdir(parents=True)
    (stage_dir / "test-corrupt.py").write_bytes(b"\xff\xfe\xfd\x00corrupted")

    response = engine.stage_adaptive_script(
        project_root=project,
        script_name="test-corrupt",
        source="pass\n",
        meta={"name": "test-corrupt", "created": "2026-04-21T10:00:00Z",
              "created_by": "t@e.co", "domain": "injection-input-handling",
              "description": "d", "target_patterns": ["x"]},
        session_id="sess-abc",
        target_gap=None,
    )

    assert response["status"] == "error"
    assert response["error"] == "stage_corrupted"
    assert "UnicodeDecodeError" in response["message"]


# --- I5: fail-fast contract lockdown for append_registry_entry --------


def test_append_registry_entry_rejects_missing_required_field(tmp_path: Path) -> None:
    """I5 contract lockdown: append_registry_entry calls
    validate_pending_approval as its FIRST line (fail-fast before I/O).
    A malformed entry must raise before any file is touched."""
    from screw_agents.adaptive.staging import (
        append_registry_entry,
        resolve_registry_path,
    )

    project = tmp_path / "project"
    project.mkdir()

    # staged event missing script_sha256, target_gap, staged_at, schema_version
    bad_entry = {"event": "staged", "script_name": "x", "session_id": "s"}

    with pytest.raises(ValueError, match="missing required"):
        append_registry_entry(project, bad_entry)

    # Verify registry file was NEVER created — fail-fast ran before I/O.
    assert not resolve_registry_path(project).exists()
    # And the parent dir wasn't touched either.
    assert not (project / ".screw" / "local").exists()


# =====================================================================
# Phase 3b T4: promote_staged_script (C1 FIX — the heart of the PR)
# =====================================================================


# --- I1: ScrewConfig schema fields (stale_staging_hours, staging_max_age_days)


def test_screw_config_staging_fields_default_values() -> None:
    """I1 regression: ScrewConfig exposes stale_staging_hours + staging_max_age_days
    with their documented defaults."""
    from screw_agents.models import ScrewConfig

    config = ScrewConfig()
    assert config.stale_staging_hours == 24
    assert config.staging_max_age_days == 14


def test_screw_config_staging_fields_accept_custom_values() -> None:
    """I1 regression: custom values within range load cleanly."""
    from screw_agents.models import ScrewConfig

    config = ScrewConfig(stale_staging_hours=72, staging_max_age_days=30)
    assert config.stale_staging_hours == 72
    assert config.staging_max_age_days == 30


def test_screw_config_staging_fields_reject_out_of_range() -> None:
    """I1 regression: out-of-range values (below minimum or above maximum)
    raise ValidationError at model-construction time rather than silently
    degrading inside helpers."""
    from pydantic import ValidationError

    from screw_agents.models import ScrewConfig

    # stale_staging_hours: ge=1, le=168
    with pytest.raises(ValidationError):
        ScrewConfig(stale_staging_hours=0)
    with pytest.raises(ValidationError):
        ScrewConfig(stale_staging_hours=169)

    # staging_max_age_days: ge=1, le=365
    with pytest.raises(ValidationError):
        ScrewConfig(staging_max_age_days=0)
    with pytest.raises(ValidationError):
        ScrewConfig(staging_max_age_days=366)


# --- C1 REGRESSION LOCK ---------------------------------------------------


def test_promote_staged_script_signature_rejects_source_param() -> None:
    """C1 REGRESSION LOCK.

    promote_staged_script MUST NOT accept a `source` parameter. The whole
    point of the C1 fix is that the approve path reads source from disk,
    not from an LLM-provided argument. If a future refactor adds `source`
    back, the regeneration vulnerability reopens. This test catches it.
    """
    import inspect

    from screw_agents.engine import ScanEngine

    sig = inspect.signature(ScanEngine.promote_staged_script)
    assert "source" not in sig.parameters, (
        "promote_staged_script must not accept `source` parameter — C1 "
        "architectural closure regressed. See spec §3.2."
    )
    # Also reject `meta` — meta is read from staging, same rationale.
    assert "meta" not in sig.parameters, (
        "promote_staged_script must not accept `meta` parameter either"
    )


# --- Happy path + error paths --------------------------------------------


def _stage_script_for_promote(
    engine,
    project: Path,
    script_name: str,
    *,
    source: str,
    session_id: str,
    created_by: str = "t@e.co",
) -> dict:
    """Helper: shared stage invocation for promote tests."""
    meta = {
        "name": script_name,
        "created": "2026-04-20T10:00:00Z",
        "created_by": created_by,
        "domain": "injection-input-handling",
        "description": "test",
        "target_patterns": ["foo.bar"],
    }
    return engine.stage_adaptive_script(
        project_root=project,
        script_name=script_name,
        source=source,
        meta=meta,
        session_id=session_id,
        target_gap=None,
    )


def test_promote_staged_script_happy_path(tmp_path: Path) -> None:
    """Stage then promote: signed artifact lands in custom-scripts/ with
    byte-identical source."""
    from screw_agents.adaptive.staging import resolve_registry_path
    from screw_agents.cli.init_trust import run_init_trust
    from screw_agents.engine import ScanEngine

    project = tmp_path / "project"
    project.mkdir()
    run_init_trust(project_root=project, name="T4 Tester", email="t4@example.com")
    engine = ScanEngine.from_defaults()
    source = (
        "from screw_agents.adaptive import emit_finding\n\n"
        "def analyze(project):\n    pass\n"
    )

    stage_r = _stage_script_for_promote(
        engine,
        project,
        "test-promote-001",
        source=source,
        session_id="sess-abc",
        created_by="t4@example.com",
    )
    assert stage_r["status"] == "staged"

    promote_r = engine.promote_staged_script(
        project_root=project,
        script_name="test-promote-001",
        session_id="sess-abc",
    )

    assert promote_r["status"] == "signed"
    assert promote_r["signed_by"] == "t4@example.com"
    assert promote_r["sha256"] == stage_r["script_sha256"]
    assert promote_r["promoted_via_fallback"] is False

    # Custom-scripts file contains EXACTLY the staged source.
    signed_py = project / ".screw" / "custom-scripts" / "test-promote-001.py"
    assert signed_py.exists()
    assert signed_py.read_text(encoding="utf-8") == source

    # Staging files deleted.
    stage_py = (
        project
        / ".screw"
        / "staging"
        / "sess-abc"
        / "adaptive-scripts"
        / "test-promote-001.py"
    )
    assert not stage_py.exists()

    # Registry has both staged + promoted entries.
    entries = [
        json.loads(line)
        for line in resolve_registry_path(project).read_text().splitlines()
        if line.strip()
    ]
    events = [e["event"] for e in entries]
    assert "staged" in events
    assert "promoted" in events


def test_promote_staging_not_found(tmp_path: Path) -> None:
    from screw_agents.engine import ScanEngine

    project = tmp_path / "project"
    project.mkdir()
    engine = ScanEngine.from_defaults()

    response = engine.promote_staged_script(
        project_root=project,
        script_name="nope",
        session_id="sess-abc",
    )

    assert response["status"] == "error"
    assert response["error"] == "staging_not_found"


def test_promote_detects_tamper(tmp_path: Path) -> None:
    """Between stage and promote, overwrite staging .py with different bytes.
    Promote must reject with tamper_detected + evidence_path + TAMPERED marker."""
    from screw_agents.adaptive.staging import resolve_staging_dir
    from screw_agents.cli.init_trust import run_init_trust
    from screw_agents.engine import ScanEngine

    project = tmp_path / "project"
    project.mkdir()
    run_init_trust(project_root=project, name="T", email="t@e.co")
    engine = ScanEngine.from_defaults()
    source = (
        "from screw_agents.adaptive import emit_finding\n"
        "def analyze(p):\n    pass\n"
    )

    _stage_script_for_promote(
        engine,
        project,
        "test-tamper-001",
        source=source,
        session_id="sess-abc",
    )

    # TAMPER: overwrite staging .py with different bytes.
    stage_py = resolve_staging_dir(project, "sess-abc") / "test-tamper-001.py"
    stage_py.write_text(
        "# malicious\nimport os\nos.system('rm -rf /')\n", encoding="utf-8"
    )

    response = engine.promote_staged_script(
        project_root=project,
        script_name="test-tamper-001",
        session_id="sess-abc",
    )

    assert response["status"] == "error"
    assert response["error"] == "tamper_detected"
    assert response["expected_sha256_prefix"]
    assert response["actual_sha256_prefix"]
    assert response["expected_sha256_prefix"] != response["actual_sha256_prefix"]
    assert "evidence_path" in response

    # TAMPERED marker file exists.
    marker = resolve_staging_dir(project, "sess-abc") / "test-tamper-001.TAMPERED"
    assert marker.exists()

    # Staging files NOT deleted (forensic evidence).
    assert stage_py.exists()

    # No custom-scripts artifact written.
    signed_py = project / ".screw" / "custom-scripts" / "test-tamper-001.py"
    assert not signed_py.exists()


def test_promote_audit_on_tamper(tmp_path: Path) -> None:
    """tamper_detected appends a tamper_detected event to the registry with
    expected/actual sha256 + evidence_path."""
    from screw_agents.adaptive.staging import (
        resolve_registry_path,
        resolve_staging_dir,
    )
    from screw_agents.cli.init_trust import run_init_trust
    from screw_agents.engine import ScanEngine

    project = tmp_path / "project"
    project.mkdir()
    run_init_trust(project_root=project, name="T", email="t@e.co")
    engine = ScanEngine.from_defaults()
    _stage_script_for_promote(
        engine,
        project,
        "test-tamper-aud",
        source="pass\n",
        session_id="sess-abc",
    )

    # Tamper.
    stage_py = resolve_staging_dir(project, "sess-abc") / "test-tamper-aud.py"
    stage_py.write_text("# different\npass\n", encoding="utf-8")

    response = engine.promote_staged_script(
        project_root=project,
        script_name="test-tamper-aud",
        session_id="sess-abc",
    )
    assert response["status"] == "error"
    assert response["error"] == "tamper_detected"

    entries = [
        json.loads(line)
        for line in resolve_registry_path(project).read_text().splitlines()
        if line.strip()
    ]
    tamper_entries = [e for e in entries if e.get("event") == "tamper_detected"]
    assert len(tamper_entries) == 1
    assert tamper_entries[0]["script_name"] == "test-tamper-aud"
    assert tamper_entries[0]["session_id"] == "sess-abc"
    assert tamper_entries[0]["expected_sha256"]
    assert tamper_entries[0]["actual_sha256"]
    assert tamper_entries[0]["expected_sha256"] != tamper_entries[0]["actual_sha256"]
    assert "evidence_path" in tamper_entries[0]


def test_promote_stale_staging_requires_confirm_stale(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Stage with staged_at 48h in the past; promote without confirm_stale
    returns stale_staging error. Retry with confirm_stale succeeds and emits
    the I5 `promoted_confirm_stale` audit event."""
    from datetime import datetime, timedelta, timezone

    from screw_agents.adaptive.staging import resolve_registry_path
    from screw_agents.cli.init_trust import run_init_trust
    from screw_agents.engine import ScanEngine

    project = tmp_path / "project"
    project.mkdir()
    run_init_trust(project_root=project, name="T", email="t@e.co")
    engine = ScanEngine.from_defaults()

    # Stage normally.
    _stage_script_for_promote(
        engine,
        project,
        "test-stale-001",
        source="pass\n",
        session_id="sess-old",
    )

    # Rewrite registry with a 48h-old staged_at.
    old_time = (datetime.now(timezone.utc) - timedelta(hours=48)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    registry = resolve_registry_path(project)
    lines = registry.read_text().splitlines()
    rewritten = []
    for line in lines:
        entry = json.loads(line)
        if entry.get("script_name") == "test-stale-001":
            entry["staged_at"] = old_time
        rewritten.append(json.dumps(entry, separators=(",", ":"), sort_keys=True))
    registry.write_text("\n".join(rewritten) + "\n")

    # Promote without confirm_stale → stale error.
    response = engine.promote_staged_script(
        project_root=project,
        script_name="test-stale-001",
        session_id="sess-old",
    )

    assert response["status"] == "error"
    assert response["error"] == "stale_staging"
    assert response["hours_old"] >= 48
    assert response["threshold_hours"] == 24

    # Retry with confirm_stale → success.
    response2 = engine.promote_staged_script(
        project_root=project,
        script_name="test-stale-001",
        session_id="sess-old",
        confirm_stale=True,
    )
    assert response2["status"] == "signed"

    # I5 regression: confirm-stale retry must emit `promoted_confirm_stale`
    # audit event (not plain `promoted`). Locks the audit-event taxonomy
    # so downstream forensics can distinguish routine promotes from
    # staleness-override promotes.
    entries = [
        json.loads(line)
        for line in resolve_registry_path(project).read_text().splitlines()
        if line.strip()
    ]
    promoted_events = [
        e for e in entries if e.get("event", "").startswith("promoted")
    ]
    assert len(promoted_events) == 1
    assert promoted_events[0]["event"] == "promoted_confirm_stale", (
        f"Expected `promoted_confirm_stale` audit event; "
        f"got {promoted_events[0]['event']!r}"
    )


def test_promote_rejects_malformed_staged_at(tmp_path: Path) -> None:
    """I3 hardening: staleness check must NOT silently bypass on a
    malformed timestamp. Force ops to investigate corrupted registry."""
    from screw_agents.adaptive.staging import resolve_registry_path
    from screw_agents.cli.init_trust import run_init_trust
    from screw_agents.engine import ScanEngine

    project = tmp_path / "project"
    project.mkdir()
    run_init_trust(project_root=project, name="T", email="t@e.co")
    engine = ScanEngine.from_defaults()
    _stage_script_for_promote(
        engine,
        project,
        "test-bad-ts",
        source="pass\n",
        session_id="sess-abc",
    )

    # Corrupt the staged_at timestamp in the registry.
    registry = resolve_registry_path(project)
    lines = registry.read_text().splitlines()
    rewritten = []
    for line in lines:
        entry = json.loads(line)
        if entry.get("script_name") == "test-bad-ts":
            entry["staged_at"] = "not-a-timestamp"
        rewritten.append(json.dumps(entry, separators=(",", ":"), sort_keys=True))
    registry.write_text("\n".join(rewritten) + "\n")

    response = engine.promote_staged_script(
        project_root=project,
        script_name="test-bad-ts",
        session_id="sess-abc",
    )

    assert response["status"] == "error"
    assert response["error"] == "invalid_registry_entry"
    assert (
        "malformed" in response["message"].lower()
        or "parse error" in response["message"].lower()
    )


def test_promote_rejects_missing_script_sha256(tmp_path) -> None:
    """I-opus-1 regression: symmetric to I3's staged_at discipline.
    A `staged` registry entry missing `script_sha256` must return
    invalid_registry_entry — not crash on NoneType subscript.
    """
    from screw_agents.cli.init_trust import run_init_trust
    from screw_agents.engine import ScanEngine
    from screw_agents.adaptive.staging import resolve_registry_path

    project = tmp_path / "project"
    project.mkdir()
    run_init_trust(project_root=project, name="T", email="t@e.co")
    engine = ScanEngine.from_defaults()
    engine.stage_adaptive_script(
        project_root=project,
        script_name="test-no-sha",
        source="pass\n",
        meta={"name": "test-no-sha", "created": "2026-04-21T10:00:00Z",
              "created_by": "t@e.co", "domain": "injection-input-handling",
              "description": "d", "target_patterns": ["x"]},
        session_id="sess-abc",
        target_gap=None,
    )

    # Corrupt the registry: remove script_sha256 from the staged entry.
    # (Simulates a legacy entry or hand-edited tamper.)
    registry = resolve_registry_path(project)
    import json as _json
    lines = registry.read_text().splitlines()
    rewritten = []
    for line in lines:
        entry = _json.loads(line)
        if entry.get("script_name") == "test-no-sha":
            entry.pop("script_sha256", None)
        rewritten.append(_json.dumps(entry, separators=(",", ":"), sort_keys=True))
    registry.write_text("\n".join(rewritten) + "\n")

    response = engine.promote_staged_script(
        project_root=project,
        script_name="test-no-sha",
        session_id="sess-abc",
    )

    assert response["status"] == "error"
    assert response["error"] == "invalid_registry_entry"
    assert "script_sha256" in response["message"]


def test_promote_fallback_registry_missing(tmp_path: Path) -> None:
    """Registry file absent → fallback_required with recovered_sha256_prefix."""
    from screw_agents.adaptive.staging import (
        resolve_registry_path,
        resolve_staging_dir,
    )
    from screw_agents.cli.init_trust import run_init_trust
    from screw_agents.engine import ScanEngine

    project = tmp_path / "project"
    project.mkdir()
    run_init_trust(project_root=project, name="T", email="t@e.co")
    engine = ScanEngine.from_defaults()
    _stage_script_for_promote(
        engine,
        project,
        "test-fb-missing",
        source="pass\n",
        session_id="sess-abc",
    )

    # Delete the registry file to simulate corruption.
    resolve_registry_path(project).unlink()

    # Staging files still on disk.
    stage_py = resolve_staging_dir(project, "sess-abc") / "test-fb-missing.py"
    assert stage_py.exists()

    response = engine.promote_staged_script(
        project_root=project,
        script_name="test-fb-missing",
        session_id="sess-abc",
    )

    assert response["status"] == "error"
    assert response["error"] == "fallback_required"
    assert "recovered_sha256_prefix" in response
    assert len(response["recovered_sha256_prefix"]) == 8


def test_promote_fallback_sha_prefix_accepted(tmp_path: Path) -> None:
    """confirm_sha_prefix matches recovered sha → promote proceeds, audit
    event is `promoted_via_fallback`."""
    from screw_agents.adaptive.signing import compute_script_sha256
    from screw_agents.adaptive.staging import resolve_registry_path
    from screw_agents.cli.init_trust import run_init_trust
    from screw_agents.engine import ScanEngine

    project = tmp_path / "project"
    project.mkdir()
    run_init_trust(project_root=project, name="T", email="t@e.co")
    engine = ScanEngine.from_defaults()
    source = "pass\n"
    _stage_script_for_promote(
        engine,
        project,
        "test-fb-ok",
        source=source,
        session_id="sess-abc",
    )

    # Delete the registry to force fallback path.
    resolve_registry_path(project).unlink()

    expected_prefix = compute_script_sha256(source)[:8]
    response = engine.promote_staged_script(
        project_root=project,
        script_name="test-fb-ok",
        session_id="sess-abc",
        confirm_sha_prefix=expected_prefix,
    )

    assert response["status"] == "signed"
    assert response["promoted_via_fallback"] is True

    # Registry now contains a promoted_via_fallback event (registry file was
    # re-created by the audit append).
    entries = [
        json.loads(line)
        for line in resolve_registry_path(project).read_text().splitlines()
        if line.strip()
    ]
    events = [e["event"] for e in entries]
    assert "promoted_via_fallback" in events


def test_promote_fallback_sha_prefix_mismatch(tmp_path: Path) -> None:
    """Wrong prefix → fallback_sha_mismatch error."""
    from screw_agents.adaptive.staging import resolve_registry_path
    from screw_agents.cli.init_trust import run_init_trust
    from screw_agents.engine import ScanEngine

    project = tmp_path / "project"
    project.mkdir()
    run_init_trust(project_root=project, name="T", email="t@e.co")
    engine = ScanEngine.from_defaults()
    _stage_script_for_promote(
        engine,
        project,
        "test-fb-bad",
        source="pass\n",
        session_id="sess-abc",
    )

    # Delete the registry to force fallback path.
    resolve_registry_path(project).unlink()

    response = engine.promote_staged_script(
        project_root=project,
        script_name="test-fb-bad",
        session_id="sess-abc",
        confirm_sha_prefix="deadbeef",  # definitely wrong
    )

    assert response["status"] == "error"
    assert response["error"] == "fallback_sha_mismatch"
    assert response["expected_in_phrase"]
    assert response["got_in_phrase"] == "deadbeef"


def test_promote_custom_scripts_collision(tmp_path: Path) -> None:
    """Signed file already exists in custom-scripts/ → sign_failed surfaces
    the collision via the I2 taxonomy-normalized error."""
    from screw_agents.cli.init_trust import run_init_trust
    from screw_agents.engine import ScanEngine

    project = tmp_path / "project"
    project.mkdir()
    run_init_trust(project_root=project, name="T", email="t@e.co")
    engine = ScanEngine.from_defaults()
    _stage_script_for_promote(
        engine,
        project,
        "test-collision",
        source="pass\n",
        session_id="sess-abc",
    )

    # Pre-plant a file in custom-scripts/ to trigger _sign_script_bytes's
    # fresh-script collision error.
    cs_dir = project / ".screw" / "custom-scripts"
    cs_dir.mkdir(parents=True, exist_ok=True)
    (cs_dir / "test-collision.py").write_text("# pre-existing\n", encoding="utf-8")

    response = engine.promote_staged_script(
        project_root=project,
        script_name="test-collision",
        session_id="sess-abc",
    )

    # I2 regression: when _sign_script_bytes returns {"status": "error",
    # "message": "..."} without an "error" key, the promote wrapper injects
    # error="sign_failed" and stashes the inner result under "detail".
    assert response["status"] == "error"
    assert response["error"] == "sign_failed"
    assert "already exists" in response["message"].lower()
    assert "detail" in response


def test_promote_invalid_lifecycle_state(tmp_path: Path) -> None:
    """Most-recent registry event is `rejected` and staging somehow present
    (mocked) → invalid_lifecycle_state defensive error."""
    from screw_agents.adaptive.staging import (
        _utc_now_iso,
        append_registry_entry,
        resolve_staging_dir,
    )
    from screw_agents.cli.init_trust import run_init_trust
    from screw_agents.engine import ScanEngine

    project = tmp_path / "project"
    project.mkdir()
    run_init_trust(project_root=project, name="T", email="t@e.co")
    engine = ScanEngine.from_defaults()

    # Stage normally so the .py + .meta.yaml exist on disk.
    _stage_script_for_promote(
        engine,
        project,
        "test-lifecycle",
        source="pass\n",
        session_id="sess-abc",
    )
    # Confirm staging is present.
    stage_py = resolve_staging_dir(project, "sess-abc") / "test-lifecycle.py"
    assert stage_py.exists()

    # Append a `rejected` event AFTER the `staged` event so the most-recent
    # entry is `rejected` even though the filesystem still has the files.
    append_registry_entry(
        project,
        {
            "event": "rejected",
            "script_name": "test-lifecycle",
            "session_id": "sess-abc",
            "reason": "simulated rejection",
            "rejected_at": _utc_now_iso(),
            "schema_version": 1,
        },
    )

    response = engine.promote_staged_script(
        project_root=project,
        script_name="test-lifecycle",
        session_id="sess-abc",
    )

    assert response["status"] == "error"
    assert response["error"] == "invalid_lifecycle_state"
    assert response["last_event"] == "rejected"


# ---------------------------------------------------------------------------
# Phase 3b T5: reject_staged_script (C1 staging-path decline tool).
# ---------------------------------------------------------------------------


def test_reject_staged_script_deletes_files_and_audits(tmp_path: Path) -> None:
    """Happy path: reject deletes staging + appends rejected audit event."""
    from screw_agents.adaptive.staging import (
        resolve_registry_path,
        resolve_staging_dir,
    )
    from screw_agents.engine import ScanEngine

    project = tmp_path / "project"
    project.mkdir()
    engine = ScanEngine.from_defaults()

    engine.stage_adaptive_script(
        project_root=project,
        script_name="test-rej-001",
        source="pass\n",
        meta={
            "name": "test-rej-001",
            "created": "2026-04-20T10:00:00Z",
            "created_by": "t@e.co",
            "domain": "injection-input-handling",
            "description": "d",
            "target_patterns": ["x"],
        },
        session_id="sess-abc",
        target_gap=None,
    )

    response = engine.reject_staged_script(
        project_root=project,
        script_name="test-rej-001",
        session_id="sess-abc",
        reason="imports look suspicious",
    )

    assert response["status"] == "rejected"
    assert response["reason"] == "imports look suspicious"

    stage_py = resolve_staging_dir(project, "sess-abc") / "test-rej-001.py"
    assert not stage_py.exists()

    entries = [
        json.loads(line)
        for line in resolve_registry_path(project).read_text().splitlines()
        if line.strip()
    ]
    events = [e["event"] for e in entries]
    assert "rejected" in events
    rej = [e for e in entries if e["event"] == "rejected"][0]
    assert rej["reason"] == "imports look suspicious"


def test_reject_staged_script_idempotent_on_second_reject(tmp_path: Path) -> None:
    """Second reject after files are gone returns already_rejected (success)."""
    from screw_agents.engine import ScanEngine

    project = tmp_path / "project"
    project.mkdir()
    engine = ScanEngine.from_defaults()

    engine.stage_adaptive_script(
        project_root=project,
        script_name="test-rej-002",
        source="pass\n",
        meta={
            "name": "test-rej-002",
            "created": "2026-04-20T10:00:00Z",
            "created_by": "t@e.co",
            "domain": "injection-input-handling",
            "description": "d",
            "target_patterns": ["x"],
        },
        session_id="sess-abc",
        target_gap=None,
    )
    r1 = engine.reject_staged_script(
        project_root=project,
        script_name="test-rej-002",
        session_id="sess-abc",
        reason=None,
    )
    r2 = engine.reject_staged_script(
        project_root=project,
        script_name="test-rej-002",
        session_id="sess-abc",
        reason=None,
    )

    assert r1["status"] == "rejected"
    assert r2["status"] == "already_rejected"  # idempotent

    # I-T5-3: audit-correctness invariant — idempotent reject must NOT
    # duplicate the `rejected` event in the registry.
    import json as _json
    from screw_agents.adaptive.staging import resolve_registry_path
    entries = [
        _json.loads(line)
        for line in resolve_registry_path(project).read_text().splitlines()
        if line.strip()
    ]
    rejected_events = [e for e in entries if e["event"] == "rejected"]
    assert len(rejected_events) == 1, (
        f"idempotent reject must not duplicate audit events; got {len(rejected_events)}"
    )


def test_reject_staged_script_rejects_invalid_session_id(tmp_path: Path) -> None:
    """I1 regression: invalid session_id (rejected by T1-part-4 allowlist)
    must become an error-dict, not an uncaught ValueError."""
    from screw_agents.engine import ScanEngine

    project = tmp_path / "project"
    project.mkdir()
    engine = ScanEngine.from_defaults()

    response = engine.reject_staged_script(
        project_root=project,
        script_name="test-001",
        session_id="foo\nbar",  # newline rejected by allowlist
        reason=None,
    )

    assert response["status"] == "error"
    assert response["error"] == "invalid_session_id"


def test_reject_staged_script_rejects_invalid_script_name(tmp_path: Path) -> None:
    """I1 regression: invalid script_name must become error-dict."""
    from screw_agents.engine import ScanEngine

    project = tmp_path / "project"
    project.mkdir()
    engine = ScanEngine.from_defaults()

    response = engine.reject_staged_script(
        project_root=project,
        script_name="UPPERCASE",  # allowlist rejects uppercase
        session_id="sess-abc",
        reason=None,
    )

    assert response["status"] == "error"
    assert response["error"] == "invalid_script_name"


def test_reject_staged_script_updates_adaptive_prompts_json(tmp_path: Path) -> None:
    """T18b's decline tracking lives in .screw/local/adaptive_prompts.json —
    reject MUST update it so the same target isn't re-proposed on the next scan."""
    import json as _json

    from screw_agents.engine import ScanEngine

    project = tmp_path / "project"
    project.mkdir()
    engine = ScanEngine.from_defaults()

    engine.stage_adaptive_script(
        project_root=project,
        script_name="test-rej-003",
        source="pass\n",
        meta={
            "name": "test-rej-003",
            "created": "2026-04-20T10:00:00Z",
            "created_by": "t@e.co",
            "domain": "injection-input-handling",
            "description": "d",
            "target_patterns": ["x"],
        },
        session_id="sess-abc",
        target_gap=None,
    )

    response = engine.reject_staged_script(
        project_root=project,
        script_name="test-rej-003",
        session_id="sess-abc",
        reason="too speculative",
    )

    assert response["status"] == "rejected"

    # The decline-tracking artifact must include the rejected script_name.
    prompts_path = project / ".screw" / "local" / "adaptive_prompts.json"
    assert prompts_path.exists(), (
        "reject_staged_script must create adaptive_prompts.json if absent"
    )
    state = _json.loads(prompts_path.read_text(encoding="utf-8"))
    assert "declined" in state
    assert "test-rej-003" in state["declined"]

    # Second reject on same target MUST NOT produce duplicate declined entries.
    engine.stage_adaptive_script(
        project_root=project,
        script_name="test-rej-003",
        source="pass\n",
        meta={
            "name": "test-rej-003",
            "created": "2026-04-20T10:00:00Z",
            "created_by": "t@e.co",
            "domain": "injection-input-handling",
            "description": "d",
            "target_patterns": ["x"],
        },
        session_id="sess-xyz",
        target_gap=None,  # different session
    )
    engine.reject_staged_script(
        project_root=project,
        script_name="test-rej-003",
        session_id="sess-xyz",
        reason=None,
    )
    state2 = _json.loads(prompts_path.read_text(encoding="utf-8"))
    assert state2["declined"].count("test-rej-003") == 1, (
        "declined list must deduplicate by script_name"
    )


def test_reject_staged_script_no_staging_returns_already_rejected(
    tmp_path: Path,
) -> None:
    """Reject before any stage (or after cleanup) returns already_rejected."""
    from screw_agents.engine import ScanEngine

    project = tmp_path / "project"
    project.mkdir()
    engine = ScanEngine.from_defaults()

    response = engine.reject_staged_script(
        project_root=project,
        script_name="never-staged",
        session_id="sess-abc",
        reason=None,
    )

    assert response["status"] == "already_rejected"


def test_reject_staged_script_tolerates_corrupted_prompts_json(tmp_path: Path) -> None:
    """I-T5-1 regression: reject must swallow corrupted adaptive_prompts.json
    (invalid JSON, wrong shape) and self-heal the file — never leak
    JSONDecodeError / AttributeError to the caller."""
    from screw_agents.engine import ScanEngine

    project = tmp_path / "project"
    project.mkdir()
    engine = ScanEngine.from_defaults()

    # Plant a corrupted prompts file.
    prompts_path = project / ".screw" / "local" / "adaptive_prompts.json"
    prompts_path.parent.mkdir(parents=True, exist_ok=True)
    prompts_path.write_text("{not valid json at all", encoding="utf-8")

    # Stage + reject. Must NOT raise.
    engine.stage_adaptive_script(
        project_root=project, script_name="test-rej-heal", source="pass\n",
        meta={"name": "test-rej-heal", "created": "2026-04-20T10:00:00Z",
              "created_by": "t@e.co", "domain": "injection-input-handling",
              "description": "d", "target_patterns": ["x"]},
        session_id="sess-abc", target_gap=None,
    )
    response = engine.reject_staged_script(
        project_root=project, script_name="test-rej-heal",
        session_id="sess-abc", reason=None,
    )

    assert response["status"] == "rejected"
    # Self-heal: after reject, the corrupted file should now be valid JSON
    # with the declined entry.
    import json as _json
    state = _json.loads(prompts_path.read_text(encoding="utf-8"))
    assert "test-rej-heal" in state.get("declined", [])


def test_reject_staged_script_tolerates_wrong_shape_prompts_json(tmp_path: Path) -> None:
    """I-T5-1 regression: valid JSON but wrong shape (list instead of dict,
    or declined is not a list) must also self-heal without exception."""
    from screw_agents.engine import ScanEngine

    project = tmp_path / "project"
    project.mkdir()
    engine = ScanEngine.from_defaults()

    # Plant a shape-corrupted prompts file: valid JSON, wrong type.
    prompts_path = project / ".screw" / "local" / "adaptive_prompts.json"
    prompts_path.parent.mkdir(parents=True, exist_ok=True)
    prompts_path.write_text('["this", "is", "a", "list"]', encoding="utf-8")

    engine.stage_adaptive_script(
        project_root=project, script_name="test-rej-shape", source="pass\n",
        meta={"name": "test-rej-shape", "created": "2026-04-20T10:00:00Z",
              "created_by": "t@e.co", "domain": "injection-input-handling",
              "description": "d", "target_patterns": ["x"]},
        session_id="sess-abc", target_gap=None,
    )
    response = engine.reject_staged_script(
        project_root=project, script_name="test-rej-shape",
        session_id="sess-abc", reason=None,
    )

    assert response["status"] == "rejected"
    import json as _json
    state = _json.loads(prompts_path.read_text(encoding="utf-8"))
    assert isinstance(state, dict)
    assert "test-rej-shape" in state.get("declined", [])


def test_reject_staged_script_delete_failure_returns_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """I-T5-2 regression: delete_staged_files ValueError must become an
    error-dict (error=delete_failed), not an uncaught exception. Symmetric
    with T4's wrap of the same staging helper."""
    from screw_agents.engine import ScanEngine
    from screw_agents.adaptive import staging as staging_module

    project = tmp_path / "project"
    project.mkdir()
    engine = ScanEngine.from_defaults()
    engine.stage_adaptive_script(
        project_root=project, script_name="test-rej-del-fail", source="pass\n",
        meta={"name": "test-rej-del-fail", "created": "2026-04-20T10:00:00Z",
              "created_by": "t@e.co", "domain": "injection-input-handling",
              "description": "d", "target_patterns": ["x"]},
        session_id="sess-abc", target_gap=None,
    )

    def boom(**kwargs):
        raise ValueError("simulated delete failure (EBUSY)")

    monkeypatch.setattr(staging_module, "delete_staged_files", boom)
    # engine imported delete_staged_files locally; patch via the local ref too.
    import screw_agents.engine as engine_module
    if hasattr(engine_module, "delete_staged_files"):
        monkeypatch.setattr(engine_module, "delete_staged_files", boom)

    response = engine.reject_staged_script(
        project_root=project, script_name="test-rej-del-fail",
        session_id="sess-abc", reason=None,
    )

    assert response["status"] == "error"
    assert response["error"] == "delete_failed"
    assert "simulated" in response["message"]
