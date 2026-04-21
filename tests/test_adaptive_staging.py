"""Unit tests for adaptive/staging.py — filesystem + registry ops.

Scope: staging path resolution, file writes, registry append/query, fallback
walk, stale sweep. Signing is NOT tested here — that's test_adaptive_signing.py.
The full stage→promote→execute integration is test_adaptive_workflow_staged.py.
"""

from __future__ import annotations

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
        with pytest.raises(ValueError, match="collapse"):
            resolve_staging_dir(project, bad)


def test_resolve_staging_dir_rejects_path_traversal_chars(tmp_path: Path) -> None:
    from screw_agents.adaptive.staging import resolve_staging_dir

    project = tmp_path / "project"
    project.mkdir()

    for bad in ("a/b", "a\\b", "a\x00b"):
        with pytest.raises(ValueError, match="invalid path chars"):
            resolve_staging_dir(project, bad)


def test_resolve_staging_dir_accepts_dots_within_session_id(tmp_path: Path) -> None:
    """Regression for I-2: `a..b` is a legitimate name, not a traversal."""
    from screw_agents.adaptive.staging import resolve_staging_dir

    project = tmp_path / "project"
    project.mkdir()

    staging_dir = resolve_staging_dir(project, "a..b")
    assert staging_dir == project / ".screw" / "staging" / "a..b" / "adaptive-scripts"


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
