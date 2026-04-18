"""Unit tests for screw_agents.adaptive.project — ProjectRoot filesystem chokepoint."""

from __future__ import annotations

from pathlib import Path

import pytest

from screw_agents.adaptive.project import ProjectRoot, ProjectPathError


def test_project_root_reads_file_within_root(tmp_path: Path):
    (tmp_path / "a.py").write_text("hello")
    project = ProjectRoot(tmp_path)
    assert project.read_file("a.py") == "hello"


def test_project_root_rejects_path_outside_root(tmp_path: Path):
    outside = tmp_path.parent / "outside.py"
    outside.write_text("secret")
    project = ProjectRoot(tmp_path)

    with pytest.raises(ProjectPathError, match="outside project root"):
        project.read_file("../outside.py")


def test_project_root_rejects_absolute_path(tmp_path: Path):
    project = ProjectRoot(tmp_path)
    with pytest.raises(ProjectPathError, match="absolute"):
        project.read_file("/etc/passwd")


def test_project_root_rejects_symlink_escape(tmp_path: Path):
    """A symlink inside project root pointing OUTSIDE is rejected."""
    (tmp_path / "outside.py").symlink_to("/etc/passwd")
    project = ProjectRoot(tmp_path)
    with pytest.raises(ProjectPathError):
        project.read_file("outside.py")


def test_project_root_list_files_within_root(tmp_path: Path):
    (tmp_path / "a.py").write_text("")
    (tmp_path / "b.py").write_text("")
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "c.py").write_text("")

    project = ProjectRoot(tmp_path)
    files = sorted(project.list_files("**/*.py"))
    assert "a.py" in files
    assert "b.py" in files
    assert "sub/c.py" in files


def test_project_root_list_files_does_not_leak_outside(tmp_path: Path):
    (tmp_path.parent / "leaked.py").write_text("secret")
    (tmp_path / "a.py").write_text("")
    project = ProjectRoot(tmp_path)
    files = project.list_files("**/*.py")
    assert "leaked.py" not in files


def test_list_files_rejects_absolute_pattern(tmp_path: Path):
    """Absolute glob patterns are rejected with ProjectPathError, not Python's
    internal NotImplementedError from Path.glob (Python 3.12+)."""
    project = ProjectRoot(tmp_path)
    with pytest.raises(ProjectPathError, match="absolute"):
        project.list_files("/etc/*")


def test_list_files_pattern_injection_with_parent_traversal(tmp_path: Path):
    """A pattern like '../**/*' returns [] because every escaped match is
    filtered by _resolve_and_check, even though raw glob does not normalize '..'."""
    # Create a sibling file that the malicious pattern would hit
    (tmp_path.parent / "sibling.py").write_text("secret")
    (tmp_path / "a.py").write_text("")

    project = ProjectRoot(tmp_path)
    files = project.list_files("../**/*.py")
    assert "sibling.py" not in files
    # The defense-in-depth check filters every match — result is empty for
    # patterns that ONLY produce escaped matches.
    assert all(".." not in f for f in files)


def test_project_root_rejects_intermediate_symlink_escape(tmp_path: Path):
    """A directory symlink inside the project root pointing OUTSIDE is rejected
    when traversed via a relative path. resolve() follows symlinks at every
    component, so '<sub_link>/passwd' resolves to '/etc/passwd' and fails
    relative_to."""
    (tmp_path / "sub_link").symlink_to("/etc")
    project = ProjectRoot(tmp_path)
    with pytest.raises(ProjectPathError):
        project.read_file("sub_link/passwd")


def test_project_root_constructor_rejects_non_directory(tmp_path: Path):
    """Constructor raises ValueError if root is a file or does not exist."""
    file_path = tmp_path / "not-a-dir.txt"
    file_path.write_text("")
    with pytest.raises(ValueError, match="not a directory"):
        ProjectRoot(file_path)

    missing = tmp_path / "does-not-exist"
    with pytest.raises(ValueError, match="not a directory"):
        ProjectRoot(missing)


def test_read_file_raises_file_not_found(tmp_path: Path):
    """read_file on a missing path inside root raises FileNotFoundError per
    the docstring contract (NOT ProjectPathError — the path is valid, the
    file just doesn't exist)."""
    project = ProjectRoot(tmp_path)
    with pytest.raises(FileNotFoundError):
        project.read_file("nope.py")
