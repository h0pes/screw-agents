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
