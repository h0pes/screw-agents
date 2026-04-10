"""Tests for the target resolver."""

import pytest

from screw_agents.resolver import resolve_target, ResolvedCode


def test_resolve_file_target(fixtures_dir):
    target = {"type": "file", "path": str(fixtures_dir / "sqli" / "vulnerable" / "python_dbapi_fstring.py")}
    result = resolve_target(target)
    assert isinstance(result, list)
    assert len(result) == 1
    assert isinstance(result[0], ResolvedCode)
    assert "SELECT" in result[0].content or "select" in result[0].content.lower()
    assert result[0].file_path.endswith(".py")


def test_resolve_file_target_nonexistent():
    target = {"type": "file", "path": "/nonexistent/file.py"}
    with pytest.raises(FileNotFoundError):
        resolve_target(target)


def test_resolve_glob_target(fixtures_dir):
    target = {
        "type": "glob",
        "pattern": str(fixtures_dir / "sqli" / "vulnerable" / "*.py"),
    }
    result = resolve_target(target)
    assert len(result) >= 1
    assert all(r.file_path.endswith(".py") for r in result)


def test_resolve_glob_with_exclude(fixtures_dir):
    target = {
        "type": "glob",
        "pattern": str(fixtures_dir / "sqli" / "**" / "*.py"),
        "exclude": ["**/safe/**"],
    }
    result = resolve_target(target)
    assert all("safe" not in r.file_path for r in result)


def test_resolve_lines_single_line(tmp_path):
    f = tmp_path / "test.py"
    f.write_text("line1\nline2\nline3\nline4\nline5\n")
    target = {"type": "lines", "file": str(f), "range": 3}
    result = resolve_target(target)
    assert len(result) == 1
    assert result[0].content.strip() == "line3"


def test_resolve_lines_range(tmp_path):
    f = tmp_path / "test.py"
    f.write_text("line1\nline2\nline3\nline4\nline5\n")
    target = {"type": "lines", "file": str(f), "range": [2, 4]}
    result = resolve_target(target)
    assert len(result) == 1
    assert "line2" in result[0].content
    assert "line4" in result[0].content


def test_resolve_unsupported_type():
    target = {"type": "unknown_type"}
    with pytest.raises(ValueError, match="Unsupported target type"):
        resolve_target(target)
