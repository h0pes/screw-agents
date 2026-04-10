"""Tests for the target resolver."""

import subprocess

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


def test_resolve_function_target(tmp_path):
    f = tmp_path / "example.py"
    f.write_text(
        "import os\n\n"
        "def foo():\n"
        "    return 1\n\n"
        "def bar():\n"
        "    return 2\n"
    )
    target = {"type": "function", "file": str(f), "name": "foo"}
    result = resolve_target(target)
    assert len(result) == 1
    assert "def foo" in result[0].content
    assert "def bar" not in result[0].content


def test_resolve_function_not_found(tmp_path):
    f = tmp_path / "example.py"
    f.write_text("def foo():\n    pass\n")
    target = {"type": "function", "file": str(f), "name": "nonexistent"}
    with pytest.raises(ValueError, match="not found"):
        resolve_target(target)


def test_resolve_class_target(tmp_path):
    f = tmp_path / "example.py"
    f.write_text(
        "class Foo:\n"
        "    def method(self):\n"
        "        pass\n\n"
        "class Bar:\n"
        "    pass\n"
    )
    target = {"type": "class", "file": str(f), "name": "Foo"}
    result = resolve_target(target)
    assert len(result) == 1
    assert "class Foo" in result[0].content
    assert "class Bar" not in result[0].content


def test_resolve_function_javascript(tmp_path):
    f = tmp_path / "example.js"
    f.write_text(
        "function greet(name) {\n"
        "  return 'Hello ' + name;\n"
        "}\n\n"
        "function farewell() {\n"
        "  return 'Bye';\n"
        "}\n"
    )
    target = {"type": "function", "file": str(f), "name": "greet"}
    result = resolve_target(target)
    assert len(result) == 1
    assert "greet" in result[0].content
    assert "farewell" not in result[0].content


def test_resolve_git_diff_unstaged(tmp_path):
    """Test git_diff with uncommitted changes in a temp git repo."""
    subprocess.run(["git", "init"], cwd=tmp_path, capture_output=True, check=True)
    subprocess.run(["git", "config", "user.email", "test@test.com"], cwd=tmp_path, capture_output=True, check=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=tmp_path, capture_output=True, check=True)

    f = tmp_path / "app.py"
    f.write_text("def safe():\n    return 1\n")
    subprocess.run(["git", "add", "."], cwd=tmp_path, capture_output=True, check=True)
    subprocess.run(["git", "commit", "-m", "init"], cwd=tmp_path, capture_output=True, check=True)

    f.write_text("def safe():\n    return 1\n\ndef vuln():\n    query = f'SELECT {x}'\n")

    target = {"type": "git_diff", "cwd": str(tmp_path)}
    result = resolve_target(target)
    assert len(result) >= 1
    assert any("vuln" in r.content for r in result)


def test_resolve_git_diff_staged(tmp_path):
    subprocess.run(["git", "init"], cwd=tmp_path, capture_output=True, check=True)
    subprocess.run(["git", "config", "user.email", "test@test.com"], cwd=tmp_path, capture_output=True, check=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=tmp_path, capture_output=True, check=True)

    f = tmp_path / "app.py"
    f.write_text("x = 1\n")
    subprocess.run(["git", "add", "."], cwd=tmp_path, capture_output=True, check=True)
    subprocess.run(["git", "commit", "-m", "init"], cwd=tmp_path, capture_output=True, check=True)

    f.write_text("x = 1\ny = 2\n")
    subprocess.run(["git", "add", "."], cwd=tmp_path, capture_output=True, check=True)
    f.write_text("x = 1\ny = 2\nz = 3\n")

    target = {"type": "git_diff", "staged_only": True, "cwd": str(tmp_path)}
    result = resolve_target(target)
    assert len(result) >= 1
    assert any("y = 2" in r.content for r in result)


def test_resolve_git_diff_base_head(tmp_path):
    subprocess.run(["git", "init"], cwd=tmp_path, capture_output=True, check=True)
    subprocess.run(["git", "config", "user.email", "test@test.com"], cwd=tmp_path, capture_output=True, check=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=tmp_path, capture_output=True, check=True)

    f = tmp_path / "app.py"
    f.write_text("original\n")
    subprocess.run(["git", "add", "."], cwd=tmp_path, capture_output=True, check=True)
    subprocess.run(["git", "commit", "-m", "init"], cwd=tmp_path, capture_output=True, check=True)

    base = subprocess.run(["git", "rev-parse", "HEAD"], cwd=tmp_path, capture_output=True, text=True, check=True).stdout.strip()

    f.write_text("modified\n")
    subprocess.run(["git", "add", "."], cwd=tmp_path, capture_output=True, check=True)
    subprocess.run(["git", "commit", "-m", "change"], cwd=tmp_path, capture_output=True, check=True)

    target = {"type": "git_diff", "base": base, "head": "HEAD", "cwd": str(tmp_path)}
    result = resolve_target(target)
    assert len(result) >= 1
    assert any("modified" in r.content for r in result)
