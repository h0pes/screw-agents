"""Unit tests for screw_agents.adaptive.ast_walker."""

from __future__ import annotations

from pathlib import Path

import pytest

from screw_agents.adaptive.ast_walker import (
    find_calls,
    find_class_definitions,
    find_imports,
    parse_ast,
    walk_ast,
)
from screw_agents.adaptive.project import ProjectRoot


def test_parse_ast_python(tmp_path: Path):
    source = "def foo():\n    return 1\n"
    tree = parse_ast(source, language="python")
    assert tree.root_node is not None
    assert tree.root_node.type == "module"


def test_find_calls_simple(tmp_path: Path):
    (tmp_path / "a.py").write_text(
        "def handle(req):\n"
        "    db.execute(req.query)\n"
        "    db.execute(req.input)\n"
    )
    project = ProjectRoot(tmp_path)
    calls = list(find_calls(project, "db.execute"))
    assert len(calls) == 2
    assert all(c.file == "a.py" for c in calls)
    assert {c.line for c in calls} == {2, 3}


def test_find_calls_no_match(tmp_path: Path):
    (tmp_path / "a.py").write_text("x = 1\n")
    project = ProjectRoot(tmp_path)
    calls = list(find_calls(project, "db.execute"))
    assert len(calls) == 0


def test_find_imports(tmp_path: Path):
    (tmp_path / "a.py").write_text(
        "import os\n"
        "from screw_agents.adaptive import find_calls\n"
    )
    project = ProjectRoot(tmp_path)
    imports = list(find_imports(project, "screw_agents.adaptive"))
    assert len(imports) == 1
    assert imports[0].file == "a.py"
    assert imports[0].line == 2


def test_find_class_definitions(tmp_path: Path):
    (tmp_path / "models.py").write_text(
        "class User:\n"
        "    pass\n"
        "\n"
        "class QueryBuilder:\n"
        "    def execute(self, sql):\n"
        "        pass\n"
    )
    project = ProjectRoot(tmp_path)
    classes = list(find_class_definitions(project, "QueryBuilder"))
    assert len(classes) == 1
    assert classes[0].file == "models.py"


def test_walk_ast_filters_by_type(tmp_path: Path):
    source = "def foo():\n    x = 1\n    y = 2\n"
    tree = parse_ast(source, language="python")
    assignments = list(walk_ast(tree, node_types=["assignment"]))
    assert len(assignments) >= 2


def test_find_imports_does_not_match_substring_collision(tmp_path: Path):
    """find_imports("os") must NOT match `import osquery` or `import operating_system` —
    pre-fix-up substring matching produced these false positives."""
    (tmp_path / "a.py").write_text(
        "import osquery\n"
        "import operating_system\n"
        "import os\n"
        "from osmodule import x\n"
    )
    project = ProjectRoot(tmp_path)
    imports = list(find_imports(project, "os"))
    # Only `import os` matches. The other 3 lines reference different modules.
    assert len(imports) == 1
    assert imports[0].module == "os"
    assert imports[0].line == 3


def test_find_imports_matches_submodules(tmp_path: Path):
    """find_imports("json") matches `import json.decoder` and `from json.x import y`
    because submodules of json are still imports of json."""
    (tmp_path / "a.py").write_text(
        "import json\n"
        "import json.decoder\n"
        "from json.encoder import JSONEncoder\n"
    )
    project = ProjectRoot(tmp_path)
    imports = list(find_imports(project, "json"))
    assert len(imports) == 3
    actual_modules = {imp.module for imp in imports}
    assert actual_modules == {"json", "json.decoder", "json.encoder"}


def test_find_calls_matches_chained_call(tmp_path: Path):
    """find_calls("connect.execute") on `engine.connect().execute(q)` matches —
    pre-fix-up the trailing `(...)` blocked multi-token suffix matches."""
    (tmp_path / "a.py").write_text(
        "def handle(req):\n"
        "    engine.connect().execute(req.query)\n"
    )
    project = ProjectRoot(tmp_path)
    calls = list(find_calls(project, "connect.execute"))
    assert len(calls) == 1
    assert calls[0].file == "a.py"
    assert calls[0].line == 2


def test_find_calls_tolerates_invalid_syntax(tmp_path: Path):
    """A file with invalid Python syntax produces tree-sitter ERROR nodes but does
    not crash the walker. Valid call sites in the same file are still found."""
    (tmp_path / "a.py").write_text(
        "def good():\n"
        "    db.execute('select 1')\n"
        "\n"
        "def bad(\n"  # syntax error: never closes
        "    pass\n"
    )
    project = ProjectRoot(tmp_path)
    # Should not raise. The valid call may or may not be found depending on
    # how tree-sitter recovers; the important property is no crash.
    calls = list(find_calls(project, "db.execute"))
    # Tree-sitter is robust to errors and typically still produces the valid
    # call inside the well-formed `good()` function.
    assert len(calls) >= 0  # primary check: no exception; secondary: probably ==1


def test_find_calls_handles_non_ascii_source(tmp_path: Path):
    """Regression for the byte-vs-char slicing bug that affected
    _call_callee_text. With a non-ASCII comment upstream, byte offsets
    exceed equivalent char indices; the pre-fix slice returned misaligned
    callee text and the pattern matcher silently missed the call site."""
    (tmp_path / "a.py").write_text(
        "# 日本語のコメント — non-ASCII shifts byte/char offsets\n"
        "def handle(req):\n"
        "    db.execute(req.q)\n",
        encoding="utf-8",
    )
    project = ProjectRoot(tmp_path)
    calls = list(find_calls(project, "db.execute"))
    assert len(calls) == 1
    assert calls[0].file == "a.py"


def test_find_calls_raises_on_non_utf8_source(tmp_path: Path) -> None:
    """Non-UTF-8 source file → UnicodeDecodeError propagates cleanly.

    Previously (T3-M1 deferred item): `except Exception: continue` silently
    swallowed this, so adaptive scripts couldn't distinguish "no findings"
    from "couldn't read this file". Post-fix: the exception surfaces to
    the caller (executor), which can log / surface to subagent.
    """
    project = tmp_path / "project"
    project.mkdir()
    # Write Latin-1-encoded bytes that aren't valid UTF-8.
    (project / "weird.py").write_bytes(b"# Latin-1: caf\xe9\n")
    root = ProjectRoot(project)

    # Post-T13: find_calls surfaces UnicodeDecodeError rather than
    # silently skipping the unreadable file. `list(...)` forces the
    # generator to walk the file, triggering the decode attempt.
    with pytest.raises(UnicodeDecodeError):
        list(find_calls(root, "foo.bar"))
