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
