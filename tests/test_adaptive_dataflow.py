"""Unit tests for screw_agents.adaptive.dataflow."""

from __future__ import annotations

from pathlib import Path

import pytest

from screw_agents.adaptive.ast_walker import find_calls, parse_ast, walk_ast
from screw_agents.adaptive.dataflow import (
    get_call_args,
    get_parent_function,
    is_sanitized,
    is_user_input,
    resolve_variable,
    trace_dataflow,
)
from screw_agents.adaptive.project import ProjectRoot


def test_get_call_args(tmp_path: Path):
    (tmp_path / "a.py").write_text("db.execute('SELECT', user_input)\n")
    project = ProjectRoot(tmp_path)
    call = next(find_calls(project, "db.execute"))
    args = get_call_args(call)
    assert len(args) == 2


def test_is_user_input_recognizes_request_args(tmp_path: Path):
    (tmp_path / "a.py").write_text(
        "def handle(request):\n"
        "    q = request.args.get('q')\n"
        "    db.execute(q)\n"
    )
    project = ProjectRoot(tmp_path)
    call = next(find_calls(project, "db.execute"))
    args = get_call_args(call)
    source = (tmp_path / "a.py").read_text()
    # For this test, pass the variable node of q — dataflow check needs source context
    # The API accepts a node and returns True if it traces back to a known user-input source.
    assert is_user_input(args[0], language="python", source=source) is True


def test_is_user_input_false_for_literal(tmp_path: Path):
    (tmp_path / "a.py").write_text("db.execute('SELECT 1')\n")
    project = ProjectRoot(tmp_path)
    call = next(find_calls(project, "db.execute"))
    args = get_call_args(call)
    assert is_user_input(args[0], language="python", source="db.execute('SELECT 1')") is False


def test_get_parent_function(tmp_path: Path):
    (tmp_path / "a.py").write_text(
        "def handle(req):\n"
        "    db.execute(req.query)\n"
    )
    project = ProjectRoot(tmp_path)
    call = next(find_calls(project, "db.execute"))
    parent = get_parent_function(call.node)
    assert parent is not None
    assert parent.type == "function_definition"


def test_resolve_variable_finds_local_assignment(tmp_path: Path):
    source = "def handle():\n    q = 'hello'\n    use(q)\n"
    (tmp_path / "a.py").write_text(source)
    project = ProjectRoot(tmp_path)
    tree = parse_ast(source, language="python")
    # Find the `use(q)` call
    calls = [c for c in walk_ast(tree, node_types=["call"])]
    use_call = calls[0]
    q_arg = use_call.child_by_field_name("arguments").children[1]  # the `q` identifier

    # Find the enclosing function definition
    func = get_parent_function(use_call)
    resolved = resolve_variable(q_arg, scope=func)
    assert resolved is not None


def test_is_sanitized_recognizes_dataflow_chain(tmp_path: Path):
    """is_sanitized traces identifier bindings symmetrically to is_user_input:
    db.execute(s) where s = html.escape(q) — s is recognized as sanitized."""
    source = (
        "def render(request):\n"
        "    q = request.args.get('q')\n"
        "    s = html.escape(q)\n"
        "    db.execute(s)\n"
    )
    (tmp_path / "a.py").write_text(source)
    project = ProjectRoot(tmp_path)
    call = next(find_calls(project, "db.execute"))
    args = get_call_args(call)
    assert is_sanitized(args[0], language="python", source=source) is True


def test_is_user_input_traces_chained_assignment(tmp_path: Path):
    """is_user_input follows multi-step identifier chains within the same scope:
    db.execute(z) where z = y, y = x, x = request.args.get(...) — depth 3."""
    source = (
        "def handle(request):\n"
        "    x = request.args.get('q')\n"
        "    y = x\n"
        "    z = y\n"
        "    db.execute(z)\n"
    )
    (tmp_path / "a.py").write_text(source)
    project = ProjectRoot(tmp_path)
    call = next(find_calls(project, "db.execute"))
    args = get_call_args(call)
    assert is_user_input(args[0], language="python", source=source) is True


def test_is_user_input_bounded_on_circular_binding(tmp_path: Path):
    """Cycle detection prevents infinite recursion on circular bindings.
    db.execute(a) where a = b, b = a — neither chains to a known source, returns False."""
    source = (
        "def handle():\n"
        "    a = b\n"
        "    b = a\n"
        "    db.execute(a)\n"
    )
    (tmp_path / "a.py").write_text(source)
    project = ProjectRoot(tmp_path)
    call = next(find_calls(project, "db.execute"))
    args = get_call_args(call)
    # Must return False without raising (cycle is broken by the seen-set guard).
    assert is_user_input(args[0], language="python", source=source) is False


def test_is_user_input_handles_non_ascii_source(tmp_path: Path):
    """Regression for MF-1: byte-vs-char slicing bug. With a non-ASCII comment
    upstream of the call, byte offsets exceed equivalent char indices; the
    pre-fix slice silently returned wrong text and the helper degraded to
    always-False even on the canonical injection pattern."""
    source = (
        "# 日本語のコメント — non-ASCII content shifts byte vs char offsets\n"
        "def handle(request):\n"
        "    q = request.args.get('q')\n"
        "    db.execute(q)\n"
    )
    (tmp_path / "a.py").write_text(source, encoding="utf-8")
    project = ProjectRoot(tmp_path)
    call = next(find_calls(project, "db.execute"))
    args = get_call_args(call)
    # Same source string the helpers will slice into.
    actual_source = (tmp_path / "a.py").read_text(encoding="utf-8")
    assert is_user_input(args[0], language="python", source=actual_source) is True
