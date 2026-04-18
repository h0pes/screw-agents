"""AST walking helpers for adaptive analysis scripts.

Provides a high-level interface over tree-sitter: parse source into an AST,
walk nodes filtered by type, locate call sites by pattern, find imports and
class definitions.

All helpers operate on files within a `ProjectRoot` — they cannot reach
outside the project.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterator

from tree_sitter import Node, Tree

from screw_agents.adaptive.project import ProjectRoot
from screw_agents.treesitter import get_parser


@dataclass(frozen=True)
class CallSite:
    """A located function/method call in the source code."""

    file: str
    line: int
    column: int
    call_text: str
    node: Node  # raw tree-sitter node for further inspection


@dataclass(frozen=True)
class ImportNode:
    """A located import statement."""

    file: str
    line: int
    module: str
    node: Node


@dataclass(frozen=True)
class ClassNode:
    """A located class definition."""

    file: str
    line: int
    name: str
    node: Node


def parse_ast(source: str, *, language: str) -> Tree:
    """Parse source text into a tree-sitter Tree.

    Args:
        source: source code as a string.
        language: tree-sitter language name (e.g., "python", "javascript").

    Returns:
        Parsed Tree. The `root_node` attribute gives the top of the AST.
    """
    return get_parser(language).parse(source.encode("utf-8"))


def walk_ast(tree: Tree, *, node_types: list[str]) -> Iterator[Node]:
    """Yield every node in the tree whose `.type` matches one of the given types."""
    yield from _walk_nodes(tree.root_node, set(node_types))


def find_calls(project: ProjectRoot, pattern: str) -> Iterator[CallSite]:
    """Locate every call site matching a pattern across all Python files in the project.

    The pattern is a simple dot-separated path like `"QueryBuilder.execute"` or
    `"db.execute"`. The walker matches any call whose function/attribute chain
    ends with the same tokens.

    For Phase 3b, this is Python-only. Future phases may extend to other languages.

    Limitations:
    - Bare single-token patterns (e.g., `"execute"`) match every call whose
      trailing identifier matches across all modules and classes. For precision,
      prefer dotted patterns like `"db.execute"` or `"Cursor.execute"`.
    - Alias resolution is not supported. `from db import execute as run; run()`
      is invisible to `find_calls(project, "execute")` because the call's
      textual callee is `"run"`, not `"execute"`.
    """
    target_tokens = pattern.split(".")
    for rel_path in project.list_files("**/*.py"):
        try:
            source = project.read_file(rel_path)
        except Exception:
            continue

        tree = parse_ast(source, language="python")
        for call in walk_ast(tree, node_types=["call"]):
            text = _call_callee_text(call, source)
            if _matches_pattern(text, target_tokens):
                yield CallSite(
                    file=rel_path,
                    line=call.start_point[0] + 1,
                    column=call.start_point[1],
                    call_text=text,
                    node=call,
                )


def find_imports(project: ProjectRoot, module_name: str) -> Iterator[ImportNode]:
    """Locate every import statement that imports the given module (Python only).

    Matches three forms:
    - `import module_name` (and `import module_name as alias`)
    - `import module_name.submodule` (any depth)
    - `from module_name import X` (and `from module_name.sub import X`)

    The match is on the actual imported module token extracted from the AST,
    NOT a substring match — `find_imports(project, "os")` does NOT match
    `import osquery` or `import operating_system`. Submodule prefixes match:
    `find_imports(project, "json")` returns hits for `import json.decoder`.

    The yielded ImportNode.module field carries the actual imported module
    text (e.g., "json.decoder"), not the search query.

    Alias resolution is NOT performed — `import os as o` matches the search
    `"os"` (the imported module) but downstream `find_calls(project, "os")`
    would not see calls through `o.*`.
    """
    for rel_path in project.list_files("**/*.py"):
        try:
            source = project.read_file(rel_path)
        except Exception:
            continue

        tree = parse_ast(source, language="python")
        for node in walk_ast(tree, node_types=["import_statement", "import_from_statement"]):
            candidates: list[Node] = []
            if node.type == "import_from_statement":
                # `from MODULE import name1, name2` — only the MODULE position counts
                mod_node = node.child_by_field_name("module_name")
                if mod_node is not None:
                    candidates.append(mod_node)
            else:
                # `import MOD1, MOD2 as alias` — every imported module counts
                # `import_statement.name` is repeated; each child is dotted_name or
                # aliased_import (which wraps a dotted_name as its 'name' field).
                for child in node.children_by_field_name("name"):
                    if child.type == "aliased_import":
                        dn = child.child_by_field_name("name")
                        if dn is not None:
                            candidates.append(dn)
                    else:
                        # bare dotted_name child
                        candidates.append(child)

            for cand in candidates:
                actual = source.encode("utf-8")[cand.start_byte:cand.end_byte].decode("utf-8")
                if actual == module_name or actual.startswith(module_name + "."):
                    yield ImportNode(
                        file=rel_path,
                        line=node.start_point[0] + 1,
                        module=actual,
                        node=node,
                    )
                    break  # one match per import statement


def find_class_definitions(project: ProjectRoot, class_name: str) -> Iterator[ClassNode]:
    """Locate class definitions by name (Python only).

    Matches classes whose AST `name` field equals `class_name` exactly. Aliased
    class definitions and dynamically-created classes are not supported.
    """
    for rel_path in project.list_files("**/*.py"):
        try:
            source = project.read_file(rel_path)
        except Exception:
            continue

        tree = parse_ast(source, language="python")
        for cls in walk_ast(tree, node_types=["class_definition"]):
            name_node = cls.child_by_field_name("name")
            if name_node is None:
                continue
            name = source.encode("utf-8")[name_node.start_byte:name_node.end_byte].decode("utf-8")
            if name == class_name:
                yield ClassNode(
                    file=rel_path,
                    line=cls.start_point[0] + 1,
                    name=name,
                    node=cls,
                )


def _call_callee_text(call_node: Node, source: str) -> str:
    """Extract the text of the callee portion of a call node."""
    function_node = call_node.child_by_field_name("function")
    if function_node is None:
        return ""
    return source.encode("utf-8")[function_node.start_byte:function_node.end_byte].decode("utf-8")


_CALL_PARENS_RE = re.compile(r"\([^()]*\)")


def _matches_pattern(callee_text: str, target_tokens: list[str]) -> bool:
    """Check if a callee text ends with the given token sequence.

    Strips `(...)` segments first so chained calls like `obj.attr().method`
    contribute clean tokens `["obj", "attr", "method"]`. Note: nested parens
    are stripped iteratively until no more match.

    Example: callee_text=`"engine.connect().execute"` matches target_tokens
    `["execute"]`, `["connect", "execute"]`, AND `["engine", "connect", "execute"]`.
    """
    cleaned = callee_text
    while True:
        new = _CALL_PARENS_RE.sub("", cleaned)
        if new == cleaned:
            break
        cleaned = new
    callee_tokens = [t for t in cleaned.split(".") if t]
    if len(callee_tokens) < len(target_tokens):
        return False
    return callee_tokens[-len(target_tokens):] == target_tokens


def _walk_nodes(node: Node, types: set[str]) -> Iterator[Node]:
    """Recursively yield every descendant of `node` (inclusive) whose .type is in `types`."""
    if node.type in types:
        yield node
    for child in node.children:
        yield from _walk_nodes(child, types)
