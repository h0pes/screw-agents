"""AST walking helpers for adaptive analysis scripts.

Provides a high-level interface over tree-sitter: parse source into an AST,
walk nodes filtered by type, locate call sites by pattern, find imports and
class definitions.

All helpers operate on files within a `ProjectRoot` — they cannot reach
outside the project.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterator

from tree_sitter import Node, Parser, Tree

from screw_agents.adaptive.project import ProjectRoot
from screw_agents.treesitter import get_language


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
    lang = get_language(language)
    parser = Parser()
    parser.language = lang
    return parser.parse(source.encode("utf-8"))


def walk_ast(tree: Tree, *, node_types: list[str]) -> Iterator[Node]:
    """Yield every node in the tree whose `.type` matches one of the given types."""
    types = set(node_types)

    def _walk(node: Node) -> Iterator[Node]:
        if node.type in types:
            yield node
        for child in node.children:
            yield from _walk(child)

    yield from _walk(tree.root_node)


def find_calls(project: ProjectRoot, pattern: str) -> Iterator[CallSite]:
    """Locate every call site matching a pattern across all Python files in the project.

    The pattern is a simple dot-separated path like `"QueryBuilder.execute"` or
    `"db.execute"`. The walker matches any call whose function/attribute chain
    ends with the same tokens.

    For Phase 3b, this is Python-only. Future phases may extend to other languages.
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
    """Locate every import statement that references the given module name.

    Matches both `import module` and `from module import X` forms.
    """
    for rel_path in project.list_files("**/*.py"):
        try:
            source = project.read_file(rel_path)
        except Exception:
            continue

        tree = parse_ast(source, language="python")
        for node in walk_ast(tree, node_types=["import_statement", "import_from_statement"]):
            text = source[node.start_byte:node.end_byte]
            if module_name in text:
                yield ImportNode(
                    file=rel_path,
                    line=node.start_point[0] + 1,
                    module=module_name,
                    node=node,
                )


def find_class_definitions(project: ProjectRoot, class_name: str) -> Iterator[ClassNode]:
    """Locate class definitions by name."""
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
            name = source[name_node.start_byte:name_node.end_byte]
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
    return source[function_node.start_byte:function_node.end_byte]


def _matches_pattern(callee_text: str, target_tokens: list[str]) -> bool:
    """Check if a callee text ends with the given token sequence.

    Example: `"self.db.execute"` matches target_tokens `["db", "execute"]`.
    """
    callee_tokens = [t for t in callee_text.replace("(", "").split(".") if t]
    if len(callee_tokens) < len(target_tokens):
        return False
    return callee_tokens[-len(target_tokens):] == target_tokens
