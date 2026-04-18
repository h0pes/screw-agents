"""Dataflow helpers for adaptive analysis scripts.

Simple intraprocedural dataflow primitives:
- trace_dataflow: walk assignments backward from a node
- is_user_input: check if a node reaches a known source of user input
- is_sanitized: check if a node passes through a known sanitizer
- get_call_args: extract argument nodes from a call
- get_parent_function: find the enclosing function definition
- resolve_variable: find a variable's assignment within a scope

These are best-effort heuristics tuned to the AST, not a full dataflow analyzer.
They're sufficient for the targeted scripts adaptive mode generates (50-150
lines of focused pattern matching), not for whole-program analysis.
"""

from __future__ import annotations

from typing import Iterator

from tree_sitter import Node


# Per-language source and sanitizer lists, keyed by language name.
# These mirror (a subset of) what the YAML agents declare in their detection_heuristics.
_USER_INPUT_SOURCES: dict[str, list[str]] = {
    "python": [
        "request.args",
        "request.form",
        "request.json",
        "request.values",
        "request.files",
        "request.cookies",
        "request.headers",
        "request.GET",
        "request.POST",
        "sys.argv",
        "os.environ",
        "input(",
    ],
}


_SANITIZERS: dict[str, list[str]] = {
    "python": [
        "html.escape",
        "markupsafe.escape",
        "cgi.escape",
        "urllib.parse.quote",
        "bleach.clean",
        "shlex.quote",
    ],
}


def trace_dataflow(node: Node) -> Iterator[Node]:
    """Walk upward from `node` yielding each assignment target that flows into it.

    Best-effort: handles direct assignments and augmented assignments within
    the same scope. Does NOT follow returns, global state, or cross-function flows.
    """
    current: Node | None = node
    seen: set[int] = set()
    while current is not None:
        if id(current) in seen:
            return
        seen.add(id(current))
        yield current
        # Walk up to parent; if parent is an assignment, record its RHS as the dataflow target
        parent = current.parent
        if parent is None:
            return
        if parent.type == "assignment":
            rhs = parent.child_by_field_name("right")
            if rhs is not None:
                current = rhs
                continue
        current = parent


def is_user_input(node: Node, *, language: str, source: str) -> bool:
    """Return True if `node`'s value reaches a known user-input source pattern.

    Performs a bounded intraprocedural dataflow trace: if `node` is an identifier,
    walks via `resolve_variable` through binding chains within the enclosing
    function (depth-limited, cycle-detected) and checks each resolved RHS for a
    source-pattern substring match. For non-identifier nodes — or when no binding
    is found — checks only the node's immediate text.

    The trace follows simple `name = expr` assignments. Conditional assignments,
    aliased imports, returns, and cross-function flows are NOT followed.

    Chain semantics for adaptive script authors:
    - The trace follows ONLY `name1 = name2`-style identifier bindings.
    - Terminates at call/attribute/subscript RHSs (e.g., `x = obj.attr` ends
      there); the terminator's text gets a single pattern check.
    - Function parameters, loop variables, context-manager bindings, and
      module-level assignments are not resolvable. Recommended idiom:
      `if is_user_input(arg) and not is_sanitized(arg): emit_finding(...)`,
      understanding both helpers can return False on chain terminators.
    """
    if language not in _USER_INPUT_SOURCES:
        return False
    return _matches_pattern_via_dataflow(
        node, source=source, patterns=_USER_INPUT_SOURCES[language]
    )


def is_sanitized(node: Node, *, language: str, source: str) -> bool:
    """Return True if `node`'s value passes through a known sanitizer.

    Symmetric to `is_user_input`: same bounded intraprocedural dataflow trace,
    checking each resolved value's text against the sanitizer pattern list.
    Lets adaptive scripts distinguish `db.execute(html.escape(q))` from
    `db.execute(q)` even when the call arg is an identifier whose binding is
    several lines above.

    Chain semantics for adaptive script authors:
    - The trace follows ONLY `name1 = name2`-style identifier bindings.
    - Terminates at call/attribute/subscript RHSs (e.g., `x = obj.attr` ends
      there); the terminator's text gets a single pattern check.
    - Function parameters, loop variables, context-manager bindings, and
      module-level assignments are not resolvable. Recommended idiom:
      `if is_user_input(arg) and not is_sanitized(arg): emit_finding(...)`,
      understanding both helpers can return False on chain terminators.
    """
    if language not in _SANITIZERS:
        return False
    return _matches_pattern_via_dataflow(
        node, source=source, patterns=_SANITIZERS[language]
    )


def match_pattern(node: Node, *, source: str, patterns: list[str]) -> bool:
    """Public entry point to the bounded dataflow-traced pattern matcher.

    Use when you need to check a node against project-specific patterns
    beyond the hardcoded `_USER_INPUT_SOURCES` / `_SANITIZERS` lists used
    by `is_user_input` / `is_sanitized`. Same semantics: direct text check
    first, then bounded identifier-binding trace within the enclosing
    function (depth-limited, cycle-detected).

    Adaptive scripts use this to detect project-specific abstractions —
    custom ORMs, in-house templating engines, proprietary frameworks —
    that the YAML-encoded pattern lists cannot anticipate. Without it,
    adaptive scripts would either re-implement the trace algorithm or
    fall back to text-only checks that lose dataflow precision.

    Example: detecting a project-specific ORM sink:
        if match_pattern(arg, source=src, patterns=["MyORM.run_unsafe"]):
            emit_finding(cwe="CWE-89", ...)

    Chain semantics for adaptive script authors:
    - The trace follows ONLY `name1 = name2`-style identifier bindings.
    - Terminates at call/attribute/subscript RHSs (e.g., `x = obj.attr` ends
      there); the terminator's text gets a single pattern check.
    - Function parameters, loop variables, context-manager bindings, and
      module-level assignments are not resolvable.
    """
    return _matches_pattern_via_dataflow(node, source=source, patterns=patterns)


def get_call_args(call_site) -> list[Node]:
    """Extract the argument nodes from a CallSite (or raw tree-sitter call node).

    Accepts either a CallSite dataclass or a raw Node for convenience.
    """
    call_node = call_site.node if hasattr(call_site, "node") else call_site
    arg_list = call_node.child_by_field_name("arguments")
    if arg_list is None:
        return []
    # Filter out punctuation (parens, commas); keep only actual argument nodes.
    return [
        child for child in arg_list.children
        if child.type not in ("(", ")", ",")
    ]


def get_parent_function(node: Node) -> Node | None:
    """Walk up the AST to find the enclosing function_definition node.

    Returns None if `node` is module-level code OR inside a `lambda` (which
    tree-sitter Python types as `lambda`, not `function_definition`). Lambda
    bodies are syntactically restricted to a single expression in Python, so
    intraprocedural taint analysis inside them is rarely useful.
    """
    current = node.parent
    while current is not None:
        if current.type == "function_definition":
            return current
        current = current.parent
    return None


def resolve_variable(identifier_node: Node, *, scope: Node) -> Node | None:
    """Find the most recent assignment to the identifier within `scope`.

    Walks the scope's body looking for assignment nodes whose LHS matches the
    identifier's text. Returns the assignment's RHS node, or None if not found.

    Limitations: only direct `name = expr` assignments inside `scope.body` are
    considered. Function parameters, `for x in ...:` loop variables, `with ... as x:`
    context-manager bindings, augmented assignments (`x += y`), and conditional
    branch reassignments (`if cond: x = a; else: x = b`) are NOT followed.
    Returns the lexically last matching assignment within the body, ignoring
    control-flow paths.
    """
    if scope is None:
        return None

    # Get identifier name
    # (identifier_node may itself be the LHS or a use-site identifier)
    ident_text = identifier_node.text.decode("utf-8") if identifier_node.text else ""
    if not ident_text:
        return None

    body = scope.child_by_field_name("body")
    if body is None:
        return None

    most_recent: Node | None = None
    for child in body.children:
        # Direct assignment: `x = ...`
        if child.type == "expression_statement":
            expr = child.children[0] if child.children else None
            if expr is not None and expr.type == "assignment":
                lhs = expr.child_by_field_name("left")
                if lhs is not None and lhs.text and lhs.text.decode("utf-8") == ident_text:
                    most_recent = expr.child_by_field_name("right")
    return most_recent


_DATAFLOW_TRACE_DEPTH_LIMIT = 8


def _matches_pattern_via_dataflow(
    node: Node, *, source: str, patterns: list[str]
) -> bool:
    """Check `node`'s text — and any value reached by tracing identifier
    bindings within the enclosing function — against the given pattern list.

    Bounded by `_DATAFLOW_TRACE_DEPTH_LIMIT` plus a per-call seen-set keyed on
    (start_byte, end_byte) tuples — stable across tree-sitter Node wrapper
    recreations — to prevent infinite recursion on circular bindings (e.g.,
    `a = b; b = a`). Both guards are load-bearing.
    """
    source_bytes = source.encode("utf-8")
    node_text = source_bytes[node.start_byte:node.end_byte].decode("utf-8")
    if any(p in node_text for p in patterns):
        return True

    if node.type != "identifier":
        return False

    scope = get_parent_function(node)
    if scope is None:
        return False

    seen: set[tuple[int, int]] = set()
    current: Node | None = node
    depth = 0
    while (
        current is not None
        and current.type == "identifier"
        and depth < _DATAFLOW_TRACE_DEPTH_LIMIT
    ):
        key = (current.start_byte, current.end_byte)
        if key in seen:
            return False
        seen.add(key)

        resolved = resolve_variable(current, scope=scope)
        if resolved is None:
            return False
        resolved_text = source_bytes[resolved.start_byte:resolved.end_byte].decode("utf-8")
        if any(p in resolved_text for p in patterns):
            return True
        current = resolved
        depth += 1
    return False
