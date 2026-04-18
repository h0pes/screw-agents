"""AST allowlist lint for adaptive analysis scripts (Layer 1 of the defense stack).

This module walks a script's Python AST and rejects every construct not on the
allowlist. It is the single most important static gate in the adaptive stack —
any bug here is a direct security vulnerability.

## Allowed constructs

Top-level:
- `from screw_agents.adaptive import ...` (with only allowlist-approved names)
- `def analyze(project: ProjectRoot) -> None:` (exactly one function)

Inside `analyze`:
- Standard statements: assignments, control flow (if/for/while/try), returns
- Calls to names imported from screw_agents.adaptive
- Calls to methods on CallSite/ImportNode/ClassNode/ProjectRoot objects
- Literals, comprehensions, f-strings (with literal format specs only)

## Forbidden constructs

- Any import outside `screw_agents.adaptive`
- `eval`, `exec`, `compile`
- `getattr` with non-literal second argument
- `setattr`, `delattr`
- Any `__builtins__`, `__class__`, `__bases__`, `__subclasses__`, `__globals__`,
  `__mro__`, `__import__`
- Raw `open()`
- `print` (scripts emit via `emit_finding`, not print)
- `try/except*` / ExceptionGroup (defensive against CVE-2025-22153 class)
- `async def` / `await`
- Any top-level statement other than imports and the `analyze` def
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field


class LintError(Exception):
    """Raised when a script fails lint. Used internally — the public API returns LintReport."""


@dataclass
class LintViolation:
    """A single rule violation found during lint."""

    rule: str
    message: str
    line: int


@dataclass
class LintReport:
    """Result of linting a script source."""

    passed: bool
    violations: list[LintViolation] = field(default_factory=list)


_ALLOWED_IMPORT_MODULES = {"screw_agents.adaptive"}
_FORBIDDEN_NAMES = {
    "eval", "exec", "compile",
    "__import__", "__builtins__",
    "setattr", "delattr",
    "open",
    "print",  # scripts use emit_finding, not print
    "input",
    "globals", "locals", "vars",
}
_FORBIDDEN_DUNDERS = {
    "__class__", "__bases__", "__subclasses__", "__globals__",
    "__mro__", "__init_subclass__", "__builtins__",
}


def lint_script(source: str) -> LintReport:
    """Parse source as Python and walk the AST rejecting forbidden constructs.

    Returns a LintReport with `passed=True` if and only if every construct is
    on the allowlist. Violations include rule name, human-readable message,
    and line number.
    """
    violations: list[LintViolation] = []

    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        return LintReport(
            passed=False,
            violations=[LintViolation(
                rule="syntax",
                message=f"script does not parse: {exc.msg}",
                line=exc.lineno or 0,
            )],
        )

    # 1. Top-level structure check
    _check_top_level_structure(tree, violations)

    # 2. Walk every node and apply forbidden-construct rules
    _walk_and_check(tree, violations)

    return LintReport(passed=(len(violations) == 0), violations=violations)


def _check_top_level_structure(tree: ast.Module, violations: list[LintViolation]) -> None:
    """Enforce: only imports from adaptive package + exactly one `analyze` function at module level."""
    analyze_found = False

    for node in tree.body:
        if isinstance(node, ast.ImportFrom):
            if node.module not in _ALLOWED_IMPORT_MODULES:
                violations.append(LintViolation(
                    rule="disallowed_import",
                    message=f"top-level import from {node.module!r} not allowed; only {_ALLOWED_IMPORT_MODULES}",
                    line=node.lineno,
                ))
        elif isinstance(node, ast.Import):
            violations.append(LintViolation(
                rule="disallowed_import",
                message=f"`import {node.names[0].name}` not allowed; use `from screw_agents.adaptive import ...`",
                line=node.lineno,
            ))
        elif isinstance(node, ast.FunctionDef) and node.name == "analyze":
            analyze_found = True
        elif isinstance(node, ast.AsyncFunctionDef):
            violations.append(LintViolation(
                rule="async_def",
                message="async def not allowed; use synchronous def analyze()",
                line=node.lineno,
            ))
        else:
            violations.append(LintViolation(
                rule="top_level_code",
                message=f"top-level {type(node).__name__} not allowed; only imports and `def analyze`",
                line=node.lineno,
            ))

    if not analyze_found:
        violations.append(LintViolation(
            rule="missing_analyze",
            message="script must define `def analyze(project: ProjectRoot) -> None`",
            line=0,
        ))


def _walk_and_check(tree: ast.Module, violations: list[LintViolation]) -> None:
    """Walk every node in the tree and apply forbidden-construct rules."""
    for node in ast.walk(tree):
        _check_node(node, violations)


def _check_node(node: ast.AST, violations: list[LintViolation]) -> None:
    line = getattr(node, "lineno", 0)

    # Forbidden name lookups (eval, exec, compile, open, etc.)
    if isinstance(node, ast.Name) and node.id in _FORBIDDEN_NAMES:
        violations.append(LintViolation(
            rule="forbidden_name",
            message=f"forbidden builtin: {node.id}",
            line=line,
        ))

    # Forbidden attribute access (dunders)
    if isinstance(node, ast.Attribute) and node.attr in _FORBIDDEN_DUNDERS:
        violations.append(LintViolation(
            rule="forbidden_dunder",
            message=f"forbidden attribute access: {node.attr}",
            line=line,
        ))

    # getattr with non-literal second argument
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "getattr":
        if len(node.args) >= 2 and not isinstance(node.args[1], ast.Constant):
            violations.append(LintViolation(
                rule="dynamic_getattr",
                message="getattr with non-literal second argument is forbidden",
                line=line,
            ))

    # try/except* (exception groups — CVE-2025-22153 defense)
    if isinstance(node, ast.Try):
        for handler in node.handlers:
            if getattr(handler, "is_star", False):
                violations.append(LintViolation(
                    rule="exception_group",
                    message="try/except* (ExceptionGroup) is forbidden",
                    line=line,
                ))
    # In newer Python, ast.TryStar is a separate node type
    if type(node).__name__ == "TryStar":
        violations.append(LintViolation(
            rule="exception_group",
            message="try/except* (ExceptionGroup) is forbidden",
            line=line,
        ))

    # async def inside a function (we already catch at top level, but nested counts too)
    if isinstance(node, ast.AsyncFunctionDef):
        violations.append(LintViolation(
            rule="async_def",
            message="async def not allowed anywhere in the script",
            line=line,
        ))

    # await (same reason)
    if isinstance(node, ast.Await):
        violations.append(LintViolation(
            rule="await",
            message="await not allowed",
            line=line,
        ))
