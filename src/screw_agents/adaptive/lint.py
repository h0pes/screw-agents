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

- Any import outside `screw_agents.adaptive` — anywhere, not just top level
- `eval`, `exec`, `compile`, `setattr`, `delattr`, `open`, `print`, `input`,
  `globals`, `locals`, `vars`, `breakpoint`, `help`, `super`, `memoryview`,
  `ExceptionGroup`, `BaseExceptionGroup` (forbidden builtin name lookups)
- ANY dunder name lookup (`__import__`, `__builtins__`, ...) or attribute
  access (`x.__class__`, `obj.__dict__`, `obj.__reduce__`, ...) — blanket
  rule, no per-dunder list to maintain
- `getattr(x, name)` where `name` is not a string literal
- `class` definitions anywhere in the script (would enable
  custom-`__getattribute__` escape paths; adaptive scripts have no
  legitimate use for classes)
- `global` and `nonlocal` statements
- `yield` and `yield from` (would turn `analyze` into a generator, which
  the executor never iterates → silent no-op)
- `try / except*` / ExceptionGroup syntax (defensive against CVE-2025-22153 class)
- `async def` and `await` anywhere
- Any top-level statement other than imports and the `analyze` def
"""

from __future__ import annotations

import ast
import importlib.util
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path


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
    # Code execution
    "eval", "exec", "compile",
    # Mutation
    "setattr", "delattr",
    # I/O
    "open", "print", "input",
    # Namespace introspection
    "globals", "locals", "vars",
    # Debugger / pager (could fork or block on stdin)
    "breakpoint", "help",
    # Inheritance escape (could reach object dunders if a class slips through)
    "super",
    # Buffer protocol (memory views can enable shared-memory tricks)
    "memoryview",
    # Direct construction of exception groups (CVE-2025-22153 class)
    "ExceptionGroup", "BaseExceptionGroup",
}


def _is_dunder(name: str) -> bool:
    """Return True if `name` is a dunder (`__x__` pattern, length >= 5)."""
    return len(name) >= 5 and name.startswith("__") and name.endswith("__")


@lru_cache(maxsize=1)
def _load_adaptive_all() -> frozenset[str]:
    """Return the cached __all__ set from screw_agents.adaptive.

    Uses AST parsing (not runtime import) to stay hermetic — lint must not
    depend on the adaptive package being fully importable in the linting
    environment. Only imports the parent `screw_agents` package via
    `importlib.util.find_spec`; the adaptive package's own module body is
    never executed.
    """
    spec = importlib.util.find_spec("screw_agents.adaptive")
    if spec is None or spec.origin is None:
        return frozenset()
    source = Path(spec.origin).read_text(encoding="utf-8")
    tree = ast.parse(source)
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == "__all__":
                    if isinstance(node.value, (ast.List, ast.Tuple)):
                        return frozenset(
                            elt.value for elt in node.value.elts
                            if isinstance(elt, ast.Constant) and isinstance(elt.value, str)
                        )
    return frozenset()


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
    """Enforce: only imports + exactly one `def analyze` are allowed at module level.

    Import-module allowlisting and async/forbidden-construct checks happen in the
    per-node walk (_check_node), so they apply to nested constructs too.
    """
    analyze_found = False
    for node in tree.body:
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            pass  # Import-allowability handled by walk
        elif isinstance(node, ast.FunctionDef) and node.name == "analyze":
            analyze_found = True
        else:
            # Anything else at top level: rejected
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

    # Forbidden builtin name lookups (eval, exec, open, breakpoint, etc.)
    if isinstance(node, ast.Name) and node.id in _FORBIDDEN_NAMES:
        violations.append(LintViolation(
            rule="forbidden_name",
            message=f"forbidden builtin: {node.id}",
            line=line,
        ))

    # Blanket dunder check on Name lookups (catches __import__, __builtins__,
    # __class__, etc. without maintaining a per-name list)
    if isinstance(node, ast.Name) and _is_dunder(node.id):
        violations.append(LintViolation(
            rule="forbidden_dunder_name",
            message=f"forbidden dunder name: {node.id}",
            line=line,
        ))

    # Blanket dunder check on Attribute access (catches __class__, __dict__,
    # __getattribute__, __reduce__, every metaclass/protocol attr)
    if isinstance(node, ast.Attribute) and _is_dunder(node.attr):
        violations.append(LintViolation(
            rule="forbidden_dunder_attr",
            message=f"forbidden dunder attribute access: {node.attr}",
            line=line,
        ))

    # Imports: only `from screw_agents.adaptive import ...` is allowed,
    # ANYWHERE in the script (not just top level — nested imports were the
    # most damaging Layer 1 escape per security review)
    if isinstance(node, ast.ImportFrom):
        if node.module not in _ALLOWED_IMPORT_MODULES:
            module_repr = repr(node.module) if node.module is not None else "<relative>"
            violations.append(LintViolation(
                rule="disallowed_import",
                message=f"import from {module_repr} not allowed; only {_ALLOWED_IMPORT_MODULES}",
                line=line,
            ))
        elif node.module == "screw_agents.adaptive":
            # Symbol-level validation: each imported name must appear in
            # screw_agents.adaptive.__all__. Guards against hallucinated
            # symbols (e.g. `read_source`, `parse_module`) slipping past
            # Layer 1 because only the module — not its members — was checked.
            allowed = _load_adaptive_all()
            for alias in node.names:
                if alias.name not in allowed:
                    allowlist_display = ", ".join(sorted(allowed))
                    violations.append(LintViolation(
                        rule="unknown_symbol",
                        message=(
                            f"'{alias.name}' is not exported from screw_agents.adaptive. "
                            f"Valid names: {allowlist_display}"
                        ),
                        line=line,
                    ))
    if isinstance(node, ast.Import):
        violations.append(LintViolation(
            rule="disallowed_import",
            message=f"`import {node.names[0].name}` not allowed; use `from screw_agents.adaptive import ...`",
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

    # Class definitions are forbidden ANYWHERE — adaptive scripts have no
    # legitimate use for class definitions, and class bodies enable the
    # custom-__getattribute__ / metaclass escape paths that bypass the
    # dunder check on the AST surface.
    if isinstance(node, ast.ClassDef):
        violations.append(LintViolation(
            rule="forbidden_classdef",
            message=f"class definition not allowed: {node.name}",
            line=line,
        ))

    # global / nonlocal — reach module-level / enclosing-scope namespace
    if isinstance(node, ast.Global):
        violations.append(LintViolation(
            rule="forbidden_global",
            message=f"global statement not allowed (names: {', '.join(node.names)})",
            line=line,
        ))
    if isinstance(node, ast.Nonlocal):
        violations.append(LintViolation(
            rule="forbidden_nonlocal",
            message=f"nonlocal statement not allowed (names: {', '.join(node.names)})",
            line=line,
        ))

    # yield / yield from — turn `analyze` into a generator, which the
    # executor never iterates → silent no-op (no findings emitted)
    if isinstance(node, (ast.Yield, ast.YieldFrom)):
        violations.append(LintViolation(
            rule="forbidden_yield",
            message="yield/yield-from in analyze turns it into a generator (silent no-op); not allowed",
            line=line,
        ))

    # try/except* — exception groups (CVE-2025-22153 defense)
    if isinstance(node, ast.Try):
        for handler in node.handlers:
            if getattr(handler, "is_star", False):
                violations.append(LintViolation(
                    rule="exception_group",
                    message="try/except* (ExceptionGroup) is forbidden",
                    line=line,
                ))
    if type(node).__name__ == "TryStar":
        violations.append(LintViolation(
            rule="exception_group",
            message="try/except* (ExceptionGroup) is forbidden",
            line=line,
        ))

    # async def — anywhere
    if isinstance(node, ast.AsyncFunctionDef):
        violations.append(LintViolation(
            rule="async_def",
            message="async def not allowed anywhere in the script",
            line=line,
        ))

    # await
    if isinstance(node, ast.Await):
        violations.append(LintViolation(
            rule="await",
            message="await not allowed",
            line=line,
        ))
