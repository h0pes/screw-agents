"""screw_agents.adaptive — the curated helper library for adaptive analysis scripts.

This package is the ONLY allowed import surface for scripts running in the adaptive
sandbox (Layer 0b of the defense stack). The AST allowlist lint (Layer 1) rejects
scripts that import anything outside this package.

## Usage from within an adaptive script

```python
from screw_agents.adaptive import (
    ProjectRoot,
    emit_finding,
    find_calls,
    get_call_args,
    is_user_input,
)

def analyze(project: ProjectRoot) -> None:
    for call in find_calls(project, "QueryBuilder.execute_raw"):
        args = get_call_args(call)
        if args and is_user_input(args[0], language="python", source=project.read_file(call.file)):
            emit_finding(
                cwe="CWE-89",
                file=call.file,
                line=call.line,
                message="User input reaches QueryBuilder.execute_raw without .bind()",
                severity="high",
            )
```

## Stability contract

This module's public API is stable across Phase 3b. Changes require:
1. Updating this docstring
2. Updating the test in tests/test_adaptive_public_api.py
3. Migrating all existing adaptive scripts in the test corpus (once
   Task 22 seeds the first end-to-end fixtures)

Adding a new helper requires a design discussion — the curated surface is
deliberately small (under 25 exports) to keep the attack surface audited.
"""

from screw_agents.adaptive.ast_walker import (
    CallSite,
    ClassNode,
    ImportNode,
    find_calls,
    find_class_definitions,
    find_imports,
    parse_ast,
    walk_ast,
)
from screw_agents.adaptive.dataflow import (
    get_call_args,
    get_parent_function,
    is_sanitized,
    is_user_input,
    match_pattern,
    resolve_variable,
    trace_dataflow,
)
from screw_agents.adaptive.findings import emit_finding
from screw_agents.adaptive.project import ProjectPathError, ProjectRoot

__all__ = [
    # Filesystem chokepoint
    "ProjectRoot",
    "ProjectPathError",
    # AST helpers
    "parse_ast",
    "walk_ast",
    "find_calls",
    "find_imports",
    "find_class_definitions",
    "CallSite",
    "ImportNode",
    "ClassNode",
    # Dataflow
    "trace_dataflow",
    "is_user_input",
    "is_sanitized",
    "match_pattern",
    "get_call_args",
    "get_parent_function",
    "resolve_variable",
    # Findings
    "emit_finding",
]
