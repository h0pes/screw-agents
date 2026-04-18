"""Verify that the screw_agents.adaptive public API contains exactly the curated
helpers — nothing more, nothing less. This test is load-bearing: it prevents
accidental exposure of internal functions that would break Layer 0b (curated
library) of the defense stack.
"""

from __future__ import annotations


EXPECTED_PUBLIC_API = {
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
}


def test_public_api_matches_expected_exactly():
    import screw_agents.adaptive as adaptive

    public_names = {name for name in dir(adaptive) if not name.startswith("_")}
    # Allow a small set of standard exports (Python magic, re-exports from deps).
    # Python attaches submodules as attributes on the parent package whenever
    # `from package.submodule import ...` runs (PEP 328 + the import system's
    # parent-binding rule). The 4 entries here mirror the `from screw_agents.
    # adaptive.{name} import ...` lines in __init__.py and grow only when a new
    # submodule import lands. Layer 0b enforcement against direct submodule
    # access lives in the AST allowlist lint (Task 7), not here.
    allowed_extras = {"ast_walker", "dataflow", "findings", "project"}
    assert public_names - allowed_extras == EXPECTED_PUBLIC_API, (
        f"Public API drift: {public_names - EXPECTED_PUBLIC_API} added, "
        f"{EXPECTED_PUBLIC_API - public_names} removed"
    )


def test_public_api_count_is_under_25():
    """Curated library should stay small. Over 25 is a red flag for scope creep."""
    import screw_agents.adaptive as adaptive

    public_count = len([n for n in dir(adaptive) if not n.startswith("_")])
    assert public_count <= 25, (
        f"adaptive public API has {public_count} entries; review for scope creep"
    )
