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
    # Force-load all submodules so dir(adaptive) is consistent regardless of
    # which test files have run before us. Without this, the test passes only
    # by luck of pytest's alphabetic test-file ordering — fragile contract for
    # what's supposed to be a security-boundary pin.
    import screw_agents.adaptive.executor  # noqa: F401
    import screw_agents.adaptive.lint  # noqa: F401
    import screw_agents.adaptive.sandbox.linux  # noqa: F401
    import screw_agents.adaptive.script_name  # noqa: F401  (T2: shared validator)
    import screw_agents.adaptive.signing  # noqa: F401

    import screw_agents.adaptive as adaptive

    public_names = {name for name in dir(adaptive) if not name.startswith("_")}
    # Allow a small set of standard exports (Python magic, re-exports from deps).
    # Python attaches submodules as attributes on the parent package whenever
    # ANY code runs `from screw_agents.adaptive.X import ...` (PEP 328 + the
    # import system's parent-binding rule) — including test files, not just
    # __init__.py. The whitelist here covers (a) submodules imported by
    # __init__.py for the public re-export surface, (b) submodules imported
    # only by test files (e.g., `lint` is imported by tests/test_adaptive_lint.py
    # but is intentionally NOT re-exported through __init__.py — adaptive
    # scripts cannot do `from screw_agents.adaptive import lint` because `lint`
    # is not in __init__.py's namespace), and (c) submodule PACKAGES with
    # nested submodules (e.g., `sandbox` is a package containing linux.py and
    # later macos.py; importing sandbox.linux attaches `sandbox` to the parent
    # package and then `linux` to `sandbox`).
    #
    # Layer 0b enforcement against direct submodule access from adaptive scripts
    # lives in the AST allowlist lint (Task 7), not here. The other contract
    # test in this file (test_all_matches_expected_exactly) verifies that
    # __all__ does NOT include any of these submodule names, so star-imports
    # remain curated.
    #
    # MAINTENANCE RULE: this set must equal exactly the direct submodules
    # (modules + packages) of screw_agents.adaptive that get loaded into
    # sys.modules during ANY pytest session, regardless of test ordering.
    # When a new submodule lands (whether imported by __init__.py or only by
    # its own test file), update this whitelist in the same commit. Without
    # this, the test passes by luck of alphabetic test-file ordering and fails
    # when run in a different order — fragile contract for a security boundary.
    #
    # T2 addition: script_name (shared SCRIPT_NAME_RE + validate_script_name).
    # Imported by signing.py and staging.py — surfaces as attribute once any
    # code in the session does `from screw_agents.adaptive.script_name import ...`.
    allowed_extras = {"ast_walker", "dataflow", "executor", "findings", "lint", "project", "sandbox", "script_name", "signing"}
    assert public_names - allowed_extras == EXPECTED_PUBLIC_API, (
        f"Public API drift: {public_names - EXPECTED_PUBLIC_API} added, "
        f"{EXPECTED_PUBLIC_API - public_names} removed"
    )


def test_public_api_count_is_under_28():
    """Curated library should stay small. Over 27 is a red flag for scope creep.

    Ceiling history:
    - 25 before T18a (original baseline).
    - 26 after T18a added `signing` (sign-side canonicalization helper).
    - 27 after T2 added `script_name` (shared SCRIPT_NAME_RE + validator).
    The EXPECTED_PUBLIC_API curated set is unchanged at 18 entries; the extra
    entries are all internal submodule attributes that Python binds automatically
    when any code does ``from screw_agents.adaptive.X import ...``.
    """
    # Force-load all submodules so dir(adaptive) is consistent regardless of
    # which test files have run before us. Without this, the test passes only
    # by luck of pytest's alphabetic test-file ordering — fragile contract for
    # what's supposed to be a security-boundary pin.
    import screw_agents.adaptive.executor  # noqa: F401
    import screw_agents.adaptive.lint  # noqa: F401
    import screw_agents.adaptive.sandbox.linux  # noqa: F401
    import screw_agents.adaptive.script_name  # noqa: F401  (T2: shared validator)
    import screw_agents.adaptive.signing  # noqa: F401

    import screw_agents.adaptive as adaptive

    public_count = len([n for n in dir(adaptive) if not n.startswith("_")])
    assert public_count <= 27, (
        f"adaptive public API has {public_count} entries; review for scope creep"
    )


def test_all_matches_expected_exactly():
    """`__all__` must equal EXPECTED_PUBLIC_API. The dir-based test catches
    new attributes appearing on the package, but a contributor who adds an
    import to __init__.py and updates EXPECTED_PUBLIC_API while forgetting
    to update __all__ would silently break `from screw_agents.adaptive import *`
    semantics for adaptive scripts. This test pins the star-import contract."""
    # Force-load all submodules so dir(adaptive) is consistent regardless of
    # which test files have run before us. Without this, the test passes only
    # by luck of pytest's alphabetic test-file ordering — fragile contract for
    # what's supposed to be a security-boundary pin.
    import screw_agents.adaptive.executor  # noqa: F401
    import screw_agents.adaptive.lint  # noqa: F401
    import screw_agents.adaptive.sandbox.linux  # noqa: F401
    import screw_agents.adaptive.script_name  # noqa: F401  (T2: shared validator)
    import screw_agents.adaptive.signing  # noqa: F401

    import screw_agents.adaptive as adaptive

    assert set(adaptive.__all__) == EXPECTED_PUBLIC_API, (
        f"__all__ drift: {set(adaptive.__all__) - EXPECTED_PUBLIC_API} added, "
        f"{EXPECTED_PUBLIC_API - set(adaptive.__all__)} removed"
    )
