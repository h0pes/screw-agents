"""screw_agents.adaptive — the curated helper library for adaptive analysis scripts.

This package is the ONLY allowed import surface for scripts running in the adaptive
sandbox (Layer 0b of the defense stack). The AST allowlist lint (Layer 1) rejects
scripts that import anything outside this package.

Public API will be populated in Task 6.
"""
