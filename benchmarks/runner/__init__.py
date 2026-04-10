"""CWE-1400-native benchmark evaluator for screw-agents.

See ADR-013 in docs/DECISIONS.md for the design rationale.

Submodules are loaded lazily to avoid import errors during scaffolding:
    from benchmarks.runner.models import Finding, BenchmarkCase
"""

__version__ = "0.1.0"
