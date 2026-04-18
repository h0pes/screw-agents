"""Sandbox backend dispatch for adaptive script execution.

Platform-specific sandbox backends live in sibling modules:
- `linux.py` — bwrap-based backend (Task 8)
- `macos.py` — sandbox-exec / Seatbelt-based backend (Task 9)

This `__init__` exposes a single `run_in_sandbox` entry point that dispatches
to the correct backend at call time based on `sys.platform`. Unsupported
platforms raise `UnsupportedPlatformError` — adaptive script execution is
disabled gracefully with a clear error message pointing users to a supported
environment (native Linux / macOS / WSL2).
"""

from __future__ import annotations

import sys
from types import ModuleType


class UnsupportedPlatformError(RuntimeError):
    """Raised when the current platform has no supported sandbox backend."""


def get_backend() -> ModuleType:
    """Return the sandbox backend module appropriate for this platform.

    Raises:
        UnsupportedPlatformError: if the platform is not supported in Phase 3b.
    """
    if sys.platform == "linux":
        from screw_agents.adaptive.sandbox import linux as backend
        return backend
    if sys.platform == "darwin":
        from screw_agents.adaptive.sandbox import macos as backend
        return backend
    raise UnsupportedPlatformError(
        f"Adaptive analysis scripts are not supported on this platform.\n"
        f"Current platform: {sys.platform}\n"
        f"Supported: Linux (bwrap), macOS (sandbox-exec)\n"
        f"Alternative: run scans in a Linux environment (native or WSL2) "
        f"for adaptive mode."
    )


def run_in_sandbox(**kwargs):
    """Dispatch to the platform backend's `run_in_sandbox` function.

    Accepts the same keyword arguments as the platform backend (see
    `linux.run_in_sandbox` / `macos.run_in_sandbox` for the canonical
    signature — both backends honor the same contract).
    """
    return get_backend().run_in_sandbox(**kwargs)
