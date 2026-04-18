"""Unit tests for the sandbox backend dispatcher + (future) executor pipeline.

Task 10 populates this file with the backend-dispatch test. Task 11 will
extend it with executor pipeline tests.
"""

from __future__ import annotations

import sys

import pytest


def test_backend_dispatch_returns_correct_module():
    """`get_backend()` returns the linux module on Linux, macos on Darwin,
    raises UnsupportedPlatformError elsewhere."""
    from screw_agents.adaptive.sandbox import get_backend, UnsupportedPlatformError

    if sys.platform == "linux":
        backend = get_backend()
        assert backend.__name__.endswith("linux")
    elif sys.platform == "darwin":
        backend = get_backend()
        assert backend.__name__.endswith("macos")
    else:
        with pytest.raises(UnsupportedPlatformError):
            get_backend()


def test_run_in_sandbox_dispatches_to_backend(tmp_path):
    """`run_in_sandbox(**kwargs)` delegates to the platform backend. On Linux
    this exercises the bwrap backend end-to-end with a minimal valid script."""
    if sys.platform not in ("linux", "darwin"):
        pytest.skip("Adaptive sandbox not supported on this platform")

    from screw_agents.adaptive.sandbox import run_in_sandbox
    from screw_agents.models import SandboxResult

    script_path = tmp_path / "probe.py"
    script_path.write_text("def analyze(project):\n    pass\nanalyze(None)\n")
    findings_path = tmp_path / "findings"
    findings_path.mkdir()
    project_path = tmp_path / "project"
    project_path.mkdir()

    # Skip if platform tool is missing (Linux without bwrap, macOS without sandbox-exec)
    import shutil
    tool = "bwrap" if sys.platform == "linux" else "sandbox-exec"
    if shutil.which(tool) is None:
        pytest.skip(f"{tool} not installed")

    result = run_in_sandbox(
        script_path=script_path,
        project_root=project_path,
        findings_path=findings_path,
        wall_clock_s=10,
    )
    assert isinstance(result, SandboxResult)
    assert result.returncode == 0


def test_get_backend_raises_on_unsupported_platform(monkeypatch):
    """If sys.platform is not linux or darwin, get_backend raises
    UnsupportedPlatformError with a clear message."""
    from screw_agents.adaptive.sandbox import get_backend, UnsupportedPlatformError

    monkeypatch.setattr(sys, "platform", "win32")
    with pytest.raises(UnsupportedPlatformError, match="not supported"):
        get_backend()
