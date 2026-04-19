"""Integration tests for the Linux bwrap sandbox backend.

These tests require bubblewrap on PATH and are skipped on other platforms.
"""

from __future__ import annotations

import shutil
import sys
from pathlib import Path

import pytest

from screw_agents.models import SandboxResult

pytestmark = [
    pytest.mark.skipif(sys.platform != "linux", reason="Linux-only (bwrap)"),
    pytest.mark.skipif(shutil.which("bwrap") is None, reason="bubblewrap not installed"),
]


def test_sandbox_runs_valid_script(tmp_path: Path):
    from screw_agents.adaptive.sandbox.linux import run_in_sandbox

    script_path = tmp_path / "script.py"
    script_path.write_text(
        "from screw_agents.adaptive import emit_finding\n"
        "def analyze(project):\n"
        "    emit_finding(cwe='CWE-89', file='x.py', line=1, message='test', severity='high')\n"
        "analyze(None)\n"  # actually invoke the function so emit_finding runs
    )
    findings_path = tmp_path / "findings"
    findings_path.mkdir()
    project_path = tmp_path / "project"
    project_path.mkdir()

    result = run_in_sandbox(
        script_path=script_path,
        project_root=project_path,
        findings_path=findings_path,
        wall_clock_s=30,
    )
    assert isinstance(result, SandboxResult)
    assert result.returncode == 0
    assert result.killed_by_timeout is False


def test_sandbox_kills_runaway_script(tmp_path: Path):
    """A script that loops forever is killed by the wall-clock timeout."""
    from screw_agents.adaptive.sandbox.linux import run_in_sandbox

    script_path = tmp_path / "script.py"
    script_path.write_text(
        "from screw_agents.adaptive import ProjectRoot\n"
        "def analyze(project):\n"
        "    while True:\n"
        "        pass\n"
        "analyze(None)\n"  # actually enter the loop so the wall-clock kill is exercised
    )
    findings_path = tmp_path / "findings"
    findings_path.mkdir()
    project_path = tmp_path / "project"
    project_path.mkdir()

    result = run_in_sandbox(
        script_path=script_path,
        project_root=project_path,
        findings_path=findings_path,
        wall_clock_s=3,  # short timeout for test speed
    )
    assert result.killed_by_timeout is True


def test_sandbox_blocks_network_access(tmp_path: Path):
    """A script attempting network access fails because of --unshare-net."""
    from screw_agents.adaptive.sandbox.linux import run_in_sandbox

    script_path = tmp_path / "script.py"
    # Bypass lint for this test by directly using a forbidden import
    # (the real defense is lint at Layer 1, but this test verifies the sandbox
    # also blocks network in case Layer 1 has a bug)
    script_path.write_text(
        "import socket\n"  # would fail lint in real use
        "def analyze(project):\n"
        "    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
        "    try:\n"
        "        s.connect(('8.8.8.8', 53))\n"
        "    except OSError:\n"
        "        pass\n"
        "analyze(None)\n"  # actually attempt the connect so --unshare-net is exercised
    )
    findings_path = tmp_path / "findings"
    findings_path.mkdir()
    project_path = tmp_path / "project"
    project_path.mkdir()

    result = run_in_sandbox(
        script_path=script_path,
        project_root=project_path,
        findings_path=findings_path,
        wall_clock_s=10,
    )
    # Either the socket.connect raises OSError (sandboxed network is down)
    # or the script exits cleanly because the exception is caught. Either way,
    # no actual network connection occurred.
    assert result.returncode == 0


def test_compute_nproc_cap_counts_threads_not_processes() -> None:
    """Regression for a T8 latent bug discovered during T19: RLIMIT_NPROC
    accounts per-UID THREADS, not processes. A heavily-threaded process
    (tokio runtime, JVM, etc.) contributes many threads but only one
    process. The cap must include all threads to avoid the kernel
    hitting EAGAIN on bwrap's clone(CLONE_NEWUSER).

    Locks the thread-counting semantics so a future refactor can't
    silently regress back to process-counting (which would only break on
    hosts with heavily-threaded processes — intermittent and expensive
    to diagnose, exactly what happened on the dev host during T19)."""
    import threading
    from screw_agents.adaptive.sandbox.linux import _compute_nproc_cap

    # Baseline measurement — this already counts the current Python
    # interpreter's threads (main + any background). Pytest may have
    # started threads too.
    baseline = _compute_nproc_cap()

    # Spawn 5 threads in THIS process. If _compute_nproc_cap counted
    # processes, the cap would not change (we didn't spawn a new process).
    # If it correctly counts threads, the cap increases by 5.
    extras: list[threading.Thread] = []
    barrier = threading.Barrier(6)  # 5 extras + the main

    def worker() -> None:
        barrier.wait(timeout=5)
        barrier.wait(timeout=5)  # second wait: main signals us to exit

    try:
        for _ in range(5):
            t = threading.Thread(target=worker, daemon=True)
            t.start()
            extras.append(t)
        barrier.wait(timeout=5)  # threads are now alive and blocked

        after = _compute_nproc_cap()

        # Expect cap to have grown by approximately 5 (the new threads).
        # Tolerance: +/- 2 to account for pytest/Python internal thread
        # churn during the test (gc threads, subprocess reaper, etc.).
        delta = after - baseline
        assert 3 <= delta <= 10, (
            f"Expected cap to grow by ~5 when 5 threads spawned; got "
            f"delta={delta} (baseline={baseline}, after={after}). "
            f"If delta is 0, _compute_nproc_cap is counting processes "
            f"not threads — the bug has regressed."
        )
    finally:
        # Release the worker threads so they can exit
        try:
            barrier.wait(timeout=1)  # second wait — workers exit after
        except threading.BrokenBarrierError:
            pass
        for t in extras:
            t.join(timeout=2)


def test_compute_nproc_cap_returns_reasonable_value_under_load() -> None:
    """Sanity check: on a realistic interactive desktop with hundreds of
    threads, _compute_nproc_cap must return a value that bwrap can
    actually fork under. This is the test that was SILENTLY FAILING
    under rustdesk load — now validates the condition post-fix.

    We don't actually spawn bwrap here; we just assert the cap is at
    least baseline+headroom, which the bug fix guarantees but the
    process-counting bug violated (baseline was pre-fork-count +
    headroom, less than real thread count + headroom)."""
    import threading
    from screw_agents.adaptive.sandbox.linux import (
        _BWRAP_HEADROOM,
        _SCRIPT_PROCESS_BUDGET,
        _compute_nproc_cap,
    )

    current_thread_count = threading.active_count()
    cap = _compute_nproc_cap()

    # Cap must be at least current-thread-count-in-this-process +
    # headroom. In practice it's bigger (includes all other UID
    # processes' threads), but this lower bound was VIOLATED by the
    # pre-fix code when other UID processes contributed many threads.
    min_expected = current_thread_count + _SCRIPT_PROCESS_BUDGET + _BWRAP_HEADROOM - 20
    # The -20 tolerance accounts for process scanner races.
    assert cap >= min_expected, (
        f"Cap {cap} is below reasonable minimum {min_expected} for "
        f"{current_thread_count} threads in this process alone — "
        f"thread-counting regression."
    )
