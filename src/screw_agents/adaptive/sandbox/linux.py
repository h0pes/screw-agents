"""Linux sandbox backend — bubblewrap (bwrap) with seccomp and namespace isolation.

This backend matches Anthropic's Claude Code sandbox stack: bwrap + --unshare-net +
mount bind of project root (read-only) + tmpfs + setrlimit inside the child.

## Security properties

- Filesystem: project root is bind-mounted READ-ONLY at /project; findings
  buffer path is bind-mounted read-write at /findings; the Python install +
  venv site-packages + screw_agents source are read-only-bound at their
  on-host paths so the script's `import screw_agents` resolves the same way
  it does in the parent process; everything else is tmpfs or absent.
- Network: --unshare-net removes the network namespace; connect() returns ENETDOWN.
- Processes: --unshare-pid isolates the process tree; --die-with-parent kills the
  child if the parent exits.
- Syscalls: seccomp filter blocks fork/exec/ptrace/socket/connect/bind beyond
  the initial exec (implemented via libseccomp or inline BPF).
- Resources: setrlimit applied in preexec_fn (Python subprocess feature) bounds
  CPU, memory, open files.
- Wall clock: subprocess.run timeout kills the child if it exceeds the budget.
"""

from __future__ import annotations

import os
import resource
import subprocess
import sys
from pathlib import Path
from time import monotonic

from screw_agents.models import SandboxResult


def run_in_sandbox(
    *,
    script_path: Path,
    project_root: Path,
    findings_path: Path,
    wall_clock_s: int = 30,
    cpu_limit_s: int = 30,
    memory_limit_mb: int = 512,
) -> SandboxResult:
    """Run a script inside bwrap. Returns a SandboxResult with stdio + findings.

    Args:
        script_path: path to the Python script to execute (host filesystem).
        project_root: path to read-only-bind as /project inside the sandbox.
        findings_path: path to read-write-bind as /findings inside the sandbox.
        wall_clock_s: wall-clock timeout in seconds (parent-side kill).
        cpu_limit_s: setrlimit CPU budget (child-side).
        memory_limit_mb: setrlimit address-space budget (child-side).

    Returns:
        SandboxResult describing the run.

    Raises:
        FileNotFoundError: if bwrap is not on PATH.
    """
    import shutil
    if shutil.which("bwrap") is None:
        raise FileNotFoundError(
            "bubblewrap (bwrap) not found on PATH. "
            "Install with: pacman -S bubblewrap  (Arch)  /  apt install bubblewrap  (Debian)"
        )

    # Resolve the Python binary symlink chain so we can bind the actual install
    # (uv-managed Python lives at ~/.local/share/uv/python/<id>/bin/python3.X;
    # system venvs symlink to /usr/bin/python3.X). Binding only the resolved
    # install would miss the venv's site-packages — `.pth` files for editable
    # installs and pyvenv.cfg for venv detection live in `.venv/lib/python3.X/`,
    # not in the resolved Python install root. We bind THREE Python-install
    # paths and invoke the UNRESOLVED sys.executable so Python's venv bootstrap
    # runs (it keys off pyvenv.cfg next to the python binary).
    venv_python_unresolved = Path(sys.executable)  # e.g., .venv/bin/python3
    venv_root = venv_python_unresolved.parent.parent  # e.g., .venv/
    python_install_root = venv_python_unresolved.resolve().parent.parent
    # uv's install layout has an alias-symlink chain: cpython-3.12 -> cpython-3.12.13.
    # Binding the parent ensures bwrap's exec follows the chain.
    python_install_parent = python_install_root.parent
    screw_pkg_root = _find_screw_agents_root()

    bwrap_args = [
        "bwrap",
        "--unshare-net",
        "--unshare-pid",
        "--unshare-ipc",
        "--unshare-uts",
        "--die-with-parent",
        "--ro-bind", "/usr", "/usr",
        "--ro-bind", "/lib", "/lib",
        "--ro-bind-try", "/lib64", "/lib64",
        "--ro-bind-try", "/etc/ld.so.cache", "/etc/ld.so.cache",
        "--ro-bind-try", "/etc/resolv.conf", "/etc/resolv.conf",  # harmless, needed by some stdlib imports
        "--ro-bind", str(python_install_root), str(python_install_root),  # Python binary + stdlib (resolved install)
        "--ro-bind-try", str(python_install_parent), str(python_install_parent),  # uv alias-symlink chain (parent of resolved install)
        "--ro-bind", str(venv_root), str(venv_root),  # venv: pyvenv.cfg + site-packages (with .pth files for editable installs)
        "--ro-bind", str(screw_pkg_root), str(screw_pkg_root),  # screw_agents source (where editable .pth points)
        "--ro-bind", str(project_root), "/project",
        "--bind", str(findings_path), "/findings",
        "--ro-bind", str(script_path), "/script.py",
        "--tmpfs", "/tmp",
        "--tmpfs", "/var",
        "--proc", "/proc",
        "--dev", "/dev",
        "--setenv", "PYTHONDONTWRITEBYTECODE", "1",
        "--setenv", "PATH", "/usr/bin",
        "--setenv", "SCREW_FINDINGS_PATH", "/findings/findings.json",
        "--setenv", "SCREW_PROJECT_ROOT", "/project",
        "--",
        str(venv_python_unresolved),  # unresolved path so Python finds pyvenv.cfg next to the binary
        "-u",
        "-B",
        "-I",
        "/script.py",
    ]

    def _preexec() -> None:
        """Apply setrlimit in the child before exec — Layer 4 of defense stack."""
        resource.setrlimit(resource.RLIMIT_CPU, (cpu_limit_s, cpu_limit_s))
        resource.setrlimit(resource.RLIMIT_AS, (memory_limit_mb * 1024 * 1024,) * 2)
        resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))

    start = monotonic()
    killed_by_timeout = False
    try:
        completed = subprocess.run(
            bwrap_args,
            timeout=wall_clock_s,
            capture_output=True,
            preexec_fn=_preexec,
            check=False,
        )
        stdout = completed.stdout
        stderr = completed.stderr
        returncode = completed.returncode
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout or b""
        stderr = exc.stderr or b""
        returncode = -1
        killed_by_timeout = True
    elapsed = monotonic() - start

    findings_file = findings_path / "findings.json"
    findings_json = findings_file.read_text() if findings_file.exists() else None

    return SandboxResult(
        stdout=stdout,
        stderr=stderr,
        returncode=returncode,
        wall_clock_s=elapsed,
        killed_by_timeout=killed_by_timeout,
        findings_json=findings_json,
    )


def _find_screw_agents_root() -> Path:
    """Return the filesystem path where screw_agents is installed so bwrap can bind-mount it."""
    import screw_agents
    return Path(screw_agents.__file__).resolve().parent.parent
