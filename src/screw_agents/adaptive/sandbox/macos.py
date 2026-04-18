"""macOS sandbox backend — sandbox-exec with a Seatbelt profile.

sandbox-exec has been officially deprecated by Apple since macOS 10.13 (2017)
but remains functional in macOS 14/15/26 and is what Chrome, Firefox, Claude
Code, Cursor, and Codex all ship with today. Track Apple's Containerization
framework (WWDC 2025) as the long-term replacement.

## Security properties (Layer 5 — macOS analog of Linux backend)

This backend mirrors the Linux backend's defense-in-depth posture (see
`linux.py` docstring for the full Linux-side property catalog and the
`docs/PHASE_3B_PLAN.md` Layer 5 Security Properties Reference for the
17-property table). macOS-specific differences:

- Sandboxing mechanism: sandbox-exec with an inline Seatbelt profile
  (deny default; explicit allow for stdlib + venv + project + findings).
  Not Linux user-namespaces / bwrap; semantically similar but
  enforced by the kernel's Sandbox.kext.
- No /proc — process listing privacy is enforced by Sandbox.kext (no
  prctl analog). The deny-default profile blocks the equivalent of
  /proc/<pid>/environ reads (mach `task_for_pid` denied).
- Network: `(deny network*)` blocks TCP, UDP, AF_UNIX (loopback also
  blocked since the deny is unconditional). No DNS resolution.
- Filesystem: explicit subpath allow rules; everything else denied.
  Findings path is the only writable location.
- Resources: setrlimit(RLIMIT_CPU, RLIMIT_AS, RLIMIT_NOFILE,
  RLIMIT_NPROC, RLIMIT_FSIZE) applied via preexec_fn — same pattern
  as Linux but without /proc-based dynamic NPROC counting (Darwin
  has no /proc; static cap of 256 used instead, still bounds fork
  bombs at <300 per script).
- Stdio: bounded tempfile capture (1 MB read cap per stream) — same
  as Linux backend.
- Wall clock: subprocess.run timeout — same as Linux backend.
- Host-side findings safety: identical `_safe_read_findings` (lstat +
  O_NOFOLLOW), `_clean_findings_path` (pre-run wipe), and
  `_check_findings_aggregate_size` (post-run cap) helpers — same
  attack surfaces as Linux orchestrator-side reads.

UNVALIDATED: This module is shipped per spec but cannot be empirically
validated on Marco's Arch Linux dev hardware. Tests skip on non-Darwin
platforms. The Seatbelt profile syntax, sandbox-exec invocation, and
macOS-specific path layout (/System/Library, /usr/lib subpaths) are
structural-only review until a macOS user runs the test suite.
"""

from __future__ import annotations

import errno
import os
import resource
import stat as stat_mod
import subprocess
import sys
import tempfile
from pathlib import Path
from time import monotonic

from screw_agents.models import SandboxResult


# Per-file write cap applied via RLIMIT_FSIZE in preexec_fn. Bounds:
# (a) findings buffer file (the script's intentional output)
# (b) parent-side tempfile stdout/stderr writes via inherited fds
# Mirrors the Linux backend's _MAX_FILE_SIZE_BYTES.
_MAX_FILE_SIZE_BYTES = 4 * 1024 * 1024  # 4 MB

# Read-side cap applied when reading captured stdout/stderr tempfiles.
_MAX_OUTPUT_BYTES = 1024 * 1024  # 1 MB

# Aggregate-size cap on the findings_path directory after script execution.
# Mirrors the Linux backend's _MAX_FINDINGS_AGGREGATE_BYTES.
_MAX_FINDINGS_AGGREGATE_BYTES = 16 * 1024 * 1024  # 16 MB

# File descriptor cap. 256 covers stdlib startup with margin.
_MAX_OPEN_FILES = 256

# Process count cap (per-UID via RLIMIT_NPROC). macOS has no /proc so we
# can't dynamically count baseline like Linux does; use a generous static
# cap that still bounds fork bombs at <300 per script. macOS process
# accounting differs from Linux but the per-UID rlimit semantics are the
# same — a static 256 will allow legitimate startup while preventing
# pathological fork patterns.
_MAX_PROCESSES = 256


def run_in_sandbox(
    *,
    script_path: Path,
    project_root: Path,
    findings_path: Path,
    wall_clock_s: int = 30,
    cpu_limit_s: int = 30,
    memory_limit_mb: int = 512,
) -> SandboxResult:
    """Run a script inside sandbox-exec with a Seatbelt profile.

    See `linux.py` `run_in_sandbox` for the analogous implementation. The
    macOS backend mirrors the Linux defense pattern: bounded tempfile
    capture, host-side symlink-safe findings read, pre-run cleanup of
    findings_path, post-run aggregate-size check, RLIMIT_FSIZE/NPROC/AS/CPU/
    NOFILE in preexec_fn.

    Args:
        script_path: path to the Python script to execute (host filesystem).
        project_root: path to permit read access via Seatbelt subpath.
        findings_path: path to permit write access via Seatbelt subpath.
        wall_clock_s: wall-clock timeout in seconds (parent-side kill).
        cpu_limit_s: setrlimit CPU budget (child-side).
        memory_limit_mb: setrlimit address-space budget (child-side).

    Returns:
        SandboxResult describing the run.

    Raises:
        FileNotFoundError: if sandbox-exec is not available (non-macOS or
            stripped install).
    """
    import shutil
    if shutil.which("sandbox-exec") is None:
        raise FileNotFoundError(
            "sandbox-exec not found on PATH. macOS-only tool; runs on macOS "
            "10.7+ (deprecated since 10.13 but still functional)."
        )

    # Same venv-binding logic as Linux (see linux.py:venv_python_unresolved
    # for full rationale). On macOS, instead of bwrap bind-mounting these
    # paths, the Seatbelt profile permits read access via subpath rules.
    venv_python_unresolved = Path(sys.executable)
    venv_root = venv_python_unresolved.parent.parent
    python_install_root = venv_python_unresolved.resolve().parent.parent
    python_install_parent = python_install_root.parent
    screw_pkg_root = _find_screw_agents_root()

    # BLOCKER 1b defense: clean findings_path of residual files BEFORE script
    # runs (defeats cross-run symlink poisoning). See linux.py for the same
    # defense + rationale.
    _clean_findings_path(findings_path)

    profile = _build_seatbelt_profile(
        project_root=project_root.resolve(),
        findings_path=findings_path.resolve(),
        screw_pkg_root=screw_pkg_root,
        venv_root=venv_root.resolve(),
        python_install_root=python_install_root,
        python_install_parent=python_install_parent,
    )

    args = [
        "sandbox-exec",
        "-p", profile,
        str(venv_python_unresolved),  # unresolved so Python finds pyvenv.cfg
        "-u", "-B", "-I",
        "/script.py" if False else str(script_path),  # macOS doesn't bind-remap; absolute host path
    ]

    # Explicit complete env replacement — mirrors Linux's env={} + --setenv
    # pattern. Only the variables the script's Python runtime + screw_agents
    # need; no PYTHONPATH/PYTHONHOME (Python -I ignores them).
    env = {
        "PYTHONDONTWRITEBYTECODE": "1",
        "PATH": "/usr/bin:/bin",
        "HOME": "/tmp",
        "LANG": "C.UTF-8",
        "SCREW_FINDINGS_PATH": str(findings_path / "findings.json"),
        "SCREW_PROJECT_ROOT": str(project_root),
    }

    def _preexec() -> None:
        """Apply setrlimit in the child before exec — same 5 limits as Linux."""
        resource.setrlimit(resource.RLIMIT_CPU, (cpu_limit_s, cpu_limit_s))
        resource.setrlimit(resource.RLIMIT_AS, (memory_limit_mb * 1024 * 1024,) * 2)
        resource.setrlimit(resource.RLIMIT_NPROC, (_MAX_PROCESSES, _MAX_PROCESSES))
        resource.setrlimit(resource.RLIMIT_NOFILE, (_MAX_OPEN_FILES, _MAX_OPEN_FILES))
        resource.setrlimit(resource.RLIMIT_FSIZE, (_MAX_FILE_SIZE_BYTES, _MAX_FILE_SIZE_BYTES))

    start = monotonic()
    killed_by_timeout = False
    # Bounded tempfile capture — mirrors Linux backend's B3 fix.
    with tempfile.TemporaryFile() as out_file, tempfile.TemporaryFile() as err_file:
        try:
            completed = subprocess.run(
                args,
                env=env,
                timeout=wall_clock_s,
                stdout=out_file,
                stderr=err_file,
                preexec_fn=_preexec,
                check=False,
            )
            returncode = completed.returncode
        except subprocess.TimeoutExpired:
            returncode = -1
            killed_by_timeout = True
        out_file.seek(0)
        err_file.seek(0)
        stdout = out_file.read(_MAX_OUTPUT_BYTES)
        stderr = err_file.read(_MAX_OUTPUT_BYTES)
    elapsed = monotonic() - start

    # BLOCKER 2 defense: refuse findings if aggregate exceeds cap.
    aggregate_bytes = _check_findings_aggregate_size(findings_path)
    if aggregate_bytes > _MAX_FINDINGS_AGGREGATE_BYTES:
        findings_json = None
    else:
        # BLOCKER 1 defense: lstat + O_NOFOLLOW symlink-safe read.
        findings_file = findings_path / "findings.json"
        findings_json = _safe_read_findings(findings_file)

    return SandboxResult(
        stdout=stdout,
        stderr=stderr,
        returncode=returncode,
        wall_clock_s=elapsed,
        killed_by_timeout=killed_by_timeout,
        findings_json=findings_json,
    )


def _build_seatbelt_profile(
    *,
    project_root: Path,
    findings_path: Path,
    screw_pkg_root: Path,
    venv_root: Path,
    python_install_root: Path,
    python_install_parent: Path,
) -> str:
    """Generate a Seatbelt profile string permitting exactly what the script needs.

    Deny-by-default. Allow-list mirrors the Linux backend's bind set:
    - /usr/lib, /usr/share, /System/Library — macOS system libraries
    - python_install_root + parent — Python binary + stdlib
    - venv_root — pyvenv.cfg + site-packages (.pth files for editable installs)
    - screw_pkg_root — screw_agents source
    - project_root — read-only access to user code
    - findings_path — write access for findings buffer
    - /private/etc/localtime, /dev/null, /dev/urandom — minimal runtime needs
    """
    return f"""
(version 1)
(deny default)

(allow file-read*
  (subpath "/usr/lib")
  (subpath "/usr/share")
  (subpath "/System/Library")
  (subpath "{python_install_root}")
  (subpath "{python_install_parent}")
  (subpath "{venv_root}")
  (subpath "{screw_pkg_root}")
  (subpath "{project_root}")
  (literal "/private/etc/localtime")
  (literal "/dev/null")
  (literal "/dev/urandom")
  (literal "/dev/random")
)

(allow file-write*
  (subpath "{findings_path}")
)

(allow process-fork)
(allow process-exec
  (literal "{Path(sys.executable).resolve()}")
)

; Network: deny all forms (TCP, UDP, raw, mach-based)
(deny network*)
(deny mach-lookup)
(deny iokit-open)

; System info reads — deny by default; specific allows only as needed
(deny system-info)
""".strip()


def _safe_read_findings(findings_file: Path) -> str | None:
    """Read findings_file's contents, refusing to follow symlinks.

    Identical defense to linux.py's `_safe_read_findings` — closes the
    Layer 5 BLOCKER 1 (symlink-replace exfiltration) on macOS too. See
    linux.py for the full rationale.
    """
    try:
        st = os.lstat(findings_file)
    except FileNotFoundError:
        return None
    except OSError:
        return None

    if not stat_mod.S_ISREG(st.st_mode):
        return None

    try:
        fd = os.open(findings_file, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            return None
        return None

    try:
        data = os.read(fd, _MAX_OUTPUT_BYTES)
    finally:
        os.close(fd)

    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("utf-8", errors="replace")


def _clean_findings_path(findings_path: Path) -> None:
    """Remove residual files from a prior sandbox invocation.

    Identical defense to linux.py's `_clean_findings_path` — closes the
    BLOCKER 1b cross-run symlink poisoning vector on macOS too.
    """
    try:
        for entry in findings_path.iterdir():
            try:
                if entry.is_symlink() or entry.is_file():
                    entry.unlink()
            except OSError:
                continue
    except OSError:
        pass


def _check_findings_aggregate_size(findings_path: Path) -> int:
    """Return the aggregate byte size of regular files directly under findings_path.

    Identical defense to linux.py's `_check_findings_aggregate_size` — closes
    BLOCKER 2 (aggregate disk DoS) on macOS too.
    """
    total = 0
    try:
        for entry in findings_path.iterdir():
            try:
                st = entry.stat(follow_symlinks=False)
                if stat_mod.S_ISREG(st.st_mode):
                    total += st.st_size
            except OSError:
                continue
    except OSError:
        return 0
    return total


def _find_screw_agents_root() -> Path:
    """Return the filesystem path where screw_agents is installed."""
    import screw_agents
    return Path(screw_agents.__file__).resolve().parent.parent
