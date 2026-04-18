"""Linux sandbox backend — bubblewrap (bwrap) with seccomp and namespace isolation.

This backend matches Anthropic's Claude Code sandbox stack: bwrap + --unshare-net +
mount bind of project root (read-only) + tmpfs + setrlimit inside the child.

## Security properties (Layer 5)

- Environment: TWO-LAYER defense closes /proc/1/environ secret exfiltration:
  (1) subprocess.run is invoked with `env={}` so the bwrap process itself
      inherits NO environment from the parent — without this, /proc/1
      inside the sandbox PID namespace (which IS the bwrap process) would
      leak the parent's full environ including ANTHROPIC_API_KEY,
      OAUTH tokens, AWS_*, etc.
  (2) `--clearenv` strips any residual env at the bwrap-to-child boundary;
      only PYTHONDONTWRITEBYTECODE / PATH / HOME / LANG /
      SCREW_FINDINGS_PATH / SCREW_PROJECT_ROOT are explicitly re-injected
      via `--setenv`.
- Hostname: --hostname sandbox masks the host system name from the script.
- Filesystem: project root is bind-mounted READ-ONLY at /project; findings
  buffer path is bind-mounted read-write at /findings; the Python install +
  venv site-packages + screw_agents source are read-only-bound at their
  on-host paths so the script's `import screw_agents` resolves the same way
  it does in the parent process; everything else is tmpfs or absent. Host-
  side findings read uses lstat + O_NOFOLLOW to refuse symlinks (Layer 5
  BLOCKER 1 defense: prevents a script from exfiltrating arbitrary host
  files by swapping findings.json for a symlink the orchestrator would
  follow). findings_path is wiped of residual files BEFORE each invocation
  to defeat cross-run symlink poisoning. Aggregate size of findings_path
  is checked AFTER each invocation against `_MAX_FINDINGS_AGGREGATE_BYTES`
  (16 MB cap) — script writing many small files to fill host disk causes
  findings to be rejected (Layer 5 BLOCKER 2 defense).
- Network: --unshare-net removes the network namespace; connect() returns
  ENETDOWN; getaddrinfo fails with gaierror; AF_PACKET fails with EPERM
  (no CAP_NET_RAW).
- Processes: --unshare-pid isolates the process tree; --die-with-parent
  kills the child if the parent exits; RLIMIT_NPROC caps the per-UID
  process count at `current_baseline + 64 + bwrap_headroom` to prevent
  fork-bomb DoS of the host PID space (the cap is dynamic because
  RLIMIT_NPROC is per-UID and a static cap would break bwrap on
  interactive desktops with many baseline processes).
- Capabilities: bwrap drops all capabilities (CapEff = 0000000000000000);
  ptrace fails EPERM; raw sockets fail EPERM. Real seccomp filter is
  deferred to Phase 3c (currently we rely on namespace + capability
  isolation for syscall-level defense).
  Defense in depth: prctl(PR_SET_DUMPABLE, 0) applied in preexec masks
  bwrap's /proc/<pid>/cmdline / environ / maps from other UIDs on the
  host. Bwrap argv path leakage to the SCRIPT (via /proc/1/cmdline) is
  not closeable from this layer alone — the script and bwrap share a UID
  in bwrap's user-ns. Mitigation lives in Task 11: use opaque temp paths
  via tempfile.mkdtemp so the bwrap argv doesn't carry the host worktree
  name, project name, or findings path.
- Resources: setrlimit applied in preexec_fn bounds CPU time (RLIMIT_CPU),
  address space (RLIMIT_AS = 512 MB), open files (RLIMIT_NOFILE = 256),
  process count per UID (RLIMIT_NPROC, dynamic — see Processes bullet),
  and per-file size (RLIMIT_FSIZE = 4 MB). FSIZE bounds /findings writes
  AND parent-side tempfile stdout/stderr writes via inherited fds.
- Stdio: stdout/stderr captured to bounded tempfiles, then read with a
  1 MB cap per stream — prevents the script from OOM'ing the parent
  via runaway output.
- Wall clock: subprocess.run timeout kills the child if it exceeds the
  budget; verified empirically to fire within tens of ms of the limit.
"""

from __future__ import annotations

import os
import resource
import subprocess
import sys
import tempfile
from pathlib import Path
from time import monotonic

from screw_agents.models import SandboxResult


# Per-file write cap applied via RLIMIT_FSIZE in preexec_fn. Bounds:
#  (a) /findings/findings.json (the script's intentional output)
#  (b) parent-side tempfile stdout/stderr via inherited file descriptors
#      (writes from inside the sandbox to those fds count against this limit)
# 4 MB is generous for a JSON findings buffer (typical < 100 KB) and bounds
# stdout/stderr abuse to a small constant per stream.
_MAX_FILE_SIZE_BYTES = 4 * 1024 * 1024  # 4 MB

# Read-side cap applied when reading the captured stdout/stderr tempfiles.
# Belt-and-suspenders with RLIMIT_FSIZE: even if FSIZE were misapplied, we
# never load more than 1 MB per stream into orchestrator memory.
_MAX_OUTPUT_BYTES = 1024 * 1024  # 1 MB

# Per-script process budget added on top of the user's existing process
# count when computing the RLIMIT_NPROC cap. RLIMIT_NPROC is enforced
# per-UID by the kernel, NOT per-process — so it counts ALL processes
# owned by the invoking user, including the user's desktop session,
# editors, browsers, etc. Setting NPROC=64 statically would prevent
# bwrap from cloning on any desktop with >50 baseline processes.
#
# Instead we cap at `baseline + _SCRIPT_PROCESS_BUDGET + _BWRAP_HEADROOM`,
# computed at run_in_sandbox call time. This still bounds fork bombs:
# the script can fork at most _SCRIPT_PROCESS_BUDGET times before EAGAIN,
# regardless of how many baseline processes the user has. Caps fork-bomb
# DoS of the host PID space (typical kernel.pid_max = 32K-128K) at a
# small constant per sandbox invocation.
_SCRIPT_PROCESS_BUDGET = 64
# bwrap's namespace setup empirically needs much more headroom than expected:
# the clone(CLONE_NEWPID|CLONE_NEWUSER|...) sequence transiently allocates
# many process slots in the parent's UID accounting (kernel checks NPROC at
# every clone phase, including the userns + pidns init forks). On a baseline
# of ~30 processes, bwrap needs the cap raised to ~150 just to enter the
# namespace; below that, clone() returns EAGAIN with "Creating new namespace
# failed: Resource temporarily unavailable". 128 gives margin for kernel
# variation while keeping the script's effective fork-bomb cap < 200 (the
# B2 regression test threshold).
_BWRAP_HEADROOM = 128

# File descriptor cap. 256 covers stdlib startup (cert bundles, .pth files,
# importlib resources) with margin; defends against fd-exhaustion abuse.
_MAX_OPEN_FILES = 256


# Aggregate-size cap on the findings_path directory after script execution.
# RLIMIT_FSIZE caps individual file size at 4 MB but doesn't bound the total
# number of files. Without this, a script writing N small files can exhaust
# the host filesystem (Layer 5 BLOCKER 2: reviewer demonstrated 2 GB written
# via 2000 × 1 MB files in 31 ms). Set to 16 MB — generous for legitimate
# multi-format output (JSON + Markdown + CSV ~ a few MB total) and bounded
# enough that a malicious script can't fill /tmp.
_MAX_FINDINGS_AGGREGATE_BYTES = 16 * 1024 * 1024  # 16 MB


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
        # --- Namespace isolation ---
        "--unshare-net",
        "--unshare-pid",
        "--unshare-ipc",
        "--unshare-uts",
        "--die-with-parent",
        "--hostname", "sandbox",  # mask host system name (Layer 5 M3)
        # --chdir / forces the sandboxed process's CWD (and PWD env) to /.
        # Without this, bwrap inherits the parent's CWD — which on a typical
        # invocation is the host worktree path, leaking the project location
        # into the sandbox via os.getcwd() and PWD.
        "--chdir", "/",
        # --- Environment hygiene (Layer 5 B1: closes /proc/1/environ exfil) ---
        "--clearenv",  # strip ALL parent env vars before any --setenv
        # --- Read-only system mounts ---
        "--ro-bind", "/usr", "/usr",
        "--ro-bind", "/lib", "/lib",
        "--ro-bind-try", "/lib64", "/lib64",
        # /etc must be a tmpfs so we can place ld.so.cache; without an explicit
        # --tmpfs, bwrap creates /etc on the root tmpfs and leaves it WRITABLE
        # (a script could drop a fake /etc/passwd or /etc/nsswitch.conf, which,
        # though ephemeral, could mislead any tooling the script invokes).
        # --remount-ro after the bind makes /etc read-only.
        "--tmpfs", "/etc",
        "--ro-bind-try", "/etc/ld.so.cache", "/etc/ld.so.cache",
        "--remount-ro", "/etc",
        # NOTE: /etc/resolv.conf intentionally NOT bound. Network is
        # unshared so DNS would never resolve anyway; the bind would only
        # leak the user's nameserver IPs (corp DNS, ad-blocker, etc.) as
        # reconnaissance value to the sandboxed script.
        # --- Python install + screw_agents (venv-binding fix from prior commit) ---
        "--ro-bind", str(python_install_root), str(python_install_root),
        "--ro-bind-try", str(python_install_parent), str(python_install_parent),
        "--ro-bind", str(venv_root), str(venv_root),
        "--ro-bind", str(screw_pkg_root), str(screw_pkg_root),
        # --- Project root + findings buffer + script ---
        "--ro-bind", str(project_root), "/project",
        "--bind", str(findings_path), "/findings",
        "--ro-bind", str(script_path), "/script.py",
        # --- Tmpfs / virtual filesystems ---
        "--tmpfs", "/tmp",
        "--tmpfs", "/var",
        "--proc", "/proc",
        "--dev", "/dev",
        # --- Explicit env injection (post --clearenv) ---
        # Only the variables the script's Python runtime + screw_agents need.
        # No PYTHONPATH / PYTHONHOME (Python -I ignores them anyway).
        "--setenv", "PYTHONDONTWRITEBYTECODE", "1",
        "--setenv", "PATH", "/usr/bin",
        "--setenv", "HOME", "/tmp",  # some stdlib paths consult HOME
        "--setenv", "LANG", "C.UTF-8",  # PEP 540 + explicit UTF-8 for str/bytes
        "--setenv", "SCREW_FINDINGS_PATH", "/findings/findings.json",
        "--setenv", "SCREW_PROJECT_ROOT", "/project",
        # --- Remount root read-only (must be after all binds) ---
        # Without this, the root tmpfs is writable so a script can do
        # `open('/anything', 'w')` even though we never bound anything writable
        # at /. The writes are ephemeral (die with the sandbox) but a
        # malicious script could place fake binaries in / that subsequent
        # in-sandbox tooling might pick up.
        "--remount-ro", "/",
        # --- Invocation ---
        "--",
        str(venv_python_unresolved),  # unresolved so Python finds pyvenv.cfg
        "-u",  # unbuffered stdout/stderr
        "-B",  # don't write .pyc files
        "-I",  # isolated mode: ignore PYTHONPATH/PYTHONHOME, no -E env vars
        "/script.py",
    ]

    # BLOCKER 1b defense: clean findings_path of residual files from prior
    # invocations BEFORE the script runs. Without this, a malicious script
    # from a prior run could have left a symlink at findings.json that the
    # NEXT (benign) script's findings would resolve through to a host file.
    _clean_findings_path(findings_path)

    # Compute the dynamic NPROC cap once, in the parent, before forking. RLIMIT_NPROC
    # is per-UID, so we must add the user's existing process count to the per-script
    # budget — otherwise we'd block bwrap's own clone() on any normal desktop.
    nproc_cap = _compute_nproc_cap()

    def _preexec() -> None:
        """Apply setrlimit in the child before exec — Layer 4 of defense stack.

        Bounds (in order applied):
        - RLIMIT_CPU: SIGXCPU when total CPU time exceeds budget
        - RLIMIT_AS:  mmap/brk fail when address space exceeds budget
        - RLIMIT_NPROC: fork() returns EAGAIN beyond per-UID process cap;
          blocks fork-bomb DoS of the host PID space (Layer 5 B2 fix).
          Cap is dynamic: baseline UID process count + per-script budget
          + bwrap headroom. See `_compute_nproc_cap` for rationale.
        - RLIMIT_NOFILE: open() returns EMFILE beyond fd cap; defends
          against fd-exhaustion abuse (raised from 64 to 256 to clear the
          stdlib startup floor — cert bundles, .pth files, importlib
          resources)
        - RLIMIT_FSIZE: write() returns EFBIG / SIGXFSZ beyond per-file
          cap; bounds /findings writes AND parent-side tempfile stdout/
          stderr writes via inherited fds (Layer 5 B3 + M1 fix)
        """
        resource.setrlimit(resource.RLIMIT_CPU, (cpu_limit_s, cpu_limit_s))
        resource.setrlimit(resource.RLIMIT_AS, (memory_limit_mb * 1024 * 1024,) * 2)
        resource.setrlimit(resource.RLIMIT_NPROC, (nproc_cap, nproc_cap))
        resource.setrlimit(resource.RLIMIT_NOFILE, (_MAX_OPEN_FILES, _MAX_OPEN_FILES))
        resource.setrlimit(resource.RLIMIT_FSIZE, (_MAX_FILE_SIZE_BYTES, _MAX_FILE_SIZE_BYTES))
        # PR_SET_DUMPABLE = 0 makes /proc/<pid>/cmdline, /proc/<pid>/environ,
        # /proc/<pid>/maps, etc. unreadable except by the process owner (root
        # or same-UID). The sandboxed script runs as the same UID as bwrap so
        # this doesn't fully hide bwrap's cmdline FROM the script (same-UID
        # can read same-UID's /proc), but it hides them from any OTHER user
        # (host operator running `ps -ef` won't see the bwrap argv with full
        # paths, reducing the attack surface for other privilege boundaries).
        # Real fix for /proc/1/cmdline path leakage to the script lives in
        # Task 11 (use opaque temp paths via tempfile.mkdtemp so the bwrap
        # argv doesn't carry the host worktree name); this prctl is defense
        # in depth for the host-side process listing.
        try:
            import ctypes
            libc = ctypes.CDLL("libc.so.6", use_errno=True)
            PR_SET_DUMPABLE = 4
            libc.prctl(PR_SET_DUMPABLE, 0, 0, 0, 0)
        except (OSError, AttributeError):
            # Not fatal — prctl is best-effort hardening.
            pass

    # Bwrap-process environment hygiene (Layer 5 B1 fix, deeper layer):
    # `--clearenv` only clears the env of the CHILD that bwrap exec()s;
    # bwrap ITSELF still inherits the parent Python's full environment.
    # Inside the sandbox PID namespace, /proc/1 IS the bwrap process —
    # so a script reading /proc/1/environ would see bwrap's environ,
    # which holds parent secrets (ANTHROPIC_API_KEY, OAUTH_TOKEN, etc.).
    # Pass an empty env to subprocess.run so bwrap itself starts with
    # a clean environment, defeating the /proc/1/environ read vector.
    bwrap_env: dict[str, str] = {}

    start = monotonic()
    killed_by_timeout = False
    # Bounded tempfile capture (Layer 5 B3 fix): unbounded `capture_output`
    # could OOM the parent if a malicious script writes multi-GB to stdout
    # before the wall-clock kill fires. Tempfiles bound at the read side
    # via _MAX_OUTPUT_BYTES; RLIMIT_FSIZE in preexec bounds the write side.
    with tempfile.TemporaryFile() as out_file, tempfile.TemporaryFile() as err_file:
        try:
            completed = subprocess.run(
                bwrap_args,
                timeout=wall_clock_s,
                stdout=out_file,
                stderr=err_file,
                preexec_fn=_preexec,
                env=bwrap_env,
                check=False,
            )
            returncode = completed.returncode
        except subprocess.TimeoutExpired:
            returncode = -1
            killed_by_timeout = True
        # Read at most _MAX_OUTPUT_BYTES from each stream regardless of how
        # much was actually written. Belt-and-suspenders with RLIMIT_FSIZE.
        out_file.seek(0)
        err_file.seek(0)
        stdout = out_file.read(_MAX_OUTPUT_BYTES)
        stderr = err_file.read(_MAX_OUTPUT_BYTES)
    elapsed = monotonic() - start

    # BLOCKER 2 defense: refuse to use findings if the script wrote more than
    # the aggregate cap (script may have filled host /tmp). Check FIRST
    # before reading findings.json so we surface the issue.
    aggregate_bytes = _check_findings_aggregate_size(findings_path)
    if aggregate_bytes > _MAX_FINDINGS_AGGREGATE_BYTES:
        # Script wrote excessive data — refuse findings, leave the directory
        # for the caller to inspect/clean. Do NOT auto-delete (the caller
        # provided this path; the caller should decide cleanup policy).
        findings_json = None
    else:
        # BLOCKER 1 defense: read findings.json with O_NOFOLLOW + lstat-
        # symlink rejection so a script that swapped findings.json for a
        # symlink to /home/<user>/.ssh/id_rsa cannot exfil host files
        # through the orchestrator.
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


def _find_screw_agents_root() -> Path:
    """Return the filesystem path where screw_agents is installed so bwrap can bind-mount it."""
    import screw_agents
    return Path(screw_agents.__file__).resolve().parent.parent


def _compute_nproc_cap() -> int:
    """Compute a per-invocation RLIMIT_NPROC cap that bounds fork bombs without
    breaking bwrap on systems with a populated user session.

    RLIMIT_NPROC is per-UID, not per-process: it counts ALL processes owned by
    the current user (desktop session, editors, browsers, the orchestrator
    itself). A static cap of 64 would prevent bwrap from cloning to set up
    namespaces on any normal interactive desktop. Instead we add a small
    per-script budget on top of the live baseline: the script can fork at
    most _SCRIPT_PROCESS_BUDGET more times before EAGAIN, regardless of
    baseline. The race window between counting and exec is benign — if
    baseline grows by N during the gap, the script's effective budget shrinks
    by N (still bounded).

    Reads /proc/<uid>/* directly to avoid spawning a `ps` subprocess (which
    would itself grow the count by 1 transiently).
    """
    uid = os.getuid()
    count = 0
    try:
        for entry in os.scandir("/proc"):
            if not entry.name.isdigit():
                continue
            try:
                # st_uid of /proc/<pid> is the process's real UID
                if entry.stat().st_uid == uid:
                    count += 1
            except (FileNotFoundError, PermissionError):
                # Process may have exited between scandir and stat; skip.
                continue
    except OSError:
        # /proc unreadable — extremely unusual; fall back to a generous cap
        # that still bounds fork bombs at < 1000 successful forks.
        count = 256
    return count + _SCRIPT_PROCESS_BUDGET + _BWRAP_HEADROOM


def _safe_read_findings(findings_file: Path) -> str | None:
    """Read findings_file's contents, refusing to follow symlinks.

    Closes Layer 5 BLOCKER 1: a malicious script inside the sandbox could
    `os.symlink("/any/host/path", "/findings/findings.json")`. The host-side
    orchestrator's `read_text()` would follow the symlink and return arbitrary
    host file contents. Two-layer defense:
    1. lstat first to refuse if the path is a symlink at all
    2. open() with O_NOFOLLOW for TOCTOU safety against a swap between
       the lstat and the open

    Returns None on missing file, symlink, ELOOP, or any read error — the
    sandbox returning "no findings" is preferable to leaking host data.
    """
    import errno
    import stat as stat_mod

    try:
        st = os.lstat(findings_file)
    except FileNotFoundError:
        return None
    except OSError:
        return None

    # Refuse if it's anything other than a regular file. Symlinks (S_ISLNK),
    # directories, devices, FIFOs all rejected.
    if not stat_mod.S_ISREG(st.st_mode):
        return None

    try:
        # O_NOFOLLOW causes open() to fail with ELOOP if the path is a symlink
        # at the moment of open. Belt-and-suspenders with the lstat above —
        # closes a TOCTOU window where a script swaps the regular file for a
        # symlink between our lstat and our open.
        fd = os.open(findings_file, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            return None  # symlink raced in
        return None

    try:
        # Bounded read defends against a script that grew the file between
        # our lstat (when it might have been small) and our open (when it
        # might be at the FSIZE cap of 4 MB). Read at most _MAX_OUTPUT_BYTES
        # which is the same cap we apply to stdout/stderr.
        data = os.read(fd, _MAX_OUTPUT_BYTES)
    finally:
        os.close(fd)

    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        # Malformed JSON (script wrote binary garbage) — return as replaced text
        # so the executor's downstream JSON parsing fails cleanly rather than
        # the orchestrator raising UnicodeDecodeError.
        return data.decode("utf-8", errors="replace")


def _clean_findings_path(findings_path: Path) -> None:
    """Remove residual files from a prior sandbox invocation (defense against
    symlink-poisoning persisting across runs — Layer 5 BLOCKER 1b).

    Walks findings_path and removes regular files + symlinks (NOT directories,
    which would require recursive descent that itself raises symlink-attack
    concerns). If the directory contains anything that isn't a regular file
    or a symlink, leaves it alone (most likely caller error; we don't try to
    fix it).

    The unlinks are scoped to direct children of findings_path; we never
    descend into subdirectories. The caller's responsibility to provide a
    sane findings_path (the orchestrator at Task 11 will create a dedicated
    temp dir per run).
    """
    try:
        for entry in findings_path.iterdir():
            try:
                # is_symlink() does NOT follow the symlink — safe to call.
                if entry.is_symlink() or entry.is_file():
                    entry.unlink()
            except OSError:
                # Ignore unlinkable entries; the worst case is the next run's
                # symlink defense rejects whatever's there.
                continue
    except OSError:
        # findings_path doesn't exist or is unreadable; nothing to clean.
        pass


def _check_findings_aggregate_size(findings_path: Path) -> int:
    """Return the aggregate byte size of regular files directly under
    findings_path.

    Used post-execution to detect the BLOCKER 2 attack (script writes many
    small files to fill the host filesystem). Does NOT follow symlinks
    (uses lstat / S_ISREG). Does NOT descend into subdirectories.
    """
    import stat as stat_mod

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
