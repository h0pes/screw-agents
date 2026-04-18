"""Isolation regression tests for the Linux bwrap sandbox.

Each test runs a probe script through `run_in_sandbox` and asserts an
isolation property holds. These tests lock in the security properties
identified during the Layer 5 quality review — if any test fails in
the future, that's a Layer 5 escape regression.

Skipped on non-Linux or when bwrap is unavailable.
"""

from __future__ import annotations

import json
import os
import shutil
import sys
from pathlib import Path

import pytest

from screw_agents.models import SandboxResult

pytestmark = [
    pytest.mark.skipif(sys.platform != "linux", reason="Linux-only (bwrap)"),
    pytest.mark.skipif(shutil.which("bwrap") is None, reason="bubblewrap not installed"),
]


# Helper: write a probe script into tmp_path and return paths needed for run_in_sandbox.
def _setup(tmp_path: Path, script_body: str) -> tuple[Path, Path, Path]:
    script_path = tmp_path / "probe.py"
    script_path.write_text(script_body)
    findings_path = tmp_path / "findings"
    findings_path.mkdir()
    project_path = tmp_path / "project"
    project_path.mkdir()
    return script_path, project_path, findings_path


# -------------------------------------------------------------------------
# B1 regression — environment isolation
# -------------------------------------------------------------------------


def test_environ_does_not_leak_parent_secrets(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """The Layer 5 review demonstrated a working API-key exfiltration via
    /proc/1/environ. With --clearenv, the sandboxed script must NOT see
    parent env vars — set a sentinel like `SCREW_TEST_SENTINEL=secret` in
    the parent and assert it's absent from /proc/1/environ inside the
    sandbox."""
    from screw_agents.adaptive.sandbox.linux import run_in_sandbox

    monkeypatch.setenv("SCREW_TEST_SENTINEL", "supersecret-do-not-leak")
    monkeypatch.setenv("ANTHROPIC_API_KEY_FAKE", "sk-fake-test-key")

    script_path, project_path, findings_path = _setup(
        tmp_path,
        "import os\n"
        "def analyze(project):\n"
        "    with open('/proc/1/environ', 'rb') as f:\n"
        "        env = f.read()\n"
        "    out_path = os.environ.get('SCREW_FINDINGS_PATH', '/findings/findings.json')\n"
        "    with open(out_path, 'wb') as f:\n"
        "        f.write(env)\n"
        "analyze(None)\n"
    )
    result = run_in_sandbox(
        script_path=script_path,
        project_root=project_path,
        findings_path=findings_path,
        wall_clock_s=10,
    )
    # Script ran successfully (--clearenv doesn't break startup)
    assert result.returncode == 0, f"stderr={result.stderr!r}"

    # The captured /proc/1/environ contents must NOT contain parent secrets
    captured = (findings_path / "findings.json").read_bytes()
    assert b"SCREW_TEST_SENTINEL" not in captured, (
        f"parent env var SCREW_TEST_SENTINEL leaked into sandbox /proc/1/environ; "
        f"captured contents (first 500 bytes): {captured[:500]!r}"
    )
    assert b"supersecret-do-not-leak" not in captured
    assert b"ANTHROPIC_API_KEY_FAKE" not in captured
    assert b"sk-fake-test-key" not in captured


def test_environ_contains_only_explicit_setenv_vars(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Explicit verification that --clearenv + explicit --setenv leaves the
    sandbox env containing ONLY our 6 explicit vars plus bwrap-injected PWD.

    PWD is set by bwrap's chdir-to-/ (not by --setenv); we accept it in the
    allowed set because it carries no host info (always "/"). The critical
    property is that no parent-process env vars leak through."""
    from screw_agents.adaptive.sandbox.linux import run_in_sandbox

    monkeypatch.setenv("SCREW_NOISE_SHOULD_BE_GONE", "x")

    script_path, project_path, findings_path = _setup(
        tmp_path,
        "import os, json\n"
        "def analyze(project):\n"
        "    out_path = os.environ['SCREW_FINDINGS_PATH']\n"
        "    env_dump = dict(os.environ)\n"
        "    with open(out_path, 'w') as f:\n"
        "        json.dump(env_dump, f)\n"
        "analyze(None)\n"
    )
    result = run_in_sandbox(
        script_path=script_path,
        project_root=project_path,
        findings_path=findings_path,
        wall_clock_s=10,
    )
    assert result.returncode == 0, f"stderr={result.stderr!r}"

    env_dump = json.loads((findings_path / "findings.json").read_text())
    keys = set(env_dump.keys())
    # Vars we explicitly --setenv
    explicit = {
        "PYTHONDONTWRITEBYTECODE", "PATH", "HOME", "LANG",
        "SCREW_FINDINGS_PATH", "SCREW_PROJECT_ROOT",
    }
    # bwrap chdir(/) sets PWD=/; accept it but assert on its safe value
    bwrap_injected = {"PWD"}
    assert keys == explicit | bwrap_injected, (
        f"sandbox env keys = {sorted(keys)} "
        f"(expected {sorted(explicit | bwrap_injected)})"
    )
    # PWD must equal "/" — anything else would leak parent CWD info
    assert env_dump.get("PWD") == "/", f"PWD leaked host path: {env_dump.get('PWD')!r}"
    # The noise sentinel must NOT have leaked
    assert "SCREW_NOISE_SHOULD_BE_GONE" not in keys


# -------------------------------------------------------------------------
# B2 regression — fork-bomb cap
# -------------------------------------------------------------------------


def test_fork_bomb_capped_by_rlimit_nproc(tmp_path: Path):
    """RLIMIT_NPROC=64 must cause fork() to fail before the script can
    exhaust the host PID space. The Layer 5 review demonstrated 20,000
    processes forked in 4s without bound prior to this fix."""
    from screw_agents.adaptive.sandbox.linux import run_in_sandbox

    script_path, project_path, findings_path = _setup(
        tmp_path,
        "import os, json\n"
        "def analyze(project):\n"
        "    forks = 0\n"
        "    err = None\n"
        "    try:\n"
        "        for _ in range(1000):\n"
        "            pid = os.fork()\n"
        "            if pid == 0:\n"
        "                os._exit(0)  # child exits immediately\n"
        "            forks += 1\n"
        "    except OSError as e:\n"
        "        err = str(e)\n"
        "    out_path = os.environ['SCREW_FINDINGS_PATH']\n"
        "    with open(out_path, 'w') as f:\n"
        "        json.dump({'forks': forks, 'err': err}, f)\n"
        "analyze(None)\n"
    )
    result = run_in_sandbox(
        script_path=script_path,
        project_root=project_path,
        findings_path=findings_path,
        wall_clock_s=10,
    )
    # Script may exit 0 (caught the OSError) or non-zero (resource exhaustion
    # killed it) — either way, fewer than 1000 forks should have succeeded.
    data = json.loads((findings_path / "findings.json").read_text())
    assert data["forks"] < 200, (
        f"fork bomb succeeded {data['forks']} times — RLIMIT_NPROC not enforced"
    )
    assert data["err"] is not None, "fork did not eventually fail"


# -------------------------------------------------------------------------
# B3 regression — stdout/stderr OOM cap
# -------------------------------------------------------------------------


def test_stdout_capped_at_max_output_bytes(tmp_path: Path):
    """The Layer 5 review demonstrated that capture_output=True buffered
    stdout unbounded - parent OOM possible at multi-GB output. With the
    bounded tempfile + read cap, stdout returned to the orchestrator must
    be <= _MAX_OUTPUT_BYTES (1 MB)."""
    from screw_agents.adaptive.sandbox.linux import run_in_sandbox

    script_path, project_path, findings_path = _setup(
        tmp_path,
        "def analyze(project):\n"
        # 10 MB of output — well above the 1 MB read cap and the 4 MB FSIZE
        "    print('A' * (10 * 1024 * 1024))\n"
        "analyze(None)\n"
    )
    result = run_in_sandbox(
        script_path=script_path,
        project_root=project_path,
        findings_path=findings_path,
        wall_clock_s=10,
    )
    # Stdout returned to orchestrator must be at most 1 MB (the read cap)
    assert len(result.stdout) <= 1024 * 1024, (
        f"stdout was {len(result.stdout)} bytes — cap not enforced"
    )


# -------------------------------------------------------------------------
# M1 regression — file-size cap on /findings
# -------------------------------------------------------------------------


def test_findings_write_capped_by_rlimit_fsize(tmp_path: Path):
    """RLIMIT_FSIZE=4MB must cause writes to /findings to fail beyond the cap.
    The Layer 5 review demonstrated 200 MB written to /findings unbounded
    prior to this fix."""
    from screw_agents.adaptive.sandbox.linux import run_in_sandbox

    script_path, project_path, findings_path = _setup(
        tmp_path,
        "import os\n"
        "def analyze(project):\n"
        "    bytes_written = 0\n"
        "    err = None\n"
        "    try:\n"
        "        with open('/findings/huge.bin', 'wb') as f:\n"
        # Try to write 100 MB — should fail well before completing
        "            for _ in range(100):\n"
        "                f.write(b'x' * (1024 * 1024))\n"
        "                bytes_written += 1024 * 1024\n"
        "    except (OSError, IOError) as e:\n"
        "        err = type(e).__name__\n"
        "    # Note: cannot use the script's findings.json buffer here because\n"
        "    # we already filled the writable area with huge.bin. Instead, write\n"
        "    # a small marker file so the test can verify err was raised.\n"
        "    try:\n"
        "        with open('/findings/result.txt', 'w') as f:\n"
        "            f.write(f'{bytes_written},{err}')\n"
        "    except (OSError, IOError):\n"
        "        pass\n"
        "analyze(None)\n"
    )
    result = run_in_sandbox(
        script_path=script_path,
        project_root=project_path,
        findings_path=findings_path,
        wall_clock_s=15,
    )
    # The huge.bin should be capped at RLIMIT_FSIZE = 4MB
    huge_path = findings_path / "huge.bin"
    if huge_path.exists():
        assert huge_path.stat().st_size <= 4 * 1024 * 1024, (
            f"huge.bin grew to {huge_path.stat().st_size} bytes — RLIMIT_FSIZE not enforced"
        )


# -------------------------------------------------------------------------
# M2 regression — /etc/resolv.conf not bound
# -------------------------------------------------------------------------


def test_resolv_conf_not_bound(tmp_path: Path):
    """/etc/resolv.conf bind was dropped (network is unshared so DNS would
    never resolve anyway; the bind only leaked nameserver IPs). Verify it's
    not accessible from inside the sandbox."""
    from screw_agents.adaptive.sandbox.linux import run_in_sandbox

    script_path, project_path, findings_path = _setup(
        tmp_path,
        "import os, json\n"
        "def analyze(project):\n"
        "    exists = os.path.exists('/etc/resolv.conf')\n"
        "    out_path = os.environ['SCREW_FINDINGS_PATH']\n"
        "    with open(out_path, 'w') as f:\n"
        "        json.dump({'exists': exists}, f)\n"
        "analyze(None)\n"
    )
    result = run_in_sandbox(
        script_path=script_path,
        project_root=project_path,
        findings_path=findings_path,
        wall_clock_s=10,
    )
    assert result.returncode == 0, f"stderr={result.stderr!r}"
    data = json.loads((findings_path / "findings.json").read_text())
    assert data["exists"] is False, "/etc/resolv.conf still accessible — bind not dropped"


def test_python_stdlib_imports_work_without_resolv_conf(tmp_path: Path):
    """Sanity: dropping the /etc/resolv.conf bind must NOT break common
    stdlib imports. The original spec comment claimed resolv.conf was
    needed — empirically it isn't."""
    from screw_agents.adaptive.sandbox.linux import run_in_sandbox

    script_path, project_path, findings_path = _setup(
        tmp_path,
        "import json, os\n"
        "def analyze(project):\n"
        "    failures = []\n"
        "    for mod in ['socket', 'http.client', 'urllib.request', 'ssl',\n"
        "                'json', 'csv', 'pathlib', 'subprocess', 'os',\n"
        "                'tempfile', 'logging', 're', 'collections']:\n"
        "        try:\n"
        "            __import__(mod)\n"
        "        except Exception as e:\n"
        "            failures.append(f'{mod}: {e}')\n"
        "    out_path = os.environ['SCREW_FINDINGS_PATH']\n"
        "    with open(out_path, 'w') as f:\n"
        "        json.dump({'failures': failures}, f)\n"
        "analyze(None)\n"
    )
    result = run_in_sandbox(
        script_path=script_path,
        project_root=project_path,
        findings_path=findings_path,
        wall_clock_s=10,
    )
    assert result.returncode == 0, f"stderr={result.stderr!r}"
    data = json.loads((findings_path / "findings.json").read_text())
    assert data["failures"] == [], (
        f"stdlib imports failed without /etc/resolv.conf: {data['failures']}"
    )


# -------------------------------------------------------------------------
# M3 regression — hostname masked
# -------------------------------------------------------------------------


def test_hostname_is_sandbox_not_host(tmp_path: Path):
    """--hostname sandbox masks the host system name from the script."""
    from screw_agents.adaptive.sandbox.linux import run_in_sandbox

    script_path, project_path, findings_path = _setup(
        tmp_path,
        "import socket, os, json\n"
        "def analyze(project):\n"
        "    name = socket.gethostname()\n"
        "    uname_node = os.uname().nodename\n"
        "    out_path = os.environ['SCREW_FINDINGS_PATH']\n"
        "    with open(out_path, 'w') as f:\n"
        "        json.dump({'gethostname': name, 'uname_node': uname_node}, f)\n"
        "analyze(None)\n"
    )
    result = run_in_sandbox(
        script_path=script_path,
        project_root=project_path,
        findings_path=findings_path,
        wall_clock_s=10,
    )
    assert result.returncode == 0, f"stderr={result.stderr!r}"
    data = json.loads((findings_path / "findings.json").read_text())
    assert data["gethostname"] == "sandbox", f"hostname={data['gethostname']!r}"
    assert data["uname_node"] == "sandbox", f"uname.nodename={data['uname_node']!r}"


# -------------------------------------------------------------------------
# Defense-in-depth: capabilities, /proc PID isolation, /dev virtualization,
# write-only-to-findings
# -------------------------------------------------------------------------


def test_capabilities_fully_dropped(tmp_path: Path):
    """bwrap drops all capabilities; CapEff in /proc/self/status must be 0."""
    from screw_agents.adaptive.sandbox.linux import run_in_sandbox

    script_path, project_path, findings_path = _setup(
        tmp_path,
        "import os, json\n"
        "def analyze(project):\n"
        "    cap_eff = None\n"
        "    with open('/proc/self/status') as f:\n"
        "        for line in f:\n"
        "            if line.startswith('CapEff:'):\n"
        "                cap_eff = line.split()[1]\n"
        "                break\n"
        "    out_path = os.environ['SCREW_FINDINGS_PATH']\n"
        "    with open(out_path, 'w') as f:\n"
        "        json.dump({'cap_eff': cap_eff}, f)\n"
        "analyze(None)\n"
    )
    result = run_in_sandbox(
        script_path=script_path,
        project_root=project_path,
        findings_path=findings_path,
        wall_clock_s=10,
    )
    assert result.returncode == 0, f"stderr={result.stderr!r}"
    data = json.loads((findings_path / "findings.json").read_text())
    assert data["cap_eff"] == "0000000000000000", (
        f"CapEff = {data['cap_eff']!r} — capabilities not fully dropped"
    )


def test_proc_pid_isolation(tmp_path: Path):
    """--unshare-pid + --proc /proc must show only sandbox-internal PIDs,
    not host PIDs."""
    from screw_agents.adaptive.sandbox.linux import run_in_sandbox

    script_path, project_path, findings_path = _setup(
        tmp_path,
        "import os, json\n"
        "def analyze(project):\n"
        "    pids = [name for name in os.listdir('/proc') if name.isdigit()]\n"
        "    pids = sorted(int(p) for p in pids)\n"
        "    out_path = os.environ['SCREW_FINDINGS_PATH']\n"
        "    with open(out_path, 'w') as f:\n"
        "        json.dump({'pids': pids}, f)\n"
        "analyze(None)\n"
    )
    result = run_in_sandbox(
        script_path=script_path,
        project_root=project_path,
        findings_path=findings_path,
        wall_clock_s=10,
    )
    assert result.returncode == 0, f"stderr={result.stderr!r}"
    data = json.loads((findings_path / "findings.json").read_text())
    # Should see only a small number of sandbox-internal PIDs (typically 1-3)
    assert all(p <= 100 for p in data["pids"]), (
        f"saw host-range PIDs in /proc: {data['pids']}"
    )
    assert len(data["pids"]) < 20, (
        f"too many PIDs visible — PID isolation may be broken: {data['pids']}"
    )


def test_dev_does_not_expose_host_devices(tmp_path: Path):
    """--dev /dev creates a tmpfs with only standard devices (null, zero,
    random, urandom, tty). Must NOT contain /dev/input/* (keylogging risk)
    or /dev/sd*/etc."""
    from screw_agents.adaptive.sandbox.linux import run_in_sandbox

    script_path, project_path, findings_path = _setup(
        tmp_path,
        "import os, json\n"
        "def analyze(project):\n"
        "    entries = sorted(os.listdir('/dev'))\n"
        "    out_path = os.environ['SCREW_FINDINGS_PATH']\n"
        "    with open(out_path, 'w') as f:\n"
        "        json.dump({'entries': entries}, f)\n"
        "analyze(None)\n"
    )
    result = run_in_sandbox(
        script_path=script_path,
        project_root=project_path,
        findings_path=findings_path,
        wall_clock_s=10,
    )
    assert result.returncode == 0, f"stderr={result.stderr!r}"
    data = json.loads((findings_path / "findings.json").read_text())
    entries = set(data["entries"])
    assert "input" not in entries, "/dev/input exposed — keylogging possible!"
    assert not any(e.startswith("sd") for e in entries), f"/dev/sd* exposed: {entries}"
    assert not any(e.startswith("nvme") for e in entries), f"/dev/nvme* exposed: {entries}"
    assert "snd" not in entries, "/dev/snd exposed (audio devices)"
    assert "dri" not in entries, "/dev/dri exposed (GPU devices)"


def test_no_writable_paths_outside_findings(tmp_path: Path):
    """Only /findings is writable. /usr, /tmp (tmpfs), /etc, /script.py
    must all reject writes."""
    from screw_agents.adaptive.sandbox.linux import run_in_sandbox

    script_path, project_path, findings_path = _setup(
        tmp_path,
        "import os, json\n"
        "def analyze(project):\n"
        "    results = {}\n"
        "    for path in ['/usr/leak.txt', '/etc/leak.txt', '/script.py.bak',\n"
        "                 '/project/leak.txt', '/proc/leak.txt']:\n"
        "        try:\n"
        "            with open(path, 'w') as f:\n"
        "                f.write('leak')\n"
        "            results[path] = 'wrote_successfully'\n"
        "        except (OSError, IOError) as e:\n"
        "            results[path] = type(e).__name__\n"
        "    # /findings should succeed\n"
        "    try:\n"
        "        with open('/findings/test_write.txt', 'w') as f:\n"
        "            f.write('ok')\n"
        "        results['/findings/test_write.txt'] = 'wrote_successfully'\n"
        "    except Exception as e:\n"
        "        results['/findings/test_write.txt'] = type(e).__name__\n"
        "    out_path = os.environ['SCREW_FINDINGS_PATH']\n"
        "    with open(out_path, 'w') as f:\n"
        "        json.dump(results, f)\n"
        "analyze(None)\n"
    )
    result = run_in_sandbox(
        script_path=script_path,
        project_root=project_path,
        findings_path=findings_path,
        wall_clock_s=10,
    )
    assert result.returncode == 0, f"stderr={result.stderr!r}"
    data = json.loads((findings_path / "findings.json").read_text())
    # All writes outside /findings must fail
    for path, outcome in data.items():
        if path.startswith("/findings"):
            assert outcome == "wrote_successfully", f"{path} write failed: {outcome}"
        else:
            assert outcome != "wrote_successfully", f"{path} was writable! outcome: {outcome}"


def test_network_comprehensively_unreachable(tmp_path: Path):
    """--unshare-net: every network operation must fail."""
    from screw_agents.adaptive.sandbox.linux import run_in_sandbox

    script_path, project_path, findings_path = _setup(
        tmp_path,
        "import socket, os, json\n"
        "def analyze(project):\n"
        "    results = {}\n"
        "    # TCP to public DNS\n"
        "    try:\n"
        "        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
        "        s.connect(('8.8.8.8', 53))\n"
        "        results['tcp_8888'] = 'connected'\n"
        "    except OSError as e:\n"
        "        results['tcp_8888'] = type(e).__name__\n"
        "    # UDP\n"
        "    try:\n"
        "        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n"
        "        s.connect(('8.8.8.8', 53))\n"
        "        results['udp_8888'] = 'connected'\n"
        "    except OSError as e:\n"
        "        results['udp_8888'] = type(e).__name__\n"
        "    # Loopback\n"
        "    try:\n"
        "        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
        "        s.connect(('127.0.0.1', 22))\n"
        "        results['tcp_loopback'] = 'connected'\n"
        "    except OSError as e:\n"
        "        results['tcp_loopback'] = type(e).__name__\n"
        "    # Raw socket (requires CAP_NET_RAW)\n"
        "    try:\n"
        "        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)\n"
        "        results['af_packet'] = 'opened'\n"
        "    except (OSError, AttributeError) as e:\n"
        "        results['af_packet'] = type(e).__name__\n"
        "    # DNS resolution\n"
        "    try:\n"
        "        socket.gethostbyname('example.com')\n"
        "        results['dns'] = 'resolved'\n"
        "    except (socket.gaierror, OSError) as e:\n"
        "        results['dns'] = type(e).__name__\n"
        "    out_path = os.environ['SCREW_FINDINGS_PATH']\n"
        "    with open(out_path, 'w') as f:\n"
        "        json.dump(results, f)\n"
        "analyze(None)\n"
    )
    result = run_in_sandbox(
        script_path=script_path,
        project_root=project_path,
        findings_path=findings_path,
        wall_clock_s=10,
    )
    assert result.returncode == 0, f"stderr={result.stderr!r}"
    data = json.loads((findings_path / "findings.json").read_text())
    # All network operations must fail
    assert data["tcp_8888"] != "connected", f"TCP to public IP succeeded: {data}"
    assert data["udp_8888"] != "connected", f"UDP to public IP succeeded: {data}"
    assert data["tcp_loopback"] != "connected", f"TCP loopback succeeded: {data}"
    assert data["af_packet"] != "opened", f"AF_PACKET raw socket opened: {data}"
    assert data["dns"] != "resolved", f"DNS resolved: {data}"
