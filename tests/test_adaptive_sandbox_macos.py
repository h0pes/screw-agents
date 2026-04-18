"""Integration tests for the macOS sandbox-exec backend.

Skipped on non-macOS platforms. UNVALIDATED on Marco's Arch dev hardware
per project memory — these tests provide structural coverage and will
exercise the actual security properties when a macOS user runs the suite.

Mirrors `test_adaptive_sandbox_linux.py` and `test_adaptive_sandbox_linux_isolation.py`
patterns: 2 functional tests (happy path, runaway timeout) + 6 isolation
regression tests (B1 symlink, B1b residual, B2 aggregate, B2 sanity,
network blocked, no-writable-paths-outside-findings).
"""

from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

import pytest

from screw_agents.models import SandboxResult

pytestmark = [
    pytest.mark.skipif(sys.platform != "darwin", reason="macOS-only (sandbox-exec)"),
    pytest.mark.skipif(shutil.which("sandbox-exec") is None, reason="sandbox-exec not available"),
]


def _setup(tmp_path: Path, script_body: str) -> tuple[Path, Path, Path]:
    script_path = tmp_path / "probe.py"
    script_path.write_text(script_body)
    findings_path = tmp_path / "findings"
    findings_path.mkdir()
    project_path = tmp_path / "project"
    project_path.mkdir()
    return script_path, project_path, findings_path


# -------------------------------------------------------------------------
# Functional tests (happy path + runaway)
# -------------------------------------------------------------------------


def test_sandbox_runs_valid_script_macos(tmp_path: Path):
    """Happy path: a script defining + invoking analyze runs to completion."""
    from screw_agents.adaptive.sandbox.macos import run_in_sandbox

    script_path, project_path, findings_path = _setup(
        tmp_path,
        "from screw_agents.adaptive import emit_finding\n"
        "def analyze(project):\n"
        "    emit_finding(cwe='CWE-89', file='x.py', line=1, message='test', severity='high')\n"
        "analyze(None)\n"
    )
    result = run_in_sandbox(
        script_path=script_path,
        project_root=project_path,
        findings_path=findings_path,
        wall_clock_s=30,
    )
    assert isinstance(result, SandboxResult)
    assert result.returncode == 0, f"stderr={result.stderr!r}"


def test_sandbox_kills_runaway_script_macos(tmp_path: Path):
    """Wall-clock kill fires for an actual runaway loop."""
    from screw_agents.adaptive.sandbox.macos import run_in_sandbox

    script_path, project_path, findings_path = _setup(
        tmp_path,
        "def analyze(project):\n"
        "    while True:\n"
        "        pass\n"
        "analyze(None)\n"
    )
    result = run_in_sandbox(
        script_path=script_path,
        project_root=project_path,
        findings_path=findings_path,
        wall_clock_s=3,
    )
    assert result.killed_by_timeout is True


# -------------------------------------------------------------------------
# Isolation regression tests (mirror Linux's test_adaptive_sandbox_linux_isolation)
# -------------------------------------------------------------------------


def test_orchestrator_refuses_symlink_findings_json_macos(tmp_path: Path):
    """BLOCKER 1: orchestrator must refuse symlinks at /findings/findings.json."""
    from screw_agents.adaptive.sandbox.macos import run_in_sandbox

    sentinel = tmp_path.parent / "macos-sandbox-exfil-sentinel.txt"
    sentinel.write_text("macos-sentinel-do-not-leak-12345")

    try:
        script_path, project_path, findings_path = _setup(
            tmp_path,
            f"import os\n"
            f"def analyze(project):\n"
            f"    fpath = os.environ['SCREW_FINDINGS_PATH']\n"
            f"    if os.path.exists(fpath):\n"
            f"        os.unlink(fpath)\n"
            f"    os.symlink({str(sentinel)!r}, fpath)\n"
            f"analyze(None)\n"
        )
        result = run_in_sandbox(
            script_path=script_path,
            project_root=project_path,
            findings_path=findings_path,
            wall_clock_s=10,
        )
        assert result.returncode == 0
        assert result.findings_json is None or "macos-sentinel" not in result.findings_json
    finally:
        try:
            sentinel.unlink()
        except OSError:
            pass


def test_orchestrator_handles_residual_symlink_macos(tmp_path: Path):
    """BLOCKER 1b: residual symlink from prior run must not exfil."""
    from screw_agents.adaptive.sandbox.macos import run_in_sandbox

    sentinel = tmp_path.parent / "macos-residual-sentinel.txt"
    sentinel.write_text("macos-residual-sentinel-67890")

    try:
        findings_path = tmp_path / "findings"
        findings_path.mkdir()
        (findings_path / "findings.json").symlink_to(sentinel)

        script_path = tmp_path / "benign.py"
        script_path.write_text("def analyze(project):\n    pass\nanalyze(None)\n")
        project_path = tmp_path / "project"
        project_path.mkdir()

        result = run_in_sandbox(
            script_path=script_path,
            project_root=project_path,
            findings_path=findings_path,
            wall_clock_s=10,
        )
        assert result.returncode == 0
        assert result.findings_json is None or "macos-residual-sentinel" not in result.findings_json
    finally:
        try:
            sentinel.unlink()
        except OSError:
            pass


def test_aggregate_findings_size_capped_macos(tmp_path: Path):
    """BLOCKER 2: aggregate findings_path size > 16 MB → orchestrator refuses."""
    from screw_agents.adaptive.sandbox.macos import run_in_sandbox

    script_path, project_path, findings_path = _setup(
        tmp_path,
        "import os\n"
        "def analyze(project):\n"
        "    for i in range(50):\n"
        "        try:\n"
        "            with open(f'{os.environ[\"SCREW_FINDINGS_PATH\"].rsplit(\"/\", 1)[0]}/file_{i:03d}.bin', 'wb') as f:\n"
        "                f.write(b'X' * (1024 * 1024))\n"
        "        except (OSError, IOError):\n"
        "            break\n"
        "    out_path = os.environ.get('SCREW_FINDINGS_PATH')\n"
        "    if out_path:\n"
        "        try:\n"
        "            with open(out_path, 'w') as f:\n"
        "                f.write('[]')\n"
        "        except (OSError, IOError):\n"
        "            pass\n"
        "analyze(None)\n"
    )
    result = run_in_sandbox(
        script_path=script_path,
        project_root=project_path,
        findings_path=findings_path,
        wall_clock_s=15,
    )
    assert result.findings_json is None


def test_aggregate_under_cap_succeeds_macos(tmp_path: Path):
    """Sanity: legitimate small findings.json passes through."""
    from screw_agents.adaptive.sandbox.macos import run_in_sandbox

    script_path, project_path, findings_path = _setup(
        tmp_path,
        "import os\n"
        "def analyze(project):\n"
        "    out_path = os.environ['SCREW_FINDINGS_PATH']\n"
        "    with open(out_path, 'w') as f:\n"
        "        f.write('[{\"cwe\": \"CWE-89\", \"line\": 1}]')\n"
        "analyze(None)\n"
    )
    result = run_in_sandbox(
        script_path=script_path,
        project_root=project_path,
        findings_path=findings_path,
        wall_clock_s=10,
    )
    assert result.returncode == 0
    assert result.findings_json is not None
    assert "CWE-89" in result.findings_json


def test_network_blocked_macos(tmp_path: Path):
    """(deny network*) blocks all network operations."""
    from screw_agents.adaptive.sandbox.macos import run_in_sandbox

    script_path, project_path, findings_path = _setup(
        tmp_path,
        "import socket, os, json\n"
        "def analyze(project):\n"
        "    results = {}\n"
        "    try:\n"
        "        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
        "        s.connect(('8.8.8.8', 53))\n"
        "        results['tcp_8888'] = 'connected'\n"
        "    except OSError as e:\n"
        "        results['tcp_8888'] = type(e).__name__\n"
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
    assert result.returncode == 0
    data = json.loads(result.findings_json)
    assert data['tcp_8888'] != 'connected'
    assert data['dns'] != 'resolved'


def test_no_writable_paths_outside_findings_macos(tmp_path: Path):
    """Only findings_path subpath is writable per Seatbelt profile."""
    from screw_agents.adaptive.sandbox.macos import run_in_sandbox

    script_path, project_path, findings_path = _setup(
        tmp_path,
        "import os, json\n"
        "def analyze(project):\n"
        "    results = {}\n"
        "    for path in ['/tmp/leak.txt', '/usr/leak.txt',\n"
        "                 '/etc/leak.txt', f'{os.environ[\"SCREW_PROJECT_ROOT\"]}/leak.txt']:\n"
        "        try:\n"
        "            with open(path, 'w') as f:\n"
        "                f.write('leak')\n"
        "            results[path] = 'wrote'\n"
        "        except (OSError, IOError) as e:\n"
        "            results[path] = type(e).__name__\n"
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
    assert result.returncode == 0
    data = json.loads(result.findings_json)
    for path, outcome in data.items():
        assert outcome != 'wrote', f"{path} was writable on macOS sandbox"
