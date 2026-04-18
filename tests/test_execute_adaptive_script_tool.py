"""Integration tests for the execute_adaptive_script MCP tool.

Phase 3b PR#4 Task 12. Exercises ScanEngine.execute_adaptive_script end
to end, plus the verify_trust script-counting wire-in that Task 12
lifts out of the Phase 3a stub.

Coverage (5 tests):
    - happy path: seeded valid script -> full pipeline -> 1 finding dict
    - missing script source -> FileNotFoundError
    - missing meta yaml -> FileNotFoundError (meta-specific message)
    - verify_trust counts a seeded script (active or quarantined)
    - verify_trust zero counts when .screw/custom-scripts/ absent
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from screw_agents.engine import ScanEngine


# ---------------------------------------------------------------------------
# execute_adaptive_script
# ---------------------------------------------------------------------------


def test_execute_adaptive_script_happy_path(tmp_path: Path) -> None:
    """Seeded valid script + metadata -> dict with 1 finding, stale=False.

    Skipped on platforms without a sandbox backend (bwrap/sandbox-exec).
    Uses skip_trust_checks=True to bypass hash + signature layers the
    MCP tool itself does not expose (production callers cannot skip).
    """
    if shutil.which("bwrap") is None and shutil.which("sandbox-exec") is None:
        pytest.skip("no sandbox backend available on this platform")

    script_dir = tmp_path / ".screw" / "custom-scripts"
    script_dir.mkdir(parents=True)
    (script_dir / "test.py").write_text(
        "from screw_agents.adaptive import emit_finding\n"
        "def analyze(project):\n"
        "    emit_finding(cwe='CWE-89', file='a.py', line=1, "
        "message='t', severity='high')\n"
    )
    # Quote timestamp so YAML keeps it as str (AdaptiveScriptMeta expects
    # str); sha256 is quoted for symmetry even though "stub" parses as str.
    (script_dir / "test.meta.yaml").write_text(
        "name: test\n"
        "created: '2026-04-14T10:00:00Z'\n"
        "created_by: marco@example.com\n"
        "domain: injection-input-handling\n"
        "description: test\n"
        "target_patterns: []\n"
        "sha256: 'stub'\n"
    )

    engine = ScanEngine.from_defaults()
    result = engine.execute_adaptive_script(
        project_root=tmp_path,
        script_name="test",
        skip_trust_checks=True,
    )

    assert result["script_name"] == "test"
    assert result["stale"] is False
    assert len(result["findings"]) == 1
    assert result["findings"][0]["classification"]["cwe"] == "CWE-89"
    assert result["findings"][0]["classification"]["severity"] == "high"
    # sandbox_result is present but stdout/stderr bytes are excluded
    assert "sandbox_result" in result
    assert "stdout" not in result["sandbox_result"]
    assert "stderr" not in result["sandbox_result"]


def test_execute_adaptive_script_missing_script(tmp_path: Path) -> None:
    """Non-existent script name -> FileNotFoundError on the .py path."""
    engine = ScanEngine.from_defaults()
    with pytest.raises(FileNotFoundError, match="adaptive script not found"):
        engine.execute_adaptive_script(
            project_root=tmp_path,
            script_name="does-not-exist",
            skip_trust_checks=True,
        )


def test_execute_adaptive_script_missing_meta(tmp_path: Path) -> None:
    """Script.py exists but meta.yaml missing -> FileNotFoundError whose
    message identifies the metadata file (separate branch from missing .py)."""
    script_dir = tmp_path / ".screw" / "custom-scripts"
    script_dir.mkdir(parents=True)
    (script_dir / "orphan.py").write_text("def analyze(project): pass\n")
    # NO orphan.meta.yaml

    engine = ScanEngine.from_defaults()
    with pytest.raises(FileNotFoundError, match="metadata"):
        engine.execute_adaptive_script(
            project_root=tmp_path,
            script_name="orphan",
            skip_trust_checks=True,
        )


# ---------------------------------------------------------------------------
# verify_trust script-counting wire-in (Task 12)
# ---------------------------------------------------------------------------


def test_verify_trust_counts_a_seeded_script(tmp_path: Path) -> None:
    """verify_trust iterates .screw/custom-scripts/*.meta.yaml and counts
    each. Without a real Ed25519 signature the script is quarantined, but
    the point is it is SEEN (total == 1), not silently stubbed to zero."""
    script_dir = tmp_path / ".screw" / "custom-scripts"
    script_dir.mkdir(parents=True)
    (script_dir / "s.py").write_text(
        "from screw_agents.adaptive import emit_finding\n"
        "def analyze(project): pass\n"
    )
    (script_dir / "s.meta.yaml").write_text(
        "name: s\n"
        "created: '2026-04-14T10:00:00Z'\n"
        "created_by: m@e\n"
        "domain: injection-input-handling\n"
        "description: t\n"
        "target_patterns: []\n"
        "sha256: 'stub'\n"
    )

    engine = ScanEngine.from_defaults()
    trust = engine.verify_trust(project_root=tmp_path)

    # Shape: 4 keys, always.
    assert set(trust.keys()) == {
        "exclusion_active_count",
        "exclusion_quarantine_count",
        "script_active_count",
        "script_quarantine_count",
    }
    # One script seeded; must be counted somewhere.
    total_scripts = trust["script_active_count"] + trust["script_quarantine_count"]
    assert total_scripts == 1


def test_verify_trust_zero_scripts_when_dir_missing(tmp_path: Path) -> None:
    """No .screw/custom-scripts/ -> both script counts 0 (graceful)."""
    engine = ScanEngine.from_defaults()
    trust = engine.verify_trust(project_root=tmp_path)
    assert trust["script_active_count"] == 0
    assert trust["script_quarantine_count"] == 0
