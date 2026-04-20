"""Tests for the verify_trust MCP tool and trust_status in scan responses."""

from __future__ import annotations

from pathlib import Path

import pytest

from screw_agents.engine import ScanEngine
from screw_agents.registry import AgentRegistry


@pytest.fixture
def engine(domains_dir: Path) -> ScanEngine:
    registry = AgentRegistry(domains_dir)
    return ScanEngine(registry)


def test_verify_trust_empty_project(engine: ScanEngine, tmp_path: Path):
    """A fresh project with no exclusions returns zero counts.

    T10-M3: Also pins the 4-key dict-shape contract — Phase 3b Task 14
    consumers depend on script_quarantine_count / script_active_count being
    present even when zero. A future refactor that drops zero-valued keys
    would silently break the contract.
    """
    result = engine.verify_trust(project_root=tmp_path)
    assert set(result.keys()) == {
        "exclusion_quarantine_count",
        "exclusion_active_count",
        "script_quarantine_count",
        "script_active_count",
    }
    assert result["exclusion_quarantine_count"] == 0
    assert result["exclusion_active_count"] == 0
    assert result["script_quarantine_count"] == 0
    assert result["script_active_count"] == 0


def test_verify_trust_reports_quarantined_unsigned(engine: ScanEngine, tmp_path: Path):
    """An unsigned exclusion + reject policy → quarantine count of 1."""
    screw = tmp_path / ".screw"
    (screw / "learning").mkdir(parents=True)
    (screw / "learning" / "exclusions.yaml").write_text(
        """
exclusions:
  - id: "fp-2026-04-14-001"
    created: "2026-04-14T10:00:00Z"
    agent: sqli
    finding:
      file: "src/a.py"
      line: 10
      code_pattern: "*"
      cwe: "CWE-89"
    reason: "unsigned"
    scope:
      type: "exact_line"
      path: "src/a.py"
"""
    )
    (screw / "config.yaml").write_text(
        "version: 1\nlegacy_unsigned_exclusions: reject\n"
    )

    result = engine.verify_trust(project_root=tmp_path)
    assert result["exclusion_quarantine_count"] == 1
    assert result["exclusion_active_count"] == 0


def test_scan_sqli_response_includes_trust_status(engine: ScanEngine, tmp_path: Path):
    """assemble_scan response includes trust_status when project_root is provided.

    T10-M5: Also asserts value types — keys-exist alone would let a future
    refactor swap ints for None or strings unnoticed.
    """
    # We don't need real source files for this test — just verify the response shape
    result = engine.assemble_scan(
        agent_name="sqli",
        target={"type": "glob", "pattern": str(tmp_path / "**")},
        project_root=tmp_path,
    )
    assert "trust_status" in result
    assert "exclusion_quarantine_count" in result["trust_status"]
    assert isinstance(result["trust_status"]["exclusion_quarantine_count"], int)
    assert isinstance(result["trust_status"]["exclusion_active_count"], int)


def test_assemble_scan_omits_trust_status_when_no_project_root(
    engine: ScanEngine, tmp_path: Path
):
    """T10-M4: trust_status must be absent when project_root is not provided.

    Pins the backwards-compat gate at engine.assemble_scan: callers that
    don't pass project_root (e.g., legacy Phase 2 callers, ad-hoc CLI
    invocations) must not see trust_status in the response — its presence
    is an opt-in feature gated on project_root.
    """
    result = engine.assemble_scan(
        agent_name="sqli",
        target={"type": "glob", "pattern": str(tmp_path / "**")},
    )
    assert "trust_status" not in result


def test_assemble_scan_omits_quarantined_exclusions_from_subagent_list(
    engine: ScanEngine, tmp_path: Path
):
    """assemble_scan must NOT include quarantined exclusions in the
    subagent-facing exclusions list. The subagent should never see entries
    it cannot safely apply — exposing them risks inconsistent behavior
    where the subagent treats a tampered entry as actionable.

    trust_status (computed from the unfiltered list) still reports the
    quarantine count separately so the conversational summary surfaces the
    warning. This test pins the boundary: subagent-facing list excludes
    quarantined; trust_status counts include them.

    Round-trip regression: paired with the match_exclusions defense, this
    test pins the second half of the integrity boundary fix from the
    Phase 3a PR#1 round-trip manual test.
    """
    # Seed an unsigned exclusion → quarantines under default reject policy
    screw = tmp_path / ".screw"
    (screw / "learning").mkdir(parents=True)
    (screw / "learning" / "exclusions.yaml").write_text(
        """
exclusions:
  - id: "fp-2026-04-16-001"
    created: "2026-04-16T07:46:50Z"
    agent: sqli
    finding:
      file: "src/api.py"
      line: 42
      code_pattern: "cursor.execute(*)"
      cwe: "CWE-89"
    reason: "tampered — signature stripped"
    scope:
      type: "exact_line"
      path: "src/api.py"
"""
    )
    (screw / "config.yaml").write_text(
        "version: 1\nlegacy_unsigned_exclusions: reject\n"
    )

    result = engine.assemble_scan(
        agent_name="sqli",
        target={"type": "glob", "pattern": str(tmp_path / "**")},
        project_root=tmp_path,
    )

    # trust_status counts the quarantine
    assert result["trust_status"]["exclusion_quarantine_count"] == 1
    assert result["trust_status"]["exclusion_active_count"] == 0
    # Subagent-facing exclusions list omits the quarantined entry
    assert result["exclusions"] == []


def test_verify_trust_counts_signed_adaptive_scripts(
    engine: ScanEngine, tmp_path: Path
):
    """Phase 3b T20 regression: verify_trust must count a signed adaptive
    script as `script_active_count=1`, not quarantine it.

    Locks the end-to-end composition of:
      - init-trust (registers local key as script_reviewer)
      - validate-script CLI (signs the fresh script using the T18a-extracted
        `build_signed_script_meta` helper — routes through AdaptiveScriptMeta
        .model_dump() before canonicalization per T13-C1 discipline)
      - verify_trust (iterates .screw/custom-scripts/*.meta.yaml and runs
        trust.verify_script on each)

    Failure here would indicate sign/verify canonical-bytes drift — the same
    class of bug T13-C1 fixed. If this test ever fails, first check whether
    validate-script's canonicalization path still matches verify_trust's.

    Note on stale detection: the plan's title says "Stale Script Detection
    (Exposes in verify_trust)" but `verify_trust` aggregates only signing
    counts (fast, called on every scan). Per-script stale detection is a
    cleanup-path concern surfaced in T21's `list_adaptive_scripts` output
    (where the AST-walk cost is paid on-demand when the user runs
    `/screw:adaptive-cleanup`), not in `verify_trust`'s hot path.
    """
    from screw_agents.cli.init_trust import run_init_trust
    from screw_agents.cli.validate_script import run_validate_script

    # Register local Ed25519 key as a trusted script_reviewer.
    run_init_trust(project_root=tmp_path, name="Marco", email="marco@example.com")

    # Write a fresh (unsigned) adaptive script + meta. validate-script will
    # recompute sha256 and sign it (T13-C1-correct path).
    script_dir = tmp_path / ".screw" / "custom-scripts"
    script_dir.mkdir(parents=True)
    (script_dir / "test.py").write_text(
        "from screw_agents.adaptive import emit_finding\n"
        "def analyze(project):\n"
        "    pass\n"
    )
    (script_dir / "test.meta.yaml").write_text(
        "name: test\n"
        'created: "2026-04-14T10:00:00Z"\n'
        "created_by: marco@example.com\n"
        "domain: injection-input-handling\n"
        "description: test fixture for T20 verify_trust signing count\n"
        "target_patterns: []\n"
        "sha256: placeholder\n"  # recomputed by validate-script
    )

    sign_result = run_validate_script(project_root=tmp_path, script_name="test")
    assert sign_result["status"] == "validated", (
        f"validate-script expected to succeed; got {sign_result}"
    )

    status = engine.verify_trust(project_root=tmp_path)
    assert status["script_active_count"] == 1, (
        f"Signed adaptive script must be counted as active; "
        f"got script_active_count={status['script_active_count']}"
    )
    assert status["script_quarantine_count"] == 0, (
        f"Signed adaptive script must NOT be quarantined; "
        f"got script_quarantine_count={status['script_quarantine_count']}"
    )
    # Exclusion counts unaffected by script-only setup
    assert status["exclusion_active_count"] == 0
    assert status["exclusion_quarantine_count"] == 0


def test_verify_trust_quarantines_unsigned_adaptive_script(
    engine: ScanEngine, tmp_path: Path
):
    """Phase 3b T20 companion regression: an UNSIGNED adaptive script
    (`.py` + `.meta.yaml` both present, but meta has no signature) must
    count as `script_quarantine_count=1`, NOT active.

    This locks the other half of the signing-count contract: an attacker
    dropping an unsigned script into .screw/custom-scripts/ must not be
    silently treated as trusted. The quarantine surface then gets surfaced
    in the trust_status section of the scan response (per the subagent
    prompt rules in T13-T18b).
    """
    from screw_agents.cli.init_trust import run_init_trust

    run_init_trust(project_root=tmp_path, name="Marco", email="marco@example.com")

    # Unsigned script — meta has NO signature/signed_by fields.
    script_dir = tmp_path / ".screw" / "custom-scripts"
    script_dir.mkdir(parents=True)
    (script_dir / "unsigned.py").write_text(
        "from screw_agents.adaptive import emit_finding\n"
        "def analyze(project):\n"
        "    pass\n"
    )
    (script_dir / "unsigned.meta.yaml").write_text(
        "name: unsigned\n"
        'created: "2026-04-14T10:00:00Z"\n'
        "created_by: attacker@example.com\n"
        "domain: injection-input-handling\n"
        "description: unsigned fixture\n"
        "target_patterns: []\n"
        "sha256: placeholder\n"
    )

    status = engine.verify_trust(project_root=tmp_path)
    assert status["script_quarantine_count"] == 1
    assert status["script_active_count"] == 0
