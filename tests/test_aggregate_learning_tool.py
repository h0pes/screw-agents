"""Integration tests for the aggregate_learning MCP tool."""

from __future__ import annotations

from pathlib import Path

import pytest

from screw_agents.engine import ScanEngine


def test_aggregate_learning_with_seeded_exclusions(tmp_path: Path):
    """Seed the exclusions file and call the engine method directly."""
    from screw_agents.cli.init_trust import run_init_trust
    from screw_agents.learning import record_exclusion
    from screw_agents.models import ExclusionFinding, ExclusionInput, ExclusionScope

    run_init_trust(project_root=tmp_path, name="Marco", email="marco@example.com")

    # Seed 12 exclusions for the same pattern → triggers pattern-confidence suggestion
    for i in range(12):
        record_exclusion(
            tmp_path,
            ExclusionInput(
                agent="sqli",
                finding=ExclusionFinding(
                    file=f"src/s{i}.py", line=10, code_pattern="db.text_search(*)", cwe="CWE-89"
                ),
                reason="safe internal",
                scope=ExclusionScope(type="pattern", pattern="db.text_search(*)"),
            ),
        )

    engine = ScanEngine.from_defaults()
    report = engine.aggregate_learning(project_root=tmp_path, report_type="all")
    assert "pattern_confidence" in report
    assert len(report["pattern_confidence"]) == 1
    assert report["pattern_confidence"][0]["pattern"] == "db.text_search(*)"
    assert "fp_report" in report
    assert len(report["fp_report"]["top_fp_patterns"]) >= 1
    # trust_status is always present regardless of report_type
    assert "trust_status" in report
    assert report["trust_status"]["exclusion_active_count"] == 12
    assert report["trust_status"]["exclusion_quarantine_count"] == 0


def test_aggregate_learning_filters_report_type(tmp_path: Path):
    """report_type='pattern_confidence' returns only that section (+ trust_status)."""
    engine = ScanEngine.from_defaults()
    report = engine.aggregate_learning(
        project_root=tmp_path, report_type="pattern_confidence"
    )
    assert "pattern_confidence" in report
    assert "directory_suggestions" not in report
    assert "fp_report" not in report
    # trust_status is ALWAYS present even when filtering report_type
    assert "trust_status" in report
    # No exclusions in tmp_path → counts are zero
    assert report["trust_status"]["exclusion_active_count"] == 0
    assert report["trust_status"]["exclusion_quarantine_count"] == 0


def test_aggregate_learning_rejects_invalid_report_type(tmp_path: Path):
    """Engine layer raises ValueError on unknown report_type — defense in depth."""
    engine = ScanEngine.from_defaults()
    with pytest.raises(ValueError, match="Unknown report_type"):
        engine.aggregate_learning(project_root=tmp_path, report_type="bogus")


def test_aggregate_learning_no_exclusions_file_returns_empty_reports(tmp_path: Path):
    """When .screw/learning/exclusions.yaml doesn't exist, reports are empty + trust_status=0."""
    # tmp_path has no .screw/ directory — load_exclusions returns []
    engine = ScanEngine.from_defaults()
    report = engine.aggregate_learning(project_root=tmp_path, report_type="all")

    assert report["pattern_confidence"] == []
    assert report["directory_suggestions"] == []
    assert report["fp_report"]["top_fp_patterns"] == []
    assert report["trust_status"]["exclusion_active_count"] == 0
    assert report["trust_status"]["exclusion_quarantine_count"] == 0


def test_aggregate_learning_surfaces_quarantined_count(tmp_path: Path):
    """trust_status reports quarantined exclusions separately from active."""
    from screw_agents.cli.init_trust import run_init_trust
    from screw_agents.learning import record_exclusion
    from screw_agents.models import ExclusionFinding, ExclusionInput, ExclusionScope

    run_init_trust(project_root=tmp_path, name="Marco", email="marco@example.com")

    # Record 3 valid exclusions
    for i in range(3):
        record_exclusion(
            tmp_path,
            ExclusionInput(
                agent="sqli",
                finding=ExclusionFinding(
                    file=f"src/s{i}.py", line=10, code_pattern="safe_call(*)", cwe="CWE-89"
                ),
                reason="safe",
                scope=ExclusionScope(type="pattern", pattern="safe_call(*)"),
            ),
        )

    # Tamper one entry's signature so it quarantines on reload.
    # YAML emits the signature as a bare scalar (no surrounding quotes), so
    # prefix-inject an 'A' into the first signature value — this decodes as
    # valid base64 but produces a different ciphertext than what Ed25519 signed.
    excl_path = tmp_path / ".screw" / "learning" / "exclusions.yaml"
    text = excl_path.read_text()
    text = text.replace("signature: ", "signature: A", 1)
    excl_path.write_text(text)

    engine = ScanEngine.from_defaults()
    report = engine.aggregate_learning(project_root=tmp_path, report_type="all")
    assert report["trust_status"]["exclusion_quarantine_count"] == 1
    assert report["trust_status"]["exclusion_active_count"] == 2
    # Only active (2) exclusions count toward aggregation, so no pattern-confidence suggestion
    # (threshold is >= 3 for _PATTERN_MIN_COUNT).
    assert report["pattern_confidence"] == []


def test_aggregate_learning_emits_trust_notice_when_quarantined(tmp_path: Path):
    """When exclusion_quarantine_count > 0, trust_status.notice_markdown is populated
    with a server-rendered block that the subagent can output verbatim.

    T21-m2: eliminates LLM discretion from the trust-notice render path. The
    server composes the Markdown; the subagent copies it. Covers Markdown-
    injection drift across LLM model versions.
    """
    from screw_agents.cli.init_trust import run_init_trust
    from screw_agents.learning import record_exclusion
    from screw_agents.models import ExclusionFinding, ExclusionInput, ExclusionScope

    run_init_trust(project_root=tmp_path, name="Marco", email="marco@example.com")

    # Seed one exclusion, then tamper its signature so it quarantines on reload.
    # Mirrors the pattern in test_aggregate_learning_surfaces_quarantined_count
    # above — YAML emits the signature as a bare scalar, so prefix-injecting
    # 'A' yields valid base64 with a different ciphertext than Ed25519 signed.
    record_exclusion(
        tmp_path,
        ExclusionInput(
            agent="sqli",
            finding=ExclusionFinding(
                file="src/s0.py", line=10, code_pattern="safe_call(*)", cwe="CWE-89"
            ),
            reason="safe",
            scope=ExclusionScope(type="pattern", pattern="safe_call(*)"),
        ),
    )
    excl_path = tmp_path / ".screw" / "learning" / "exclusions.yaml"
    text = excl_path.read_text()
    text = text.replace("signature: ", "signature: A", 1)
    excl_path.write_text(text)

    engine = ScanEngine.from_defaults()
    report = engine.aggregate_learning(project_root=tmp_path, report_type="all")

    trust = report["trust_status"]
    assert trust["exclusion_quarantine_count"] >= 1
    assert "notice_markdown" in trust
    notice = trust["notice_markdown"]
    # Deterministic server-rendered Markdown block — verbatim for the subagent.
    assert notice.startswith("⚠")
    assert "quarantine" in notice.lower()
    # Bold marker + both backticked CLI hints present.
    assert "**" in notice
    assert "`screw-agents validate-exclusion" in notice
    assert "`screw-agents migrate-exclusions`" in notice


def test_aggregate_learning_omits_trust_notice_when_clean(tmp_path: Path):
    """No quarantined entries => notice_markdown is empty string.

    T21-m2: the key is always present (even when empty) so the subagent can do
    a simple truthy check without KeyError-handling gymnastics.
    """
    engine = ScanEngine.from_defaults()
    report = engine.aggregate_learning(project_root=tmp_path, report_type="all")

    trust = report["trust_status"]
    assert trust["exclusion_quarantine_count"] == 0
    # Presence-with-empty, not absence — stable contract for the subagent.
    assert "notice_markdown" in trust
    assert trust["notice_markdown"] == ""
