"""End-to-end integration tests for Phase 3a PR #2 learning aggregation."""

from __future__ import annotations

from pathlib import Path

import pytest

from screw_agents.cli.init_trust import run_init_trust
from screw_agents.engine import ScanEngine
from screw_agents.learning import record_exclusion
from screw_agents.models import ExclusionFinding, ExclusionInput, ExclusionScope


def test_full_aggregation_flow_signed_exclusions(tmp_path: Path):
    """End-to-end: init-trust → record N exclusions → aggregate → validate all 3 reports."""
    # 1. Initialize trust
    run_init_trust(project_root=tmp_path, name="Marco", email="marco@example.com")

    # 2. Record 12 exclusions matching the same pattern
    for i in range(12):
        record_exclusion(
            tmp_path,
            ExclusionInput(
                agent="sqli",
                finding=ExclusionFinding(
                    file=f"src/services/s{i}.py",
                    line=42,
                    code_pattern="db.text_search(*)",
                    cwe="CWE-89",
                ),
                reason="full-text search with parameterized internals",
                scope=ExclusionScope(type="pattern", pattern="db.text_search(*)"),
            ),
        )

    # 3. Record 5 exclusions concentrated in test/ directory
    for i in range(5):
        record_exclusion(
            tmp_path,
            ExclusionInput(
                agent="sqli",
                finding=ExclusionFinding(
                    file=f"test/test_a{i}.py",
                    line=10,
                    code_pattern=f"fixture_query{i}(*)",
                    cwe="CWE-89",
                ),
                reason="test fixture data",
                scope=ExclusionScope(type="exact_line", path=f"test/test_a{i}.py"),
            ),
        )

    # 4. Aggregate via the engine
    engine = ScanEngine.from_defaults()
    report = engine.aggregate_learning(project_root=tmp_path, report_type="all")

    # 5. Verify all three sections + trust_status
    assert "pattern_confidence" in report
    assert "directory_suggestions" in report
    assert "fp_report" in report
    assert "trust_status" in report

    # Pattern confidence: the db.text_search pattern is surfaced
    patterns = {s["pattern"] for s in report["pattern_confidence"]}
    assert "db.text_search(*)" in patterns

    # Directory suggestions: test/ is surfaced
    dirs = {s["directory"] for s in report["directory_suggestions"]}
    assert "test/" in dirs

    # FP report: at least one pattern surfaced
    assert len(report["fp_report"]["top_fp_patterns"]) >= 1

    # Trust status: all 17 recorded entries are active, none quarantined
    assert report["trust_status"]["exclusion_active_count"] == 17
    assert report["trust_status"]["exclusion_quarantine_count"] == 0


def test_empty_exclusions_empty_reports(tmp_path: Path):
    """With no exclusions, all three sections are present but empty (+ zero trust counts)."""
    engine = ScanEngine.from_defaults()
    report = engine.aggregate_learning(project_root=tmp_path, report_type="all")

    assert report["pattern_confidence"] == []
    assert report["directory_suggestions"] == []
    assert report["fp_report"]["top_fp_patterns"] == []
    assert report["trust_status"]["exclusion_active_count"] == 0
    assert report["trust_status"]["exclusion_quarantine_count"] == 0
