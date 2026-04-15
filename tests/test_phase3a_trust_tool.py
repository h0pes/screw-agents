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
    """A fresh project with no exclusions returns zero counts."""
    result = engine.verify_trust(project_root=tmp_path)
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
    """assemble_scan response includes trust_status when project_root is provided."""
    # We don't need real source files for this test — just verify the response shape
    result = engine.assemble_scan(
        agent_name="sqli",
        target={"type": "glob", "pattern": str(tmp_path / "**")},
        project_root=tmp_path,
    )
    assert "trust_status" in result
    assert "exclusion_quarantine_count" in result["trust_status"]
