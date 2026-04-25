"""Tests for registry invariants — agent-vs-domain collision and YAML filename-stem checks.

Phase 4 prereq T-SCAN-REFACTOR Task 1: bare-token slash command parser depends
on these invariants. Spec sections 10.2 + 10.3.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from screw_agents.registry import AgentRegistry


# ---------------------------------------------------------------------------
# Filename-stem assertion (Section 10.3)
# ---------------------------------------------------------------------------


def _write_minimal_agent_yaml(path: Path, *, name: str, domain: str) -> None:
    """Write a minimal valid AgentDefinition YAML to `path`."""
    path.write_text(
        f"""\
meta:
  name: {name}
  display_name: "Test Agent"
  domain: {domain}
  version: "0.1.0"
  last_updated: "2026-04-25"
  cwes:
    primary: "CWE-89"
    related: []
  capec: []
  owasp:
    top10: ""
    asvs: []
    testing_guide: ""
  sources: []
core_prompt: "test prompt"
detection_heuristics:
  high_confidence: []
  medium_confidence: []
  context_required: []
remediation:
  preferred: "use parameterized queries"
""",
        encoding="utf-8",
    )


def test_filename_stem_matches_meta_name(tmp_path: Path) -> None:
    """Registry loads cleanly when YAML filename stem equals meta.name."""
    domain_dir = tmp_path / "test-domain"
    domain_dir.mkdir()
    _write_minimal_agent_yaml(domain_dir / "agent_a.yaml", name="agent_a", domain="test-domain")

    registry = AgentRegistry(tmp_path)
    assert registry.get_agent("agent_a") is not None


def test_filename_stem_mismatch_raises(tmp_path: Path) -> None:
    """Registry refuses to load when YAML filename stem differs from meta.name."""
    domain_dir = tmp_path / "test-domain"
    domain_dir.mkdir()
    _write_minimal_agent_yaml(domain_dir / "wrong_stem.yaml", name="actual_name", domain="test-domain")

    with pytest.raises(ValueError, match="does not match meta.name"):
        AgentRegistry(tmp_path)


# ---------------------------------------------------------------------------
# Agent-vs-domain collision assertion (Section 10.2)
# ---------------------------------------------------------------------------


def test_agent_name_unique_from_domain_names(tmp_path: Path) -> None:
    """Registry loads cleanly when agent names and domain names are disjoint."""
    domain_dir = tmp_path / "domain-foo"
    domain_dir.mkdir()
    _write_minimal_agent_yaml(domain_dir / "agent_x.yaml", name="agent_x", domain="domain-foo")

    registry = AgentRegistry(tmp_path)
    assert "agent_x" in registry.agents
    assert "domain-foo" in registry.list_domains()


def test_agent_name_collides_with_domain_name_raises(tmp_path: Path) -> None:
    """Registry refuses to load when an agent name equals any domain name."""
    # Two domains: 'bar' and 'qux'. An agent in 'qux' is named 'bar' — collision.
    bar_dir = tmp_path / "bar"
    bar_dir.mkdir()
    _write_minimal_agent_yaml(bar_dir / "innocent.yaml", name="innocent", domain="bar")

    qux_dir = tmp_path / "qux"
    qux_dir.mkdir()
    _write_minimal_agent_yaml(qux_dir / "bar.yaml", name="bar", domain="qux")

    with pytest.raises(ValueError, match="collide with domain name"):
        AgentRegistry(tmp_path)


def test_existing_agent_uniqueness_check_still_enforced(tmp_path: Path) -> None:
    """Sanity check: agent-vs-agent uniqueness from registry.py:44-48 is preserved."""
    a_dir = tmp_path / "domain-a"
    a_dir.mkdir()
    _write_minimal_agent_yaml(a_dir / "dup.yaml", name="dup", domain="domain-a")

    b_dir = tmp_path / "domain-b"
    b_dir.mkdir()
    _write_minimal_agent_yaml(b_dir / "dup.yaml", name="dup", domain="domain-b")

    with pytest.raises(ValueError, match="Duplicate agent name"):
        AgentRegistry(tmp_path)
