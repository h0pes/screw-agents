"""Tests for the scan engine."""

import json
import pytest
from pathlib import Path

from screw_agents.engine import ScanEngine
from screw_agents.registry import AgentRegistry


@pytest.fixture
def engine(domains_dir):
    registry = AgentRegistry(domains_dir)
    return ScanEngine(registry)


def test_engine_assemble_prompt(engine, fixtures_dir):
    vuln_dir = fixtures_dir / "sqli" / "vulnerable"
    py_files = list(vuln_dir.glob("*.py"))
    if not py_files:
        pytest.skip("no Python fixtures")

    target = {"type": "file", "path": str(py_files[0])}
    result = engine.assemble_scan(agent_name="sqli", target=target)

    assert "core_prompt" in result
    assert "code" in result
    assert "agent_name" in result
    assert result["agent_name"] == "sqli"
    assert len(result["core_prompt"]) > 100
    assert len(result["code"]) > 0


def test_engine_assemble_prompt_unknown_agent(engine):
    target = {"type": "file", "path": "/dev/null"}
    with pytest.raises(ValueError, match="Unknown agent"):
        engine.assemble_scan(agent_name="nonexistent", target=target)


def test_engine_assemble_domain_scan(engine, fixtures_dir):
    vuln_dir = fixtures_dir / "sqli" / "vulnerable"
    py_files = list(vuln_dir.glob("*.py"))
    if not py_files:
        pytest.skip("no Python fixtures")

    target = {"type": "file", "path": str(py_files[0])}
    results = engine.assemble_domain_scan(
        domain="injection-input-handling",
        target=target,
    )
    assert len(results) == 4
    agent_names = {r["agent_name"] for r in results}
    assert agent_names == {"sqli", "cmdi", "ssti", "xss"}


def test_engine_prompt_includes_heuristics(engine, fixtures_dir):
    vuln_dir = fixtures_dir / "sqli" / "vulnerable"
    py_files = list(vuln_dir.glob("*.py"))
    if not py_files:
        pytest.skip("no Python fixtures")

    target = {"type": "file", "path": str(py_files[0])}
    result = engine.assemble_scan(agent_name="sqli", target=target)
    prompt = result["core_prompt"]
    # Should include detection heuristics section
    assert "Detection Heuristics" in prompt or "heuristic" in prompt.lower()


def test_engine_list_tools(engine):
    tools = engine.list_tool_definitions()
    tool_names = {t["name"] for t in tools}
    assert "scan_sqli" in tool_names
    assert "scan_cmdi" in tool_names
    assert "list_domains" in tool_names
    assert "list_agents" in tool_names
    assert "scan_domain" in tool_names
    assert "scan_full" in tool_names


def test_full_pipeline_all_agents(engine, fixtures_dir):
    """Integration: verify all 4 Phase 1 agents can scan their own fixtures."""
    agents = ["sqli", "cmdi", "ssti", "xss"]
    for agent_name in agents:
        vuln_dir = fixtures_dir / agent_name / "vulnerable"
        if not vuln_dir.exists():
            continue
        py_files = list(vuln_dir.glob("*.py"))
        if not py_files:
            continue

        target = {"type": "file", "path": str(py_files[0])}
        result = engine.assemble_scan(agent_name=agent_name, target=target)
        assert result["agent_name"] == agent_name
        assert len(result["core_prompt"]) > 100
        assert len(result["code"]) > 0


def test_tool_definitions_json_schema_valid(engine):
    tools = engine.list_tool_definitions()
    for t in tools:
        schema = t["input_schema"]
        assert schema["type"] == "object"
        assert "properties" in schema
        if t["name"].startswith("scan_"):
            assert "target" in schema["properties"]


def test_full_pipeline_sqli(engine, fixtures_dir):
    """Integration: load sqli agent → resolve fixture → assemble → verify structure."""
    vuln_dir = fixtures_dir / "sqli" / "vulnerable"
    if not vuln_dir.exists():
        pytest.skip("fixtures not found")

    py_files = list(vuln_dir.glob("*.py"))
    if not py_files:
        pytest.skip("no Python fixtures")

    target = {"type": "file", "path": str(py_files[0])}
    result = engine.assemble_scan(agent_name="sqli", target=target)

    assert result["agent_name"] == "sqli"
    assert "SQL" in result["core_prompt"] or "sql" in result["core_prompt"].lower()
    assert len(result["code"]) > 0
    assert result["meta"]["cwe_primary"] == "CWE-89"
    assert result["meta"]["domain"] == "injection-input-handling"


def test_full_pipeline_domain_scan(engine, fixtures_dir):
    """Integration: domain scan assembles prompts for all 4 agents."""
    vuln_dir = fixtures_dir / "sqli" / "vulnerable"
    py_files = list(vuln_dir.glob("*.py"))
    if not py_files:
        pytest.skip("no Python fixtures")

    target = {"type": "file", "path": str(py_files[0])}
    results = engine.assemble_domain_scan(
        domain="injection-input-handling", target=target,
    )
    assert len(results) == 4
    agent_names = {r["agent_name"] for r in results}
    assert agent_names == {"sqli", "cmdi", "ssti", "xss"}
    for r in results:
        assert len(r["code"]) > 0


import yaml


class TestAssembleScanExclusions:
    def test_assemble_scan_no_project_root_no_exclusions_key(self, engine, fixtures_dir):
        """Backwards compat: no project_root means no exclusions in payload."""
        vuln_dir = fixtures_dir / "sqli" / "vulnerable"
        py_files = list(vuln_dir.glob("*.py"))
        if not py_files:
            pytest.skip("no Python fixtures")
        target = {"type": "file", "path": str(py_files[0])}
        result = engine.assemble_scan(agent_name="sqli", target=target)
        assert "exclusions" not in result

    def test_assemble_scan_with_project_root_no_file(self, engine, fixtures_dir, tmp_path):
        """project_root with no exclusions file → empty exclusions list."""
        vuln_dir = fixtures_dir / "sqli" / "vulnerable"
        py_files = list(vuln_dir.glob("*.py"))
        if not py_files:
            pytest.skip("no Python fixtures")
        target = {"type": "file", "path": str(py_files[0])}
        result = engine.assemble_scan(agent_name="sqli", target=target, project_root=tmp_path)
        assert "exclusions" in result
        assert result["exclusions"] == []

    def test_assemble_scan_with_exclusions(self, engine, fixtures_dir, tmp_path):
        """project_root with exclusions file → filtered exclusions in payload."""
        vuln_dir = fixtures_dir / "sqli" / "vulnerable"
        py_files = list(vuln_dir.glob("*.py"))
        if not py_files:
            pytest.skip("no Python fixtures")

        learning_dir = tmp_path / ".screw" / "learning"
        learning_dir.mkdir(parents=True)
        data = {
            "exclusions": [
                {
                    "id": "fp-2026-04-11-001",
                    "created": "2026-04-11T14:35:00Z",
                    "agent": "sqli",
                    "finding": {"file": "src/api.py", "line": 42, "code_pattern": "db.query(*)", "cwe": "CWE-89"},
                    "reason": "safe",
                    "scope": {"type": "pattern", "pattern": "db.query(*)"},
                    "times_suppressed": 0,
                    "last_suppressed": None,
                },
                {
                    "id": "fp-2026-04-11-002",
                    "created": "2026-04-11T14:36:00Z",
                    "agent": "xss",
                    "finding": {"file": "src/api.py", "line": 50, "code_pattern": "render(*)", "cwe": "CWE-79"},
                    "reason": "safe",
                    "scope": {"type": "file", "path": "src/api.py"},
                    "times_suppressed": 0,
                    "last_suppressed": None,
                },
            ]
        }
        (learning_dir / "exclusions.yaml").write_text(yaml.dump(data))

        target = {"type": "file", "path": str(py_files[0])}
        result = engine.assemble_scan(agent_name="sqli", target=target, project_root=tmp_path)
        assert "exclusions" in result
        assert len(result["exclusions"]) == 1
        assert result["exclusions"][0]["agent"] == "sqli"

    def test_assemble_domain_scan_with_project_root(self, engine, fixtures_dir, tmp_path):
        """Domain scan passes project_root through to each agent scan."""
        vuln_dir = fixtures_dir / "sqli" / "vulnerable"
        py_files = list(vuln_dir.glob("*.py"))
        if not py_files:
            pytest.skip("no Python fixtures")
        target = {"type": "file", "path": str(py_files[0])}
        results = engine.assemble_domain_scan(
            domain="injection-input-handling", target=target, project_root=tmp_path,
        )
        for r in results:
            assert "exclusions" in r

    def test_assemble_full_scan_with_project_root(self, engine, fixtures_dir, tmp_path):
        """Full scan passes project_root through."""
        vuln_dir = fixtures_dir / "sqli" / "vulnerable"
        py_files = list(vuln_dir.glob("*.py"))
        if not py_files:
            pytest.skip("no Python fixtures")
        target = {"type": "file", "path": str(py_files[0])}
        results = engine.assemble_full_scan(target=target, project_root=tmp_path)
        for r in results:
            assert "exclusions" in r
