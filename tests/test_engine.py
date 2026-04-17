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
    result = engine.assemble_domain_scan(
        domain="injection-input-handling",
        target=target,
    )
    assert isinstance(result, dict)
    assert "agents" in result
    assert len(result["agents"]) == 4
    agent_names = {r["agent_name"] for r in result["agents"]}
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
    """Integration: domain-scan init page (cursor=None) ships prompts for all
    4 agents at the top level and per-agent metadata entries without code.

    Post X1-M1 Task 2, assemble_domain_scan(cursor=None) returns an init page
    whose contract is:
      - top-level ``prompts`` dict keyed by agent_name → detection prompt string
      - per-agent entries carry ``agent_name`` + ``meta`` only (no core_prompt,
        no code; ``exclusions`` is optional, only when project_root is set)
      - ``code_chunks_on_page == 0`` and ``offset == 0`` on the init page
    Full code-page walking is exercised in tests/test_pagination.py.
    """
    vuln_dir = fixtures_dir / "sqli" / "vulnerable"
    py_files = list(vuln_dir.glob("*.py"))
    if not py_files:
        pytest.skip("no Python fixtures")

    target = {"type": "file", "path": str(py_files[0])}
    result = engine.assemble_domain_scan(
        domain="injection-input-handling", target=target,
    )
    assert isinstance(result, dict)

    # Top-level prompts dict keyed by agent_name.
    assert "prompts" in result
    assert isinstance(result["prompts"], dict)
    assert set(result["prompts"].keys()) == {"sqli", "cmdi", "ssti", "xss"}
    for prompt in result["prompts"].values():
        assert isinstance(prompt, str)
        assert len(prompt) > 0

    # Per-agent entries: metadata only on init; no code, no core_prompt.
    assert "agents" in result
    assert len(result["agents"]) == 4
    agent_names = {r["agent_name"] for r in result["agents"]}
    assert agent_names == {"sqli", "cmdi", "ssti", "xss"}
    for r in result["agents"]:
        assert "meta" in r
        assert "code" not in r
        assert "core_prompt" not in r

    # Init-page metadata.
    assert result["code_chunks_on_page"] == 0
    assert result["offset"] == 0


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

        screw_dir = tmp_path / ".screw"
        screw_dir.mkdir()
        # Warn policy keeps unsigned entries active (test exercises the
        # exclusions-list shape, not the trust pipeline). With the default
        # reject policy + the round-trip defect fix, unsigned entries are
        # quarantined and engine.assemble_scan correctly omits them from
        # the subagent-facing list.
        (screw_dir / "config.yaml").write_text(
            "version: 1\n"
            "exclusion_reviewers: []\n"
            "script_reviewers: []\n"
            "legacy_unsigned_exclusions: warn\n"
        )
        learning_dir = screw_dir / "learning"
        learning_dir.mkdir()
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
        result = engine.assemble_domain_scan(
            domain="injection-input-handling", target=target, project_root=tmp_path,
        )
        for r in result["agents"]:
            assert "exclusions" in r
        # Domain-level trust_status is present when project_root is set
        assert "trust_status" in result

    def test_assemble_full_scan_with_project_root(self, engine, fixtures_dir, tmp_path):
        """Full scan passes project_root through."""
        vuln_dir = fixtures_dir / "sqli" / "vulnerable"
        py_files = list(vuln_dir.glob("*.py"))
        if not py_files:
            pytest.skip("no Python fixtures")
        target = {"type": "file", "path": str(py_files[0])}
        result = engine.assemble_full_scan(target=target, project_root=tmp_path)
        for r in result["agents"]:
            assert "exclusions" in r
        # Top-level trust_status is present when project_root is set
        assert "trust_status" in result


def test_assemble_scan_default_includes_core_prompt(tmp_path: Path):
    """Regression: assemble_scan's default behavior is unchanged — core_prompt
    is present in the result. Phase 3a per-agent callers (scan_sqli, scan_cmdi,
    etc.) depend on this default."""
    (tmp_path / "a.py").write_text("cursor.execute('SELECT * FROM t')\n")
    engine = ScanEngine.from_defaults()
    target = {"type": "glob", "pattern": str(tmp_path / "*.py")}

    result = engine.assemble_scan("sqli", target)

    assert "core_prompt" in result
    assert isinstance(result["core_prompt"], str)
    assert len(result["core_prompt"]) > 0


def test_assemble_scan_include_prompt_false_omits_core_prompt(tmp_path: Path):
    """When include_prompt=False, the response does not contain a core_prompt
    key at all (not empty string — absent). Used by domain-level and
    full-scan-level callers on code pages / fan-out iterations."""
    (tmp_path / "a.py").write_text("cursor.execute('SELECT * FROM t')\n")
    engine = ScanEngine.from_defaults()
    target = {"type": "glob", "pattern": str(tmp_path / "*.py")}

    result = engine.assemble_scan("sqli", target, include_prompt=False)

    assert "core_prompt" not in result
    assert result["agent_name"] == "sqli"
    assert "code" in result
    assert "resolved_files" in result
    assert "meta" in result


def test_assemble_full_scan_returns_dict_with_top_level_prompts(tmp_path: Path):
    """BREAKING CHANGE: assemble_full_scan now returns a dict (not list).
    Top-level `prompts` keyed by agent_name; `agents` list carries per-agent
    entries without core_prompt."""
    (tmp_path / "a.py").write_text(
        "cursor.execute('SELECT * FROM t WHERE x = ' + user_input)\n"
    )
    engine = ScanEngine.from_defaults()
    target = {"type": "glob", "pattern": str(tmp_path / "*.py")}

    result = engine.assemble_full_scan(target)

    assert isinstance(result, dict)
    assert "prompts" in result
    assert "agents" in result
    assert isinstance(result["prompts"], dict)
    assert isinstance(result["agents"], list)

    agent_names_in_agents = {a["agent_name"] for a in result["agents"]}
    assert set(result["prompts"].keys()) == agent_names_in_agents

    for agent_entry in result["agents"]:
        assert "core_prompt" not in agent_entry
        assert "code" in agent_entry
        assert "meta" in agent_entry


def test_assemble_full_scan_includes_trust_status_when_project_root_set(tmp_path: Path):
    """trust_status appears at the top level of the full-scan response when
    project_root is provided. Bare tmp_path (no .screw/) still yields a
    present, all-zero trust_status dict."""
    (tmp_path / "a.py").write_text("cursor.execute('SELECT 1')\n")
    engine = ScanEngine.from_defaults()
    target = {"type": "glob", "pattern": str(tmp_path / "*.py")}

    result = engine.assemble_full_scan(target, project_root=tmp_path)

    assert "trust_status" in result
    assert "exclusion_quarantine_count" in result["trust_status"]


def test_get_agent_prompt_returns_expected_shape(tmp_path: Path):
    """New MCP-facing method: returns {agent_name, core_prompt, meta} for a
    registered agent, so orchestrator subagents can fetch prompts lazily
    per-agent instead of receiving an aggregate prompts dict on scan_domain."""
    engine = ScanEngine.from_defaults()

    result = engine.get_agent_prompt("sqli", "standard")

    assert isinstance(result, dict)
    assert result["agent_name"] == "sqli"
    assert isinstance(result["core_prompt"], str)
    assert len(result["core_prompt"]) > 0
    # meta subset (same keys as assemble_scan emits)
    meta = result["meta"]
    assert meta["name"] == "sqli"
    assert "display_name" in meta
    assert "domain" in meta
    assert "cwe_primary" in meta


def test_get_agent_prompt_thoroughness_affects_prompt(tmp_path: Path):
    """quick vs standard vs deep produce different prompt sizes (different
    tiers of heuristics/examples included)."""
    engine = ScanEngine.from_defaults()

    quick = engine.get_agent_prompt("sqli", "quick")
    standard = engine.get_agent_prompt("sqli", "standard")
    deep = engine.get_agent_prompt("sqli", "deep")

    # quick < standard < deep (monotonic inclusion of tiers)
    assert len(quick["core_prompt"]) < len(standard["core_prompt"])
    assert len(standard["core_prompt"]) <= len(deep["core_prompt"])


def test_get_agent_prompt_unknown_agent_raises(tmp_path: Path):
    """Unknown agent name raises ValueError (consistent with assemble_scan)."""
    engine = ScanEngine.from_defaults()

    with pytest.raises(ValueError, match="Unknown agent"):
        engine.get_agent_prompt("nonexistent", "standard")
