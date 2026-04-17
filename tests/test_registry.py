"""Tests for the agent registry."""

import pytest

from screw_agents.registry import AgentRegistry


def test_registry_loads_from_domains_dir(domains_dir):
    registry = AgentRegistry(domains_dir)
    assert len(registry.agents) >= 4


def test_registry_agents_by_name(domains_dir):
    registry = AgentRegistry(domains_dir)
    sqli = registry.get_agent("sqli")
    assert sqli is not None
    assert sqli.meta.name == "sqli"
    assert sqli.meta.cwes.primary == "CWE-89"


def test_registry_agents_by_domain(domains_dir):
    registry = AgentRegistry(domains_dir)
    agents = registry.get_agents_by_domain("injection-input-handling")
    names = {a.meta.name for a in agents}
    assert names == {"sqli", "cmdi", "ssti", "xss"}


def test_registry_list_domains(domains_dir):
    registry = AgentRegistry(domains_dir)
    domains = registry.list_domains()
    assert "injection-input-handling" in domains
    assert domains["injection-input-handling"] >= 4


def test_registry_list_agents(domains_dir):
    registry = AgentRegistry(domains_dir)
    agents = registry.list_agents()
    assert len(agents) >= 4
    names = {a["name"] for a in agents}
    assert {"sqli", "cmdi", "ssti", "xss"} <= names


def test_registry_get_nonexistent_agent(domains_dir):
    registry = AgentRegistry(domains_dir)
    assert registry.get_agent("nonexistent") is None


def test_registry_empty_dir(tmp_path):
    registry = AgentRegistry(tmp_path)
    assert len(registry.agents) == 0


def test_registry_malformed_yaml_raises(tmp_path):
    bad_dir = tmp_path / "bad-domain"
    bad_dir.mkdir()
    (bad_dir / "broken.yaml").write_text("meta:\n  name: broken\n")
    with pytest.raises(Exception):
        AgentRegistry(tmp_path)


def test_all_phase1_agents_have_short_description(domains_dir):
    from screw_agents.registry import AgentRegistry
    registry = AgentRegistry(domains_dir)
    for agent_name in ("sqli", "cmdi", "ssti", "xss"):
        agent = registry.get_agent(agent_name)
        assert agent is not None, f"{agent_name} not loaded"
        assert agent.meta.short_description is not None, f"{agent_name} missing short_description"
        assert len(agent.meta.short_description) > 20, f"{agent_name} short_description too short"
