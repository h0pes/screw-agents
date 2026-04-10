"""Tests for Pydantic models — YAML agent schema."""

import yaml
import pytest

from screw_agents.models import AgentDefinition, AgentMeta, CWEs


def test_cwes_model():
    cwes = CWEs(primary="CWE-89", related=["CWE-564", "CWE-566"])
    assert cwes.primary == "CWE-89"
    assert len(cwes.related) == 2


def test_cwes_requires_primary():
    with pytest.raises(Exception):
        CWEs(related=["CWE-564"])


def test_agent_meta_minimal():
    meta = AgentMeta(
        name="test",
        display_name="Test Agent",
        domain="test-domain",
        version="1.0.0",
        last_updated="2026-04-10",
        cwes=CWEs(primary="CWE-89"),
        capec=["CAPEC-66"],
        owasp={"top10": "A05:2025"},
        sources=[],
    )
    assert meta.name == "test"


def test_agent_definition_from_real_yaml(sqli_yaml_path):
    with open(sqli_yaml_path) as f:
        data = yaml.safe_load(f)
    agent = AgentDefinition.model_validate(data)
    assert agent.meta.name == "sqli"
    assert agent.meta.cwes.primary == "CWE-89"
    assert agent.core_prompt is not None
    assert len(agent.core_prompt) > 100
    assert agent.detection_heuristics.high_confidence is not None
    assert len(agent.detection_heuristics.high_confidence) > 0
    assert len(agent.bypass_techniques) > 0
    assert agent.target_strategy.scope == "function"


def test_all_phase1_yamls_validate(domains_dir):
    yaml_dir = domains_dir / "injection-input-handling"
    for yaml_path in yaml_dir.glob("*.yaml"):
        with open(yaml_path) as f:
            data = yaml.safe_load(f)
        agent = AgentDefinition.model_validate(data)
        assert agent.meta.name in ("sqli", "cmdi", "ssti", "xss")
        assert agent.meta.domain == "injection-input-handling"


def test_agent_definition_missing_core_prompt_fails():
    data = {
        "meta": {
            "name": "bad",
            "display_name": "Bad",
            "domain": "test",
            "version": "1.0.0",
            "last_updated": "2026-01-01",
            "cwes": {"primary": "CWE-89"},
            "capec": [],
            "owasp": {"top10": "A05:2025"},
            "sources": [],
        },
        "detection_heuristics": {"high_confidence": ["pattern"]},
        "bypass_techniques": [],
        "remediation": {"preferred": "fix it"},
        "few_shot_examples": {"vulnerable": [], "safe": []},
        "target_strategy": {"scope": "function", "file_patterns": ["**/*.py"]},
    }
    with pytest.raises(Exception):
        AgentDefinition.model_validate(data)


def test_agent_definition_missing_detection_heuristics_fails():
    data = {
        "meta": {
            "name": "bad",
            "display_name": "Bad",
            "domain": "test",
            "version": "1.0.0",
            "last_updated": "2026-01-01",
            "cwes": {"primary": "CWE-89"},
            "capec": [],
            "owasp": {"top10": "A05:2025"},
            "sources": [],
        },
        "core_prompt": "You are a test agent.",
        "bypass_techniques": [],
        "remediation": {"preferred": "fix it"},
        "few_shot_examples": {"vulnerable": [], "safe": []},
        "target_strategy": {"scope": "function", "file_patterns": ["**/*.py"]},
    }
    with pytest.raises(Exception):
        AgentDefinition.model_validate(data)
