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


from screw_agents.models import (
    Finding, FindingLocation, DataFlow, FindingClassification,
    FindingAnalysis, FindingRemediation, FindingTriage,
)


def test_finding_location_minimal():
    loc = FindingLocation(
        file="src/api/users.py",
        line_start=42,
    )
    assert loc.file == "src/api/users.py"
    assert loc.data_flow is None


def test_finding_location_with_data_flow():
    loc = FindingLocation(
        file="src/api/users.py",
        line_start=42,
        line_end=48,
        function="get_user",
        data_flow=DataFlow(
            source="request.getParameter('username')",
            source_location="UserController.java:42",
            sink="stmt.executeQuery(query)",
            sink_location="UserController.java:48",
        ),
    )
    assert loc.data_flow.source == "request.getParameter('username')"


def test_finding_complete():
    finding = Finding(
        id="sqli-001-abc123",
        agent="sqli",
        domain="injection-input-handling",
        timestamp="2026-04-10T14:30:00Z",
        location=FindingLocation(file="test.py", line_start=10),
        classification=FindingClassification(
            cwe="CWE-89",
            cwe_name="SQL Injection",
            severity="high",
            confidence="high",
        ),
        analysis=FindingAnalysis(
            description="SQL injection via f-string",
            impact="Data exfiltration",
            exploitability="Trivially exploitable",
        ),
        remediation=FindingRemediation(
            recommendation="Use parameterized queries",
        ),
    )
    assert finding.id == "sqli-001-abc123"
    assert finding.triage.status == "pending"


def test_finding_requires_location():
    with pytest.raises(Exception):
        Finding(
            id="test",
            agent="sqli",
            domain="test",
            timestamp="2026-01-01T00:00:00Z",
            classification=FindingClassification(
                cwe="CWE-89", cwe_name="SQLi",
                severity="high", confidence="high",
            ),
            analysis=FindingAnalysis(description="test"),
            remediation=FindingRemediation(recommendation="fix"),
        )
