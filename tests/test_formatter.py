"""Tests for the output formatter."""

import json

import pytest

from screw_agents.formatter import format_findings
from screw_agents.models import (
    Finding, FindingLocation, FindingClassification,
    FindingAnalysis, FindingRemediation, DataFlow,
)


def _make_finding(**overrides) -> Finding:
    defaults = dict(
        id="sqli-001",
        agent="sqli",
        domain="injection-input-handling",
        timestamp="2026-04-10T14:30:00Z",
        location=FindingLocation(file="test.py", line_start=10),
        classification=FindingClassification(
            cwe="CWE-89", cwe_name="SQL Injection",
            severity="high", confidence="high",
        ),
        analysis=FindingAnalysis(
            description="SQL injection via f-string",
            impact="Data exfiltration",
            exploitability="Trivially exploitable",
        ),
        remediation=FindingRemediation(recommendation="Use parameterized queries"),
    )
    defaults.update(overrides)
    return Finding(**defaults)


# === JSON Tests ===

def test_format_json_single_finding():
    findings = [_make_finding()]
    output = format_findings(findings, format="json")
    parsed = json.loads(output)
    assert isinstance(parsed, list)
    assert len(parsed) == 1
    assert parsed[0]["id"] == "sqli-001"
    assert parsed[0]["classification"]["cwe"] == "CWE-89"
    assert parsed[0]["triage"]["status"] == "pending"


def test_format_json_empty():
    output = format_findings([], format="json")
    parsed = json.loads(output)
    assert parsed == []


def test_format_json_with_data_flow():
    finding = _make_finding(
        location=FindingLocation(
            file="test.py",
            line_start=10,
            line_end=15,
            data_flow=DataFlow(
                source="request.args.get('id')",
                source_location="test.py:10",
                sink="cursor.execute(query)",
                sink_location="test.py:15",
            ),
        ),
    )
    output = format_findings([finding], format="json")
    parsed = json.loads(output)
    assert parsed[0]["location"]["data_flow"]["source"] == "request.args.get('id')"


def test_format_json_multiple_findings():
    findings = [
        _make_finding(id="sqli-001"),
        _make_finding(id="xss-001", agent="xss", classification=FindingClassification(
            cwe="CWE-79", cwe_name="XSS",
            severity="medium", confidence="medium",
        )),
    ]
    output = format_findings(findings, format="json")
    parsed = json.loads(output)
    assert len(parsed) == 2


# === SARIF Tests ===

def test_format_sarif_structure():
    findings = [_make_finding()]
    output = format_findings(findings, format="sarif", scan_metadata={"agents": ["sqli"]})
    sarif = json.loads(output)
    assert sarif["$schema"] == "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json"
    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"]) == 1
    run = sarif["runs"][0]
    assert "tool" in run
    assert "results" in run


def test_format_sarif_results():
    findings = [_make_finding()]
    output = format_findings(findings, format="sarif", scan_metadata={"agents": ["sqli"]})
    sarif = json.loads(output)
    results = sarif["runs"][0]["results"]
    assert len(results) == 1
    r = results[0]
    assert r["ruleId"] == "CWE-89"
    assert r["level"] == "error"
    assert r["message"]["text"] == "SQL injection via f-string"
    locs = r["locations"]
    assert len(locs) == 1
    assert locs[0]["physicalLocation"]["artifactLocation"]["uri"] == "test.py"
    assert locs[0]["physicalLocation"]["region"]["startLine"] == 10


def test_format_sarif_severity_mapping():
    finding_medium = _make_finding(
        classification=FindingClassification(
            cwe="CWE-79", cwe_name="XSS",
            severity="medium", confidence="medium",
        ),
    )
    output = format_findings([finding_medium], format="sarif")
    sarif = json.loads(output)
    assert sarif["runs"][0]["results"][0]["level"] == "warning"


def test_format_sarif_empty():
    output = format_findings([], format="sarif")
    sarif = json.loads(output)
    assert sarif["runs"][0]["results"] == []
