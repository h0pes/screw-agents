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


# === Markdown Tests ===

def test_format_markdown_structure():
    findings = [
        _make_finding(id="sqli-001"),
        _make_finding(
            id="xss-001", agent="xss",
            classification=FindingClassification(
                cwe="CWE-79", cwe_name="XSS",
                severity="medium", confidence="high",
            ),
            analysis=FindingAnalysis(description="Reflected XSS"),
            remediation=FindingRemediation(recommendation="Encode output"),
        ),
    ]
    output = format_findings(
        findings,
        format="markdown",
        scan_metadata={"agents": ["sqli", "xss"], "target": "src/api/"},
    )
    assert "# Security Scan Report" in output
    assert "## Summary" in output
    assert "| Severity" in output
    assert "| High" in output
    assert "| Medium" in output
    assert "## Findings Overview" in output
    assert "sqli-001" in output
    assert "xss-001" in output
    assert "## Detailed Findings" in output
    assert "CWE-89" in output
    assert "CWE-79" in output


def test_format_markdown_empty():
    output = format_findings([], format="markdown")
    assert "No findings" in output or "0" in output


def test_format_markdown_with_data_flow():
    finding = _make_finding(
        location=FindingLocation(
            file="test.py",
            line_start=10,
            data_flow=DataFlow(
                source="request.args['id']",
                source_location="test.py:10",
                sink="cursor.execute(q)",
                sink_location="test.py:15",
            ),
        ),
    )
    output = format_findings([finding], format="markdown")
    assert "Source" in output
    assert "Sink" in output
    assert "request.args" in output


def test_format_markdown_with_fix_code():
    finding = _make_finding(
        remediation=FindingRemediation(
            recommendation="Use parameterized queries",
            fix_code="cursor.execute('SELECT * FROM users WHERE id = %s', (uid,))",
        ),
    )
    output = format_findings([finding], format="markdown")
    assert "cursor.execute" in output


# === Task 11 — Trust verification section in Markdown ===


def test_format_findings_markdown_renders_trust_section_with_quarantined():
    """When trust_status shows quarantined exclusions, the Markdown output
    includes a 'Trust verification' section with counts and CLI pointers."""
    trust_status = {
        "exclusion_quarantine_count": 2,
        "exclusion_active_count": 3,
        "script_quarantine_count": 0,
        "script_active_count": 0,
    }
    output = format_findings(
        [],  # no findings is fine — we're testing the header section
        format="markdown",
        scan_metadata={
            "target": "src/",
            "agents": ["sqli"],
            "timestamp": "2026-04-14T10:00:00Z",
        },
        trust_status=trust_status,
    )
    assert "## Trust verification" in output
    assert "2 exclusions quarantined" in output
    assert "3 trusted exclusions applied" in output
    assert "screw-agents validate-exclusion" in output


def test_format_findings_markdown_trust_section_omitted_when_all_zeros():
    """When trust_status is all-zero (empty project), the trust section is
    NOT rendered — no noise for projects without any trust surface."""
    trust_status = {
        "exclusion_quarantine_count": 0,
        "exclusion_active_count": 0,
        "script_quarantine_count": 0,
        "script_active_count": 0,
    }
    output = format_findings(
        [],
        format="markdown",
        scan_metadata={
            "target": "src/",
            "agents": ["sqli"],
            "timestamp": "2026-04-14T10:00:00Z",
        },
        trust_status=trust_status,
    )
    assert "## Trust verification" not in output


def test_format_findings_markdown_trust_section_omitted_when_none():
    """When trust_status is not provided, no Trust verification section appears
    (backwards compat — Phase 2 callers don't pass trust_status)."""
    output = format_findings(
        [],
        format="markdown",
        scan_metadata={"target": "src/"},
    )
    assert "## Trust verification" not in output


def test_format_findings_markdown_trust_section_singular_plural():
    """Singular 'exclusion' when count == 1, plural 'exclusions' when > 1."""
    trust_status_1 = {
        "exclusion_quarantine_count": 1,
        "exclusion_active_count": 1,
        "script_quarantine_count": 0,
        "script_active_count": 0,
    }
    output = format_findings([], format="markdown", trust_status=trust_status_1)
    assert "1 exclusion quarantined" in output
    assert "1 trusted exclusion applied" in output

    trust_status_2 = {
        "exclusion_quarantine_count": 2,
        "exclusion_active_count": 3,
        "script_quarantine_count": 0,
        "script_active_count": 0,
    }
    output = format_findings([], format="markdown", trust_status=trust_status_2)
    assert "2 exclusions quarantined" in output
    assert "3 trusted exclusions applied" in output


def test_format_findings_json_ignores_trust_status():
    """trust_status kwarg is silently ignored for JSON output (not a report
    envelope — just a list of findings)."""
    output = format_findings(
        [],
        format="json",
        trust_status={
            "exclusion_quarantine_count": 5,
            "exclusion_active_count": 0,
            "script_quarantine_count": 0,
            "script_active_count": 0,
        },
    )
    assert json.loads(output) == []


# === Task 32 — CWE long-name lookup table ===


def test_json_formatter_emits_null_for_none_impact():
    """When FindingAnalysis omits impact, JSON serializes analysis.impact as null."""
    from screw_agents.models import FindingAnalysis

    finding = _make_finding(analysis=FindingAnalysis(description="SQLi via f-string"))
    assert finding.analysis.impact is None  # guard
    output = format_findings([finding], format="json")
    parsed = json.loads(output)
    assert isinstance(parsed, list)
    assert parsed[0]["analysis"]["impact"] is None
    assert parsed[0]["analysis"]["exploitability"] is None


def test_cwe_long_name_lookup():
    from screw_agents.cwe_names import CWE_LONG_NAMES
    assert CWE_LONG_NAMES["CWE-89"] == "SQL Injection"
    assert CWE_LONG_NAMES["CWE-78"] == "OS Command Injection"
    assert CWE_LONG_NAMES["CWE-79"] == "Cross-site Scripting"
    assert CWE_LONG_NAMES["CWE-1336"] == "Improper Neutralization of Special Elements Used in a Template Engine"


def test_cwe_long_name_fallback_unknown():
    from screw_agents.cwe_names import long_name
    assert long_name("CWE-999") == "CWE-999"
    assert long_name("CWE-89") == "SQL Injection"


# === Task 33 — Markdown formatter uses full CWE name in detail heading ===


def test_markdown_detail_heading_uses_full_cwe_name():
    """Per-finding detail heading carries id + CWE-ID + long CWE name."""
    finding = _make_finding()  # sqli-001, CWE-89
    out = format_findings([finding], format="markdown")
    assert "### sqli-001 — CWE-89 — SQL Injection" in out


# === Task 31 — SARIF shortDescription uses agent meta ===


def test_sarif_short_description_uses_agent_meta(domains_dir):
    """SARIF shortDescription.text uses agent.meta.short_description when
    agent_registry is provided and the agent has a short_description."""
    from screw_agents.registry import AgentRegistry

    finding = _make_finding()  # agent="sqli", CWE-89
    registry = AgentRegistry(domains_dir)
    out = format_findings([finding], format="sarif", agent_registry=registry)
    parsed = json.loads(out)
    rules = parsed["runs"][0]["tool"]["driver"]["rules"]
    short = rules[0]["shortDescription"]["text"]
    assert "SQL injection" in short


def test_sarif_short_description_fallback_without_registry():
    """SARIF shortDescription.text falls back to 'CWE-ID — cwe_name' when no
    agent_registry is provided."""
    finding = _make_finding()  # CWE-89, cwe_name="SQL Injection"
    out = format_findings([finding], format="sarif")
    parsed = json.loads(out)
    short = parsed["runs"][0]["tool"]["driver"]["rules"][0]["shortDescription"]["text"]
    assert "CWE-89" in short
    assert "SQL Injection" in short
