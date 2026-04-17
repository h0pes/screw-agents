"""Tests for Phase 2 MCP server changes: new tools + project_root."""

import json
import yaml
import pytest
from pathlib import Path

from screw_agents.server import create_server, _dispatch_tool


@pytest.fixture
def engine(domains_dir):
    _, engine = create_server(domains_dir)
    return engine


class TestFormatOutputTool:
    def test_dispatch_format_output_json(self, engine):
        findings = [
            {
                "id": "test-001",
                "agent": "sqli",
                "domain": "injection-input-handling",
                "timestamp": "2026-04-11T14:30:00Z",
                "location": {"file": "src/api.py", "line_start": 42},
                "classification": {
                    "cwe": "CWE-89",
                    "cwe_name": "SQL Injection",
                    "severity": "high",
                    "confidence": "high",
                },
                "analysis": {"description": "SQL injection found"},
                "remediation": {"recommendation": "Use parameterized queries"},
            }
        ]
        result = _dispatch_tool(engine, "format_output", {
            "findings": findings,
            "format": "json",
        })
        assert "formatted" in result
        parsed = json.loads(result["formatted"])
        assert len(parsed) == 1
        assert parsed[0]["id"] == "test-001"

    def test_dispatch_format_output_markdown(self, engine):
        result = _dispatch_tool(engine, "format_output", {
            "findings": [],
            "format": "markdown",
            "scan_metadata": {"target": "src/api/", "agents": ["sqli"]},
        })
        assert "formatted" in result
        assert "Security Scan Report" in result["formatted"]

    def test_dispatch_format_output_sarif(self, engine):
        result = _dispatch_tool(engine, "format_output", {
            "findings": [],
            "format": "sarif",
        })
        assert "formatted" in result
        parsed = json.loads(result["formatted"])
        assert parsed["version"] == "2.1.0"


class TestExclusionTools:
    def test_dispatch_record_exclusion(self, engine, tmp_path):
        result = _dispatch_tool(engine, "record_exclusion", {
            "project_root": str(tmp_path),
            "exclusion": {
                "agent": "sqli",
                "finding": {"file": "src/api.py", "line": 42, "code_pattern": "db.query(*)", "cwe": "CWE-89"},
                "reason": "safe",
                "scope": {"type": "pattern", "pattern": "db.query(*)"},
            },
        })
        assert "exclusion" in result
        assert result["exclusion"]["id"].startswith("fp-")
        assert result["exclusion"]["agent"] == "sqli"

    def test_dispatch_check_exclusions_empty(self, engine, tmp_path):
        result = _dispatch_tool(engine, "check_exclusions", {
            "project_root": str(tmp_path),
            "agent": "sqli",
        })
        assert "exclusions" in result
        assert result["exclusions"] == []

    def test_dispatch_check_exclusions_filtered(self, engine, tmp_path):
        _dispatch_tool(engine, "record_exclusion", {
            "project_root": str(tmp_path),
            "exclusion": {
                "agent": "sqli",
                "finding": {"file": "a.py", "line": 1, "code_pattern": "x", "cwe": "CWE-89"},
                "reason": "safe",
                "scope": {"type": "file", "path": "a.py"},
            },
        })
        _dispatch_tool(engine, "record_exclusion", {
            "project_root": str(tmp_path),
            "exclusion": {
                "agent": "xss",
                "finding": {"file": "b.py", "line": 2, "code_pattern": "y", "cwe": "CWE-79"},
                "reason": "safe",
                "scope": {"type": "file", "path": "b.py"},
            },
        })
        result = _dispatch_tool(engine, "check_exclusions", {
            "project_root": str(tmp_path),
            "agent": "sqli",
        })
        assert len(result["exclusions"]) == 1
        assert result["exclusions"][0]["agent"] == "sqli"


class TestAccumulateFinalizeTools:
    """X1-M1 T18 replacement: the accumulate_findings + finalize_scan_results
    tools supersede the legacy write_scan_results dispatch path."""

    def test_dispatch_accumulate_then_finalize(self, engine, tmp_path):
        finding = {
            "id": "test-001",
            "agent": "sqli",
            "domain": "injection-input-handling",
            "timestamp": "2026-04-11T14:30:00Z",
            "location": {"file": "src/api.py", "line_start": 42},
            "classification": {
                "cwe": "CWE-89",
                "cwe_name": "SQL Injection",
                "severity": "high",
                "confidence": "high",
            },
            "analysis": {"description": "SQL injection found"},
            "remediation": {"recommendation": "Use parameterized queries"},
        }

        acc = _dispatch_tool(engine, "accumulate_findings", {
            "project_root": str(tmp_path),
            "findings_chunk": [finding],
        })
        assert "session_id" in acc
        assert acc["accumulated_count"] == 1

        result = _dispatch_tool(engine, "finalize_scan_results", {
            "project_root": str(tmp_path),
            "session_id": acc["session_id"],
            "agent_names": ["sqli"],
            "scan_metadata": {"target": "src/api.py"},
        })
        assert "files_written" in result
        assert set(result["files_written"].keys()) == {"json", "markdown"}
        assert result["summary"]["total"] == 1
        assert (tmp_path / ".screw" / "findings").is_dir()
        assert (tmp_path / ".screw" / ".gitignore").exists()
        # Staging cleaned up
        assert not (tmp_path / ".screw" / "staging" / acc["session_id"]).exists()


class TestScanToolProjectRoot:
    def test_scan_tool_accepts_project_root(self, engine, domains_dir, tmp_path):
        fixtures_dir = Path(__file__).resolve().parent.parent / "benchmarks" / "fixtures"
        vuln_dir = fixtures_dir / "sqli" / "vulnerable"
        py_files = list(vuln_dir.glob("*.py"))
        if not py_files:
            pytest.skip("no Python fixtures")
        result = _dispatch_tool(engine, "scan_sqli", {
            "target": {"type": "file", "path": str(py_files[0])},
            "project_root": str(tmp_path),
        })
        assert "exclusions" in result

    def test_scan_tool_without_project_root(self, engine, domains_dir):
        fixtures_dir = Path(__file__).resolve().parent.parent / "benchmarks" / "fixtures"
        vuln_dir = fixtures_dir / "sqli" / "vulnerable"
        py_files = list(vuln_dir.glob("*.py"))
        if not py_files:
            pytest.skip("no Python fixtures")
        result = _dispatch_tool(engine, "scan_sqli", {
            "target": {"type": "file", "path": str(py_files[0])},
        })
        assert "exclusions" not in result


class TestNewToolsRegistered:
    def test_format_output_in_tool_list(self, domains_dir):
        _, engine = create_server(domains_dir)
        tools = engine.list_tool_definitions()
        names = {t["name"] for t in tools}
        assert "format_output" in names
        assert "record_exclusion" in names
        assert "check_exclusions" in names

    def test_accumulate_and_finalize_in_tool_list(self, domains_dir):
        """X1-M1 T18: write_scan_results replaced by accumulate_findings +
        finalize_scan_results in the MCP tool surface."""
        _, engine = create_server(domains_dir)
        tools = engine.list_tool_definitions()
        names = {t["name"] for t in tools}
        assert "accumulate_findings" in names
        assert "finalize_scan_results" in names
        # Legacy tool is gone
        assert "write_scan_results" not in names

    def test_scan_tools_have_project_root(self, domains_dir):
        _, engine = create_server(domains_dir)
        tools = engine.list_tool_definitions()
        for t in tools:
            if t["name"].startswith("scan_") or t["name"] in ("scan_domain", "scan_full"):
                props = t["input_schema"].get("properties", {})
                assert "project_root" in props, f"{t['name']} missing project_root"
