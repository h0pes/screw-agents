"""Tests for the evaluation orchestrator."""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from benchmarks.runner.evaluator import (
    Evaluator,
    EvalConfig,
    load_cases_from_manifest,
    map_case_to_agent,
    build_prompt,
    parse_findings_response,
)
from benchmarks.runner.invoker import InvokeResult
from benchmarks.runner.models import (
    BenchmarkCase,
    CodeLocation,
    Finding,
    FindingKind,
    Language,
)


@pytest.fixture
def sample_manifest(tmp_path):
    manifest = {
        "dataset_name": "test-dataset",
        "source_url": "https://example.com",
        "case_count": 2,
        "cases": [
            {
                "case_id": "test-1",
                "project": "proj",
                "language": "python",
                "vulnerable_version": "v1",
                "patched_version": "v2",
                "published_date": None,
                "fail_count": 1,
                "pass_count": 1,
            },
            {
                "case_id": "test-2",
                "project": "proj2",
                "language": "go",
                "vulnerable_version": "v1",
                "patched_version": "v2",
                "published_date": None,
                "fail_count": 1,
                "pass_count": 1,
            },
        ],
    }
    path = tmp_path / "test.manifest.json"
    path.write_text(json.dumps(manifest))
    return path


class TestLoadCases:
    def test_loads_cases_from_manifest(self, sample_manifest):
        cases = load_cases_from_manifest(sample_manifest)
        assert len(cases) == 2
        assert cases[0]["case_id"] == "test-1"
        assert cases[0]["language"] == "python"


class TestMapCaseToAgent:
    def test_maps_xss_case(self):
        case = BenchmarkCase(
            case_id="t", project="p", language=Language.PYTHON,
            vulnerable_version="v1", patched_version="v2",
            ground_truth=[
                Finding(cwe_id="CWE-79", kind=FindingKind.FAIL,
                        location=CodeLocation(file="a.py", start_line=1, end_line=1)),
            ],
            source_dataset="test",
        )
        assert map_case_to_agent(case) == "xss"

    def test_returns_none_for_unknown_cwe(self):
        case = BenchmarkCase(
            case_id="t", project="p", language=Language.PYTHON,
            vulnerable_version="v1", patched_version="v2",
            ground_truth=[
                Finding(cwe_id="CWE-502", kind=FindingKind.FAIL,
                        location=CodeLocation(file="a.py", start_line=1, end_line=1)),
            ],
            source_dataset="test",
        )
        assert map_case_to_agent(case) is None


class TestBuildPrompt:
    def test_includes_instructions_and_code(self):
        prompt = build_prompt(
            core_prompt="Detect XSS vulnerabilities.",
            code="var x = document.innerHTML;",
            file_path="view.js",
        )
        assert "Detect XSS" in prompt
        assert "document.innerHTML" in prompt
        assert "JSON" in prompt


class TestParseFindingsResponse:
    def test_parses_valid_findings(self):
        raw = [
            {"cwe_id": "CWE-79", "file": "a.js", "start_line": 10,
             "end_line": 15, "confidence": 0.9, "message": "XSS"}
        ]
        findings = parse_findings_response(raw, agent_name="xss")
        assert len(findings) == 1
        assert findings[0].cwe_id == "CWE-79"
        assert findings[0].agent_name == "xss"

    def test_skips_malformed_entries(self):
        raw = [
            {"cwe_id": "CWE-79"},  # missing required fields
            {"cwe_id": "CWE-79", "file": "a.js", "start_line": 1,
             "end_line": 5, "confidence": 0.8, "message": "ok"},
        ]
        findings = parse_findings_response(raw, agent_name="xss")
        assert len(findings) == 1
