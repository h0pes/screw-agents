"""Integration test: full pipeline with mocked Claude invoker."""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from benchmarks.runner.code_extractor import CodeVariant, ExtractedCode
from benchmarks.runner.evaluator import Evaluator, EvalConfig
from benchmarks.runner.invoker import InvokeResult, InvokerConfig
from benchmarks.runner.models import (
    BenchmarkCase,
    CodeLocation,
    Finding,
    FindingKind,
    Language,
)

from screw_agents.engine import ScanEngine
from screw_agents.registry import AgentRegistry


REPO_ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def engine():
    return ScanEngine(AgentRegistry(REPO_ROOT / "domains"))


@pytest.fixture
def xss_case():
    return BenchmarkCase(
        case_id="integration-xss-1",
        project="test-proj",
        language=Language.PYTHON,
        vulnerable_version="v1",
        patched_version="v2",
        ground_truth=[
            Finding(cwe_id="CWE-79", kind=FindingKind.FAIL,
                    location=CodeLocation(file="view.py", start_line=5, end_line=10)),
            Finding(cwe_id="CWE-79", kind=FindingKind.PASS,
                    location=CodeLocation(file="view.py", start_line=5, end_line=10)),
        ],
        source_dataset="reality-check-python",
    )


def _mock_extract(case, variant, ext_dir):
    if variant == CodeVariant.VULNERABLE:
        return [ExtractedCode(
            file_path="view.py",
            content='from flask import request, Markup\n\n@app.route("/")\ndef index():\n    name = request.args.get("name")\n    return Markup(f"<h1>Hello {name}</h1>")',
            language="python",
        )]
    return [ExtractedCode(
        file_path="view.py",
        content='from flask import request, escape\n\n@app.route("/")\ndef index():\n    name = escape(request.args.get("name"))\n    return f"<h1>Hello {name}</h1>"',
        language="python",
    )]


def _mock_invoke_vuln(prompt, config):
    return InvokeResult(
        success=True,
        findings=[{
            "cwe_id": "CWE-79",
            "file": "view.py",
            "start_line": 5,
            "end_line": 6,
            "confidence": 0.95,
            "message": "User input rendered without escaping via Markup()",
        }],
    )


def _mock_invoke_patched(prompt, config):
    return InvokeResult(success=True, findings=[])


class TestIntegrationPipeline:
    def test_full_pipeline_produces_summary(self, engine, xss_case, tmp_path):
        config = EvalConfig(
            results_dir=tmp_path / "results",
            invoker_config=InvokerConfig(throttle_delay=0.0),
        )
        evaluator = Evaluator(config)

        call_count = 0

        def mock_invoke(prompt, cfg):
            nonlocal call_count
            call_count += 1
            if call_count % 2 == 1:
                return _mock_invoke_vuln(prompt, cfg)
            return _mock_invoke_patched(prompt, cfg)

        with patch("benchmarks.runner.evaluator.extract_code_for_case", side_effect=_mock_extract), \
             patch("benchmarks.runner.evaluator.invoke_claude", side_effect=mock_invoke):
            summaries = evaluator.run([xss_case], engine)

        assert len(summaries) == 1
        s = summaries[0]
        assert s.agent_name == "xss"
        overall = next(m for m in s.metrics if m.cwe_id is None and m.language is None)
        assert overall.true_positives >= 1
        assert overall.tpr > 0.0

        cases_dir = config.results_dir / evaluator.run_id / "cases"
        assert (cases_dir / "integration-xss-1_vuln.json").exists()
        assert (cases_dir / "integration-xss-1_patched.json").exists()
