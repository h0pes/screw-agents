"""End-to-end smoke test: ingested benchmark + mock agent → metrics + report."""
import json
from datetime import date
from pathlib import Path

import pytest

from benchmarks.runner.cwe import load_hierarchy
from benchmarks.runner.metrics import compute_metrics
from benchmarks.runner.models import (
    AgentRun,
    BenchmarkCase,
    CodeLocation,
    Finding,
    FindingKind,
    Language,
)
from benchmarks.runner.report import render_markdown


@pytest.fixture
def mini_case():
    return BenchmarkCase(
        case_id="e2e-1",
        project="e2e/proj",
        language=Language.JAVASCRIPT,
        vulnerable_version="1.0.0",
        patched_version="1.0.1",
        ground_truth=[
            Finding(cwe_id="CWE-79", kind=FindingKind.FAIL,
                    location=CodeLocation(file="src/view.js", start_line=42, end_line=55,
                                          function_name="render")),
            Finding(cwe_id="CWE-79", kind=FindingKind.PASS,
                    location=CodeLocation(file="src/view.js", start_line=42, end_line=58,
                                          function_name="render")),
        ],
        published_date=date(2024, 5, 1),
        source_dataset="e2e-test",
    )


def test_end_to_end_pipeline_produces_markdown(mini_case):
    hierarchy = load_hierarchy()
    vuln_run = AgentRun(
        case_id=mini_case.case_id, agent_name="mock", runtime_seconds=0.1,
        findings=[
            Finding(cwe_id="CWE-79", kind=FindingKind.FAIL,
                    location=CodeLocation(file="src/view.js", start_line=42, end_line=55,
                                          function_name="render"),
                    agent_name="mock", confidence=0.95),
        ],
    )
    patched_run = AgentRun(
        case_id=mini_case.case_id, agent_name="mock", runtime_seconds=0.1, findings=[],
    )

    summary = compute_metrics(
        cases=[mini_case], runs_vulnerable=[vuln_run], runs_patched=[patched_run],
        hierarchy=hierarchy, agent_name="mock", dataset="e2e-test",
    )

    overall = next(m for m in summary.metrics if m.cwe_id is None and m.language is None)
    assert overall.true_positives == 1
    assert overall.false_positives == 0
    assert overall.tpr == 1.0
    assert overall.fpr == 0.0

    md = render_markdown(summary)
    assert "e2e-test" in md
    assert "mock" in md
    assert "100.0%" in md
