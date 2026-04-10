"""Tests for benchmarks.runner.metrics — pair-based TPR/FPR/precision."""
from datetime import date

import pytest

from benchmarks.runner.cwe import load_hierarchy
from benchmarks.runner.metrics import compute_metrics, locations_match
from benchmarks.runner.models import (
    AgentRun,
    BenchmarkCase,
    CodeLocation,
    Finding,
    FindingKind,
    Language,
)


@pytest.fixture
def hierarchy():
    return load_hierarchy()


def _make_case(case_id: str, cwe: str, file: str, lines: tuple[int, int]) -> BenchmarkCase:
    return BenchmarkCase(
        case_id=case_id,
        project="test/project",
        language=Language.PYTHON,
        vulnerable_version="1.0.0",
        patched_version="1.0.1",
        ground_truth=[
            Finding(cwe_id=cwe, kind=FindingKind.FAIL,
                    location=CodeLocation(file=file, start_line=lines[0], end_line=lines[1])),
            Finding(cwe_id=cwe, kind=FindingKind.PASS,
                    location=CodeLocation(file=file, start_line=lines[0], end_line=lines[1] + 2)),
        ],
        published_date=date(2024, 1, 1),
        source_dataset="test",
    )


def _agent_find(case_id: str, cwe: str, file: str, lines: tuple[int, int], agent: str = "test") -> Finding:
    return Finding(
        cwe_id=cwe, kind=FindingKind.FAIL, agent_name=agent, confidence=0.9,
        location=CodeLocation(file=file, start_line=lines[0], end_line=lines[1]),
    )


def test_perfect_agent_all_true_positives(hierarchy):
    cases = [_make_case("c1", "CWE-89", "a.py", (10, 15))]
    runs_vuln = [AgentRun(case_id="c1", agent_name="perfect",
                          findings=[_agent_find("c1", "CWE-89", "a.py", (10, 15))],
                          runtime_seconds=0.1)]
    runs_patched = [AgentRun(case_id="c1", agent_name="perfect",
                             findings=[], runtime_seconds=0.1)]
    summary = compute_metrics(cases, runs_vuln, runs_patched, hierarchy,
                              agent_name="perfect", dataset="test")
    overall = next(m for m in summary.metrics if m.cwe_id is None and m.language is None)
    assert overall.true_positives == 1
    assert overall.false_positives == 0
    assert overall.false_negatives == 0
    assert overall.tpr == 1.0
    assert overall.fpr == 0.0


def test_missed_vulnerability_counts_false_negative(hierarchy):
    cases = [_make_case("c1", "CWE-89", "a.py", (10, 15))]
    runs_vuln = [AgentRun(case_id="c1", agent_name="blind", findings=[], runtime_seconds=0.1)]
    runs_patched = [AgentRun(case_id="c1", agent_name="blind", findings=[], runtime_seconds=0.1)]
    summary = compute_metrics(cases, runs_vuln, runs_patched, hierarchy,
                              agent_name="blind", dataset="test")
    overall = next(m for m in summary.metrics if m.cwe_id is None and m.language is None)
    assert overall.true_positives == 0
    assert overall.false_negatives == 1
    assert overall.tpr == 0.0


def test_flagging_patched_counts_false_positive(hierarchy):
    cases = [_make_case("c1", "CWE-89", "a.py", (10, 15))]
    runs_vuln = [AgentRun(case_id="c1", agent_name="noisy",
                          findings=[_agent_find("c1", "CWE-89", "a.py", (10, 15))],
                          runtime_seconds=0.1)]
    runs_patched = [AgentRun(case_id="c1", agent_name="noisy",
                             findings=[_agent_find("c1", "CWE-89", "a.py", (10, 15))],
                             runtime_seconds=0.1)]
    summary = compute_metrics(cases, runs_vuln, runs_patched, hierarchy,
                              agent_name="noisy", dataset="test")
    overall = next(m for m in summary.metrics if m.cwe_id is None and m.language is None)
    assert overall.true_positives == 0
    assert overall.false_positives == 1
    assert overall.true_negatives == 0
    assert overall.false_negatives == 1


def test_wrong_file_not_a_match(hierarchy):
    cases = [_make_case("c1", "CWE-89", "a.py", (10, 15))]
    runs_vuln = [AgentRun(case_id="c1", agent_name="confused",
                          findings=[_agent_find("c1", "CWE-89", "b.py", (10, 15))],
                          runtime_seconds=0.1)]
    runs_patched = [AgentRun(case_id="c1", agent_name="confused",
                             findings=[], runtime_seconds=0.1)]
    summary = compute_metrics(cases, runs_vuln, runs_patched, hierarchy,
                              agent_name="confused", dataset="test")
    overall = next(m for m in summary.metrics if m.cwe_id is None and m.language is None)
    assert overall.true_positives == 0
    assert overall.false_positives == 1
    assert overall.false_negatives == 1


def test_locations_match_line_overlap():
    a = CodeLocation(file="x.py", start_line=10, end_line=20)
    b = CodeLocation(file="x.py", start_line=15, end_line=25)
    assert locations_match(a, b) is True

    c = CodeLocation(file="x.py", start_line=30, end_line=40)
    assert locations_match(a, c) is False

    d = CodeLocation(file="y.py", start_line=10, end_line=20)
    assert locations_match(a, d) is False


def test_agent_flags_patched_only_is_fp(hierarchy):
    """Agent flags the patched version but NOT the vulnerable version."""
    cases = [_make_case("c1", "CWE-89", "a.py", (10, 15))]
    runs_vuln = [AgentRun(case_id="c1", agent_name="inverse",
                          findings=[], runtime_seconds=0.1)]
    runs_patched = [AgentRun(case_id="c1", agent_name="inverse",
                             findings=[_agent_find("c1", "CWE-89", "a.py", (10, 15))],
                             runtime_seconds=0.1)]
    summary = compute_metrics(cases, runs_vuln, runs_patched, hierarchy,
                              agent_name="inverse", dataset="test")
    overall = next(m for m in summary.metrics if m.cwe_id is None and m.language is None)
    assert overall.true_positives == 0
    assert overall.false_positives == 1
    assert overall.true_negatives == 0
    assert overall.false_negatives == 1


def test_spurious_patched_finding_counts_fp(hierarchy):
    """Agent reports a finding on patched version at an unrelated location."""
    cases = [_make_case("c1", "CWE-89", "a.py", (10, 15))]
    runs_vuln = [AgentRun(case_id="c1", agent_name="noisy",
                          findings=[_agent_find("c1", "CWE-89", "a.py", (10, 15))],
                          runtime_seconds=0.1)]
    runs_patched = [AgentRun(case_id="c1", agent_name="noisy",
                             findings=[_agent_find("c1", "CWE-89", "a.py", (100, 110))],
                             runtime_seconds=0.1)]
    summary = compute_metrics(cases, runs_vuln, runs_patched, hierarchy,
                              agent_name="noisy", dataset="test")
    overall = next(m for m in summary.metrics if m.cwe_id is None and m.language is None)
    assert overall.true_positives == 1  # correctly flagged vuln, didn't flag patched at same loc
    assert overall.false_positives == 1  # spurious finding at unrelated patched location
    assert overall.true_negatives == 1  # pass truth not flagged
    assert overall.false_negatives == 0


def test_per_cwe_breakdown(hierarchy):
    cases = [
        _make_case("c1", "CWE-89", "a.py", (10, 15)),
        _make_case("c2", "CWE-79", "b.py", (30, 40)),
    ]
    runs_vuln = [
        AgentRun(case_id="c1", agent_name="a", runtime_seconds=0.1,
                 findings=[_agent_find("c1", "CWE-89", "a.py", (10, 15))]),
        AgentRun(case_id="c2", agent_name="a", runtime_seconds=0.1, findings=[]),
    ]
    runs_patched = [
        AgentRun(case_id="c1", agent_name="a", runtime_seconds=0.1, findings=[]),
        AgentRun(case_id="c2", agent_name="a", runtime_seconds=0.1, findings=[]),
    ]
    summary = compute_metrics(cases, runs_vuln, runs_patched, hierarchy,
                              agent_name="a", dataset="test")
    cwe89 = next(m for m in summary.metrics if m.cwe_id == "CWE-89" and m.language is None)
    cwe79 = next(m for m in summary.metrics if m.cwe_id == "CWE-79" and m.language is None)
    assert cwe89.tpr == 1.0
    assert cwe79.tpr == 0.0
