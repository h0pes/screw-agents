"""Unit tests for benchmarks.runner.models — typed domain objects."""
from datetime import date

import pytest
from pydantic import ValidationError

from benchmarks.runner.models import (
    AgentRun,
    BenchmarkCase,
    CodeLocation,
    Finding,
    FindingKind,
    Language,
    MetricSet,
    Summary,
)


def test_code_location_requires_file_and_lines():
    loc = CodeLocation(file="src/api.py", start_line=10, end_line=20)
    assert loc.file == "src/api.py"
    assert loc.start_line == 10
    assert loc.end_line == 20
    assert loc.function_name is None


def test_finding_kind_is_constrained_enum():
    with pytest.raises(ValidationError):
        Finding(
            cwe_id="CWE-89",
            kind="maybe",  # invalid — must be fail or pass
            location=CodeLocation(file="x", start_line=1, end_line=1),
        )


def test_finding_accepts_fail_and_pass():
    Finding(cwe_id="CWE-89", kind=FindingKind.FAIL,
            location=CodeLocation(file="x", start_line=1, end_line=1))
    Finding(cwe_id="CWE-89", kind=FindingKind.PASS,
            location=CodeLocation(file="x", start_line=1, end_line=1))


def test_benchmark_case_pair_has_both_kinds():
    case = BenchmarkCase(
        case_id="test-1",
        project="acme/widget",
        language=Language.PYTHON,
        vulnerable_version="1.0.0",
        patched_version="1.0.1",
        ground_truth=[
            Finding(cwe_id="CWE-89", kind=FindingKind.FAIL,
                    location=CodeLocation(file="src/db.py", start_line=10, end_line=12)),
            Finding(cwe_id="CWE-89", kind=FindingKind.PASS,
                    location=CodeLocation(file="src/db.py", start_line=10, end_line=14)),
        ],
        published_date=date(2024, 5, 1),
        source_dataset="reality-check",
    )
    assert len(case.ground_truth) == 2
    kinds = {f.kind for f in case.ground_truth}
    assert kinds == {FindingKind.FAIL, FindingKind.PASS}


def test_metric_set_accuracy_formula():
    m = MetricSet(
        agent_name="xss",
        dataset="ossf-cve-benchmark",
        cwe_id="CWE-79",
        language=Language.JAVASCRIPT,
        true_positives=15, false_positives=3, true_negatives=12, false_negatives=5,
        tpr=0.75, fpr=0.20,
        precision=0.833, f1=0.789, accuracy=0.55,
    )
    assert round(m.accuracy, 3) == 0.550
    assert m.tpr - m.fpr == pytest.approx(m.accuracy, abs=0.001)


def test_code_location_rejects_inverted_lines():
    with pytest.raises(ValidationError):
        CodeLocation(file="x", start_line=20, end_line=5)


def test_summary_round_trips_json():
    summary = Summary(
        run_id="test-run",
        agent_name="xss",
        dataset="ossf-cve-benchmark",
        methodology={"dedup": True, "chrono_split": True, "pair_based": True},
        metrics=[],
        generated_at="2026-04-09T12:00:00Z",
    )
    js = summary.model_dump_json()
    restored = Summary.model_validate_json(js)
    assert restored.run_id == "test-run"
