"""Tests for the Markdown report renderer."""
from benchmarks.runner.models import Language, MetricSet, Summary
from benchmarks.runner.report import render_markdown


def _make_summary() -> Summary:
    return Summary(
        run_id="test-run-001",
        agent_name="xss",
        dataset="ossf-cve-benchmark",
        methodology={"dedup": True, "chrono_split": True, "pair_based": True},
        metrics=[
            MetricSet(agent_name="xss", dataset="ossf-cve-benchmark",
                      cwe_id=None, language=None,
                      true_positives=20, false_positives=5,
                      true_negatives=15, false_negatives=10,
                      tpr=0.667, fpr=0.25, precision=0.80, f1=0.727, accuracy=0.417),
            MetricSet(agent_name="xss", dataset="ossf-cve-benchmark",
                      cwe_id="CWE-79", language=None,
                      true_positives=18, false_positives=4,
                      true_negatives=14, false_negatives=8,
                      tpr=0.692, fpr=0.222, precision=0.818, f1=0.750, accuracy=0.470),
            MetricSet(agent_name="xss", dataset="ossf-cve-benchmark",
                      cwe_id=None, language=Language.JAVASCRIPT,
                      true_positives=15, false_positives=3,
                      true_negatives=10, false_negatives=7,
                      tpr=0.682, fpr=0.231, precision=0.833, f1=0.750, accuracy=0.451),
        ],
        generated_at="2026-04-09T12:00:00+00:00",
    )


def test_report_contains_run_header():
    md = render_markdown(_make_summary())
    assert "xss" in md
    assert "ossf-cve-benchmark" in md
    assert "test-run-001" in md


def test_report_contains_overall_table():
    md = render_markdown(_make_summary())
    assert "Overall" in md
    assert "TPR" in md
    assert "66.7%" in md or "0.667" in md


def test_report_contains_per_cwe_section():
    md = render_markdown(_make_summary())
    assert "CWE-79" in md


def test_report_contains_per_language_section():
    md = render_markdown(_make_summary())
    assert "Javascript" in md or "javascript" in md or "JavaScript" in md


def test_report_contains_methodology_block():
    md = render_markdown(_make_summary())
    assert "dedup" in md.lower()
    assert "pair" in md.lower()
