# benchmarks/tests/test_gate_checker.py
"""Tests for G5-G7 gate checking."""
# ruff: noqa: S101

from __future__ import annotations

from benchmarks.runner.gate_checker import (
    RETIRED_G5_GATES,
    build_g7_failure_dump,
    check_g5_gates,
    check_g6_rust_disclaimer,
)
from benchmarks.runner.models import (
    CodeLocation,
    Finding,
    FindingKind,
    Language,
    MetricSet,
    Summary,
)


def _make_summary(agent: str, dataset: str, tpr: float, fpr: float,
                  cwe_id: str | None = None) -> Summary:
    ms = MetricSet(
        agent_name=agent, dataset=dataset,
        cwe_id=cwe_id, language=None,
        true_positives=int(tpr * 10), false_positives=int(fpr * 10),
        true_negatives=int((1 - fpr) * 10), false_negatives=int((1 - tpr) * 10),
        tpr=tpr, fpr=fpr,
        precision=0.5, f1=0.5, accuracy=tpr - fpr,
    )
    return Summary(
        run_id="test", agent_name=agent, dataset=dataset,
        methodology={"pair_based": True, "match_mode": "broad"},
        metrics=[ms], generated_at="2026-04-11T00:00:00Z",
    )


class TestCheckG5Gates:
    def test_all_gates_pass(self):
        summaries = [
            _make_summary("xss", "ossf-cve-benchmark", tpr=0.75, fpr=0.20),
            _make_summary("xss", "reality-check-csharp", tpr=0.65, fpr=0.10, cwe_id="CWE-79"),
            _make_summary("xss", "reality-check-python", tpr=0.65, fpr=0.10, cwe_id="CWE-79"),
            _make_summary("cmdi", "ossf-cve-benchmark", tpr=0.65, fpr=0.10),
            _make_summary("cmdi", "reality-check-java", tpr=0.55, fpr=0.10, cwe_id="CWE-78"),
            _make_summary("sqli", "reality-check-csharp", tpr=0.55, fpr=0.10, cwe_id="CWE-89"),
            _make_summary("sqli", "morefixes", tpr=0.55, fpr=0.10, cwe_id="CWE-89"),
            _make_summary("ssti", "morefixes", tpr=0.55, fpr=0.10, cwe_id="CWE-1336"),
        ]
        results = check_g5_gates(summaries)
        assert all(r.passed for r in results)
        assert {r.gate_id for r in results} == {
            "G5.1",
            "G5.2",
            "G5.3",
            "G5.4",
            "G5.5",
            "G5.6",
            "G5.7",
            "G5.8",
            "G5.11",
        }

    def test_misleading_ssti_gates_are_retired(self):
        assert "G5.9" in RETIRED_G5_GATES
        assert "G5.10" in RETIRED_G5_GATES
        assert "SQLi/CWE-89" in RETIRED_G5_GATES["G5.9"]
        assert "SQLi/CWE-89" in RETIRED_G5_GATES["G5.10"]

    def test_gate_fails_below_threshold(self):
        summaries = [_make_summary("xss", "ossf-cve-benchmark", tpr=0.50, fpr=0.20)]
        results = check_g5_gates(summaries)
        xss_ossf = [r for r in results if r.gate_id == "G5.1"]
        assert len(xss_ossf) == 1
        assert xss_ossf[0].passed is False

    def test_missing_summary_reports_not_run(self):
        results = check_g5_gates([])
        assert any(not r.passed for r in results)


class TestG6:
    def test_rust_disclaimer_present(self):
        languages_in_run = [Language.JAVASCRIPT, Language.PYTHON]
        assert check_g6_rust_disclaimer(languages_in_run) is True

    def test_rust_disclaimer_fails_if_rust_present(self):
        languages_in_run = [Language.JAVASCRIPT, Language.RUST]
        assert check_g6_rust_disclaimer(languages_in_run) is False


class TestG7:
    def test_failure_dump_lists_missed_cases(self):
        missed = [
            Finding(cwe_id="CWE-79", kind=FindingKind.FAIL,
                    location=CodeLocation(file="a.js", start_line=1, end_line=5),
                    cve_id="CVE-2024-001"),
        ]
        dump = build_g7_failure_dump(missed_findings=missed, false_flags=[], max_items=10)
        assert len(dump["missed"]) == 1
        assert dump["missed"][0]["cve_id"] == "CVE-2024-001"
