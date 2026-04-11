# benchmarks/tests/test_report_gates.py
"""Tests for gate report rendering (G5/G6/G7 sections)."""
from __future__ import annotations

import pytest

from benchmarks.runner.gate_checker import GateResult
from benchmarks.runner.report import render_gate_report


class TestRenderGateReport:
    def test_g5_pass_renders_checkmarks(self):
        gate_results = [
            GateResult(gate_id="G5.1", passed=True, actual_value=0.75,
                       threshold=0.70, comparison="gte", agent="xss",
                       dataset="ossf-cve-benchmark"),
        ]
        md = render_gate_report(gate_results, g6_passed=True, g7_dumps={})
        assert "PASS" in md
        assert "G5.1" in md

    def test_g5_fail_renders_crosses(self):
        gate_results = [
            GateResult(gate_id="G5.1", passed=False, actual_value=0.50,
                       threshold=0.70, comparison="gte", agent="xss",
                       dataset="ossf-cve-benchmark"),
        ]
        md = render_gate_report(gate_results, g6_passed=True, g7_dumps={})
        assert "FAIL" in md

    def test_g6_rust_disclaimer_present(self):
        md = render_gate_report([], g6_passed=True, g7_dumps={})
        assert "Rust detection quality not benchmarked" in md
        assert "ADR-014" in md

    def test_g7_failure_dump_included(self):
        dumps = {
            "G5.1": {
                "missed": [{"cwe_id": "CWE-79", "cve_id": "CVE-2024-001",
                            "file": "a.js", "start_line": 1, "end_line": 5,
                            "message": "XSS"}],
                "false_flags": [],
            }
        }
        md = render_gate_report([], g6_passed=True, g7_dumps=dumps)
        assert "CVE-2024-001" in md
        assert "a.js" in md
