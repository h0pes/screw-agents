"""Tests for benchmarks.runner.sarif — bentoo-sarif round-trip."""
import json
from pathlib import Path

import pytest

from benchmarks.runner.models import CodeLocation, Finding, FindingKind
from benchmarks.runner.sarif import load_bentoo_sarif, write_bentoo_sarif


def test_load_mini_truth_returns_three_findings(fixtures_dir: Path):
    findings = load_bentoo_sarif(fixtures_dir / "mini_truth.sarif")
    assert len(findings) == 3


def test_load_preserves_cwe_and_kind(fixtures_dir: Path):
    findings = load_bentoo_sarif(fixtures_dir / "mini_truth.sarif")
    cwes = {f.cwe_id for f in findings}
    kinds = [f.kind for f in findings]
    assert cwes == {"CWE-89", "CWE-79"}
    assert kinds.count(FindingKind.FAIL) == 2
    assert kinds.count(FindingKind.PASS) == 1


def test_load_extracts_file_lines_and_function(fixtures_dir: Path):
    findings = load_bentoo_sarif(fixtures_dir / "mini_truth.sarif")
    sqli_fail = next(f for f in findings if f.cwe_id == "CWE-89" and f.kind == FindingKind.FAIL)
    assert sqli_fail.location.file == "src/api/users.py"
    assert sqli_fail.location.start_line == 42
    assert sqli_fail.location.end_line == 50
    assert sqli_fail.location.function_name == "get_user_by_id"
    assert sqli_fail.cve_id == "CVE-2024-99999"


def test_load_rejects_missing_rule_id(fixtures_dir: Path, tmp_path: Path):
    bad = tmp_path / "bad.sarif"
    bad.write_text(json.dumps({
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "t"}},
                  "results": [{"kind": "fail", "message": {"text": "x"}, "locations": []}]}]
    }))
    with pytest.raises(ValueError, match="ruleId"):
        load_bentoo_sarif(bad)


def test_write_then_load_round_trips(tmp_path: Path):
    original = [
        Finding(cwe_id="CWE-78", kind=FindingKind.FAIL,
                location=CodeLocation(file="a.py", start_line=1, end_line=2, function_name="f"),
                cve_id="CVE-2024-1"),
        Finding(cwe_id="CWE-78", kind=FindingKind.PASS,
                location=CodeLocation(file="a.py", start_line=1, end_line=3, function_name="f"),
                cve_id="CVE-2024-1"),
    ]
    out = tmp_path / "roundtrip.sarif"
    write_bentoo_sarif(out, original, tool_name="test-driver")
    loaded = load_bentoo_sarif(out)
    assert len(loaded) == 2
    assert loaded[0].cwe_id == "CWE-78"
    assert loaded[0].kind == FindingKind.FAIL
    assert loaded[1].kind == FindingKind.PASS
