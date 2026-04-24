"""Tests for CSV output format (Phase 3a PR #3 X3)."""

from __future__ import annotations

import csv
import io
from pathlib import Path

import pytest

from screw_agents.formatter import format_csv
from screw_agents.models import FindingTriage

# Reuse the Finding construction helper from test_formatter.py
from tests.test_formatter import _make_finding


_EXPECTED_COLUMNS = [
    "id", "file", "line", "cwe", "cwe_name", "agent",
    "severity", "confidence", "description", "code_snippet",
    "excluded", "exclusion_ref", "merged_sources",
]


def test_format_csv_empty_findings():
    out = format_csv([], scan_metadata={"agent": "sqli"})
    reader = csv.reader(io.StringIO(out))
    rows = list(reader)
    assert len(rows) == 1  # header only
    assert rows[0] == _EXPECTED_COLUMNS


def test_format_csv_single_finding():
    finding = _make_finding()  # sqli-001, CWE-89, severity=high
    out = format_csv([finding], scan_metadata={"agent": "sqli"})
    reader = csv.reader(io.StringIO(out))
    rows = list(reader)
    assert len(rows) == 2  # header + 1 row
    data = dict(zip(_EXPECTED_COLUMNS, rows[1]))
    assert data["id"] == "sqli-001"
    assert data["file"] == "test.py"
    assert data["line"] == "10"
    assert data["cwe"] == "CWE-89"
    assert data["cwe_name"] == "SQL Injection"
    assert data["agent"] == "sqli"
    assert data["severity"] == "high"
    assert data["confidence"] == "high"
    assert "SQL injection" in data["description"]


def test_format_csv_includes_exclusion_status():
    finding = _make_finding(
        triage=FindingTriage(
            excluded=True,
            exclusion_ref="fp-2026-04-14-001",
        ),
    )
    out = format_csv([finding], scan_metadata={"agent": "sqli"})
    rows = list(csv.reader(io.StringIO(out)))
    data = dict(zip(_EXPECTED_COLUMNS, rows[1]))
    assert data["excluded"] == "True"
    assert data["exclusion_ref"] == "fp-2026-04-14-001"


def test_format_csv_handles_none_code_snippet():
    """location.code_snippet is optional — absent should serialize as empty string."""
    from screw_agents.models import FindingLocation

    finding = _make_finding(location=FindingLocation(file="src/x.py", line_start=5))
    out = format_csv([finding], scan_metadata={})
    rows = list(csv.reader(io.StringIO(out)))
    data = dict(zip(_EXPECTED_COLUMNS, rows[1]))
    assert data["code_snippet"] == ""


def test_render_and_write_csv_format(tmp_path: Path):
    """render_and_write writes a .csv file when 'csv' is in formats list."""
    from screw_agents.results import render_and_write

    finding = _make_finding()
    result = render_and_write(
        project_root=tmp_path,
        findings_raw=[finding.model_dump()],
        agent_names=["sqli"],
        scan_metadata={"agent": "sqli", "timestamp": "2026-04-14T10:00:00Z"},
        formats=["json", "markdown", "csv"],
    )
    assert "csv" in result["files_written"]
    csv_path = Path(result["files_written"]["csv"])
    assert csv_path.exists()
    assert csv_path.suffix == ".csv"
    content = csv_path.read_text()
    assert "test.py" in content
    assert "CWE-89" in content


def test_format_csv_sanitizes_formula_injection():
    """Cells starting with = + - @ get a tab prefix to prevent spreadsheet formula execution."""
    from screw_agents.models import FindingAnalysis, FindingLocation

    finding = _make_finding(
        analysis=FindingAnalysis(description="=cmd('calc')"),
        location=FindingLocation(file="src/a.py", line_start=10, code_snippet='+HYPERLINK("evil")'),
    )
    out = format_csv([finding])
    rows = list(csv.reader(io.StringIO(out)))
    data = dict(zip(rows[0], rows[1]))
    assert data["description"].startswith("\t=")
    assert data["code_snippet"].startswith("\t+")


def test_format_csv_merged_finding_populates_merged_sources_column():
    """A merged Finding's CSV row must carry a `"; "`-joined merged_sources
    cell in the last column; unmerged findings emit an empty last cell
    (T19-M1 D4).
    """
    from screw_agents.models import MergedSource

    merged = _make_finding(
        id="f1",
        merged_from_sources=[
            MergedSource(agent="adaptive_script:qb-check", severity="high"),
            MergedSource(agent="xss", severity="medium"),
        ],
    )
    unmerged = _make_finding(id="f2", merged_from_sources=None)

    out = format_csv([merged, unmerged])
    rows = list(csv.reader(io.StringIO(out)))

    # Header must include merged_sources as the LAST column.
    assert rows[0][-1] == "merged_sources"
    # Merged row: last cell is "; "-joined "<agent> (<severity>)".
    assert rows[1][-1] == "adaptive_script:qb-check (high); xss (medium)"
    # Unmerged row: last cell is empty.
    assert rows[2][-1] == ""
