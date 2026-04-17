"""End-to-end integration tests for Phase 3a PR #3 carryover cleanup."""

from __future__ import annotations

import csv
import io
import json
from pathlib import Path

import pytest

from screw_agents.engine import ScanEngine
from screw_agents.models import FindingAnalysis
from screw_agents.results import write_scan_results

from tests.test_formatter import _make_finding


def test_scan_domain_pagination_with_large_target(tmp_path: Path):
    """Pagination completes without error on a directory of 100+ files."""
    src = tmp_path / "src"
    src.mkdir()
    for i in range(120):
        (src / f"f{i:03d}.py").write_text(
            f"cursor.execute('SELECT * FROM t{i}')\n"
        )

    engine = ScanEngine.from_defaults()
    cursor: str | None = None
    all_files: set[str] = set()
    pages = 0
    while pages < 10:
        result = engine.assemble_domain_scan(
            domain="injection-input-handling",
            target={"type": "glob", "pattern": str(src / "*.py")},
            project_root=tmp_path,
            cursor=cursor,
            page_size=30,
        )
        for agent_result in result["agents"]:
            all_files.update(agent_result.get("resolved_files", []))
        pages += 1
        if result["next_cursor"] is None:
            break
        cursor = result["next_cursor"]

    assert len(all_files) == 120


def test_write_scan_results_all_three_formats(tmp_path: Path):
    """write_scan_results produces JSON (with null impact), Markdown (with full CWE
    name), and CSV (valid schema) when all three formats are requested."""
    # Construct a finding with no impact/exploitability set — exercises Task 27 null defaults
    finding = _make_finding(analysis=FindingAnalysis(description="SQLi via f-string"))
    result = write_scan_results(
        project_root=tmp_path,
        findings_raw=[finding.model_dump()],
        agent_names=["sqli"],
        scan_metadata={"agent": "sqli", "timestamp": "2026-04-14T10:00:00Z"},
        formats=["json", "markdown", "csv"],
    )

    assert set(result["files_written"].keys()) == {"json", "markdown", "csv"}

    # JSON output — nested analysis.impact is null (X2.1 nested-path assertion)
    json_data = json.loads(Path(result["files_written"]["json"]).read_text())
    assert isinstance(json_data, list)
    assert json_data[0]["analysis"]["impact"] is None
    assert json_data[0]["analysis"]["exploitability"] is None

    # Markdown — detail heading contains finding id + CWE id + long name (X2.3)
    md_content = Path(result["files_written"]["markdown"]).read_text()
    assert "### sqli-001 — CWE-89 — SQL Injection" in md_content

    # CSV — valid structure, expected columns, key values present (X3)
    csv_content = Path(result["files_written"]["csv"]).read_text()
    reader = csv.reader(io.StringIO(csv_content))
    rows = list(reader)
    assert len(rows) == 2  # header + 1 data row
    assert rows[0][0] == "id"
    assert rows[0][3] == "cwe"
    data = dict(zip(rows[0], rows[1]))
    assert data["id"] == "sqli-001"
    assert data["cwe"] == "CWE-89"
    assert data["agent"] == "sqli"
