"""Smoke tests for MoreFixes extract — no DB connection required."""
# ruff: noqa: S101

from pathlib import Path

from benchmarks.scripts._active_cwes import ACTIVE_CWE_INTS
from benchmarks.scripts.morefixes_extract import (
    MOREFIXES_LANGUAGES,
    MoreFixesExtractor,
    build_query,
)


def test_phase1_cwes_present_in_active_set():
    for cwe in (79, 78, 89, 94, 1336):
        assert cwe in ACTIVE_CWE_INTS


def test_morefixes_languages_all_present():
    for lang in ("python", "javascript", "typescript", "java", "go", "ruby", "php", "csharp"):
        assert lang in MOREFIXES_LANGUAGES


def test_build_query_has_cwe_and_language_filters():
    q = build_query(min_score=65)
    assert "cwe" in q.lower()
    assert "language" in q.lower() or "programming_language" in q.lower()
    assert "code_before" in q
    assert "code_after" in q
    assert "65" in q
    assert "ORDER BY f.cve_id, f.repo_url, f.hash" in q
    assert "mc.method_change_id" in q


def test_append_case_writes_snapshots_without_retaining_rows(tmp_path: Path):
    extractor = MoreFixesExtractor(root=tmp_path)
    rows = [
        {
            "cve_id": "CVE-2024-0001",
            "cwe": "CWE-89",
            "language": "python",
            "project": "https://github.com/example/project",
            "published_date": "2024-01-01T00:00:00",
            "commit_hash": "abc1234567890",
            "file_path": "src/app.py",
            "code_before": "print('vulnerable')",
            "code_after": "print('patched')",
            "method_name": "handler",
            "start_line": 5,
            "end_line": 8,
        }
    ]
    cases = []
    findings = extractor._row_to_findings(rows[0], "CWE-89", "CVE-2024-0001")

    extractor._write_row_snapshot(rows[0], rows[0])
    extractor._append_case(cases, rows[0], findings or [])

    assert len(cases) == 1
    case_dir = tmp_path / "external" / "morefixes" / cases[0].case_id
    assert (case_dir / "code" / "vulnerable" / "src%2Fapp.py").read_text() == (
        "print('vulnerable')"
    )
    assert (case_dir / "code" / "patched" / "src%2Fapp.py").read_text() == (
        "print('patched')"
    )
