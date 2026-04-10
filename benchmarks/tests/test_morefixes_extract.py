"""Smoke tests for MoreFixes extract — no DB connection required."""
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
    assert "65" in q
