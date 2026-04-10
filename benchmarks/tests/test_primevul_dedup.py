"""Tests for benchmarks.runner.primevul dedup."""
from datetime import date

import pytest

from benchmarks.runner.models import (
    BenchmarkCase,
    CodeLocation,
    Finding,
    FindingKind,
    Language,
)
from benchmarks.runner.primevul import ast_normalize, dedupe, hash_normalized


def _case(case_id: str, code: str, lang: Language, published: date) -> BenchmarkCase:
    return BenchmarkCase(
        case_id=case_id,
        project="test/proj",
        language=lang,
        vulnerable_version="1.0.0",
        patched_version="1.0.1",
        ground_truth=[
            Finding(
                cwe_id="CWE-89", kind=FindingKind.FAIL,
                location=CodeLocation(file="src/a.py", start_line=1, end_line=len(code.splitlines())),
                message=code,
            ),
        ],
        published_date=published,
        source_dataset="test",
    )


def test_ast_normalize_strips_comments_python():
    code1 = "def f(x):\n    # this is a comment\n    return x + 1\n"
    code2 = "def f(x):\n    return x + 1\n"
    n1 = ast_normalize(code1, Language.PYTHON)
    n2 = ast_normalize(code2, Language.PYTHON)
    assert n1 == n2


def test_ast_normalize_whitespace_insensitive():
    code1 = "def   f(x):\n    return     x+1\n"
    code2 = "def f(x):\n    return x + 1\n"
    n1 = ast_normalize(code1, Language.PYTHON)
    n2 = ast_normalize(code2, Language.PYTHON)
    assert n1 == n2


def test_hash_normalized_is_deterministic():
    code = "def f(x): return x"
    h1 = hash_normalized(code, Language.PYTHON)
    h2 = hash_normalized(code, Language.PYTHON)
    assert h1 == h2
    assert len(h1) == 64  # SHA-256 hex


def test_dedupe_keeps_earliest_published():
    c1 = _case("early", "def f(x): return x", Language.PYTHON, date(2024, 1, 1))
    c2 = _case("late", "def f(x): return x # different comment", Language.PYTHON, date(2024, 6, 1))
    result = dedupe([c1, c2])
    assert len(result) == 1
    assert result[0].case_id == "early"


def test_dedupe_preserves_distinct_cases():
    c1 = _case("a", "def f(x): return x", Language.PYTHON, date(2024, 1, 1))
    c2 = _case("b", "def g(x): return x * 2", Language.PYTHON, date(2024, 6, 1))
    result = dedupe([c1, c2])
    assert len(result) == 2


def test_dedupe_different_languages_never_match():
    c_py = _case("py", "def f(x): return x", Language.PYTHON, date(2024, 1, 1))
    c_js = _case("js", "function f(x) { return x; }", Language.JAVASCRIPT, date(2024, 1, 1))
    result = dedupe([c_py, c_js])
    assert len(result) == 2
