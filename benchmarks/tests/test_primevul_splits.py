"""Tests for chronological and cross-project splits."""
from datetime import date

import pytest

from benchmarks.runner.models import (
    BenchmarkCase,
    CodeLocation,
    Finding,
    FindingKind,
    Language,
)
from benchmarks.runner.primevul import chronological_split, cross_project_split


def _case(case_id: str, project: str, published: date) -> BenchmarkCase:
    return BenchmarkCase(
        case_id=case_id,
        project=project,
        language=Language.PYTHON,
        vulnerable_version="1.0",
        patched_version="1.1",
        ground_truth=[
            Finding(cwe_id="CWE-89", kind=FindingKind.FAIL,
                    location=CodeLocation(file="a.py", start_line=1, end_line=5)),
        ],
        published_date=published,
        source_dataset="test",
    )


def test_chronological_split_by_cutoff():
    cases = [
        _case("old1", "p1", date(2022, 1, 1)),
        _case("old2", "p2", date(2023, 6, 1)),
        _case("new1", "p1", date(2024, 5, 1)),
        _case("new2", "p3", date(2025, 1, 1)),
    ]
    train, test = chronological_split(cases, cutoff=date(2024, 1, 1))
    assert {c.case_id for c in train} == {"old1", "old2"}
    assert {c.case_id for c in test} == {"new1", "new2"}


def test_chronological_split_undated_go_to_train():
    cases = [
        _case("dated", "p1", date(2024, 1, 1)),
    ]
    undated = BenchmarkCase(
        case_id="undated", project="p2", language=Language.PYTHON,
        vulnerable_version="1.0", patched_version="1.1",
        ground_truth=[Finding(cwe_id="CWE-89", kind=FindingKind.FAIL,
                              location=CodeLocation(file="a.py", start_line=1, end_line=5))],
        published_date=None, source_dataset="test",
    )
    train, test = chronological_split([cases[0], undated], cutoff=date(2024, 6, 1))
    assert {c.case_id for c in train} == {"dated", "undated"}
    assert test == []


def test_cross_project_split_holds_out_one_project():
    cases = [
        _case("c1", "p1", date(2024, 1, 1)),
        _case("c2", "p1", date(2024, 2, 1)),
        _case("c3", "p2", date(2024, 3, 1)),
        _case("c4", "p3", date(2024, 4, 1)),
    ]
    train, test = cross_project_split(cases, holdout_project="p1")
    assert {c.case_id for c in train} == {"c3", "c4"}
    assert {c.case_id for c in test} == {"c1", "c2"}
