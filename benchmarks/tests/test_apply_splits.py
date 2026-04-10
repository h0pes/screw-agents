"""Tests for apply_splits.py."""
from datetime import date

from benchmarks.scripts.apply_splits import apply_chrono_split, apply_cross_project_splits


def test_chrono_split_by_date():
    cases = [
        {"case_id": "old", "project": "p1", "published_date": "2023-06-01"},
        {"case_id": "new", "project": "p2", "published_date": "2024-06-01"},
        {"case_id": "undated", "project": "p3", "published_date": None},
    ]
    result = apply_chrono_split(cases, cutoff=date(2024, 1, 1))
    assert "old" in result["train_case_ids"]
    assert "new" in result["test_case_ids"]
    assert "undated" in result["train_case_ids"]


def test_cross_project_split_yields_one_per_project():
    cases = [
        {"case_id": "a", "project": "p1"},
        {"case_id": "b", "project": "p1"},
        {"case_id": "c", "project": "p2"},
    ]
    result = apply_cross_project_splits(cases)
    assert result["total_projects"] == 2
    p1_split = next(s for s in result["splits"] if s["holdout_project"] == "p1")
    assert {"a", "b"} == set(p1_split["test_case_ids"])
    assert ["c"] == p1_split["train_case_ids"]
