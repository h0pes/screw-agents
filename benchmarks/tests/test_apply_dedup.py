"""Tests for apply_dedup.py."""
import json
from pathlib import Path

import pytest

from benchmarks.scripts.apply_dedup import load_all_cases


def test_load_all_cases_handles_empty(tmp_path: Path):
    (tmp_path / "external" / "manifests").mkdir(parents=True)
    cases = load_all_cases(tmp_path)
    assert cases == []


def test_load_all_cases_skips_prefixed_manifests(tmp_path: Path):
    manifests = tmp_path / "external" / "manifests"
    manifests.mkdir(parents=True)
    # A _-prefixed manifest should be ignored
    (manifests / "_deduplicated.manifest.json").write_text(json.dumps({
        "dataset_name": "_deduplicated", "cases": [{"case_id": "should-skip"}]
    }))
    cases = load_all_cases(tmp_path)
    assert cases == []


def test_load_all_cases_skips_pin_and_deployment(tmp_path: Path):
    manifests = tmp_path / "external" / "manifests"
    manifests.mkdir(parents=True)
    (manifests / "cve-ingest-pin.json").write_text("{}")
    (manifests / "morefixes-deployment.manifest.json").write_text("{}")
    cases = load_all_cases(tmp_path)
    assert cases == []


def test_load_all_cases_skips_missing_truth_sarif(tmp_path: Path):
    manifests = tmp_path / "external" / "manifests"
    manifests.mkdir(parents=True)
    (manifests / "test-dataset.manifest.json").write_text(json.dumps({
        "dataset_name": "test-dataset",
        "cases": [{"case_id": "no-sarif", "language": "python",
                    "project": "p", "vulnerable_version": "1",
                    "patched_version": "2"}]
    }))
    # Don't create the truth.sarif file — case should be skipped
    cases = load_all_cases(tmp_path)
    assert cases == []
