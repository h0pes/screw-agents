"""Tests for apply_dedup.py."""
import json
from pathlib import Path

import pytest

from benchmarks.scripts.apply_dedup import load_all_cases


def test_load_all_cases_handles_empty(tmp_path: Path):
    (tmp_path / "external" / "manifests").mkdir(parents=True)
    cases = load_all_cases(tmp_path)
    assert cases == []
