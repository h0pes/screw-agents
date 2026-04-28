"""Validation for Phase 4 D-01 synthetic Rust SSTI fixtures."""

from __future__ import annotations

import json
from pathlib import Path


METADATA_PATH = Path("benchmarks/data/rust-d01-synthetic-ssti.json")


def test_rust_d01_synthetic_ssti_metadata_is_explicit() -> None:
    payload = json.loads(METADATA_PATH.read_text(encoding="utf-8"))

    assert payload["schema_version"] == "rust-d01-synthetic-ssti/v1"
    assert payload["cwe_id"] == "CWE-1336"
    assert payload["agent"] == "ssti"
    assert payload["fixtures"]

    for fixture in payload["fixtures"]:
        path = Path(fixture["path"])
        assert path.exists(), fixture["path"]
        assert fixture["synthetic"] is True
        assert fixture["real_cve"] is False
        assert fixture["expected"] in {"true_positive", "true_negative"}
        assert fixture["misuse_pattern"]
        assert fixture["cwe_rationale"]


def test_rust_d01_synthetic_ssti_covers_expected_engines_and_sides() -> None:
    payload = json.loads(METADATA_PATH.read_text(encoding="utf-8"))
    by_engine: dict[str, set[str]] = {}
    for fixture in payload["fixtures"]:
        by_engine.setdefault(fixture["engine"], set()).add(fixture["expected"])

    assert by_engine["Tera"] == {"true_positive", "true_negative"}
    assert by_engine["MiniJinja"] == {"true_positive", "true_negative"}
    assert by_engine["Handlebars-rust"] == {"true_positive", "true_negative"}
    assert by_engine["Askama"] == {"true_negative"}
