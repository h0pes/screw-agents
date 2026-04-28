"""Validation for the tracked D-01 Rust real-CVE seed list."""

from __future__ import annotations

import json
from pathlib import Path


SEEDS_PATH = Path("benchmarks/data/rust-d01-reviewed-seeds.json")
ACTIVE_CWE_AGENT = {
    "CWE-77": "cmdi",
    "CWE-78": "cmdi",
    "CWE-79": "xss",
    "CWE-89": "sqli",
    "CWE-1336": "ssti",
}


def test_rust_d01_review_seeds_are_real_cve_ready() -> None:
    payload = json.loads(SEEDS_PATH.read_text(encoding="utf-8"))

    assert payload["schema_version"] == "rust-d01-reviewed-seeds/v1"
    assert payload["seeds"]

    seen_ghsas: set[str] = set()
    for seed in payload["seeds"]:
        assert seed["review_status"] == "include_real_cve"
        assert seed["training_contamination"] is False
        assert seed["ghsa_id"].startswith("GHSA-")
        assert seed["ghsa_id"] not in seen_ghsas
        seen_ghsas.add(seed["ghsa_id"])
        assert seed["cve_id"].startswith("CVE-")
        assert seed["repo_url"].startswith("https://github.com/")
        assert seed["vulnerable_ref"]
        assert seed["patched_ref"]
        assert seed["source_urls"]
        assert seed["target_agents"] == [ACTIVE_CWE_AGENT[seed["cwe_id"]]]
        assert seed["affected_files"]
        for affected_file in seed["affected_files"]:
            assert affected_file["path"].endswith(".rs")
            assert affected_file["function_name"]
            assert affected_file["vulnerable_lines"]["start"] <= affected_file[
                "vulnerable_lines"
            ]["end"]
            assert affected_file["patched_lines"]["start"] <= affected_file[
                "patched_lines"
            ]["end"]


def test_rust_d01_review_seeds_cover_initial_active_agents() -> None:
    payload = json.loads(SEEDS_PATH.read_text(encoding="utf-8"))
    covered_agents = {
        agent for seed in payload["seeds"] for agent in seed["target_agents"]
    }

    assert {"cmdi", "sqli", "xss"}.issubset(covered_agents)
