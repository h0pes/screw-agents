"""Tests for D-01 Rust advisory review policy."""

from __future__ import annotations

import json
from pathlib import Path

from benchmarks.scripts.review_rust_advisory_candidates import (
    build_review_manifest,
    write_json,
)


def _candidate(
    ghsa_id: str,
    *,
    cwes: list[str],
    queried_cwes: list[str] | None = None,
    exclusion_reasons: list[str] | None = None,
    referenced_in_agent_yaml: bool = False,
) -> dict:
    return {
        "ghsa_id": ghsa_id,
        "cve_id": "CVE-2026-0001",
        "aliases": [ghsa_id, "CVE-2026-0001"],
        "referenced_identifiers": ["RUSTSEC-2026-0001"],
        "package_names": ["demo-crate"],
        "summary": "demo",
        "cwes": cwes,
        "queried_cwes": queried_cwes or cwes,
        "exclusion_reasons": exclusion_reasons or [],
        "referenced_in_agent_yaml": referenced_in_agent_yaml,
        "agent_yaml_refs": (
            {"CVE-2026-0001": ["domains/injection-input-handling/xss.yaml"]}
            if referenced_in_agent_yaml
            else {}
        ),
        "html_url": f"https://github.com/advisories/{ghsa_id}",
        "url": f"https://api.github.com/advisories/{ghsa_id}",
    }


def test_review_manifest_marks_viable_active_agent_candidate_for_manual_trace() -> None:
    manifest = build_review_manifest(
        {
            "schema_version": "rust-advisory-candidates/v1",
            "generated_at": "2026-04-28T00:00:00+00:00",
            "candidates": [_candidate("GHSA-xss", cwes=["CWE-79"])],
        }
    )

    reviewed = manifest["candidates"][0]
    assert reviewed["status"] == "needs_manual_code_trace"
    assert reviewed["target_agents"] == ["xss"]
    assert reviewed["referenced_identifiers"] == ["RUSTSEC-2026-0001"]
    assert reviewed["code_trace"]["fix_ref"] is None


def test_review_manifest_preserves_exclusions() -> None:
    manifest = build_review_manifest(
        {
            "candidates": [
                _candidate(
                    "GHSA-race",
                    cwes=["CWE-77"],
                    exclusion_reasons=["known_cwe77_data_race_mislabel"],
                )
            ]
        }
    )

    reviewed = manifest["candidates"][0]
    assert reviewed["status"] == "exclude"
    assert reviewed["status_reasons"] == ["known_cwe77_data_race_mislabel"]
    assert reviewed["target_agents"] == []


def test_review_manifest_marks_yaml_refs_as_training_only() -> None:
    manifest = build_review_manifest(
        {
            "candidates": [
                _candidate(
                    "GHSA-yaml-ref",
                    cwes=["CWE-89"],
                    referenced_in_agent_yaml=True,
                )
            ]
        }
    )

    reviewed = manifest["candidates"][0]
    assert reviewed["status"] == "training_only"
    assert reviewed["status_reasons"] == ["referenced_in_existing_agent_yaml"]
    assert reviewed["target_agents"] == ["sqli"]


def test_review_manifest_keeps_adjacent_cwe_for_manual_mapping() -> None:
    manifest = build_review_manifest(
        {"candidates": [_candidate("GHSA-cwe116", cwes=["CWE-116"])]}
    )

    reviewed = manifest["candidates"][0]
    assert reviewed["status"] == "needs_manual_code_trace"
    assert reviewed["target_agents"] == []
    assert reviewed["adjacent_cwes"] == ["CWE-116"]
    assert "adjacent:CWE-116" in reviewed["status_reasons"]


def test_write_json_creates_parent_and_newline(tmp_path: Path) -> None:
    out = tmp_path / "nested" / "reviewed.json"
    payload = {"schema_version": "rust-advisory-review/v1", "candidates": []}

    write_json(out, payload)

    assert json.loads(out.read_text()) == payload
    assert out.read_text().endswith("\n")
