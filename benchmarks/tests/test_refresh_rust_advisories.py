"""Tests for Phase 4 D-01 Rust advisory refresh."""

from __future__ import annotations

import json
from pathlib import Path

from benchmarks.scripts.refresh_rust_advisories import (
    build_candidate_manifest,
    _github_cwe_query_value,
    write_manifest,
)


def _advisory(
    ghsa_id: str,
    *,
    package: str,
    cwes: list[str],
    cve_id: str | None = None,
    aliases: list[str] | None = None,
    references: list[str] | None = None,
) -> dict:
    identifiers = [{"type": "GHSA", "value": ghsa_id}]
    if cve_id:
        identifiers.append({"type": "CVE", "value": cve_id})
    for alias in aliases or []:
        identifiers.append({"type": "RUSTSEC", "value": alias})
    return {
        "ghsa_id": ghsa_id,
        "cve_id": cve_id,
        "summary": f"{package} advisory",
        "severity": "high",
        "published_at": "2026-01-02T00:00:00Z",
        "updated_at": "2026-01-03T00:00:00Z",
        "withdrawn_at": None,
        "html_url": f"https://github.com/advisories/{ghsa_id}",
        "url": f"https://api.github.com/advisories/{ghsa_id}",
        "references": references or [],
        "identifiers": identifiers,
        "cwes": [{"cwe_id": cwe, "name": cwe} for cwe in cwes],
        "vulnerabilities": [
            {
                "package": {"ecosystem": "rust", "name": package},
                "vulnerable_version_range": "< 1.2.3",
                "first_patched_version": {"identifier": "1.2.3"},
            }
        ],
    }


def test_manifest_deduplicates_advisory_seen_under_multiple_cwes(tmp_path: Path) -> None:
    domains = tmp_path / "domains"
    domains.mkdir()
    fetched = {
        "CWE-77": [
            _advisory("GHSA-vx24-x4mv-vwr5", package="starship", cwes=["CWE-77", "CWE-78"])
        ],
        "CWE-78": [
            _advisory("GHSA-vx24-x4mv-vwr5", package="starship", cwes=["CWE-77", "CWE-78"])
        ],
    }

    manifest = build_candidate_manifest(fetched, domains_dir=domains)

    assert manifest["candidate_count"] == 1
    candidate = manifest["candidates"][0]
    assert candidate["ghsa_id"] == "GHSA-vx24-x4mv-vwr5"
    assert candidate["queried_cwes"] == ["CWE-77", "CWE-78"]
    assert candidate["manual_review_status"] == "needs_review"


def test_github_cwe_query_value_strips_display_prefix() -> None:
    assert _github_cwe_query_value("CWE-79") == "79"
    assert _github_cwe_query_value("79") == "79"


def test_known_cwe77_data_race_package_is_excluded(tmp_path: Path) -> None:
    manifest = build_candidate_manifest(
        {
            "CWE-77": [
                _advisory("GHSA-example-data-race", package="kekbit", cwes=["CWE-77"])
            ]
        },
        domains_dir=tmp_path / "missing-domains",
    )

    candidate = manifest["candidates"][0]
    assert candidate["manual_review_status"] == "exclude"
    assert candidate["exclusion_reasons"] == ["known_cwe77_data_race_mislabel"]


def test_agent_yaml_references_mark_training_contamination(tmp_path: Path) -> None:
    domains = tmp_path / "domains" / "injection-input-handling"
    domains.mkdir(parents=True)
    (domains / "sqli.yaml").write_text(
        "sources:\n  - url: https://github.com/advisories/GHSA-wq9x-qwcq-mmgf\n",
        encoding="utf-8",
    )

    manifest = build_candidate_manifest(
        {
            "CWE-89": [
                _advisory(
                    "GHSA-wq9x-qwcq-mmgf",
                    package="diesel",
                    cwes=["CWE-89"],
                    aliases=["RUSTSEC-2024-0365"],
                )
            ]
        },
        domains_dir=tmp_path / "domains",
    )

    candidate = manifest["candidates"][0]
    assert candidate["referenced_in_agent_yaml"] is True
    assert candidate["agent_yaml_refs"] == {
        "GHSA-wq9x-qwcq-mmgf": [
            str(tmp_path / "domains" / "injection-input-handling" / "sqli.yaml")
        ]
    }


def test_reference_url_identifiers_mark_training_contamination(tmp_path: Path) -> None:
    domains = tmp_path / "domains" / "injection-input-handling"
    domains.mkdir(parents=True)
    (domains / "xss.yaml").write_text(
        "sources:\n  - url: https://rustsec.org/advisories/RUSTSEC-2025-0071.html\n",
        encoding="utf-8",
    )

    manifest = build_candidate_manifest(
        {
            "CWE-79": [
                _advisory(
                    "GHSA-mm7x-qfjj-5g2c",
                    package="ammonia",
                    cwes=["CWE-79"],
                    references=[
                        "https://rustsec.org/advisories/RUSTSEC-2025-0071.html"
                    ],
                )
            ]
        },
        domains_dir=tmp_path / "domains",
    )

    candidate = manifest["candidates"][0]
    assert candidate["referenced_identifiers"] == ["RUSTSEC-2025-0071"]
    assert candidate["referenced_in_agent_yaml"] is True
    assert candidate["agent_yaml_refs"] == {
        "RUSTSEC-2025-0071": [
            str(tmp_path / "domains" / "injection-input-handling" / "xss.yaml")
        ]
    }


def test_write_manifest_creates_parent_and_stable_json(tmp_path: Path) -> None:
    out = tmp_path / "nested" / "rust_advisories.json"
    manifest = {
        "schema_version": "rust-advisory-candidates/v1",
        "candidate_count": 0,
        "candidates": [],
    }

    write_manifest(out, manifest)

    assert json.loads(out.read_text()) == manifest
    assert out.read_text().endswith("\n")
