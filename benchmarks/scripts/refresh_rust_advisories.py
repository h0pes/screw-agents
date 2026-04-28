#!/usr/bin/env python3
"""Refresh Rust advisory candidates for Phase 4 D-01.

Queries the GitHub Advisory Database for Rust ecosystem advisories by CWE,
deduplicates advisories that match multiple queried CWEs, annotates known
Phase-4 triage facts, and writes a reproducible candidate manifest.

The output is an intermediate review artifact, not the final benchmark
manifest. Later D-01 tasks consume the reviewed candidates to materialize
Rust fixtures and bentoo-SARIF truth files.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# Keep direct invocation behavior aligned with the other benchmark scripts.
_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))


DEFAULT_CWES: tuple[str, ...] = (
    "CWE-77",
    "CWE-78",
    "CWE-79",
    "CWE-89",
    "CWE-94",
    "CWE-116",
    "CWE-1336",
)

DEFAULT_OUTPUT = (
    Path("benchmarks")
    / "external"
    / "rust-advisory-candidates"
    / "rust_advisories.json"
)

GITHUB_ADVISORIES_URL = "https://api.github.com/advisories"

# ADR-014 / benchmark-tier4-rust-modern.md: these Rust advisories appear under
# CWE-77 in GHSA/MITRE searches but are data-race / soundness issues, not command
# injection. Keep this list explicit so automated refreshes cannot quietly admit
# them into the CmdI candidate pool.
KNOWN_CWE77_DATA_RACE_PACKAGES: frozenset[str] = frozenset(
    {
        "bunch",
        "cache",
        "dces",
        "kekbit",
        "lever",
        "lexer",
        "multiqueue",
        "noise_search",
        "rcu_cell",
        "slock",
        "syncpool",
        "toolshed",
        "v9",
    }
)

# Existing D-01 research found this as a GHSA CWE-1336 hit, but it is a Zebra
# consensus/node crash, not server-side template injection.
KNOWN_NOT_SSTI_GHSAS: frozenset[str] = frozenset({"GHSA-qp6f-w4r3-h8wg"})

ADVISORY_TOKEN_RE = re.compile(
    r"\b(?:GHSA-[0-9A-Za-z]{4}-[0-9A-Za-z]{4}-[0-9A-Za-z]{4}|"
    r"CVE-\d{4}-\d{4,}|RUSTSEC-\d{4}-\d{4,})\b"
)


def _auth_headers() -> dict[str, str]:
    """Return GitHub API headers, using an optional local token if present."""
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "screw-agents-rust-advisory-refresh",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def fetch_github_advisories_for_cwe(
    cwe: str,
    *,
    per_page: int = 100,
    sleep_s: float = 0.0,
) -> list[dict[str, Any]]:
    """Fetch all GitHub advisories for one Rust CWE query."""
    page = 1
    advisories: list[dict[str, Any]] = []
    headers = _auth_headers()
    while True:
        query = urllib.parse.urlencode(
            {
                "ecosystem": "rust",
                # GitHub's advisory API expects the numeric CWE id ("79"),
                # not the display id ("CWE-79"). Keep the manifest's
                # `queried_cwes` in display form, but normalize the query.
                "cwes": _github_cwe_query_value(cwe),
                "per_page": per_page,
                "page": page,
            }
        )
        request = urllib.request.Request(
            f"{GITHUB_ADVISORIES_URL}?{query}",
            headers=headers,
            method="GET",
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                batch = json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(
                f"GitHub advisory query failed for {cwe} page {page}: "
                f"HTTP {exc.code}: {body}"
            ) from exc
        if not isinstance(batch, list):
            raise RuntimeError(
                f"GitHub advisory query for {cwe} page {page} returned "
                f"{type(batch).__name__}, expected list"
            )
        if not batch:
            break
        advisories.extend(batch)
        if len(batch) < per_page:
            break
        page += 1
        if sleep_s > 0:
            time.sleep(sleep_s)
    return advisories


def _github_cwe_query_value(cwe: str) -> str:
    """Convert ``CWE-79`` display ids to GitHub's ``79`` query value."""
    return cwe.removeprefix("CWE-")


def build_candidate_manifest(
    fetched_by_cwe: dict[str, list[dict[str, Any]]],
    *,
    domains_dir: Path = Path("domains"),
) -> dict[str, Any]:
    """Normalize, deduplicate, and annotate fetched advisory records."""
    yaml_index = _load_agent_yaml_index(domains_dir)
    by_ghsa: dict[str, dict[str, Any]] = {}
    for queried_cwe, advisories in fetched_by_cwe.items():
        for advisory in advisories:
            ghsa_id = advisory.get("ghsa_id")
            if not isinstance(ghsa_id, str) or not ghsa_id:
                continue
            if ghsa_id not in by_ghsa:
                by_ghsa[ghsa_id] = _normalize_advisory(advisory)
                by_ghsa[ghsa_id]["queried_cwes"] = []
            by_ghsa[ghsa_id]["queried_cwes"].append(queried_cwe)

    candidates = []
    for candidate in by_ghsa.values():
        candidate["queried_cwes"] = sorted(set(candidate["queried_cwes"]))
        candidate.update(_triage_annotations(candidate, yaml_index))
        candidates.append(candidate)

    candidates.sort(key=lambda c: (c["ghsa_id"], c["package_names"]))
    return {
        "schema_version": "rust-advisory-candidates/v1",
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "source": "github_advisory_database",
        "ecosystem": "rust",
        "cwes_queried": sorted(fetched_by_cwe.keys()),
        "candidate_count": len(candidates),
        "candidates": candidates,
        "notes": [
            "Intermediate D-01 review artifact; not final benchmark ground truth.",
            "GitHub Advisory Database CWE data is authoritative over RustSec categories.",
            "manual_review_status must be reviewed before fixture materialization.",
        ],
    }


def _normalize_advisory(advisory: dict[str, Any]) -> dict[str, Any]:
    identifiers = advisory.get("identifiers") or []
    aliases = sorted(
        {
            i.get("value")
            for i in identifiers
            if isinstance(i, dict) and isinstance(i.get("value"), str)
        }
    )
    referenced_identifiers = _referenced_advisory_identifiers(advisory)
    package_names = sorted(
        {
            vuln.get("package", {}).get("name")
            for vuln in advisory.get("vulnerabilities", []) or []
            if isinstance(vuln, dict)
            and isinstance(vuln.get("package"), dict)
            and vuln.get("package", {}).get("ecosystem") == "rust"
            and isinstance(vuln.get("package", {}).get("name"), str)
        }
    )
    cwes = sorted(
        {
            cwe.get("cwe_id")
            for cwe in advisory.get("cwes", []) or []
            if isinstance(cwe, dict) and isinstance(cwe.get("cwe_id"), str)
        }
    )
    vulnerabilities = []
    for vuln in advisory.get("vulnerabilities", []) or []:
        if not isinstance(vuln, dict):
            continue
        package = vuln.get("package") if isinstance(vuln.get("package"), dict) else {}
        patched = vuln.get("first_patched_version")
        vulnerabilities.append(
            {
                "package": package.get("name"),
                "ecosystem": package.get("ecosystem"),
                "vulnerable_version_range": vuln.get("vulnerable_version_range"),
                "first_patched_version": (
                    patched.get("identifier") if isinstance(patched, dict) else None
                ),
            }
        )

    return {
        "ghsa_id": advisory.get("ghsa_id"),
        "cve_id": advisory.get("cve_id"),
        "aliases": aliases,
        "referenced_identifiers": referenced_identifiers,
        "package_names": package_names,
        "summary": advisory.get("summary"),
        "severity": advisory.get("severity"),
        "cwes": cwes,
        "published_at": advisory.get("published_at"),
        "updated_at": advisory.get("updated_at"),
        "withdrawn_at": advisory.get("withdrawn_at"),
        "html_url": advisory.get("html_url"),
        "url": advisory.get("url"),
        "vulnerabilities": vulnerabilities,
    }


def _load_agent_yaml_index(domains_dir: Path) -> dict[str, list[str]]:
    """Index known advisory identifiers cited in tracked agent YAML."""
    index: dict[str, list[str]] = {}
    if not domains_dir.exists():
        return index
    for path in sorted(domains_dir.rglob("*.yaml")):
        text = path.read_text(encoding="utf-8")
        for token in _advisory_tokens_from_text(text):
            index.setdefault(token, []).append(str(path))
    return index


def _advisory_tokens_from_text(text: str) -> set[str]:
    return set(ADVISORY_TOKEN_RE.findall(text))


def _referenced_advisory_identifiers(advisory: dict[str, Any]) -> list[str]:
    """Extract advisory ids mentioned outside GitHub's identifier list.

    GitHub's Rust advisory records do not always expose RustSec ids in
    `identifiers`, while the agent YAML often cites RustSec URLs. Keeping these
    ids visible prevents Phase 4 from accidentally turning training examples
    into benchmark holdouts.
    """
    text_fragments: list[str] = []
    for key in ("summary", "description"):
        value = advisory.get(key)
        if isinstance(value, str):
            text_fragments.append(value)
    for reference in advisory.get("references", []) or []:
        if isinstance(reference, str):
            text_fragments.append(reference)
        elif isinstance(reference, dict):
            text_fragments.extend(
                value for value in reference.values() if isinstance(value, str)
            )
    return sorted(_advisory_tokens_from_text("\n".join(text_fragments)))


def _triage_annotations(
    candidate: dict[str, Any],
    yaml_index: dict[str, list[str]],
) -> dict[str, Any]:
    package_names = set(candidate["package_names"])
    cwes = set(candidate["cwes"]) | set(candidate["queried_cwes"])
    exclusion_reasons: list[str] = []
    if "CWE-77" in cwes and package_names & KNOWN_CWE77_DATA_RACE_PACKAGES:
        exclusion_reasons.append("known_cwe77_data_race_mislabel")
    if candidate["ghsa_id"] in KNOWN_NOT_SSTI_GHSAS:
        exclusion_reasons.append("known_not_ssti")

    refs: dict[str, list[str]] = {}
    for token in [
        candidate["ghsa_id"],
        candidate.get("cve_id"),
        *candidate["aliases"],
        *candidate["referenced_identifiers"],
    ]:
        if isinstance(token, str) and token in yaml_index:
            refs[token] = yaml_index[token]

    if exclusion_reasons:
        status = "exclude"
    else:
        status = "needs_review"
    return {
        "manual_review_status": status,
        "exclusion_reasons": sorted(exclusion_reasons),
        "referenced_in_agent_yaml": bool(refs),
        "agent_yaml_refs": refs,
    }


def write_manifest(path: Path, manifest: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Refresh Phase 4 D-01 Rust advisory candidate manifest",
    )
    parser.add_argument(
        "--cwe",
        action="append",
        dest="cwes",
        help="CWE to query. Repeatable. Defaults to the D-01 Rust CWE set.",
    )
    parser.add_argument(
        "--domains-dir",
        type=Path,
        default=Path("domains"),
        help="Agent YAML root used to mark training-contaminated advisories.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT,
        help=f"Output JSON path (default: {DEFAULT_OUTPUT})",
    )
    parser.add_argument("--per-page", type=int, default=100)
    parser.add_argument(
        "--sleep",
        type=float,
        default=0.0,
        help="Seconds to sleep between paginated GitHub requests.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    cwes = tuple(args.cwes or DEFAULT_CWES)
    fetched_by_cwe = {
        cwe: fetch_github_advisories_for_cwe(
            cwe,
            per_page=args.per_page,
            sleep_s=args.sleep,
        )
        for cwe in cwes
    }
    manifest = build_candidate_manifest(
        fetched_by_cwe,
        domains_dir=args.domains_dir,
    )
    write_manifest(args.output, manifest)
    print(
        f"Wrote {manifest['candidate_count']} Rust advisory candidates "
        f"to {args.output}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
