#!/usr/bin/env python3
"""Create a reviewed D-01 Rust advisory manifest skeleton.

This is the policy layer between the raw GHSA refresh output and fixture
materialization. It deliberately does not auto-promote candidates to
``include_real_cve`` because that status requires manual code tracing: repo URL,
fix reference, vulnerable reference, and affected file/function.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

# Support direct invocation:
# `uv run python benchmarks/scripts/review_rust_advisory_candidates.py`
_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from benchmarks.scripts.refresh_rust_advisories import DEFAULT_OUTPUT


ReviewStatus = Literal[
    "exclude",
    "training_only",
    "needs_manual_code_trace",
    "include_real_cve",
]

REVIEWED_SCHEMA_VERSION = "rust-advisory-review/v1"
DEFAULT_REVIEWED_OUTPUT = DEFAULT_OUTPUT.with_name("rust_advisories.reviewed.json")

ACTIVE_AGENT_BY_CWE: dict[str, str] = {
    "CWE-77": "cmdi",
    "CWE-78": "cmdi",
    "CWE-79": "xss",
    "CWE-89": "sqli",
    "CWE-1336": "ssti",
}

ADJACENT_CWES: frozenset[str] = frozenset({"CWE-94", "CWE-116"})


def build_review_manifest(raw_manifest: dict[str, Any]) -> dict[str, Any]:
    """Convert a raw candidate manifest into a reviewed-manifest skeleton."""
    candidates = [
        _review_candidate(candidate)
        for candidate in raw_manifest.get("candidates", [])
    ]
    candidates.sort(key=lambda c: (c["status"], c["ghsa_id"]))
    return {
        "schema_version": REVIEWED_SCHEMA_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "source_manifest_schema": raw_manifest.get("schema_version"),
        "source_generated_at": raw_manifest.get("generated_at"),
        "candidate_count": len(candidates),
        "status_counts": _status_counts(candidates),
        "candidates": candidates,
        "notes": [
            "This file is a review skeleton. include_real_cve requires manual code tracing.",
            "needs_manual_code_trace is the expected status for viable but untraced GHSA candidates.",
            "training_only marks candidates already cited by agent YAML and unsuitable as holdout data.",
        ],
    }


def _review_candidate(candidate: dict[str, Any]) -> dict[str, Any]:
    cwes = sorted(set(candidate.get("cwes", [])) | set(candidate.get("queried_cwes", [])))
    agent_names = sorted({ACTIVE_AGENT_BY_CWE[cwe] for cwe in cwes if cwe in ACTIVE_AGENT_BY_CWE})
    adjacent_cwes = sorted(cwe for cwe in cwes if cwe in ADJACENT_CWES)

    status, reasons = _initial_status(candidate, agent_names, adjacent_cwes)
    if status == "exclude":
        agent_names = []
    return {
        "ghsa_id": candidate["ghsa_id"],
        "cve_id": candidate.get("cve_id"),
        "aliases": candidate.get("aliases", []),
        "package_names": candidate.get("package_names", []),
        "summary": candidate.get("summary"),
        "cwes": cwes,
        "queried_cwes": candidate.get("queried_cwes", []),
        "target_agents": agent_names,
        "adjacent_cwes": adjacent_cwes,
        "status": status,
        "status_reasons": reasons,
        "exclusion_reasons": candidate.get("exclusion_reasons", []),
        "referenced_in_agent_yaml": candidate.get("referenced_in_agent_yaml", False),
        "agent_yaml_refs": candidate.get("agent_yaml_refs", {}),
        "source_urls": {
            "html_url": candidate.get("html_url"),
            "api_url": candidate.get("url"),
        },
        "code_trace": {
            "repo_url": None,
            "fix_ref": None,
            "vulnerable_ref": None,
            "affected_files": [],
            "affected_functions": [],
            "trace_notes": None,
        },
    }


def _initial_status(
    candidate: dict[str, Any],
    agent_names: list[str],
    adjacent_cwes: list[str],
) -> tuple[ReviewStatus, list[str]]:
    if candidate.get("exclusion_reasons"):
        return "exclude", list(candidate["exclusion_reasons"])
    if candidate.get("referenced_in_agent_yaml"):
        return "training_only", ["referenced_in_existing_agent_yaml"]
    if agent_names:
        return "needs_manual_code_trace", ["requires_repo_fix_and_function_trace"]
    if adjacent_cwes:
        return "needs_manual_code_trace", [
            "adjacent_cwe_requires_manual_agent_mapping",
            *[f"adjacent:{cwe}" for cwe in adjacent_cwes],
        ]
    return "exclude", ["no_active_agent_or_adjacent_cwe"]


def _status_counts(candidates: list[dict[str, Any]]) -> dict[str, int]:
    counts = {
        "exclude": 0,
        "training_only": 0,
        "needs_manual_code_trace": 0,
        "include_real_cve": 0,
    }
    for candidate in candidates:
        counts[candidate["status"]] += 1
    return counts


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Create reviewed D-01 Rust advisory manifest skeleton",
    )
    parser.add_argument(
        "--input",
        type=Path,
        default=DEFAULT_OUTPUT,
        help=f"Raw candidate manifest path (default: {DEFAULT_OUTPUT})",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_REVIEWED_OUTPUT,
        help=f"Reviewed manifest output path (default: {DEFAULT_REVIEWED_OUTPUT})",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    raw = read_json(args.input)
    reviewed = build_review_manifest(raw)
    write_json(args.output, reviewed)
    print(
        f"Wrote {reviewed['candidate_count']} reviewed Rust advisory records "
        f"to {args.output}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
