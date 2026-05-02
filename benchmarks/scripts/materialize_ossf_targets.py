#!/usr/bin/env python3
"""Materialize target-project git clones for OSSF CVE benchmark cases."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlparse

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Clone or update target repositories referenced by OSSF CVE metadata. "
            "Generated clones are written under benchmarks/external and remain "
            "gitignored."
        ),
    )
    parser.add_argument(
        "--external-dir",
        type=Path,
        default=Path("benchmarks/external"),
        help="Benchmark external-data root.",
    )
    parser.add_argument(
        "--case-id",
        action="append",
        default=[],
        help="Specific OSSF case id to materialize, e.g. ossf-CVE-2017-16087.",
    )
    parser.add_argument(
        "--max-cases",
        type=int,
        default=0,
        help="Maximum manifest cases to materialize when --case-id is omitted.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    dataset_dir = args.external_dir / "ossf-cve-benchmark"
    manifest_path = args.external_dir / "manifests" / "ossf-cve-benchmark.manifest.json"
    cves_dir = dataset_dir / "repo" / "CVEs"
    if not manifest_path.exists():
        raise SystemExit(f"Manifest not found: {manifest_path}")
    if not cves_dir.exists():
        raise SystemExit(f"OSSF metadata CVEs directory not found: {cves_dir}")

    requested = set(args.case_id)
    cases = json.loads(manifest_path.read_text(encoding="utf-8")).get("cases", [])
    selected = [
        case
        for case in cases
        if not requested or str(case["case_id"]) in requested
    ]
    if args.max_cases > 0 and not requested:
        selected = selected[: args.max_cases]
    if requested and len(selected) != len(requested):
        found = {str(case["case_id"]) for case in selected}
        missing = ", ".join(sorted(requested - found))
        raise SystemExit(f"Requested case id(s) not found in manifest: {missing}")

    materialized = 0
    for case in selected:
        case_id = str(case["case_id"])
        metadata = _load_metadata(cves_dir, case_id)
        repository = str(metadata.get("repository") or case.get("project") or "")
        pre_commit = _commit(metadata, "prePatch")
        post_commit = _commit(metadata, "postPatch")
        if not repository or not pre_commit or not post_commit:
            print(f"skip {case_id}: missing repository or commit metadata")
            continue
        repo_dir = dataset_dir / "repos" / _repo_slug(repository)
        _ensure_clone(repository, repo_dir)
        _ensure_commit(repo_dir, pre_commit)
        _ensure_commit(repo_dir, post_commit)
        print(f"materialized {case_id}: {repo_dir}")
        materialized += 1

    print(f"Materialized {materialized} OSSF target repo(s).")
    return 0


def _load_metadata(cves_dir: Path, case_id: str) -> dict:
    cve_id = case_id.removeprefix("ossf-")
    metadata_path = cves_dir / f"{cve_id}.json"
    if not metadata_path.exists():
        raise SystemExit(f"Metadata not found for {case_id}: {metadata_path}")
    return json.loads(metadata_path.read_text(encoding="utf-8"))


def _commit(metadata: dict, key: str) -> str | None:
    data = metadata.get(key) or {}
    commit = data.get("commit")
    return str(commit) if commit else None


def _repo_slug(repository: str) -> str:
    parsed = urlparse(repository)
    path = parsed.path if parsed.scheme else repository
    return path.strip("/").removesuffix(".git").replace("/", "__")


def _ensure_clone(repository: str, repo_dir: Path) -> None:
    if (repo_dir / ".git").exists():
        subprocess.run(  # noqa: S603
            ["git", "-C", str(repo_dir), "fetch", "--tags", "origin"],  # noqa: S607
            check=True,
        )
        return
    repo_dir.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(  # noqa: S603
        ["git", "clone", "--no-checkout", repository, str(repo_dir)],  # noqa: S607
        check=True,
    )


def _ensure_commit(repo_dir: Path, commit: str) -> None:
    result = subprocess.run(  # noqa: S603
        ["git", "-C", str(repo_dir), "cat-file", "-e", f"{commit}^{{commit}}"],  # noqa: S607
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode == 0:
        return
    subprocess.run(  # noqa: S603
        ["git", "-C", str(repo_dir), "fetch", "origin", commit],  # noqa: S607
        check=True,
    )


if __name__ == "__main__":
    sys.exit(main())
