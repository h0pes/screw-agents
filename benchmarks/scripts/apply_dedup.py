"""Apply PrimeVul deduplication across all ingested benchmarks.

Reads all *.manifest.json from benchmarks/external/manifests/, rehydrates
BenchmarkCase objects by loading truth.sarif, runs dedupe(), and writes
_deduplicated.manifest.json.

Skip logic:
  - Manifests whose name starts with '_'
  - cve-ingest-pin.json
  - morefixes-deployment.manifest.json

For each case in a manifest, truth.sarif is expected at:
  <root>/external/<dataset_name>/<case_id>/truth.sarif

If truth.sarif doesn't exist, the case hasn't been ingested yet — skip it.
"""
from __future__ import annotations

import json
from pathlib import Path

from benchmarks.runner.models import BenchmarkCase
from benchmarks.runner.primevul import dedupe
from benchmarks.runner.sarif import load_bentoo_sarif


_SKIP_NAMES = {"cve-ingest-pin.json", "morefixes-deployment.manifest.json"}


def load_all_cases(root: Path) -> list[BenchmarkCase]:
    """Load and return all BenchmarkCase objects from ingested manifests.

    Parameters
    ----------
    root:
        The benchmarks/ root directory. Manifests are expected at
        ``root/external/manifests/*.manifest.json``.
    """
    manifests_dir = root / "external" / "manifests"
    if not manifests_dir.exists():
        return []

    cases: list[BenchmarkCase] = []
    for manifest_path in sorted(manifests_dir.glob("*.json")):
        name = manifest_path.name
        if name.startswith("_") or name in _SKIP_NAMES:
            continue
        # Derive dataset name: strip .manifest.json or .json suffix
        dataset_name = name
        for suffix in (".manifest.json", ".json"):
            if dataset_name.endswith(suffix):
                dataset_name = dataset_name[: -len(suffix)]
                break

        manifest = json.loads(manifest_path.read_text())
        for case_meta in manifest.get("cases", []):
            case = _rehydrate_case(case_meta, root / "external", dataset_name)
            if case is not None:
                cases.append(case)

    return cases


def _rehydrate_case(
    meta: dict,
    dataset_dir: Path,
    dataset_name: str,
) -> BenchmarkCase | None:
    """Reconstruct a BenchmarkCase from manifest metadata + truth.sarif.

    Returns None if the truth.sarif file doesn't exist (case not ingested yet).
    """
    case_id = meta.get("case_id")
    if not case_id:
        return None

    sarif_path = dataset_dir / dataset_name / case_id / "truth.sarif"
    if not sarif_path.exists():
        return None

    ground_truth = load_bentoo_sarif(sarif_path)

    from datetime import date
    from benchmarks.runner.models import Language

    published_raw = meta.get("published_date")
    published: date | None = None
    if published_raw:
        try:
            published = date.fromisoformat(published_raw)
        except ValueError:
            pass

    lang_str = meta.get("language", "")
    try:
        language = Language(lang_str)
    except ValueError:
        print(f"  WARN: unknown language {lang_str!r} for case {case_id}, skipping")
        return None

    return BenchmarkCase(
        case_id=case_id,
        project=meta.get("project", case_id),
        language=language,
        vulnerable_version=meta.get("vulnerable_version", "unknown"),
        patched_version=meta.get("patched_version", "unknown"),
        ground_truth=ground_truth,
        published_date=published,
        source_dataset=dataset_name,
    )


def main() -> None:
    """Deduplicate all ingested cases and write _deduplicated.manifest.json."""
    root = Path(__file__).parent.parent
    cases = load_all_cases(root)
    print(f"Loaded {len(cases)} cases from ingested manifests")

    deduped = dedupe(cases)
    print(f"After dedup: {len(deduped)} cases ({len(cases) - len(deduped)} duplicates removed)")

    out_path = root / "external" / "manifests" / "_deduplicated.manifest.json"
    output = {
        "generated_by": "benchmarks/scripts/apply_dedup.py",
        "total_before_dedup": len(cases),
        "total_after_dedup": len(deduped),
        "cases": [
            {
                "case_id": c.case_id,
                "project": c.project,
                "language": c.language.value,
                "vulnerable_version": c.vulnerable_version,
                "patched_version": c.patched_version,
                "published_date": c.published_date.isoformat() if c.published_date else None,
                "source_dataset": c.source_dataset,
            }
            for c in deduped
        ],
    }
    out_path.write_text(json.dumps(output, indent=2))
    print(f"Written: {out_path}")


if __name__ == "__main__":
    main()
