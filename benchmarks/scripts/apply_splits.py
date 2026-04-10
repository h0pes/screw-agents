"""Generate chronological and cross-project splits from the deduplicated manifest.

Reads _deduplicated.manifest.json, applies:
  - Chronological split (default cutoff: 2024-01-01)
  - Cross-project splits (one holdout per project)

Writes:
  - _chrono_split.manifest.json
  - _cross_project_splits.manifest.json
"""
from __future__ import annotations

import json
from collections import defaultdict
from datetime import date
from pathlib import Path
from typing import Any


def apply_chrono_split(
    cases: list[dict[str, Any]],
    cutoff: date = date(2024, 1, 1),
) -> dict[str, Any]:
    """Split cases into train/test by published_date.

    Cases with published_date < cutoff go to train.
    Cases with published_date >= cutoff go to test.
    Cases with no date (None) default to train.

    Returns a dict with 'train_case_ids', 'test_case_ids', and 'cutoff'.
    """
    train_ids: list[str] = []
    test_ids: list[str] = []

    for case in cases:
        case_id = case["case_id"]
        published_raw = case.get("published_date")
        if published_raw is None:
            train_ids.append(case_id)
            continue
        try:
            published = date.fromisoformat(published_raw)
        except (ValueError, TypeError):
            train_ids.append(case_id)
            continue

        if published < cutoff:
            train_ids.append(case_id)
        else:
            test_ids.append(case_id)

    return {
        "cutoff": cutoff.isoformat(),
        "train_case_ids": train_ids,
        "test_case_ids": test_ids,
        "train_count": len(train_ids),
        "test_count": len(test_ids),
    }


def apply_cross_project_splits(
    cases: list[dict[str, Any]],
) -> dict[str, Any]:
    """Generate one holdout split per project.

    For each unique project, hold out all cases from that project as test;
    everything else is train.

    Returns a dict with 'total_projects', 'splits' list (one per project).
    Each split has 'holdout_project', 'train_case_ids', 'test_case_ids'.
    """
    projects: dict[str, list[str]] = defaultdict(list)
    for case in cases:
        projects[case["project"]].append(case["case_id"])

    all_ids = [c["case_id"] for c in cases]
    splits = []
    for project, project_ids in sorted(projects.items()):
        train_ids = [cid for cid in all_ids if cid not in set(project_ids)]
        splits.append({
            "holdout_project": project,
            "train_case_ids": train_ids,
            "test_case_ids": project_ids,
            "train_count": len(train_ids),
            "test_count": len(project_ids),
        })

    return {
        "total_projects": len(projects),
        "total_cases": len(all_ids),
        "splits": splits,
    }


def main() -> None:
    """Read _deduplicated.manifest.json, write chrono + cross-project splits."""
    root = Path(__file__).parent.parent
    manifests_dir = root / "external" / "manifests"
    dedup_path = manifests_dir / "_deduplicated.manifest.json"

    if not dedup_path.exists():
        print(f"ERROR: {dedup_path} not found. Run apply_dedup.py first.")
        return

    manifest = json.loads(dedup_path.read_text())
    cases = manifest.get("cases", [])
    print(f"Loaded {len(cases)} deduplicated cases")

    # Chronological split
    cutoff = date(2024, 1, 1)
    chrono = apply_chrono_split(cases, cutoff=cutoff)
    chrono["generated_by"] = "benchmarks/scripts/apply_splits.py"
    chrono["source"] = "_deduplicated.manifest.json"
    chrono_path = manifests_dir / "_chrono_split.manifest.json"
    chrono_path.write_text(json.dumps(chrono, indent=2))
    print(
        f"Chrono split written: {chrono_path} "
        f"(train={chrono['train_count']}, test={chrono['test_count']})"
    )

    # Cross-project splits
    cross = apply_cross_project_splits(cases)
    cross["generated_by"] = "benchmarks/scripts/apply_splits.py"
    cross["source"] = "_deduplicated.manifest.json"
    cross_path = manifests_dir / "_cross_project_splits.manifest.json"
    cross_path.write_text(json.dumps(cross, indent=2))
    print(
        f"Cross-project splits written: {cross_path} "
        f"({cross['total_projects']} projects)"
    )


if __name__ == "__main__":
    main()
