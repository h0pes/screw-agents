#!/usr/bin/env python3
"""Write a dry-run Phase 4 autoresearch benchmark plan.

This script does not invoke Claude and does not mutate agent YAML. It inventories
tracked benchmark manifests, current G5 gates, dataset availability, and known
gate/data mismatches so the expensive run can be reviewed first.
"""

from __future__ import annotations

import argparse
import sys
from datetime import UTC, datetime
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from screw_agents.autoresearch.planner import (  # noqa: E402
    build_run_plan,
    write_run_plan_json,
    write_run_plan_markdown,
)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Create a no-execution Phase 4 autoresearch run plan",
    )
    parser.add_argument(
        "--manifests-dir",
        type=Path,
        default=Path("benchmarks/external/manifests"),
    )
    parser.add_argument(
        "--external-dir",
        type=Path,
        default=Path("benchmarks/external"),
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=None,
        help="Output directory. Defaults to benchmarks/results/autoresearch-plan/<timestamp>.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    timestamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
    output_dir = args.output_dir or (
        Path("benchmarks") / "results" / "autoresearch-plan" / timestamp
    )
    plan = build_run_plan(
        manifests_dir=args.manifests_dir,
        external_dir=args.external_dir,
        mode="dry-run",
    )
    json_path = output_dir / "run_plan.json"
    markdown_path = output_dir / "run_plan.md"
    write_run_plan_json(json_path, plan)
    write_run_plan_markdown(markdown_path, plan)
    print(f"Wrote autoresearch run plan JSON to {json_path}")
    print(f"Wrote autoresearch run plan Markdown to {markdown_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
