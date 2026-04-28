#!/usr/bin/env python3
"""Write a no-execution Phase 4 autoresearch dataset readiness report."""

from __future__ import annotations

import argparse
import sys
from datetime import UTC, datetime
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from screw_agents.autoresearch.planner import build_run_plan, plan_to_dict  # noqa: E402
from screw_agents.autoresearch.readiness import (  # noqa: E402
    build_readiness_report,
    load_dry_run_plan,
    write_readiness_json,
    write_readiness_markdown,
)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Create a no-execution Phase 4 autoresearch readiness report",
    )
    parser.add_argument(
        "--dry-run-plan",
        type=Path,
        default=None,
        help="Optional run_plan.json produced by plan_autoresearch.py.",
    )
    parser.add_argument(
        "--manifests-dir",
        type=Path,
        default=Path("benchmarks/external/manifests"),
        help="Used when --dry-run-plan is omitted.",
    )
    parser.add_argument(
        "--external-dir",
        type=Path,
        default=Path("benchmarks/external"),
        help="Used when --dry-run-plan is omitted.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=None,
        help=(
            "Output directory. Defaults to "
            "benchmarks/results/autoresearch-readiness/<timestamp>."
        ),
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    timestamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
    output_dir = args.output_dir or (
        Path("benchmarks") / "results" / "autoresearch-readiness" / timestamp
    )

    if args.dry_run_plan is None:
        dry_run_plan = plan_to_dict(
            build_run_plan(
                manifests_dir=args.manifests_dir,
                external_dir=args.external_dir,
                mode="dry-run",
            )
        )
    else:
        dry_run_plan = load_dry_run_plan(args.dry_run_plan)

    report = build_readiness_report(dry_run_plan)
    json_path = output_dir / "readiness_report.json"
    markdown_path = output_dir / "readiness_report.md"
    write_readiness_json(json_path, report)
    write_readiness_markdown(markdown_path, report)

    print(f"Wrote autoresearch readiness JSON to {json_path}")
    print(f"Wrote autoresearch readiness Markdown to {markdown_path}")
    if report.blocker_count:
        print("Autoresearch readiness is blocked; review readiness_report.md.")
        return 2
    print("Autoresearch readiness has no active controlled-run blockers.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
