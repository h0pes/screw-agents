#!/usr/bin/env python3
"""Prepare a controlled Phase 4 autoresearch benchmark run.

This command writes reviewable JSON/Markdown execution plans only. It does not
invoke Claude and does not mutate agent YAML.
"""

from __future__ import annotations

import argparse
import sys
from datetime import UTC, datetime
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from screw_agents.autoresearch.controlled_run import (  # noqa: E402
    build_controlled_execution_plan,
    write_controlled_execution_plan_json,
    write_controlled_execution_plan_markdown,
)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Prepare a guarded sample autoresearch execution plan",
    )
    parser.add_argument(
        "--dry-run-plan",
        type=Path,
        required=True,
        help="Path to run_plan.json produced by plan_autoresearch.py.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=None,
        help=(
            "Output directory. Defaults to "
            "benchmarks/results/autoresearch-controlled/<timestamp>."
        ),
    )
    parser.add_argument(
        "--max-cases-per-dataset",
        type=int,
        default=1,
    )
    parser.add_argument(
        "--max-cases-per-agent",
        type=int,
        default=1,
    )
    parser.add_argument(
        "--allow-claude-invocation",
        action="store_true",
        help="Required before a controlled execution plan may become executable.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    timestamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
    output_dir = args.output_dir or (
        Path("benchmarks") / "results" / "autoresearch-controlled" / timestamp
    )
    plan = build_controlled_execution_plan(
        dry_run_plan_path=args.dry_run_plan,
        output_dir=output_dir,
        allow_claude_invocation=args.allow_claude_invocation,
        max_cases_per_dataset=args.max_cases_per_dataset,
        max_cases_per_agent=args.max_cases_per_agent,
    )
    json_path = output_dir / "controlled_run_plan.json"
    markdown_path = output_dir / "controlled_run_plan.md"
    write_controlled_execution_plan_json(json_path, plan)
    write_controlled_execution_plan_markdown(markdown_path, plan)

    print(f"Wrote controlled run plan JSON to {json_path}")
    print(f"Wrote controlled run plan Markdown to {markdown_path}")
    if not plan.execution_allowed:
        print("Controlled execution is blocked; review controlled_run_plan.md.")
        return 2
    print("Controlled execution is allowed by the plan, but this scaffold did not run it.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
