#!/usr/bin/env python3
"""Generate Phase 4 failure-analysis payloads from a controlled executor run."""

from __future__ import annotations

import argparse
import sys
from datetime import UTC, datetime
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from screw_agents.autoresearch.failure_payloads import (  # noqa: E402
    build_failure_payloads_from_controlled_report,
)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Generate phase4-autoresearch-failure-input/v1 payloads from a "
            "controlled executor report."
        )
    )
    parser.add_argument(
        "--controlled-executor-report",
        type=Path,
        required=True,
        help="Path to controlled_executor_report.json from an executed run.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=None,
        help=(
            "Output directory. Defaults to "
            "benchmarks/results/autoresearch-failure-inputs/<timestamp>."
        ),
    )
    parser.add_argument(
        "--domains-dir",
        type=Path,
        default=Path("domains"),
        help="Directory containing agent YAML definitions.",
    )
    parser.add_argument(
        "--external-dir",
        type=Path,
        default=None,
        help=(
            "Override benchmark external-data directory. Useful when the "
            "controlled plan used a cwd-relative benchmarks/external path from "
            "another checkout."
        ),
    )
    parser.add_argument(
        "--max-missed-per-agent",
        type=int,
        default=5,
        help="Maximum missed-vulnerability examples to include per agent payload.",
    )
    parser.add_argument(
        "--max-false-positives-per-agent",
        type=int,
        default=5,
        help="Maximum false-positive examples to include per agent payload.",
    )
    parser.add_argument(
        "--no-code-excerpts",
        action="store_true",
        help="Omit code excerpts from generated examples.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    timestamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
    output_dir = args.output_dir or (
        Path("benchmarks")
        / "results"
        / "autoresearch-failure-inputs"
        / timestamp
    )
    paths = build_failure_payloads_from_controlled_report(
        controlled_executor_report_path=args.controlled_executor_report,
        output_dir=output_dir,
        domains_dir=args.domains_dir,
        external_dir_override=args.external_dir,
        max_missed_per_agent=args.max_missed_per_agent,
        max_false_positives_per_agent=args.max_false_positives_per_agent,
        include_code_excerpt=not args.no_code_excerpts,
    )
    if not paths:
        print("No failure-input payloads generated; no concrete failures were found.")
        return 0
    for path in paths:
        print(f"Wrote failure-input payload: {path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
