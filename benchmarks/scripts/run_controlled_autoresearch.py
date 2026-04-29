#!/usr/bin/env python3
"""Validate or execute a reviewed Phase 4 controlled-run plan."""

from __future__ import annotations

import argparse
import sys
from datetime import UTC, datetime
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from screw_agents.autoresearch.controlled_executor import (  # noqa: E402
    build_controlled_executor_report,
    write_controlled_executor_report_json,
    write_controlled_executor_report_markdown,
)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Validate or execute a reviewed controlled autoresearch plan",
    )
    parser.add_argument(
        "--controlled-plan",
        type=Path,
        required=True,
        help="Path to controlled_run_plan.json.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=None,
        help=(
            "Output directory. Defaults to "
            "benchmarks/results/autoresearch-controlled-executor/<timestamp>."
        ),
    )
    parser.add_argument(
        "--execute",
        action="store_true",
        help="Actually invoke Claude for the selected cases.",
    )
    parser.add_argument(
        "--allow-claude-invocation",
        action="store_true",
        help="Required with --execute before Claude can be invoked.",
    )
    parser.add_argument(
        "--throttle",
        type=float,
        default=2.0,
        help="Seconds between Claude calls when --execute is used.",
    )
    parser.add_argument(
        "--max-retries",
        type=int,
        default=3,
        help="Max retries per Claude call when --execute is used.",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=300,
        help="Timeout in seconds per Claude call when --execute is used.",
    )
    parser.add_argument(
        "--agent",
        action="append",
        default=[],
        help=(
            "Restrict validation/execution to a reviewed agent slice. "
            "May be supplied multiple times."
        ),
    )
    parser.add_argument(
        "--case-id",
        action="append",
        default=[],
        help=(
            "Restrict validation/execution to a reviewed case ID. "
            "May be supplied multiple times."
        ),
    )
    parser.add_argument(
        "--include-related-context",
        action="store_true",
        help=(
            "Include same-variant related truth files as prompt context for "
            "multi-file controlled cases."
        ),
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    timestamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
    output_dir = args.output_dir or (
        Path("benchmarks")
        / "results"
        / "autoresearch-controlled-executor"
        / timestamp
    )
    report = build_controlled_executor_report(
        controlled_plan_path=args.controlled_plan,
        output_dir=output_dir,
        execute=args.execute,
        allow_claude_invocation=args.allow_claude_invocation,
        throttle_delay=args.throttle,
        max_retries=args.max_retries,
        timeout=args.timeout,
        agents=args.agent,
        case_ids=args.case_id,
        include_related_context=args.include_related_context,
    )
    json_path = output_dir / "controlled_executor_report.json"
    markdown_path = output_dir / "controlled_executor_report.md"
    write_controlled_executor_report_json(json_path, report)
    write_controlled_executor_report_markdown(markdown_path, report)

    print(f"Wrote controlled executor JSON to {json_path}")
    print(f"Wrote controlled executor Markdown to {markdown_path}")
    blockers = [issue for issue in report.issues if issue.severity == "blocker"]
    if blockers:
        print("Controlled executor is blocked; review controlled_executor_report.md.")
        return 2
    if report.execution_performed:
        print(f"Controlled benchmark execution completed: {report.benchmark_run_id}")
        return 0
    print("Controlled executor validation passed; no Claude invocation was attempted.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
