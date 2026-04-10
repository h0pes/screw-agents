"""Command-line interface for the benchmark runner.

Subcommands:
    list                  — list datasets and agents
    validate <path>       — validate a bentoo-sarif file
    run --agent <n> --dataset <n> [opts] — run evaluation
"""
from __future__ import annotations

import argparse
import sys
from datetime import date
from pathlib import Path

from benchmarks.runner.sarif import load_bentoo_sarif


def cmd_list(args: argparse.Namespace) -> int:
    """List available datasets and agents."""
    manifests_dir = Path("benchmarks/external/manifests")
    print("Datasets:")
    if manifests_dir.exists():
        for m in sorted(manifests_dir.glob("*.manifest.json")):
            print(f"  {m.stem.replace('.manifest', '')}")
    else:
        print("  (no manifests directory found)")

    domains_dir = Path("domains")
    print("\nAgents:")
    if domains_dir.exists():
        for yaml_file in sorted(domains_dir.rglob("*.yaml")):
            print(f"  {yaml_file.stem}")
    else:
        print("  (no domains directory found)")
    return 0


def cmd_validate(args: argparse.Namespace) -> int:
    """Validate that a SARIF file parses as bentoo-sarif."""
    try:
        findings = load_bentoo_sarif(Path(args.path))
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    print(f"OK: {args.path} is a valid bentoo-sarif file with {len(findings)} findings")
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    """Run a benchmark evaluation.

    Phase 0.5 stub: reads ground truth + a synthetic agent SARIF file from
    disk and emits a Summary. Phase 1 will replace the synthetic agent source
    with live MCP agent invocations.
    """
    print(f"[stub] Would run agent={args.agent} on dataset={args.dataset}")
    print(f"  match_mode={args.match_mode}")
    print(f"  chrono_cutoff={args.chrono_cutoff}")
    print(f"  dedup={args.dedup}")
    print("Full implementation in Task 25 (smoke test).")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="benchmarks.runner",
        description="CWE-1400-native benchmark evaluator for screw-agents",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_list = sub.add_parser("list", help="list datasets and agents")
    p_list.set_defaults(func=cmd_list)

    p_validate = sub.add_parser("validate", help="validate a bentoo-sarif file")
    p_validate.add_argument("path", help="path to a .sarif file")
    p_validate.set_defaults(func=cmd_validate)

    p_run = sub.add_parser("run", help="run a benchmark evaluation")
    p_run.add_argument("--agent", required=True, help="agent name (e.g., xss)")
    p_run.add_argument("--dataset", required=True, help="dataset name")
    p_run.add_argument("--match-mode", choices=["strict", "broad"], default="broad")
    p_run.add_argument("--chrono-cutoff", type=date.fromisoformat, default=None,
                       help="YYYY-MM-DD — train/test split date")
    p_run.add_argument("--dedup", action="store_true", help="apply PrimeVul dedup")
    p_run.set_defaults(func=cmd_run)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
