#!/usr/bin/env python3
"""CLI entry point for G5-G7 gate validation.

Usage:
    uv run python benchmarks/scripts/run_gates.py --mode sample
    uv run python benchmarks/scripts/run_gates.py --mode full
    uv run python benchmarks/scripts/run_gates.py --mode full --resume <run_id>
"""
from __future__ import annotations

import argparse
import json
import logging
import sys
from collections import defaultdict
from pathlib import Path

# Ensure repo root is on sys.path so `benchmarks.*` imports resolve when
# invoked directly (uv run python benchmarks/scripts/run_gates.py).
_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from benchmarks.runner.evaluator import (
    Evaluator,
    EvalConfig,
    load_full_cases_from_manifest,
    map_case_to_agent,
)
from benchmarks.runner.gate_checker import (
    check_g5_gates,
    check_g6_rust_disclaimer,
)
from benchmarks.runner.invoker import InvokerConfig
from benchmarks.runner.models import Language
from benchmarks.runner.report import render_gate_report, render_markdown

REPO_ROOT = Path(__file__).resolve().parents[2]
MANIFESTS_DIR = REPO_ROOT / "benchmarks" / "external" / "manifests"
EXTERNAL_DIR = REPO_ROOT / "benchmarks" / "external"

SAMPLE_DATASETS = [
    "reality-check-csharp",
    "reality-check-python",
    "reality-check-java",
    "go-sec-code-mutated",
    "skf-labs-mutated",
    "crossvul",
]


def collect_cases(mode: str):
    """Load and filter benchmark cases from manifests."""
    from benchmarks.runner.models import BenchmarkCase

    datasets = SAMPLE_DATASETS if mode == "sample" else None
    all_cases = []

    for manifest_path in sorted(MANIFESTS_DIR.glob("*.manifest.json")):
        ds_name = manifest_path.stem.replace(".manifest", "")

        if ds_name.startswith("_"):
            continue

        if datasets is not None and ds_name not in datasets:
            continue

        truth_dir = EXTERNAL_DIR / ds_name
        if not truth_dir.exists():
            logging.warning("Dataset dir missing for %s — skipping. Run ingest first.", ds_name)
            continue

        cases = load_full_cases_from_manifest(manifest_path, truth_dir)
        cases = [c for c in cases if map_case_to_agent(c) is not None]
        all_cases.extend(cases)

    return all_cases


def select_sample(cases, max_per_agent: int = 5):
    """Select a representative sample: up to max_per_agent cases per agent."""
    by_agent = defaultdict(list)
    for case in cases:
        agent = map_case_to_agent(case)
        if agent:
            by_agent[agent].append(case)

    selected = []
    for agent, agent_cases in by_agent.items():
        selected.extend(agent_cases[:max_per_agent])

    return selected


def ensure_datasets_downloaded(datasets: list[str]) -> None:
    """Re-clone/download datasets that aren't on disk."""
    import importlib

    ingest_map = {
        "reality-check-csharp": "benchmarks.scripts.ingest_reality_check_csharp",
        "reality-check-python": "benchmarks.scripts.ingest_reality_check_python",
        "reality-check-java": "benchmarks.scripts.ingest_reality_check_java",
        "go-sec-code-mutated": "benchmarks.scripts.ingest_go_sec_code",
        "skf-labs-mutated": "benchmarks.scripts.ingest_skf_labs",
        "crossvul": "benchmarks.scripts.ingest_crossvul",
    }

    for ds in datasets:
        ds_dir = EXTERNAL_DIR / ds
        has_data = False
        if ds_dir.exists():
            has_data = (ds_dir / "repo").exists() or any(
                d.is_dir() for d in ds_dir.iterdir()
                if d.name not in ("truth.sarif",) and not d.name.endswith(".manifest.json")
            )

        if has_data:
            print(f"  {ds}: already present")
            continue

        module_name = ingest_map.get(ds)
        if module_name is None:
            print(f"  {ds}: no ingest module, skipping download")
            continue

        print(f"  {ds}: downloading...")
        mod = importlib.import_module(module_name)
        mod.main()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run G5-G7 detection rate validation gates",
    )
    parser.add_argument(
        "--mode", choices=["sample", "full"], default="sample",
        help="'sample' runs ~20 cases to validate pipeline; 'full' runs all filtered cases",
    )
    parser.add_argument(
        "--resume", type=str, default=None,
        help="Resume a previous run by run_id (reads cached results)",
    )
    parser.add_argument(
        "--throttle", type=float, default=2.0,
        help="Seconds between Claude calls (default: 2.0)",
    )
    parser.add_argument(
        "--max-retries", type=int, default=3,
        help="Max retries per Claude call (default: 3)",
    )
    parser.add_argument(
        "--log-level", choices=["DEBUG", "INFO", "WARNING"], default="INFO",
    )
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    print(f"\n=== Phase 1.7: G5-G7 Gate Validation ({args.mode} mode) ===\n")

    # Step 1: Ensure datasets are downloaded
    print("Step 1: Checking dataset availability...")
    datasets = SAMPLE_DATASETS if args.mode == "sample" else None
    if datasets:
        ensure_datasets_downloaded(datasets)

    # Step 2: Load and filter cases
    print("\nStep 2: Loading benchmark cases...")
    cases = collect_cases(args.mode)
    if args.mode == "sample":
        cases = select_sample(cases, max_per_agent=5)
    print(f"  {len(cases)} cases selected")

    if not cases:
        print("ERROR: No cases found. Run ingest scripts first.")
        return 1

    # Step 3: Initialize engine and evaluator
    print("\nStep 3: Initializing scan engine...")
    from screw_agents.engine import ScanEngine
    from screw_agents.registry import AgentRegistry

    registry = AgentRegistry(REPO_ROOT / "domains")
    engine = ScanEngine(registry)

    invoker_config = InvokerConfig(
        throttle_delay=args.throttle,
        max_retries=args.max_retries,
    )
    eval_config = EvalConfig(
        mode=args.mode,
        invoker_config=invoker_config,
    )
    evaluator = Evaluator(eval_config)

    if args.resume:
        evaluator.run_id = args.resume
        evaluator._run_dir = eval_config.results_dir / args.resume
        evaluator._cases_dir = evaluator._run_dir / "cases"

    # Step 4: Run evaluation
    print(f"\nStep 4: Running evaluation (run_id: {evaluator.run_id})...")
    summaries = evaluator.run(cases, engine)

    # Step 5: Check gates
    print("\nStep 5: Checking gates...")
    gate_results = check_g5_gates(summaries)
    languages_seen = {case.language for case in cases}
    g6_passed = check_g6_rust_disclaimer(list(languages_seen))

    g7_dumps: dict[str, dict] = {}
    for gr in gate_results:
        if not gr.passed and gr.note != "Not run — no matching summary found":
            g7_dumps[gr.gate_id] = {"missed": [], "false_flags": []}

    # Step 6: Generate report
    print("\nStep 6: Generating report...")
    run_dir = eval_config.results_dir / evaluator.run_id
    run_dir.mkdir(parents=True, exist_ok=True)

    for s in summaries:
        md = render_markdown(s)
        (run_dir / f"summary_{s.agent_name}_{s.dataset}.md").write_text(md)

    gate_md = render_gate_report(gate_results, g6_passed, g7_dumps)
    (run_dir / "gate_report.md").write_text(gate_md)

    gate_json = {
        "run_id": evaluator.run_id,
        "mode": args.mode,
        "g5": [
            {"gate_id": r.gate_id, "passed": r.passed,
             "actual": r.actual_value, "threshold": r.threshold,
             "agent": r.agent, "dataset": r.dataset, "note": r.note}
            for r in gate_results
        ],
        "g6_passed": g6_passed,
        "g7_dumps": g7_dumps,
    }
    (run_dir / "gate_results.json").write_text(json.dumps(gate_json, indent=2))

    # Print summary
    print(f"\n=== Results (run_id: {evaluator.run_id}) ===\n")
    passed = sum(1 for r in gate_results if r.passed)
    total = len(gate_results)
    for r in gate_results:
        status = "PASS" if r.passed else "FAIL"
        actual = f"{r.actual_value:.1%}" if r.actual_value is not None else "N/A"
        op = ">=" if r.comparison == "gte" else "<="
        print(f"  {r.gate_id}: {status}  {r.agent}/{r.dataset}  {actual} ({op} {r.threshold:.0%})")

    print(f"\nG5: {passed}/{total} gates passed")
    print(f"G6 (Rust disclaimer): {'PASS' if g6_passed else 'FAIL'}")
    print(f"G7 (Failure dumps): {len(g7_dumps)} dumps generated")
    print(f"\nFull report: {run_dir / 'gate_report.md'}")

    return 0 if (passed == total and g6_passed) else 1


if __name__ == "__main__":
    sys.exit(main())
