#!/usr/bin/env python3
"""Summarize live Claude invocation progress JSONL."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

TERMINAL_STATUSES = {"completed", "failed", "timeout"}


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Summarize invocation_progress.jsonl from controlled runs.",
    )
    parser.add_argument("progress_log", type=Path)
    parser.add_argument(
        "--stale-grace-seconds",
        type=int,
        default=30,
        help="Seconds past timeout before an active invocation is marked stale.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON.",
    )
    return parser.parse_args(argv)


def summarize_progress(
    progress_log: Path,
    *,
    stale_grace_seconds: int = 30,
) -> dict[str, Any]:
    events = _load_events(progress_log)
    by_id: dict[str, list[dict[str, Any]]] = {}
    for event in events:
        by_id.setdefault(str(event.get("invocation_id", "")), []).append(event)

    now = datetime.now(UTC)
    active: list[dict[str, Any]] = []
    stale: list[dict[str, Any]] = []
    completed = failed = timed_out = 0
    for invocation_events in by_id.values():
        latest = invocation_events[-1]
        status = str(latest.get("status", ""))
        if status == "completed":
            completed += 1
        elif status == "failed":
            failed += 1
        elif status == "timeout":
            timed_out += 1
        elif status == "started":
            elapsed = _elapsed_seconds(now, str(latest.get("timestamp", "")))
            timeout = int(latest.get("timeout_seconds") or 0)
            item = {
                **latest,
                "elapsed_since_start_seconds": elapsed,
                "stale": timeout > 0
                and elapsed > timeout + stale_grace_seconds,
            }
            if item["stale"]:
                stale.append(item)
            else:
                active.append(item)

    return {
        "progress_log": str(progress_log),
        "event_count": len(events),
        "invocation_count": len(by_id),
        "completed": completed,
        "failed": failed,
        "timeout": timed_out,
        "active": active,
        "stale": stale,
    }


def render_summary(summary: dict[str, Any]) -> str:
    lines = [
        f"Progress log: {summary['progress_log']}",
        f"Events: {summary['event_count']}",
        f"Invocations: {summary['invocation_count']}",
        (
            "Completed: "
            f"{summary['completed']} | Failed: {summary['failed']} | "
            f"Timeout: {summary['timeout']}"
        ),
        f"Active: {len(summary['active'])} | Stale: {len(summary['stale'])}",
    ]
    for label in ("active", "stale"):
        if not summary[label]:
            continue
        lines.append("")
        lines.append(label.title())
        for item in summary[label]:
            lines.append(
                "- "
                f"{item.get('case_id', '-')} "
                f"{item.get('variant', '-')} "
                f"{item.get('file', '-')} "
                f"attempt {item.get('attempt', '-')} "
                f"elapsed={item.get('elapsed_since_start_seconds', '-')}s "
                f"timeout={item.get('timeout_seconds', '-')}s"
            )
    return "\n".join(lines)


def _load_events(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    events = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        events.append(json.loads(line))
    return events


def _elapsed_seconds(now: datetime, timestamp: str) -> int:
    try:
        start = datetime.fromisoformat(timestamp)
    except ValueError:
        return 0
    if start.tzinfo is None:
        start = start.replace(tzinfo=UTC)
    return max(0, int((now - start).total_seconds()))


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    summary = summarize_progress(
        args.progress_log,
        stale_grace_seconds=args.stale_grace_seconds,
    )
    if args.json:
        print(json.dumps(summary, indent=2, sort_keys=True))
    else:
        print(render_summary(summary))
    return 2 if summary["stale"] else 0


if __name__ == "__main__":
    sys.exit(main())
