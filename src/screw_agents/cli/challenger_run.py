"""CLI entrypoint for opt-in Phase 5 challenger CLI runs."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from screw_agents.challenger.execution import run_challenger_cli
from screw_agents.challenger.providers import CliCommandRunner


def run_challenger_run_cli(
    *,
    project_root: Path,
    mode_name: str,
    finding_json: str,
    prompt: str,
    run_id: str,
    session_id: str,
    target_path: str,
    timeout_seconds: int,
    command_runner: CliCommandRunner | None = None,
) -> dict[str, Any]:
    """Run a configured CLI-only challenger mode and return JSON data."""
    finding = _parse_finding_json(finding_json)
    result = run_challenger_cli(
        project_root=project_root,
        mode_name=mode_name,
        run_id=run_id,
        session_id=session_id,
        agents=[_agent_from_finding(finding)],
        target={"type": "file", "path": target_path},
        prompt=prompt,
        findings=[finding],
        timeout_seconds=timeout_seconds,
        command_runner=command_runner,
    )
    return result.model_dump(mode="json")


def _parse_finding_json(raw: str) -> dict[str, Any]:
    try:
        finding = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid finding JSON: {exc}") from exc
    if not isinstance(finding, dict):
        raise ValueError("finding JSON must be an object")
    return finding


def _agent_from_finding(finding: dict[str, Any]) -> str:
    agent = finding.get("agent")
    return agent if isinstance(agent, str) and agent else "unknown"
