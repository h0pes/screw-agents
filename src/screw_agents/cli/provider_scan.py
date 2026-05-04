"""Implementation of ``screw-agents provider-scan``."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from screw_agents.engine import ScanEngine
from screw_agents.primary_scan.execution import run_provider_scan_workflow


def run_provider_scan_cli(
    *,
    project_root: Path,
    provider: str,
    transport: str,
    execution: str,
    agents_csv: str,
    target_json: str,
    run_id: str,
    session_id: str,
    thoroughness: str = "standard",
    timeout_seconds: int = 120,
    fixture_findings_json: str | None = None,
    finalize: bool = False,
    formats: list[str] | None = None,
) -> dict[str, Any]:
    """Run a provider-neutral primary scan and return a JSON-ready dict."""
    target = _json_object(target_json, "target-json")
    fixture_findings = (
        _json_list(fixture_findings_json, "fixture-findings-json")
        if fixture_findings_json
        else None
    )
    agents = [agent.strip() for agent in agents_csv.split(",") if agent.strip()]
    if not agents:
        raise ValueError("agents must include at least one agent name")

    return run_provider_scan_workflow(
        engine=ScanEngine.from_defaults(),
        project_root=project_root,
        provider=provider,
        transport=transport,
        execution=execution,
        run_id=run_id,
        session_id=session_id,
        agents=agents,
        target=target,
        thoroughness=thoroughness,
        timeout_seconds=timeout_seconds,
        fixture_findings=fixture_findings,
        finalize=finalize,
        formats=formats,
    )


def _json_object(raw: str, label: str) -> dict[str, Any]:
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"{label} must be valid JSON") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a JSON object")
    return value


def _json_list(raw: str, label: str) -> list[dict[str, Any]]:
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"{label} must be valid JSON") from exc
    if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
        raise ValueError(f"{label} must be a JSON array of objects")
    return value
