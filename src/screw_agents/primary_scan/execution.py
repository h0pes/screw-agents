"""Execution surfaces for provider-neutral primary scans."""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from screw_agents.challenger.models import ChallengerConfig, ChallengerTransportConfig
from screw_agents.engine import ScanEngine
from screw_agents.primary_scan.models import PrimaryScanParticipant, PrimaryScanResult
from screw_agents.primary_scan.providers import (
    ClaudeCliPrimaryScanRunner,
    CliPrimaryScanCommandRunner,
    CliPrimaryScanRunner,
    CodexCliPrimaryScanRunner,
    FixturePrimaryScanRunner,
)
from screw_agents.trust import load_config


def run_provider_scan(
    *,
    engine: ScanEngine,
    project_root: Path,
    provider: str,
    transport: str,
    execution: str,
    run_id: str,
    session_id: str,
    agents: list[str],
    target: dict[str, Any],
    thoroughness: str = "standard",
    timeout_seconds: int = 120,
    fixture_findings: list[dict[str, Any]] | None = None,
    command_runner: CliPrimaryScanCommandRunner | None = None,
    env: Mapping[str, str] | None = None,
) -> PrimaryScanResult:
    """Run one provider-neutral primary scan through an exposed execution path."""
    if execution not in {"fixture", "cli"}:
        raise ValueError("execution must be one of: 'fixture', 'cli'")

    config = load_config(project_root).challenger
    transport_config = _enabled_transport(config, provider, transport)
    if transport_config.kind != execution:
        raise ValueError(
            f"execution {execution!r} requires a {execution!r} transport; "
            f"{provider!r}/{transport!r} is {transport_config.kind!r}"
        )

    participant = PrimaryScanParticipant(provider=provider, transport=transport)
    scan_input = engine.assemble_primary_scan_input(
        run_id=run_id,
        session_id=session_id,
        participant=participant,
        agents=agents,
        target=target,
        thoroughness=thoroughness,
        project_root=project_root,
    )

    if execution == "fixture":
        runner = FixturePrimaryScanRunner(
            participant=participant,
            findings=fixture_findings,
            provider_metadata={
                provider: {
                    "transport": transport,
                    "execution": "fixture",
                }
            },
        )
        return runner.run(scan_input)

    _require_cli_consent(config, provider, transport, transport_config)
    runner = _cli_runner_for(
        participant=participant,
        transport=transport_config,
        command_runner=command_runner,
        timeout_seconds=timeout_seconds,
        env=env,
    )
    return runner.run(scan_input)


def run_provider_scan_workflow(
    *,
    engine: ScanEngine,
    project_root: Path,
    provider: str,
    transport: str,
    execution: str,
    run_id: str,
    session_id: str,
    agents: list[str],
    target: dict[str, Any],
    thoroughness: str = "standard",
    timeout_seconds: int = 120,
    fixture_findings: list[dict[str, Any]] | None = None,
    command_runner: CliPrimaryScanCommandRunner | None = None,
    env: Mapping[str, str] | None = None,
    finalize: bool = False,
    formats: list[str] | None = None,
) -> dict[str, Any]:
    """Run provider scan and optionally finalize findings into reports."""
    scan_result = run_provider_scan(
        engine=engine,
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
        command_runner=command_runner,
        env=env,
    )
    result = scan_result.model_dump(mode="json")
    if not finalize:
        return result

    findings = [finding.model_dump(mode="json") for finding in scan_result.findings]
    accumulate_result = engine.accumulate_findings(
        project_root=project_root,
        findings_chunk=findings,
        session_id=session_id,
    )
    finalize_result = engine.finalize_scan_results(
        project_root=project_root,
        session_id=accumulate_result["session_id"],
        agent_names=agents,
        scan_metadata={
            "target": target,
            "provider_scan": {
                "provider": provider,
                "transport": transport,
                "execution": execution,
                "run_id": run_id,
            },
        },
        formats=formats,
    )
    return {
        "primary_scan_result": result,
        "accumulate_result": accumulate_result,
        "finalize_result": finalize_result,
    }


def run_composed_provider_scan_workflow(
    *,
    engine: ScanEngine,
    project_root: Path,
    primary_provider: str,
    primary_transport: str,
    primary_execution: str,
    challenger_mode: str,
    challenger_execution: str,
    run_id: str,
    session_id: str,
    agents: list[str],
    target: dict[str, Any],
    thoroughness: str = "standard",
    primary_timeout_seconds: int = 120,
    challenger_timeout_seconds: int = 120,
    fixture_findings: list[dict[str, Any]] | None = None,
    primary_command_runner: CliPrimaryScanCommandRunner | None = None,
    env: Mapping[str, str] | None = None,
    formats: list[str] | None = None,
    challenger_prompt: str | None = None,
) -> dict[str, Any]:
    """Run provider-neutral primary scanning and configured challenger review.

    This is the backend composition for Phase 5 primary/challenger modes:
    one configured provider acts as first-pass scanner from YAML agent
    knowledge, the findings are accumulated/finalized through the normal
    reporting path, and finalization attaches a configured challenger mode.
    """
    scan_result = run_provider_scan(
        engine=engine,
        project_root=project_root,
        provider=primary_provider,
        transport=primary_transport,
        execution=primary_execution,
        run_id=run_id,
        session_id=session_id,
        agents=agents,
        target=target,
        thoroughness=thoroughness,
        timeout_seconds=primary_timeout_seconds,
        fixture_findings=fixture_findings,
        command_runner=primary_command_runner,
        env=env,
    )
    findings = [finding.model_dump(mode="json") for finding in scan_result.findings]
    accumulate_result = engine.accumulate_findings(
        project_root=project_root,
        findings_chunk=findings,
        session_id=session_id,
    )
    finalize_result = engine.finalize_scan_results(
        project_root=project_root,
        session_id=accumulate_result["session_id"],
        agent_names=agents,
        scan_metadata={
            "target": target,
            "provider_scan": {
                "provider": primary_provider,
                "transport": primary_transport,
                "execution": primary_execution,
                "run_id": run_id,
            },
            "phase5_mode": {
                "type": "primary_challenger",
                "challenger_mode": challenger_mode,
                "challenger_execution": challenger_execution,
            },
        },
        formats=formats,
        challenger_mode=challenger_mode,
        challenger_execution=challenger_execution,
        challenger_prompt=challenger_prompt,
        challenger_target=target,
        challenger_timeout_seconds=challenger_timeout_seconds,
    )
    return {
        "mode": {
            "type": "primary_challenger",
            "primary": {
                "provider": primary_provider,
                "transport": primary_transport,
                "execution": primary_execution,
            },
            "challenger": {
                "mode": challenger_mode,
                "execution": challenger_execution,
            },
        },
        "primary_scan_result": scan_result.model_dump(mode="json"),
        "accumulate_result": accumulate_result,
        "finalize_result": finalize_result,
        "challenger_results": _challenger_results_from_finalize_result(
            finalize_result
        ),
    }


def _enabled_transport(
    config: ChallengerConfig,
    provider: str,
    transport: str,
) -> ChallengerTransportConfig:
    if provider not in config.providers:
        raise ValueError(f"unknown provider {provider!r}")
    return config.providers[provider].enabled_transport(transport)


def _require_cli_consent(
    config: ChallengerConfig,
    provider: str,
    transport: str,
    transport_config: ChallengerTransportConfig,
) -> None:
    consent = config.consent
    if transport_config.sends_source_externally:
        if not consent.privacy_acknowledged:
            raise ValueError("CLI provider execution requires privacy_acknowledged=true")
        if not consent.source_sharing_allowed:
            raise ValueError(
                "CLI provider execution requires source_sharing_allowed=true"
            )
    if transport_config.may_bill_api_credits():
        if not consent.cost_acknowledged:
            raise ValueError("API-billing transports require cost_acknowledged=true")
        if not consent.api_billing_allowed:
            raise ValueError("API-billing transports require api_billing_allowed=true")
    if transport_config.kind != "cli":
        raise ValueError(
            "provider primary scan live execution only supports cli transports; "
            f"{provider!r}/{transport!r} uses {transport_config.kind!r}. "
            "Fixture, API, and local execution are separate surfaces."
        )


def _cli_runner_for(
    *,
    participant: PrimaryScanParticipant,
    transport: ChallengerTransportConfig,
    command_runner: CliPrimaryScanCommandRunner | None,
    timeout_seconds: int,
    env: Mapping[str, str] | None,
) -> CliPrimaryScanRunner:
    if participant.provider == "claude":
        return ClaudeCliPrimaryScanRunner(
            participant=participant,
            transport=transport,
            command_runner=command_runner,
            timeout_seconds=timeout_seconds,
            env=env,
        )
    if participant.provider == "codex":
        return CodexCliPrimaryScanRunner(
            participant=participant,
            transport=transport,
            command_runner=command_runner,
            timeout_seconds=timeout_seconds,
            env=env,
        )
    return CliPrimaryScanRunner(
        participant=participant,
        transport=transport,
        command_runner=command_runner,
        timeout_seconds=timeout_seconds,
        env=env,
    )


def _challenger_results_from_finalize_result(
    finalize_result: dict[str, Any],
) -> list[dict[str, Any]]:
    json_path = finalize_result.get("files_written", {}).get("json")
    if not json_path:
        return []
    try:
        payload = json.loads(Path(json_path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    challenger_results = payload.get("challenger_results", [])
    if isinstance(challenger_results, list):
        return [
            item for item in challenger_results
            if isinstance(item, dict)
        ]
    return []
