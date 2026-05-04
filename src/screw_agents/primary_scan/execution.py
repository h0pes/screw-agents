"""Execution surfaces for provider-neutral primary scans."""

from __future__ import annotations

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
