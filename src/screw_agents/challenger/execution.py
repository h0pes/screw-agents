"""Dry-run execution surface for Phase 5 challenger modes."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from screw_agents.challenger.models import (
    ChallengerConfig,
    ChallengerParticipant,
    ChallengerRunInput,
    ChallengerRunResult,
)
from screw_agents.challenger.orchestrator import run_challenger_mode
from screw_agents.challenger.runner_factory import build_runners_for_mode
from screw_agents.trust import load_config


def run_challenger_dry_run(
    *,
    project_root: Path,
    mode_name: str,
    run_id: str,
    session_id: str,
    agents: list[str],
    target: dict[str, Any],
    prompt: str,
    findings: list[dict[str, Any]],
) -> ChallengerRunResult:
    """Run one configured challenger mode with fixture transports only."""
    project_config = load_config(project_root)
    challenger_config = project_config.challenger
    _require_fixture_only(challenger_config, mode_name)
    participant = _first_participant(challenger_config, mode_name)

    run_input = ChallengerRunInput(
        run_id=run_id,
        session_id=session_id,
        participant=participant,
        agents=agents,
        target=target,
        prompt=prompt,
        findings=findings,
        metadata={
            "mode": mode_name,
            "dry_run": True,
        },
    )
    return run_challenger_mode(
        config=challenger_config,
        mode_name=mode_name,
        run_input=run_input,
        runners=build_runners_for_mode(
            config=challenger_config,
            mode_name=mode_name,
        ),
    )


def _require_fixture_only(config: ChallengerConfig, mode_name: str) -> None:
    if mode_name not in config.modes:
        raise ValueError(f"unknown challenger mode {mode_name!r}")

    mode = config.modes[mode_name]
    for participant in mode.participants:
        provider = config.providers[participant.provider]
        transport = provider.enabled_transport(participant.transport)
        if transport.kind != "fixture":
            raise ValueError(
                "challenger dry-run only supports fixture transports; "
                f"{participant.provider!r}/{participant.transport!r} uses "
                f"{transport.kind!r}. Live provider execution is not exposed yet."
            )


def _first_participant(
    config: ChallengerConfig,
    mode_name: str,
) -> ChallengerParticipant:
    return config.modes[mode_name].participants[0]
