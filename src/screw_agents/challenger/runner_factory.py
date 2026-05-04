"""Runner factory for configured Phase 5 challenger modes."""

from __future__ import annotations

from collections.abc import Mapping

from screw_agents.challenger.models import (
    ChallengerAssessment,
    ChallengerConfig,
    ChallengerParticipant,
    ChallengerTransportConfig,
)
from screw_agents.challenger.orchestrator import RunnerKey, participant_runner_key
from screw_agents.challenger.providers import (
    ClaudeCliProviderRunner,
    CliCommandRunner,
    CliProviderRunner,
    CodexCliProviderRunner,
    FixtureProviderRunner,
    ProviderRunner,
)


def build_runners_for_mode(
    *,
    config: ChallengerConfig,
    mode_name: str,
    command_runner: CliCommandRunner | None = None,
    timeout_seconds: int = 120,
    env: Mapping[str, str] | None = None,
    fixture_assessments: Mapping[RunnerKey, list[ChallengerAssessment]] | None = None,
    fixture_findings: Mapping[RunnerKey, list[dict]] | None = None,
) -> dict[RunnerKey, ProviderRunner]:
    """Instantiate provider runners for one configured mode.

    CLI command execution is injectable so tests and dry-runs can build live
    runner mappings without invoking external assistants.
    """
    if mode_name not in config.modes:
        raise ValueError(f"unknown challenger mode {mode_name!r}")

    mode = config.modes[mode_name]
    runners: dict[RunnerKey, ProviderRunner] = {}
    for participant in mode.participants:
        key = participant_runner_key(participant)
        provider_config = config.providers[participant.provider]
        transport = provider_config.enabled_transport(participant.transport)
        if transport.kind == "fixture":
            runners[key] = FixtureProviderRunner(
                participant=participant,
                transport=transport,
                assessments=(fixture_assessments or {}).get(key),
                findings=(fixture_findings or {}).get(key),
            )
        elif transport.kind == "cli":
            runners[key] = _cli_runner_for(
                participant=participant,
                transport=transport,
                command_runner=command_runner,
                timeout_seconds=timeout_seconds,
                env=env,
            )
        else:
            raise ValueError(
                f"transport {transport.kind!r} for provider "
                f"{participant.provider!r} is not supported by the runner factory yet"
            )

    return runners


def _cli_runner_for(
    *,
    participant: ChallengerParticipant,
    transport: ChallengerTransportConfig,
    command_runner: CliCommandRunner | None,
    timeout_seconds: int,
    env: Mapping[str, str] | None,
) -> ProviderRunner:
    if participant.provider == "claude":
        return ClaudeCliProviderRunner(
            participant=participant,
            transport=transport,
            command_runner=command_runner,
            timeout_seconds=timeout_seconds,
            env=env,
        )
    if participant.provider == "codex":
        return CodexCliProviderRunner(
            participant=participant,
            transport=transport,
            command_runner=command_runner,
            timeout_seconds=timeout_seconds,
            env=env,
        )
    return CliProviderRunner(
        participant=participant,
        transport=transport,
        command_runner=command_runner,
        timeout_seconds=timeout_seconds,
        env=env,
    )
