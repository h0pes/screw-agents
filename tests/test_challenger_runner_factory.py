from __future__ import annotations

import json

import pytest

from screw_agents.challenger import (
    ChallengerAssessment,
    ChallengerConfig,
    ChallengerConsent,
    ChallengerModeConfig,
    ChallengerParticipant,
    ChallengerProviderConfig,
    ChallengerRunInput,
    ChallengerTransportConfig,
    ClaudeCliProviderRunner,
    CliCommandResult,
    CliInvocation,
    CliProviderRunner,
    CodexCliProviderRunner,
    FixtureProviderRunner,
    build_runners_for_mode,
    participant_runner_key,
    run_challenger_mode,
)


def _participant(
    provider: str,
    role: str,
    *,
    transport: str = "cli",
) -> ChallengerParticipant:
    return ChallengerParticipant(
        provider=provider,
        transport=transport,
        role=role,  # type: ignore[arg-type]
    )


def _provider(
    provider: str,
    *,
    transport: ChallengerTransportConfig,
) -> ChallengerProviderConfig:
    return ChallengerProviderConfig(
        assistant=provider,
        transports={transport.kind: transport},
        default_transport=transport.kind,
    )


def _cli_transport(command: str) -> ChallengerTransportConfig:
    return ChallengerTransportConfig(
        kind="cli",
        enabled=True,
        command=command,
        use_api_key=False,
        sends_source_externally=True,
    )


def _fixture_transport() -> ChallengerTransportConfig:
    return ChallengerTransportConfig(
        kind="fixture",
        enabled=True,
        sends_source_externally=False,
    )


def _api_transport() -> ChallengerTransportConfig:
    return ChallengerTransportConfig(
        kind="api",
        enabled=True,
        api_key_env="OPENAI_API_KEY",
        allow_api_billing=True,
    )


def _config(
    *,
    mode_name: str,
    participants: list[ChallengerParticipant],
    providers: dict[str, ChallengerProviderConfig],
    api_billing_allowed: bool = False,
) -> ChallengerConfig:
    return ChallengerConfig(
        enabled=True,
        consent=ChallengerConsent(
            cost_acknowledged=True,
            privacy_acknowledged=True,
            api_billing_allowed=api_billing_allowed,
            source_sharing_allowed=True,
        ),
        providers=providers,
        modes={
            mode_name: ChallengerModeConfig(
                enabled=True,
                participants=participants,
            )
        },
    )


def _finding() -> dict:
    return {
        "id": "sqli-001",
        "agent": "sqli",
        "location": {"file": "src/app.py", "line_start": 42},
        "classification": {"cwe": "CWE-89", "severity": "high"},
    }


def _run_input(participant: ChallengerParticipant) -> ChallengerRunInput:
    return ChallengerRunInput(
        run_id="run-001",
        session_id="session-001",
        participant=participant,
        agents=["sqli"],
        target={"type": "file", "path": "src/app.py"},
        prompt="review this finding",
        findings=[_finding()],
    )


def _assessment(provider: str, role: str) -> ChallengerAssessment:
    return ChallengerAssessment(
        provider=provider,
        transport="fixture",
        role=role,  # type: ignore[arg-type]
        finding_id="sqli-001",
        exploitability="agree",
        severity="agree",
        remediation="agree",
        confidence="high",
        reasoning="fixture agreement",
    )


class RecordingCommandRunner:
    def __init__(self) -> None:
        self.invocations: list[CliInvocation] = []

    def __call__(self, invocation: CliInvocation) -> CliCommandResult:
        self.invocations.append(invocation)
        return CliCommandResult(
            returncode=0,
            stdout=json.dumps(
                {
                    "assessments": [
                        {
                            "finding_id": "sqli-001",
                            "exploitability": "agree",
                            "severity": "agree",
                            "remediation": "agree",
                            "confidence": "high",
                            "reasoning": "confirmed",
                        }
                    ]
                }
            ),
        )


def test_factory_selects_provider_specific_and_generic_cli_runners() -> None:
    claude = _participant("claude", "primary")
    codex = _participant("codex", "challenger")
    gemini = _participant("gemini", "challenger")
    config = _config(
        mode_name="mixed_cli",
        participants=[claude, codex, gemini],
        providers={
            "claude": _provider("claude", transport=_cli_transport("claude --print")),
            "codex": _provider("codex", transport=_cli_transport("codex exec --json")),
            "gemini": _provider("gemini", transport=_cli_transport("gemini review")),
        },
    )

    runners = build_runners_for_mode(config=config, mode_name="mixed_cli")

    assert isinstance(runners[participant_runner_key(claude)], ClaudeCliProviderRunner)
    assert isinstance(runners[participant_runner_key(codex)], CodexCliProviderRunner)
    assert isinstance(runners[participant_runner_key(gemini)], CliProviderRunner)


def test_factory_wired_cli_runners_execute_required_mode_without_live_commands() -> None:
    claude = _participant("claude", "primary")
    codex = _participant("codex", "challenger")
    command_runner = RecordingCommandRunner()
    config = _config(
        mode_name="claude_primary_codex_challenger",
        participants=[claude, codex],
        providers={
            "claude": _provider("claude", transport=_cli_transport("claude --print")),
            "codex": _provider("codex", transport=_cli_transport("codex exec --json")),
        },
    )

    runners = build_runners_for_mode(
        config=config,
        mode_name="claude_primary_codex_challenger",
        command_runner=command_runner,
        env={
            "ANTHROPIC_API_KEY": "must-not-leak",
            "OPENAI_API_KEY": "must-not-leak",
            "PATH": "/usr/bin",
        },
    )
    result = run_challenger_mode(
        config=config,
        mode_name="claude_primary_codex_challenger",
        run_input=_run_input(claude),
        runners=runners,
    )

    assert result.reconciliations[0].status == "agreed"
    assert [invocation.argv for invocation in command_runner.invocations] == [
        ["claude", "--print"],
        ["codex", "exec", "--json"],
    ]
    assert "ANTHROPIC_API_KEY" not in command_runner.invocations[0].env
    assert "OPENAI_API_KEY" not in command_runner.invocations[1].env


def test_factory_wires_codex_primary_claude_challenger_mode() -> None:
    codex = _participant("codex", "primary")
    claude = _participant("claude", "challenger")
    command_runner = RecordingCommandRunner()
    config = _config(
        mode_name="codex_primary_claude_challenger",
        participants=[codex, claude],
        providers={
            "codex": _provider("codex", transport=_cli_transport("codex exec --json")),
            "claude": _provider("claude", transport=_cli_transport("claude --print")),
        },
    )

    result = run_challenger_mode(
        config=config,
        mode_name="codex_primary_claude_challenger",
        run_input=_run_input(codex),
        runners=build_runners_for_mode(
            config=config,
            mode_name="codex_primary_claude_challenger",
            command_runner=command_runner,
        ),
    )

    assert result.reconciliations[0].primary_provider == "codex"
    assert result.reconciliations[0].participant_providers == ["codex", "claude"]
    assert len(command_runner.invocations) == 2


def test_factory_wires_parallel_mode() -> None:
    claude = _participant("claude", "parallel")
    codex = _participant("codex", "parallel")
    command_runner = RecordingCommandRunner()
    config = _config(
        mode_name="parallel",
        participants=[claude, codex],
        providers={
            "claude": _provider("claude", transport=_cli_transport("claude --print")),
            "codex": _provider("codex", transport=_cli_transport("codex exec --json")),
        },
    )

    result = run_challenger_mode(
        config=config,
        mode_name="parallel",
        run_input=_run_input(claude),
        runners=build_runners_for_mode(
            config=config,
            mode_name="parallel",
            command_runner=command_runner,
        ),
    )

    assert result.reconciliations[0].primary_provider is None
    assert result.reconciliations[0].participant_providers == ["claude", "codex"]
    assert len(command_runner.invocations) == 2


def test_factory_builds_fixture_runners_with_fixture_payloads() -> None:
    claude = _participant("claude", "primary", transport="fixture")
    codex = _participant("codex", "challenger", transport="fixture")
    codex_key = participant_runner_key(codex)
    config = _config(
        mode_name="fixture_mode",
        participants=[claude, codex],
        providers={
            "claude": _provider("claude", transport=_fixture_transport()),
            "codex": _provider("codex", transport=_fixture_transport()),
        },
    )

    runners = build_runners_for_mode(
        config=config,
        mode_name="fixture_mode",
        fixture_assessments={codex_key: [_assessment("codex", "challenger")]},
    )
    result = run_challenger_mode(
        config=config,
        mode_name="fixture_mode",
        run_input=_run_input(claude),
        runners=runners,
    )

    assert isinstance(runners[codex_key], FixtureProviderRunner)
    assert result.reconciliations[0].status == "agreed"


def test_factory_rejects_api_transport_until_adapter_exists() -> None:
    codex = _participant("codex", "challenger", transport="api")
    config = _config(
        mode_name="api_mode",
        participants=[_participant("claude", "primary"), codex],
        providers={
            "claude": _provider("claude", transport=_cli_transport("claude --print")),
            "codex": _provider("codex", transport=_api_transport()),
        },
        api_billing_allowed=True,
    )

    with pytest.raises(ValueError, match="not supported"):
        build_runners_for_mode(config=config, mode_name="api_mode")
