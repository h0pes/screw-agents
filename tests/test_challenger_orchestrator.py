from __future__ import annotations

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
    FixtureProviderRunner,
    participant_runner_key,
    run_challenger_mode,
)


def _participant(
    provider: str,
    role: str,
    *,
    transport: str = "fixture",
) -> ChallengerParticipant:
    return ChallengerParticipant(
        provider=provider,
        transport=transport,
        role=role,  # type: ignore[arg-type]
    )


def _finding(finding_id: str = "sqli-001") -> dict:
    return {
        "id": finding_id,
        "agent": "sqli",
        "location": {"file": "src/app.py", "line_start": 42},
        "classification": {"cwe": "CWE-89", "severity": "high"},
    }


def _assessment(
    provider: str,
    role: str,
    *,
    finding_id: str = "sqli-001",
    exploitability: str = "agree",
    severity: str = "agree",
    remediation: str = "agree",
) -> ChallengerAssessment:
    return ChallengerAssessment(
        provider=provider,
        transport="fixture",
        role=role,  # type: ignore[arg-type]
        finding_id=finding_id,
        exploitability=exploitability,  # type: ignore[arg-type]
        severity=severity,  # type: ignore[arg-type]
        remediation=remediation,  # type: ignore[arg-type]
        confidence="high",
        reasoning=f"{provider} fixture assessment",
    )


def _transport(*, sends_source_externally: bool = False) -> ChallengerTransportConfig:
    return ChallengerTransportConfig(
        kind="fixture",
        enabled=True,
        sends_source_externally=sends_source_externally,
    )


def _config(
    *,
    mode_name: str,
    participants: list[ChallengerParticipant],
    source_sharing_allowed: bool = True,
    enabled: bool = True,
) -> ChallengerConfig:
    providers = {
        participant.provider: ChallengerProviderConfig(
            assistant=participant.provider,
            transports={"fixture": _transport()},
            default_transport="fixture",
        )
        for participant in participants
    }
    return ChallengerConfig(
        enabled=enabled,
        consent=ChallengerConsent(
            cost_acknowledged=True,
            privacy_acknowledged=True,
            source_sharing_allowed=source_sharing_allowed,
        ),
        providers=providers,
        modes={
            mode_name: ChallengerModeConfig(
                enabled=True,
                participants=participants,
            )
        },
    )


def _run_input(participant: ChallengerParticipant) -> ChallengerRunInput:
    return ChallengerRunInput(
        run_id="run-001",
        session_id="session-001",
        participant=participant,
        agents=["sqli"],
        target={"type": "file", "path": "src/app.py"},
        prompt="fixture prompt",
        findings=[_finding()],
    )


def _runners(
    participants: list[ChallengerParticipant],
    *,
    assessments: list[ChallengerAssessment],
    sends_source_externally: bool = False,
) -> dict[tuple[str, str], FixtureProviderRunner]:
    return {
        participant_runner_key(participant): FixtureProviderRunner(
            participant=participant,
            transport=_transport(sends_source_externally=sends_source_externally),
            assessments=assessments,
        )
        for participant in participants
    }


def test_claude_primary_codex_challenger_mode_reconciles() -> None:
    claude = _participant("claude", "primary")
    codex = _participant("codex", "challenger")
    participants = [claude, codex]
    runners = _runners(
        participants,
        assessments=[_assessment("codex", "challenger")],
    )

    result = run_challenger_mode(
        config=_config(
            mode_name="claude_primary_codex_challenger",
            participants=participants,
        ),
        mode_name="claude_primary_codex_challenger",
        run_input=_run_input(claude),
        runners=runners,
    )

    assert result.mode == "claude_primary_codex_challenger"
    assert result.guardrails["allowed"] is True
    assert result.reconciliations[0].primary_provider == "claude"
    assert result.reconciliations[0].participant_providers == ["claude", "codex"]
    assert result.reconciliations[0].status == "agreed"
    assert runners[participant_runner_key(claude)].run_count == 1
    assert runners[participant_runner_key(codex)].run_count == 1


def test_codex_primary_claude_challenger_mode_reconciles() -> None:
    codex = _participant("codex", "primary")
    claude = _participant("claude", "challenger")
    participants = [codex, claude]
    runners = _runners(
        participants,
        assessments=[_assessment("claude", "challenger", severity="disagree")],
    )

    result = run_challenger_mode(
        config=_config(
            mode_name="codex_primary_claude_challenger",
            participants=participants,
        ),
        mode_name="codex_primary_claude_challenger",
        run_input=_run_input(codex),
        runners=runners,
    )

    assert result.reconciliations[0].primary_provider == "codex"
    assert result.reconciliations[0].participant_providers == ["codex", "claude"]
    assert result.reconciliations[0].status == "disputed"


def test_parallel_mode_runs_independent_participants() -> None:
    claude = _participant("claude", "parallel")
    codex = _participant("codex", "parallel")
    participants = [claude, codex]
    runners = _runners(
        participants,
        assessments=[
            _assessment("claude", "parallel"),
            _assessment("codex", "parallel"),
        ],
    )

    result = run_challenger_mode(
        config=_config(mode_name="parallel_review", participants=participants),
        mode_name="parallel_review",
        run_input=_run_input(claude),
        runners=runners,
    )

    assert result.reconciliations[0].primary_provider is None
    assert result.reconciliations[0].participant_providers == ["claude", "codex"]
    assert result.reconciliations[0].status == "agreed"
    assert result.provider_metadata["participants"]["claude:fixture"]["is_fixture"]
    assert result.provider_metadata["participants"]["codex:fixture"]["is_fixture"]


def test_guardrail_block_prevents_all_runner_execution() -> None:
    claude = _participant("claude", "primary")
    codex = _participant("codex", "challenger")
    participants = [claude, codex]
    runners = _runners(
        participants,
        assessments=[_assessment("codex", "challenger")],
        sends_source_externally=True,
    )

    result = run_challenger_mode(
        config=_config(
            mode_name="blocked_mode",
            participants=participants,
            source_sharing_allowed=False,
            enabled=False,
        ),
        mode_name="blocked_mode",
        run_input=_run_input(claude),
        runners=runners,
    )

    assert result.guardrails["allowed"] is False
    assert result.guardrails["blocked"] == ["claude:fixture", "codex:fixture"]
    assert result.assessments == []
    assert result.reconciliations == []
    assert runners[participant_runner_key(claude)].run_count == 0
    assert runners[participant_runner_key(codex)].run_count == 0


def test_missing_runner_is_rejected_before_execution() -> None:
    claude = _participant("claude", "primary")
    codex = _participant("codex", "challenger")
    participants = [claude, codex]
    runners = _runners([claude], assessments=[])

    with pytest.raises(ValueError, match="missing runner"):
        run_challenger_mode(
            config=_config(mode_name="missing_runner", participants=participants),
            mode_name="missing_runner",
            run_input=_run_input(claude),
            runners=runners,
        )

    assert runners[participant_runner_key(claude)].run_count == 0


def test_disabled_mode_is_rejected() -> None:
    claude = _participant("claude", "primary")
    codex = _participant("codex", "challenger")
    participants = [claude, codex]
    config = _config(mode_name="disabled_mode", participants=participants, enabled=False)
    config.modes["disabled_mode"].enabled = False

    with pytest.raises(ValueError, match="not enabled"):
        run_challenger_mode(
            config=config,
            mode_name="disabled_mode",
            run_input=_run_input(claude),
            runners=_runners(participants, assessments=[]),
        )
