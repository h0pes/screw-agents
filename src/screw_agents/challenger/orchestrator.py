"""Mode orchestration for Phase 5 challenger execution.

The orchestrator is intentionally provider-neutral: callers pass configured
participants and explicit runner instances. Real CLI/API/local adapters can be
registered later without changing the mode control flow.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from screw_agents.challenger.models import (
    ChallengerAssessment,
    ChallengerConfig,
    ChallengerModeConfig,
    ChallengerParticipant,
    ChallengerRunInput,
    ChallengerRunResult,
)
from screw_agents.challenger.providers import ProviderGuardrailReport, ProviderRunner
from screw_agents.challenger.reconciliation import reconcile_findings

RunnerKey = tuple[str, str]


def participant_runner_key(participant: ChallengerParticipant) -> RunnerKey:
    """Return the registry key for a participant runner."""
    return (participant.provider, participant.transport)


def participant_label(participant: ChallengerParticipant) -> str:
    """Return a stable provider/transport label for result metadata."""
    return f"{participant.provider}:{participant.transport}"


def run_challenger_mode(
    *,
    config: ChallengerConfig,
    mode_name: str,
    run_input: ChallengerRunInput,
    runners: Mapping[RunnerKey, ProviderRunner],
) -> ChallengerRunResult:
    """Run one configured Phase 5 mode through injected provider runners.

    This function performs all provider preflights before running anything. If
    any participant is blocked by cost/privacy guardrails, no runner is invoked
    and the returned result records the guardrail blockers.
    """
    if mode_name not in config.modes:
        raise ValueError(f"unknown challenger mode {mode_name!r}")

    mode = config.modes[mode_name]
    if not mode.enabled:
        raise ValueError(f"challenger mode {mode_name!r} is not enabled")

    participants = _execution_participants(mode)
    _ensure_runners(participants, runners)
    preflight_reports = _preflight(participants, config, runners)
    blocked = _blocked_labels(preflight_reports)
    if blocked:
        return _blocked_result(
            run_input=run_input,
            mode_name=mode_name,
            preflight_reports=preflight_reports,
            blocked=blocked,
        )

    assessments: list[ChallengerAssessment] = []
    provider_metadata: dict[str, Any] = {"participants": {}}
    guardrails: dict[str, Any] = {
        "mode": mode_name,
        "allowed": True,
        "preflight": _dump_reports(preflight_reports),
        "blocked": [],
    }

    primary_provider = _primary_provider(mode)
    findings = _finding_pool(run_input.findings, assessments)
    for participant in participants:
        runner = runners[participant_runner_key(participant)]
        participant_input = _participant_input(
            run_input,
            participant=participant,
            mode_name=mode_name,
            primary_provider=primary_provider,
        )
        result = runner.run(participant_input)
        assessments.extend(result.assessments)
        provider_metadata["participants"][participant_label(participant)] = (
            runner.capabilities.model_dump(mode="json")
        )
        findings = _finding_pool(run_input.findings, assessments)

    return ChallengerRunResult(
        run_id=run_input.run_id,
        mode=mode_name,
        assessments=assessments,
        reconciliations=reconcile_findings(
            findings,
            assessments,
            primary_provider=primary_provider,
        ),
        provider_metadata=provider_metadata,
        guardrails=guardrails,
    )


def _execution_participants(
    mode: ChallengerModeConfig,
) -> list[ChallengerParticipant]:
    if any(participant.role == "parallel" for participant in mode.participants):
        return list(mode.participants)
    return [
        participant
        for participant in mode.participants
        if participant.role == "challenger"
    ]


def _ensure_runners(
    participants: list[ChallengerParticipant],
    runners: Mapping[RunnerKey, ProviderRunner],
) -> None:
    for participant in participants:
        key = participant_runner_key(participant)
        if key not in runners:
            raise ValueError(
                "missing runner for participant "
                f"{participant.provider!r}/{participant.transport!r}"
            )


def _preflight(
    participants: list[ChallengerParticipant],
    config: ChallengerConfig,
    runners: Mapping[RunnerKey, ProviderRunner],
) -> dict[str, ProviderGuardrailReport]:
    reports: dict[str, ProviderGuardrailReport] = {}
    for participant in participants:
        runner = runners[participant_runner_key(participant)]
        reports[participant_label(participant)] = runner.preflight(config.consent)
    return reports


def _blocked_labels(
    reports: Mapping[str, ProviderGuardrailReport],
) -> list[str]:
    return [label for label, report in reports.items() if not report.allowed]


def _blocked_result(
    *,
    run_input: ChallengerRunInput,
    mode_name: str,
    preflight_reports: Mapping[str, ProviderGuardrailReport],
    blocked: list[str],
) -> ChallengerRunResult:
    return ChallengerRunResult(
        run_id=run_input.run_id,
        mode=mode_name,
        guardrails={
            "mode": mode_name,
            "allowed": False,
            "preflight": _dump_reports(preflight_reports),
            "blocked": blocked,
        },
    )


def _dump_reports(
    reports: Mapping[str, ProviderGuardrailReport],
) -> dict[str, dict[str, Any]]:
    return {
        label: report.model_dump(mode="json")
        for label, report in reports.items()
    }


def _participant_input(
    run_input: ChallengerRunInput,
    *,
    participant: ChallengerParticipant,
    mode_name: str,
    primary_provider: str | None,
) -> ChallengerRunInput:
    metadata = {
        **run_input.metadata,
        "mode": mode_name,
        "primary_provider": primary_provider,
    }
    return run_input.model_copy(
        update={
            "participant": participant,
            "metadata": metadata,
        }
    )


def _primary_provider(mode: ChallengerModeConfig) -> str | None:
    for participant in mode.participants:
        if participant.role == "primary":
            return participant.provider
    return None


def _finding_pool(
    input_findings: list[dict[str, Any]],
    assessments: list[ChallengerAssessment],
) -> list[dict[str, Any]]:
    findings = list(input_findings)
    for assessment in assessments:
        findings.extend(assessment.additional_findings)
    return findings
