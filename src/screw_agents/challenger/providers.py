"""Provider runner contracts and provider runners for Phase 5.

This module defines the provider boundary. Fixture runners prove orchestration
without invoking external providers; CLI runners provide the first
subscription-backed live transport path without requiring API credits.
"""

from __future__ import annotations

import json
import os
import shlex
import subprocess
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any, Protocol

from pydantic import BaseModel, ConfigDict, Field

from screw_agents.challenger.models import (
    ChallengerAssessment,
    ChallengerConsent,
    ChallengerParticipant,
    ChallengerRunInput,
    ChallengerRunResult,
    ChallengerTransportConfig,
)
from screw_agents.challenger.reconciliation import reconcile_findings


class ProviderRunnerCapabilities(BaseModel):
    """Static capability and risk metadata declared by a provider runner."""

    model_config = ConfigDict(extra="forbid")

    provider: str
    transport: str
    sends_source_externally: bool
    may_bill_api_credits: bool
    required_env_vars: list[str] = Field(default_factory=list)
    command: str | None = None
    endpoint: str | None = None
    supports_prompt_budget: bool = False
    is_fixture: bool = False


class ProviderGuardrailReport(BaseModel):
    """Pre-execution guardrail assessment for one provider run."""

    model_config = ConfigDict(extra="forbid")

    provider: str
    transport: str
    allowed: bool
    blockers: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    capabilities: ProviderRunnerCapabilities


class ProviderRunner(Protocol):
    """Protocol implemented by Phase 5 provider runners."""

    @property
    def capabilities(self) -> ProviderRunnerCapabilities:
        """Return static provider/transport metadata."""

    def preflight(self, consent: ChallengerConsent) -> ProviderGuardrailReport:
        """Return guardrail status without invoking the provider."""

    def run(self, run_input: ChallengerRunInput) -> ChallengerRunResult:
        """Run provider analysis and return structured result data."""


@dataclass(frozen=True)
class CliInvocation:
    """One shell-free CLI invocation request."""

    argv: list[str]
    stdin: str
    env: Mapping[str, str]
    timeout_seconds: int


@dataclass(frozen=True)
class CliCommandResult:
    """Normalized CLI process result."""

    returncode: int
    stdout: str = ""
    stderr: str = ""


CliCommandRunner = Callable[[CliInvocation], CliCommandResult]


def capabilities_from_transport(
    participant: ChallengerParticipant,
    transport: ChallengerTransportConfig,
    *,
    is_fixture: bool = False,
) -> ProviderRunnerCapabilities:
    """Build runner capability metadata from provider config."""
    required_env_vars: list[str] = []
    if transport.requires_api_key() and transport.api_key_env:
        required_env_vars.append(transport.api_key_env)

    return ProviderRunnerCapabilities(
        provider=participant.provider,
        transport=participant.transport,
        sends_source_externally=transport.sends_source_externally,
        may_bill_api_credits=transport.may_bill_api_credits(),
        required_env_vars=required_env_vars,
        command=transport.command_for_challenger_review(),
        endpoint=transport.endpoint,
        supports_prompt_budget=transport.max_prompt_chars is not None,
        is_fixture=is_fixture,
    )


def preflight_capabilities(
    capabilities: ProviderRunnerCapabilities,
    consent: ChallengerConsent,
) -> ProviderGuardrailReport:
    """Evaluate cost/privacy guardrails before provider execution."""
    blockers: list[str] = []
    warnings: list[str] = []

    if capabilities.may_bill_api_credits and not consent.api_billing_allowed:
        blockers.append("api_billing_not_allowed")
    if capabilities.sends_source_externally and not consent.source_sharing_allowed:
        blockers.append("source_sharing_not_allowed")
    if capabilities.may_bill_api_credits and not consent.cost_acknowledged:
        blockers.append("cost_not_acknowledged")
    if capabilities.sends_source_externally and not consent.privacy_acknowledged:
        blockers.append("privacy_not_acknowledged")
    if capabilities.required_env_vars:
        warnings.append("requires_env_vars")
    if capabilities.command:
        warnings.append("would_invoke_command")

    return ProviderGuardrailReport(
        provider=capabilities.provider,
        transport=capabilities.transport,
        allowed=not blockers,
        blockers=blockers,
        warnings=warnings,
        capabilities=capabilities,
    )


class FixtureProviderRunner:
    """Deterministic in-memory provider runner for tests and orchestration dry-runs."""

    def __init__(
        self,
        *,
        participant: ChallengerParticipant,
        transport: ChallengerTransportConfig,
        assessments: list[ChallengerAssessment] | None = None,
        findings: list[dict] | None = None,
    ) -> None:
        self._participant = participant
        self._capabilities = capabilities_from_transport(
            participant,
            transport,
            is_fixture=True,
        )
        self._assessments = assessments or []
        self._findings = findings or []
        self.run_count = 0

    @property
    def capabilities(self) -> ProviderRunnerCapabilities:
        return self._capabilities

    def preflight(self, consent: ChallengerConsent) -> ProviderGuardrailReport:
        return preflight_capabilities(self.capabilities, consent)

    def run(self, run_input: ChallengerRunInput) -> ChallengerRunResult:
        self.run_count += 1

        findings = self._findings or run_input.findings
        assessments = [
            assessment
            for assessment in self._assessments
            if assessment.provider == self._participant.provider
            and assessment.transport == self._participant.transport
            and assessment.role == self._participant.role
        ]

        return ChallengerRunResult(
            run_id=run_input.run_id,
            mode=run_input.metadata.get("mode", "fixture"),
            assessments=assessments,
            reconciliations=reconcile_findings(
                findings,
                assessments,
                primary_provider=run_input.metadata.get("primary_provider"),
            ),
            provider_metadata={
                self._participant.provider: self.capabilities.model_dump(mode="json")
            },
            guardrails={"fixture_runner": True},
        )


class CliProviderRunner:
    """Provider runner for subscription-backed CLI transports.

    The runner invokes a configured command without ``shell=True`` and sends the
    challenger prompt over stdin. The command is expected to emit JSON with an
    optional ``assessments`` list and optional ``findings`` list. Future
    provider-specific prompt envelopes can sit above this class while preserving
    the same command, guardrail, and result behavior.
    """

    def __init__(
        self,
        *,
        participant: ChallengerParticipant,
        transport: ChallengerTransportConfig,
        command_runner: CliCommandRunner | None = None,
        timeout_seconds: int = 120,
        env: Mapping[str, str] | None = None,
        unset_env_vars: tuple[str, ...] = (),
    ) -> None:
        if transport.kind != "cli":
            raise ValueError("CliProviderRunner requires a cli transport")
        command = transport.command_for_challenger_review()
        if not command:
            raise ValueError("CliProviderRunner requires a challenger command")
        if timeout_seconds < 1:
            raise ValueError("timeout_seconds must be >= 1")

        self._participant = participant
        self._transport = transport
        self._command = command
        self._command_runner = command_runner or _subprocess_command_runner
        self._timeout_seconds = timeout_seconds
        self._base_env = dict(env) if env is not None else dict(os.environ)
        self._unset_env_vars = unset_env_vars
        self._capabilities = capabilities_from_transport(participant, transport)

    @property
    def capabilities(self) -> ProviderRunnerCapabilities:
        return self._capabilities

    def preflight(self, consent: ChallengerConsent) -> ProviderGuardrailReport:
        return preflight_capabilities(self.capabilities, consent)

    def run(self, run_input: ChallengerRunInput) -> ChallengerRunResult:
        argv = shlex.split(self._command)
        if not argv:
            raise ValueError("transport command must include an executable")

        invocation = CliInvocation(
            argv=argv,
            stdin=_stdin_payload(run_input),
            env=self._execution_env(),
            timeout_seconds=self._timeout_seconds,
        )
        result = self._command_runner(invocation)
        if result.returncode != 0:
            return self._failed_result(run_input, result)

        return self._successful_result(run_input, result)

    def _execution_env(self) -> dict[str, str]:
        env = dict(self._base_env)
        for name in self._unset_env_vars:
            env.pop(name, None)
        return env

    def _successful_result(
        self,
        run_input: ChallengerRunInput,
        command_result: CliCommandResult,
    ) -> ChallengerRunResult:
        payload = _parse_cli_payload(command_result.stdout)
        assessments = [
            _assessment_from_payload(
                item,
                participant=self._participant,
            )
            for item in payload.get("assessments", [])
        ]
        findings = _payload_findings(payload) or run_input.findings
        findings_for_reconciliation = _finding_pool(findings, assessments)

        return ChallengerRunResult(
            run_id=run_input.run_id,
            mode=run_input.metadata.get("mode", "cli"),
            assessments=assessments,
            reconciliations=reconcile_findings(
                findings_for_reconciliation,
                assessments,
                primary_provider=run_input.metadata.get("primary_provider"),
            ),
            provider_metadata={
                self._participant.provider: {
                    **self.capabilities.model_dump(mode="json"),
                    "returncode": command_result.returncode,
                }
            },
            guardrails={
                "cli_runner": True,
                "command": self.capabilities.command,
            },
        )

    def _failed_result(
        self,
        run_input: ChallengerRunInput,
        command_result: CliCommandResult,
    ) -> ChallengerRunResult:
        assessment = ChallengerAssessment(
            provider=self._participant.provider,
            transport=self._participant.transport,
            role=self._participant.role,
            exploitability="unsupported",
            severity="unsupported",
            remediation="unsupported",
            confidence="low",
            reasoning=_failure_reason(command_result),
        )
        return ChallengerRunResult(
            run_id=run_input.run_id,
            mode=run_input.metadata.get("mode", "cli"),
            assessments=[assessment],
            provider_metadata={
                self._participant.provider: {
                    **self.capabilities.model_dump(mode="json"),
                    "returncode": command_result.returncode,
                }
            },
            guardrails={
                "cli_runner": True,
                "command": self.capabilities.command,
                "failed": True,
            },
        )


class ClaudeCliProviderRunner(CliProviderRunner):
    """Claude CLI runner that avoids Anthropic API-key billing by default."""

    def __init__(
        self,
        *,
        participant: ChallengerParticipant,
        transport: ChallengerTransportConfig,
        command_runner: CliCommandRunner | None = None,
        timeout_seconds: int = 120,
        env: Mapping[str, str] | None = None,
    ) -> None:
        super().__init__(
            participant=participant,
            transport=transport,
            command_runner=command_runner,
            timeout_seconds=timeout_seconds,
            env=env,
            unset_env_vars=("ANTHROPIC_API_KEY",),
        )


class CodexCliProviderRunner(CliProviderRunner):
    """Codex CLI runner that avoids OpenAI API-key billing by default."""

    def __init__(
        self,
        *,
        participant: ChallengerParticipant,
        transport: ChallengerTransportConfig,
        command_runner: CliCommandRunner | None = None,
        timeout_seconds: int = 120,
        env: Mapping[str, str] | None = None,
    ) -> None:
        super().__init__(
            participant=participant,
            transport=transport,
            command_runner=command_runner,
            timeout_seconds=timeout_seconds,
            env=env,
            unset_env_vars=("OPENAI_API_KEY",),
        )


def _subprocess_command_runner(invocation: CliInvocation) -> CliCommandResult:
    # Provider commands come from explicit challenger transport config and run
    # as argv without a shell.
    try:
        completed = subprocess.run(  # noqa: S603
            invocation.argv,
            input=invocation.stdin,
            env=dict(invocation.env),
            capture_output=True,
            text=True,
            timeout=invocation.timeout_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        return CliCommandResult(
            returncode=124,
            stdout=(exc.stdout or "") if isinstance(exc.stdout, str) else "",
            stderr=(
                f"provider CLI timed out after {invocation.timeout_seconds} seconds"
            ),
        )
    return CliCommandResult(
        returncode=completed.returncode,
        stdout=completed.stdout,
        stderr=completed.stderr,
    )


def _stdin_payload(run_input: ChallengerRunInput) -> str:
    return (
        f"{run_input.prompt}\n\n"
        "## Challenger input\n"
        "Use the following JSON payload as the authoritative scan context. "
        "Assess the supplied findings; do not search for findings elsewhere.\n"
        "```json\n"
        f"{json.dumps(_run_input_payload(run_input), sort_keys=True)}\n"
        "```"
    )


def _run_input_payload(run_input: ChallengerRunInput) -> dict[str, Any]:
    return {
        "run_id": run_input.run_id,
        "session_id": run_input.session_id,
        "participant": run_input.participant.model_dump(mode="json"),
        "agents": run_input.agents,
        "target": run_input.target,
        "findings": run_input.findings,
        "metadata": run_input.metadata,
    }


def _parse_cli_payload(stdout: str) -> dict[str, Any]:
    if not stdout.strip():
        return {}
    try:
        payload = json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise ValueError("CLI provider output must be JSON") from exc
    if not isinstance(payload, dict):
        raise ValueError("CLI provider output must be a JSON object")
    return payload


def _assessment_from_payload(
    item: Any,
    *,
    participant: ChallengerParticipant,
) -> ChallengerAssessment:
    if not isinstance(item, dict):
        raise ValueError("CLI assessment entries must be JSON objects")
    data = {
        "provider": participant.provider,
        "transport": participant.transport,
        "role": participant.role,
        **item,
    }
    return ChallengerAssessment.model_validate(data)


def _payload_findings(payload: dict[str, Any]) -> list[dict[str, Any]]:
    raw_findings = payload.get("findings", [])
    if raw_findings is None:
        return []
    if not isinstance(raw_findings, list):
        raise ValueError("CLI findings payload must be a list")
    findings: list[dict[str, Any]] = []
    for finding in raw_findings:
        if not isinstance(finding, dict):
            raise ValueError("CLI finding entries must be JSON objects")
        findings.append(finding)
    return findings


def _finding_pool(
    findings: list[dict[str, Any]],
    assessments: list[ChallengerAssessment],
) -> list[dict[str, Any]]:
    pool = list(findings)
    for assessment in assessments:
        pool.extend(assessment.additional_findings)
    return pool


def _failure_reason(command_result: CliCommandResult) -> str:
    stderr = command_result.stderr.strip()
    stdout = command_result.stdout.strip()
    detail = stderr or stdout or "no output"
    return f"CLI provider exited with {command_result.returncode}: {detail}"
