"""Provider runner contracts for provider-neutral primary scanning."""

from __future__ import annotations

import json
import os
import shlex
import subprocess
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Protocol

from screw_agents.challenger.models import ChallengerTransportConfig
from screw_agents.models import Finding
from screw_agents.primary_scan.models import (
    PrimaryScanInput,
    PrimaryScanParticipant,
    PrimaryScanResult,
    parse_primary_scan_output,
)


class PrimaryScanRunner(Protocol):
    """Protocol implemented by first-pass scanner provider runners."""

    def run(self, scan_input: PrimaryScanInput) -> PrimaryScanResult:
        """Run first-pass analysis and return validated findings."""


@dataclass(frozen=True)
class CliPrimaryScanInvocation:
    """One shell-free primary scanner CLI invocation request."""

    argv: list[str]
    stdin: str
    env: Mapping[str, str]
    timeout_seconds: int


@dataclass(frozen=True)
class CliPrimaryScanCommandResult:
    """Normalized primary scanner CLI process result."""

    returncode: int
    stdout: str = ""
    stderr: str = ""


CliPrimaryScanCommandRunner = Callable[
    [CliPrimaryScanInvocation],
    CliPrimaryScanCommandResult,
]


class FixturePrimaryScanRunner:
    """Deterministic in-memory primary scanner for tests and dry runs."""

    def __init__(
        self,
        *,
        participant: PrimaryScanParticipant,
        findings: list[Finding | dict] | None = None,
        provider_metadata: dict | None = None,
        guardrails: dict | None = None,
    ) -> None:
        self._participant = participant
        self._findings = [Finding.model_validate(finding) for finding in findings or []]
        self._provider_metadata = provider_metadata or {}
        self._guardrails = guardrails or {"fixture_runner": True}
        self.run_count = 0

    def run(self, scan_input: PrimaryScanInput) -> PrimaryScanResult:
        self.run_count += 1
        return PrimaryScanResult(
            run_id=scan_input.run_id,
            provider=self._participant.provider,
            transport=self._participant.transport,
            transport_kind="fixture",
            findings=list(self._findings),
            raw_output={
                "findings": [
                    finding.model_dump(mode="json") for finding in self._findings
                ]
            },
            provider_metadata=self._provider_metadata,
            guardrails=self._guardrails,
        )


class CliPrimaryScanRunner:
    """Primary scanner runner for subscription-backed CLI transports."""

    def __init__(
        self,
        *,
        participant: PrimaryScanParticipant,
        transport: ChallengerTransportConfig,
        command_runner: CliPrimaryScanCommandRunner | None = None,
        timeout_seconds: int = 120,
        env: Mapping[str, str] | None = None,
        unset_env_vars: tuple[str, ...] = (),
    ) -> None:
        if transport.kind != "cli":
            raise ValueError("CliPrimaryScanRunner requires a cli transport")
        if not transport.command:
            raise ValueError("CliPrimaryScanRunner requires transport.command")
        if timeout_seconds < 1:
            raise ValueError("timeout_seconds must be >= 1")

        self._participant = participant
        self._transport = transport
        self._command_runner = command_runner or _subprocess_command_runner
        self._timeout_seconds = timeout_seconds
        self._base_env = dict(env) if env is not None else dict(os.environ)
        self._unset_env_vars = unset_env_vars

    def run(self, scan_input: PrimaryScanInput) -> PrimaryScanResult:
        argv = shlex.split(self._transport.command or "")
        if not argv:
            raise ValueError("transport.command must include an executable")

        invocation = CliPrimaryScanInvocation(
            argv=argv,
            stdin=_stdin_payload(scan_input),
            env=self._execution_env(),
            timeout_seconds=self._timeout_seconds,
        )
        command_result = self._command_runner(invocation)
        if command_result.returncode != 0:
            return self._failed_result(scan_input, command_result)

        result = parse_primary_scan_output(
            command_result.stdout,
            run_id=scan_input.run_id,
            participant=self._participant,
            transport_kind="cli",
        )
        result.provider_metadata.setdefault(self._participant.provider, {})
        result.provider_metadata[self._participant.provider].update(
            {
                "returncode": command_result.returncode,
                "command": self._transport.command,
            }
        )
        result.guardrails.update(
            {
                "cli_runner": True,
                "command": self._transport.command,
            }
        )
        return result

    def _execution_env(self) -> dict[str, str]:
        env = dict(self._base_env)
        for name in self._unset_env_vars:
            env.pop(name, None)
        return env

    def _failed_result(
        self,
        scan_input: PrimaryScanInput,
        command_result: CliPrimaryScanCommandResult,
    ) -> PrimaryScanResult:
        return PrimaryScanResult(
            run_id=scan_input.run_id,
            provider=self._participant.provider,
            transport=self._participant.transport,
            transport_kind="cli",
            findings=[],
            provider_metadata={
                self._participant.provider: {
                    "returncode": command_result.returncode,
                    "command": self._transport.command,
                }
            },
            guardrails={
                "cli_runner": True,
                "command": self._transport.command,
                "failed": True,
                "reason": _failure_reason(command_result),
            },
        )


class ClaudeCliPrimaryScanRunner(CliPrimaryScanRunner):
    """Claude CLI primary scanner that avoids Anthropic API-key billing by default."""

    def __init__(
        self,
        *,
        participant: PrimaryScanParticipant,
        transport: ChallengerTransportConfig,
        command_runner: CliPrimaryScanCommandRunner | None = None,
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


class CodexCliPrimaryScanRunner(CliPrimaryScanRunner):
    """Codex CLI primary scanner that avoids OpenAI API-key billing by default."""

    def __init__(
        self,
        *,
        participant: PrimaryScanParticipant,
        transport: ChallengerTransportConfig,
        command_runner: CliPrimaryScanCommandRunner | None = None,
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


def _stdin_payload(scan_input: PrimaryScanInput) -> str:
    return json.dumps(
        {
            "prompt": scan_input.prompt,
            "run_id": scan_input.run_id,
            "session_id": scan_input.session_id,
            "participant": scan_input.participant.model_dump(mode="json"),
            "agents": scan_input.agents,
            "target": scan_input.target,
            "source_chunks": [
                chunk.model_dump(mode="json") for chunk in scan_input.source_chunks
            ],
            "output_schema": scan_input.output_schema,
            "metadata": scan_input.metadata,
        },
        sort_keys=True,
        separators=(",", ":"),
    )


def _subprocess_command_runner(
    invocation: CliPrimaryScanInvocation,
) -> CliPrimaryScanCommandResult:
    completed = subprocess.run(  # noqa: S603
        invocation.argv,
        input=invocation.stdin,
        env=dict(invocation.env),
        capture_output=True,
        text=True,
        timeout=invocation.timeout_seconds,
        check=False,
    )
    return CliPrimaryScanCommandResult(
        returncode=completed.returncode,
        stdout=completed.stdout,
        stderr=completed.stderr,
    )


def _failure_reason(command_result: CliPrimaryScanCommandResult) -> str:
    stderr = command_result.stderr.strip()
    stdout = command_result.stdout.strip()
    detail = stderr or stdout or "no output"
    return f"CLI primary scanner exited with {command_result.returncode}: {detail}"
