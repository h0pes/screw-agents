from __future__ import annotations

import json
import subprocess

import pytest

from screw_agents.challenger import (
    ChallengerConsent,
    ChallengerParticipant,
    ChallengerRunInput,
    ChallengerTransportConfig,
    ClaudeCliProviderRunner,
    CliCommandResult,
    CliInvocation,
    CliProviderRunner,
    CodexCliProviderRunner,
)
from screw_agents.challenger.providers import _subprocess_command_runner


def _participant(
    *,
    provider: str = "claude",
    role: str = "challenger",
) -> ChallengerParticipant:
    return ChallengerParticipant(
        provider=provider,
        transport="cli",
        role=role,  # type: ignore[arg-type]
    )


def _transport(command: str = "claude --print") -> ChallengerTransportConfig:
    return ChallengerTransportConfig(
        kind="cli",
        enabled=True,
        command=command,
        use_api_key=False,
        sends_source_externally=True,
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
        metadata={"mode": "claude_primary_codex_challenger", "primary_provider": "codex"},
    )


class RecordingCommandRunner:
    def __init__(self, result: CliCommandResult) -> None:
        self.result = result
        self.invocations: list[CliInvocation] = []

    def __call__(self, invocation: CliInvocation) -> CliCommandResult:
        self.invocations.append(invocation)
        return self.result


def test_cli_runner_invokes_command_without_shell_and_parses_assessments() -> None:
    participant = _participant(provider="codex")
    runner_backend = RecordingCommandRunner(
        CliCommandResult(
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
    )
    runner = CliProviderRunner(
        participant=participant,
        transport=_transport(command="codex exec --json"),
        command_runner=runner_backend,
        timeout_seconds=17,
        env={"OPENAI_API_KEY": "not-used-by-cli"},
    )

    result = runner.run(_run_input(participant))

    assert runner_backend.invocations[0].argv == ["codex", "exec", "--json"]
    assert "review this finding" in runner_backend.invocations[0].stdin
    assert "sqli-001" in runner_backend.invocations[0].stdin
    assert runner_backend.invocations[0].timeout_seconds == 17
    assert result.assessments[0].provider == "codex"
    assert result.assessments[0].transport == "cli"
    assert result.reconciliations[0].status == "agreed"
    assert result.provider_metadata["codex"]["returncode"] == 0


def test_cli_runner_uses_challenger_command_for_primary_participant() -> None:
    participant = _participant(provider="codex", role="primary")
    runner_backend = RecordingCommandRunner(
        CliCommandResult(returncode=0, stdout=json.dumps({"assessments": []}))
    )
    transport = ChallengerTransportConfig(
        kind="cli",
        enabled=True,
        primary_command="codex primary-command",
        challenger_command="codex challenger-command",
        use_api_key=False,
        sends_source_externally=True,
    )
    runner = CliProviderRunner(
        participant=participant,
        transport=transport,
        command_runner=runner_backend,
    )

    result = runner.run(_run_input(participant))

    assert runner_backend.invocations[0].argv == ["codex", "challenger-command"]
    assert runner.capabilities.command == "codex challenger-command"
    assert result.guardrails["command"] == "codex challenger-command"


def test_claude_cli_runner_unsets_anthropic_api_key() -> None:
    participant = _participant(provider="claude")
    runner_backend = RecordingCommandRunner(
        CliCommandResult(returncode=0, stdout=json.dumps({"assessments": []}))
    )
    runner = ClaudeCliProviderRunner(
        participant=participant,
        transport=_transport(),
        command_runner=runner_backend,
        env={
            "ANTHROPIC_API_KEY": "must-not-leak",
            "PATH": "/usr/bin",
        },
    )

    runner.run(_run_input(participant))

    assert "ANTHROPIC_API_KEY" not in runner_backend.invocations[0].env
    assert runner_backend.invocations[0].env["PATH"] == "/usr/bin"


def test_codex_cli_runner_unsets_openai_api_key() -> None:
    participant = _participant(provider="codex")
    runner_backend = RecordingCommandRunner(
        CliCommandResult(returncode=0, stdout=json.dumps({"assessments": []}))
    )
    runner = CodexCliProviderRunner(
        participant=participant,
        transport=_transport(command="codex exec --json"),
        command_runner=runner_backend,
        env={
            "OPENAI_API_KEY": "must-not-leak",
            "PATH": "/usr/bin",
        },
    )

    runner.run(_run_input(participant))

    assert runner_backend.invocations[0].argv == ["codex", "exec", "--json"]
    assert "OPENAI_API_KEY" not in runner_backend.invocations[0].env
    assert runner_backend.invocations[0].env["PATH"] == "/usr/bin"


def test_cli_preflight_keeps_source_sharing_opt_in() -> None:
    runner = CliProviderRunner(
        participant=_participant(provider="codex"),
        transport=_transport(command="codex exec"),
        command_runner=RecordingCommandRunner(CliCommandResult(returncode=0)),
    )

    report = runner.preflight(
        ChallengerConsent(
            cost_acknowledged=True,
            privacy_acknowledged=True,
            source_sharing_allowed=False,
        )
    )

    assert report.allowed is False
    assert report.blockers == ["source_sharing_not_allowed"]
    assert "would_invoke_command" in report.warnings


def test_cli_failure_returns_unsupported_assessment() -> None:
    participant = _participant(provider="codex")
    runner = CliProviderRunner(
        participant=participant,
        transport=_transport(command="codex exec"),
        command_runner=RecordingCommandRunner(
            CliCommandResult(returncode=2, stderr="not authenticated")
        ),
    )

    result = runner.run(_run_input(participant))

    assert result.assessments[0].exploitability == "unsupported"
    assert result.assessments[0].severity == "unsupported"
    assert "not authenticated" in result.assessments[0].reasoning
    assert result.guardrails["failed"] is True


def test_subprocess_command_runner_returns_timeout_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def timeout_run(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd=["codex"], timeout=7)

    monkeypatch.setattr(subprocess, "run", timeout_run)

    result = _subprocess_command_runner(
        CliInvocation(
            argv=["codex"],
            stdin="prompt",
            env={},
            timeout_seconds=7,
        )
    )

    assert result.returncode == 124
    assert "timed out after 7 seconds" in result.stderr


def test_cli_runner_rejects_non_json_output() -> None:
    participant = _participant(provider="codex")
    runner = CliProviderRunner(
        participant=participant,
        transport=_transport(command="codex exec"),
        command_runner=RecordingCommandRunner(
            CliCommandResult(returncode=0, stdout="plain text")
        ),
    )

    with pytest.raises(ValueError, match="must be JSON"):
        runner.run(_run_input(participant))


def test_cli_runner_requires_cli_transport() -> None:
    with pytest.raises(ValueError, match="requires a cli transport"):
        CliProviderRunner(
            participant=_participant(),
            transport=ChallengerTransportConfig(kind="fixture", enabled=True),
        )
