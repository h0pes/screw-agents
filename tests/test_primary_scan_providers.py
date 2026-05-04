import json

import pytest

from screw_agents.challenger.models import ChallengerTransportConfig
from screw_agents.primary_scan import (
    ClaudeCliPrimaryScanRunner,
    CliPrimaryScanCommandResult,
    CliPrimaryScanInvocation,
    CliPrimaryScanRunner,
    CodexCliPrimaryScanRunner,
    FixturePrimaryScanRunner,
    PrimaryScanInput,
    PrimaryScanParticipant,
    SourceChunk,
)


def _finding_dict():
    return {
        "id": "sqli-001",
        "agent": "sqli",
        "domain": "injection-input-handling",
        "timestamp": "2026-05-04T10:00:00Z",
        "location": {"file": "src/app.py", "line_start": 12},
        "classification": {
            "cwe": "CWE-89",
            "cwe_name": "SQL Injection",
            "severity": "high",
            "confidence": "high",
        },
        "analysis": {"description": "Unsafely concatenated SQL query."},
        "remediation": {"recommendation": "Use parameterized queries."},
    }


def _participant(provider: str = "codex") -> PrimaryScanParticipant:
    return PrimaryScanParticipant(provider=provider, transport="cli")


def _transport(command: str = "codex exec --json") -> ChallengerTransportConfig:
    return ChallengerTransportConfig(
        kind="cli",
        enabled=True,
        command=command,
        use_api_key=False,
        sends_source_externally=True,
    )


def _scan_input(participant: PrimaryScanParticipant) -> PrimaryScanInput:
    return PrimaryScanInput(
        run_id="run-1",
        session_id="session-1",
        participant=participant,
        agents=["sqli"],
        target={"type": "file", "path": "src/app.py"},
        prompt="Scan for SQL injection and return JSON.",
        source_chunks=[
            SourceChunk(
                path="src/app.py",
                language="python",
                content="query = f\"select * from users where id = {user_id}\"",
            )
        ],
        output_schema={"title": "Finding"},
        metadata={"thoroughness": "standard"},
    )


class RecordingCommandRunner:
    def __init__(self, result: CliPrimaryScanCommandResult) -> None:
        self.result = result
        self.invocations: list[CliPrimaryScanInvocation] = []

    def __call__(
        self,
        invocation: CliPrimaryScanInvocation,
    ) -> CliPrimaryScanCommandResult:
        self.invocations.append(invocation)
        return self.result


def test_fixture_primary_scan_runner_returns_validated_findings():
    participant = PrimaryScanParticipant(provider="fixture", transport="fixture")
    runner = FixturePrimaryScanRunner(
        participant=participant,
        findings=[_finding_dict()],
        provider_metadata={"model": "fixture"},
    )
    scan_input = PrimaryScanInput(
        run_id="run-1",
        session_id="session-1",
        participant=participant,
        agents=["sqli"],
        target={"path": "src/app.py"},
        prompt="Scan for SQL injection.",
    )

    result = runner.run(scan_input)

    assert runner.run_count == 1
    assert result.run_id == "run-1"
    assert result.transport_kind == "fixture"
    assert result.findings[0].id == "sqli-001"
    assert result.provider_metadata == {"model": "fixture"}
    assert result.guardrails == {"fixture_runner": True}


def test_cli_primary_scan_runner_invokes_command_and_parses_findings():
    participant = _participant()
    runner_backend = RecordingCommandRunner(
        CliPrimaryScanCommandResult(
            returncode=0,
            stdout=json.dumps({"findings": [_finding_dict()]}),
        )
    )
    runner = CliPrimaryScanRunner(
        participant=participant,
        transport=_transport(),
        command_runner=runner_backend,
        timeout_seconds=19,
        env={"OPENAI_API_KEY": "not-used-by-generic-cli"},
    )

    result = runner.run(_scan_input(participant))

    invocation = runner_backend.invocations[0]
    stdin_payload = json.loads(invocation.stdin)
    assert invocation.argv == ["codex", "exec", "--json"]
    assert invocation.timeout_seconds == 19
    assert stdin_payload["prompt"] == "Scan for SQL injection and return JSON."
    assert stdin_payload["source_chunks"][0]["path"] == "src/app.py"
    assert stdin_payload["output_schema"] == {"title": "Finding"}
    assert result.findings[0].id == "sqli-001"
    assert result.provider_metadata["codex"]["returncode"] == 0
    assert result.guardrails["cli_runner"] is True


def test_claude_cli_primary_scan_runner_unsets_anthropic_api_key():
    participant = _participant(provider="claude")
    runner_backend = RecordingCommandRunner(
        CliPrimaryScanCommandResult(returncode=0, stdout=json.dumps({"findings": []}))
    )
    runner = ClaudeCliPrimaryScanRunner(
        participant=participant,
        transport=_transport(command="claude --print"),
        command_runner=runner_backend,
        env={"ANTHROPIC_API_KEY": "must-not-leak", "PATH": "/usr/bin"},
    )

    runner.run(_scan_input(participant))

    assert runner_backend.invocations[0].argv == ["claude", "--print"]
    assert "ANTHROPIC_API_KEY" not in runner_backend.invocations[0].env
    assert runner_backend.invocations[0].env["PATH"] == "/usr/bin"


def test_codex_cli_primary_scan_runner_unsets_openai_api_key():
    participant = _participant(provider="codex")
    runner_backend = RecordingCommandRunner(
        CliPrimaryScanCommandResult(returncode=0, stdout=json.dumps({"findings": []}))
    )
    runner = CodexCliPrimaryScanRunner(
        participant=participant,
        transport=_transport(),
        command_runner=runner_backend,
        env={"OPENAI_API_KEY": "must-not-leak", "PATH": "/usr/bin"},
    )

    runner.run(_scan_input(participant))

    assert runner_backend.invocations[0].argv == ["codex", "exec", "--json"]
    assert "OPENAI_API_KEY" not in runner_backend.invocations[0].env
    assert runner_backend.invocations[0].env["PATH"] == "/usr/bin"


def test_cli_primary_scan_runner_returns_failed_result_on_nonzero_exit():
    participant = _participant()
    runner = CliPrimaryScanRunner(
        participant=participant,
        transport=_transport(),
        command_runner=RecordingCommandRunner(
            CliPrimaryScanCommandResult(returncode=2, stderr="not authenticated")
        ),
    )

    result = runner.run(_scan_input(participant))

    assert result.findings == []
    assert result.guardrails["failed"] is True
    assert "not authenticated" in result.guardrails["reason"]
    assert result.provider_metadata["codex"]["returncode"] == 2


def test_cli_primary_scan_runner_rejects_non_json_output():
    participant = _participant()
    runner = CliPrimaryScanRunner(
        participant=participant,
        transport=_transport(),
        command_runner=RecordingCommandRunner(
            CliPrimaryScanCommandResult(returncode=0, stdout="plain text")
        ),
    )

    with pytest.raises(ValueError, match="must be JSON"):
        runner.run(_scan_input(participant))


def test_cli_primary_scan_runner_requires_cli_transport():
    with pytest.raises(ValueError, match="requires a cli transport"):
        CliPrimaryScanRunner(
            participant=_participant(),
            transport=ChallengerTransportConfig(kind="fixture", enabled=True),
        )
