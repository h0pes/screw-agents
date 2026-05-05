from __future__ import annotations

import json
import shlex
import sys
from pathlib import Path

import pytest
import yaml

from screw_agents.challenger.execution import run_challenger_cli
from screw_agents.challenger.providers import CliCommandResult, CliInvocation
from screw_agents.cli import main
from screw_agents.cli.challenger_run import run_challenger_run_cli


def _finding() -> dict:
    return {
        "id": "sqli-001",
        "agent": "sqli",
        "location": {"file": "src/app.py", "line_start": 42},
        "classification": {"cwe": "CWE-89", "severity": "high"},
    }


def _assessment_payload() -> dict:
    return {
        "assessments": [
            {
                "finding_id": "sqli-001",
                "exploitability": "agree",
                "severity": "agree",
                "remediation": "agree",
                "confidence": "high",
                "reasoning": "Finding matches the configured injection pattern.",
            }
        ]
    }


def _python_json_command(payload: dict) -> str:
    code = f"print({json.dumps(payload)!r})"
    return shlex.join([sys.executable, "-c", code])


def _write_config(
    project_root: Path,
    *,
    transport_kind: str = "cli",
    source_sharing_allowed: bool = True,
    command: str | None = None,
) -> None:
    screw_dir = project_root / ".screw"
    screw_dir.mkdir()
    if transport_kind == "cli":
        transport = {
            "kind": "cli",
            "enabled": True,
            "command": command or _python_json_command(_assessment_payload()),
            "use_api_key": False,
            "sends_source_externally": True,
        }
    elif transport_kind == "fixture":
        transport = {
            "kind": "fixture",
            "enabled": True,
            "sends_source_externally": False,
        }
    else:
        raise AssertionError(f"unsupported test transport {transport_kind}")

    (screw_dir / "config.yaml").write_text(
        yaml.safe_dump(
            {
                "version": 1,
                "challenger": {
                    "enabled": True,
                    "consent": {
                        "cost_acknowledged": True,
                        "privacy_acknowledged": True,
                        "source_sharing_allowed": source_sharing_allowed,
                    },
                    "providers": {
                        "claude": {
                            "assistant": "claude",
                            "transports": {transport_kind: transport},
                            "default_transport": transport_kind,
                        },
                        "codex": {
                            "assistant": "codex",
                            "transports": {transport_kind: transport},
                            "default_transport": transport_kind,
                        },
                    },
                    "modes": {
                        "cli_mode": {
                            "enabled": True,
                            "participants": [
                                {
                                    "provider": "claude",
                                    "transport": transport_kind,
                                    "role": "primary",
                                },
                                {
                                    "provider": "codex",
                                    "transport": transport_kind,
                                    "role": "challenger",
                                },
                            ],
                        }
                    },
                },
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )


def test_challenger_cli_executes_configured_cli_mode(tmp_path: Path) -> None:
    _write_config(tmp_path)
    invocations: list[CliInvocation] = []

    def command_runner(invocation: CliInvocation) -> CliCommandResult:
        invocations.append(invocation)
        return CliCommandResult(returncode=0, stdout=json.dumps(_assessment_payload()))

    result = run_challenger_cli(
        project_root=tmp_path,
        mode_name="cli_mode",
        run_id="run-001",
        session_id="session-001",
        agents=["sqli"],
        target={"type": "file", "path": "src/app.py"},
        prompt="live prompt",
        findings=[_finding()],
        command_runner=command_runner,
    )

    assert result.run_id == "run-001"
    assert result.mode == "cli_mode"
    assert result.guardrails["allowed"] is True
    assert result.reconciliations[0].status == "agreed"
    assert len(invocations) == 1
    assert "live prompt" in invocations[0].stdin
    assert "sqli-001" in invocations[0].stdin
    assert "OPENAI_API_KEY" not in invocations[0].env


def test_challenger_cli_refuses_fixture_transport(tmp_path: Path) -> None:
    _write_config(tmp_path, transport_kind="fixture")

    with pytest.raises(ValueError, match="only supports cli transports"):
        run_challenger_cli(
            project_root=tmp_path,
            mode_name="cli_mode",
            run_id="run-001",
            session_id="session-001",
            agents=["sqli"],
            target={"type": "file", "path": "src/app.py"},
            prompt="live prompt",
            findings=[_finding()],
        )


def test_challenger_cli_rejects_missing_source_sharing_consent(
    tmp_path: Path,
) -> None:
    _write_config(tmp_path, source_sharing_allowed=False)

    with pytest.raises(ValueError, match="source_sharing_allowed"):
        run_challenger_cli(
            project_root=tmp_path,
            mode_name="cli_mode",
            run_id="run-001",
            session_id="session-001",
            agents=["sqli"],
            target={"type": "file", "path": "src/app.py"},
            prompt="live prompt",
            findings=[_finding()],
        )


def test_challenger_run_cli_outputs_json_with_injected_runner(tmp_path: Path) -> None:
    _write_config(tmp_path)

    def command_runner(invocation: CliInvocation) -> CliCommandResult:
        return CliCommandResult(returncode=0, stdout=json.dumps(_assessment_payload()))

    payload = run_challenger_run_cli(
        project_root=tmp_path,
        mode_name="cli_mode",
        finding_json=json.dumps(_finding()),
        prompt="live prompt",
        run_id="run-001",
        session_id="session-001",
        target_path="src/app.py",
        timeout_seconds=120,
        command_runner=command_runner,
    )

    assert payload["run_id"] == "run-001"
    assert payload["mode"] == "cli_mode"
    assert payload["reconciliations"][0]["status"] == "agreed"


def test_challenger_run_cli_rejects_invalid_finding_json(tmp_path: Path) -> None:
    _write_config(tmp_path)

    with pytest.raises(ValueError, match="invalid finding JSON"):
        run_challenger_run_cli(
            project_root=tmp_path,
            mode_name="cli_mode",
            finding_json="{not json}",
            prompt="live prompt",
            run_id="run-001",
            session_id="session-001",
            target_path="src/app.py",
            timeout_seconds=120,
        )


def test_challenger_run_main_outputs_json_with_local_python_command(
    tmp_path: Path,
    capsys,
) -> None:
    _write_config(tmp_path)

    exit_code = main(
        [
            "challenger-run",
            "cli_mode",
            "--project-root",
            str(tmp_path),
            "--finding-json",
            json.dumps(_finding()),
            "--prompt",
            "live prompt",
            "--target-path",
            "src/app.py",
            "--run-id",
            "run-001",
            "--session-id",
            "session-001",
        ]
    )

    assert exit_code == 0
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert payload["run_id"] == "run-001"
    assert payload["mode"] == "cli_mode"
    assert payload["reconciliations"][0]["status"] == "agreed"


def test_challenger_run_main_refuses_fixture_transport(
    tmp_path: Path,
    capsys,
) -> None:
    _write_config(tmp_path, transport_kind="fixture")

    exit_code = main(
        [
            "challenger-run",
            "cli_mode",
            "--project-root",
            str(tmp_path),
            "--finding-json",
            json.dumps(_finding()),
        ]
    )

    assert exit_code == 1
    captured = capsys.readouterr()
    assert "screw-agents challenger-run:" in captured.err
    assert "only supports cli transports" in captured.err
