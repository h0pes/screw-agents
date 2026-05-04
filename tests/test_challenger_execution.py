from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from screw_agents.challenger.execution import run_challenger_dry_run
from screw_agents.cli import main


def _finding() -> dict:
    return {
        "id": "sqli-001",
        "agent": "sqli",
        "location": {"file": "src/app.py", "line_start": 42},
        "classification": {"cwe": "CWE-89", "severity": "high"},
    }


def _write_config(
    project_root: Path,
    *,
    transport_kind: str = "fixture",
    mode_enabled: bool = True,
) -> None:
    screw_dir = project_root / ".screw"
    screw_dir.mkdir()
    if transport_kind == "fixture":
        transport = {
            "kind": "fixture",
            "enabled": True,
            "sends_source_externally": False,
        }
    elif transport_kind == "cli":
        transport = {
            "kind": "cli",
            "enabled": True,
            "command": "claude --print",
            "use_api_key": False,
            "sends_source_externally": True,
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
                        "source_sharing_allowed": True,
                    },
                    "providers": {
                        "claude": {
                            "assistant": "claude",
                            "transports": {transport_kind: transport},
                            "default_transport": transport_kind,
                        },
                        "codex": {
                            "assistant": "codex",
                            "transports": {
                                "fixture": {
                                    "kind": "fixture",
                                    "enabled": True,
                                    "sends_source_externally": False,
                                }
                            },
                            "default_transport": "fixture",
                        },
                    },
                    "modes": {
                        "dry_run_mode": {
                            "enabled": mode_enabled,
                            "participants": [
                                {
                                    "provider": "claude",
                                    "transport": transport_kind,
                                    "role": "primary",
                                },
                                {
                                    "provider": "codex",
                                    "transport": "fixture",
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


def test_challenger_dry_run_executes_fixture_mode(tmp_path: Path) -> None:
    _write_config(tmp_path)

    result = run_challenger_dry_run(
        project_root=tmp_path,
        mode_name="dry_run_mode",
        run_id="run-001",
        session_id="session-001",
        agents=["sqli"],
        target={"type": "file", "path": "src/app.py"},
        prompt="dry-run prompt",
        findings=[_finding()],
    )

    assert result.run_id == "run-001"
    assert result.mode == "dry_run_mode"
    assert result.guardrails["allowed"] is True
    assert result.reconciliations[0].status == "unique"
    assert result.model_dump(mode="json")["run_id"] == "run-001"


def test_challenger_dry_run_refuses_live_cli_transport(tmp_path: Path) -> None:
    _write_config(tmp_path, transport_kind="cli")

    with pytest.raises(ValueError, match="only supports fixture transports"):
        run_challenger_dry_run(
            project_root=tmp_path,
            mode_name="dry_run_mode",
            run_id="run-001",
            session_id="session-001",
            agents=["sqli"],
            target={"type": "file", "path": "src/app.py"},
            prompt="dry-run prompt",
            findings=[_finding()],
        )


def test_challenger_dry_run_rejects_missing_mode(tmp_path: Path) -> None:
    _write_config(tmp_path)

    with pytest.raises(ValueError, match="unknown challenger mode"):
        run_challenger_dry_run(
            project_root=tmp_path,
            mode_name="missing",
            run_id="run-001",
            session_id="session-001",
            agents=["sqli"],
            target={"type": "file", "path": "src/app.py"},
            prompt="dry-run prompt",
            findings=[_finding()],
        )


def test_challenger_dry_run_rejects_config_with_no_enabled_modes(tmp_path: Path) -> None:
    _write_config(tmp_path, mode_enabled=False)

    with pytest.raises(ValueError, match="requires an enabled mode"):
        run_challenger_dry_run(
            project_root=tmp_path,
            mode_name="dry_run_mode",
            run_id="run-001",
            session_id="session-001",
            agents=["sqli"],
            target={"type": "file", "path": "src/app.py"},
            prompt="dry-run prompt",
            findings=[_finding()],
        )


def test_challenger_dry_run_cli_outputs_json(tmp_path: Path, capsys) -> None:
    _write_config(tmp_path)

    exit_code = main(
        [
            "challenger-dry-run",
            "dry_run_mode",
            "--project-root",
            str(tmp_path),
            "--finding-json",
            json.dumps(_finding()),
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
    assert payload["mode"] == "dry_run_mode"
    assert payload["reconciliations"][0]["status"] == "unique"


def test_challenger_dry_run_cli_refuses_live_cli_transport(
    tmp_path: Path,
    capsys,
) -> None:
    _write_config(tmp_path, transport_kind="cli")

    exit_code = main(
        [
            "challenger-dry-run",
            "dry_run_mode",
            "--project-root",
            str(tmp_path),
            "--finding-json",
            json.dumps(_finding()),
        ]
    )

    assert exit_code == 1
    captured = capsys.readouterr()
    assert "screw-agents challenger-dry-run:" in captured.err
    assert "Live provider execution is not exposed yet" in captured.err


def test_challenger_dry_run_cli_rejects_invalid_finding_json(
    tmp_path: Path,
    capsys,
) -> None:
    _write_config(tmp_path)

    exit_code = main(
        [
            "challenger-dry-run",
            "dry_run_mode",
            "--project-root",
            str(tmp_path),
            "--finding-json",
            "{not json}",
        ]
    )

    assert exit_code == 1
    captured = capsys.readouterr()
    assert "screw-agents challenger-dry-run:" in captured.err
    assert "invalid finding JSON" in captured.err
