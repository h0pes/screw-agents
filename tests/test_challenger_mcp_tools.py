from __future__ import annotations

import json
import shlex
import sys
from pathlib import Path

import pytest
import yaml

from screw_agents.server import _dispatch_tool, create_server


@pytest.fixture
def engine(domains_dir):
    _, engine = create_server(domains_dir)
    return engine


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
    transport_kind: str,
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
            "command": _python_json_command(_assessment_payload()),
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
                        "source_sharing_allowed": transport_kind == "cli",
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
                        "challenger_mode": {
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


def _tool_args(project_root: Path) -> dict:
    return {
        "project_root": str(project_root),
        "mode": "challenger_mode",
        "run_id": "run-001",
        "session_id": "session-001",
        "agents": ["sqli"],
        "target": {"type": "file", "path": "src/app.py"},
        "prompt": "Review this finding.",
        "findings": [_finding()],
    }


def test_challenger_mcp_tools_are_registered(engine) -> None:
    tools = engine.list_tool_definitions()
    names = {tool["name"] for tool in tools}

    assert "challenger_dry_run" in names
    assert "challenger_run" in names
    challenger_run = next(tool for tool in tools if tool["name"] == "challenger_run")
    props = challenger_run["input_schema"]["properties"]
    assert "timeout_seconds" in props


def test_dispatch_challenger_dry_run_fixture_mode(engine, tmp_path: Path) -> None:
    _write_config(tmp_path, transport_kind="fixture")

    result = _dispatch_tool(engine, "challenger_dry_run", _tool_args(tmp_path))

    assert result["run_id"] == "run-001"
    assert result["mode"] == "challenger_mode"
    assert result["guardrails"]["allowed"] is True
    assert result["reconciliations"][0]["status"] == "unique"


def test_dispatch_challenger_dry_run_refuses_cli_mode(
    engine,
    tmp_path: Path,
) -> None:
    _write_config(tmp_path, transport_kind="cli")

    with pytest.raises(ValueError, match="only supports fixture transports"):
        _dispatch_tool(engine, "challenger_dry_run", _tool_args(tmp_path))


def test_dispatch_challenger_run_cli_mode(engine, tmp_path: Path) -> None:
    _write_config(tmp_path, transport_kind="cli")

    result = _dispatch_tool(
        engine,
        "challenger_run",
        {
            **_tool_args(tmp_path),
            "timeout_seconds": 10,
        },
    )

    assert result["run_id"] == "run-001"
    assert result["mode"] == "challenger_mode"
    assert result["guardrails"]["allowed"] is True
    assert result["reconciliations"][0]["status"] == "agreed"


def test_dispatch_challenger_run_refuses_fixture_mode(
    engine,
    tmp_path: Path,
) -> None:
    _write_config(tmp_path, transport_kind="fixture")

    with pytest.raises(ValueError, match="only supports cli transports"):
        _dispatch_tool(engine, "challenger_run", _tool_args(tmp_path))
