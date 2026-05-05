from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from screw_agents.cli import main
from screw_agents.engine import ScanEngine
from screw_agents.primary_scan.execution import (
    _challenger_results_from_finalize_result,
    run_composed_provider_scan_workflow,
    run_parallel_provider_scan_workflow,
    run_provider_scan,
    run_provider_scan_workflow,
)
from screw_agents.primary_scan.providers import (
    CliPrimaryScanCommandResult,
    CliPrimaryScanInvocation,
)
from screw_agents.registry import AgentRegistry
from screw_agents.server import _dispatch_tool


def _finding_dict() -> dict:
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


def _finding_variant(
    *,
    finding_id: str,
    line_start: int = 12,
    severity: str = "high",
) -> dict:
    finding = json.loads(json.dumps(_finding_dict()))
    finding["id"] = finding_id
    finding["location"]["line_start"] = line_start
    finding["classification"]["severity"] = severity
    return finding


def _write_config(project_root: Path, *, transport_kind: str = "fixture") -> None:
    screw_dir = project_root / ".screw"
    screw_dir.mkdir()
    transport: dict
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
            "command": "codex exec --json",
            "use_api_key": False,
            "sends_source_externally": True,
        }
    elif transport_kind == "api":
        transport = {
            "kind": "api",
            "enabled": True,
            "api_key_env": "OPENAI_API_KEY",
            "allow_api_billing": True,
            "sends_source_externally": True,
        }
    else:
        raise AssertionError(f"unsupported transport {transport_kind}")

    (screw_dir / "config.yaml").write_text(
        yaml.safe_dump(
            {
                "version": 1,
                "challenger": {
                    "enabled": False,
                    "consent": {
                        "cost_acknowledged": True,
                        "privacy_acknowledged": True,
                        "source_sharing_allowed": True,
                        "api_billing_allowed": transport_kind == "api",
                    },
                    "providers": {
                        "codex": {
                            "assistant": "codex",
                            "transports": {transport_kind: transport},
                            "default_transport": transport_kind,
                        }
                    },
                },
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )


def _write_composed_config(
    project_root: Path,
    *,
    primary_provider: str,
    challenger_provider: str,
    mode_name: str = "primary_challenger",
) -> None:
    screw_dir = project_root / ".screw"
    screw_dir.mkdir()
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
                            "transports": {
                                "fixture": {
                                    "kind": "fixture",
                                    "enabled": True,
                                    "sends_source_externally": False,
                                }
                            },
                            "default_transport": "fixture",
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
                        mode_name: {
                            "enabled": True,
                            "participants": [
                                {
                                    "provider": primary_provider,
                                    "transport": "fixture",
                                    "role": "primary",
                                },
                                {
                                    "provider": challenger_provider,
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


def _engine() -> ScanEngine:
    domains_dir = Path(__file__).parents[1] / "domains"
    return ScanEngine(AgentRegistry(domains_dir))


def _target(tmp_path: Path) -> dict:
    path = tmp_path / "app.py"
    path.write_text(
        "import sqlite3\n"
        "query = f\"select * from users where id = {user_id}\"\n",
        encoding="utf-8",
    )
    return {"type": "file", "path": str(path)}


class RecordingCommandRunner:
    def __init__(self) -> None:
        self.invocations: list[CliPrimaryScanInvocation] = []

    def __call__(
        self,
        invocation: CliPrimaryScanInvocation,
    ) -> CliPrimaryScanCommandResult:
        self.invocations.append(invocation)
        return CliPrimaryScanCommandResult(
            returncode=0,
            stdout=json.dumps({"findings": [_finding_dict()]}),
        )


def test_run_provider_scan_fixture_returns_validated_result(tmp_path: Path) -> None:
    _write_config(tmp_path, transport_kind="fixture")

    result = run_provider_scan(
        engine=_engine(),
        project_root=tmp_path,
        provider="codex",
        transport="fixture",
        execution="fixture",
        run_id="run-1",
        session_id="session-1",
        agents=["sqli"],
        target=_target(tmp_path),
        fixture_findings=[_finding_dict()],
    )

    assert result.provider == "codex"
    assert result.transport_kind == "fixture"
    assert result.findings[0].id == "sqli-001"
    assert result.guardrails == {"fixture_runner": True}


def test_run_provider_scan_cli_uses_injected_runner(tmp_path: Path) -> None:
    _write_config(tmp_path, transport_kind="cli")
    command_runner = RecordingCommandRunner()

    result = run_provider_scan(
        engine=_engine(),
        project_root=tmp_path,
        provider="codex",
        transport="cli",
        execution="cli",
        run_id="run-1",
        session_id="session-1",
        agents=["sqli"],
        target=_target(tmp_path),
        command_runner=command_runner,
        env={"OPENAI_API_KEY": "must-not-leak", "PATH": "/usr/bin"},
    )

    stdin_payload = json.loads(command_runner.invocations[0].stdin)
    assert command_runner.invocations[0].argv == ["codex", "exec", "--json"]
    assert "OPENAI_API_KEY" not in command_runner.invocations[0].env
    assert stdin_payload["agents"] == ["sqli"]
    assert result.findings[0].id == "sqli-001"


def test_run_provider_scan_rejects_api_transport(tmp_path: Path) -> None:
    _write_config(tmp_path, transport_kind="api")

    with pytest.raises(ValueError, match="requires a 'cli' transport"):
        run_provider_scan(
            engine=_engine(),
            project_root=tmp_path,
            provider="codex",
            transport="api",
            execution="cli",
            run_id="run-1",
            session_id="session-1",
            agents=["sqli"],
            target=_target(tmp_path),
        )


def test_run_provider_scan_mcp_tool_fixture(tmp_path: Path) -> None:
    _write_config(tmp_path, transport_kind="fixture")

    result = _dispatch_tool(
        _engine(),
        "run_provider_scan",
        {
            "project_root": str(tmp_path),
            "provider": "codex",
            "transport": "fixture",
            "execution": "fixture",
            "run_id": "run-1",
            "session_id": "session-1",
            "agents": ["sqli"],
            "target": _target(tmp_path),
            "fixture_findings": [_finding_dict()],
        },
    )

    assert result["provider"] == "codex"
    assert result["findings"][0]["id"] == "sqli-001"


def test_provider_scan_tool_is_registered() -> None:
    names = {tool["name"] for tool in _engine().list_tool_definitions()}

    assert "run_provider_scan" in names
    assert "run_composed_provider_scan" in names
    assert "run_parallel_provider_scan" in names


def test_provider_scan_cli_fixture_outputs_json(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _write_config(tmp_path, transport_kind="fixture")
    target = _target(tmp_path)

    exit_code = main(
        [
            "provider-scan",
            "--project-root",
            str(tmp_path),
            "--provider",
            "codex",
            "--transport",
            "fixture",
            "--execution",
            "fixture",
            "--agents",
            "sqli",
            "--target-json",
            json.dumps(target),
            "--fixture-findings-json",
            json.dumps([_finding_dict()]),
        ]
    )

    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert exit_code == 0
    assert payload["findings"][0]["id"] == "sqli-001"


def test_run_provider_scan_workflow_finalize_writes_reports(tmp_path: Path) -> None:
    _write_config(tmp_path, transport_kind="fixture")

    result = run_provider_scan_workflow(
        engine=_engine(),
        project_root=tmp_path,
        provider="codex",
        transport="fixture",
        execution="fixture",
        run_id="run-1",
        session_id="session-1",
        agents=["sqli"],
        target=_target(tmp_path),
        fixture_findings=[_finding_dict()],
        finalize=True,
        formats=["json", "markdown"],
    )

    assert result["primary_scan_result"]["findings"][0]["id"] == "sqli-001"
    assert result["accumulate_result"]["session_id"] == "session-1"
    assert result["finalize_result"]["summary"]["total"] == 1
    assert "json" in result["finalize_result"]["files_written"]
    assert "markdown" in result["finalize_result"]["files_written"]
    assert Path(result["finalize_result"]["files_written"]["json"]).exists()


def test_run_provider_scan_mcp_tool_finalize_fixture(tmp_path: Path) -> None:
    _write_config(tmp_path, transport_kind="fixture")

    result = _dispatch_tool(
        _engine(),
        "run_provider_scan",
        {
            "project_root": str(tmp_path),
            "provider": "codex",
            "transport": "fixture",
            "execution": "fixture",
            "run_id": "run-1",
            "session_id": "session-1",
            "agents": ["sqli"],
            "target": _target(tmp_path),
            "fixture_findings": [_finding_dict()],
            "finalize": True,
            "formats": ["json"],
        },
    )

    assert result["accumulate_result"]["session_id"] == "session-1"
    assert result["finalize_result"]["summary"]["total"] == 1
    assert Path(result["finalize_result"]["files_written"]["json"]).exists()


def test_provider_scan_cli_finalize_outputs_report_paths(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _write_config(tmp_path, transport_kind="fixture")
    target = _target(tmp_path)

    exit_code = main(
        [
            "provider-scan",
            "--project-root",
            str(tmp_path),
            "--provider",
            "codex",
            "--transport",
            "fixture",
            "--execution",
            "fixture",
            "--agents",
            "sqli",
            "--target-json",
            json.dumps(target),
            "--fixture-findings-json",
            json.dumps([_finding_dict()]),
            "--run-id",
            "run-1",
            "--session-id",
            "session-1",
            "--finalize",
            "--format",
            "json",
            "--format",
            "markdown",
        ]
    )

    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert exit_code == 0
    assert payload["primary_scan_result"]["findings"][0]["id"] == "sqli-001"
    assert payload["finalize_result"]["summary"]["total"] == 1
    assert Path(payload["finalize_result"]["files_written"]["json"]).exists()


def test_composed_provider_scan_workflow_codex_primary_claude_challenger(
    tmp_path: Path,
) -> None:
    _write_composed_config(
        tmp_path,
        primary_provider="codex",
        challenger_provider="claude",
    )

    result = run_composed_provider_scan_workflow(
        engine=_engine(),
        project_root=tmp_path,
        primary_provider="codex",
        primary_transport="fixture",
        primary_execution="fixture",
        challenger_mode="primary_challenger",
        challenger_execution="dry_run",
        run_id="run-1",
        session_id="session-1",
        agents=["sqli"],
        target=_target(tmp_path),
        fixture_findings=[_finding_dict()],
        formats=["json", "markdown"],
    )

    assert result["mode"]["primary"]["provider"] == "codex"
    assert result["mode"]["challenger"]["mode"] == "primary_challenger"
    assert result["primary_scan_result"]["findings"][0]["id"] == "sqli-001"
    assert result["finalize_result"]["summary"]["total"] == 1
    assert result["challenger_results"][0]["mode"] == "primary_challenger"
    assert result["challenger_results"][0]["reconciliations"][0]["finding_ids"] == [
        "sqli-001"
    ]

    report_path = Path(result["finalize_result"]["files_written"]["json"])
    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert report["challenger_results"][0]["mode"] == "primary_challenger"


def test_composed_provider_scan_workflow_handles_list_json_report(
    tmp_path: Path,
) -> None:
    report_path = tmp_path / "findings.json"
    report_path.write_text("[]", encoding="utf-8")

    assert _challenger_results_from_finalize_result(
        {"files_written": {"json": str(report_path)}}
    ) == []


def test_composed_provider_scan_workflow_claude_primary_codex_challenger(
    tmp_path: Path,
) -> None:
    _write_composed_config(
        tmp_path,
        primary_provider="claude",
        challenger_provider="codex",
    )

    result = run_composed_provider_scan_workflow(
        engine=_engine(),
        project_root=tmp_path,
        primary_provider="claude",
        primary_transport="fixture",
        primary_execution="fixture",
        challenger_mode="primary_challenger",
        challenger_execution="dry_run",
        run_id="run-1",
        session_id="session-1",
        agents=["sqli"],
        target=_target(tmp_path),
        fixture_findings=[_finding_dict()],
        formats=["json"],
    )

    assert result["mode"]["primary"]["provider"] == "claude"
    assert result["primary_scan_result"]["provider"] == "claude"
    assert result["challenger_results"][0]["reconciliations"][0]["primary_provider"] == (
        "claude"
    )


def test_parallel_provider_scan_workflow_reconciles_agreed_findings(
    tmp_path: Path,
) -> None:
    _write_composed_config(
        tmp_path,
        primary_provider="claude",
        challenger_provider="codex",
    )

    result = run_parallel_provider_scan_workflow(
        engine=_engine(),
        project_root=tmp_path,
        participants=[
            {"provider": "claude", "transport": "fixture", "execution": "fixture"},
            {"provider": "codex", "transport": "fixture", "execution": "fixture"},
        ],
        run_id="parallel-run",
        session_id="parallel-session",
        agents=["sqli"],
        target=_target(tmp_path),
        fixture_findings_by_provider={
            "claude": [_finding_variant(finding_id="claude-sqli-001")],
            "codex": [_finding_variant(finding_id="codex-sqli-001")],
        },
    )

    assert result["mode"]["type"] == "parallel"
    assert len(result["primary_scan_results"]) == 2
    assert result["provider_findings"]["claude"][0]["id"] == "claude-sqli-001"
    assert result["provider_findings"]["codex"][0]["id"] == "codex-sqli-001"
    assert result["reconciliations"][0]["status"] == "agreed"
    assert result["reconciliations"][0]["participant_providers"] == [
        "claude",
        "codex",
    ]
    assert result["reconciliations"][0]["finding_ids"] == [
        "claude-sqli-001",
        "codex-sqli-001",
    ]


def test_parallel_provider_scan_workflow_marks_unique_findings(
    tmp_path: Path,
) -> None:
    _write_composed_config(
        tmp_path,
        primary_provider="claude",
        challenger_provider="codex",
    )

    result = run_parallel_provider_scan_workflow(
        engine=_engine(),
        project_root=tmp_path,
        participants=[
            {"provider": "claude", "transport": "fixture", "execution": "fixture"},
            {"provider": "codex", "transport": "fixture", "execution": "fixture"},
        ],
        run_id="parallel-run",
        session_id="parallel-session",
        agents=["sqli"],
        target=_target(tmp_path),
        fixture_findings_by_provider={
            "claude": [_finding_variant(finding_id="claude-sqli-001", line_start=12)],
            "codex": [_finding_variant(finding_id="codex-sqli-002", line_start=42)],
        },
    )

    assert [item["status"] for item in result["reconciliations"]] == [
        "unique",
        "unique",
    ]
    assert result["reconciliations"][0]["participant_providers"] == ["claude"]
    assert result["reconciliations"][1]["participant_providers"] == ["codex"]


def test_parallel_provider_scan_workflow_marks_severity_disputes(
    tmp_path: Path,
) -> None:
    _write_composed_config(
        tmp_path,
        primary_provider="claude",
        challenger_provider="codex",
    )

    result = run_parallel_provider_scan_workflow(
        engine=_engine(),
        project_root=tmp_path,
        participants=[
            {"provider": "claude", "transport": "fixture", "execution": "fixture"},
            {"provider": "codex", "transport": "fixture", "execution": "fixture"},
        ],
        run_id="parallel-run",
        session_id="parallel-session",
        agents=["sqli"],
        target=_target(tmp_path),
        fixture_findings_by_provider={
            "claude": [_finding_variant(finding_id="claude-sqli-001", severity="high")],
            "codex": [_finding_variant(finding_id="codex-sqli-001", severity="medium")],
        },
    )

    assert result["reconciliations"][0]["status"] == "disputed"
    assert result["reconciliations"][0]["agreed_severity"] is None


def test_composed_provider_scan_mcp_tool_fixture(tmp_path: Path) -> None:
    _write_composed_config(
        tmp_path,
        primary_provider="codex",
        challenger_provider="claude",
    )

    result = _dispatch_tool(
        _engine(),
        "run_composed_provider_scan",
        {
            "project_root": str(tmp_path),
            "primary_provider": "codex",
            "primary_transport": "fixture",
            "primary_execution": "fixture",
            "challenger_mode": "primary_challenger",
            "challenger_execution": "dry_run",
            "run_id": "run-1",
            "session_id": "session-1",
            "agents": ["sqli"],
            "target": _target(tmp_path),
            "fixture_findings": [_finding_dict()],
            "formats": ["json"],
        },
    )

    assert result["mode"]["type"] == "primary_challenger"
    assert result["primary_scan_result"]["provider"] == "codex"
    assert result["challenger_results"][0]["mode"] == "primary_challenger"


def test_parallel_provider_scan_mcp_tool_fixture(tmp_path: Path) -> None:
    _write_composed_config(
        tmp_path,
        primary_provider="claude",
        challenger_provider="codex",
    )

    result = _dispatch_tool(
        _engine(),
        "run_parallel_provider_scan",
        {
            "project_root": str(tmp_path),
            "participants": [
                {"provider": "claude", "transport": "fixture", "execution": "fixture"},
                {"provider": "codex", "transport": "fixture", "execution": "fixture"},
            ],
            "run_id": "parallel-run",
            "session_id": "parallel-session",
            "agents": ["sqli"],
            "target": _target(tmp_path),
            "fixture_findings_by_provider": {
                "claude": [_finding_variant(finding_id="claude-sqli-001")],
                "codex": [_finding_variant(finding_id="codex-sqli-001")],
            },
        },
    )

    assert result["mode"]["type"] == "parallel"
    assert result["reconciliations"][0]["status"] == "agreed"
