from pathlib import Path

import pytest

from screw_agents.engine import ScanEngine
from screw_agents.primary_scan import PrimaryScanInput, PrimaryScanParticipant
from screw_agents.registry import AgentRegistry


@pytest.fixture
def engine() -> ScanEngine:
    domains_dir = Path(__file__).parents[1] / "domains"
    return ScanEngine(AgentRegistry(domains_dir))


@pytest.fixture
def python_file_target(tmp_path: Path) -> dict:
    target = tmp_path / "app.py"
    target.write_text(
        "import sqlite3\n"
        "def get_user(user_id):\n"
        "    query = f\"select * from users where id = {user_id}\"\n"
        "    return sqlite3.connect(':memory:').execute(query)\n",
        encoding="utf-8",
    )
    return {"type": "file", "path": str(target)}


def test_assemble_primary_scan_input_packages_yaml_prompt_and_source(
    engine: ScanEngine,
    python_file_target: dict,
) -> None:
    participant = PrimaryScanParticipant(provider="codex", transport="cli")

    scan_input = engine.assemble_primary_scan_input(
        run_id="run-1",
        session_id="session-1",
        participant=participant,
        agents=["sqli"],
        target=python_file_target,
        thoroughness="standard",
    )

    assert isinstance(scan_input, PrimaryScanInput)
    assert scan_input.participant == participant
    assert scan_input.agents == ["sqli"]
    assert len(scan_input.source_chunks) == 1
    assert scan_input.source_chunks[0].path == python_file_target["path"]
    assert "## Agent: sqli" in scan_input.prompt
    assert "SQL Injection" in scan_input.prompt
    assert "Return JSON only" in scan_input.prompt
    assert scan_input.output_schema["title"] == "Finding"
    assert scan_input.metadata["provider_execution"] is False


def test_assemble_primary_scan_input_matches_existing_agent_prompt(
    engine: ScanEngine,
    python_file_target: dict,
) -> None:
    participant = PrimaryScanParticipant(provider="gemini", transport="api")
    existing_prompt = engine.get_agent_prompt("sqli", "deep")["core_prompt"]

    scan_input = engine.assemble_primary_scan_input(
        run_id="run-1",
        session_id="session-1",
        participant=participant,
        agents=["sqli"],
        target=python_file_target,
        thoroughness="deep",
    )

    assert existing_prompt in scan_input.prompt


def test_assemble_primary_scan_input_orders_agents_deterministically(
    engine: ScanEngine,
    python_file_target: dict,
) -> None:
    participant = PrimaryScanParticipant(provider="local", transport="local")

    first = engine.assemble_primary_scan_input(
        run_id="run-1",
        session_id="session-1",
        participant=participant,
        agents=["xss", "sqli"],
        target=python_file_target,
    )
    second = engine.assemble_primary_scan_input(
        run_id="run-2",
        session_id="session-1",
        participant=participant,
        agents=["sqli", "xss"],
        target=python_file_target,
    )

    assert first.agents == second.agents == ["sqli", "xss"]
    assert first.metadata["agent_meta"] == second.metadata["agent_meta"]


def test_assemble_primary_scan_input_rejects_unknown_agent(
    engine: ScanEngine,
    python_file_target: dict,
) -> None:
    participant = PrimaryScanParticipant(provider="codex", transport="cli")

    with pytest.raises(ValueError, match="Unknown agent"):
        engine.assemble_primary_scan_input(
            run_id="run-1",
            session_id="session-1",
            participant=participant,
            agents=["missing-agent"],
            target=python_file_target,
        )


def test_assemble_primary_scan_input_rejects_unsupported_target(
    engine: ScanEngine,
) -> None:
    participant = PrimaryScanParticipant(provider="codex", transport="cli")

    with pytest.raises(ValueError, match="Unsupported target type"):
        engine.assemble_primary_scan_input(
            run_id="run-1",
            session_id="session-1",
            participant=participant,
            agents=["sqli"],
            target={"type": "unsupported"},
        )


def test_assemble_primary_scan_input_does_not_run_provider(
    engine: ScanEngine,
    python_file_target: dict,
) -> None:
    participant = PrimaryScanParticipant(provider="codex", transport="cli")

    scan_input = engine.assemble_primary_scan_input(
        run_id="run-1",
        session_id="session-1",
        participant=participant,
        agents=["sqli"],
        target=python_file_target,
    )

    assert scan_input.metadata["provider_execution"] is False
    assert "provider_result" not in scan_input.metadata
