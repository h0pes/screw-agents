"""Tests for MCP server initialization and tool registration."""

from pathlib import Path

import pytest

from screw_agents.server import create_server
from screw_agents.server import _dispatch_tool


@pytest.fixture
def engine(domains_dir):
    _, engine = create_server(domains_dir)
    return engine


def test_create_server(domains_dir):
    server, engine = create_server(domains_dir)
    assert server is not None
    assert engine is not None


def test_server_tool_definitions(domains_dir):
    _, engine = create_server(domains_dir)
    tools = engine.list_tool_definitions()
    names = {t["name"] for t in tools}
    assert "scan_sqli" in names
    assert "scan_cmdi" in names
    assert "scan_ssti" in names
    assert "scan_xss" in names
    assert "list_domains" in names
    assert "list_agents" in names
    assert "scan_domain" in names
    assert "scan_full" in names
    assert "scan_agents" in names


def test_create_http_app(domains_dir):
    from screw_agents.server import create_http_app
    app = create_http_app(domains_dir)
    assert app is not None


def test_scan_agents_dispatch_via_server(engine, tmp_path: Path) -> None:
    """server._dispatch_tool routes scan_agents to engine.assemble_agents_scan.

    Tests the actual MCP dispatch path (matches the precedent at
    tests/test_phase2_server.py:36+).
    """
    src = tmp_path / "src"
    src.mkdir()
    (src / "x.py").write_text("import sqlite3\n")

    response = _dispatch_tool(
        engine,
        "scan_agents",
        {
            "agents": ["sqli"],
            "target": {"type": "codebase", "root": str(tmp_path)},
        },
    )
    assert "agents" in response
    assert any(a["agent_name"] == "sqli" for a in response["agents"])
