"""Tests for MCP server initialization and tool registration."""

import pytest

from screw_agents.server import create_server


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
