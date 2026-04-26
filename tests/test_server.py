"""Tests for MCP server initialization and tool registration."""

from pathlib import Path

import pytest

from screw_agents.server import _dispatch_tool, create_server


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
    assert "list_domains" in names
    assert "list_agents" in names
    assert "scan_domain" in names
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


def test_retired_tool_names_raise_actionable_error(engine) -> None:
    """Calling a retired tool name (scan_full, scan_<agent>) raises with migration hint
    pointing to scan_agents and scan_domain replacements.

    T-SCAN-REFACTOR Task 6 (Escalation I1): defense-in-depth UX. Caller
    migration mistakes (calling retired names against a post-refactor server)
    get a one-line migration hint pointing to scan_agents / scan_domain
    rather than a generic ``Unknown tool:`` dead-end.

    Marco-approved Option B (quality-review escalation): positive list of
    actually-retired names; future ``scan_<future>`` names fall to the
    generic 'Unknown tool' branch (verified by the negative test below).
    """
    for retired_name in ("scan_full", "scan_sqli", "scan_xss"):
        with pytest.raises(ValueError) as exc_info:
            _dispatch_tool(engine, retired_name, {})
        msg = str(exc_info.value)
        assert "was retired in T-SCAN-REFACTOR" in msg
        assert "scan_agents(" in msg
        assert "scan_domain(" in msg


def test_unknown_scan_prefixed_name_does_not_claim_retired(engine) -> None:
    """A scan_-prefixed name that was never retired falls to the generic 'Unknown tool'
    branch, not the retired-tool actionable-error branch. Guards against the over-broad
    pattern-match anti-pattern (Marco-approved Option B: positive list semantics)."""
    with pytest.raises(ValueError) as exc_info:
        _dispatch_tool(engine, "scan_unknown_future_thing", {})
    msg = str(exc_info.value)
    assert "Unknown tool" in msg
    assert "was retired" not in msg  # must not falsely claim retirement
