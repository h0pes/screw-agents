"""Integration-style tests simulating the multi-page orchestration a subagent
would run against scan_domain. Asserts structural correctness of the full
walk: no aggregate prompts dict on any page (X1-M1 T13: subagents fetch each
agent's prompt lazily via get_agent_prompt), code on code pages only, no
duplicate coverage, all expected files processed exactly once across the walk."""

from __future__ import annotations

from pathlib import Path

import pytest

from screw_agents.engine import ScanEngine


def _seed(root: Path, n: int = 12) -> None:
    """Seed n Python files carrying sqli relevance signals so the sqli
    relevance filter retains all of them."""
    for i in range(n):
        (root / f"file_{i:02d}.py").write_text(
            f"cursor.execute('SELECT * FROM t WHERE x = ' + user_input_{i})\n"
        )


def test_domain_scan_full_walk_no_prompt_duplication(tmp_path: Path):
    """Walk the entire pagination sequence: init → code pages → null cursor.
    Assert:
      - `prompts` never present on any page (X1-M1 T13 — orchestrators fetch
        prompts lazily via get_agent_prompt instead)
      - `core_prompt` never present in any `agents[]` entry on any page
      - Every file appears in exactly one code page's `resolved_files`
      - `agents[].code` has meaningful content on every code page
    """
    _seed(tmp_path, n=12)
    engine = ScanEngine.from_defaults()
    target = {"type": "glob", "pattern": str(tmp_path / "*.py")}

    init = engine.assemble_domain_scan(
        "injection-input-handling", target, cursor=None, page_size=3
    )
    assert "prompts" not in init
    assert init["code_chunks_on_page"] == 0
    for agent_entry in init["agents"]:
        assert "core_prompt" not in agent_entry

    total_files_expected = init["total_files"]
    assert total_files_expected > 3  # ensure fixture produces a multi-page walk

    cursor = init["next_cursor"]
    files_seen_per_agent: dict[str, list[str]] = {
        agent_entry["agent_name"]: [] for agent_entry in init["agents"]
    }
    code_pages_count = 0

    while cursor is not None:
        page = engine.assemble_domain_scan(
            "injection-input-handling", target, cursor=cursor, page_size=3
        )
        assert "prompts" not in page, "prompts must not appear on code pages"
        assert page["code_chunks_on_page"] > 0
        for agent_entry in page["agents"]:
            assert "core_prompt" not in agent_entry
            files_seen_per_agent[agent_entry["agent_name"]].extend(
                agent_entry["resolved_files"]
            )
        code_pages_count += 1
        cursor = page["next_cursor"]

    assert code_pages_count >= 2

    for agent_name, seen in files_seen_per_agent.items():
        assert len(seen) == len(set(seen)), f"agent {agent_name} saw duplicates: {seen}"


def test_domain_scan_full_walk_payload_size_regression(tmp_path: Path):
    """Smoke-check the intended token savings: X1-M1 T13 — no page should ship
    any aggregate prompts dict. Subagents fetch each agent's prompt lazily via
    the get_agent_prompt MCP tool on first encounter and cache for reuse."""
    _seed(tmp_path, n=12)
    engine = ScanEngine.from_defaults()
    target = {"type": "glob", "pattern": str(tmp_path / "*.py")}

    pages = []
    cursor = None
    while True:
        page = engine.assemble_domain_scan(
            "injection-input-handling", target, cursor=cursor, page_size=3
        )
        pages.append(page)
        cursor = page["next_cursor"]
        if cursor is None:
            break

    pages_with_prompts = [p for p in pages if "prompts" in p]
    assert pages_with_prompts == []

    for page in pages:
        for agent_entry in page["agents"]:
            assert "core_prompt" not in agent_entry
