"""Tests for scan_domain cursor pagination (Phase 3a PR #3 X1)."""

from __future__ import annotations

from pathlib import Path

import pytest

from screw_agents.engine import ScanEngine


def test_scan_domain_empty_cursor_returns_dict_with_cursor_key(tmp_path: Path):
    """Even the first call (cursor=None) returns the new dict shape with next_cursor key.

    This is the BREAKING change: pre-PR#3 callers got list[dict]; post-PR#3 always
    get dict[str, Any] with keys agents/next_cursor/page_size/total_files/offset.
    """
    engine = ScanEngine.from_defaults()
    result = engine.assemble_domain_scan(
        domain="injection-input-handling",
        target={"type": "glob", "pattern": str(tmp_path / "*.py")},
        project_root=tmp_path,
        cursor=None,
        page_size=50,
    )
    assert isinstance(result, dict)
    assert "agents" in result
    assert isinstance(result["agents"], list)  # list of per-agent payloads
    assert "next_cursor" in result
    assert "page_size" in result
    assert "total_files" in result
    assert "offset" in result
    # Empty tmp_path resolves to no files — next_cursor is None (pagination done)
    assert result["total_files"] == 0
    assert result["next_cursor"] is None


def test_scan_domain_pagination_returns_distinct_pages(tmp_path: Path):
    """With 100 seeded files and page_size=30, page 1 and page 2 cover different slices."""
    src = tmp_path / "src"
    src.mkdir()
    for i in range(100):
        # Include a relevance signal so at least the sqli agent retains these files
        # after per-agent relevance filtering (sqli matches "SELECT", "cursor.execute", etc.)
        (src / f"file_{i:03d}.py").write_text(f"cursor.execute('SELECT * FROM t{i}')\n")

    engine = ScanEngine.from_defaults()
    page1 = engine.assemble_domain_scan(
        domain="injection-input-handling",
        target={"type": "glob", "pattern": str(src / "*.py")},
        project_root=tmp_path,
        cursor=None,
        page_size=30,
    )
    assert page1["next_cursor"] is not None
    assert page1["offset"] == 0
    assert page1["total_files"] == 100

    page2 = engine.assemble_domain_scan(
        domain="injection-input-handling",
        target={"type": "glob", "pattern": str(src / "*.py")},
        project_root=tmp_path,
        cursor=page1["next_cursor"],
        page_size=30,
    )
    assert page2["offset"] == 30

    # Per-agent resolved_files across the two pages must be disjoint
    files_page1: set[str] = set()
    files_page2: set[str] = set()
    for agent_result in page1["agents"]:
        files_page1.update(agent_result.get("resolved_files", []))
    # At least one agent must have resolved files on the first page to validate disjointness meaningfully
    assert files_page1, "page 1 resolved no files — test is vacuously true (check relevance signals)"
    for agent_result in page2["agents"]:
        files_page2.update(agent_result.get("resolved_files", []))
    # Either disjoint, OR one page is empty (tolerated for relevance-filtered agents)
    assert files_page1.isdisjoint(files_page2) or not files_page1 or not files_page2


def test_scan_domain_cursor_is_opaque_base64_string(tmp_path: Path):
    """The cursor must be a non-empty string when there are more pages."""
    src = tmp_path / "src"
    src.mkdir()
    for i in range(100):
        (src / f"file_{i:03d}.py").write_text(f"# fixture {i}\n")

    engine = ScanEngine.from_defaults()
    result = engine.assemble_domain_scan(
        domain="injection-input-handling",
        target={"type": "glob", "pattern": str(src / "*.py")},
        project_root=tmp_path,
        cursor=None,
        page_size=25,
    )
    assert isinstance(result["next_cursor"], str)
    assert len(result["next_cursor"]) > 0


def test_scan_domain_rejects_cursor_from_different_target(tmp_path: Path):
    """A cursor bound to target A must not be accepted on a scan with target B."""
    src = tmp_path / "src"
    src.mkdir()
    for i in range(60):
        (src / f"file_{i:03d}.py").write_text(f"# fixture {i}\n")

    engine = ScanEngine.from_defaults()
    result_a = engine.assemble_domain_scan(
        domain="injection-input-handling",
        target={"type": "glob", "pattern": str(src / "*.py")},
        project_root=tmp_path,
        cursor=None,
        page_size=20,
    )
    assert result_a["next_cursor"] is not None

    # Replay cursor A against a DIFFERENT target — must raise
    with pytest.raises(ValueError, match="cursor"):
        engine.assemble_domain_scan(
            domain="injection-input-handling",
            target={"type": "glob", "pattern": str(src / "file_0[0-4]*.py")},  # narrower target
            project_root=tmp_path,
            cursor=result_a["next_cursor"],
            page_size=20,
        )


def test_pagination_walks_all_files_without_duplicates(tmp_path: Path):
    """Full pagination loop: walk all 150 files across pages with no duplicates."""
    src = tmp_path / "src"
    src.mkdir()
    total_files = 150
    for i in range(total_files):
        # Zero-padded names for deterministic sort; sqli relevance signal retained
        (src / f"file_{i:03d}.py").write_text(
            f"cursor.execute('SELECT * FROM t{i}')\n"
        )

    engine = ScanEngine.from_defaults()
    all_visited: set[str] = set()
    cursor: str | None = None
    pages_consumed = 0

    while True:
        result = engine.assemble_domain_scan(
            domain="injection-input-handling",
            target={"type": "glob", "pattern": str(src / "*.py")},
            project_root=tmp_path,
            cursor=cursor,
            page_size=25,
        )
        pages_consumed += 1
        for agent_result in result["agents"]:
            for path in agent_result.get("resolved_files", []):
                assert path not in all_visited, f"duplicate file across pages: {path}"
                all_visited.add(path)

        cursor = result["next_cursor"]
        if cursor is None:
            break

        # Safety: don't loop forever in a broken impl
        assert pages_consumed < 20, "pagination did not terminate"

    assert len(all_visited) == total_files
