"""Tests for scan_domain cursor pagination (Phase 3a PR #3 X1)."""

from __future__ import annotations

from pathlib import Path

import pytest

from screw_agents.engine import ScanEngine


def _seed_injection_fixture(root: Path, n: int = 12) -> None:
    """Helper: write n Python files with sqli-visible patterns so the
    sqli relevance filter retains them."""
    for i in range(n):
        (root / f"file_{i:02d}.py").write_text(
            f"cursor.execute('SELECT * FROM t WHERE x = ' + user_input_{i})\n"
        )


def test_domain_scan_init_page_shape(tmp_path: Path):
    """Init page (cursor=None) returns top-level `prompts` dict keyed by
    agent_name, per-agent entries without core_prompt, zero code chunks, and
    a next_cursor encoding offset=0."""
    _seed_injection_fixture(tmp_path)
    engine = ScanEngine.from_defaults()
    target = {"type": "glob", "pattern": str(tmp_path / "*.py")}

    result = engine.assemble_domain_scan(
        "injection-input-handling", target, cursor=None
    )

    # Top-level prompts dict
    assert "prompts" in result
    assert isinstance(result["prompts"], dict)
    assert {"sqli", "cmdi", "ssti", "xss"}.issubset(set(result["prompts"].keys()))
    for prompt in result["prompts"].values():
        assert isinstance(prompt, str)
        assert len(prompt) > 0

    # Per-agent entries: metadata only on init, no core_prompt, no code
    assert "agents" in result
    for agent_entry in result["agents"]:
        assert "agent_name" in agent_entry
        assert "core_prompt" not in agent_entry
        assert "meta" in agent_entry
        assert "code" not in agent_entry

    # Init-page metadata
    assert result["code_chunks_on_page"] == 0
    assert result["offset"] == 0
    assert result["next_cursor"] is not None  # non-empty scan → next cursor for code pages


def test_domain_scan_init_page_idempotent(tmp_path: Path):
    """Calling assemble_domain_scan with cursor=None twice returns the same
    init-page shape both times. No state change between calls."""
    _seed_injection_fixture(tmp_path)
    engine = ScanEngine.from_defaults()
    target = {"type": "glob", "pattern": str(tmp_path / "*.py")}

    r1 = engine.assemble_domain_scan("injection-input-handling", target, cursor=None)
    r2 = engine.assemble_domain_scan("injection-input-handling", target, cursor=None)

    assert r1.keys() == r2.keys()
    assert set(r1["prompts"].keys()) == set(r2["prompts"].keys())
    assert r1["code_chunks_on_page"] == r2["code_chunks_on_page"] == 0
    assert r1["next_cursor"] == r2["next_cursor"]


def test_domain_scan_init_page_empty_target(tmp_path: Path):
    """When total_files == 0, init page still ships with prompts; next_cursor
    is None (no code pages to fetch)."""
    engine = ScanEngine.from_defaults()
    target = {"type": "glob", "pattern": str(tmp_path / "*.py")}  # empty dir

    result = engine.assemble_domain_scan(
        "injection-input-handling", target, cursor=None
    )

    assert "prompts" in result
    assert result["total_files"] == 0
    assert result["code_chunks_on_page"] == 0
    assert result["next_cursor"] is None  # nothing to paginate


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
    """With 100 seeded files and page_size=30, successive code pages cover
    different slices. Post-X1-M1 the first call is the init page (no code),
    so the first two CODE pages are the init's next_cursor + that cursor's
    next."""
    src = tmp_path / "src"
    src.mkdir()
    for i in range(100):
        # Include a relevance signal so at least the sqli agent retains these files
        # after per-agent relevance filtering (sqli matches "SELECT", "cursor.execute", etc.)
        (src / f"file_{i:03d}.py").write_text(f"cursor.execute('SELECT * FROM t{i}')\n")

    engine = ScanEngine.from_defaults()
    init = engine.assemble_domain_scan(
        domain="injection-input-handling",
        target={"type": "glob", "pattern": str(src / "*.py")},
        project_root=tmp_path,
        cursor=None,
        page_size=30,
    )
    assert init["next_cursor"] is not None
    assert init["offset"] == 0
    assert init["total_files"] == 100
    assert init["code_chunks_on_page"] == 0

    code_page_1 = engine.assemble_domain_scan(
        domain="injection-input-handling",
        target={"type": "glob", "pattern": str(src / "*.py")},
        project_root=tmp_path,
        cursor=init["next_cursor"],
        page_size=30,
    )
    assert code_page_1["offset"] == 0
    assert code_page_1["code_chunks_on_page"] > 0

    code_page_2 = engine.assemble_domain_scan(
        domain="injection-input-handling",
        target={"type": "glob", "pattern": str(src / "*.py")},
        project_root=tmp_path,
        cursor=code_page_1["next_cursor"],
        page_size=30,
    )
    assert code_page_2["offset"] == 30

    # Per-agent resolved_files across the two code pages must be disjoint
    files_page1: set[str] = set()
    files_page2: set[str] = set()
    for agent_result in code_page_1["agents"]:
        files_page1.update(agent_result.get("resolved_files", []))
    # At least one agent must have resolved files on the first code page to validate disjointness meaningfully
    assert files_page1, "code page 1 resolved no files — test is vacuously true (check relevance signals)"
    for agent_result in code_page_2["agents"]:
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


def test_domain_scan_code_page_shape(tmp_path: Path):
    """First code page (cursor from init): no top-level prompts, per-agent
    entries have code but no core_prompt, no exclusions (moved to init)."""
    _seed_injection_fixture(tmp_path)
    engine = ScanEngine.from_defaults()
    target = {"type": "glob", "pattern": str(tmp_path / "*.py")}

    init = engine.assemble_domain_scan("injection-input-handling", target, cursor=None)
    code_page = engine.assemble_domain_scan(
        "injection-input-handling", target, cursor=init["next_cursor"]
    )

    assert "prompts" not in code_page

    for agent_entry in code_page["agents"]:
        assert "agent_name" in agent_entry
        assert "core_prompt" not in agent_entry
        assert "code" in agent_entry
        assert "exclusions" not in agent_entry
        assert "meta" in agent_entry

    assert code_page["offset"] == 0
    assert code_page["code_chunks_on_page"] > 0


def test_domain_scan_code_page_cursor_replay_different_target_rejected(tmp_path: Path):
    """Replaying a cursor against a different target raises ValueError —
    existing invariant preserved."""
    _seed_injection_fixture(tmp_path)
    other = tmp_path / "other"
    other.mkdir()
    (other / "b.py").write_text("cursor.execute('SELECT 1')\n")

    engine = ScanEngine.from_defaults()
    target_a = {"type": "glob", "pattern": str(tmp_path / "*.py")}
    target_b = {"type": "glob", "pattern": str(other / "*.py")}

    init = engine.assemble_domain_scan("injection-input-handling", target_a, cursor=None)
    with pytest.raises(ValueError, match="cursor is bound to a different target"):
        engine.assemble_domain_scan(
            "injection-input-handling", target_b, cursor=init["next_cursor"]
        )


def test_domain_scan_trust_status_on_every_page(tmp_path: Path):
    """trust_status appears on init AND on every code page — subagent may
    read it from any page. Bare tmp_path (no .screw/) still yields a
    present, all-zero trust_status dict."""
    _seed_injection_fixture(tmp_path)
    engine = ScanEngine.from_defaults()
    target = {"type": "glob", "pattern": str(tmp_path / "*.py")}

    init = engine.assemble_domain_scan(
        "injection-input-handling", target, project_root=tmp_path, cursor=None
    )
    code_page = engine.assemble_domain_scan(
        "injection-input-handling", target, project_root=tmp_path,
        cursor=init["next_cursor"]
    )

    assert "trust_status" in init
    assert "trust_status" in code_page
    assert init["trust_status"].keys() == code_page["trust_status"].keys()


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
