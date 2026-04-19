"""Tests for `ScanEngine.record_context_required_match` + staging protocol.

Phase 3b T16 part 2. Mirrors the test structure of
`tests/test_accumulate_finalize.py` for the findings staging buffer:
atomicity, dedup, session carryforward, and cleanup by finalize.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from screw_agents.engine import ScanEngine


def _make_match(
    agent: str = "sqli",
    file: str = "app.py",
    line: int = 42,
    pattern: str = "raw_method_check",
) -> dict:
    return {
        "agent": agent,
        "file": file,
        "line": line,
        "pattern": pattern,
    }


def _make_finding(fid: str, agent: str = "sqli") -> dict:
    """Copied minimal finding shape from test_accumulate_finalize.py for the
    finalize-cleanup E2E test."""
    return {
        "id": fid,
        "agent": agent,
        "domain": "injection-input-handling",
        "timestamp": "2026-04-19T00:00:00Z",
        "classification": {
            "cwe": "CWE-89",
            "cwe_name": "SQL Injection",
            "severity": "high",
            "confidence": "high",
        },
        "location": {
            "file": "src/a.py",
            "line_start": 10,
            "line_end": 10,
            "function": None,
            "code_snippet": "db.execute(x)",
        },
        "analysis": {"description": "ok"},
        "remediation": {"recommendation": "use parameterized queries"},
        "triage": {"status": "open"},
    }


def test_record_context_required_match_creates_staging_file(tmp_path: Path) -> None:
    """First call with session_id=None generates a new session and writes the
    context-required staging file under .screw/staging/{session_id}/."""
    engine = ScanEngine.from_defaults()

    result = engine.record_context_required_match(
        project_root=tmp_path,
        match=_make_match(),
        session_id=None,
    )

    assert "session_id" in result
    assert isinstance(result["session_id"], str)
    assert len(result["session_id"]) > 0
    assert result["matches_recorded"] == 1

    staging_file = (
        tmp_path / ".screw" / "staging" / result["session_id"]
        / "context_required_matches.json"
    )
    assert staging_file.exists()
    data = json.loads(staging_file.read_text())
    assert len(data) == 1
    assert data[0]["agent"] == "sqli"
    assert data[0]["line"] == 42


def test_record_context_required_match_session_id_carryforward(tmp_path: Path) -> None:
    """Passing the returned session_id on subsequent calls appends to the
    same staging file."""
    engine = ScanEngine.from_defaults()

    first = engine.record_context_required_match(
        project_root=tmp_path,
        match=_make_match(line=10),
        session_id=None,
    )
    sid = first["session_id"]

    second = engine.record_context_required_match(
        project_root=tmp_path,
        match=_make_match(line=20),
        session_id=sid,
    )

    assert second["session_id"] == sid
    assert second["matches_recorded"] == 2

    staging_file = (
        tmp_path / ".screw" / "staging" / sid / "context_required_matches.json"
    )
    data = json.loads(staging_file.read_text())
    lines = {m["line"] for m in data}
    assert lines == {10, 20}


def test_record_context_required_match_dedup_by_key(tmp_path: Path) -> None:
    """Re-recording the same (agent, file, line, pattern) 4-tuple is a no-op.
    matches_recorded stays stable."""
    engine = ScanEngine.from_defaults()

    first = engine.record_context_required_match(
        project_root=tmp_path,
        match=_make_match(),
        session_id=None,
    )
    sid = first["session_id"]
    assert first["matches_recorded"] == 1

    second = engine.record_context_required_match(
        project_root=tmp_path,
        match=_make_match(),  # identical 4-tuple
        session_id=sid,
    )
    assert second["matches_recorded"] == 1  # dedup held

    staging_file = (
        tmp_path / ".screw" / "staging" / sid / "context_required_matches.json"
    )
    data = json.loads(staging_file.read_text())
    assert len(data) == 1


def test_record_context_required_match_different_pattern_not_deduped(
    tmp_path: Path,
) -> None:
    """Same (agent, file, line) but different pattern yields two entries —
    matches D1's tuple-key semantics in gap_signal.py."""
    engine = ScanEngine.from_defaults()

    first = engine.record_context_required_match(
        project_root=tmp_path,
        match=_make_match(pattern="pattern_a"),
        session_id=None,
    )
    sid = first["session_id"]

    second = engine.record_context_required_match(
        project_root=tmp_path,
        match=_make_match(pattern="pattern_b"),
        session_id=sid,
    )
    assert second["matches_recorded"] == 2


def test_record_context_required_match_rejects_missing_key(tmp_path: Path) -> None:
    """Missing 'pattern' key is a producer bug and must raise loudly."""
    engine = ScanEngine.from_defaults()
    bad = _make_match()
    del bad["pattern"]
    with pytest.raises(ValueError, match="missing required key"):
        engine.record_context_required_match(
            project_root=tmp_path,
            match=bad,
            session_id=None,
        )


def test_record_context_required_match_rejects_wrong_line_type(tmp_path: Path) -> None:
    """'line' must be int — a string would round-trip through JSON but break
    D1's key comparison at detect time."""
    engine = ScanEngine.from_defaults()
    bad = _make_match()
    bad["line"] = "42"  # type: ignore[assignment]
    with pytest.raises(ValueError, match="'line' must be int"):
        engine.record_context_required_match(
            project_root=tmp_path,
            match=bad,
            session_id=None,
        )


def test_record_context_required_match_atomic_write(tmp_path: Path) -> None:
    """If os.replace fails mid-write, the original file (if any) is intact
    and no partial write is left behind under the final path.

    Atomicity model: we write to a .tmp file first, then swap via
    os.replace (atomic on POSIX). If the swap fails, the tmp file may be
    left behind (cleanup is not guaranteed) but the canonical path is
    never partial.
    """
    engine = ScanEngine.from_defaults()

    first = engine.record_context_required_match(
        project_root=tmp_path,
        match=_make_match(line=10),
        session_id=None,
    )
    sid = first["session_id"]
    staging_file = (
        tmp_path / ".screw" / "staging" / sid / "context_required_matches.json"
    )
    original_content = staging_file.read_text()

    # Patch Path.replace so the atomic swap raises. The second call must
    # surface the error and leave the original file unmodified.
    with patch("pathlib.Path.replace", side_effect=OSError("simulated disk failure")):
        with pytest.raises(OSError, match="simulated disk failure"):
            engine.record_context_required_match(
                project_root=tmp_path,
                match=_make_match(line=20),
                session_id=sid,
            )

    # The original file is still there and unmodified.
    assert staging_file.exists()
    assert staging_file.read_text() == original_content


def test_record_context_required_match_after_finalize_raises(tmp_path: Path) -> None:
    """Recording into an already-finalized session raises — finalized sessions
    are locked, mirroring accumulate_findings semantics."""
    engine = ScanEngine.from_defaults()

    # Establish a session via accumulate_findings → finalize_scan_results.
    acc = engine.accumulate_findings(
        project_root=tmp_path,
        findings_chunk=[_make_finding("sqli-001")],
        session_id=None,
    )
    sid = acc["session_id"]
    engine.finalize_scan_results(
        project_root=tmp_path, session_id=sid, agent_names=["sqli"]
    )

    with pytest.raises(ValueError, match="already been finalized"):
        engine.record_context_required_match(
            project_root=tmp_path,
            match=_make_match(),
            session_id=sid,
        )


def test_finalize_scan_results_cleans_up_context_required_staging(
    tmp_path: Path,
) -> None:
    """After finalize, the context_required_matches.json file is gone —
    mirrors the findings.json cleanup pattern."""
    engine = ScanEngine.from_defaults()

    # Record a context-required match + accumulate a finding on the same session.
    acc = engine.accumulate_findings(
        project_root=tmp_path,
        findings_chunk=[_make_finding("sqli-001")],
        session_id=None,
    )
    sid = acc["session_id"]
    engine.record_context_required_match(
        project_root=tmp_path,
        match=_make_match(),
        session_id=sid,
    )

    staging_dir = tmp_path / ".screw" / "staging" / sid
    assert (staging_dir / "context_required_matches.json").exists()

    engine.finalize_scan_results(
        project_root=tmp_path, session_id=sid, agent_names=["sqli"]
    )

    # context_required_matches.json is cleaned up (same pattern as findings.json).
    assert not (staging_dir / "context_required_matches.json").exists()
    # Staging directory persists (holds the result.json sidecar for idempotency).
    assert staging_dir.exists()
    assert (staging_dir / "result.json").exists()
