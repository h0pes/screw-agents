"""Tests for `ScanEngine.detect_coverage_gaps` + the adaptive E2E loop.

Phase 3b T16 part 3. Verifies:

- D1 runs from staging (context_required_matches.json populated by
  `record_context_required_match`).
- D2 runs from YAML `adaptive_inputs` when the agent declares it.
- Agents without `adaptive_inputs` still produce D1 gracefully.
- Unknown agent raises KeyError, not ValueError.
- MCP dispatch wires the tool end-to-end.
- `finalize_scan_results` includes `coverage_gaps` in its response when
  the scan session had adaptive signal (staged context-required matches
  OR an adaptive-capable agent) — and OMITS the key otherwise for
  backward compatibility with non-adaptive scans.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from screw_agents.engine import ScanEngine
from screw_agents.models import CoverageGap
from screw_agents.server import _dispatch_tool


def _make_finding(fid: str, agent: str = "sqli") -> dict:
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


def _write_d2_fixture(tmp_path: Path) -> None:
    """Create a small Python file that satisfies D2's three conditions:
    sink method, unknown receiver, tainted argument chain from a known source.

    Uses an `orm` receiver token — NOT present in sqli's shipped
    `known_receivers` (cursor, connection, conn, Session, session, db,
    engine, client, pool, stmt, statement, ps, pstmt, pdo, wpdb) — so
    condition 2 (unknown receiver) holds.
    """
    (tmp_path / "handler.py").write_text(
        "def handle(request):\n"
        "    q = request.args.get('q')\n"
        "    self.orm.execute_raw(q)\n"
    )


def test_detect_coverage_gaps_empty_staging_returns_d2_only(tmp_path: Path) -> None:
    """No recorded context-required matches + adaptive-capable agent with a D2
    fixture → D1 yields nothing, D2 fires, combined list has only D2."""
    _write_d2_fixture(tmp_path)
    engine = ScanEngine.from_defaults()

    gaps = engine.detect_coverage_gaps(
        agent_name="sqli",
        project_root=tmp_path,
        session_id="never-existed",  # no staging file → D1 empty
    )

    assert all(isinstance(g, CoverageGap) for g in gaps)
    types = {g.type for g in gaps}
    assert types == {"unresolved_sink"}, f"expected only D2 gaps, got types {types}"


def test_detect_coverage_gaps_with_matches_returns_combined_d1_and_d2(
    tmp_path: Path,
) -> None:
    """Recorded matches + adaptive-capable agent with D2 fixture → both D1 and
    D2 fire; combined list has one of each."""
    _write_d2_fixture(tmp_path)
    engine = ScanEngine.from_defaults()

    # Record a context-required match via the public engine method (E2E).
    rec = engine.record_context_required_match(
        project_root=tmp_path,
        match={
            "agent": "sqli",
            "file": "handler.py",
            "line": 2,
            "pattern": "any-raw-method-check",
        },
        session_id=None,
    )
    sid = rec["session_id"]

    gaps = engine.detect_coverage_gaps(
        agent_name="sqli",
        project_root=tmp_path,
        session_id=sid,
    )

    types = {g.type for g in gaps}
    assert "context_required" in types
    assert "unresolved_sink" in types


def test_detect_coverage_gaps_agent_without_adaptive_inputs_returns_d1_only(
    tmp_path: Path,
) -> None:
    """Agent without `adaptive_inputs` declared → D2 is skipped gracefully; D1
    still runs from staging if any matches were recorded.

    Simulated by monkeypatching the sqli agent's `adaptive_inputs` to None
    for the scope of the test; matches T16's graceful-skip contract for
    future agents that opt out of D2.
    """
    _write_d2_fixture(tmp_path)
    engine = ScanEngine.from_defaults()

    # Opt this agent out of D2.
    sqli = engine._registry.get_agent("sqli")
    assert sqli is not None
    original = sqli.adaptive_inputs
    sqli.adaptive_inputs = None
    try:
        rec = engine.record_context_required_match(
            project_root=tmp_path,
            match={
                "agent": "sqli",
                "file": "handler.py",
                "line": 3,
                "pattern": "some_context_required_pattern",
            },
            session_id=None,
        )
        sid = rec["session_id"]

        gaps = engine.detect_coverage_gaps(
            agent_name="sqli",
            project_root=tmp_path,
            session_id=sid,
        )

        types = {g.type for g in gaps}
        assert types == {"context_required"}, (
            f"agent without adaptive_inputs must skip D2; got types {types}"
        )
    finally:
        sqli.adaptive_inputs = original


def test_detect_coverage_gaps_unknown_agent_raises_key_error(tmp_path: Path) -> None:
    """Unknown agent_name surfaces as KeyError (distinct from ValueError for
    malformed staging)."""
    engine = ScanEngine.from_defaults()
    with pytest.raises(KeyError, match="not in registry"):
        engine.detect_coverage_gaps(
            agent_name="bogus-agent",
            project_root=tmp_path,
            session_id="whatever",
        )


def test_detect_coverage_gaps_mcp_tool_dispatches_correctly(tmp_path: Path) -> None:
    """End-to-end through server.py dispatch: tool returns a dict with
    coverage_gaps array of serialized gap dicts."""
    _write_d2_fixture(tmp_path)
    engine = ScanEngine.from_defaults()

    result = _dispatch_tool(
        engine,
        "detect_coverage_gaps",
        {
            "agent_name": "sqli",
            "project_root": str(tmp_path),
            "session_id": "empty",
        },
    )

    assert "coverage_gaps" in result
    assert isinstance(result["coverage_gaps"], list)
    assert all(isinstance(g, dict) for g in result["coverage_gaps"])
    types = {g["type"] for g in result["coverage_gaps"]}
    assert "unresolved_sink" in types


def test_detect_coverage_gaps_mcp_tool_unknown_agent_raises(tmp_path: Path) -> None:
    """KeyError propagates through the MCP dispatch — the outer MCP transport
    layer surfaces it as a tool error, not a silent empty result."""
    engine = ScanEngine.from_defaults()
    with pytest.raises(KeyError):
        _dispatch_tool(
            engine,
            "detect_coverage_gaps",
            {
                "agent_name": "bogus-agent",
                "project_root": str(tmp_path),
                "session_id": "whatever",
            },
        )


def test_finalize_scan_results_includes_coverage_gaps_when_adaptive_session(
    tmp_path: Path,
) -> None:
    """Full E2E: record context-required match + accumulate finding + finalize.
    The response carries `coverage_gaps` populated from both D1 (staged
    matches) and D2 (agent's adaptive_inputs + AST walk).
    """
    _write_d2_fixture(tmp_path)
    engine = ScanEngine.from_defaults()

    rec = engine.record_context_required_match(
        project_root=tmp_path,
        match={
            "agent": "sqli",
            "file": "handler.py",
            "line": 3,
            "pattern": "any-raw-method-check",
        },
        session_id=None,
    )
    sid = rec["session_id"]

    # Must have a finding staged so finalize proceeds past read_for_finalize.
    engine.accumulate_findings(
        project_root=tmp_path,
        findings_chunk=[_make_finding("sqli-001")],
        session_id=sid,
    )

    result = engine.finalize_scan_results(
        project_root=tmp_path,
        session_id=sid,
        agent_names=["sqli"],
    )

    assert "coverage_gaps" in result, (
        "adaptive-capable agent must surface coverage_gaps in finalize response"
    )
    gaps = result["coverage_gaps"]
    assert isinstance(gaps, list)
    types = {g["type"] for g in gaps}
    assert "context_required" in types, "D1 gap missing from finalize response"
    assert "unresolved_sink" in types, "D2 gap missing from finalize response"


def test_finalize_scan_results_omits_coverage_gaps_when_non_adaptive(
    tmp_path: Path,
) -> None:
    """Backward compat: a scan with neither staged context-required matches
    nor an adaptive-capable agent MUST omit `coverage_gaps` from the
    response entirely (not empty list — absent), so non-adaptive scans
    see no schema change.
    """
    engine = ScanEngine.from_defaults()

    # Opt all 4 shipped agents out of adaptive_inputs for the duration of
    # this test so the finalize response has no D2 signal.
    opted_out: list = []
    for name in ("sqli", "cmdi", "ssti", "xss"):
        a = engine._registry.get_agent(name)
        if a is not None:
            opted_out.append((a, a.adaptive_inputs))
            a.adaptive_inputs = None

    try:
        acc = engine.accumulate_findings(
            project_root=tmp_path,
            findings_chunk=[_make_finding("sqli-001")],
            session_id=None,
        )
        result = engine.finalize_scan_results(
            project_root=tmp_path,
            session_id=acc["session_id"],
            agent_names=["sqli"],
        )
        assert "coverage_gaps" not in result, (
            "non-adaptive scan must NOT carry coverage_gaps key "
            "(backward compat — absent, not empty)"
        )
    finally:
        for agent, original in opted_out:
            agent.adaptive_inputs = original


def test_finalize_scan_results_does_not_duplicate_d1_gaps_across_agents(
    tmp_path: Path,
) -> None:
    """C1 regression: one recorded match + multi-agent finalize must NOT
    produce duplicate D1 gaps. D1 runs once globally (matches already
    carry their own `agent` attribution); D2 runs per-agent.

    Reproduces the pre-fix bug where looping `detect_coverage_gaps` per
    agent in ``agent_names`` would re-emit every recorded match once per
    loop iteration — a realistic multi-agent run
    (``agent_names=["sqli","cmdi","ssti","xss"]``) would 4x the D1 counts
    downstream in T17/T18 consumers.
    """
    engine = ScanEngine.from_defaults()

    # Record a SINGLE context-required match for sqli.
    rec = engine.record_context_required_match(
        project_root=tmp_path,
        match={
            "agent": "sqli",
            "file": "handler.py",
            "line": 42,
            "pattern": "raw-sql-single-match",
        },
        session_id=None,
    )
    sid = rec["session_id"]

    # Stage a finding so finalize proceeds past `read_for_finalize`.
    engine.accumulate_findings(
        project_root=tmp_path,
        findings_chunk=[_make_finding("sqli-001")],
        session_id=sid,
    )

    # Finalize across MULTIPLE agents — the realistic injection-input-
    # handling adaptive path.
    result = engine.finalize_scan_results(
        project_root=tmp_path,
        session_id=sid,
        agent_names=["sqli", "cmdi", "ssti", "xss"],
    )

    assert "coverage_gaps" in result
    d1_gaps = [g for g in result["coverage_gaps"] if g["type"] == "context_required"]
    assert len(d1_gaps) == 1, (
        f"C1 regression — one recorded match must yield exactly ONE D1 gap "
        f"regardless of agent_names cardinality; got {len(d1_gaps)} gaps: "
        f"{d1_gaps!r}"
    )
    # The lone D1 gap is attributed to the recording agent, not any other
    # agent in agent_names.
    assert d1_gaps[0]["agent"] == "sqli"


def test_detect_coverage_gaps_filters_matches_by_agent_name(
    tmp_path: Path,
) -> None:
    """Per-agent contract: `detect_coverage_gaps(agent_name=X)` must return
    ONLY D1 gaps whose recorded agent is X. A match recorded for sqli
    must not surface in a cmdi query — even though both share staging.
    """
    engine = ScanEngine.from_defaults()

    rec = engine.record_context_required_match(
        project_root=tmp_path,
        match={
            "agent": "sqli",
            "file": "handler.py",
            "line": 7,
            "pattern": "sqli-only-pattern",
        },
        session_id=None,
    )
    sid = rec["session_id"]

    # Query with agent_name="cmdi" — no cmdi matches recorded, so D1
    # must yield zero entries. (D2 for cmdi may still fire if the tmp
    # dir had sink-shaped calls — we didn't write any here, so it won't.)
    cmdi_gaps = engine.detect_coverage_gaps(
        agent_name="cmdi",
        project_root=tmp_path,
        session_id=sid,
    )
    cmdi_d1 = [g for g in cmdi_gaps if g.type == "context_required"]
    assert cmdi_d1 == [], (
        "per-agent detect_coverage_gaps must filter D1 matches by agent_name; "
        f"cmdi query returned {len(cmdi_d1)} D1 gaps from sqli's match"
    )

    # Query with agent_name="sqli" — still sees the recorded sqli match.
    sqli_gaps = engine.detect_coverage_gaps(
        agent_name="sqli",
        project_root=tmp_path,
        session_id=sid,
    )
    sqli_d1 = [g for g in sqli_gaps if g.type == "context_required"]
    assert len(sqli_d1) == 1
    assert sqli_d1[0].agent == "sqli"


def test_finalize_includes_coverage_gaps_cached_on_second_call(
    tmp_path: Path,
) -> None:
    """Idempotency: the cached finalize result (returned on second call)
    carries the same `coverage_gaps` field as the first call."""
    _write_d2_fixture(tmp_path)
    engine = ScanEngine.from_defaults()

    rec = engine.record_context_required_match(
        project_root=tmp_path,
        match={
            "agent": "sqli",
            "file": "handler.py",
            "line": 3,
            "pattern": "pattern_x",
        },
        session_id=None,
    )
    sid = rec["session_id"]
    engine.accumulate_findings(
        project_root=tmp_path,
        findings_chunk=[_make_finding("sqli-001")],
        session_id=sid,
    )

    first = engine.finalize_scan_results(
        project_root=tmp_path, session_id=sid, agent_names=["sqli"]
    )
    second = engine.finalize_scan_results(
        project_root=tmp_path, session_id=sid, agent_names=["sqli"]
    )

    # Cached result is byte-identical — same coverage_gaps present both times.
    assert first == second
    assert "coverage_gaps" in first
    assert "coverage_gaps" in second
