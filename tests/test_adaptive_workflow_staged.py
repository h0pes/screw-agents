"""End-to-end integration test for the PR #6 staged adaptive-workflow.

Exercises the full stage -> review -> approve -> promote flow across
every MCP tool and engine method a real subagent invokes when a user
runs ``/screw:scan sqli --adaptive``. Asserts the C1 invariant: the
source bytes seen at stage time are byte-identical to the signed
artifact at custom-scripts/ post-promote.

If this test breaks, the C1 architectural closure has regressed — the
regeneration-after-approval vulnerability may have reopened.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest


pytestmark = pytest.mark.skipif(
    shutil.which("bwrap") is None and shutil.which("sandbox-exec") is None,
    reason="adaptive workflow requires bwrap (Linux) or sandbox-exec (macOS)",
)


def test_full_adaptive_workflow_with_staging_composition(tmp_path: Path) -> None:
    """PR #6 exit gate: full composition of the adaptive stage -> promote
    workflow.

    The 18 steps cover: trust-init, coverage-gap detection, hand-written
    adaptive script, lint, stage, registry audit, promote (with C1
    invariant lock), executor round-trip, accumulate + finalize with
    merge + Sources-line, verify_trust active count, per-script stale
    listing.

    Breakage diagnosis: the FIRST failing assertion pins the regressing
    integration boundary. If Step 12's invariant fails
    (`signed_py.read_text() == source`), C1 has regressed — do not merge.
    """
    from screw_agents.adaptive.signing import compute_script_sha256
    from screw_agents.adaptive.staging import resolve_registry_path
    from screw_agents.cli.init_trust import run_init_trust
    from screw_agents.engine import ScanEngine

    # Step 1: Seed project (IDENTICAL to T22).
    project = tmp_path / "project"
    project.mkdir()
    fixture_file = project / "dao.py"
    fixture_file.write_text(
        "# Fixture for PR #6 full-composition E2E test\n"
        "class QueryBuilder:\n"
        "    def execute_raw(self, sql):\n"
        "        pass\n"
        "\n"
        "def handle(request):\n"
        "    q = request.args.get('q')\n"
        "    # D1 — context_required drop:\n"
        "    cursor.execute(q)\n"
        "    # D2 — qb not in known_receivers, tainted arg:\n"
        "    self.qb.execute_raw(q)\n"
        "    # Adaptive target + YAML merge alignment:\n"
        "    QueryBuilder().execute_raw(q)\n"
    )

    # Step 2: init-trust (IDENTICAL).
    run_init_trust(
        project_root=project, name="C1 Tester", email="c1@example.com",
    )
    engine = ScanEngine.from_defaults()

    # Step 3: record_context_required_match (IDENTICAL).
    match_response = engine.record_context_required_match(
        project_root=project,
        match={"agent": "sqli", "file": "dao.py", "line": 9, "pattern": "any-raw-method-check"},
        session_id=None,
    )
    session_id = match_response["session_id"]

    # Step 4: accumulate_findings — YAML finding (IDENTICAL).
    yaml_finding = {
        "id": "sqli-001",
        "agent": "sqli",
        "domain": "injection-input-handling",
        "timestamp": "2026-04-20T10:00:00Z",
        "location": {"file": "dao.py", "line_start": 13, "line_end": 13},
        "classification": {
            "cwe": "CWE-89", "cwe_name": "SQL Injection",
            "severity": "high", "confidence": "medium",
        },
        "analysis": {"description": "YAML detection"},
        "remediation": {"recommendation": "use parameterized queries"},
    }
    acc_response = engine.accumulate_findings(
        project_root=project, findings_chunk=[yaml_finding], session_id=session_id,
    )
    assert acc_response["session_id"] == session_id

    # Step 5: detect_coverage_gaps (IDENTICAL to T22 — including D1+D2 assertions).
    gaps = engine.detect_coverage_gaps(
        agent_name="sqli", project_root=project, session_id=session_id,
    )
    assert isinstance(gaps, list)
    assert len(gaps) >= 1, f"expected at least 1 gap; got {len(gaps)}"

    # D1 check: the recorded context_required match surfaces as a gap.
    d1_gaps = [g for g in gaps if g.type == "context_required"]
    assert len(d1_gaps) == 1, (
        f"expected exactly 1 D1 gap (the one recorded in Step 3); "
        f"got {len(d1_gaps)}: {d1_gaps}"
    )
    d1 = d1_gaps[0]
    assert d1.agent == "sqli"
    assert d1.file == "dao.py"
    assert d1.line == 9
    assert d1.evidence["pattern"] == "any-raw-method-check"

    # D2 check: `self.qb.execute_raw(q)` (receiver "qb" not in sqli
    # known_receivers, tainted arg "q" from request.args.get) must
    # produce an unresolved_sink gap. Firm assertion — if this fails
    # either sqli.yaml's known_receivers/known_sources were edited
    # or gap_signal.detect_d2_unresolved_sink_gaps regressed.
    d2_gaps = [g for g in gaps if g.type == "unresolved_sink"]
    assert any(g.file == "dao.py" for g in d2_gaps), (
        f"expected D2 gap at dao.py (self.qb.execute_raw with tainted "
        f"arg); got D2 gaps: {d2_gaps}"
    )

    # Step 6: Hand-write adaptive script source (IDENTICAL).
    script_source = (
        "from screw_agents.adaptive import emit_finding, find_calls\n"
        "\n"
        "def analyze(project):\n"
        "    for call in find_calls(project, 'QueryBuilder.execute_raw'):\n"
        "        emit_finding(\n"
        "            cwe='CWE-89',\n"
        "            file=call.file,\n"
        "            line=call.line,\n"
        "            message='QueryBuilder.execute_raw sink (adaptive)',\n"
        "            severity='high',\n"
        "        )\n"
    )

    # Step 7: Layer 1 lint (IDENTICAL).
    lint_result = engine.lint_adaptive_script(source=script_source)
    assert lint_result["status"] == "pass"

    # Step 8: **NEW — stage_adaptive_script** (replaces T22's direct sign).
    meta = {
        "name": "qb-check",
        "created": "2026-04-20T10:00:00Z",
        "created_by": "c1@example.com",
        "domain": "injection-input-handling",
        "description": "E2E fixture: QueryBuilder.execute_raw verifier",
        "target_patterns": ["QueryBuilder.execute_raw"],
    }
    stage_response = engine.stage_adaptive_script(
        project_root=project,
        script_name="qb-check",
        source=script_source,
        meta=meta,
        session_id=session_id,
        target_gap={"type": "unresolved_sink", "file": "dao.py", "line": 13, "agent": "sqli"},
    )
    assert stage_response["status"] == "staged"
    assert stage_response["script_sha256"] == compute_script_sha256(script_source)

    # Step 9: Verify staging file exists AND has exact source.
    # Use engine-returned path — do not reconstruct layout manually.
    stage_py = Path(stage_response["stage_path"])
    assert stage_py.exists()
    assert stage_py.read_text(encoding="utf-8") == script_source

    # Step 10: Verify registry entry exists with correct sha.
    registry = resolve_registry_path(project)
    entries = [json.loads(l) for l in registry.read_text().splitlines() if l.strip()]
    staged_entries = [e for e in entries if e["event"] == "staged" and e["script_name"] == "qb-check"]
    assert len(staged_entries) == 1
    assert staged_entries[0]["script_sha256"] == stage_response["script_sha256"]

    # Step 11: promote_staged_script — sign + persist the staged bytes.
    # Asserts session_id threading, sha256 match against the staged
    # bytes, and the C1-specific promoted_via_fallback guard.
    promote_response = engine.promote_staged_script(
        project_root=project, script_name="qb-check", session_id=session_id,
    )
    assert promote_response["status"] == "signed"
    assert promote_response["signed_by"] == "c1@example.com"
    assert promote_response["session_id"] == session_id
    assert promote_response["sha256"] == compute_script_sha256(script_source), (
        "C1 INVARIANT VIOLATED at signing layer: promote_response['sha256'] "
        "does NOT match compute_script_sha256(script_source). The signed "
        "bytes differ from the hand-written source."
    )
    assert promote_response["promoted_via_fallback"] is False

    # Step 12: **C1 INVARIANT LOCK** — signed source == staged source == hand-written source.
    # Use engine-returned path — do not reconstruct layout manually.
    signed_py = Path(promote_response["script_path"])
    assert signed_py.exists()
    signed_content = signed_py.read_text(encoding="utf-8")
    assert signed_content == script_source, (
        "C1 INVARIANT VIOLATED: signed source bytes do NOT match "
        "hand-written staged source. The regeneration-after-approval "
        "vulnerability has reopened. DO NOT MERGE."
    )

    # Step 13: Staging files deleted; registry has 'promoted' event.
    assert not stage_py.exists()
    promoted_entries = [
        e for e in (json.loads(l) for l in registry.read_text().splitlines() if l.strip())
        if e["event"] == "promoted" and e["script_name"] == "qb-check"
    ]
    assert len(promoted_entries) == 1

    # Step 14: execute_adaptive_script (UNCHANGED from T22).
    exec_result = engine.execute_adaptive_script(
        project_root=project, script_name="qb-check", wall_clock_s=30,
    )
    assert exec_result["stale"] is False
    assert len(exec_result["findings"]) >= 1
    adaptive_finding = exec_result["findings"][0]
    assert adaptive_finding["location"]["file"] == "dao.py"
    assert adaptive_finding["location"]["line_start"] == 13
    assert adaptive_finding["classification"]["cwe"] == "CWE-89"
    assert adaptive_finding["agent"] == "adaptive_script:qb-check"

    # Step 15: Accumulate adaptive findings (IDENTICAL to T22).
    acc2 = engine.accumulate_findings(
        project_root=project,
        findings_chunk=exec_result["findings"],
        session_id=session_id,
    )
    assert acc2["session_id"] == session_id

    # Step 16: finalize_scan_results with coverage_gaps + T19 Sources line.
    finalize_response = engine.finalize_scan_results(
        project_root=project,
        session_id=session_id,
        agent_names=["sqli"],
        scan_metadata={"target": "dao.py", "timestamp": "2026-04-20T10:00:00Z"},
    )
    assert "coverage_gaps" in finalize_response
    md_path = Path(finalize_response["files_written"]["markdown"])
    md = md_path.read_text(encoding="utf-8")
    assert "**Sources:**" in md
    assert md.count("**Sources:**") == 1
    sources_line = next(l for l in md.splitlines() if "**Sources:**" in l)
    assert "sqli" in sources_line
    assert "adaptive_script:qb-check" in sources_line
    assert finalize_response["summary"]["total"] == 1

    # Step 17: verify_trust — script active (T20 regression still holds).
    trust_status = engine.verify_trust(project_root=project)
    assert trust_status["script_active_count"] == 1
    assert trust_status["script_quarantine_count"] == 0

    # Step 18: list_adaptive_scripts (I6 migration: engine method, not CLI).
    list_response = engine.list_adaptive_scripts(project_root=project)
    scripts = list_response["scripts"]
    assert len(scripts) == 1
    qb = scripts[0]
    assert qb["name"] == "qb-check"
    assert qb["validated"] is True
    assert qb["signed_by"] == "c1@example.com"
    assert qb["stale"] is False
