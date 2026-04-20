"""End-to-end full-composition integration test for Phase 3b PR #5's
adaptive workflow.

This test exercises every MCP tool and engine method shipped in T13-T21
in sequence — the same sequence a real subagent would produce when a
user runs ``/screw:scan sqli --adaptive``. It is the PR #5 exit gate:
if any integration boundary across those tasks silently regresses,
this test breaks.

The test does NOT drive an actual LLM. Instead it HAND-WRITES the
adaptive script source (simulating what T18b's subagent prompt would
generate) and HAND-WRITES YAML findings (simulating what the YAML scan
would produce). This matches the plan's T22 approach — the generation
layer is a prompt-engineering concern validated elsewhere
(test_adaptive_subagent_prompts.py format-smoke tests).

Test composition order (mirrors `/screw:scan sqli --adaptive`):

  1. Seed project with a QueryBuilder fixture exercising D1 + D2 + merge
  2. init-trust (register local signing key for scripts + exclusions)
  3. Record a dropped context_required match (D1 producer, T16)
  4. Accumulate a YAML finding (simulates scan path, T16)
  5. detect_coverage_gaps → returns D1 (+ D2) gaps (T14/T15/T16)
  6. Hand-write the adaptive script source (simulates T18b subagent)
  7. lint_adaptive_script → status=pass (T18a Layer 1 pre-approval)
  8. sign_adaptive_script → status=signed (T18a fresh-script approve path)
  9. execute_adaptive_script → sandbox runs the signed script (PR #4 T12)
 10. Accumulate adaptive findings into the same session (T16 threading)
 11. finalize_scan_results → merged markdown + coverage_gaps (T16/T19)
 12. verify_trust → script_active_count=1 (T20 signing-count regression)
 13. list_adaptive_scripts → script present, stale=False (T21 per-script)

Breakage → diagnose by matching the failing assertion to the task it
exercises. The test is intentionally sequential so the FIRST failing
assertion pins the regressing integration boundary.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest


# Skip this entire module if no sandbox backend is available — bwrap on
# Linux or sandbox-exec on macOS. Same skip predicate as other adaptive
# integration tests that exercise execute_adaptive_script end-to-end.
pytestmark = pytest.mark.skipif(
    shutil.which("bwrap") is None and shutil.which("sandbox-exec") is None,
    reason="adaptive workflow requires bwrap (Linux) or sandbox-exec (macOS)",
)


def test_full_adaptive_workflow_composition(tmp_path: Path) -> None:
    """PR #5 exit gate: one test exercising every T13-T21 integration
    point in the exact order a real subagent would run them.

    If this test breaks, check the T13-C1 / T16-C1 / T18b-C1 bug classes:
    sign/verify canonical-bytes drift, session_id threading across
    accumulate/record/finalize, and augmentative-merge dedup keys. These
    are the integration patterns that have bitten this PR repeatedly
    across T13-T21 unit-test baselines.
    """
    from screw_agents.adaptive.signing import compute_script_sha256
    from screw_agents.cli.adaptive_cleanup import list_adaptive_scripts
    from screw_agents.cli.init_trust import run_init_trust
    from screw_agents.engine import ScanEngine

    # ------------------------------------------------------------------
    # Step 1: Seed project with a QueryBuilder fixture.
    # ------------------------------------------------------------------
    # Fixture layout (line numbers pinned by the string below — keep in
    # sync with the assertions further down; assertions reference lines
    # 9 (D1), 11 (D2), 13 (adaptive + YAML merge target)):
    #
    #   Line  9  cursor.execute(q)           — D1 context_required drop
    #   Line 11  self.qb.execute_raw(q)      — D2 unresolved_sink (qb ∉
    #                                           sqli.known_receivers)
    #   Line 13  QueryBuilder().execute_raw(q) — adaptive script finds
    #                                           this call via
    #                                           `find_calls(project,
    #                                           "QueryBuilder.execute_raw")`.
    #                                           After paren-strip the
    #                                           callee tokens are
    #                                           ["QueryBuilder",
    #                                            "execute_raw"], matching
    #                                           the pattern's trailing
    #                                           tokens exactly. This is
    #                                           also the line YAML's
    #                                           hand-written finding
    #                                           targets, so augmentative
    #                                           merge fires on
    #                                           (file, line_start, cwe)
    #                                           = ("dao.py", 13, "CWE-89").
    #
    # Flat file (no src/ nesting) so find_calls's relative path matches
    # "dao.py" literally — keeps gap.file assertion simple.
    project = tmp_path / "project"
    project.mkdir()
    fixture_file = project / "dao.py"
    fixture_file.write_text(
        "# Fixture for T22 full-composition E2E test\n"
        "class QueryBuilder:\n"
        "    def execute_raw(self, sql):\n"
        "        pass\n"
        "\n"
        "def handle(request):\n"
        "    q = request.args.get('q')\n"
        "    # D1 — context_required drop (YAML investigates, drops):\n"
        "    cursor.execute(q)\n"
        "    # D2 — qb not in sqli known_receivers, tainted arg:\n"
        "    self.qb.execute_raw(q)\n"
        "    # Adaptive target + YAML merge alignment:\n"
        "    QueryBuilder().execute_raw(q)\n"
    )

    # ------------------------------------------------------------------
    # Step 2: init-trust — register local Ed25519 key for BOTH
    # exclusion_reviewers AND script_reviewers. Required before
    # sign_adaptive_script can match the local key's fingerprint
    # (Model A identity check) to a configured reviewer.
    # ------------------------------------------------------------------
    run_init_trust(
        project_root=project,
        name="T22 Reviewer",
        email="t22@example.com",
    )

    # Single engine instance threaded through every tool call so the
    # in-process registry (populated from repo-root domains/) is shared.
    # sqli's adaptive_inputs YAML is required for D2; from_defaults()
    # reads it from the repo's domains/ dir.
    engine = ScanEngine.from_defaults()

    # ------------------------------------------------------------------
    # Step 3: Record a dropped context_required match (D1 producer side).
    # ------------------------------------------------------------------
    # First call with session_id=None → server generates a fresh id we
    # thread through every subsequent tool call in this scan session.
    # The YAML scan would call this once per investigated-and-dropped
    # context_required pattern match; we simulate a single drop at
    # line 9 (cursor.execute line).
    match_response = engine.record_context_required_match(
        project_root=project,
        match={
            "agent": "sqli",
            "file": "dao.py",
            "line": 9,
            "pattern": "any-raw-method-check",
        },
        session_id=None,
    )
    session_id = match_response["session_id"]
    assert isinstance(session_id, str) and len(session_id) > 0
    assert match_response["matches_recorded"] == 1

    # ------------------------------------------------------------------
    # Step 4: Accumulate a YAML finding (simulates the scan's emit path).
    # ------------------------------------------------------------------
    # This finding points at line 13 (QueryBuilder().execute_raw), CWE-89
    # — the SAME (file, line_start, cwe) tuple the adaptive script's
    # emit_finding will produce, so T19's augmentative merge fires at
    # finalize time. Uses the NESTED Finding shape (location.file,
    # classification.cwe) — flat-shape drafts in older plans are
    # incorrect and were a drift source in T19 and T22.
    yaml_finding = {
        "id": "sqli-001",
        "agent": "sqli",
        "domain": "injection-input-handling",
        "timestamp": "2026-04-20T10:00:00Z",
        "location": {
            "file": "dao.py",
            "line_start": 13,
            "line_end": 13,
        },
        "classification": {
            "cwe": "CWE-89",
            "cwe_name": "SQL Injection",
            "severity": "high",
            "confidence": "medium",
        },
        "analysis": {
            "description": (
                "Tainted user input flows into QueryBuilder.execute_raw "
                "(YAML detection)"
            ),
        },
        "remediation": {
            "recommendation": "use parameterized queries",
        },
    }
    acc_response = engine.accumulate_findings(
        project_root=project,
        findings_chunk=[yaml_finding],
        session_id=session_id,
    )
    assert acc_response["session_id"] == session_id
    assert acc_response["accumulated_count"] == 1

    # ------------------------------------------------------------------
    # Step 5: detect_coverage_gaps — returns D1 (always) + D2 (sqli has
    # adaptive_inputs in its shipped YAML, so D2 is attempted).
    # ------------------------------------------------------------------
    gaps = engine.detect_coverage_gaps(
        agent_name="sqli",
        project_root=project,
        session_id=session_id,
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

    # D2 check: `self.qb.execute_raw(q)` with receiver token "qb"
    # (not in sqli.known_receivers) + tainted arg "q" flowing from
    # `request.args.get(...)` must produce a D2 gap. This is a firm
    # assertion: sqli's shipped `known_receivers` (cursor, connection,
    # conn, Session, session, db, engine, client, pool, stmt, statement,
    # ps, pstmt, pdo, wpdb — see
    # domains/injection-input-handling/sqli.yaml) does NOT include "qb",
    # and "request.args" is in `known_sources`. If this assertion fails,
    # either the YAML's known_receivers / known_sources were edited OR
    # D2 (gap_signal.detect_d2_unresolved_sink_gaps) regressed.
    d2_gaps = [g for g in gaps if g.type == "unresolved_sink"]
    assert any(g.file == "dao.py" for g in d2_gaps), (
        f"expected D2 gap at dao.py (self.qb.execute_raw with tainted "
        f"arg); got D2 gaps: {d2_gaps}. Check sqli.yaml's "
        f"known_receivers (must NOT contain 'qb') and known_sources "
        f"(must contain 'request.args'), or D2 algorithm regression "
        f"in gap_signal.detect_d2_unresolved_sink_gaps."
    )

    # ------------------------------------------------------------------
    # Step 6: Hand-write the adaptive script source. Simulates what
    # T18b's subagent prompt would generate in response to one of the
    # gaps from Step 5 (the reviewer would pick the QueryBuilder one).
    # ------------------------------------------------------------------
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

    # ------------------------------------------------------------------
    # Step 7: Layer 1 pre-approval lint — the subagent shows the lint
    # result to the human reviewer as part of the 5-section review
    # BEFORE approval.
    # ------------------------------------------------------------------
    lint_result = engine.lint_adaptive_script(source=script_source)
    assert lint_result["status"] == "pass", (
        f"hand-written script should lint clean; got {lint_result}"
    )
    assert lint_result["violations"] == []

    # ------------------------------------------------------------------
    # Step 8: sign_adaptive_script — T18a fresh-script approve path.
    # This is the MCP tool the subagent invokes when the human types
    # `approve qb-check`. Distinct from T13's validate-script CLI
    # (which is the re-sign path for existing quarantined scripts).
    # ------------------------------------------------------------------
    # Meta dict omits AdaptiveScriptMeta default fields (last_used,
    # findings_produced, false_positive_rate, validated, signature,
    # signed_by, signature_version) — build_signed_script_meta fills
    # them in. This exercises the T13-C1 routing-through-the-model
    # discipline that keeps sign and verify canonical bytes aligned.
    sign_response = engine.sign_adaptive_script(
        project_root=project,
        script_name="qb-check",
        source=script_source,
        meta={
            "name": "qb-check",
            "created": "2026-04-20T10:00:00Z",
            "created_by": "t22@example.com",
            "domain": "injection-input-handling",
            "description": "E2E fixture: QueryBuilder.execute_raw verifier",
            "target_patterns": ["QueryBuilder.execute_raw"],
        },
        session_id=session_id,
    )
    assert sign_response["status"] == "signed", (
        f"sign_adaptive_script expected to succeed; got {sign_response}"
    )
    assert sign_response["signed_by"] == "t22@example.com"
    assert sign_response["session_id"] == session_id

    # Files landed where subsequent tools (execute, verify, list) expect.
    script_dir = project / ".screw" / "custom-scripts"
    persisted_py = script_dir / "qb-check.py"
    persisted_meta = script_dir / "qb-check.meta.yaml"
    assert persisted_py.exists()
    assert persisted_meta.exists()
    assert persisted_py.read_text() == script_source
    expected_sha = compute_script_sha256(script_source)
    assert sign_response["sha256"] == expected_sha

    # ------------------------------------------------------------------
    # Step 9: execute_adaptive_script — run under the full 7-layer
    # defense pipeline (AST lint, SHA-256 pin, Ed25519 signature, stale
    # check, sandbox launch, wall-clock kill, JSON-schema validation).
    # ------------------------------------------------------------------
    # skip_trust_checks is DELIBERATELY OMITTED (defaults False) so
    # Layers 2 + 3 actually run. This is the C1 regression lock: if
    # sign-side canonical bytes drift from verify-side, the signature
    # doesn't validate and Layer 3 raises SignatureFailure.
    #
    # Per T18b Deviation 1: execute_adaptive_script does NOT accept
    # session_id (the script is already on disk with its signed meta;
    # the session context is not needed for execution).
    exec_result = engine.execute_adaptive_script(
        project_root=project,
        script_name="qb-check",
        wall_clock_s=30,
    )

    # Shape matches test_execute_adaptive_script_tool.py's happy-path
    # assertions: dict with findings list and stale flag.
    assert exec_result["stale"] is False
    assert len(exec_result["findings"]) >= 1, (
        f"expected adaptive script to produce ≥1 finding for the "
        f"QueryBuilder.execute_raw call at line 13 in the fixture; "
        f"got {len(exec_result['findings'])}. "
        f"sandbox_result={exec_result.get('sandbox_result')!r}"
    )

    adaptive_finding = exec_result["findings"][0]
    # Adaptive findings are LIFTED by the executor (_parse_findings)
    # from the flat emit_finding dict into the nested Finding shape.
    # Assert via nested access — flat would silently pass if the lift
    # ever broke. agent label is "adaptive_script:<meta.name>".
    assert adaptive_finding["location"]["file"] == "dao.py"
    assert adaptive_finding["location"]["line_start"] == 13
    assert adaptive_finding["classification"]["cwe"] == "CWE-89"
    assert adaptive_finding["agent"] == "adaptive_script:qb-check"

    # ------------------------------------------------------------------
    # Step 10: Accumulate the adaptive findings into the SAME session.
    # ------------------------------------------------------------------
    # T16 session-threading discipline: YAML + adaptive findings from
    # the same --adaptive run land in the same staging session so
    # finalize can merge them via T19's augmentative-merge key
    # (file, line_start, cwe).
    acc2 = engine.accumulate_findings(
        project_root=project,
        findings_chunk=exec_result["findings"],
        session_id=session_id,
    )
    assert acc2["session_id"] == session_id
    # YAML finding (id=sqli-001) + adaptive finding (id=content-hash
    # from executor's _compute_finding_id). Different ids, so both
    # survive accumulate-dedup. Merge happens at finalize, not here.
    assert acc2["accumulated_count"] >= 2

    # ------------------------------------------------------------------
    # Step 11: finalize_scan_results — renders JSON + Markdown, applies
    # augmentative merge (T19), exposes coverage_gaps (T16).
    # ------------------------------------------------------------------
    finalize_response = engine.finalize_scan_results(
        project_root=project,
        session_id=session_id,
        agent_names=["sqli"],
        scan_metadata={
            "target": "dao.py",
            "timestamp": "2026-04-20T10:00:00Z",
        },
    )

    # T16: coverage_gaps MUST be present when the session had
    # context_required_matches (regardless of whether the scan's
    # agent_names include an adaptive-capable agent). Omission here
    # would hide D1 signal from the subagent's downstream summary.
    assert "coverage_gaps" in finalize_response, (
        "coverage_gaps field missing from finalize response — "
        "T16 regression (inclusion rule: present when staged matches "
        "exist OR an adaptive-capable agent is in agent_names)"
    )
    d1_in_response = [
        g for g in finalize_response["coverage_gaps"]
        if g["type"] == "context_required"
    ]
    assert len(d1_in_response) >= 1, (
        f"expected at least 1 D1 gap in finalize coverage_gaps; "
        f"got {finalize_response['coverage_gaps']}"
    )

    # T19: YAML + adaptive findings align on (dao.py, 13, CWE-89) and
    # MUST merge into a single primary finding with merged_from_sources
    # populated. The markdown formatter surfaces this via a
    # "**Sources:**" line listing both source agents. Absence of this
    # line indicates T19's augmentative-merge regressed OR the
    # formatter's merged_from_sources branch stopped emitting the line.
    md_path = Path(finalize_response["files_written"]["markdown"])
    md_content = md_path.read_text(encoding="utf-8")
    assert "**Sources:**" in md_content, (
        f"**Sources:** line missing from merged-finding markdown at "
        f"{md_path} — T19 augmentative merge regression. "
        f"YAML finding (dao.py:13 CWE-89, agent=sqli) and adaptive "
        f"finding (dao.py:13 CWE-89, agent=adaptive_script:qb-check) "
        f"should bucket by (file, line_start, cwe) and render one "
        f"primary with a Sources line."
    )
    # Both source agents must appear in the Sources list.
    assert "sqli" in md_content
    assert "adaptive_script:qb-check" in md_content, (
        "adaptive source label `adaptive_script:qb-check` missing from "
        "merged markdown — executor's _parse_findings agent label "
        "(`adaptive_script:<meta.name>`) or T19's source-list "
        "formatter (`<agent> (<severity>)`) may have regressed."
    )

    # ------------------------------------------------------------------
    # Step 12: verify_trust — T20 regression: a script signed via
    # sign_adaptive_script MUST round-trip through verify_script and
    # count as ACTIVE (not quarantined). Before T20 this was stubbed.
    # ------------------------------------------------------------------
    trust_status = engine.verify_trust(project_root=project)
    assert trust_status["script_active_count"] == 1, (
        f"signed script should count as active; got {trust_status}. "
        f"If this is 0 and script_quarantine_count is 1, T20's "
        f"signing round-trip regressed — verify_script rejected a "
        f"signature sign_adaptive_script just produced."
    )
    assert trust_status["script_quarantine_count"] == 0

    # ------------------------------------------------------------------
    # Step 13: list_adaptive_scripts — T21 per-script stale detection.
    # ------------------------------------------------------------------
    # target_patterns=["QueryBuilder.execute_raw"] and the fixture's
    # line 13 has a literal `QueryBuilder().execute_raw(q)` call.
    # After find_calls's paren-strip, callee tokens are
    # ["QueryBuilder", "execute_raw"], which match the pattern exactly
    # → find_calls yields ≥1 hit → _check_stale returns (False, None).
    scripts = list_adaptive_scripts(project)
    assert len(scripts) == 1, (
        f"expected 1 script in list; got {len(scripts)}: {scripts}"
    )
    qb = scripts[0]
    assert qb["name"] == "qb-check"
    assert qb["validated"] is True
    assert qb["signed_by"] == "t22@example.com"
    assert qb["stale"] is False, (
        f"script should NOT be stale — QueryBuilder.execute_raw has a "
        f"live call at dao.py:13. Got stale_reason={qb.get('stale_reason')}. "
        f"If this fails, either _check_stale's find_calls iteration "
        f"regressed OR the fixture no longer contains a literal "
        f"QueryBuilder().execute_raw(...) call site."
    )
    assert qb["stale_reason"] is None
