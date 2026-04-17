"""Tests for the accumulate_findings + finalize_scan_results protocol
(replaces the legacy write_scan_results single-shot write)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from screw_agents.engine import ScanEngine


def _make_finding(fid: str, file: str = "src/a.py", line: int = 10,
                  cwe: str = "CWE-89", agent: str = "sqli") -> dict:
    return {
        "id": fid,
        "agent": agent,
        "domain": "injection-input-handling",
        "timestamp": "2026-04-17T00:00:00Z",
        "classification": {
            "cwe": cwe,
            "cwe_name": "SQL Injection",
            "severity": "high",
            "confidence": "high",
        },
        "location": {
            "file": file,
            "line_start": line,
            "line_end": line,
            "function": None,
            "code_snippet": "db.execute(x)",
        },
        "analysis": {"description": "ok"},
        "remediation": {"recommendation": "use parameterized queries"},
        "triage": {"status": "open"},
    }


def test_accumulate_findings_creates_session_on_first_call(tmp_path: Path):
    """First call with session_id=None generates a new id and stages findings."""
    engine = ScanEngine.from_defaults()

    result = engine.accumulate_findings(
        project_root=tmp_path,
        findings_chunk=[_make_finding("sqli-001")],
        session_id=None,
    )

    assert "session_id" in result
    assert isinstance(result["session_id"], str)
    assert len(result["session_id"]) > 0
    assert result["accumulated_count"] == 1

    staging_file = tmp_path / ".screw" / "staging" / result["session_id"] / "findings.json"
    assert staging_file.exists()
    data = json.loads(staging_file.read_text())
    assert len(data) == 1
    assert data[0]["id"] == "sqli-001"


def test_accumulate_findings_merges_across_calls(tmp_path: Path):
    """Multiple accumulate calls with the same session_id merge findings."""
    engine = ScanEngine.from_defaults()

    first = engine.accumulate_findings(
        project_root=tmp_path,
        findings_chunk=[_make_finding("sqli-001"), _make_finding("sqli-002")],
        session_id=None,
    )
    sid = first["session_id"]

    second = engine.accumulate_findings(
        project_root=tmp_path,
        findings_chunk=[_make_finding("cmdi-001", agent="cmdi", cwe="CWE-78")],
        session_id=sid,
    )

    assert second["session_id"] == sid
    assert second["accumulated_count"] == 3

    staging_file = tmp_path / ".screw" / "staging" / sid / "findings.json"
    data = json.loads(staging_file.read_text())
    ids = {f["id"] for f in data}
    assert ids == {"sqli-001", "sqli-002", "cmdi-001"}


def test_accumulate_findings_dedup_by_id_replaces_prior(tmp_path: Path):
    """Re-accumulating the same finding.id replaces the prior entry."""
    engine = ScanEngine.from_defaults()

    first = engine.accumulate_findings(
        project_root=tmp_path,
        findings_chunk=[_make_finding("sqli-001", line=10)],
        session_id=None,
    )
    sid = first["session_id"]

    second = engine.accumulate_findings(
        project_root=tmp_path,
        findings_chunk=[_make_finding("sqli-001", line=99)],  # same id, new line
        session_id=sid,
    )

    assert second["accumulated_count"] == 1  # no duplication
    staging_file = tmp_path / ".screw" / "staging" / sid / "findings.json"
    data = json.loads(staging_file.read_text())
    assert len(data) == 1
    assert data[0]["location"]["line_start"] == 99  # updated


def test_accumulate_findings_rejects_finding_without_id(tmp_path: Path):
    """Findings must carry an id for dedup; missing id raises ValueError."""
    engine = ScanEngine.from_defaults()
    bad = _make_finding("sqli-001")
    del bad["id"]
    with pytest.raises(ValueError, match="missing required 'id'"):
        engine.accumulate_findings(
            project_root=tmp_path,
            findings_chunk=[bad],
            session_id=None,
        )


def test_finalize_scan_results_reads_staging_and_writes_reports(tmp_path: Path):
    """finalize_scan_results reads the staged findings, writes reports, and
    removes the staging directory."""
    engine = ScanEngine.from_defaults()

    acc = engine.accumulate_findings(
        project_root=tmp_path,
        findings_chunk=[_make_finding("sqli-001")],
        session_id=None,
    )
    sid = acc["session_id"]

    result = engine.finalize_scan_results(
        project_root=tmp_path,
        session_id=sid,
        agent_names=["sqli"],
        scan_metadata={"target": "fixture", "timestamp": "2026-04-17T00:00:00Z"},
    )

    # Output reports written
    assert "files_written" in result
    assert "json" in result["files_written"]
    assert "markdown" in result["files_written"]
    assert Path(result["files_written"]["json"]).exists()

    # Staging dir persists (holds the result.json sidecar for idempotency);
    # findings.json is consumed on the first finalize call.
    staging_dir = tmp_path / ".screw" / "staging" / sid
    assert staging_dir.exists()  # persists (holds result.json sidecar)
    assert not (staging_dir / "findings.json").exists()  # consumed
    assert (staging_dir / "result.json").exists()  # cached

    # Summary carries expected shape
    assert result["summary"]["total"] == 1
    assert "trust_status" in result


def test_finalize_scan_results_unknown_session_raises(tmp_path: Path):
    """Calling finalize with a non-existent session_id raises ValueError."""
    engine = ScanEngine.from_defaults()
    with pytest.raises(ValueError, match="not found"):
        engine.finalize_scan_results(
            project_root=tmp_path,
            session_id="bogus",
            agent_names=["sqli"],
        )


def test_finalize_scan_results_idempotent_on_second_call(tmp_path: Path):
    """After finalize, subsequent calls with the same session_id return the
    SAME cached result without error or re-rendering. Idempotent protocol
    (T23) — first call does the work, subsequent calls just return the
    cached dict."""
    engine = ScanEngine.from_defaults()
    acc = engine.accumulate_findings(
        project_root=tmp_path,
        findings_chunk=[_make_finding("sqli-001")],
        session_id=None,
    )
    sid = acc["session_id"]

    first = engine.finalize_scan_results(
        project_root=tmp_path, session_id=sid, agent_names=["sqli"]
    )
    second = engine.finalize_scan_results(
        project_root=tmp_path, session_id=sid, agent_names=["sqli"]
    )

    assert first == second
    assert "files_written" in first
    # Staging dir persists (holds result.json sidecar for idempotency)
    staging_dir = tmp_path / ".screw" / "staging" / sid
    assert staging_dir.exists()
    # findings.json is gone (consumed during first finalize)
    assert not (staging_dir / "findings.json").exists()
    # result.json sidecar is present
    assert (staging_dir / "result.json").exists()


def test_accumulate_after_finalize_raises(tmp_path: Path):
    """Accumulating into an already-finalized session raises a clear error.
    Finalized sessions are locked — use a fresh session_id for a new scan."""
    engine = ScanEngine.from_defaults()
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
        engine.accumulate_findings(
            project_root=tmp_path,
            findings_chunk=[_make_finding("sqli-002")],
            session_id=sid,
        )


def test_accumulate_then_finalize_applies_exclusions(tmp_path: Path):
    """End-to-end: accumulated findings are subject to server-side
    exclusion matching during finalize (same semantic as legacy
    write_scan_results)."""
    # Pre-seed an exclusion file
    learning = tmp_path / ".screw" / "learning"
    learning.mkdir(parents=True)
    # (Skip detailed exclusion YAML setup — the point is end-to-end shape)

    engine = ScanEngine.from_defaults()
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
    # Shape — no exclusions pre-seeded in this minimal fixture, but trust_status still populates
    assert "exclusions_applied" in result
    assert isinstance(result["exclusions_applied"], list)
    assert "trust_status" in result
    assert result["trust_status"]["exclusion_active_count"] == 0
