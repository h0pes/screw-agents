"""Unit tests for screw_agents.adaptive.findings."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from screw_agents.adaptive.findings import (
    FindingBuffer,
    emit_finding,
    get_buffer,
    reset_buffer,
)


def test_emit_finding_appends_to_buffer(tmp_path: Path):
    reset_buffer()
    emit_finding(
        cwe="CWE-89",
        file="src/a.py",
        line=10,
        message="SQLi via QueryBuilder",
        severity="high",
    )
    buf = get_buffer()
    assert len(buf.findings) == 1
    assert buf.findings[0]["cwe"] == "CWE-89"
    assert buf.findings[0]["severity"] == "high"


def test_emit_finding_validates_severity():
    reset_buffer()
    with pytest.raises(ValueError, match="severity"):
        emit_finding(
            cwe="CWE-89",
            file="src/a.py",
            line=10,
            message="test",
            severity="INVALID",
        )
    # Validation must precede mutation: bad call must not pollute buffer.
    assert len(get_buffer().findings) == 0


def test_emit_finding_validates_cwe_format():
    reset_buffer()
    with pytest.raises(ValueError, match="CWE"):
        emit_finding(
            cwe="89",  # missing "CWE-" prefix
            file="src/a.py",
            line=10,
            message="test",
            severity="high",
        )
    # Validation must precede mutation: bad call must not pollute buffer.
    assert len(get_buffer().findings) == 0


def test_finding_buffer_serialize_to_json():
    reset_buffer()
    emit_finding(
        cwe="CWE-89",
        file="src/a.py",
        line=10,
        message="test",
        severity="high",
    )
    emit_finding(
        cwe="CWE-78",
        file="src/b.py",
        line=20,
        message="cmdi",
        severity="medium",
    )
    buf = get_buffer()
    as_json = buf.to_json()
    parsed = json.loads(as_json)
    assert isinstance(parsed, list)
    assert len(parsed) == 2


def test_emit_finding_rejects_non_positive_line():
    """line=0 and line=-1 both raise ValueError. Regression-pin for the existing
    `line < 1` validation that the spec tests didn't directly cover."""
    reset_buffer()
    for bad in (0, -1, -100):
        with pytest.raises(ValueError, match="line"):
            emit_finding(
                cwe="CWE-89",
                file="src/a.py",
                line=bad,
                message="t",
                severity="high",
            )
        assert len(get_buffer().findings) == 0


def test_emit_finding_rejects_bool_line():
    """line=True / line=False raise ValueError even though isinstance(True, int)
    is True in Python. Pins the explicit bool exclusion added during T5 fix-up."""
    reset_buffer()
    for bad in (True, False):
        with pytest.raises(ValueError, match="line"):
            emit_finding(
                cwe="CWE-89",
                file="src/a.py",
                line=bad,
                message="t",
                severity="high",
            )
        assert len(get_buffer().findings) == 0


def test_flush_to_path_round_trip(tmp_path: Path):
    """flush_to_path writes parseable JSON that round-trips through the buffer.
    Currently the only test of flush_to_path."""
    reset_buffer()
    emit_finding(
        cwe="CWE-89",
        file="src/a.py",
        line=10,
        message="t",
        severity="high",
        code_snippet="db.execute(q)",
        column=4,
    )
    out_path = tmp_path / "findings.json"
    from screw_agents.adaptive.findings import flush_to_path
    flush_to_path(str(out_path))
    parsed = json.loads(out_path.read_text(encoding="utf-8"))
    assert isinstance(parsed, list)
    assert len(parsed) == 1
    # All 7 fields the spec promises round-trip.
    f = parsed[0]
    assert f["cwe"] == "CWE-89"
    assert f["file"] == "src/a.py"
    assert f["line"] == 10
    assert f["column"] == 4
    assert f["message"] == "t"
    assert f["severity"] == "high"
    assert f["code_snippet"] == "db.execute(q)"


def test_emit_finding_preserves_emit_order():
    """Findings appear in the buffer in the order emit_finding was called.
    Test 4 (`test_finding_buffer_serialize_to_json`) only checks count."""
    reset_buffer()
    for i in range(5):
        emit_finding(
            cwe="CWE-89",
            file=f"src/a{i}.py",
            line=i + 1,
            message=f"finding {i}",
            severity="high",
        )
    buf = get_buffer()
    assert [f["file"] for f in buf.findings] == [f"src/a{i}.py" for i in range(5)]
    assert [f["line"] for f in buf.findings] == list(range(1, 6))
