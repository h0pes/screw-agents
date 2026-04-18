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
