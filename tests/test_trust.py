"""Unit tests for screw_agents.trust — signing, verification, canonicalization."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from screw_agents.models import (
    Exclusion,
    ExclusionFinding,
    ExclusionScope,
)
from screw_agents.trust import (
    canonicalize_exclusion,
    canonicalize_script,
)


def _sample_exclusion(*, signed: bool = False) -> Exclusion:
    return Exclusion(
        id="fp-2026-04-14-001",
        created="2026-04-14T10:00:00Z",
        agent="sqli",
        finding=ExclusionFinding(
            file="src/services/user_service.py",
            line=42,
            code_pattern="db.text_search(*)",
            cwe="CWE-89",
        ),
        reason="uses parameterized internals",
        scope=ExclusionScope(type="pattern", pattern="db.text_search(*)"),
        signed_by="marco@example.com" if signed else None,
        signature="U1NIU0lH..." if signed else None,
    )


def test_canonicalize_exclusion_is_deterministic():
    excl = _sample_exclusion()
    out1 = canonicalize_exclusion(excl)
    out2 = canonicalize_exclusion(excl)
    assert out1 == out2
    assert isinstance(out1, bytes)


def test_canonicalize_exclusion_excludes_signature_fields():
    """Canonical form must not include signature-related fields; otherwise signing loops forever."""
    unsigned = _sample_exclusion(signed=False)
    signed = _sample_exclusion(signed=True)
    assert canonicalize_exclusion(unsigned) == canonicalize_exclusion(signed)


def test_canonicalize_exclusion_excludes_runtime_flags():
    """`quarantined` is a runtime flag, not part of the signed content."""
    excl = _sample_exclusion()
    excl_quarantined = _sample_exclusion()
    excl_quarantined.quarantined = True
    assert canonicalize_exclusion(excl) == canonicalize_exclusion(excl_quarantined)


def test_canonicalize_exclusion_changes_when_content_changes():
    a = _sample_exclusion()
    b = _sample_exclusion()
    b.reason = "different reason"
    assert canonicalize_exclusion(a) != canonicalize_exclusion(b)


def test_canonicalize_script_is_deterministic():
    source = "from screw_agents.adaptive import emit_finding\n\ndef analyze(project):\n    pass\n"
    meta = {
        "name": "test-script",
        "created": "2026-04-14T10:00:00Z",
        "target_patterns": ["QueryBuilder.execute"],
    }
    out1 = canonicalize_script(source=source, meta=meta)
    out2 = canonicalize_script(source=source, meta=meta)
    assert out1 == out2


def test_canonicalize_script_excludes_signature_keys():
    source = "def analyze(project): pass\n"
    meta_unsigned = {"name": "s", "target_patterns": ["x"]}
    meta_signed = {
        "name": "s",
        "target_patterns": ["x"],
        "signed_by": "marco@example.com",
        "signature": "U1NI...",
    }
    assert canonicalize_script(source=source, meta=meta_unsigned) == canonicalize_script(
        source=source, meta=meta_signed
    )
