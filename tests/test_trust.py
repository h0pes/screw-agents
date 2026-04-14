"""Unit tests for screw_agents.trust — signing, verification, canonicalization."""

from __future__ import annotations

import json

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


def test_canonicalize_exclusion_changes_when_signature_version_changes():
    """signature_version is part of the signed content — flipping it must
    invalidate the signature. Prevents silent version downgrade attacks where
    an attacker changes `signature_version: 2` back to `1` to exploit a
    weaker v1 verifier.
    """
    a = _sample_exclusion()
    b = _sample_exclusion()
    b.signature_version = 2
    assert canonicalize_exclusion(a) != canonicalize_exclusion(b)


def test_canonicalize_exclusion_changes_when_content_changes():
    a = _sample_exclusion()
    b = _sample_exclusion()
    b.reason = "different reason"
    assert canonicalize_exclusion(a) != canonicalize_exclusion(b)


def test_canonicalize_exclusion_keys_are_sorted():
    """Regression guard: canonical JSON must use sort_keys=True and compact separators.

    Parse the canonical bytes and re-serialize with explicit flags; if the
    canonicalizer ever drops sort_keys or separators, this test will fail.
    """
    excl = _sample_exclusion()
    canonical = canonicalize_exclusion(excl)
    parsed = json.loads(canonical.decode("utf-8"))
    reserialized = json.dumps(
        parsed, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    assert canonical == reserialized


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


def test_canonicalize_script_handles_unicode():
    """ensure_ascii=False is contractual — non-ASCII content must serialize as
    UTF-8 bytes, not \\uXXXX escapes. A future regression that removes
    ensure_ascii=False (or changes it to True) would silently break signatures
    for any exclusion or script metadata containing non-ASCII content.
    """
    out = canonicalize_script(source="x", meta={"name": "тест", "emoji": "🔒"})
    # Non-ASCII bytes appear in UTF-8 form
    assert "тест".encode("utf-8") in out
    assert "🔒".encode("utf-8") in out
    # No \\u escape sequences leaked into the canonical form
    assert b"\\u" not in out
    # Round-trip: canonical bytes must be valid UTF-8 JSON with the original characters
    parsed = json.loads(out.decode("utf-8"))
    assert parsed["meta"]["name"] == "тест"
    assert parsed["meta"]["emoji"] == "🔒"
