"""Smoke tests for ``screw_agents.adaptive.signing`` (Phase 3b T18a).

Thin coverage — the full sign-side + verify-side behavior is exercised in
``test_cli_validate_script.py`` (CLI consumer) and
``test_adaptive_executor.py::test_execute_script_valid_signature_path``
(C1 regression via executor). These tests pin the extracted helpers'
contracts so future refactors don't silently change the shape of the
returned dict or the sha256 encoding.
"""

from __future__ import annotations

import hashlib


def test_compute_script_sha256_matches_manual() -> None:
    """sha256 helper must match `hashlib.sha256(source.encode("utf-8")).hexdigest()`.

    This is the exact encoding + algorithm + hex output the executor's
    Layer 2 hash pin compares against on read. Drift here = every signed
    script fails hash pin.
    """
    from screw_agents.adaptive.signing import compute_script_sha256

    source = "from screw_agents.adaptive import emit_finding\ndef analyze(project): pass\n"
    expected = hashlib.sha256(source.encode("utf-8")).hexdigest()
    assert compute_script_sha256(source) == expected
    assert len(compute_script_sha256(source)) == 64  # hex digest


def test_build_signed_script_meta_routes_through_model() -> None:
    """The returned dict MUST have all AdaptiveScriptMeta defaults populated.

    Missing defaults in the returned dict → sign-side canonical bytes
    differ from verify-side canonical bytes (because the executor re-
    parses the YAML through AdaptiveScriptMeta and sees defaults re-
    injected) → every signed script fails Layer 3 verification.
    """
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
    )

    from screw_agents.adaptive.signing import (
        build_signed_script_meta,
        compute_script_sha256,
    )

    priv = Ed25519PrivateKey.generate()
    source = "def analyze(project): pass\n"
    sha = compute_script_sha256(source)
    meta_raw = {
        "name": "smoke",
        "created": "2026-04-19T10:00:00Z",
        "created_by": "marco@example.com",
        "domain": "injection-input-handling",
    }

    signed = build_signed_script_meta(
        meta_raw=meta_raw,
        source=source,
        current_sha256=sha,
        signer_email="marco@example.com",
        private_key=priv,
    )

    # Signing fields present and populated.
    assert signed["signed_by"] == "marco@example.com"
    assert isinstance(signed["signature"], str) and len(signed["signature"]) > 0
    assert signed["signature_version"] == 1
    assert signed["validated"] is True
    assert signed["sha256"] == sha
    # Defaults injected by AdaptiveScriptMeta (NOT present in meta_raw).
    # If any of these are missing, sign-side and verify-side will disagree.
    assert signed["last_used"] is None
    assert signed["findings_produced"] == 0
    assert signed["false_positive_rate"] is None
    # Caller-provided fields preserved.
    assert signed["name"] == "smoke"
    assert signed["domain"] == "injection-input-handling"


def test_build_signed_script_meta_schema_failure_raises_valueerror() -> None:
    """Missing required `name` field → the helper wraps ValidationError
    as a ValueError with a hint pointing at the schema."""
    import pytest
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
    )

    from screw_agents.adaptive.signing import build_signed_script_meta

    priv = Ed25519PrivateKey.generate()
    # Missing required `name`.
    bad_meta = {
        "created": "2026-04-19T10:00:00Z",
        "created_by": "marco@example.com",
        "domain": "injection-input-handling",
    }

    with pytest.raises(ValueError) as excinfo:
        build_signed_script_meta(
            meta_raw=bad_meta,
            source="def analyze(p): pass\n",
            current_sha256="0" * 64,
            signer_email="marco@example.com",
            private_key=priv,
        )

    msg = str(excinfo.value)
    assert "fails AdaptiveScriptMeta schema" in msg
    assert "Fix the YAML manually" in msg
