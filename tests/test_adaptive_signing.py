"""Smoke tests for ``screw_agents.adaptive.signing`` (Phase 3b T18a/T2).

Thin coverage — the full sign-side + verify-side behavior is exercised in
``test_cli_validate_script.py`` (CLI consumer) and
``test_adaptive_executor.py::test_execute_script_valid_signature_path``
(C1 regression via executor). These tests pin the extracted helpers'
contracts so future refactors don't silently change the shape of the
returned dict or the sha256 encoding.

T2 additions:
- Locking / delegation tests for Option D ``_sign_script_bytes`` helper.
- Regex regression tests (I-new-1 trailing-newline + I-new-2 coverage gaps).
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest
import yaml


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


# ---------------------------------------------------------------------------
# T2 — Option D locking / delegation tests
# ---------------------------------------------------------------------------


def test_sign_script_bytes_is_defined_in_signing_module() -> None:
    """Locking: _sign_script_bytes lives in adaptive.signing, not engine.

    If this test breaks, the Option D refactor has regressed — the shared
    helper got moved back inline into engine.promote_staged_script.
    """
    from screw_agents.adaptive import signing

    assert hasattr(signing, "_sign_script_bytes"), (
        "_sign_script_bytes missing from adaptive/signing.py — "
        "Option D shared helper regressed"
    )


def test_sign_script_bytes_canonical_bytes_stable(tmp_path: Path) -> None:
    """Call _sign_script_bytes twice with identical inputs in two separate
    project dirs; verify sha256 and dict fields (minus the randomized
    Ed25519 signature) are byte-for-byte identical.
    """
    from screw_agents.adaptive.signing import _sign_script_bytes
    from screw_agents.cli.init_trust import run_init_trust

    source = (
        "from screw_agents.adaptive import emit_finding\n"
        "def analyze(project):\n"
        "    pass\n"
    )
    meta = {
        "name": "stable-test",
        "created": "2026-04-21T00:00:00Z",
        "created_by": "marco@example.com",
        "domain": "injection-input-handling",
        "description": "stability test",
        "target_patterns": [],
    }

    # Two separate project dirs so the "already exists" collision check
    # does not fire on the second call.
    project_a = tmp_path / "a"
    project_b = tmp_path / "b"
    project_a.mkdir()
    project_b.mkdir()

    run_init_trust(project_root=project_a, name="Marco", email="marco@example.com")
    run_init_trust(project_root=project_b, name="Marco", email="marco@example.com")

    result_a = _sign_script_bytes(
        project_root=project_a,
        script_name="stable-test",
        source=source,
        meta_dict=dict(meta),
        session_id="sess-1",
    )
    result_b = _sign_script_bytes(
        project_root=project_b,
        script_name="stable-test",
        source=source,
        meta_dict=dict(meta),
        session_id="sess-2",
    )

    assert result_a["status"] == "signed", result_a
    assert result_b["status"] == "signed", result_b

    # sha256 must be identical (deterministic).
    assert result_a["sha256"] == result_b["sha256"]
    assert result_a["signed_by"] == result_b["signed_by"]

    # Load both written meta files and compare non-signature fields.
    meta_a = yaml.safe_load(Path(result_a["meta_path"]).read_text(encoding="utf-8"))
    meta_b = yaml.safe_load(Path(result_b["meta_path"]).read_text(encoding="utf-8"))

    # Remove the randomized signature before comparison (Ed25519 is
    # non-deterministic; comparing signatures would always differ).
    for m in (meta_a, meta_b):
        m.pop("signature", None)

    assert meta_a == meta_b, (
        "Non-signature meta fields differ between two identical sign calls — "
        "canonical bytes are not stable."
    )

    # Source bytes must be identical.
    py_a = Path(result_a["script_path"]).read_bytes()
    py_b = Path(result_b["script_path"]).read_bytes()
    assert py_a == py_b


def test_sign_script_bytes_roundtrip_verifies(tmp_path: Path) -> None:
    """Call _sign_script_bytes once, then run execute_script with
    skip_trust_checks=False. Asserts returncode 0 and >= 1 finding.

    This is a reduced variant of test_sign_output_passes_executor_verification.
    """
    import shutil

    if shutil.which("bwrap") is None and shutil.which("sandbox-exec") is None:
        pytest.skip("no sandbox backend available on this platform")

    from screw_agents.adaptive.executor import execute_script
    from screw_agents.adaptive.signing import _sign_script_bytes
    from screw_agents.cli.init_trust import run_init_trust

    run_init_trust(project_root=tmp_path, name="Marco", email="marco@example.com")

    analyze_source = (
        "from screw_agents.adaptive import emit_finding\n"
        "def analyze(project):\n"
        "    emit_finding(\n"
        "        cwe='CWE-89',\n"
        "        file='app.py',\n"
        "        line=1,\n"
        "        message='roundtrip test finding',\n"
        "        severity='low',\n"
        "    )\n"
    )

    result = _sign_script_bytes(
        project_root=tmp_path,
        script_name="roundtrip-test",
        source=analyze_source,
        meta_dict={
            "name": "roundtrip-test",
            "created": "2026-04-21T00:00:00Z",
            "created_by": "marco@example.com",
            "domain": "injection-input-handling",
            "description": "roundtrip verification test",
            "target_patterns": [],
        },
        session_id="sess-rt",
    )
    assert result["status"] == "signed", result

    exec_result = execute_script(
        script_path=Path(result["script_path"]),
        meta_path=Path(result["meta_path"]),
        project_root=tmp_path,
        wall_clock_s=15,
        skip_trust_checks=False,
    )
    assert exec_result.sandbox_result.returncode == 0, (
        f"sandbox failed: stderr={exec_result.sandbox_result.stderr!r}"
    )
    assert len(exec_result.findings) >= 1


def test_sign_script_bytes_no_writes_on_collision(tmp_path: Path) -> None:
    """Pre-create script_path; confirm _sign_script_bytes returns status=error
    with 'already exists' and leaves no tmp files behind.
    """
    from screw_agents.adaptive.signing import _sign_script_bytes
    from screw_agents.cli.init_trust import run_init_trust

    run_init_trust(project_root=tmp_path, name="Marco", email="marco@example.com")

    script_dir = tmp_path / ".screw" / "custom-scripts"
    script_dir.mkdir(parents=True, exist_ok=True)
    (script_dir / "collision-test.py").write_text("existing\n", encoding="utf-8")

    result = _sign_script_bytes(
        project_root=tmp_path,
        script_name="collision-test",
        source="print('hi')\n",
        meta_dict={
            "name": "collision-test",
            "created": "2026-04-21T00:00:00Z",
            "created_by": "marco@example.com",
            "domain": "injection-input-handling",
            "description": "collision test",
            "target_patterns": [],
        },
        session_id="sess-col",
    )

    assert result["status"] == "error"
    assert "already exists" in result["message"]

    # No tmp files should linger.
    lingering = sorted(script_dir.iterdir())
    names = {p.name for p in lingering}
    # Only the pre-created .py should be present (plus trust infra).
    assert "collision-test.py.tmp" not in names
    assert "collision-test.meta.yaml.tmp" not in names
    assert "collision-test.meta.yaml" not in names


# ---------------------------------------------------------------------------
# T2 — I-new-1 / I-new-2 regex regression tests
# ---------------------------------------------------------------------------


from screw_agents.adaptive.script_name import validate_script_name  # noqa: E402


@pytest.mark.parametrize(
    "bad_name, reason",
    [
        ("", "empty"),
        ("---", "dash-only (first char not alnum)"),
        ("a\x00b", "null byte"),
        ("a" * 64, "over-limit"),
        ("abc\n", "trailing LF — regression for I-new-1"),
        ("abc\r\n", "trailing CRLF"),
        ("ab cd", "space"),
        ("UPPERCASE", "uppercase"),
        ("-leading-dash", "leading dash"),
        ("ab", "too short"),
    ],
)
def test_validate_script_name_rejects(bad_name: str, reason: str) -> None:
    """Lock regex behavior for edge cases. The ``\\n`` case is the primary
    I-new-1 regression — it passed under ``^...$`` and fails under ``\\A...\\Z``.
    """
    with pytest.raises(ValueError, match="does not match"):
        validate_script_name(bad_name)


@pytest.mark.parametrize(
    "good_name",
    [
        "abc",           # min length
        "a" * 63,        # max length
        "test-script",   # common case
        "0abc",          # digit first
        "test-001",      # trailing digits
        "a--b",          # middle dashes
    ],
)
def test_validate_script_name_accepts(good_name: str) -> None:
    """Regression coverage for valid inputs."""
    validate_script_name(good_name)  # should not raise
