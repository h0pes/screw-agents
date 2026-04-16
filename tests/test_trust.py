"""Unit tests for screw_agents.trust — signing, verification, canonicalization."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from screw_agents.models import (
    Exclusion,
    ExclusionFinding,
    ExclusionScope,
    ReviewerKey,
    ScrewConfig,
)
from screw_agents.trust import (
    _public_key_to_openssh_line,
    canonicalize_exclusion,
    canonicalize_script,
    load_config,
    sign_content,
    verify_exclusion,
    verify_script,
    verify_signature,
)
from screw_agents.trust import VerificationResult


@pytest.fixture
def ed25519_keypair() -> tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    """T5-M6 — shared keypair fixture for tests that need a freshly-generated
    Ed25519 key. Tests that previously did `priv = Ed25519PrivateKey.generate()`
    inline can use this instead.
    """
    priv = Ed25519PrivateKey.generate()
    return priv, priv.public_key()


def _sample_exclusion(*, with_placeholder_signature: bool = False) -> Exclusion:
    """Build a sample Exclusion. The placeholder-signature variant has signed_by
    and signature set to literal placeholders that are NOT cryptographically
    valid — tests that need a real signature must call sign_content directly.
    The placeholder is only useful for canonicalization tests that assert
    signature-related fields are excluded from the canonical bytes regardless
    of their value.
    """
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
        signed_by="marco@example.com" if with_placeholder_signature else None,
        signature="U1NIU0lH..." if with_placeholder_signature else None,
    )


def test_canonicalize_exclusion_is_deterministic():
    excl = _sample_exclusion()
    out1 = canonicalize_exclusion(excl)
    out2 = canonicalize_exclusion(excl)
    assert out1 == out2
    assert isinstance(out1, bytes)


def test_canonicalize_exclusion_excludes_signature_fields():
    """Canonical form must not include signature-related fields; otherwise signing loops forever."""
    unsigned = _sample_exclusion(with_placeholder_signature=False)
    signed = _sample_exclusion(with_placeholder_signature=True)
    assert canonicalize_exclusion(unsigned) == canonicalize_exclusion(signed)


def test_canonicalize_exclusion_excludes_runtime_flags():
    """`quarantined` is a runtime flag, not part of the signed content."""
    excl = _sample_exclusion()
    excl_quarantined = _sample_exclusion()
    excl_quarantined.quarantined = True
    assert canonicalize_exclusion(excl) == canonicalize_exclusion(excl_quarantined)


def test_canonicalize_exclusion_invariant_across_trust_state():
    """`trust_state` is a runtime flag and must never appear in signed bytes.

    This test pins the crypto-correctness contract independently of the
    `Exclusion.model_dump` override. Even if a future refactor loosens the
    override's `_RUNTIME_ONLY_FIELDS` union, `_EXCLUSION_CANONICAL_EXCLUDE`
    must still enumerate `trust_state` explicitly so canonicalize_exclusion
    produces identical bytes regardless of the field's current value. If
    this invariant drifts, verification of every stored exclusion breaks
    silently — the loaded exclusion's canonical bytes would no longer match
    the bytes that were signed at record time.
    """
    excl_trusted = _sample_exclusion()
    excl_trusted.trust_state = "trusted"

    excl_warned = _sample_exclusion()
    excl_warned.trust_state = "warned"

    excl_quarantined = _sample_exclusion()
    excl_quarantined.trust_state = "quarantined"

    excl_allowed = _sample_exclusion()
    excl_allowed.trust_state = "allowed"

    canonical_trusted = canonicalize_exclusion(excl_trusted)
    canonical_warned = canonicalize_exclusion(excl_warned)
    canonical_quarantined = canonicalize_exclusion(excl_quarantined)
    canonical_allowed = canonicalize_exclusion(excl_allowed)

    assert canonical_trusted == canonical_warned
    assert canonical_trusted == canonical_quarantined
    assert canonical_trusted == canonical_allowed


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


def test_canonicalize_script_empty_meta():
    """T3-M4 — pin the empty-meta edge case so a future regression that
    e.g. omits meta entirely from the payload is caught immediately.
    """
    out = canonicalize_script(source="x", meta={})
    assert out == b'{"meta":{},"source":"x"}'


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


def test_sign_content_rejects_empty_canonical(ed25519_keypair):
    """T4-M3 — empty canonical is upstream-bug territory; refuse loudly
    instead of producing a "valid" signature for nothing.
    """
    priv, _pub = ed25519_keypair
    with pytest.raises(ValueError, match="empty"):
        sign_content(b"", private_key=priv)


def test_sign_content_returns_base64_signature(ed25519_keypair):
    # Cryptography-library signing. Ed25519 private key from fixture.
    priv, _pub = ed25519_keypair

    canonical = b"test content to sign"
    signature = sign_content(canonical, private_key=priv)

    assert isinstance(signature, str)
    assert len(signature) > 0
    # Raw 64-byte Ed25519 signature, base64-encoded → 88 chars (with padding) or 86 (without).
    # Opaque here; verification test (Task 5) exercises round-trip.


def test_sign_content_deterministic_for_same_input(ed25519_keypair):
    """Ed25519 signatures are deterministic — same key + same message → same signature."""
    priv, _pub = ed25519_keypair

    canonical = b"identical content"
    sig1 = sign_content(canonical, private_key=priv)
    sig2 = sign_content(canonical, private_key=priv)
    assert sig1 == sig2


def test_verify_signature_accepts_valid_signature(ed25519_keypair):
    """Sign with cryptography, verify with cryptography — round-trip success."""
    priv, pub = ed25519_keypair

    canonical = b"valid content"
    signature = sign_content(canonical, private_key=priv)

    result = verify_signature(canonical, signature, public_keys=[pub])
    assert isinstance(result, VerificationResult)
    assert result.valid is True
    assert result.reason is None


def test_verify_signature_rejects_tampered_content(ed25519_keypair):
    priv, pub = ed25519_keypair

    canonical = b"original content"
    signature = sign_content(canonical, private_key=priv)

    tampered = b"MODIFIED content"
    result = verify_signature(tampered, signature, public_keys=[pub])
    assert result.valid is False
    assert "content mismatch" in result.reason.lower() or "invalid" in result.reason.lower()


def test_verify_signature_rejects_untrusted_key():
    signing_priv = Ed25519PrivateKey.generate()
    other_priv = Ed25519PrivateKey.generate()

    canonical = b"content"
    signature = sign_content(canonical, private_key=signing_priv)

    result = verify_signature(canonical, signature, public_keys=[other_priv.public_key()])
    assert result.valid is False


def test_verify_signature_empty_allowed_keys():
    """With no allowed keys, verification must fail.

    T5-M7 decoupling: this test's only contract is the empty-keys branch
    rejecting before any signature work happens. We use a literal base64
    placeholder to make the independence explicit — the verifier returns
    `no trusted keys configured` BEFORE attempting to base64-decode or
    crypto-verify, so any string suffices here.
    """
    result = verify_signature(b"content", "AAAA", public_keys=[])
    assert result.valid is False
    assert "no trusted keys" in result.reason.lower()


def test_load_config_generates_stub_when_missing(tmp_path: Path):
    """First-run scenario: .screw/ exists but config.yaml does not → auto-generate stub."""
    project_root = tmp_path
    screw_dir = project_root / ".screw"
    screw_dir.mkdir()

    config = load_config(project_root)

    assert isinstance(config, ScrewConfig)
    assert config.version == 1
    assert config.legacy_unsigned_exclusions == "reject"
    assert config.exclusion_reviewers == []
    assert config.script_reviewers == []
    assert config.adaptive is False

    # The stub file was written to disk
    config_file = screw_dir / "config.yaml"
    assert config_file.exists()
    content = config_file.read_text()
    assert "version:" in content
    assert "legacy_unsigned_exclusions" in content
    # Auto-generated stub must include a helpful comment pointing at init-trust
    assert "init-trust" in content.lower() or "screw-agents" in content.lower()


def test_load_config_creates_screw_dir_when_missing(tmp_path: Path):
    """Very-first-run: neither .screw/ nor config.yaml exists → create both."""
    project_root = tmp_path
    # .screw/ does not exist at all

    config = load_config(project_root)

    assert (project_root / ".screw").is_dir()
    assert (project_root / ".screw" / "config.yaml").exists()
    assert config.version == 1


def test_load_config_parses_valid_file(tmp_path: Path):
    """Existing .screw/config.yaml with valid content is parsed into ScrewConfig."""
    project_root = tmp_path
    screw_dir = project_root / ".screw"
    screw_dir.mkdir()
    config_file = screw_dir / "config.yaml"
    config_file.write_text(
        """
version: 1
adaptive: true
legacy_unsigned_exclusions: warn
exclusion_reviewers:
  - name: Marco
    email: marco@example.com
    key: ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIexample marco@arch
script_reviewers:
  - name: Marco
    email: marco@example.com
    key: ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIexample marco@arch
"""
    )

    config = load_config(project_root)

    assert config.version == 1
    assert config.adaptive is True
    assert config.legacy_unsigned_exclusions == "warn"
    assert len(config.exclusion_reviewers) == 1
    assert config.exclusion_reviewers[0].name == "Marco"
    assert config.exclusion_reviewers[0].email == "marco@example.com"
    assert config.exclusion_reviewers[0].key.startswith("ssh-ed25519 ")
    assert len(config.script_reviewers) == 1


def test_load_config_rejects_malformed_yaml(tmp_path: Path):
    """Malformed YAML → ValueError pointing at the bad field with line number context."""
    project_root = tmp_path
    screw_dir = project_root / ".screw"
    screw_dir.mkdir()
    config_file = screw_dir / "config.yaml"
    # Unclosed bracket is a classic YAML parse error
    config_file.write_text("version: [unclosed\nadaptive: true\n")

    with pytest.raises(ValueError) as exc_info:
        load_config(project_root)

    # Error message must include the config file path for debuggability
    assert "config.yaml" in str(exc_info.value)


def test_load_config_rejects_invalid_schema(tmp_path: Path):
    """YAML parses but violates the ScrewConfig schema → ValueError."""
    project_root = tmp_path
    screw_dir = project_root / ".screw"
    screw_dir.mkdir()
    config_file = screw_dir / "config.yaml"
    # legacy_unsigned_exclusions must be Literal["reject", "warn", "allow"]
    config_file.write_text("version: 1\nlegacy_unsigned_exclusions: nonsense\n")

    with pytest.raises(ValueError) as exc_info:
        load_config(project_root)

    assert "config.yaml" in str(exc_info.value) or "legacy_unsigned_exclusions" in str(exc_info.value)


# T6-M5 — additional load_config edge case coverage


def test_load_config_raises_when_dot_screw_is_file(tmp_path: Path):
    """If `.screw` exists as a regular file, load_config raises a clear error.

    The mkdir(parents=True, exist_ok=True) call surfaces NotADirectoryError /
    FileExistsError when the path is occupied by a non-directory. The CLI
    boundary wraps these into actionable ValueError messages; here we pin
    the underlying low-level behavior.
    """
    screw_path = tmp_path / ".screw"
    screw_path.write_text("not a directory")

    with pytest.raises((FileExistsError, NotADirectoryError)):
        load_config(tmp_path)


@pytest.mark.skipif(
    not hasattr(__import__("os"), "geteuid") or __import__("os").geteuid() == 0,
    reason="chmod-based read-only test is unreliable for root and on Windows",
)
def test_load_config_raises_on_readonly_directory(tmp_path: Path):
    """If `.screw/` exists but is read-only, load_config raises PermissionError.

    The CLI boundary wraps this into a ValueError; here we pin the raw
    propagation contract so a future refactor doesn't accidentally swallow
    write failures during stub creation.
    """
    import os

    screw_dir = tmp_path / ".screw"
    screw_dir.mkdir()
    original_mode = screw_dir.stat().st_mode
    screw_dir.chmod(0o500)  # r-x — no write
    try:
        with pytest.raises(PermissionError):
            load_config(tmp_path)
    finally:
        # Restore mode so pytest can clean up the tmp_path tree
        screw_dir.chmod(original_mode)


def test_load_config_stub_is_valid_yaml_and_schema(tmp_path: Path):
    """The auto-generated stub round-trips through yaml.safe_load AND
    ScrewConfig.model_validate without modification. Catches a future
    regression that introduces a typo into the stub template.
    """
    config = load_config(tmp_path)
    # First run wrote the stub — re-load and assert schema validity
    raw = (tmp_path / ".screw" / "config.yaml").read_text(encoding="utf-8")
    parsed = yaml.safe_load(raw)
    revalidated = ScrewConfig.model_validate(parsed)
    assert revalidated == config


def test_load_config_idempotent_does_not_rewrite(tmp_path: Path):
    """Calling load_config twice does not mutate the existing config.yaml.

    A future regression that re-writes the stub on every call (e.g., to
    add a missing key during migration) would unconditionally bump mtime;
    pin the read-only-on-existing-file contract here.
    """
    load_config(tmp_path)
    config_path = tmp_path / ".screw" / "config.yaml"
    first_mtime = config_path.stat().st_mtime_ns
    first_bytes = config_path.read_bytes()

    # Second call should NOT touch the file
    load_config(tmp_path)
    assert config_path.stat().st_mtime_ns == first_mtime
    assert config_path.read_bytes() == first_bytes


def test_load_config_empty_file_uses_defaults(tmp_path: Path):
    """An existing-but-empty config.yaml (whitespace/comments only) parses
    as `data is None` from yaml.safe_load → load_config falls back to {}
    and ScrewConfig defaults take over. Pins the `data is None → {}` path.
    """
    screw_dir = tmp_path / ".screw"
    screw_dir.mkdir()
    config_path = screw_dir / "config.yaml"
    config_path.write_text("# only a comment, no content\n")

    config = load_config(tmp_path)
    # Defaults — same as ScrewConfig() with no args
    assert config == ScrewConfig()


def test_verify_exclusion_valid_signature_returns_trusted(tmp_path: Path, ed25519_keypair):
    """Full round-trip: sign an exclusion, build a config with the matching key,
    verify_exclusion returns valid=True."""
    priv, pub = ed25519_keypair
    key_line = _public_key_to_openssh_line(pub, comment="marco@test")

    excl = _sample_exclusion()
    canonical = canonicalize_exclusion(excl)
    signature = sign_content(canonical, private_key=priv)
    excl.signed_by = "marco@example.com"
    excl.signature = signature

    config = ScrewConfig(
        exclusion_reviewers=[
            ReviewerKey(name="Marco", email="marco@example.com", key=key_line)
        ]
    )

    result = verify_exclusion(excl, config=config)
    assert result.valid is True


def test_verify_exclusion_unsigned_returns_invalid(tmp_path: Path):
    excl = _sample_exclusion()  # no signature
    config = ScrewConfig()
    result = verify_exclusion(excl, config=config)
    assert result.valid is False
    assert "unsigned" in (result.reason or "").lower()


def test_verify_exclusion_untrusted_signer_returns_invalid(tmp_path: Path, ed25519_keypair):
    priv, _pub = ed25519_keypair
    excl = _sample_exclusion()
    excl.signature = sign_content(canonicalize_exclusion(excl), private_key=priv)
    excl.signed_by = "attacker@example.com"

    config = ScrewConfig()  # empty exclusion_reviewers → no trusted keys
    result = verify_exclusion(excl, config=config)
    assert result.valid is False


def test_verify_script_round_trip(tmp_path: Path, ed25519_keypair):
    priv, pub = ed25519_keypair
    key_line = _public_key_to_openssh_line(pub, comment="marco@test")

    source = "from screw_agents.adaptive import emit_finding\n\ndef analyze(project):\n    pass\n"
    meta = {"name": "test", "target_patterns": ["X"], "sha256": "abc"}

    canonical = canonicalize_script(source=source, meta=meta)
    signature = sign_content(canonical, private_key=priv)

    meta_signed = {**meta, "signed_by": "marco@example.com", "signature": signature}

    config = ScrewConfig(
        script_reviewers=[
            ReviewerKey(name="Marco", email="marco@example.com", key=key_line)
        ]
    )
    result = verify_script(source=source, meta=meta_signed, config=config)
    assert result.valid is True


def test_verify_exclusion_signer_identity_mismatch_returns_invalid(tmp_path: Path):
    """Attacker with a valid reviewer key forges signed_by as another reviewer.

    Even though the signature is cryptographically valid against Bob's key,
    signed_by claims Alice. Model A verification catches the mismatch.
    """
    # Two trusted reviewers: Alice and Bob
    alice_priv = Ed25519PrivateKey.generate()
    bob_priv = Ed25519PrivateKey.generate()
    alice_line = _public_key_to_openssh_line(alice_priv.public_key(), comment="alice@test")
    bob_line = _public_key_to_openssh_line(bob_priv.public_key(), comment="bob@test")

    # Bob signs the exclusion but claims Alice is the signer
    excl = _sample_exclusion()
    canonical = canonicalize_exclusion(excl)
    excl.signature = sign_content(canonical, private_key=bob_priv)
    excl.signed_by = "alice@example.com"  # Bob's lie

    config = ScrewConfig(
        exclusion_reviewers=[
            ReviewerKey(name="Alice", email="alice@example.com", key=alice_line),
            ReviewerKey(name="Bob", email="bob@example.com", key=bob_line),
        ]
    )

    result = verify_exclusion(excl, config=config)
    assert result.valid is False
    assert "identity mismatch" in (result.reason or "").lower()
    assert "alice@example.com" in (result.reason or "")
    assert "bob@example.com" in (result.reason or "")


def test_verify_script_unsigned_meta_returns_invalid(tmp_path: Path):
    """verify_script with no signature/signed_by in meta returns unsigned."""
    config = ScrewConfig()
    result = verify_script(
        source="def analyze(project): pass\n",
        meta={"name": "test", "target_patterns": ["X"]},
        config=config,
    )
    assert result.valid is False
    assert "unsigned" in (result.reason or "").lower()


def test_verify_exclusion_dropped_rsa_key_reports_diagnostic(tmp_path: Path):
    """An RSA key in exclusion_reviewers is dropped with a diagnostic reason."""
    excl = _sample_exclusion()
    excl.signature = "AAAA"  # dummy — verification never reaches this
    excl.signed_by = "marco@example.com"

    config = ScrewConfig(
        exclusion_reviewers=[
            ReviewerKey(
                name="Marco",
                email="marco@example.com",
                # Fake RSA key — only the prefix matters for the diagnostic
                key="ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAA fake@rsa",
            ),
        ]
    )

    result = verify_exclusion(excl, config=config)
    assert result.valid is False
    reason = (result.reason or "").lower()
    assert "no usable reviewer keys" in reason
    assert "ssh-rsa" in reason
    assert "not supported" in reason


def test_verify_exclusion_authorized_keys_option_prefix_reported(tmp_path: Path):
    """A reviewer entry with authorized_keys-style options is dropped diagnostically."""
    excl = _sample_exclusion()
    excl.signature = "AAAA"
    excl.signed_by = "marco@example.com"

    config = ScrewConfig(
        exclusion_reviewers=[
            ReviewerKey(
                name="Marco",
                email="marco@example.com",
                # authorized_keys-style: option_prefix ssh-ed25519 base64 comment
                key='command="restrict" ssh-ed25519 AAAAC3Nz... marco@arch',
            ),
        ]
    )

    result = verify_exclusion(excl, config=config)
    assert result.valid is False
    reason = (result.reason or "").lower()
    assert "no usable reviewer keys" in reason
    # One of the diagnostics should mention the unrecognized prefix
    assert "unrecognized" in reason or "prefix" in reason
