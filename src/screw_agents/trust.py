"""Content trust for .screw/ — Ed25519 signing and verification.

Phase 3a establishes a uniform trust boundary for everything in .screw/ that
affects scan integrity. Exclusions (Phase 2, retrofit) and adaptive scripts
(Phase 3b, new) both go through this module.

The trust root is the git repository itself: .screw/config.yaml declares
trusted signing keys (OpenSSH format), and its integrity is rooted in commit
history.

Signing uses the `cryptography` library with Ed25519 end-to-end. Users' existing
~/.ssh/id_ed25519 keys are loaded via cryptography.serialization.load_ssh_private_key
when present; otherwise `init-trust` generates a project-local key under
.screw/local/keys/. The wire format is raw 64-byte Ed25519 signatures, base64-encoded.

(Design history: an earlier iteration considered ssh-keygen subprocess wrapping
with cryptography as a fallback. That was rejected during Task 4 code review
because the two backends produced incompatible wire formats and implementing
SSHSIG envelope in pure Python was disproportionate effort for the value.)
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

import yaml
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from pydantic import ValidationError

from screw_agents.models import Exclusion, ReviewerKey, ScrewConfig

if TYPE_CHECKING:
    from pathlib import Path

# Public re-exports.
__all__ = [
    "Ed25519PrivateKey",
    "Ed25519PublicKey",
    "VerificationResult",
    "canonicalize_exclusion",
    "canonicalize_script",
    "load_config",
    "sign_content",
    "verify_exclusion",
    "verify_script",
    "verify_signature",
]

# Canonical form excludes these keys when hashing/signing exclusions.
# signature_version is INCLUDED in the canonical form on purpose: changing the
# version flips the canonical bytes and invalidates the signature, preventing
# silent version downgrade attacks (e.g., "downgrade v2 to v1 to exploit a
# weaker verifier"). Only the signature material itself and runtime flags are
# excluded.
_EXCLUSION_CANONICAL_EXCLUDE = {
    "signed_by",
    "signature",
    "quarantined",
}

# Canonical form excludes these keys when hashing/signing script metadata.
_SCRIPT_META_CANONICAL_EXCLUDE = {
    "signed_by",
    "signature",
    "signature_version",
}


# Auto-generated .screw/config.yaml stub written on first run when no config
# exists. Defaults to `legacy_unsigned_exclusions: reject` — fail-safe. Users
# must explicitly opt into applying their Phase 2 unsigned exclusions by
# running `screw-agents init-trust` followed by `screw-agents migrate-exclusions`.
_CONFIG_STUB_TEMPLATE = """\
# screw-agents project configuration
# See https://github.com/h0pes/screw-agents for the trust model details.
#
# Exclusion and script signing are SEPARATE trust domains (split lists).
# To register your local SSH key, run: `screw-agents init-trust`.

version: 1

# Reviewers authorized to sign .screw/learning/exclusions.yaml entries.
# Populated by `screw-agents init-trust`. Each entry is {name, email, key}
# where `key` is an OpenSSH-format ed25519 public key.
exclusion_reviewers: []

# Reviewers authorized to sign .screw/custom-scripts/*.py adaptive scripts
# (Phase 3b feature). Leave empty until adaptive scripts are enabled.
script_reviewers: []

# Adaptive analysis mode (Phase 3b). Default: false.
adaptive: false

# Policy for legacy unsigned exclusions (from Phase 2 before signing existed):
#   reject  — quarantine unsigned entries; user must re-sign via
#             `screw-agents migrate-exclusions` (safest, default)
#   warn    — apply unsigned entries with a loud warning (90-day window)
#   allow   — silently apply unsigned entries (NOT RECOMMENDED)
legacy_unsigned_exclusions: reject
"""


def canonicalize_exclusion(exclusion: Exclusion) -> bytes:
    """Return the canonical JSON byte form of an exclusion for signing.

    Deterministic: identical inputs produce identical outputs across Python
    versions, OS platforms, and repeated calls. Signature-related fields and
    runtime flags are excluded — they must never affect the signed content.
    """
    data = exclusion.model_dump(exclude=_EXCLUSION_CANONICAL_EXCLUDE)
    return _canonical_json_bytes(data)


def canonicalize_script(*, source: str, meta: dict[str, Any]) -> bytes:
    """Return the canonical byte form of a script + metadata pair for signing.

    The canonical form is `{"source": <str>, "meta": <dict minus signing keys>}`
    serialized as sorted-key JSON. Both the source text and metadata contribute
    to the signature so either changing alone invalidates it.
    """
    filtered_meta = {k: v for k, v in meta.items() if k not in _SCRIPT_META_CANONICAL_EXCLUDE}
    payload = {"source": source, "meta": filtered_meta}
    return _canonical_json_bytes(payload)


def _canonical_json_bytes(data: Any) -> bytes:
    """Sorted-key, compact-separator JSON with UTF-8 encoding.

    This is NOT RFC 8785 JCS — we use `json.dumps(..., sort_keys=True, separators=(',', ':'))`
    which is deterministic for the data shapes we sign (dicts/lists/strings/ints/bools/None).
    If we need stronger canonicalization later (Unicode normalization, number handling edge
    cases), swap the implementation here — callers are stable.
    """
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


def sign_content(canonical: bytes, *, private_key: Ed25519PrivateKey) -> str:
    """Sign canonical bytes with an Ed25519 private key and return a base64 signature.

    Phase 3a uses cryptography-library signing uniformly. The produced signature
    is raw 64-byte Ed25519 bytes, base64-encoded. Callers load their SSH key via
    `cryptography.hazmat.primitives.serialization.load_ssh_private_key()` (which
    accepts OpenSSH-format ~/.ssh/id_ed25519) and pass the resulting private_key
    to this function.

    The CLI init-trust subcommand (Task 12) handles the user-facing flow: detect
    an existing ~/.ssh/id_ed25519, decrypt with getpass if encrypted, or generate
    a fresh project-local key under .screw/local/keys/ if none is available.
    """
    signature_bytes = private_key.sign(canonical)
    return base64.b64encode(signature_bytes).decode("ascii")


@dataclass(frozen=True)
class VerificationResult:
    """Result of a signature verification attempt."""

    valid: bool
    reason: str | None = None  # populated when valid is False
    matched_key_fingerprint: str | None = None  # populated when valid is True


def verify_signature(
    canonical: bytes,
    signature: str,
    *,
    public_keys: list[Ed25519PublicKey],
) -> VerificationResult:
    """Verify a base64-encoded signature against a list of allowed public keys.

    Tries each public key until one succeeds. Phase 3a uses cryptography-library
    signing and verification uniformly (Task 4 revised per Option C — see Task 4
    NOTE block in PHASE_3A_PLAN.md). Signatures are raw 64-byte Ed25519,
    base64-encoded. The CLI subcommands (Tasks 12-14) use the same cryptography
    path — no ssh-keygen subprocess dependency.
    """
    if not public_keys:
        return VerificationResult(valid=False, reason="no trusted keys configured")

    try:
        signature_bytes = base64.b64decode(signature, validate=True)
    except (ValueError, base64.binascii.Error):
        return VerificationResult(valid=False, reason="signature is not valid base64")

    for pub in public_keys:
        try:
            pub.verify(signature_bytes, canonical)
            return VerificationResult(
                valid=True, matched_key_fingerprint=_fingerprint_public_key(pub)
            )
        except Exception:  # InvalidSignature from cryptography
            continue

    return VerificationResult(valid=False, reason="signature invalid or content mismatch")


def _fingerprint_public_key(public_key: Ed25519PublicKey) -> str:
    """Short fingerprint of an Ed25519 public key for logging/diagnostics.

    Returns SHA-256 of the raw public key bytes, base64-encoded, first 16 chars.
    NOT cryptographic identity — for display only. Do not use as a trust anchor.
    """
    import hashlib

    from cryptography.hazmat.primitives import serialization

    raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    digest = hashlib.sha256(raw).digest()
    return base64.b64encode(digest).decode("ascii")[:16]


def load_config(project_root: Path) -> ScrewConfig:
    """Load .screw/config.yaml into a ScrewConfig, auto-generating a stub if missing.

    Behavior:
    - If `.screw/` does not exist, create it (mkdir parents=True, exist_ok=True).
    - If `.screw/config.yaml` does not exist, write the stub template and load it.
    - If the file exists but is malformed YAML, raise `ValueError` with the
      config file path and the parser's line/column context.
    - If the file parses but fails `ScrewConfig` validation, raise `ValueError`
      with the config file path and the pydantic error detail.

    The fail-safe stub defaults to `legacy_unsigned_exclusions: reject` — no
    Phase 2 exclusions are applied until the user signs them via
    `screw-agents migrate-exclusions`.

    Args:
        project_root: project root directory (Path).

    Returns:
        Parsed `ScrewConfig`. On first run this is the defaults from the stub.

    Raises:
        ValueError: if the file exists but is malformed or schema-invalid.
    """
    screw_dir = project_root / ".screw"
    config_path = screw_dir / "config.yaml"

    if not config_path.exists():
        screw_dir.mkdir(parents=True, exist_ok=True)
        config_path.write_text(_CONFIG_STUB_TEMPLATE, encoding="utf-8")

    raw_text = config_path.read_text(encoding="utf-8")

    try:
        data = yaml.safe_load(raw_text)
    except yaml.YAMLError as exc:
        # YAMLError's str() includes "in <unicode string>, line N, column M" which
        # is the line-number context we promise in the docstring/tests.
        raise ValueError(f"Malformed YAML in {config_path}: {exc}") from exc

    if data is None:
        # Empty file (whitespace-only, comments-only) — treat as defaults.
        data = {}

    try:
        return ScrewConfig.model_validate(data)
    except ValidationError as exc:
        raise ValueError(f"Invalid schema in {config_path}: {exc}") from exc


def verify_exclusion(exclusion: Exclusion, *, config: ScrewConfig) -> VerificationResult:
    """Verify an exclusion's signature AND claimed signer identity.

    Returns VerificationResult. Four outcomes:
    - Unsigned (signature or signed_by missing) → valid=False, reason='exclusion {id}: unsigned'
    - All configured reviewer keys malformed → valid=False with dropped-key diagnostics
    - Signature valid but signed_by mismatches the matched key's reviewer →
      valid=False, reason='exclusion {id}: signer identity mismatch...'
    - Signature valid AND signed_by matches the matched reviewer's email → valid=True

    The caller (learning.py) applies the legacy_unsigned_exclusions policy on
    unsigned results; other invalid results are quarantined unconditionally.
    """
    if exclusion.signature is None or exclusion.signed_by is None:
        return VerificationResult(valid=False, reason=f"exclusion {exclusion.id}: unsigned")

    canonical = canonicalize_exclusion(exclusion)
    keys_with_reviewers, dropped = _load_public_keys_with_reviewers(config.exclusion_reviewers)
    public_keys = [pub for pub, _ in keys_with_reviewers]

    if not public_keys and dropped:
        # All reviewer entries were malformed — give the user actionable feedback
        dropped_reasons = ", ".join(f"{r.email}: {reason}" for r, reason in dropped)
        return VerificationResult(
            valid=False,
            reason=(
                f"exclusion {exclusion.id}: no usable reviewer keys "
                f"({len(dropped)} dropped: {dropped_reasons})"
            ),
        )

    result = verify_signature(canonical, exclusion.signature, public_keys=public_keys)
    if not result.valid:
        # Propagate the verify_signature reason but wrap with exclusion ID for context
        return VerificationResult(
            valid=False,
            reason=f"exclusion {exclusion.id}: {result.reason}",
        )

    # Signature is valid — now cross-check that signed_by matches the key's owner
    matched_reviewer = _find_matching_reviewer(
        result.matched_key_fingerprint, keys_with_reviewers
    )
    if matched_reviewer is None:
        # Defensive: shouldn't happen because verify_signature only returns
        # matched_key_fingerprint when it found a key in the list we passed in.
        return VerificationResult(
            valid=False,
            reason=(
                f"exclusion {exclusion.id}: matched key has no reviewer entry "
                f"(internal error)"
            ),
        )

    if matched_reviewer.email != exclusion.signed_by:
        return VerificationResult(
            valid=False,
            reason=(
                f"exclusion {exclusion.id}: signer identity mismatch "
                f"(claimed {exclusion.signed_by!r}, actual {matched_reviewer.email!r})"
            ),
        )

    return result


def verify_script(
    *,
    source: str,
    meta: dict[str, Any],
    config: ScrewConfig,
) -> VerificationResult:
    """Verify a script's signature AND claimed signer identity.

    Same four-outcome model as verify_exclusion. The script identifier used
    in error reasons is meta.get('name', '<unnamed script>').
    """
    script_name = meta.get("name", "<unnamed script>")
    signature = meta.get("signature")
    signed_by = meta.get("signed_by")
    if signature is None or signed_by is None:
        return VerificationResult(valid=False, reason=f"script {script_name}: unsigned")

    canonical = canonicalize_script(source=source, meta=meta)
    keys_with_reviewers, dropped = _load_public_keys_with_reviewers(config.script_reviewers)
    public_keys = [pub for pub, _ in keys_with_reviewers]

    if not public_keys and dropped:
        dropped_reasons = ", ".join(f"{r.email}: {reason}" for r, reason in dropped)
        return VerificationResult(
            valid=False,
            reason=(
                f"script {script_name}: no usable reviewer keys "
                f"({len(dropped)} dropped: {dropped_reasons})"
            ),
        )

    result = verify_signature(canonical, signature, public_keys=public_keys)
    if not result.valid:
        return VerificationResult(
            valid=False,
            reason=f"script {script_name}: {result.reason}",
        )

    matched_reviewer = _find_matching_reviewer(
        result.matched_key_fingerprint, keys_with_reviewers
    )
    if matched_reviewer is None:
        return VerificationResult(
            valid=False,
            reason=(
                f"script {script_name}: matched key has no reviewer entry "
                f"(internal error)"
            ),
        )

    if matched_reviewer.email != signed_by:
        return VerificationResult(
            valid=False,
            reason=(
                f"script {script_name}: signer identity mismatch "
                f"(claimed {signed_by!r}, actual {matched_reviewer.email!r})"
            ),
        )

    return result


def _find_matching_reviewer(
    fingerprint: str | None,
    keys_with_reviewers: list[tuple[Ed25519PublicKey, ReviewerKey]],
) -> ReviewerKey | None:
    """Find the reviewer whose public key fingerprint matches the given value.

    Used by verify_exclusion/verify_script to correlate a
    VerificationResult.matched_key_fingerprint back to the reviewer entry so the
    caller can cross-check signed_by against reviewer.email.
    """
    if fingerprint is None:
        return None
    for pub, reviewer in keys_with_reviewers:
        if _fingerprint_public_key(pub) == fingerprint:
            return reviewer
    return None


def _load_public_keys_with_reviewers(
    reviewers: list[ReviewerKey],
) -> tuple[list[tuple[Ed25519PublicKey, ReviewerKey]], list[tuple[ReviewerKey, str]]]:
    """Parse ssh-ed25519 lines in reviewer entries into (pub, reviewer) pairs.

    Returns (valid_pairs, dropped_diagnostics). Each dropped entry pairs the
    reviewer with a short reason string explaining why it was dropped
    ("ssh-rsa not supported", "malformed base64", "wrong prefix",
    "authorized_keys option prefix", "truncated key", etc.). Callers surface
    these diagnostics when `valid_pairs` is empty so users with misconfigured
    keys get actionable feedback instead of a generic "no trusted keys" error.

    Only Ed25519 keys are supported in Phase 3a. Future work may add RSA/ECDSA.
    """
    valid: list[tuple[Ed25519PublicKey, ReviewerKey]] = []
    dropped: list[tuple[ReviewerKey, str]] = []
    for reviewer in reviewers:
        try:
            parts = reviewer.key.strip().split()
            if len(parts) < 2:
                dropped.append((reviewer, "key field does not contain a type/data pair"))
                continue
            if parts[0] != "ssh-ed25519":
                if parts[0].startswith("ssh-"):
                    dropped.append(
                        (reviewer, f"{parts[0]} not supported (only ssh-ed25519)")
                    )
                else:
                    # authorized_keys-style option prefix or garbage
                    dropped.append(
                        (
                            reviewer,
                            f"unrecognized key prefix {parts[0]!r} "
                            f"(authorized_keys option line?)",
                        )
                    )
                continue
            try:
                key_bytes_with_header = base64.b64decode(parts[1], validate=True)
            except (ValueError, base64.binascii.Error):
                dropped.append((reviewer, "base64 decode failed"))
                continue
            # SSH wire format header: uint32(11) + "ssh-ed25519" + uint32(32) = 19 bytes
            raw_key = key_bytes_with_header[19 : 19 + 32]
            if len(raw_key) != 32:
                dropped.append((reviewer, "key payload truncated"))
                continue
            valid.append((Ed25519PublicKey.from_public_bytes(raw_key), reviewer))
        except Exception as exc:
            dropped.append((reviewer, f"unexpected error: {type(exc).__name__}"))
    return valid, dropped


def _public_key_to_openssh_line(public_key: Ed25519PublicKey, *, comment: str) -> str:
    """Encode an Ed25519PublicKey as a single-line OpenSSH public key.

    Format: "ssh-ed25519 <base64(wire_format)> <comment>"
    This is the inverse of _load_public_keys_with_reviewers and is used by tests plus `init-trust`.
    """
    raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    # SSH wire format: len("ssh-ed25519")=11, key_len=32
    wire = (
        len("ssh-ed25519").to_bytes(4, "big")
        + b"ssh-ed25519"
        + (32).to_bytes(4, "big")
        + raw
    )
    return f"ssh-ed25519 {base64.b64encode(wire).decode('ascii')} {comment}"
