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
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from screw_agents.models import Exclusion

# Public re-exports.
__all__ = [
    "Ed25519PrivateKey",
    "Ed25519PublicKey",
    "VerificationResult",
    "canonicalize_exclusion",
    "canonicalize_script",
    "sign_content",
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
    matched_key_identity: str | None = None  # populated when valid is True


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
                valid=True, matched_key_identity=_fingerprint_public_key(pub)
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
