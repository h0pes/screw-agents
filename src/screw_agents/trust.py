"""Content trust for .screw/ — SSH-key-based signing and verification.

Phase 3a establishes a uniform trust boundary for everything in .screw/ that
affects scan integrity. Exclusions (Phase 2, retrofit) and adaptive scripts
(Phase 3b, new) both go through this module.

The trust root is the git repository itself: .screw/config.yaml declares
trusted signing keys, and its integrity is rooted in commit history.

Primary signing path: `ssh-keygen -Y sign` / `ssh-keygen -Y verify` via subprocess.
Fallback signing path: Python `cryptography` Ed25519 when OpenSSH is not available.
"""

from __future__ import annotations

import base64
import json
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from screw_agents.models import Exclusion

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


def ssh_keygen_available() -> bool:
    """Return True if `ssh-keygen` is on PATH."""
    return shutil.which("ssh-keygen") is not None


def sign_content(
    canonical: bytes,
    *,
    private_key: Ed25519PrivateKey | None = None,
    key_path: Path | None = None,
    key_comment: str = "screw-agents",
    namespace: str = "screw-agents",
) -> str:
    """Sign canonical bytes and return a base64-encoded signature.

    Two paths:
      1. `key_path` provided AND `ssh-keygen` on PATH → shell out to `ssh-keygen -Y sign`
      2. `private_key` provided (Ed25519PrivateKey) → cryptography-library signing

    Callers should prefer path 1 for user-facing CLI commands (which consume the user's
    existing SSH key). Path 2 is for tests and for environments without OpenSSH.

    The `namespace` argument is used by ssh-keygen's domain separation. Exclusions
    use "screw-exclusions"; scripts use "screw-scripts".
    """
    if key_path is not None and ssh_keygen_available():
        return _sign_with_ssh_keygen(canonical, key_path=key_path, namespace=namespace)
    if private_key is not None:
        return _sign_with_cryptography(canonical, private_key=private_key)
    raise ValueError(
        "sign_content requires either key_path (with ssh-keygen on PATH) or private_key"
    )


def _sign_with_ssh_keygen(canonical: bytes, *, key_path: Path, namespace: str) -> str:
    """Sign via `ssh-keygen -Y sign` subprocess. Writes to a tempfile because
    ssh-keygen reads the content to sign from a file."""
    with tempfile.NamedTemporaryFile(mode="wb", delete=False) as tf:
        tf.write(canonical)
        tf_path = Path(tf.name)
    try:
        subprocess.run(
            [
                "ssh-keygen",
                "-Y",
                "sign",
                "-f",
                str(key_path),
                "-n",
                namespace,
                str(tf_path),
            ],
            check=True,
            capture_output=True,
        )
        # ssh-keygen writes the signature to <input>.sig
        sig_path = tf_path.with_suffix(tf_path.suffix + ".sig")
        sig_bytes = sig_path.read_bytes()
        sig_path.unlink()
        return base64.b64encode(sig_bytes).decode("ascii")
    finally:
        tf_path.unlink(missing_ok=True)


def _sign_with_cryptography(canonical: bytes, *, private_key: Ed25519PrivateKey) -> str:
    """Sign via the cryptography library — raw Ed25519 signature, base64 encoded."""
    signature_bytes = private_key.sign(canonical)
    return base64.b64encode(signature_bytes).decode("ascii")
