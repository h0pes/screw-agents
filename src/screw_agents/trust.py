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

import json
from pathlib import Path
from typing import Any

from screw_agents.models import Exclusion

# Canonical form excludes these keys when hashing/signing exclusions.
_EXCLUSION_CANONICAL_EXCLUDE = {
    "signed_by",
    "signature",
    "signature_version",
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
