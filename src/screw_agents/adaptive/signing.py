"""Adaptive-script signing helpers.

This module centralizes the sign-side canonicalization + signature binding
used by two entry points:

1. ``screw_agents.cli.validate_script.run_validate_script`` — the CLI
   path for re-signing existing quarantined scripts.
2. ``screw_agents.engine.ScanEngine.sign_adaptive_script`` — the MCP
   tool path for signing fresh scripts after human approval.

Both paths MUST produce byte-identical canonical bytes to what the
executor's Layer 3 verification canonicalizes on read. The routing
through ``AdaptiveScriptMeta.model_dump()`` BEFORE ``canonicalize_script``
is load-bearing — see ``build_signed_script_meta``'s docstring for the
full rationale. The tiny ``compute_script_sha256`` helper is exposed so
both sign-side callers compute sha256 identically (encoding + algorithm
+ hex output); drift in any of those three properties would silently
break signature verification.

Extracted in Phase 3b T18a from ``cli/validate_script._build_signed_meta``
to prevent drift across the three consumers (CLI, MCP tool, executor
fixture). The trust.py split (DEFERRED_BACKLOG T4-M6) remains deferred
— adaptive-specific signing helpers have a cleaner architectural home
here than in lower-level trust.py.
"""

from __future__ import annotations

import hashlib
from typing import TYPE_CHECKING, Any

from pydantic import ValidationError

from screw_agents.models import AdaptiveScriptMeta
from screw_agents.trust import canonicalize_script, sign_content

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
    )


def build_signed_script_meta(
    *,
    meta_raw: dict[str, Any],
    source: str,
    current_sha256: str,
    signer_email: str,
    private_key: "Ed25519PrivateKey",
) -> dict[str, Any]:
    """Return a fully populated meta dict ready to persist.

    Binds ``sha256``, ``validated=True``, ``signed_by``, ``signature``, and
    ``signature_version`` to the source via the user's Ed25519 key. The
    returned dict is the single source of truth for what signing paths
    persist and what the executor's Layer 3 verification will canonicalize
    on read.

    Routing ``meta_raw`` through ``AdaptiveScriptMeta`` BEFORE canonicalization
    is load-bearing: the executor parses persisted YAML via
    ``AdaptiveScriptMeta(**meta_raw)`` which INJECTS defaults for omitted
    fields (``last_used=None``, ``findings_produced=0``,
    ``false_positive_rate=None``). If sign-side canonicalized the raw user
    dict and verify-side canonicalized the model-dumped dict, the two
    byte strings would differ and every signed script would fail Layer 3
    verification — the classic "silent failure at the trust boundary"
    bug that T13 fixed in commit ``0468b91``.

    Args:
        meta_raw: Mutable dict parsed from meta YAML or constructed by
            the approve-path caller.
        source: Current script source. Must equal the bytes from which
            ``current_sha256`` was computed.
        current_sha256: ``hashlib.sha256(source.encode("utf-8")).hexdigest()``.
        signer_email: Reviewer email matched to the local signing key
            via Model A fingerprint matching.
        private_key: Loaded Ed25519 private key.

    Returns:
        A new dict with all persistence fields populated. Safe to
        ``yaml.dump`` and write.

    Raises:
        ValueError: If ``meta_raw`` fails the ``AdaptiveScriptMeta`` schema.
    """
    # Pre-populate fields that must be bound to the signature BEFORE the
    # model normalizes defaults. `validated=True` is semantically part of
    # the signed state — a script that's been validated cannot be silently
    # downgraded to `validated=False` without invalidating the signature.
    prepared = dict(meta_raw)
    prepared["sha256"] = current_sha256
    prepared["validated"] = True

    try:
        meta_model = AdaptiveScriptMeta(**prepared)
    except ValidationError as exc:
        raise ValueError(
            f"Script metadata fails AdaptiveScriptMeta schema: {exc}. "
            f"Fix the YAML manually before signing."
        ) from exc

    # model_dump() emits ALL fields including the defaults the executor will
    # re-inject on read. The canonical bytes sign-side and verify-side
    # compute from this dict are byte-for-byte identical.
    meta_for_persist = meta_model.model_dump()

    canonical = canonicalize_script(source=source, meta=meta_for_persist)
    signature = sign_content(canonical, private_key=private_key)

    meta_for_persist["signed_by"] = signer_email
    meta_for_persist["signature"] = signature
    meta_for_persist["signature_version"] = 1
    return meta_for_persist


def compute_script_sha256(source: str) -> str:
    """Return ``hashlib.sha256(source.encode("utf-8")).hexdigest()``.

    Tiny convenience so the two signing paths compute sha256 identically
    (encoding, algorithm, hex output). Exposed because drift in any of
    these three properties would silently break signature verification.
    """
    return hashlib.sha256(source.encode("utf-8")).hexdigest()
