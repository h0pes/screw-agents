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

T2 (Phase 3b C1): ``_sign_script_bytes`` added as the shared signing core
used by both ``sign_adaptive_script`` (direct path) and the upcoming
``promote_staged_script`` (T4 staged path).  Engine's ``sign_adaptive_script``
delegates entirely to this helper after its own collision / config checks.
"""

from __future__ import annotations

import hashlib
import os
import yaml
from pathlib import Path
from typing import TYPE_CHECKING, Any

from pydantic import ValidationError

from screw_agents.adaptive.script_name import (
    USER_FACING_NAME_REGEX,
    validate_script_name,
)
from screw_agents.learning import _get_or_create_local_private_key
from screw_agents.models import AdaptiveScriptMeta
from screw_agents.trust import (
    _find_matching_reviewer,
    _fingerprint_public_key,
    _load_public_keys_with_reviewers,
    canonicalize_script,
    load_config,
    sign_content,
)

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


def _sign_script_bytes(
    *,
    project_root: Path,
    script_name: str,
    source: str,
    meta_dict: dict[str, Any],
    session_id: str,
) -> dict[str, Any]:
    """Shared signing core — write + sign a fresh adaptive script to disk.

    Used by:
    - ``ScanEngine.sign_adaptive_script`` (direct/approve path, T18a).
    - ``ScanEngine.promote_staged_script`` (staged path, T4) — not yet
      implemented; this helper is extracted now to avoid a follow-on
      refactor when T4 lands.

    Performs ALL filesystem work and key operations: name validation,
    collision check, config load, key load, fingerprint match, meta
    schema validation, yaml.dump, and the two-stage atomic write with
    rollback on meta failure.

    Args:
        project_root: Project root with ``.screw/`` directory.
        script_name: Filesystem-safe name
            (regex ``^[a-z0-9][a-z0-9-]{2,62}$``); produces
            ``<name>.py`` + ``<name>.meta.yaml`` in
            ``.screw/custom-scripts/``.
        source: Python source code. Not validated to be syntactically
            valid Python or lint-clean — caller is responsible.
        meta_dict: Partial meta dict conforming to AdaptiveScriptMeta
            minus signing fields. Tool computes ``sha256``, sets
            ``validated=True``, signs, and writes.
        session_id: Scan session the script was generated for. Echoed
            in the response for orchestrator correlation; NOT written
            to disk and NOT used to modify session staging.

    Returns:
        Dict with keys ``status`` (``"signed"`` | ``"error"``),
        ``message``, and on ``"signed"``: ``script_path``, ``meta_path``,
        ``signed_by``, ``sha256``, ``session_id``.

    Raises:
        ValueError: On filesystem shape errors (PermissionError /
            IsADirectoryError / NotADirectoryError while accessing
            ``.screw/config.yaml`` or writing script files), wrapped
            via the T13 I1 discipline.
        RuntimeError: On local key generation failure (permission /
            OS error under ``.screw/local/keys/``).
    """
    # Name validation — reject anything that could turn into path
    # traversal, shell metacharacters, or Windows reserved names
    # when these land on disk.
    try:
        validate_script_name(script_name)
    except ValueError:
        return {
            "status": "error",
            "message": (
                f"Invalid script name {script_name!r}. Must match "
                f"regex {USER_FACING_NAME_REGEX!r} "
                f"(lowercase alphanumeric + dashes, 3-63 chars, "
                f"starts with alphanumeric)."
            ),
        }

    script_dir = project_root / ".screw" / "custom-scripts"
    script_path = script_dir / f"{script_name}.py"
    meta_path = script_dir / f"{script_name}.meta.yaml"

    # Fresh-script semantics: if EITHER file already exists, refuse.
    # Idempotent re-sign is the validate-script CLI's job, not this
    # helper's — bailing cleanly prevents the subagent accidentally
    # overwriting a user's hand-edited custom script.
    if script_path.exists() or meta_path.exists():
        return {
            "status": "error",
            "message": (
                f"Script {script_name} already exists at "
                f"{script_path} or {meta_path}. Refusing to overwrite; "
                f"use `screw-agents validate-script {script_name}` to "
                f"re-sign an existing script."
            ),
        }

    # Ensure the target directory exists — a fresh project may not
    # have .screw/custom-scripts/ yet.
    try:
        script_dir.mkdir(parents=True, exist_ok=True)
    except PermissionError as exc:
        raise ValueError(
            f"Cannot create adaptive script directory at {script_dir}: "
            f"permission denied. Original error: {exc}"
        ) from exc
    except OSError as exc:
        raise ValueError(
            f"Cannot create adaptive script directory at {script_dir}: "
            f"filesystem shape error ({type(exc).__name__}). "
            f"Original error: {exc}"
        ) from exc

    # T13 I1 discipline — friendly error wrapping around load_config.
    # Mirrors validate_script.py:229-247.
    try:
        config = load_config(project_root)
    except PermissionError as exc:
        raise ValueError(
            f"Cannot access `.screw/config.yaml` at "
            f"{project_root / '.screw' / 'config.yaml'}: "
            f"permission denied. Check directory permissions or run "
            f"with appropriate user. Original error: {exc}"
        ) from exc
    except OSError as exc:
        raise ValueError(
            f"Cannot access `.screw/config.yaml` at "
            f"{project_root / '.screw' / 'config.yaml'}: filesystem "
            f"shape error ({type(exc).__name__}). The `.screw` path "
            f"or config.yaml may be the wrong type (file vs. "
            f"directory). Original error: {exc}"
        ) from exc

    if not config.script_reviewers:
        return {
            "status": "error",
            "message": (
                "No script_reviewers configured in .screw/config.yaml. "
                "Run `screw-agents init-trust --name <name> "
                "--email <email>` first to register your local "
                "signing key."
            ),
        }

    # T13 I1 discipline — friendly error wrapping around
    # _get_or_create_local_private_key.
    try:
        priv, _pub_line = _get_or_create_local_private_key(project_root)
    except PermissionError as exc:
        raise RuntimeError(
            f"Cannot create local signing key at "
            f"{project_root / '.screw' / 'local' / 'keys'}: permission "
            f"denied. Check directory permissions. Original: {exc}"
        ) from exc
    except OSError as exc:
        raise RuntimeError(
            f"Failed to create local signing key at "
            f"{project_root / '.screw' / 'local' / 'keys'}: {exc}. "
            f"Check disk space and filesystem state."
        ) from exc

    # Model A fingerprint-based signer identity selection.
    # Matching against config.script_reviewers[0].email is WRONG on
    # multi-reviewer projects (the local key may not be [0]).
    keys_with_reviewers, _dropped = _load_public_keys_with_reviewers(
        config.script_reviewers
    )
    local_fingerprint = _fingerprint_public_key(priv.public_key())
    matching_reviewer = _find_matching_reviewer(
        local_fingerprint, keys_with_reviewers
    )

    if matching_reviewer is None:
        return {
            "status": "error",
            "message": (
                "Local signing key does not match any registered "
                "reviewer in script_reviewers. Run "
                "`screw-agents init-trust` to register this machine's "
                "key before signing scripts."
            ),
        }

    signer_email = matching_reviewer.email
    current_sha256 = compute_script_sha256(source)

    # Delegate canonicalization + signing to the shared helper so the
    # approve-path and the validate-script CLI produce byte-identical
    # canonical input to the executor's Layer 3 verification.
    try:
        meta_for_persist = build_signed_script_meta(
            meta_raw=meta_dict,
            source=source,
            current_sha256=current_sha256,
            signer_email=signer_email,
            private_key=priv,
        )
    except ValueError as exc:
        return {
            "status": "error",
            "message": (
                f"Meta dict failed AdaptiveScriptMeta schema: {exc}"
            ),
        }

    # Atomic write, ORDER-SENSITIVE: source file first, then meta.
    # Rationale: if the meta landed first but source failed, the
    # executor's Layer 2 hash pin would never be checked (no source
    # file to hash). If the source lands but meta fails, Layer 2
    # would fail on next executor run — same partial-state bug class.
    # Writing source first + best-effort rollback on meta failure
    # ensures either BOTH files are present and consistent, or
    # NEITHER is (modulo the best-effort rollback itself racing).
    #
    # Single-writer assumption: between the two `os.replace` calls
    # below, a concurrent reader of `.screw/custom-scripts/` sees the
    # source file without its meta (brief window). Tolerable today
    # because approve-path is human-gated — only one reviewer typing
    # `approve <name>` at a time. If Phase 4 autoresearch automates
    # the approve path, revisit: consider lock-file serialization or
    # landing both `.tmp` files before either `os.replace`.
    script_tmp = script_dir / f"{script_name}.py.tmp"
    meta_tmp = script_dir / f"{script_name}.meta.yaml.tmp"
    try:
        script_tmp.write_text(source, encoding="utf-8")
        os.replace(script_tmp, script_path)
    except (PermissionError, OSError) as exc:
        # T13 I1 discipline — narrow `PermissionError` would leak
        # bare tracebacks for `IsADirectoryError`, `NotADirectoryError`,
        # `FileExistsError`, ENOSPC, EROFS (read-only mount), quota
        # exceeded. All are `OSError` subclasses but NOT
        # `PermissionError` subclasses. Catch the superset and surface
        # the concrete type in the message so the user knows whether
        # to chmod, free disk space, or fix a filesystem shape error.
        if script_tmp.exists():
            try:
                script_tmp.unlink()
            except OSError:
                pass
        raise ValueError(
            f"Cannot write script source at {script_path}: "
            f"{type(exc).__name__}. Check directory permissions and "
            f"disk space. Original error: {exc}"
        ) from exc

    try:
        meta_tmp.write_text(
            yaml.dump(
                meta_for_persist,
                default_flow_style=False,
                sort_keys=False,
            ),
            encoding="utf-8",
        )
        os.replace(meta_tmp, meta_path)
    except (PermissionError, OSError) as exc:
        # Best-effort rollback: we succeeded writing the script but
        # failed on the meta. Leaving the orphaned .py creates a
        # partial-state bug (Layer 2 would fail on next executor
        # call). Unlink the orphan; if the unlink itself fails,
        # swallow — the user will see both the script and our
        # error message and can clean up manually.
        if meta_tmp.exists():
            try:
                meta_tmp.unlink()
            except OSError:
                pass
        try:
            script_path.unlink()
        except OSError:
            pass
        raise ValueError(
            f"Cannot write script metadata at {meta_path}: "
            f"{type(exc).__name__}. Script file at {script_path} was "
            f"rolled back best-effort. Original error: {exc}"
        ) from exc

    return {
        "status": "signed",
        "message": (
            f"Signed adaptive script {script_name} with {signer_email} "
            f"(sha256={current_sha256[:12]}...)."
        ),
        "script_path": str(script_path),
        "meta_path": str(meta_path),
        "signed_by": signer_email,
        "sha256": current_sha256,
        "session_id": session_id,
    }
