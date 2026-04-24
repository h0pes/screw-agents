"""Implementation of ``screw-agents validate-script <script_name>``.

Re-signs an adaptive analysis script after manual review. The user workflow:
a new (or edited) adaptive script lives at
``.screw/custom-scripts/<script_name>.py`` with a companion metadata file at
``.screw/custom-scripts/<script_name>.meta.yaml`` (either unsigned, or signed
against a stale source the user has since edited). The user reviews the
source, then runs ``screw-agents validate-script <script_name>`` which:

1. Recomputes ``sha256`` from the current source text.
2. Canonicalizes ``(source, meta-minus-signing-fields)`` via
   ``trust.canonicalize_script``.
3. Signs the canonical bytes with the local Ed25519 key.
4. Writes ``signed_by``, ``signature``, ``signature_version: 1``,
   ``validated: true``, and the new ``sha256`` back into the meta YAML via
   an atomic tmp-file + ``os.replace`` swap.

The next ``execute_script`` call will pass Layer 2 (hash pin) and Layer 3
(signature verification) and actually run the script in the sandbox.

Same three plan-vs-reality corrections as Phase 3a Task 14's
``validate_exclusion.py``:

1. Fingerprint-based signer selection (Model A, not the plan's
   ``config.script_reviewers[0].email`` heuristic which is wrong on
   multi-reviewer projects).
2. Friendly error wrapping around ``load_config`` and
   ``_get_or_create_local_private_key`` at the CLI boundary.
3. Atomic write via ``tmp.write_text`` + ``os.replace`` (not a direct
   ``meta_path.write_text``, which can leave a half-written meta file if
   the process dies mid-write).

Additional idempotency beyond the plan: if the meta already has a signature
AND the stored sha256 matches the current source hash, return
``status="already_validated"`` without re-signing. If sha256 differs (the
user edited the source after signing), DO re-sign — stale signatures are
exactly the case this command exists to fix.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml

from screw_agents.adaptive.signing import (
    build_signed_script_meta,
    compute_script_sha256,
)
from screw_agents.learning import _get_or_create_local_private_key
from screw_agents.trust import (
    _find_matching_reviewer,
    _fingerprint_public_key,
    _load_public_keys_with_reviewers,
    load_config,
)


def run_validate_script(
    *, project_root: Path, script_name: str
) -> dict[str, Any]:
    """Sign (or re-sign) an adaptive script after manual review.

    Args:
        project_root: Project root directory.
        script_name: The adaptive script name without suffix (e.g. ``"sqli_a"``
            for ``.screw/custom-scripts/sqli_a.py``).

    Returns:
        Dict with keys:
        - ``status``: ``"validated"`` | ``"already_validated"`` | ``"not_found"`` | ``"error"``
        - ``message``: human-readable summary for CLI output.

    Raises:
        ValueError: If ``.screw/config.yaml`` has a filesystem-shape error
            (e.g., the path exists as a directory when a file is expected,
            or vice versa); if ``.screw/config.yaml`` has invalid schema;
            if the meta YAML is malformed, is not a mapping, or fails the
            ``AdaptiveScriptMeta`` schema; or if a permission error blocks
            reading/writing config/script/meta files.
        RuntimeError: If the local key generation fails with an OS error.
    """
    script_dir = project_root / ".screw" / "custom-scripts"
    script_path = script_dir / f"{script_name}.py"
    meta_path = script_dir / f"{script_name}.meta.yaml"

    if not script_path.exists():
        return {
            "status": "not_found",
            "message": (
                f"No adaptive script found at {script_path}. "
                f"Expected `.screw/custom-scripts/{script_name}.py`."
            ),
        }
    if not meta_path.exists():
        return {
            "status": "not_found",
            "message": (
                f"No metadata file found at {meta_path}. "
                f"Expected `.screw/custom-scripts/{script_name}.meta.yaml`."
            ),
        }

    source = script_path.read_text(encoding="utf-8")
    try:
        meta_raw = yaml.safe_load(meta_path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ValueError(
            f"Malformed script metadata YAML at {meta_path}: {exc}. "
            f"Fix the YAML syntax manually before running validate-script."
        ) from exc

    if not isinstance(meta_raw, dict):
        raise ValueError(
            f"Script metadata at {meta_path} must be a YAML mapping; "
            f"got {type(meta_raw).__name__}."
        )

    # Recompute sha256 from the CURRENT source so an edit-after-signing
    # correctly re-signs with the edited content.
    current_sha256 = compute_script_sha256(source)

    # Idempotency: if already signed AND sha256 matches current source,
    # no work is needed. If sha256 differs, the source was edited after
    # the last signing — DO re-sign with the new content.
    if (
        meta_raw.get("signature")
        and meta_raw.get("signed_by")
        and meta_raw.get("sha256") == current_sha256
    ):
        return {
            "status": "already_validated",
            "message": (
                f"Script {script_name} is already signed "
                f"(signed_by={meta_raw.get('signed_by')}) and its sha256 "
                f"matches the current source. No changes made."
            ),
        }

    # Wrap load_config for T6-I1/I2 friendly errors at the CLI boundary
    # (mirrors validate_exclusion.py). T13 re-review I1 residual: the
    # previous tuple `(FileExistsError, NotADirectoryError)` did NOT cover
    # `IsADirectoryError` (a sibling of NotADirectoryError, NOT a subclass),
    # so a config.yaml that exists as a DIRECTORY leaked a raw traceback.
    # `OSError` is the common parent of FileExistsError / NotADirectoryError
    # / IsADirectoryError / PermissionError and other filesystem edge
    # cases. Keep PermissionError FIRST so its specific message wins over
    # the generic OSError catch-all.
    try:
        config = load_config(project_root)
    except PermissionError as exc:
        raise ValueError(
            f"Cannot access `.screw/config.yaml` at "
            f"{project_root / '.screw' / 'config.yaml'}: permission denied. "
            f"Check directory permissions or run with appropriate user. "
            f"Original error: {exc}"
        ) from exc
    except OSError as exc:
        # FileExistsError / NotADirectoryError / IsADirectoryError — the
        # `.screw` path or config.yaml exists but is not the expected
        # file/directory shape. Distinct message helps the user diagnose.
        raise ValueError(
            f"Cannot access `.screw/config.yaml` at "
            f"{project_root / '.screw' / 'config.yaml'}: filesystem shape "
            f"error ({type(exc).__name__}). The `.screw` path or "
            f"config.yaml may be the wrong type (file vs. directory). "
            f"Original error: {exc}"
        ) from exc

    if not config.script_reviewers:
        return {
            "status": "error",
            "message": (
                "No script_reviewers configured in .screw/config.yaml. "
                "Run `screw-agents init-trust --name <name> --email <email>` "
                "first to register your local signing key."
            ),
        }

    # T9-I3 — friendly error wrapping for _get_or_create_local_private_key
    # (mirrors validate_exclusion.py). `mkdir(parents=True, exist_ok=True)`
    # inside that helper can raise FileExistsError / NotADirectoryError /
    # IsADirectoryError when a regular file blocks a parent path; all three
    # are OSError subclasses. PermissionError (also OSError) is kept FIRST
    # so its specific message wins.
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

    # Model A fingerprint-based signer identity selection. The plan's
    # `config.script_reviewers[0].email` heuristic is WRONG on multi-reviewer
    # projects (the local key may not be `[0]`). Same correction shipped in
    # validate_exclusion.py.
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
                "Local signing key does not match any registered reviewer in "
                "script_reviewers. Run `screw-agents init-trust` to register "
                "this machine's key before validating scripts."
            ),
        }

    signer_email = matching_reviewer.email

    # C1 fix: route the meta through AdaptiveScriptMeta BEFORE canonicalization
    # so the executor's verify-side canonicalization sees byte-identical input.
    # All persisted-but-not-signing-metadata fields (sha256, validated, plus
    # any model defaults like last_used/findings_produced/false_positive_rate)
    # must be set before canonical JSON is computed. The returned dict is
    # what gets canonicalized AND what gets written to disk. Delegates to the
    # shared helper in `adaptive/signing.py` so this CLI path, the MCP
    # `promote_staged_script` tool, and the test_adaptive_executor fixture
    # can never drift.
    meta_for_persist = build_signed_script_meta(
        meta_raw=meta_raw,
        source=source,
        current_sha256=current_sha256,
        signer_email=signer_email,
        private_key=priv,
    )

    # T9-I2 — atomic write via tmp file + os.replace.
    # Manual tmp-path construction instead of `meta_path.with_suffix(".tmp")`
    # because `with_suffix` only replaces the LAST suffix:
    #     Path("test.meta.yaml").with_suffix(".tmp") -> Path("test.meta.tmp")
    # which would drop the `.yaml` marker. Manual construction preserves the
    # full filename and appends `.tmp` atomically.
    tmp_path = meta_path.parent / f"{meta_path.name}.tmp"
    try:
        tmp_path.write_text(
            yaml.dump(
                meta_for_persist, default_flow_style=False, sort_keys=False
            ),
            encoding="utf-8",
        )
        os.replace(tmp_path, meta_path)
    except PermissionError as exc:
        if tmp_path.exists():
            try:
                tmp_path.unlink()
            except OSError:
                pass
        raise ValueError(
            f"Cannot write script metadata at {meta_path}: permission denied. "
            f"Check directory permissions. Original error: {exc}"
        ) from exc

    return {
        "status": "validated",
        "message": (
            f"Signed adaptive script {script_name} with {signer_email} "
            f"(sha256={current_sha256[:12]}...)."
        ),
    }
