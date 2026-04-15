"""Implementation of ``screw-agents validate-exclusion <id>``.

Signs a single quarantined exclusion by ID after manual review. The user's
workflow: run a scan, see that an exclusion was quarantined (missing
signature, invalid signature, or signer identity mismatch), manually inspect
the entry in ``.screw/learning/exclusions.yaml``, and then run
``screw-agents validate-exclusion <id>`` to re-sign it with the local key.
The next scan will apply the exclusion instead of flagging the finding.

Same three plan-vs-reality corrections as Task 13's migrate_exclusions.py:
1. Fingerprint-based signer selection (Model A, not the plan's `[0]` heuristic)
2. Friendly error wrapping (T6-I1/I2, T9-I3 parity)
3. Atomic write via tmp.write_text + os.replace (T9-I2 parity)

Additional idempotency beyond the plan: if the target entry already has a
signature, returns ``status="already_validated"`` without re-signing (the
plan's implementation would re-sign, which is harmless but wastes work).
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml

from screw_agents.learning import (
    _EXCLUSIONS_PATH,
    _get_or_create_local_private_key,
)
from screw_agents.models import Exclusion
from screw_agents.trust import (
    _find_matching_reviewer,
    _fingerprint_public_key,
    _load_public_keys_with_reviewers,
    canonicalize_exclusion,
    load_config,
    sign_content,
)


def run_validate_exclusion(
    *, project_root: Path, exclusion_id: str
) -> dict[str, Any]:
    """Sign a single exclusion by ID after manual review.

    Used to un-quarantine an entry after the user reviews its content
    (opens the YAML, confirms the reason and scope look correct, then
    runs this command to re-sign). Idempotent: if the target entry is
    already signed, returns ``already_validated`` without re-signing.

    Args:
        project_root: Project root directory.
        exclusion_id: The exclusion ID to validate (e.g. "fp-2026-04-14-001").

    Returns:
        Dict with keys:
        - ``status``: ``"validated"`` | ``"already_validated"`` | ``"not_found"`` | ``"error"``
        - ``message``: human-readable summary for CLI output

    Raises:
        ValueError: If ``.screw`` exists as a file (not directory), or if
            ``.screw/config.yaml`` has invalid schema, or if a permission
            error blocks reading/writing the config or exclusions file.
        RuntimeError: If the local key generation fails with an OS error.
    """
    path = project_root / _EXCLUSIONS_PATH
    if not path.exists():
        return {
            "status": "not_found",
            "message": (
                f"Exclusions file does not exist at {path}. "
                f"No exclusions have been recorded yet."
            ),
        }

    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ValueError(
            f"Malformed exclusions YAML at {path}: {exc}. "
            f"Fix the YAML syntax manually before running validate-exclusion."
        ) from exc

    if not raw or not raw.get("exclusions"):
        return {
            "status": "not_found",
            "message": f"No exclusions in file at {path}.",
        }

    # Find the target entry by ID
    target_entry = None
    for entry in raw["exclusions"]:
        if entry.get("id") == exclusion_id:
            target_entry = entry
            break

    if target_entry is None:
        available_ids = [e.get("id", "<missing-id>") for e in raw["exclusions"]]
        return {
            "status": "not_found",
            "message": (
                f"No exclusion with id '{exclusion_id}' found in {path}. "
                f"Available IDs: {', '.join(available_ids)}"
            ),
        }

    # Idempotency: if the entry is already signed, do nothing.
    if target_entry.get("signature"):
        return {
            "status": "already_validated",
            "message": (
                f"Exclusion {exclusion_id} is already signed "
                f"(signed_by={target_entry.get('signed_by', '?')}). "
                f"No changes made."
            ),
        }

    # Wrap load_config for T6-I1/I2 friendly errors at the CLI boundary.
    try:
        config = load_config(project_root)
    except (FileExistsError, NotADirectoryError) as exc:
        raise ValueError(
            f"A `.screw` path exists at {project_root / '.screw'} but is not "
            f"a directory. Remove or rename it before running "
            f"`screw-agents validate-exclusion`. Original error: {exc}"
        ) from exc
    except PermissionError as exc:
        raise ValueError(
            f"Cannot access `.screw/config.yaml` at "
            f"{project_root / '.screw' / 'config.yaml'}: permission denied. "
            f"Check directory permissions or run with appropriate user. "
            f"Original error: {exc}"
        ) from exc

    if not config.exclusion_reviewers:
        return {
            "status": "error",
            "message": (
                "No exclusion_reviewers configured in .screw/config.yaml. "
                "Run `screw-agents init-trust --name <name> --email <email>` "
                "first to register your local signing key."
            ),
        }

    # T9-I3 — friendly error wrapping for _get_or_create_local_private_key.
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

    # Model A fingerprint-based signer identity selection — see Task 9.1
    # fix-up (commit 6a46a9b) and Task 13's migrate_exclusions.py. The
    # plan's `config.exclusion_reviewers[0].email` heuristic is WRONG.
    keys_with_reviewers, _dropped = _load_public_keys_with_reviewers(
        config.exclusion_reviewers
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
                "exclusion_reviewers. Run `screw-agents init-trust` to "
                "register this machine's key before validating exclusions."
            ),
        }

    signer_email = matching_reviewer.email

    # Build an Exclusion model from the raw entry so canonicalize_exclusion
    # sees the same shape the signed-path Exclusions have. Runtime-only
    # fields (quarantined, trust_state) get defaults and are excluded from
    # canonicalization by _EXCLUSION_CANONICAL_EXCLUDE.
    excl = Exclusion(**target_entry)
    canonical = canonicalize_exclusion(excl)
    signature = sign_content(canonical, private_key=priv)

    target_entry["signed_by"] = signer_email
    target_entry["signature"] = signature
    target_entry["signature_version"] = 1

    # T9-I2 — atomic write via tmp file + os.replace.
    tmp_path = path.with_suffix(".yaml.tmp")
    try:
        tmp_path.write_text(
            yaml.dump(raw, default_flow_style=False, sort_keys=False),
            encoding="utf-8",
        )
        os.replace(tmp_path, path)
    except PermissionError as exc:
        if tmp_path.exists():
            try:
                tmp_path.unlink()
            except OSError:
                pass
        raise ValueError(
            f"Cannot write `.screw/learning/exclusions.yaml` at {path}: "
            f"permission denied. Check directory permissions. "
            f"Original error: {exc}"
        ) from exc

    return {
        "status": "validated",
        "message": f"Signed exclusion {exclusion_id} with {signer_email}.",
    }
