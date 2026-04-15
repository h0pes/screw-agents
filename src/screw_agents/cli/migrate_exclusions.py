"""Implementation of ``screw-agents migrate-exclusions``.

Bulk-signs every legacy unsigned exclusion in
``.screw/learning/exclusions.yaml`` with the local Ed25519 key. Reads the
raw YAML (bypasses ``learning.load_exclusions`` to avoid quarantine
filtering), signs unsigned entries with the Model A fingerprint-matched
signer identity, and writes the updated YAML back atomically.

This is the second CLI command to invoke
``learning._get_or_create_local_private_key`` (after ``init-trust``).
Friendly error wrapping for ``load_config`` (T6-I1/I2) and
``_get_or_create_local_private_key`` (T9-I3) parallels the pattern
established in ``cli/init_trust.py``.

Atomic write via ``tmp.write_text + os.replace`` resolves T9-I2 for the
CLI write path — a crash mid-write cannot leave a partial YAML file.
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


def run_migrate_exclusions(
    *, project_root: Path, skip_confirm: bool
) -> dict[str, Any]:
    """Sign every currently-unsigned exclusion with the local Ed25519 key.

    Reads the raw YAML (bypasses ``learning.load_exclusions`` to avoid
    quarantine filtering applied by ``_apply_trust_policy``), signs entries
    that lack a signature using the Model A fingerprint-matched signer
    identity, and writes the updated YAML back atomically.

    Args:
        project_root: Project root directory.
        skip_confirm: If ``True``, skip per-entry confirmation prompt.
            In Phase 3a, ``False`` triggers an interactive ``[y/N]`` prompt
            for each unsigned entry. The CLI dispatcher always passes ``True``
            when ``--yes`` is on the command line; otherwise passes ``False``.

    Returns:
        Dict with keys:
        - ``status``: one of ``"success"``, ``"no_exclusions"``, ``"error"``
        - ``signed_count``: int — number of entries that were newly signed
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
            "status": "no_exclusions",
            "signed_count": 0,
            "message": (
                "No exclusions file found at .screw/learning/exclusions.yaml. "
                "Nothing to migrate."
            ),
        }

    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ValueError(
            f"Malformed exclusions YAML at {path}: {exc}. "
            f"Fix the YAML syntax manually before running migrate-exclusions."
        ) from exc

    if not raw or not raw.get("exclusions"):
        return {
            "status": "no_exclusions",
            "signed_count": 0,
            "message": "No exclusions to migrate (empty exclusions list).",
        }

    # Wrap load_config for T6-I1/I2 friendly errors at the CLI boundary.
    try:
        config = load_config(project_root)
    except (FileExistsError, NotADirectoryError) as exc:
        raise ValueError(
            f"A `.screw` path exists at {project_root / '.screw'} but is not "
            f"a directory. Remove or rename it before running "
            f"`screw-agents migrate-exclusions`. Original error: {exc}"
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
            "signed_count": 0,
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
    # fix-up (commit 6a46a9b). The plan's `config.exclusion_reviewers[0].email`
    # heuristic is WRONG — it breaks when multiple reviewers are registered
    # and the local machine's key doesn't match the first entry. Loading
    # the resulting YAML would fail Model A identity verification and
    # quarantine all the just-signed entries.
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
            "signed_count": 0,
            "message": (
                "Local signing key does not match any registered reviewer in "
                "exclusion_reviewers. Run `screw-agents init-trust` to "
                "register this machine's key before signing exclusions."
            ),
        }

    signer_email = matching_reviewer.email

    signed_count = 0
    for entry in raw["exclusions"]:
        if entry.get("signature"):
            continue  # already signed — idempotent skip

        if not skip_confirm:
            # Phase 3a interactive confirmation. Dispatcher passes --yes
            # through as skip_confirm=True, so this branch only triggers
            # when the user explicitly runs without --yes. Keep minimal:
            # tests always pass skip_confirm=True.
            print(f"\nSign exclusion {entry['id']}?")
            print(f"  agent: {entry['agent']}")
            finding = entry.get("finding", {})
            print(f"  file: {finding.get('file', '?')}:{finding.get('line', '?')}")
            print(f"  reason: {entry.get('reason', '?')}")
            response = input("  [y/N]: ").strip().lower()
            if response != "y":
                continue

        # Build an Exclusion model from the raw entry so canonicalize_exclusion
        # sees the same shape the signed-path Exclusions have. The runtime-only
        # fields (quarantined, trust_state) get their defaults — they're
        # excluded from canonicalization by _EXCLUSION_CANONICAL_EXCLUDE, so
        # the signed bytes match what verify_exclusion will recompute on reload.
        excl = Exclusion(**entry)
        canonical = canonicalize_exclusion(excl)
        signature = sign_content(canonical, private_key=priv)

        entry["signed_by"] = signer_email
        entry["signature"] = signature
        entry["signature_version"] = 1
        signed_count += 1

    if signed_count == 0:
        return {
            "status": "success",
            "signed_count": 0,
            "message": "All exclusions already signed. Nothing to migrate.",
        }

    # T9-I2 — atomic write via tmp file + os.replace. A crash mid-write
    # cannot leave a partial YAML file. os.replace is atomic on POSIX and
    # Windows (as of Python 3.3+).
    tmp_path = path.with_suffix(".yaml.tmp")
    try:
        tmp_path.write_text(
            yaml.dump(raw, default_flow_style=False, sort_keys=False),
            encoding="utf-8",
        )
        os.replace(tmp_path, path)
    except PermissionError as exc:
        # Best-effort cleanup of the tmp file if we failed after writing it
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
        "status": "success",
        "signed_count": signed_count,
        "message": f"Signed {signed_count} legacy exclusion(s) with {signer_email}.",
    }
