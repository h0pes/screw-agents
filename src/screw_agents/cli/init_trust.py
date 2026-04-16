"""Implementation of ``screw-agents init-trust``.

Registers the local Ed25519 key as a trusted reviewer in both
``exclusion_reviewers`` and ``script_reviewers`` lists in
``.screw/config.yaml``. Idempotent: a second run with the same email
returns ``status="already_registered"`` without duplicating entries.

This is the first CLI command to invoke
``learning._get_or_create_local_private_key``. T9-I3 punchlist item
(friendly error wrapping for ``_get_or_create_local_private_key``'s
``OSError``/``PermissionError``) is addressed at this boundary.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from screw_agents.learning import _get_or_create_local_private_key
from screw_agents.models import ReviewerKey
from screw_agents.trust import load_config


def run_init_trust(
    *, project_root: Path, name: str, email: str
) -> dict[str, Any]:
    """Register the local Ed25519 key in the project's trusted-reviewer lists.

    Behavior:
    - On first run, generates a local Ed25519 key under
      ``.screw/local/keys/screw-local.ed25519`` (via
      ``learning._get_or_create_local_private_key``) and writes the OpenSSH
      public key line into BOTH ``exclusion_reviewers`` and
      ``script_reviewers`` in ``.screw/config.yaml``.
    - If the email is already registered in both lists, returns
      ``status="already_registered"`` without modifying the config.
    - If the email is registered in ONLY ONE list (partial registration from
      prior manual edit), the missing list gets the entry appended and
      returns ``status="created"``.

    Args:
        project_root: Project root directory.
        name: Reviewer display name (stored in ReviewerKey.name).
        email: Reviewer email address (used as the idempotency key and
            the ``signed_by`` attribution on future exclusions).

    Returns:
        Dict with ``status`` (``"created"`` or ``"already_registered"``)
        and ``message`` (human-readable summary for CLI output). All
        failure modes raise ``ValueError`` or ``RuntimeError`` instead of
        returning a non-success status — the dispatcher's defensive
        ``status not in (...)`` check is intentional belt-and-suspenders
        for forward compatibility, but no current code path reaches it.

    Raises:
        ValueError: If ``.screw`` exists as a file (not directory), if
            ``.screw/config.yaml`` has invalid schema, or if a permission
            error blocks reading/writing the config. The error message is
            user-actionable (includes the offending path and a suggested fix).
        RuntimeError: If the local key generation fails with an OS error.
            The error message includes the key path and the underlying cause.
    """
    # Wrap load_config for T6-I1/I2 friendly errors at the CLI boundary.
    try:
        config = load_config(project_root)
    except (FileExistsError, NotADirectoryError) as exc:
        raise ValueError(
            f"A `.screw` path exists at {project_root / '.screw'} but is not "
            f"a directory. Remove or rename it before running "
            f"`screw-agents init-trust`. Original error: {exc}"
        ) from exc
    except PermissionError as exc:
        raise ValueError(
            f"Cannot access `.screw/config.yaml` at "
            f"{project_root / '.screw' / 'config.yaml'}: permission denied. "
            f"Check directory permissions or run with appropriate user. "
            f"Original error: {exc}"
        ) from exc

    # T9-I3 — friendly error wrapping for _get_or_create_local_private_key.
    try:
        _priv, pub_line = _get_or_create_local_private_key(project_root)
    except (FileExistsError, NotADirectoryError) as exc:
        # T12-N1 — `mkdir(parents=True, exist_ok=True)` raises one of these
        # if `.screw/local/keys/` (or any parent) exists as a FILE rather
        # than a directory. Surface that distinct case actionably instead
        # of falling through to the generic OSError branch.
        raise RuntimeError(
            f"Cannot create local signing key directory at "
            f"{project_root / '.screw' / 'local' / 'keys'}: a file blocks "
            f"that path. Remove or rename it. Original: {exc}"
        ) from exc
    except PermissionError as exc:
        raise RuntimeError(
            f"Cannot create local signing key at "
            f"{project_root / '.screw' / 'local' / 'keys'}: permission "
            f"denied. Check directory permissions. Original: {exc}"
        ) from exc
    except OSError as exc:
        raise RuntimeError(
            f"Failed to create local signing key at "
            f"{project_root / '.screw' / 'local' / 'keys'}: {exc}. Check "
            f"disk space and filesystem state."
        ) from exc

    # Idempotency: check if this email is already registered in BOTH lists.
    in_exclusion_list = any(r.email == email for r in config.exclusion_reviewers)
    in_script_list = any(r.email == email for r in config.script_reviewers)

    if in_exclusion_list and in_script_list:
        return {
            "status": "already_registered",
            "message": (
                f"{email} is already registered in both exclusion_reviewers "
                f"and script_reviewers. No changes made."
            ),
        }

    # Either missing from one or both lists — register as needed.
    new_reviewer = ReviewerKey(name=name, email=email, key=pub_line)
    if not in_exclusion_list:
        config.exclusion_reviewers = list(config.exclusion_reviewers) + [new_reviewer]
    if not in_script_list:
        config.script_reviewers = list(config.script_reviewers) + [new_reviewer]

    # Write the updated config back. Wrap for T6-I2 parity.
    config_path = project_root / ".screw" / "config.yaml"
    try:
        # T12-N4 — `width=1000` prevents PyYAML from line-folding long
        # OpenSSH key values across multiple lines with continuation chars
        # (which is syntactically valid YAML but visually noisy and tempts
        # users to "fix" it manually, breaking the round-trip).
        config_path.write_text(
            yaml.dump(
                config.model_dump(),
                default_flow_style=False,
                sort_keys=False,
                width=1000,
            ),
            encoding="utf-8",
        )
    except PermissionError as exc:
        raise ValueError(
            f"Cannot write `.screw/config.yaml` at {config_path}: permission "
            f"denied. Check directory permissions. Original error: {exc}"
        ) from exc

    return {
        "status": "created",
        "message": (
            f"Registered {email} in .screw/config.yaml.\n"
            f"Local key stored at "
            f"{project_root / '.screw' / 'local' / 'keys' / 'screw-local.ed25519'} "
            f"(mode 0600).\n"
            f"You can now sign exclusions with `screw-agents migrate-exclusions`."
        ),
    }
