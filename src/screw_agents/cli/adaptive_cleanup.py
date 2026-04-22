"""Backend for /screw:adaptive-cleanup — list, stale-check, and remove
adaptive scripts under `.screw/custom-scripts/`.

Staleness is a per-script property computed on demand (not persisted):
a script is stale when NONE of its declared `target_patterns` have
matching call sites in the current project AST. Semantic matches
`src/screw_agents/adaptive/executor.py::_is_stale` exactly — see that
function's docstring for the detailed rationale.

AST-walk cost is paid only when `list_adaptive_scripts(...)` is called,
so this is safe for the `/screw:adaptive-cleanup` use case. Do NOT call
this from hot-path code (e.g., `verify_trust` or `assemble_scan`) —
there the cost would apply per scan regardless of whether the user cares
about cleanup.

If the executor's `_is_stale` semantic ever changes, update `_check_stale`
here to match — the two functions share intent (empty patterns → not
stale; any live pattern → not stale; all dead → stale) and drift would
confuse users who see "stale" in one surface but not the other.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from screw_agents.adaptive.executor import _check_stale


def list_adaptive_scripts(project_root: Path) -> list[dict[str, Any]]:
    """List every adaptive script in `.screw/custom-scripts/` with metadata
    AND per-script stale status.

    Args:
        project_root: Absolute path to the project root.

    Returns:
        List of dicts, one per script. Each dict has keys:

        - ``name``: str, from meta.name
        - ``created``: str, from meta.created (ISO8601)
        - ``created_by``: str, from meta.created_by
        - ``domain``: str, from meta.domain (e.g. "injection-input-handling")
        - ``description``: str, from meta.description
        - ``target_patterns``: list[str], from meta.target_patterns
        - ``findings_produced``: int, from meta.findings_produced (default 0)
        - ``last_used``: str | None, from meta.last_used
        - ``validated``: bool, from meta.validated (default False)
        - ``signed_by``: str | None, from meta.signed_by
        - ``stale``: bool, COMPUTED per ``_check_stale``
        - ``stale_reason``: str | None, COMPUTED (human-readable reason
          when stale, or ``"no target_patterns declared"`` when patterns
          are empty; ``None`` when not stale)

        Entries with missing / malformed meta YAML are skipped silently
        (the user can surface these via ``verify_trust`` which marks them
        as quarantined). Entries with a meta but missing companion ``.py``
        are also skipped (same reason).

        Empty list if ``.screw/custom-scripts/`` does not exist.

    Sort order: alphabetical by ``name`` for deterministic output.
    """
    script_dir = project_root / ".screw" / "custom-scripts"
    if not script_dir.exists():
        return []

    scripts: list[dict[str, Any]] = []
    for meta_file in sorted(script_dir.glob("*.meta.yaml")):
        # meta_file has two suffixes (".meta.yaml"); stripping both yields
        # the bare script name. Use explicit string handling to avoid
        # path-suffix ambiguity across Python versions.
        stem = meta_file.name[: -len(".meta.yaml")]
        source_file = script_dir / f"{stem}.py"
        if not source_file.exists():
            continue
        try:
            meta = yaml.safe_load(meta_file.read_text(encoding="utf-8"))
        except (yaml.YAMLError, OSError):
            continue
        if not isinstance(meta, dict):
            continue

        target_patterns = meta.get("target_patterns", []) or []
        stale, stale_reason = _check_stale(project_root, target_patterns)

        scripts.append({
            "name": meta.get("name"),
            "created": meta.get("created"),
            "created_by": meta.get("created_by"),
            "domain": meta.get("domain"),
            "description": meta.get("description", ""),
            "target_patterns": target_patterns,
            "findings_produced": meta.get("findings_produced", 0),
            "last_used": meta.get("last_used"),
            "validated": meta.get("validated", False),
            "signed_by": meta.get("signed_by"),
            "stale": stale,
            "stale_reason": stale_reason,
        })

    # Sort by name for deterministic output. None-named entries (malformed
    # but parsed YAML) are rare; sort them to the end by treating None as
    # a very-large string so ordering stays total.
    scripts.sort(key=lambda s: (s["name"] is None, s["name"] or ""))
    return scripts


def remove_adaptive_script(
    project_root: Path, *, script_name: str
) -> dict[str, Any]:
    """Remove an adaptive script's ``.py`` + ``.meta.yaml`` pair from
    ``.screw/custom-scripts/``.

    Args:
        project_root: Absolute path to the project root.
        script_name: Script name without suffix (e.g. ``"qb-check"`` for
            ``qb-check.py`` + ``qb-check.meta.yaml``).

    Returns:
        Dict with keys:

        - ``status``: ``"removed"`` | ``"not_found"`` | ``"partial"`` | ``"error"``
        - ``message``: Human-readable summary
        - ``removed_files``: list[str] of absolute paths deleted

        Status semantics:

        - ``"removed"``: both files existed and both were deleted.
        - ``"not_found"``: neither file existed.
        - ``"partial"``: only one of the pair existed (the other was
          missing); the present one was deleted. This is a stale-state
          recovery case — surfacing it in the status helps the user
          understand the state before and after.
        - ``"error"``: a filesystem error prevented deletion.
          ``message`` explains.

    Does NOT validate signature / trust status — deletion is a destructive
    user-initiated action; unsigned/quarantined scripts are equally
    removable. The user made the decision in ``/screw:adaptive-cleanup``.

    Does NOT cascade (e.g., to ``.screw/learning/`` or ``.screw/findings/``
    that may reference this script). Those artifacts survive — they're
    historical records of what the script produced, not live state.

    Atomicity: ``Path.unlink`` is called for each file individually. If
    the process dies between the two unlinks, disk has a partial state,
    but the next ``list_adaptive_scripts`` call skips that entry (companion
    missing) and the next ``remove_adaptive_script(same_name)`` call
    returns ``"partial"`` cleanly. This is acceptable.
    """
    script_dir = project_root / ".screw" / "custom-scripts"
    source_file = script_dir / f"{script_name}.py"
    meta_file = script_dir / f"{script_name}.meta.yaml"

    source_exists = source_file.exists()
    meta_exists = meta_file.exists()

    if not source_exists and not meta_exists:
        return {
            "status": "not_found",
            "message": f"No adaptive script named '{script_name}' found.",
            "removed_files": [],
        }

    removed: list[str] = []
    try:
        if source_exists:
            source_file.unlink()
            removed.append(str(source_file))
        if meta_exists:
            meta_file.unlink()
            removed.append(str(meta_file))
    except OSError as exc:
        return {
            "status": "error",
            "message": (
                f"Filesystem error removing adaptive script "
                f"'{script_name}': {exc}"
            ),
            "removed_files": removed,
        }

    if source_exists and meta_exists:
        return {
            "status": "removed",
            "message": (
                f"Removed adaptive script '{script_name}' "
                f"(both .py and .meta.yaml)."
            ),
            "removed_files": removed,
        }

    # Partial state: only one side existed.
    missing = ".meta.yaml" if source_exists else ".py"
    return {
        "status": "partial",
        "message": (
            f"Adaptive script '{script_name}' was in a partial state: "
            f"companion {missing} was already missing. Removed the remaining "
            f"file."
        ),
        "removed_files": removed,
    }
