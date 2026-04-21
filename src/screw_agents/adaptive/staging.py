"""Staging-directory + pending-approvals registry for adaptive scripts.

Layout:
    .screw/staging/{session_id}/adaptive-scripts/{script_name}.{py,meta.yaml}
    .screw/local/pending-approvals.jsonl  (append-only JSONL audit log)

This module has NO signing logic. It only reads/writes files on disk and
appends/queries the registry. The shared signing helper lives at
``adaptive/signing.py::_sign_script_bytes``; engine methods compose the
two. See spec §1.1 "File inventory" for the deliberate separation.

Registry event types (one entry per event, append-only):
    - staged
    - promoted
    - promoted_via_fallback
    - promoted_confirm_stale
    - rejected
    - tamper_detected
    - swept (issued by sweep_stale_staging)

SECURITY NOTE:
    This module does NOT validate ``script_name``. Callers MUST validate
    the name against ``^[a-z0-9][a-z0-9-]{2,62}$`` (the regex that
    ``_sign_script_bytes`` enforces) BEFORE calling ``write_staged_files``
    or ``delete_staged_files``. A malicious or buggy caller passing
    ``"../../../etc/shadow"`` as ``script_name`` will write outside the
    staging directory. In the normal C1 flow, ``engine.stage_adaptive_script``
    validates the name before reaching this module (see T3).
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

__all__ = [
    "resolve_staging_dir",
    "resolve_registry_path",
    "StagedPaths",
    "write_staged_files",
    "read_staged_files",
    "delete_staged_files",
]


def resolve_staging_dir(project_root: Path, session_id: str) -> Path:
    """Return the absolute path to the session-scoped staging dir.

    Does NOT create the directory. Caller decides when to mkdir (so read-only
    lookups don't pollute the filesystem).

    Raises ValueError if session_id is empty or contains path separators.
    """
    if not session_id:
        raise ValueError("session_id must be non-empty")
    if session_id in (".", ".."):
        raise ValueError(f"session_id cannot be {session_id!r} (would collapse session isolation)")
    if "/" in session_id or "\\" in session_id or "\x00" in session_id:
        raise ValueError(f"session_id contains invalid path chars: {session_id!r}")
    return project_root / ".screw" / "staging" / session_id / "adaptive-scripts"


def resolve_registry_path(project_root: Path) -> Path:
    """Return the absolute path to pending-approvals.jsonl (may not exist)."""
    return project_root / ".screw" / "local" / "pending-approvals.jsonl"


@dataclass(frozen=True)
class StagedPaths:
    """Return value from write_staged_files; paths to staged artifacts."""

    py_path: Path
    meta_path: Path


def write_staged_files(
    *,
    project_root: Path,
    script_name: str,
    source: str,
    meta_yaml: str,
    session_id: str,
) -> StagedPaths:
    """Write source + meta to staging-dir atomically.

    Order: source (.py) first, then meta (.meta.yaml). On meta failure,
    best-effort unlinks the just-written .py to avoid leaving a partial
    stage. Mirrors T18a's atomic-write discipline for custom-scripts/.

    Raises ValueError wrapping (PermissionError, OSError) with
    {type(exc).__name__} in the message (T13-C1 discipline).

    SECURITY: ``script_name`` is NOT validated here — callers must have
    already verified it matches ``^[a-z0-9][a-z0-9-]{2,62}$`` or they risk
    path traversal via the ``stage_dir / f"{script_name}.py"`` derivation.
    """
    stage_dir = resolve_staging_dir(project_root, session_id)
    try:
        stage_dir.mkdir(parents=True, exist_ok=True)
    except (PermissionError, OSError) as exc:
        raise ValueError(
            f"failed to create staging dir {stage_dir} "
            f"({type(exc).__name__}: {exc})"
        ) from exc

    py_path = stage_dir / f"{script_name}.py"
    meta_path = stage_dir / f"{script_name}.meta.yaml"
    # String-concat from script_name (not Path.with_suffix) — mirrors T18a's
    # engine.py pattern exactly. `Path("x.meta.yaml").with_suffix(".meta.yaml.tmp")`
    # produces `x.meta.meta.yaml.tmp` because Path.suffix is only the last
    # dotted segment. Concat keeps tmp names symmetric with their targets.
    py_tmp = stage_dir / f"{script_name}.py.tmp"
    meta_tmp = stage_dir / f"{script_name}.meta.yaml.tmp"

    # Source first.
    try:
        py_tmp.write_text(source, encoding="utf-8")
        os.replace(py_tmp, py_path)
    except (PermissionError, OSError) as exc:
        try:
            py_tmp.unlink()
        except OSError:
            pass
        raise ValueError(
            f"failed to write staged source {py_path} "
            f"({type(exc).__name__}: {exc})"
        ) from exc

    # Meta second, with rollback-of-.py on failure.
    try:
        meta_tmp.write_text(meta_yaml, encoding="utf-8")
        os.replace(meta_tmp, meta_path)
    except (PermissionError, OSError) as exc:
        for cleanup_target in (meta_tmp, py_path):
            try:
                cleanup_target.unlink()
            except OSError:
                pass
        raise ValueError(
            f"failed to write staged meta {meta_path} "
            f"({type(exc).__name__}: {exc}); "
            f"rolled back source file"
        ) from exc

    return StagedPaths(py_path=py_path, meta_path=meta_path)


def read_staged_files(
    *,
    project_root: Path,
    script_name: str,
    session_id: str,
) -> tuple[str, str]:
    """Return (source, meta_yaml) strings from staging.

    Raises FileNotFoundError if either file is missing.
    Raises ValueError wrapping OSError on other filesystem errors.

    SECURITY: ``script_name`` is NOT validated here — caller must have verified it.
    """
    stage_dir = resolve_staging_dir(project_root, session_id)
    py_path = stage_dir / f"{script_name}.py"
    meta_path = stage_dir / f"{script_name}.meta.yaml"

    try:
        source = py_path.read_text(encoding="utf-8")
        meta_yaml = meta_path.read_text(encoding="utf-8")
    except FileNotFoundError:
        raise
    except (PermissionError, OSError) as exc:
        raise ValueError(
            f"failed to read staged files for {script_name} in {session_id} "
            f"({type(exc).__name__}: {exc})"
        ) from exc

    return source, meta_yaml


def delete_staged_files(
    *,
    project_root: Path,
    script_name: str,
    session_id: str,
) -> None:
    """Delete .py + .meta.yaml from staging (idempotent).

    Missing files are NOT an error — second-reject/second-promote scenarios.
    Raises ValueError wrapping OSError on permission / busy-file errors.

    SECURITY: ``script_name`` is NOT validated here — caller must have verified it.
    """
    stage_dir = resolve_staging_dir(project_root, session_id)
    for suffix in (".py", ".meta.yaml"):
        target = stage_dir / f"{script_name}{suffix}"
        try:
            target.unlink(missing_ok=True)
        except (PermissionError, OSError) as exc:
            raise ValueError(
                f"failed to delete staged {target} "
                f"({type(exc).__name__}: {exc})"
            ) from exc
