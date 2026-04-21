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

SECURITY — script_name validation:
    This module enforces ``script_name`` against
    ``^[a-z0-9][a-z0-9-]{2,62}$`` as defense-in-depth. The canonical
    validator lives in ``adaptive.script_name.validate_script_name``
    (T2); every engine-layer caller runs that validation before reaching
    this module. Defense here ensures that:
    - Bypass bugs in upstream callers surface as ``ValueError`` from
      the closest boundary, not as path-traversal filesystem ops.
    - Direct callers of this public module (tests, future tooling)
      cannot construct a traversal primitive via ``script_name``.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from screw_agents.adaptive.script_name import validate_script_name as _validate_script_name
from screw_agents.adaptive.signing import compute_script_sha256  # noqa: F401 — re-exported for T3 engine

__all__ = [
    "resolve_staging_dir",
    "resolve_registry_path",
    "StagedPaths",
    "write_staged_files",
    "read_staged_files",
    "delete_staged_files",
    # Phase 3b T3: registry append/query + I-opus-3 runtime validator.
    "append_registry_entry",
    "query_registry_most_recent",
    "fallback_walk_for_script",
    "validate_pending_approval",
]


# Symmetric-allowlist session_id validator (I-opus-1 fix). The pre-Opus
# validator was a 5-char denylist which let `"foo\nbar"`, `"foo:bar"`,
# `".hidden"`, `"\xff"` through — each a distinct threat:
#   - `\n`: JSONL audit-log line-injection when session_id is embedded
#           into pending-approvals.jsonl (T3+).
#   - `:` on NTFS: alternate-data-stream primitive.
#   - leading-`.`: hidden-dir bypass of operator `ls` and sweep walks.
#   - high-bit bytes: unicode homoglyphs and terminal-control injection.
# This regex mirrors script_name's allowlist discipline: \A...\Z anchors
# (no newline slip), strict character allowlist (alnum + underscore +
# dash), bounded length 1-64.
_SESSION_ID_RE = re.compile(r"\A[A-Za-z0-9_\-]{1,64}\Z")


def resolve_staging_dir(project_root: Path, session_id: str) -> Path:
    """Return the absolute path to the session-scoped staging dir.

    Does NOT create the directory. Caller decides when to mkdir (so read-only
    lookups don't pollute the filesystem).

    Raises:
        ValueError: If session_id is empty OR does not match
            ``\\A[A-Za-z0-9_-]{1,64}\\Z`` (alphanumeric + underscore + dash,
            1-64 chars). Rejects newlines (JSONL-injection primitive),
            colons (NTFS alternate-data-stream primitive), leading dots
            (hidden-dir bypass), and high-bit bytes (homoglyph /
            terminal-control primitive).
    """
    if not session_id:
        raise ValueError("session_id must be non-empty")
    if not _SESSION_ID_RE.match(session_id):
        raise ValueError(
            f"session_id {session_id!r} does not match "
            f"^[A-Za-z0-9_-]{{1,64}}$ (alphanumeric + underscore + dash, "
            f"1-64 chars). Rejects newlines, colons, leading dots, and "
            f"high-bit bytes."
        )
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

    SECURITY: ``script_name`` is validated against
    ``^[a-z0-9][a-z0-9-]{2,62}$`` at entry (defense-in-depth; the canonical
    validator lives in ``adaptive.script_name.validate_script_name``).
    Invalid names raise ``ValueError`` before any filesystem access.
    """
    _validate_script_name(script_name)
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

    SECURITY: ``script_name`` is validated against
    ``^[a-z0-9][a-z0-9-]{2,62}$`` at entry (defense-in-depth; the canonical
    validator lives in ``adaptive.script_name.validate_script_name``).
    Invalid names raise ``ValueError`` before any filesystem access.
    """
    _validate_script_name(script_name)
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

    SECURITY: ``script_name`` is validated against
    ``^[a-z0-9][a-z0-9-]{2,62}$`` at entry (defense-in-depth; the canonical
    validator lives in ``adaptive.script_name.validate_script_name``).
    Invalid names raise ``ValueError`` before any filesystem access.
    """
    _validate_script_name(script_name)
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


# =====================================================================
# Phase 3b T3 — PendingApproval registry (append-only JSONL audit log)
# =====================================================================
#
# The audit log at ``.screw/local/pending-approvals.jsonl`` is the
# forensic-evidence chain for every adaptive-script lifecycle event
# (stage, promote, reject, tamper, sweep). Downstream C1 tasks (T4
# promote, T5 reject, T6 sweep) consume these entries via
# ``query_registry_most_recent`` and rely on the per-event-type field
# contract documented inline in ``PendingApproval`` at
# ``models.py``. A silently-malformed entry would corrupt every
# subsequent forensic-analysis query — hence the runtime validator
# below (I-opus-3 absorbed into T3 as the first producer).
#
# POSIX-atomicity: each ``os.write(fd, line)`` of a <PIPE_BUF-sized
# (4096 bytes on Linux) line is atomic under ``O_APPEND``. Registry
# entries are <500 bytes; safe for single-process MCP.


# I-opus-3: runtime enforcement of the per-event-type required-fields
# contract. The ``PendingApproval(TypedDict, total=False)`` in
# ``models.py`` documents these via inline comments but cannot
# enforce them structurally (TypedDict.total=False disables the
# TypedDict-level required check). Without this runtime guard, any
# producer could emit ``{"event": "staged"}`` with no sha256 / no
# staged_at and corrupt downstream consumers.
#
# New event types must opt in by adding an entry here — unknown events
# raise. This prevents the drift where a new producer invents an event
# name that older consumers do not know how to filter.
_REQUIRED_FIELDS_BY_EVENT: dict[str, frozenset[str]] = {
    "staged": frozenset({
        "event", "script_name", "session_id", "script_sha256",
        "target_gap", "staged_at", "schema_version",
    }),
    "promoted": frozenset({
        "event", "script_name", "session_id", "script_sha256",
        "signed_by", "promoted_at", "schema_version",
    }),
    "promoted_via_fallback": frozenset({
        "event", "script_name", "session_id", "script_sha256",
        "signed_by", "promoted_at", "schema_version",
    }),
    "promoted_confirm_stale": frozenset({
        "event", "script_name", "session_id", "script_sha256",
        "signed_by", "promoted_at", "schema_version",
    }),
    "rejected": frozenset({
        "event", "script_name", "session_id", "reason",
        "rejected_at", "schema_version",
    }),
    "tamper_detected": frozenset({
        "event", "script_name", "session_id",
        "expected_sha256", "actual_sha256", "evidence_path",
        "tampered_at", "schema_version",
    }),
    "swept": frozenset({
        "event", "script_name", "session_id",
        "swept_at", "sweep_reason", "schema_version",
    }),
}


def validate_pending_approval(entry: dict) -> None:
    """Raise ValueError if entry lacks required fields for its event type.

    Called from ``append_registry_entry`` BEFORE the JSONL write to
    prevent silent forensic-audit corruption. Unknown event types raise
    (new event types require an explicit opt-in via
    ``_REQUIRED_FIELDS_BY_EVENT``).

    Args:
        entry: Registry entry dict (conforms to ``PendingApproval``
            TypedDict in ``models.py``).

    Raises:
        ValueError: If ``event`` key is missing, event type is unknown,
            or the entry lacks one of the event-type-specific required
            fields. Error message names the concrete missing fields so
            the caller can fix the producer.
    """
    event = entry.get("event")
    if event is None:
        raise ValueError("PendingApproval entry missing required 'event' field")
    required = _REQUIRED_FIELDS_BY_EVENT.get(event)
    if required is None:
        raise ValueError(
            f"PendingApproval entry has unknown event type: {event!r}"
        )
    missing = required - set(entry.keys())
    if missing:
        raise ValueError(
            f"PendingApproval '{event}' entry missing required fields: "
            f"{sorted(missing)}"
        )


def append_registry_entry(project_root: Path, entry: dict) -> None:
    """Append one JSONL entry to pending-approvals.jsonl atomically.

    POSIX-atomicity: a single ``os.write(fd, line)`` < PIPE_BUF bytes is
    atomic on Linux under ``O_APPEND``. Entries are <500 bytes; safe
    for single-process MCP.

    Calls ``validate_pending_approval(entry)`` as the first line to
    fail-fast before any I/O — this prevents partial-state registry
    writes (PARTIAL-STATE SEMANTICS below only covers filesystem vs
    registry, not corruption within the registry itself).

    Creates parent dirs if needed. Raises ValueError on filesystem
    errors per T13-C1 discipline.

    PARTIAL-STATE SEMANTICS: If the engine has already written the
    staged ``.py`` + ``.meta.yaml`` files and THIS registry append raises
    ValueError, the staged files remain on disk without a registry
    entry. This is deliberate — the filesystem is the source of truth;
    the registry is the audit log. T6's ``sweep_stale_staging`` recovers
    orphaned staging dirs by age. The engine does NOT roll back staged
    files on registry-write failure.

    Args:
        project_root: Project root containing ``.screw/`` directory.
        entry: Dict conforming to ``PendingApproval``. Must pass
            ``validate_pending_approval`` (called as first line).

    Raises:
        ValueError: From ``validate_pending_approval`` on schema failure,
            or wrapping (PermissionError, OSError) with
            ``{type(exc).__name__}`` in the message on filesystem failure
            (T13-C1 discipline).
    """
    validate_pending_approval(entry)  # I-opus-3: fail-fast before any I/O
    registry_path = resolve_registry_path(project_root)
    try:
        registry_path.parent.mkdir(parents=True, exist_ok=True)
        line = json.dumps(entry, separators=(",", ":"), sort_keys=True) + "\n"
        # O_APPEND | O_WRONLY | O_CREAT; let OS handle the atomic append.
        fd = os.open(
            registry_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644
        )
        try:
            os.write(fd, line.encode("utf-8"))
        finally:
            os.close(fd)
    except (PermissionError, OSError) as exc:
        raise ValueError(
            f"failed to append registry entry to {registry_path} "
            f"({type(exc).__name__}: {exc})"
        ) from exc


def query_registry_most_recent(
    project_root: Path,
    *,
    script_name: str,
    session_id: str,
) -> dict | None:
    """Return the most-recent registry entry matching (script_name, session_id).

    Returns None if the registry file is missing, empty, or no entry
    matches. Ignores corrupted JSONL lines (tolerate-and-skip); returns
    whatever valid entries matched. The caller interprets "no matching
    entry" as "fall back to filesystem walk" per Q3 in the design spec.

    "Most recent" == last entry in file order (JSONL is append-only and
    each event emits a timestamp; file order == chronological order).

    Args:
        project_root: Project root containing ``.screw/`` directory.
        script_name: Script name to match on.
        session_id: Session id to match on.

    Returns:
        The last entry in the registry with matching
        (script_name, session_id), or None if no match / empty registry.

    Raises:
        ValueError: On (PermissionError, OSError) reading the registry.
    """
    registry_path = resolve_registry_path(project_root)
    if not registry_path.exists():
        return None
    try:
        lines = registry_path.read_text(encoding="utf-8").splitlines()
    except (PermissionError, OSError) as exc:
        raise ValueError(
            f"failed to read registry {registry_path} "
            f"({type(exc).__name__}: {exc})"
        ) from exc

    most_recent: dict | None = None
    for raw in lines:
        raw = raw.strip()
        if not raw:
            continue
        try:
            entry = json.loads(raw)
        except json.JSONDecodeError:
            continue  # corrupt line; tolerate
        if (
            entry.get("script_name") == script_name
            and entry.get("session_id") == session_id
        ):
            most_recent = entry  # later entries overwrite earlier
    return most_recent


def fallback_walk_for_script(
    project_root: Path,
    *,
    script_name: str,
) -> list[tuple[str, Path]]:
    """Walk ``.screw/staging/*/adaptive-scripts/`` for ``{script_name}.py``.

    Returns ``[(session_id, py_path), ...]``. Used when registry lookup
    fails (Q3 fallback path in the design spec). Empty list if nothing
    is found.

    Args:
        project_root: Project root containing ``.screw/`` directory.
        script_name: Bare script name (no ``.py`` extension).

    Returns:
        List of (session_id, py_path) pairs, sorted by session_id for
        deterministic ordering. Empty list if staging dir is absent or
        no matching files exist.

    Raises:
        ValueError: Wrapping (PermissionError, OSError) on filesystem
            walk failure.
    """
    staging_root = project_root / ".screw" / "staging"
    if not staging_root.exists():
        return []
    matches: list[tuple[str, Path]] = []
    try:
        for session_dir in sorted(staging_root.iterdir()):
            if not session_dir.is_dir():
                continue
            py = session_dir / "adaptive-scripts" / f"{script_name}.py"
            if py.exists():
                matches.append((session_dir.name, py))
    except (PermissionError, OSError) as exc:
        raise ValueError(
            f"failed to walk staging root {staging_root} "
            f"({type(exc).__name__}: {exc})"
        ) from exc
    return matches


def _utc_now_iso() -> str:
    """Return UTC now as ISO8601 with Z suffix (seconds precision).

    Example: ``"2026-04-21T14:03:27Z"``. Parsed downstream by
    ``datetime.strptime(..., "%Y-%m-%dT%H:%M:%SZ")`` with ``tzinfo``
    injected — keep the format stable across releases.
    """
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
