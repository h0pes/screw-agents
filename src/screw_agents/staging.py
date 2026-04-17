"""Staging buffer for incremental finding accumulation.

Supports the accumulate_findings / finalize_scan_results split:
  - accumulate_findings writes to `.screw/staging/{session_id}/findings.json`
    (dedup by finding.id)
  - finalize_scan_results reads that staging file, renders reports,
    cleans up the staging directory

The staging layout is per-scan-session. Parallel scans would use
different session_ids (currently single-process MCP, so parallelism
isn't a concern in Phase 3a; forward-compatible).
"""

from __future__ import annotations

import base64
import json
import secrets
import shutil
from pathlib import Path
from typing import Any


def _staging_dir(project_root: Path, session_id: str) -> Path:
    return project_root / ".screw" / "staging" / session_id


def _staging_findings_path(project_root: Path, session_id: str) -> Path:
    return _staging_dir(project_root, session_id) / "findings.json"


def generate_session_id() -> str:
    """Generate a fresh session id. Uses 16 random bytes, base64url-encoded."""
    return base64.urlsafe_b64encode(secrets.token_bytes(16)).rstrip(b"=").decode("ascii")


def load_staging(project_root: Path, session_id: str) -> list[dict[str, Any]]:
    """Load the current staging buffer for a session.

    Returns an empty list if the staging file doesn't exist (session just
    started). Raises ValueError if the staging directory exists but is
    malformed.
    """
    path = _staging_findings_path(project_root, session_id)
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text())
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"Staging file {path} is not valid JSON: {exc}"
        ) from exc
    if not isinstance(data, list):
        raise ValueError(
            f"Staging file {path} must contain a JSON array, got {type(data).__name__}"
        )
    return data


def accumulate(
    project_root: Path,
    findings_chunk: list[dict[str, Any]],
    session_id: str | None = None,
) -> tuple[str, int]:
    """Accumulate a chunk of findings into the staging buffer for a session.

    If session_id is None, a fresh id is generated. Returns (session_id,
    total_count_after_merge). Dedup is by finding["id"] — new findings with
    an existing id REPLACE the prior entry.

    Creates `.screw/staging/{session_id}/` if it doesn't exist.
    """
    if session_id is None:
        session_id = generate_session_id()
    existing = load_staging(project_root, session_id)

    # Validate incoming chunk up-front so a malformed entry doesn't leave
    # staging in a half-merged state.
    for f in findings_chunk:
        if "id" not in f:
            raise ValueError(
                f"Finding is missing required 'id' field: {f}"
            )

    # Build dedup index from existing (by id)
    by_id: dict[str, dict[str, Any]] = {f["id"]: f for f in existing if "id" in f}

    # Merge new chunk — later writer wins for same id
    for f in findings_chunk:
        by_id[f["id"]] = f

    merged = list(by_id.values())

    # Write back
    dir_path = _staging_dir(project_root, session_id)
    dir_path.mkdir(parents=True, exist_ok=True)
    path = _staging_findings_path(project_root, session_id)
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(merged, indent=2))
    tmp.replace(path)  # atomic on POSIX

    return session_id, len(merged)


def read_and_clear(
    project_root: Path,
    session_id: str,
) -> list[dict[str, Any]]:
    """Read the complete accumulated findings for a session, then delete the
    staging directory. Called by finalize_scan_results.

    Raises ValueError if the session doesn't exist (e.g., finalize called
    twice, or with a bogus session_id).
    """
    path = _staging_findings_path(project_root, session_id)
    if not path.exists():
        raise ValueError(
            f"Staging session {session_id!r} not found (already finalized or "
            f"never accumulated). Path checked: {path}"
        )
    findings = load_staging(project_root, session_id)
    shutil.rmtree(_staging_dir(project_root, session_id))
    return findings
