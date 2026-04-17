"""Staging buffer for incremental finding accumulation.

Supports the accumulate_findings / finalize_scan_results split:
  - accumulate_findings writes to `.screw/staging/{session_id}/findings.json`
    (dedup by finding.id)
  - finalize_scan_results reads that staging file, renders reports, and
    caches the result dict in `.screw/staging/{session_id}/result.json`
    so subsequent finalize calls with the same session_id are idempotent
    (return the cached dict rather than erroring on missing staging).

The staging layout is per-scan-session. Parallel scans would use
different session_ids (currently single-process MCP, so parallelism
isn't a concern in Phase 3a; forward-compatible).
"""

from __future__ import annotations

import base64
import json
import secrets
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

    Raises ValueError if the session has already been finalized (the
    `result.json` sidecar exists). Accumulating more findings into a
    finalized session would be silently dropped, so we refuse it loudly
    and require callers to open a fresh session for a new scan.
    """
    # Guard: if this session was already finalized (result.json sidecar exists),
    # refuse to accumulate more findings. The LLM should use a fresh session_id
    # for a new scan.
    if session_id is not None:
        result_path = _staging_dir(project_root, session_id) / "result.json"
        if result_path.exists():
            raise ValueError(
                f"Session {session_id!r} has already been finalized. "
                f"Accumulating more findings into a finalized session would "
                f"be silently dropped. Use a fresh session_id (pass None) "
                f"for a new scan."
            )

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


def finalize_result_cached(
    project_root: Path, session_id: str
) -> dict[str, Any] | None:
    """Check if a session has a cached finalize result.

    Returns the cached result dict if the session was already finalized
    (idempotent re-call path). Returns None if the session is staged but
    not yet finalized (normal first-call path). Raises ValueError if the
    session doesn't exist at all (bogus session_id).
    """
    staging_dir = _staging_dir(project_root, session_id)
    result_path = staging_dir / "result.json"
    findings_path = _staging_findings_path(project_root, session_id)

    if result_path.exists():
        try:
            return json.loads(result_path.read_text())
        except json.JSONDecodeError as exc:
            raise ValueError(
                f"Cached finalize result at {result_path} is not valid JSON: {exc}"
            ) from exc

    if findings_path.exists():
        return None  # staged but not finalized yet; caller proceeds with normal finalize

    raise ValueError(
        f"Staging session {session_id!r} not found (no findings.json and no "
        f"cached result.json). Path checked: {staging_dir}"
    )


def read_for_finalize(
    project_root: Path, session_id: str
) -> list[dict[str, Any]]:
    """Read staged findings for rendering. Caller is responsible for calling
    save_finalize_result once rendering is complete.

    Raises ValueError if the session has no staged findings.
    """
    findings_path = _staging_findings_path(project_root, session_id)
    if not findings_path.exists():
        raise ValueError(
            f"Staging session {session_id!r} has no findings to finalize. "
            f"Path checked: {findings_path}"
        )
    return load_staging(project_root, session_id)


def save_finalize_result(
    project_root: Path,
    session_id: str,
    result: dict[str, Any],
) -> None:
    """Cache the finalize result on disk and remove the staged findings.json.

    The staging directory itself + result.json sidecar persist so that
    subsequent finalize calls with the same session_id return the cached
    result via finalize_result_cached (idempotent protocol).
    """
    staging_dir = _staging_dir(project_root, session_id)
    result_path = staging_dir / "result.json"
    findings_path = _staging_findings_path(project_root, session_id)

    tmp = result_path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(result, indent=2))
    tmp.replace(result_path)

    if findings_path.exists():
        findings_path.unlink()
