"""Persistent false-positive learning — exclusion storage and matching.

Phase 2 implements layers 1-2 of PRD §11.2:
  Layer 1: Exclusion storage in .screw/learning/exclusions.yaml
  Layer 2: Pre-scan filtering via scope-based matching

Layers 3 (aggregation) and 4 (feedback loop) are Phase 4 scope.
"""

from __future__ import annotations

import fnmatch
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from screw_agents.models import Exclusion, ExclusionInput

_EXCLUSIONS_PATH = Path(".screw") / "learning" / "exclusions.yaml"


def load_exclusions(project_root: Path) -> list[Exclusion]:
    """Read exclusions from .screw/learning/exclusions.yaml.

    Args:
        project_root: Project root directory.

    Returns:
        List of Exclusion objects. Empty list if file doesn't exist.

    Raises:
        ValueError: If the YAML is malformed or unparseable.
    """
    path = project_root / _EXCLUSIONS_PATH
    if not path.exists():
        return []

    try:
        raw = yaml.safe_load(path.read_text())
    except yaml.YAMLError as exc:
        raise ValueError(f"Malformed exclusions YAML at {path}: {exc}") from exc

    if raw is None or not isinstance(raw, dict):
        return []

    entries = raw.get("exclusions", [])
    if not entries:
        return []

    return [Exclusion(**entry) for entry in entries]


def record_exclusion(project_root: Path, exclusion: ExclusionInput) -> Exclusion:
    """Record a new exclusion in .screw/learning/exclusions.yaml.

    Creates the directory and file if they don't exist. Assigns a unique
    ID with format fp-YYYY-MM-DD-NNN (sequential per day).

    Args:
        project_root: Project root directory.
        exclusion: The exclusion input from the subagent.

    Returns:
        The saved Exclusion with generated id and created timestamp.
    """
    path = project_root / _EXCLUSIONS_PATH
    path.parent.mkdir(parents=True, exist_ok=True)

    existing = load_exclusions(project_root) if path.exists() else []

    now = datetime.now(timezone.utc)
    date_str = now.strftime("%Y-%m-%d")
    today_prefix = f"fp-{date_str}-"
    today_ids = [e.id for e in existing if e.id.startswith(today_prefix)]
    next_seq = len(today_ids) + 1
    exclusion_id = f"{today_prefix}{next_seq:03d}"

    saved = Exclusion(
        id=exclusion_id,
        created=now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        agent=exclusion.agent,
        finding=exclusion.finding,
        reason=exclusion.reason,
        scope=exclusion.scope,
        times_suppressed=0,
        last_suppressed=None,
    )

    existing.append(saved)
    data = {"exclusions": [e.model_dump() for e in existing]}
    path.write_text(yaml.dump(data, default_flow_style=False, sort_keys=False))

    return saved


def match_exclusions(
    exclusions: list[Exclusion],
    *,
    file: str,
    line: int,
    code: str,
    agent: str,
    function: str | None = None,
) -> list[Exclusion]:
    """Return exclusions that match a finding's context.

    Args:
        exclusions: All loaded exclusions.
        file: File path of the finding.
        line: Line number of the finding.
        code: Code content at the finding location.
        agent: Agent name that produced the finding.
        function: Optional function name containing the finding.

    Returns:
        List of matching Exclusion objects.
    """
    matches: list[Exclusion] = []
    for exc in exclusions:
        if exc.agent != agent:
            continue
        if _scope_matches(exc, file=file, line=line, code=code, function=function):
            matches.append(exc)
    return matches


def _scope_matches(
    exc: Exclusion,
    *,
    file: str,
    line: int,
    code: str,
    function: str | None,
) -> bool:
    """Check if an exclusion's scope matches the given finding context."""
    scope = exc.scope
    scope_type = scope.type

    if scope_type == "exact_line":
        return scope.path == file and exc.finding.line == line

    if scope_type == "pattern":
        if scope.pattern is None:
            return False
        return fnmatch.fnmatch(code, f"*{scope.pattern}*")

    if scope_type == "file":
        return scope.path == file

    if scope_type == "directory":
        if scope.path is None:
            return False
        dir_path = scope.path.rstrip("/") + "/"
        return file.startswith(dir_path)

    if scope_type == "function":
        return scope.path == file and scope.name == function

    return False
