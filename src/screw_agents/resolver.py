"""Target resolver — resolves target specs to code content.

Supports all target types from PRD §5: file, glob, lines, function,
class, codebase, git_diff, git_commits, pull_request.
"""

from __future__ import annotations

import fnmatch
import glob as globlib
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class ResolvedCode:
    """A resolved chunk of code from a target."""

    file_path: str
    content: str
    language: str | None = None
    line_start: int | None = None
    line_end: int | None = None
    metadata: dict = field(default_factory=dict)


def resolve_target(target: dict) -> list[ResolvedCode]:
    """Resolve a target spec dict to code content.

    Args:
        target: A target specification dict following PRD §5.

    Returns:
        List of ResolvedCode chunks.

    Raises:
        ValueError: If the target type is unsupported.
        FileNotFoundError: If a specified file does not exist.
    """
    target_type = target.get("type")
    if target_type == "file":
        return _resolve_file(target)
    elif target_type == "glob":
        return _resolve_glob(target)
    elif target_type == "lines":
        return _resolve_lines(target)
    elif target_type == "function":
        return _resolve_function(target)
    elif target_type == "class":
        return _resolve_class(target)
    elif target_type == "codebase":
        return _resolve_codebase(target)
    elif target_type == "git_diff":
        return _resolve_git_diff(target)
    elif target_type == "git_commits":
        return _resolve_git_commits(target)
    elif target_type == "pull_request":
        return _resolve_pull_request(target)
    else:
        raise ValueError(f"Unsupported target type: {target_type!r}")


def _read_file(path: str) -> str:
    """Read a file, raising FileNotFoundError if missing."""
    p = Path(path)
    if not p.is_file():
        raise FileNotFoundError(f"File not found: {path}")
    return p.read_text(encoding="utf-8", errors="replace")


def _detect_language(path: str) -> str | None:
    """Detect language from file extension."""
    from screw_agents.treesitter import language_from_path
    return language_from_path(path)


def _resolve_file(target: dict) -> list[ResolvedCode]:
    path = target["path"]
    content = _read_file(path)
    return [ResolvedCode(
        file_path=path,
        content=content,
        language=_detect_language(path),
    )]


def _resolve_glob(target: dict) -> list[ResolvedCode]:
    pattern = target["pattern"]
    exclude = target.get("exclude", [])

    matches = sorted(globlib.glob(pattern, recursive=True))

    if exclude:
        filtered = []
        for m in matches:
            if Path(m).is_file() and not any(
                fnmatch.fnmatch(m, ex) for ex in exclude
            ):
                filtered.append(m)
        matches = filtered
    else:
        matches = [m for m in matches if Path(m).is_file()]

    results = []
    for path in matches:
        content = Path(path).read_text(encoding="utf-8", errors="replace")
        results.append(ResolvedCode(
            file_path=path,
            content=content,
            language=_detect_language(path),
        ))
    return results


def _resolve_lines(target: dict) -> list[ResolvedCode]:
    path = target["file"]
    line_spec = target["range"]
    content = _read_file(path)
    lines = content.splitlines(keepends=True)

    if isinstance(line_spec, int):
        # Single line (1-indexed)
        idx = line_spec - 1
        if 0 <= idx < len(lines):
            selected = lines[idx]
        else:
            selected = ""
        start = end = line_spec
    else:
        # Range [start, end] (1-indexed, inclusive)
        start, end = line_spec
        selected = "".join(lines[start - 1 : end])

    return [ResolvedCode(
        file_path=path,
        content=selected,
        language=_detect_language(path),
        line_start=start,
        line_end=end,
    )]


# Stub implementations — filled in by later tasks.

def _resolve_function(target: dict) -> list[ResolvedCode]:
    raise NotImplementedError("function target — implemented in Task 8")


def _resolve_class(target: dict) -> list[ResolvedCode]:
    raise NotImplementedError("class target — implemented in Task 8")


def _resolve_codebase(target: dict) -> list[ResolvedCode]:
    raise NotImplementedError("codebase target — implemented in Task 10")


def _resolve_git_diff(target: dict) -> list[ResolvedCode]:
    raise NotImplementedError("git_diff target — implemented in Task 9")


def _resolve_git_commits(target: dict) -> list[ResolvedCode]:
    raise NotImplementedError("git_commits target — implemented in Task 10")


def _resolve_pull_request(target: dict) -> list[ResolvedCode]:
    raise NotImplementedError("pull_request target — implemented in Task 10")
