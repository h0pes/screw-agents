"""ProjectRoot — filesystem chokepoint for adaptive scripts.

All file access from within an adaptive script goes through ProjectRoot instead
of `open()` or `pathlib.Path.read_text()`. This is the single enforcement point
for "scripts cannot read files outside project_root" — even if the sandbox layer
(bwrap/sandbox-exec) has a bug, ProjectRoot's Python-level checks add a second
defense.
"""

from __future__ import annotations

from pathlib import Path


class ProjectPathError(ValueError):
    """Raised when a script attempts to access a path outside the project root."""


class ProjectRoot:
    """Bounded filesystem accessor for adaptive analysis scripts.

    Given a project root directory, provides read-only access to files within it.
    Rejects absolute paths, parent-dir traversal, and symlink escapes.

    Usage from within an adaptive script:

        from screw_agents.adaptive import ProjectRoot

        def analyze(project: ProjectRoot) -> None:
            content = project.read_file("src/services/user_service.py")
            # ...

    The script's `analyze(project)` entry point receives a ProjectRoot instance
    constructed by the executor — scripts never construct ProjectRoot themselves.
    """

    def __init__(self, root: Path):
        self._root = root.resolve()
        if not self._root.is_dir():
            raise ValueError(f"project root is not a directory: {root}")

    @property
    def path(self) -> Path:
        """The absolute resolved project root."""
        return self._root

    def read_file(self, relative_path: str) -> str:
        """Read a file inside the project root as UTF-8 text.

        Args:
            relative_path: path relative to project root.

        Raises:
            ProjectPathError: if the path escapes the project root.
            FileNotFoundError: if the file does not exist.
        """
        return self._resolve_and_check(relative_path).read_text(encoding="utf-8")

    def list_files(self, pattern: str) -> list[str]:
        """List files under project root matching a glob pattern.

        Args:
            pattern: glob pattern relative to project root (e.g., "**/*.py")

        Returns:
            Sorted list of relative paths (forward slashes).
        """
        matches: list[str] = []
        for path in self._root.glob(pattern):
            try:
                resolved = self._resolve_and_check(str(path.relative_to(self._root)))
                if resolved.is_file():
                    matches.append(str(path.relative_to(self._root)).replace("\\", "/"))
            except (ProjectPathError, ValueError):
                continue
        return sorted(matches)

    def _resolve_and_check(self, relative_path: str) -> Path:
        """Resolve a relative path and verify it stays within the project root.

        Rejects:
        - Absolute paths (`/etc/passwd`)
        - Parent traversal (`../outside.py`)
        - Symlinks pointing outside the project root
        """
        if Path(relative_path).is_absolute():
            raise ProjectPathError(f"absolute paths not allowed: {relative_path}")

        candidate = (self._root / relative_path).resolve()
        try:
            candidate.relative_to(self._root)
        except ValueError:
            raise ProjectPathError(
                f"path is outside project root: {relative_path}"
            ) from None

        return candidate
