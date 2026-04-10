"""Target resolver — resolves target specs to code content.

Supports all target types from PRD §5: file, glob, lines, function,
class, codebase, git_diff, git_commits, pull_request.
"""

from __future__ import annotations

import fnmatch
import glob as globlib
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from screw_agents.treesitter import get_parser

# tree-sitter node types for function/method definitions across languages.
_FUNCTION_NODE_TYPES = {
    "function_definition",      # Python
    "function_declaration",     # JS, Go, C, C++
    "method_definition",        # JS class methods, Ruby
    "method_declaration",       # Java, C#
    "function_item",            # Rust
    "function",                 # PHP
}

_CLASS_NODE_TYPES = {
    "class_definition",         # Python
    "class_declaration",        # JS, Java, C#, C++
    "class",                    # PHP, Ruby
    "struct_item",              # Rust (closest equivalent)
    "impl_item",                # Rust impl blocks
}


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


def _find_named_node(content: str, language: str, name: str, node_types: set[str]):
    """Walk the AST to find a node of the given types with the given name."""
    parser = get_parser(language)
    tree = parser.parse(content.encode("utf-8"))

    def walk(node):
        if node.type in node_types:
            name_node = node.child_by_field_name("name")
            if name_node and name_node.text.decode("utf-8") == name:
                return node
        for child in node.children:
            result = walk(child)
            if result is not None:
                return result
        return None

    return walk(tree.root_node)


def _resolve_function(target: dict) -> list[ResolvedCode]:
    path = target["file"]
    name = target["name"]
    content = _read_file(path)
    lang = _detect_language(path)

    if lang is None:
        raise ValueError(f"Cannot detect language for {path}")

    node = _find_named_node(content, lang, name, node_types=_FUNCTION_NODE_TYPES)
    if node is None:
        raise ValueError(f"Function {name!r} not found in {path}")

    extracted = content.encode("utf-8")[node.start_byte:node.end_byte].decode("utf-8")
    return [ResolvedCode(
        file_path=path,
        content=extracted,
        language=lang,
        line_start=node.start_point[0] + 1,
        line_end=node.end_point[0] + 1,
    )]


def _resolve_class(target: dict) -> list[ResolvedCode]:
    path = target["file"]
    name = target["name"]
    content = _read_file(path)
    lang = _detect_language(path)

    if lang is None:
        raise ValueError(f"Cannot detect language for {path}")

    node = _find_named_node(content, lang, name, node_types=_CLASS_NODE_TYPES)
    if node is None:
        raise ValueError(f"Class {name!r} not found in {path}")

    extracted = content.encode("utf-8")[node.start_byte:node.end_byte].decode("utf-8")
    return [ResolvedCode(
        file_path=path,
        content=extracted,
        language=lang,
        line_start=node.start_point[0] + 1,
        line_end=node.end_point[0] + 1,
    )]


def _resolve_codebase(target: dict) -> list[ResolvedCode]:
    root = Path(target.get("root", "."))
    exclude = target.get("exclude", [])
    default_exclude = {"node_modules", ".venv", "venv", ".git", "__pycache__", "vendor", ".tox"}
    exclude_set = default_exclude | set(exclude)

    from screw_agents.treesitter import EXTENSION_MAP

    results = []
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        if any(ex in path.parts for ex in exclude_set):
            continue
        if path.suffix.lower() not in EXTENSION_MAP:
            continue
        content = path.read_text(encoding="utf-8", errors="replace")
        results.append(ResolvedCode(
            file_path=str(path),
            content=content,
            language=_detect_language(str(path)),
        ))
    return results


def _resolve_git_diff(target: dict) -> list[ResolvedCode]:
    cwd = target.get("cwd", ".")
    context_lines = target.get("context_lines", 10)

    if "base" in target and "head" in target:
        cmd = ["git", "diff", f"-U{context_lines}", f"{target['base']}...{target['head']}", "--"]
    elif target.get("staged_only"):
        cmd = ["git", "diff", "--staged", f"-U{context_lines}", "--"]
    else:
        cmd = ["git", "diff", f"-U{context_lines}", "--"]

    try:
        result = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, check=True)
    except subprocess.CalledProcessError as e:
        raise ValueError(f"git command failed: {e.stderr.strip() or e}") from e

    if not result.stdout.strip():
        return []

    return _parse_unified_diff(result.stdout, cwd)


def _parse_unified_diff(diff_text: str, cwd: str) -> list[ResolvedCode]:
    """Parse unified diff output into ResolvedCode chunks per file."""
    results = []
    current_file = None
    current_lines: list[str] = []

    for line in diff_text.splitlines(keepends=True):
        if line.startswith("diff --git"):
            if current_file and current_lines:
                results.append(ResolvedCode(
                    file_path=current_file,
                    content="".join(current_lines),
                    language=_detect_language(current_file),
                    metadata={"source": "git_diff"},
                ))
            current_lines = []
            current_file = None
        elif line.startswith("+++ b/"):
            current_file = str(Path(cwd) / line[6:].strip())
        elif line.startswith("--- "):
            continue
        elif current_file is not None:
            current_lines.append(line)

    if current_file and current_lines:
        results.append(ResolvedCode(
            file_path=current_file,
            content="".join(current_lines),
            language=_detect_language(current_file),
            metadata={"source": "git_diff"},
        ))

    return results


def _resolve_git_commits(target: dict) -> list[ResolvedCode]:
    cwd = target.get("cwd", ".")
    commit_range = target["range"]
    context_lines = target.get("context_lines", 10)

    try:
        result = subprocess.run(
            ["git", "diff", f"-U{context_lines}", commit_range, "--"],
            cwd=cwd, capture_output=True, text=True, check=True,
        )
    except subprocess.CalledProcessError as e:
        raise ValueError(f"git command failed: {e.stderr.strip() or e}") from e

    if not result.stdout.strip():
        return []

    return _parse_unified_diff(result.stdout, cwd)


def _resolve_pull_request(target: dict) -> list[ResolvedCode]:
    return _resolve_git_diff({
        "base": target["base"],
        "head": target["head"],
        "cwd": target.get("cwd", "."),
        "context_lines": target.get("context_lines", 10),
    })


def filter_by_relevance(
    codes: list[ResolvedCode],
    relevance_signals: list[str],
) -> list[ResolvedCode]:
    """Filter resolved code chunks by agent relevance signals.

    A file is kept if its content contains at least one signal string.
    If signals is empty, all files pass through.
    """
    if not relevance_signals:
        return codes

    filtered = []
    for code in codes:
        content_lower = code.content.lower()
        if any(signal.lower() in content_lower for signal in relevance_signals):
            filtered.append(code)
    return filtered
