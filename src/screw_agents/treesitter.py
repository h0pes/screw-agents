"""Shared tree-sitter language loading, parser creation, and AST queries.

Used by both the MCP server target resolver (Phase 1) and the benchmark
runner's PrimeVul dedup (Phase 0.5). Replaces the ctypes hack in
benchmarks/runner/primevul.py with the official individual grammar
package API (tree-sitter 0.25+).
"""

from __future__ import annotations

import importlib
from functools import lru_cache
from pathlib import Path

from tree_sitter import Language, Parser

# Lazy imports — each grammar package is imported only when needed.
# This dict maps our canonical language names to (module_name, ts_function_name) pairs.
_GRAMMAR_REGISTRY: dict[str, tuple[str, str]] = {
    "python": ("tree_sitter_python", "language"),
    "javascript": ("tree_sitter_javascript", "language"),
    "typescript": ("tree_sitter_typescript", "language_typescript"),
    "go": ("tree_sitter_go", "language"),
    "rust": ("tree_sitter_rust", "language"),
    "java": ("tree_sitter_java", "language"),
    "ruby": ("tree_sitter_ruby", "language"),
    "php": ("tree_sitter_php", "language_php"),
    "c": ("tree_sitter_c", "language"),
    "cpp": ("tree_sitter_cpp", "language"),
    "c_sharp": ("tree_sitter_c_sharp", "language"),
}

SUPPORTED_LANGUAGES: tuple[str, ...] = tuple(_GRAMMAR_REGISTRY.keys())

# File extension → language name mapping.
EXTENSION_MAP: dict[str, str] = {
    ".py": "python",
    ".js": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".go": "go",
    ".rs": "rust",
    ".java": "java",
    ".rb": "ruby",
    ".php": "php",
    ".c": "c",
    ".h": "c",
    ".cpp": "cpp",
    ".cc": "cpp",
    ".cxx": "cpp",
    ".hpp": "cpp",
    ".hh": "cpp",
    ".cs": "c_sharp",
}


def language_from_path(path: str | Path) -> str | None:
    """Detect language from file extension. Returns None if unsupported."""
    suffix = Path(path).suffix.lower()
    return EXTENSION_MAP.get(suffix)


# Shebang interpreter → canonical language name. Restricted to languages
# present in EXTENSION_MAP / SUPPORTED_LANGUAGES so the rest of the
# pipeline (tree-sitter parsing, agent language declarations) stays
# coherent. Bash, perl, etc. map to None even if a shebang line points
# at them, since we have no parsers for those.
SHEBANG_MAP: dict[str, str] = {
    "python": "python",
    "python2": "python",
    "python3": "python",
    "ruby": "ruby",
    "node": "javascript",
    "nodejs": "javascript",
    "ts-node": "typescript",
    "tsnode": "typescript",
    "deno": "typescript",
    "php": "php",
}


def language_from_shebang(first_line: str) -> str | None:
    """Detect language from a shebang line (e.g., '#!/usr/bin/env python3').

    Returns the canonical language name (one of EXTENSION_MAP's values) or
    None if the line is not a shebang or names an unsupported interpreter.

    Examples:
        '#!/usr/bin/env python3'  -> 'python'
        '#!/usr/bin/python'       -> 'python'
        '#!/usr/bin/env ruby'     -> 'ruby'
        '#!/usr/bin/env node'     -> 'javascript'
        '#!/bin/bash'             -> None  (bash not in supported set)
        'not a shebang'           -> None
    """
    if not first_line.startswith("#!"):
        return None
    # Strip '#!' then split on whitespace; take the last token.
    # Examples: '/usr/bin/env python3' -> ['/usr/bin/env', 'python3']
    #           '/usr/bin/python'      -> ['/usr/bin/python']
    parts = first_line[2:].strip().split()
    if not parts:
        return None
    interpreter_path = parts[-1]
    interpreter = interpreter_path.rsplit("/", 1)[-1]
    return SHEBANG_MAP.get(interpreter)


@lru_cache(maxsize=None)
def get_language(name: str) -> Language:
    """Return a tree-sitter Language for the given canonical name.

    Raises ValueError if the language is not supported.
    """
    if name not in _GRAMMAR_REGISTRY:
        raise ValueError(
            f"Unsupported language: {name!r}. "
            f"Supported: {', '.join(SUPPORTED_LANGUAGES)}"
        )
    module_name, func_name = _GRAMMAR_REGISTRY[name]
    mod = importlib.import_module(module_name)
    lang_func = getattr(mod, func_name)
    return Language(lang_func())


def get_parser(name: str) -> Parser:
    """Return a new tree-sitter Parser for the given language.

    A new parser is created on each call because Parser objects are
    stateful and not safe to share across concurrent requests.
    """
    lang = get_language(name)
    return Parser(lang)
