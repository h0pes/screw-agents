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
    """Detect language from a shebang line.

    Walks the shebang tokens left-to-right, skipping interpreter flags
    (anything starting with '-') and the 'env' wrapper. Returns the
    canonical language name for the first remaining token whose basename
    appears in SHEBANG_MAP, or None if no token matches.

    Handles real-world shebang forms including interpreter flags and
    `env -S` split-args:
        '#!/usr/bin/env python3'              -> 'python'
        '#!/usr/bin/python3 -O'               -> 'python'      (interpreter flag)
        '#!/usr/bin/env python3 -O'           -> 'python'
        '#!/usr/bin/env -S python3 -O'        -> 'python'      (env -S)
        '#!/usr/bin/env node --harmony'       -> 'javascript'  (node flag)
        '#!/bin/bash'                         -> None          (bash not supported)
        '#!/usr/bin/env perl'                 -> None          (perl not supported)
        'not a shebang'                       -> None
    """
    if not first_line.startswith("#!"):
        return None
    parts = first_line[2:].strip().split()
    for token in parts:
        if token.startswith("-"):
            continue  # interpreter or env flag (e.g., -O, -u, -S, --harmony)
        interpreter = token.rsplit("/", 1)[-1]
        if interpreter == "env":
            continue  # env is a wrapper; the real interpreter follows
        # First non-flag non-env token IS the interpreter; supported or not.
        return SHEBANG_MAP.get(interpreter)
    return None


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
