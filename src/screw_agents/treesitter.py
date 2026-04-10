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


@lru_cache(maxsize=None)
def get_parser(name: str) -> Parser:
    """Return a configured tree-sitter Parser for the given language."""
    lang = get_language(name)
    return Parser(lang)
