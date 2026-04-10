"""Tests for the shared tree-sitter module."""

import pytest

from screw_agents.treesitter import get_language, get_parser, SUPPORTED_LANGUAGES


def test_supported_languages_contains_all_eleven():
    expected = {
        "python", "javascript", "typescript", "go", "rust",
        "java", "ruby", "php", "c", "cpp", "c_sharp",
    }
    assert set(SUPPORTED_LANGUAGES) == expected


def test_get_language_python():
    lang = get_language("python")
    assert lang is not None


def test_get_language_all_supported():
    for name in SUPPORTED_LANGUAGES:
        lang = get_language(name)
        assert lang is not None, f"Failed to load language: {name}"


def test_get_language_unsupported_raises():
    with pytest.raises(ValueError, match="Unsupported language"):
        get_language("haskell")


def test_get_language_caching():
    lang1 = get_language("python")
    lang2 = get_language("python")
    assert lang1 is lang2


def test_get_parser_python():
    parser = get_parser("python")
    assert parser is not None


def test_get_parser_parses_python_code():
    parser = get_parser("python")
    tree = parser.parse(b"def foo():\n    pass\n")
    root = tree.root_node
    assert root.type == "module"
    assert root.children[0].type == "function_definition"


def test_get_parser_parses_rust_code():
    parser = get_parser("rust")
    tree = parser.parse(b"fn main() {}\n")
    root = tree.root_node
    assert root.type == "source_file"
    assert root.children[0].type == "function_item"


def test_get_parser_parses_javascript_code():
    parser = get_parser("javascript")
    tree = parser.parse(b"function foo() {}\n")
    root = tree.root_node
    assert root.type == "program"
