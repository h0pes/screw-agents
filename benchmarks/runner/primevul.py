"""PrimeVul methodology: dedup, chronological splits, pair-based evaluation.

Based on Ding et al. 2024. LLM F1 dropped from 68% to 3% after proper dedup.

Approach:
  dedupe(cases) — group by SHA-256 hash of AST-normalized code; keep earliest.
  ast_normalize(code, language) — tree-sitter tokenize, strip comments, normalize whitespace.
  Chronological splits and pair-based eval are in Task 9.
"""
from __future__ import annotations

import hashlib
from collections import defaultdict
from typing import Iterable

from benchmarks.runner.models import BenchmarkCase, Language
from screw_agents.treesitter import get_parser, SUPPORTED_LANGUAGES

# Language name mapping — bridges benchmarks/runner/models.py Language enum
# to the canonical names used by screw_agents.treesitter.
_LANG_TO_TS_NAME: dict[Language, str] = {
    Language.PYTHON: "python",
    Language.JAVASCRIPT: "javascript",
    Language.TYPESCRIPT: "typescript",
    Language.JAVA: "java",
    Language.GO: "go",
    Language.RUBY: "ruby",
    Language.PHP: "php",
    Language.CSHARP: "c_sharp",
    Language.RUST: "rust",
    Language.C: "c",
    Language.CPP: "cpp",
}


def ast_normalize(code: str, language: Language) -> str:
    """Strip comments and normalize whitespace using tree-sitter.

    Walks CST, skips comment nodes, emits terminal token text separated by single spaces.
    """
    ts_name = _LANG_TO_TS_NAME.get(language)
    if ts_name is None:
        return code  # unsupported language, return as-is
    parser = get_parser(ts_name)
    tree = parser.parse(code.encode("utf-8"))
    tokens: list[str] = []
    _collect_tokens(tree.root_node, code.encode("utf-8"), tokens)
    return " ".join(tokens)


def _collect_tokens(node, source: bytes, out: list[str]) -> None:
    """Recursive walk of CST, collecting non-comment leaf tokens."""
    if "comment" in node.type:
        return
    if node.child_count == 0:
        text = source[node.start_byte:node.end_byte].decode("utf-8", errors="replace").strip()
        if text:
            out.append(text)
        return
    for child in node.children:
        _collect_tokens(child, source, out)


def hash_normalized(code: str, language: Language) -> str:
    """SHA-256 hex digest of the AST-normalized code."""
    normalized = ast_normalize(code, language)
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def dedupe(cases: Iterable[BenchmarkCase]) -> list[BenchmarkCase]:
    """Remove duplicate cases, keeping the earliest-published one in each group.

    Two cases are duplicates if: same language AND all FAIL ground-truth code
    snippets have the same AST-normalized SHA-256 hash.
    """
    cases_list = list(cases)
    groups: dict[tuple[Language, str], list[BenchmarkCase]] = defaultdict(list)

    for case in cases_list:
        fail_code = "\n".join(
            f.message for f in case.ground_truth
            if f.kind.value == "fail" and f.message
        )
        if not fail_code:
            groups[(case.language, case.case_id)].append(case)
            continue
        h = hash_normalized(fail_code, case.language)
        groups[(case.language, h)].append(case)

    result: list[BenchmarkCase] = []
    for group in groups.values():
        group.sort(key=lambda c: (c.published_date is None, c.published_date or None))
        result.append(group[0])

    result.sort(key=lambda c: c.case_id)
    return result


from datetime import date


def chronological_split(
    cases: list[BenchmarkCase],
    cutoff: date,
) -> tuple[list[BenchmarkCase], list[BenchmarkCase]]:
    """Split cases into (train, test) by published_date.

    Cases with published_date < cutoff go to train.
    Cases with published_date >= cutoff go to test.
    Cases with no date default to train.
    """
    train: list[BenchmarkCase] = []
    test: list[BenchmarkCase] = []
    for case in cases:
        if case.published_date is None or case.published_date < cutoff:
            train.append(case)
        else:
            test.append(case)
    return train, test


def cross_project_split(
    cases: list[BenchmarkCase],
    holdout_project: str,
) -> tuple[list[BenchmarkCase], list[BenchmarkCase]]:
    """Hold out all cases from a single project.

    Returns (train, test) where test contains every case whose project ==
    holdout_project.
    """
    train = [c for c in cases if c.project != holdout_project]
    test = [c for c in cases if c.project == holdout_project]
    return train, test
