"""Tests for T-SCAN-REFACTOR Task 2: relevance filter + shebang detection.

Spec sections 8.1, 8.2, 8.5.
"""

from __future__ import annotations

import pytest

from screw_agents.engine import _agent_supported_languages, _filter_relevant_agents
from screw_agents.models import (
    AgentDefinition,
    AgentMeta,
    CWEs,
    DetectionHeuristics,
    HeuristicEntry,
    OWASPMapping,
    Remediation,
)
from screw_agents.resolver import ResolvedCode
from screw_agents.treesitter import language_from_shebang


# ---------------------------------------------------------------------------
# Shebang detection
# ---------------------------------------------------------------------------


def test_shebang_python3_returns_python() -> None:
    assert language_from_shebang("#!/usr/bin/env python3") == "python"


def test_shebang_python_returns_python() -> None:
    assert language_from_shebang("#!/usr/bin/python") == "python"


def test_shebang_ruby_returns_ruby() -> None:
    assert language_from_shebang("#!/usr/bin/env ruby") == "ruby"


def test_shebang_node_returns_javascript() -> None:
    assert language_from_shebang("#!/usr/bin/env node") == "javascript"


def test_shebang_php_returns_php() -> None:
    assert language_from_shebang("#!/usr/bin/php") == "php"


def test_shebang_unknown_returns_none() -> None:
    assert language_from_shebang("#!/bin/bash") is None
    assert language_from_shebang("#!/usr/bin/perl") is None
    assert language_from_shebang("not a shebang") is None
    assert language_from_shebang("") is None


def test_shebang_with_interpreter_flag_returns_language() -> None:
    """Shebang with interpreter flag (e.g., python -O) still detects language."""
    assert language_from_shebang("#!/usr/bin/python3 -O") == "python"
    assert language_from_shebang("#!/usr/bin/python3 -u") == "python"


def test_shebang_env_with_interpreter_flag_returns_language() -> None:
    """`env interpreter flag` form returns language."""
    assert language_from_shebang("#!/usr/bin/env python3 -O") == "python"


def test_shebang_env_dash_S_split_args_returns_language() -> None:
    """`env -S interpreter flag1 flag2` (split-args form) returns language."""
    assert language_from_shebang("#!/usr/bin/env -S python3 -O") == "python"
    assert language_from_shebang("#!/usr/bin/env -S deno run --allow-net") == "typescript"


def test_shebang_node_with_flag_returns_javascript() -> None:
    """Node shebang with --harmony flag returns javascript."""
    assert language_from_shebang("#!/usr/bin/env node --harmony") == "javascript"


def test_shebang_env_with_unsupported_interpreter_returns_none() -> None:
    """`env perl` returns None (perl not in SHEBANG_MAP)."""
    assert language_from_shebang("#!/usr/bin/env perl") is None


# ---------------------------------------------------------------------------
# `_agent_supported_languages` helper
# ---------------------------------------------------------------------------


def _make_agent(name: str, *, languages_per_entry: list[list[str]]) -> AgentDefinition:
    """Build a minimal AgentDefinition with one HeuristicEntry per languages list."""
    entries = [
        HeuristicEntry(id=f"e{i}", pattern="dummy", languages=langs)
        for i, langs in enumerate(languages_per_entry)
    ]
    return AgentDefinition(
        meta=AgentMeta(
            name=name,
            display_name="X",
            domain="test-domain",
            version="0.1.0",
            last_updated="2026-04-25",
            cwes=CWEs(primary="CWE-1", related=[]),
            owasp=OWASPMapping(top10="", asvs=[], testing_guide=""),
        ),
        core_prompt="x",
        detection_heuristics=DetectionHeuristics(high_confidence=entries),
        remediation=Remediation(preferred="x"),
    )


def test_agent_supported_languages_unions_all_buckets() -> None:
    a = AgentDefinition(
        meta=AgentMeta(
            name="multi",
            display_name="X",
            domain="t",
            version="0.1.0",
            last_updated="2026-04-25",
            cwes=CWEs(primary="CWE-1", related=[]),
            owasp=OWASPMapping(top10="", asvs=[], testing_guide=""),
        ),
        core_prompt="x",
        detection_heuristics=DetectionHeuristics(
            high_confidence=[HeuristicEntry(id="h1", pattern="p", languages=["python"])],
            medium_confidence=[HeuristicEntry(id="m1", pattern="p", languages=["java"])],
            context_required=[HeuristicEntry(id="c1", pattern="p", languages=["python", "go"])],
        ),
        remediation=Remediation(preferred="x"),
    )
    assert _agent_supported_languages(a) == {"python", "java", "go"}


def test_agent_supported_languages_empty_when_no_languages_declared() -> None:
    a = _make_agent("nolang", languages_per_entry=[[]])
    assert _agent_supported_languages(a) == set()


def test_agent_supported_languages_handles_string_entries() -> None:
    """Plain string heuristic entries (HeuristicItem = str | HeuristicEntry) contribute nothing."""
    a = AgentDefinition(
        meta=AgentMeta(
            name="mixed",
            display_name="X",
            domain="t",
            version="0.1.0",
            last_updated="2026-04-25",
            cwes=CWEs(primary="CWE-1", related=[]),
            owasp=OWASPMapping(top10="", asvs=[], testing_guide=""),
        ),
        core_prompt="x",
        detection_heuristics=DetectionHeuristics(
            high_confidence=[
                "plain string heuristic",
                HeuristicEntry(id="e1", pattern="p", languages=["python"]),
            ],
        ),
        remediation=Remediation(preferred="x"),
    )
    assert _agent_supported_languages(a) == {"python"}


# ---------------------------------------------------------------------------
# `_filter_relevant_agents`
# ---------------------------------------------------------------------------


def test_filter_keeps_agent_when_languages_intersect() -> None:
    py_agent = _make_agent("py", languages_per_entry=[["python"]])
    target_codes = [ResolvedCode(file_path="x.py", content="", language="python")]
    kept, excluded = _filter_relevant_agents(target_codes, [py_agent])
    assert kept == [py_agent]
    assert excluded == []


def test_filter_drops_agent_when_languages_disjoint() -> None:
    java_agent = _make_agent("java", languages_per_entry=[["java"]])
    target_codes = [ResolvedCode(file_path="x.py", content="", language="python")]
    kept, excluded = _filter_relevant_agents(target_codes, [java_agent])
    assert kept == []
    assert len(excluded) == 1
    assert excluded[0]["agent_name"] == "java"
    assert excluded[0]["reason"] == "language_mismatch"
    assert excluded[0]["agent_languages"] == ["java"]
    assert excluded[0]["target_languages"] == ["python"]


def test_filter_keeps_agent_with_empty_language_declaration_failopen() -> None:
    """D6 fail-open: agent with no language declaration is always kept."""
    nolang = _make_agent("nolang", languages_per_entry=[[]])
    target_codes = [ResolvedCode(file_path="x.py", content="", language="python")]
    kept, excluded = _filter_relevant_agents(target_codes, [nolang])
    assert kept == [nolang]
    assert excluded == []


def test_filter_failopen_when_target_languages_empty() -> None:
    """Empty target_languages set → keep all agents (target may be non-code)."""
    py_agent = _make_agent("py", languages_per_entry=[["python"]])
    target_codes = [ResolvedCode(file_path="data.bin", content="", language=None)]
    kept, excluded = _filter_relevant_agents(target_codes, [py_agent])
    assert kept == [py_agent]
    assert excluded == []


def test_filter_uses_shebang_when_extension_lookup_returns_none() -> None:
    """File without extension match but with a known shebang contributes its language."""
    py_agent = _make_agent("py", languages_per_entry=[["python"]])
    java_agent = _make_agent("java", languages_per_entry=[["java"]])
    target_codes = [
        ResolvedCode(
            file_path="bin/myscript",
            content="#!/usr/bin/env python3\nprint('hello')\n",
            language=None,
        )
    ]
    kept, excluded = _filter_relevant_agents(target_codes, [py_agent, java_agent])
    kept_names = {a.meta.name for a in kept}
    assert kept_names == {"py"}
    assert {e["agent_name"] for e in excluded} == {"java"}


# ---------------------------------------------------------------------------
# HeuristicEntry.languages validator (Section 8.5 reinforcement)
# ---------------------------------------------------------------------------


def test_heuristic_entry_languages_unsupported_rejected() -> None:
    """A typo or unsupported language name is rejected at schema validation."""
    from pydantic import ValidationError

    with pytest.raises(ValidationError, match="not in SUPPORTED_LANGUAGES"):
        HeuristicEntry(id="x", pattern="p", languages=["csharp"])  # missing underscore


def test_heuristic_entry_languages_uppercase_rejected() -> None:
    """An uppercase language name is rejected (SUPPORTED_LANGUAGES values are lowercase)."""
    from pydantic import ValidationError

    with pytest.raises(ValidationError, match="not in SUPPORTED_LANGUAGES"):
        HeuristicEntry(id="x", pattern="p", languages=["Python"])


# ---------------------------------------------------------------------------
# CodeExample.language validator (Section 8.5 reinforcement, Task 2 fix-up)
# ---------------------------------------------------------------------------


def test_code_example_language_unsupported_rejected() -> None:
    """Typo or unsupported language in CodeExample.language is rejected."""
    from pydantic import ValidationError

    from screw_agents.models import CodeExample

    with pytest.raises(ValidationError, match="not in SUPPORTED_LANGUAGES"):
        CodeExample(language="csharp", code="// missing underscore", explanation="x")


def test_code_example_language_uppercase_rejected() -> None:
    """Uppercase language name in CodeExample.language is rejected."""
    from pydantic import ValidationError

    from screw_agents.models import CodeExample

    with pytest.raises(ValidationError, match="not in SUPPORTED_LANGUAGES"):
        CodeExample(language="Python", code="x = 1", explanation="x")
