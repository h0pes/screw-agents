"""Tests for the AdaptiveInputs Pydantic model + YAML schema integration.

Phase 3b T16 part 1. Locks the contract between agent YAMLs and the D2
taint-verified unresolved-sink gap signal (`gap_signal.detect_d2_unresolved_sink_gaps`):

- Schema accepts agents with `adaptive_inputs` and validates the three
  required fields (sink_regex + known_receivers + known_sources).
- Schema rejects malformed adaptive_inputs blocks early, at registry load
  time, so a typo in a YAML never reaches the engine at scan time.
- The 4 shipped agents (sqli, cmdi, ssti, xss) declare valid
  adaptive_inputs with non-empty sink_regex. This test locks the YAML
  population as part of the schema contract — removing adaptive_inputs
  from any of these agents is a breaking change.
- Every shipped sink_regex compiles as a valid Python regex (catches
  typos the parser can't detect on its own).
"""

from __future__ import annotations

import re

import pytest
from pydantic import ValidationError

from screw_agents.engine import ScanEngine
from screw_agents.models import AdaptiveInputs, AgentDefinition


_MINIMAL_AGENT_YAML: dict = {
    "meta": {
        "name": "test-agent",
        "display_name": "Test Agent",
        "domain": "test",
        "version": "0.0.0",
        "last_updated": "2026-04-19",
        "cwes": {"primary": "CWE-0", "related": []},
        "owasp": {"top10": "A00"},
    },
    "core_prompt": "test",
    "detection_heuristics": {},
    "remediation": {"preferred": "test"},
}


def test_adaptive_inputs_schema_accepts_valid_input() -> None:
    """Happy path: all three fields present with valid types yields a model."""
    ai = AdaptiveInputs(
        sink_regex=r"execute|query",
        known_receivers={"cursor", "db"},
        known_sources=["request.args", "request.form"],
    )
    assert ai.sink_regex == r"execute|query"
    assert ai.known_receivers == {"cursor", "db"}
    assert ai.known_sources == ["request.args", "request.form"]


def test_adaptive_inputs_schema_rejects_missing_sink_regex() -> None:
    """sink_regex is required (no default). Pydantic raises ValidationError."""
    with pytest.raises(ValidationError) as exc_info:
        AdaptiveInputs(  # type: ignore[call-arg]
            known_receivers={"cursor"},
            known_sources=["request.args"],
        )
    assert "sink_regex" in str(exc_info.value)


def test_adaptive_inputs_schema_rejects_extra_fields() -> None:
    """extra='forbid' catches typos so a malformed YAML fails loudly."""
    with pytest.raises(ValidationError) as exc_info:
        AdaptiveInputs(
            sink_regex="execute",
            known_receivers={"cursor"},
            known_sources=["request.args"],
            unknown_field="oops",  # type: ignore[call-arg]
        )
    assert "unknown_field" in str(exc_info.value) or "Extra" in str(exc_info.value)


def test_adaptive_inputs_optional_on_agent_root() -> None:
    """Agents without adaptive_inputs still validate — the field is optional.
    Future agents that opt out of D2 simply omit the block.
    """
    agent = AgentDefinition.model_validate(_MINIMAL_AGENT_YAML)
    assert agent.adaptive_inputs is None


def test_adaptive_inputs_nested_on_agent_root_parses() -> None:
    """An agent declaring adaptive_inputs inline parses into the typed submodel."""
    yaml_data = {
        **_MINIMAL_AGENT_YAML,
        "adaptive_inputs": {
            "sink_regex": "execute|query",
            "known_receivers": ["cursor", "db"],
            "known_sources": ["request.args"],
        },
    }
    agent = AgentDefinition.model_validate(yaml_data)
    assert agent.adaptive_inputs is not None
    assert agent.adaptive_inputs.sink_regex == "execute|query"
    assert agent.adaptive_inputs.known_receivers == {"cursor", "db"}
    assert agent.adaptive_inputs.known_sources == ["request.args"]


def test_all_shipped_injection_agents_declare_adaptive_inputs() -> None:
    """sqli, cmdi, ssti, xss each carry a valid adaptive_inputs with
    non-empty sink_regex. Locks the T16 YAML population — removing
    adaptive_inputs from any of these agents is a breaking change that
    must update this test and plan documentation.
    """
    engine = ScanEngine.from_defaults()
    for name in ("sqli", "cmdi", "ssti", "xss"):
        agent = engine._registry.get_agent(name)
        assert agent is not None, f"agent {name!r} not loaded"
        assert agent.adaptive_inputs is not None, (
            f"agent {name!r} missing adaptive_inputs — required for Phase 3b D2"
        )
        assert agent.adaptive_inputs.sink_regex, (
            f"agent {name!r} has empty sink_regex"
        )
        assert agent.adaptive_inputs.known_sources, (
            f"agent {name!r} has empty known_sources — D2 has no taint seeds"
        )


def test_all_shipped_adaptive_sink_regexes_compile() -> None:
    """Every shipped sink_regex is a valid Python regex. Catches typos the
    YAML parser cannot detect on its own (a malformed regex like `a(b` is
    a string, parses fine, but explodes at scan time when D2 compiles it).
    """
    engine = ScanEngine.from_defaults()
    for name in ("sqli", "cmdi", "ssti", "xss"):
        agent = engine._registry.get_agent(name)
        assert agent is not None
        assert agent.adaptive_inputs is not None
        try:
            re.compile(agent.adaptive_inputs.sink_regex)
        except re.error as exc:  # pragma: no cover — guards test intent
            pytest.fail(
                f"agent {name!r} has malformed sink_regex "
                f"{agent.adaptive_inputs.sink_regex!r}: {exc}"
            )


# ----------------------------------------------------------------------
# I1 post-review: negative-match tests locking anchored sink_regex so a
# future YAML edit that drops the `^(...)$` anchors or re-introduces an
# ambiguous bare token (e.g., `call`, `new`, `write`) immediately fails
# here rather than silently inflating FPs in real D2 scans.
#
# Each case name is an innocuous method identifier that the PRE-FIX
# (unanchored) regex empirically matched via `re.search`. All of these
# are taken from real Python/JS codebases, not speculation.
# ----------------------------------------------------------------------


def _get_sink_pattern(agent_name: str) -> re.Pattern[str]:
    engine = ScanEngine.from_defaults()
    agent = engine._registry.get_agent(agent_name)
    assert agent is not None and agent.adaptive_inputs is not None
    return re.compile(agent.adaptive_inputs.sink_regex)


@pytest.mark.parametrize(
    "innocuous_method",
    [
        "drawing",       # substring of 'raw'
        "draw",          # substring of 'raw'
        "inquery",       # substring of 'query'
        "requery",       # substring of 'query'
        "queryset",      # substring of 'query' (Django)
        "preparation",   # substring of 'prepare'
        "preexecute",    # substring of 'execute'
        "executor",      # substring of 'execute'
        "formatted_sql", # substring of 'format_sql'
        "from_string_builder",  # substring of 'from_string'
    ],
)
def test_sqli_sink_regex_does_not_overmatch(innocuous_method: str) -> None:
    """I1 regression: sqli sink_regex must not match common innocuous
    method names that happen to contain sink tokens as substrings.
    """
    pattern = _get_sink_pattern("sqli")
    assert not pattern.search(innocuous_method), (
        f"sqli sink_regex spuriously matches innocuous method "
        f"{innocuous_method!r}; anchor with ^(...)$ or drop the offending token"
    )


@pytest.mark.parametrize(
    "innocuous_method",
    [
        "callback",     # substring of 'call' — dropped entirely
        "recall",       # substring of 'call'
        "callable",     # substring of 'call'
        "newCustomer",  # substring of 'new' — dropped entirely
        "newline",      # substring of 'new'
        "renew",        # substring of 'new'
        "execute",      # substring of 'exec'
        "executor",     # substring of 'exec'
        "running",      # substring of 'run'
        "runtime",      # substring of 'run'
        "Startup",      # substring of 'Start'
        "Started",      # substring of 'Start'
        "systemd",      # substring of 'system'
        "popened",      # substring of 'popen'
        "spawner",      # substring of 'spawn'
    ],
)
def test_cmdi_sink_regex_does_not_overmatch(innocuous_method: str) -> None:
    """I1 regression: cmdi sink_regex must not match innocuous method
    names via substring. Also locks the decision to DROP `call` and
    `new` — re-introducing them would fail this test.
    """
    pattern = _get_sink_pattern("cmdi")
    assert not pattern.search(innocuous_method), (
        f"cmdi sink_regex spuriously matches innocuous method "
        f"{innocuous_method!r}"
    )


@pytest.mark.parametrize(
    "innocuous_method",
    [
        "parser",       # substring of 'parse'
        "parsed",       # substring of 'parse'
        "compiled",     # substring of 'compile'
        "compiler",     # substring of 'compile'
        "rendered",     # substring of 'render'
        "renderer",     # substring of 'render'
        "prefetch",     # substring of 'fetch'
        "fetcher",      # substring of 'fetch'
        "generated",    # substring of 'generate'
        "generator",    # substring of 'generate'
        "Executed",     # substring of 'Execute'
        "Executes",     # substring of 'Execute'
        "evaluated",    # substring of 'evaluate'
    ],
)
def test_ssti_sink_regex_does_not_overmatch(innocuous_method: str) -> None:
    """I1 regression: ssti sink_regex must not match innocuous method
    names via substring.
    """
    pattern = _get_sink_pattern("ssti")
    assert not pattern.search(innocuous_method), (
        f"ssti sink_regex spuriously matches innocuous method "
        f"{innocuous_method!r}"
    )


@pytest.mark.parametrize(
    "innocuous_method",
    [
        "rewrite",       # substring of 'write' — `write` dropped
        "overwrite",     # substring of 'write'
        "write_csv",     # substring of 'write'
        "sprint",        # substring of 'print' — `print` dropped
        "imprint",       # substring of 'print'
        "evaluate",      # substring of 'eval'
        "sender",        # substring of 'send'
        "sendgrid_send", # substring of 'send'
        "newCustomer",   # substring of 'new' — `new` dropped
        "renew",         # substring of 'new'
        "newline",       # substring of 'new'
        "innerHTMLx",    # trailing-char overmatch guard (anchor check)
        "xinnerHTML",    # leading-char overmatch guard (anchor check)
        "RawBytes",      # substring of 'Raw' — anchored `^Raw$` excludes
    ],
)
def test_xss_sink_regex_does_not_overmatch(innocuous_method: str) -> None:
    """I1 regression: xss sink_regex must not match innocuous method
    names via substring. Also locks the decisions to DROP `write`,
    `print`, `new` entirely — re-introducing them would fail this test.
    """
    pattern = _get_sink_pattern("xss")
    assert not pattern.search(innocuous_method), (
        f"xss sink_regex spuriously matches innocuous method "
        f"{innocuous_method!r}"
    )


@pytest.mark.parametrize(
    "agent_name, true_positive_methods",
    [
        (
            "sqli",
            ["execute", "executemany", "raw", "query", "queryRaw", "prepare"],
        ),
        (
            "cmdi",
            ["system", "popen", "exec", "run", "Popen", "shell_exec"],
        ),
        (
            "ssti",
            ["render_template_string", "render", "from_string", "evaluate"],
        ),
        (
            "xss",
            [
                "innerHTML",
                "insertAdjacentHTML",
                "mark_safe",
                "bypassSecurityTrustHtml",
                "bypassSecurityTrustScript",
                "Raw",
                "eval",
            ],
        ),
    ],
)
def test_sink_regex_still_matches_true_positives(
    agent_name: str, true_positive_methods: list[str]
) -> None:
    """I1 companion: the anchored regex must STILL match the sink methods
    the agent is supposed to cover. Guards against an over-eager future
    tightening that drops a real sink.
    """
    pattern = _get_sink_pattern(agent_name)
    for method in true_positive_methods:
        assert pattern.search(method), (
            f"{agent_name} sink_regex fails to match expected sink "
            f"method {method!r}"
        )
