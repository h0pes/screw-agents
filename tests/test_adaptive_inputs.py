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
