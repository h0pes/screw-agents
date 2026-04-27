"""Tests for T-SCAN-REFACTOR Task 8: slash command scope parser.

Spec section 6. The parser is exposed as a Python helper for testability;
the slash command's markdown body invokes it via the registered
`mcp__screw-agents__resolve_scope` tool (E1=A: no shell out).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from screw_agents.engine import ScanEngine
from screw_agents.registry import AgentRegistry
from screw_agents.scan_command import (
    ParsedScope,
    ScopeResolutionError,
    parse_scope_spec,
    resolve_scope,
    summarize_scope,
    validate_flags,
)
from screw_agents.server import _dispatch_tool


_REPO_ROOT = Path(__file__).parents[1]
_DOMAINS_DIR = _REPO_ROOT / "domains"


@pytest.fixture
def registry() -> AgentRegistry:
    return AgentRegistry(_DOMAINS_DIR)


def _write_minimal_agent_yaml(path: Path, *, name: str, domain: str) -> None:
    """Write a minimal valid AgentDefinition YAML to `path`.

    Mirrors `tests/test_registry_invariants.py::_write_minimal_agent_yaml`
    so cross-domain rejection tests can build a fake 2-domain registry.
    """
    path.write_text(
        f"""\
meta:
  name: {name}
  display_name: "Test Agent"
  domain: {domain}
  version: "0.1.0"
  last_updated: "2026-04-25"
  cwes:
    primary: "CWE-89"
    related: []
  capec: []
  owasp:
    top10: ""
    asvs: []
    testing_guide: ""
  sources: []
core_prompt: "test prompt"
detection_heuristics:
  high_confidence: []
  medium_confidence: []
  context_required: []
remediation:
  preferred: "use parameterized queries"
""",
        encoding="utf-8",
    )


# ---------------------------------------------------------------------------
# Bare-token form
# ---------------------------------------------------------------------------


def test_bare_token_agent_name(registry: AgentRegistry) -> None:
    parsed = parse_scope_spec("sqli")
    resolved = resolve_scope(parsed, registry)
    assert resolved == ["sqli"]


def test_bare_token_domain_name(registry: AgentRegistry) -> None:
    parsed = parse_scope_spec("injection-input-handling")
    resolved = resolve_scope(parsed, registry)
    assert set(resolved) == {"sqli", "cmdi", "ssti", "xss"}


def test_bare_token_unknown_raises(registry: AgentRegistry) -> None:
    parsed = parse_scope_spec("unknownname")
    with pytest.raises(ScopeResolutionError, match="not a domain or agent"):
        resolve_scope(parsed, registry)


# ---------------------------------------------------------------------------
# `full` keyword
# ---------------------------------------------------------------------------


def test_full_keyword_returns_all_registered(registry: AgentRegistry) -> None:
    parsed = parse_scope_spec("full")
    resolved = resolve_scope(parsed, registry)
    all_names = set(registry.agents.keys())
    assert set(resolved) == all_names


# ---------------------------------------------------------------------------
# Prefix-key form
# ---------------------------------------------------------------------------


def test_domains_only_implies_full(registry: AgentRegistry) -> None:
    parsed = parse_scope_spec("domains:injection-input-handling")
    resolved = resolve_scope(parsed, registry)
    assert set(resolved) == {"sqli", "cmdi", "ssti", "xss"}


def test_agents_only_no_domains(registry: AgentRegistry) -> None:
    parsed = parse_scope_spec("agents:sqli,xss")
    resolved = resolve_scope(parsed, registry)
    assert set(resolved) == {"sqli", "xss"}


def test_domains_with_subset_agents(registry: AgentRegistry) -> None:
    parsed = parse_scope_spec("domains:injection-input-handling agents:sqli,xss")
    resolved = resolve_scope(parsed, registry)
    assert set(resolved) == {"sqli", "xss"}


def test_cross_domain_agent_ref_raises(registry: AgentRegistry) -> None:
    """Spec section 6.6: agent listed in agents: must belong to a listed
    domain when domains: is non-empty.

    Today's single-domain registry can only reach the `Unknown domain`
    early-exit branch; a 2-domain fake registry exercises the true cross-
    domain rejection path — see `test_cross_domain_agent_rejection`.
    """
    parsed = parse_scope_spec("domains:nonexistent agents:sqli")
    with pytest.raises(ScopeResolutionError, match="Unknown domain"):
        resolve_scope(parsed, registry)


def test_unknown_agent_in_prefix_key_raises(registry: AgentRegistry) -> None:
    parsed = parse_scope_spec("agents:nonexistent")
    with pytest.raises(ScopeResolutionError, match="Unknown agent"):
        resolve_scope(parsed, registry)


# ---------------------------------------------------------------------------
# Mutual exclusivity (forms)
# ---------------------------------------------------------------------------


def test_full_with_prefix_keys_raises(registry: AgentRegistry) -> None:
    with pytest.raises(ScopeResolutionError, match="exclusive"):
        parse_scope_spec("full domains:injection-input-handling")


def test_bare_token_with_prefix_keys_raises(registry: AgentRegistry) -> None:
    with pytest.raises(ScopeResolutionError, match="exclusive"):
        parse_scope_spec("sqli agents:xss")


# ---------------------------------------------------------------------------
# Empty / malformed
# ---------------------------------------------------------------------------


def test_empty_scope_spec_raises(registry: AgentRegistry) -> None:
    with pytest.raises(ScopeResolutionError, match="empty"):
        parse_scope_spec("")


def test_malformed_prefix_key_raises(registry: AgentRegistry) -> None:
    with pytest.raises(ScopeResolutionError, match="Unknown prefix key"):
        parse_scope_spec("typos:sqli")


# ---------------------------------------------------------------------------
# Result determinism
# ---------------------------------------------------------------------------


def test_resolved_list_dedup_explicit(registry: AgentRegistry) -> None:
    """Duplicates in input are deduplicated; output is sorted.

    Strengthened from the prior tautological
    `assert resolved == sorted(set(resolved))` to assert concrete
    expected values (per pre-audit IMPORTANT finding).
    """
    parsed = parse_scope_spec("agents:sqli,xss,sqli")  # 'sqli' appears twice
    resolved = resolve_scope(parsed, registry)
    assert resolved == ["sqli", "xss"]
    assert len(resolved) == 2  # sqli appeared twice in input


# ---------------------------------------------------------------------------
# Cross-domain rejection (15th test — security boundary, T8 plan-fix Edit 8)
# ---------------------------------------------------------------------------


def test_cross_domain_agent_rejection(tmp_path: Path) -> None:
    """If `domains:` is given AND `agents:` names cross-belong, parser
    rejects.

    Today's registry has 1 domain so the path is unreachable with real
    YAMLs; this test uses a tmp_path-built fake registry with 2 fake
    domains. Closes the security-boundary gap flagged in pre-audit Edit 8.
    """
    d1 = tmp_path / "domain-a"
    d1.mkdir()
    _write_minimal_agent_yaml(d1 / "agent_x.yaml", name="agent_x", domain="domain-a")
    d2 = tmp_path / "domain-b"
    d2.mkdir()
    _write_minimal_agent_yaml(d2 / "agent_y.yaml", name="agent_y", domain="domain-b")
    fake_registry = AgentRegistry(tmp_path)

    parsed = parse_scope_spec("domains:domain-a agents:agent_y")
    with pytest.raises(
        ScopeResolutionError,
        match="not in any of the listed domains|domain-a",
    ):
        resolve_scope(parsed, fake_registry)


# ---------------------------------------------------------------------------
# Whitespace handling in prefix-key tokens (T8 plan-fix Edit 11)
# ---------------------------------------------------------------------------


def test_whitespace_in_prefix_key_raises_actionable(registry: AgentRegistry) -> None:
    """`domains: foo` (space after colon) raises an actionable error.

    Without explicit handling, `foo` would be silently re-classified as
    a bare token. Pre-audit IMPORTANT (Edit 11): explicit error is
    friendlier than silent re-interpretation. The shell-style tokenizer
    produces ``domains:`` as a token with empty ``rest`` — the parser
    catches this and raises with a message naming the prefix key.
    Quality review Minor 2: error wording generalized so the same
    branch covers `agents:` (no value at all) too.
    """
    with pytest.raises(
        ScopeResolutionError,
        match="Empty value after prefix key 'domains'",
    ):
        parse_scope_spec("domains: foo")


# ---------------------------------------------------------------------------
# Mutual exclusivity: --adaptive + --no-confirm (E4=A, T8 plan-fix Edit 7)
# ---------------------------------------------------------------------------


def test_adaptive_and_no_confirm_mutually_exclusive() -> None:
    """Combining --adaptive and --no-confirm raises with actionable
    message.

    E4=A (Marco approved): hard error — `--adaptive` needs interactive
    consent, `--no-confirm` signals non-interactive context. They cannot
    be combined.
    """
    with pytest.raises(ValueError, match="cannot be combined"):
        validate_flags(["--adaptive", "--no-confirm"])


# ---------------------------------------------------------------------------
# MCP-dispatch (E1=A: tool registration eliminates shell-injection class)
# ---------------------------------------------------------------------------


def test_resolve_scope_mcp_dispatch_sqli() -> None:
    """resolve_scope MCP tool routes to scan_command parser; no shell exec."""
    engine = ScanEngine(AgentRegistry(_DOMAINS_DIR))
    result = _dispatch_tool(engine, "resolve_scope", {"scope_text": "sqli"})
    assert result["agents"] == ["sqli"]
    assert isinstance(result["summary"], list)
    assert all("domain" in entry and "mode" in entry for entry in result["summary"])


def test_resolve_scope_mcp_rejects_unknown_token() -> None:
    """Unknown scope tokens raise ValueError with actionable message."""
    engine = ScanEngine(AgentRegistry(_DOMAINS_DIR))
    with pytest.raises(ValueError, match="not a domain or agent"):
        _dispatch_tool(engine, "resolve_scope", {"scope_text": "unknownname"})


# ---------------------------------------------------------------------------
# summarize_scope shape sanity (subset|full annotation)
# ---------------------------------------------------------------------------


def test_summarize_scope_full_keyword(registry: AgentRegistry) -> None:
    """`full` produces one entry per domain in 'full' mode."""
    parsed = parse_scope_spec("full")
    summary = summarize_scope(parsed, registry)
    assert len(summary) == 1  # one domain registered today
    assert summary[0]["domain"] == "injection-input-handling"
    assert summary[0]["mode"] == "full"
    assert set(summary[0]["agents"]) == {"sqli", "cmdi", "ssti", "xss"}


def test_summarize_scope_subset_agents(registry: AgentRegistry) -> None:
    """`agents:sqli,xss` produces a single 'subset' entry for the domain."""
    parsed = parse_scope_spec("agents:sqli,xss")
    summary = summarize_scope(parsed, registry)
    assert len(summary) == 1
    assert summary[0]["domain"] == "injection-input-handling"
    assert summary[0]["mode"] == "subset"
    assert summary[0]["agents"] == ["sqli", "xss"]


# ---------------------------------------------------------------------------
# ParsedScope dataclass shape (form discriminator + frozen=True)
# ---------------------------------------------------------------------------


def test_parsed_scope_form_discriminator_and_frozen() -> None:
    """ParsedScope.form discriminates between the three exclusive
    grammars; the dataclass is frozen so the parsed form never gets
    mutated between parse and resolve.

    Combined into a single test (vs three parametrized cases) to keep
    net-new tests at the plan-budgeted count.
    """
    import dataclasses

    assert parse_scope_spec("full").form == "full"
    assert parse_scope_spec("sqli").form == "bare-token"
    assert parse_scope_spec("agents:sqli,xss").form == "prefix-key"

    parsed = parse_scope_spec("full")
    with pytest.raises(dataclasses.FrozenInstanceError):
        parsed.full_keyword = False  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Quality review escalations: parser-layer hardening
# ---------------------------------------------------------------------------


def test_scope_size_limit_exceeded() -> None:
    """Scope size > MAX_SCOPE_SIZE (50) raises with actionable message.

    EQ1=B (Marco approved): cap at the parser layer so all callers
    (MCP traffic, direct Python tests) hit the same guard. 50 covers
    the future 41-agent CWE-1400 expansion plus headroom.
    """
    big_list = ",".join(f"agent_{i}" for i in range(60))
    with pytest.raises(ScopeResolutionError, match="exceeds limit"):
        parse_scope_spec(f"agents:{big_list}")


def test_control_char_in_token_rejected() -> None:
    """Control characters in CSV tokens are rejected at parse time.

    EQ2=B (Marco approved): tokens must match
    ``^[a-z0-9][a-z0-9_-]*$`` so NUL / other control characters,
    uppercase, leading dash etc. are caught at the parser layer
    rather than reaching the registry-layer "Unknown agent" rejection.
    """
    with pytest.raises(ScopeResolutionError, match="Invalid token"):
        parse_scope_spec("agents:sqli,xss\x00")
