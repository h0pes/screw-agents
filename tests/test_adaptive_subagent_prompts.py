"""Format smoke tests for the `--adaptive` prompt surface in the 4 per-agent
injection subagents, the injection orchestrator, and the `/screw:scan` command
documentation.

These tests are NOT semantic — they lock markdown structure and tool-surface
presence so a future edit can't silently drop or weaken the adaptive-mode
contract. Semantic behavior (actual generation / review flow) is validated by
manual interactive testing and by T22's E2E integration test.

Design decisions locked here:

- The Adaptive Mode section MUST be byte-identical across the 4 per-agent
  subagents modulo the agent-name substitution (sqli/cmdi/ssti/xss). A drift
  in one agent's prompt is a regression — either intentional drift moves to
  a shared prompt library, or it's a bug.
- The orchestrator (screw-injection.md) has its OWN adaptive section because
  it implements the shared Layer 0f quota across all 4 agents. Its wording
  differs deliberately; we only check for presence of the section and its
  shared-quota language.
- The scan.md command doc MUST flag `--adaptive` as interactive-consent-only.
  The flag itself IS the consent; CI must not pass it.
"""

from __future__ import annotations

from pathlib import Path

import yaml


_REPO_ROOT = Path(__file__).parent.parent
_AGENTS_DIR = _REPO_ROOT / "plugins" / "screw" / "agents"
_COMMANDS_DIR = _REPO_ROOT / "plugins" / "screw" / "commands"

_PER_AGENT_FILES = {
    "sqli": _AGENTS_DIR / "screw-sqli.md",
    "cmdi": _AGENTS_DIR / "screw-cmdi.md",
    "ssti": _AGENTS_DIR / "screw-ssti.md",
    "xss": _AGENTS_DIR / "screw-xss.md",
}
_ORCHESTRATOR_FILE = _AGENTS_DIR / "screw-injection.md"
_SCAN_COMMAND_FILE = _COMMANDS_DIR / "scan.md"

# Tools required in the per-agent LLM-flow subagents (sqli/cmdi/ssti/xss).
# Post-C1 (PR #6 T15+T16): LLM-flow uses the staging tools (stage → promote →
# reject) instead of sign_adaptive_script directly. The direct signing tool
# is retained on the server for non-LLM callers but MUST NOT appear in
# per-agent subagent tools/frontmatter or Step 3.5d section prose
# (spec §3.2, Option D isolation).
_PER_AGENT_ADAPTIVE_MCP_TOOLS = [
    "mcp__screw-agents__record_context_required_match",
    "mcp__screw-agents__detect_coverage_gaps",
    "mcp__screw-agents__lint_adaptive_script",
    "mcp__screw-agents__stage_adaptive_script",
    "mcp__screw-agents__promote_staged_script",
    "mcp__screw-agents__reject_staged_script",
    "mcp__screw-agents__execute_adaptive_script",
]

# Tools required in the orchestrator (screw-injection.md). The orchestrator
# is updated separately in T17 — until then, it still references the
# pre-C1 tool surface (sign_adaptive_script). Split out so T15+T16 can land
# without pulling T17 into scope.
_ORCHESTRATOR_ADAPTIVE_MCP_TOOLS = [
    "mcp__screw-agents__record_context_required_match",
    "mcp__screw-agents__detect_coverage_gaps",
    "mcp__screw-agents__lint_adaptive_script",
    "mcp__screw-agents__sign_adaptive_script",
    "mcp__screw-agents__execute_adaptive_script",
]

# Back-compat alias — some tests reference the old name; point it at the
# orchestrator list (which is still the superset including sign).
_ADAPTIVE_MCP_TOOLS = _ORCHESTRATOR_ADAPTIVE_MCP_TOOLS


def _parse_subagent_file(path: Path) -> tuple[dict, str]:
    """Parse a Claude Code subagent/command markdown file into (frontmatter, body)."""
    content = path.read_text(encoding="utf-8")
    assert content.startswith("---\n"), f"{path.name} must start with YAML frontmatter"
    end = content.index("\n---\n", 4)
    frontmatter_text = content[4:end]
    body = content[end + len("\n---\n") :]
    return yaml.safe_load(frontmatter_text), body


def _extract_adaptive_section(body: str, heading: str) -> str:
    """Extract the adaptive-mode section from a subagent body.

    `heading` is the exact first-line match (e.g., '### Step 3.5: Adaptive Mode'
    for per-agent, '### Step 2.5: Adaptive Mode' for orchestrator). Section
    terminates at the next '### Step' heading or EOF.
    """
    start = body.index(heading)
    rest = body[start:]
    # Find the next '### Step ' heading after the section's own heading.
    # Skip the section's own heading by starting the search one char in.
    search_from = len(heading)
    nxt = rest.find("\n### Step ", search_from)
    if nxt == -1:
        return rest
    return rest[: nxt + 1]  # include the trailing newline before next section


# ---- Test 1: section exists in all 4 per-agent subagents --------------------


def test_adaptive_section_exists_in_all_four_per_agent_subagents() -> None:
    for agent, path in _PER_AGENT_FILES.items():
        _, body = _parse_subagent_file(path)
        assert "### Step 3.5: Adaptive Mode" in body, (
            f"screw-{agent}.md missing '### Step 3.5: Adaptive Mode' heading"
        )


# ---- Test 2: byte-identical section modulo agent-name substitution ----------


def test_adaptive_section_identical_modulo_agent_name() -> None:
    sections: dict[str, str] = {}
    for agent, path in _PER_AGENT_FILES.items():
        _, body = _parse_subagent_file(path)
        sections[agent] = _extract_adaptive_section(body, "### Step 3.5: Adaptive Mode")

    def normalize(agent: str, section: str) -> str:
        # Replace this file's agent name with a neutral placeholder.
        normalized = section.replace(agent, "{AGENT}")
        # Restore the literal list 'sqli/cmdi/ssti/xss' which appears verbatim
        # in all 4 files (it's the self-referential "this subagent's name" hint).
        for variant in (
            "{AGENT}/cmdi/ssti/xss",
            "sqli/{AGENT}/ssti/xss",
            "sqli/cmdi/{AGENT}/xss",
            "sqli/cmdi/ssti/{AGENT}",
        ):
            normalized = normalized.replace(variant, "sqli/cmdi/ssti/xss")
        return normalized

    normalized = {a: normalize(a, s) for a, s in sections.items()}
    distinct = set(normalized.values())
    assert len(distinct) == 1, (
        f"adaptive sections differ across per-agent subagents: "
        f"{len(distinct)} distinct normalized versions"
    )


# ---- Test 3: tools frontmatter updated in all 5 subagent files --------------


def test_tools_frontmatter_includes_adaptive_mcp_tools() -> None:
    per_agent = {f"screw-{a}.md": p for a, p in _PER_AGENT_FILES.items()}
    for name, path in per_agent.items():
        frontmatter, _ = _parse_subagent_file(path)
        tools = frontmatter.get("tools", [])
        assert isinstance(tools, list), f"{name} tools must be a list"
        for required in _PER_AGENT_ADAPTIVE_MCP_TOOLS:
            assert required in tools, (
                f"{name} tools frontmatter missing required adaptive MCP tool: "
                f"{required}"
            )
        # Post-C1: per-agent LLM-flow MUST NOT list sign_adaptive_script
        # (direct-path tool is reserved for non-LLM callers). If this
        # fails, the Option D isolation has regressed.
        assert "mcp__screw-agents__sign_adaptive_script" not in tools, (
            f"{name} tools frontmatter still lists sign_adaptive_script — "
            f"Option D isolation regressed (spec §3.2)"
        )
        assert "Task" in tools, (
            f"{name} tools frontmatter missing 'Task' "
            f"(needed to invoke screw-script-reviewer for Layer 0d)"
        )

    # Orchestrator still uses the pre-C1 tool surface until T17 ships.
    frontmatter, _ = _parse_subagent_file(_ORCHESTRATOR_FILE)
    tools = frontmatter.get("tools", [])
    assert isinstance(tools, list), "screw-injection.md tools must be a list"
    for required in _ORCHESTRATOR_ADAPTIVE_MCP_TOOLS:
        assert required in tools, (
            f"screw-injection.md tools frontmatter missing required "
            f"adaptive MCP tool: {required}"
        )
    assert "Task" in tools


# ---- Test 4: orchestrator has its own adaptive section ---------------------


def test_injection_orchestrator_has_adaptive_section() -> None:
    _, body = _parse_subagent_file(_ORCHESTRATOR_FILE)
    assert "### Step 2.5: Adaptive Mode" in body, (
        "screw-injection.md missing '### Step 2.5: Adaptive Mode' heading"
    )
    section = _extract_adaptive_section(body, "### Step 2.5: Adaptive Mode")
    # Orchestrator-specific: must mention the shared quota across all 4 agents
    assert "shared" in section.lower() or "single" in section.lower()
    assert "layer 0f" in section.lower()
    # Must list all 4 agents in the domain explicitly
    for agent in ("sqli", "cmdi", "ssti", "xss"):
        assert agent in section, (
            f"orchestrator adaptive section must reference {agent} by name"
        )


# ---- Test 5: scan.md documents --adaptive flag -----------------------------


def test_scan_command_doc_documents_adaptive_flag() -> None:
    _, body = _parse_subagent_file(_SCAN_COMMAND_FILE)
    # Syntax line mentions the flag
    assert "--adaptive" in body, "scan.md must document the --adaptive flag"
    # Body has an "Example" invocation with --adaptive
    assert "/screw:scan" in body and "--adaptive" in body
    # Interactive-consent caveat is present
    body_lower = body.lower()
    assert (
        "interactive" in body_lower
        and ("consent" in body_lower or "non-interactive" in body_lower or "ci" in body_lower)
    ), "scan.md must include the interactive-consent caveat for --adaptive"


# ---- Test 6: adaptive section references all 5 new MCP tools + reviewer ----


def test_adaptive_section_references_all_required_mcp_tools() -> None:
    required = set(_PER_AGENT_ADAPTIVE_MCP_TOOLS)
    required.add("screw-script-reviewer")
    for agent, path in _PER_AGENT_FILES.items():
        _, body = _parse_subagent_file(path)
        section = _extract_adaptive_section(body, "### Step 3.5: Adaptive Mode")
        for token in required:
            assert token in section, (
                f"screw-{agent}.md adaptive section missing reference to `{token}`"
            )
        # Post-C1: LLM-flow section MUST NOT reference sign_adaptive_script
        # (the direct-path tool). Option D isolation regression guard.
        assert "sign_adaptive_script" not in section, (
            f"screw-{agent}.md adaptive section still references "
            f"sign_adaptive_script — Option D isolation regressed "
            f"(use stage + promote instead)"
        )


# ---- Test 7: prompt-injection-resistance language is present ---------------


def test_adaptive_section_has_prompt_injection_resistance() -> None:
    for agent, path in _PER_AGENT_FILES.items():
        _, body = _parse_subagent_file(path)
        section = _extract_adaptive_section(body, "### Step 3.5: Adaptive Mode")
        # Untrusted fence construct
        assert "UNTRUSTED_CODE_" in section, (
            f"screw-{agent}.md adaptive section must include the "
            f"UNTRUSTED_CODE_<fence> Layer 0a construct"
        )
        # Explicit "treat as data, NOT instructions" language
        assert (
            "treat as data, NOT instructions" in section
            or "treat as data, not instructions" in section.lower()
        ), (
            f"screw-{agent}.md adaptive section must explicitly frame target "
            f"code as data, not instructions (Layer 0a discipline)"
        )
        # Fence-token derivation forbids it being controllable by the target
        assert "fence_token" in section
        assert "sha256" in section.lower()


# ---- Test 8: 15-layer stack referenced, not 7-layer (regression guard) -----


def test_adaptive_section_documents_15_layer_stack() -> None:
    # Per-agent files
    for agent, path in _PER_AGENT_FILES.items():
        _, body = _parse_subagent_file(path)
        section = _extract_adaptive_section(body, "### Step 3.5: Adaptive Mode")
        section_lower = section.lower()
        assert "15-layer" in section_lower or "15 layer" in section_lower, (
            f"screw-{agent}.md adaptive section must reference the canonical "
            f"15-layer defense stack"
        )
        # Regression guard: must NOT reference the wrong '7-layer' count
        assert "7-layer" not in section_lower and "7 layer" not in section_lower, (
            f"screw-{agent}.md adaptive section must not reference the wrong "
            f"'7-layer' count"
        )
        # Must name at least 3 specific layer IDs
        layer_ids = ["layer 0a", "layer 0b", "layer 0c", "layer 0d", "layer 0e",
                     "layer 0f", "layer 1", "layer 5"]
        present = sum(1 for lid in layer_ids if lid in section_lower)
        assert present >= 3, (
            f"screw-{agent}.md adaptive section names {present} layer IDs; "
            f"must name at least 3 of {layer_ids}"
        )
    # Orchestrator
    _, body = _parse_subagent_file(_ORCHESTRATOR_FILE)
    section = _extract_adaptive_section(body, "### Step 2.5: Adaptive Mode")
    assert "15-layer" in section.lower() or "15 layer" in section.lower()


# ---- Test 9: script naming regex is locked ---------------------------------


def test_adaptive_section_documents_script_naming_regex() -> None:
    for agent, path in _PER_AGENT_FILES.items():
        _, body = _parse_subagent_file(path)
        section = _extract_adaptive_section(body, "### Step 3.5: Adaptive Mode")
        # Must include the regex literally so a reviewer can verify the engine
        # matches (signing.py / models.py)
        assert "^[a-z0-9][a-z0-9-]{2,62}$" in section, (
            f"screw-{agent}.md adaptive section must document the script-name "
            f"regex `^[a-z0-9][a-z0-9-]{{2,62}}$` (matches sign_adaptive_script "
            f"validation)"
        )
        # Must mention hash6 derivation
        assert "hash6" in section
        assert "sha256" in section.lower()


# ---- Test 10: no hand-wavy non-interactive-detection language --------------


def test_adaptive_section_removes_noninteractive_detection() -> None:
    forbidden_phrases = [
        "if the session appears non-interactive",
        "session appears non-interactive",
        "appears to be non-interactive",
        "detect non-interactive",
    ]
    required_phrases = [
        "--adaptive",  # the flag itself
    ]
    for agent, path in _PER_AGENT_FILES.items():
        _, body = _parse_subagent_file(path)
        section = _extract_adaptive_section(body, "### Step 3.5: Adaptive Mode")
        section_lower = section.lower()
        for phrase in forbidden_phrases:
            assert phrase.lower() not in section_lower, (
                f"screw-{agent}.md adaptive section contains forbidden hand-wavy "
                f"non-interactive-detection phrase: `{phrase}`. The `--adaptive` "
                f"flag IS the user consent — do not reintroduce runtime probing."
            )
        for phrase in required_phrases:
            assert phrase in section
        # Must explicitly frame the flag as consent
        assert "flag is consent" in section_lower or "flag is user consent" in section_lower or \
               "--adaptive` flag is" in section_lower.replace("**", "").replace("\n", " ") or \
               "flag is the user consent" in section_lower, (
            f"screw-{agent}.md adaptive section must explicitly frame "
            f"`--adaptive` as the user consent (no runtime non-interactivity "
            f"probe)"
        )


# ---- Test 11: execute_adaptive_script invocation omits session_id ----------


def test_execute_adaptive_script_invocation_omits_session_id() -> None:
    """T18a Deviation 1 regression guard: the server.py signature for
    execute_adaptive_script accepts only project_root, script_name,
    and wall_clock_s (not session_id). A future "helpful" edit that
    re-adds session_id to the subagent's sample invocation would
    drift from the server signature and fail at runtime. This test
    locks the correct call shape across all 4 per-agent subagents."""
    for agent, path in _PER_AGENT_FILES.items():
        _, body = _parse_subagent_file(path)
        # Find the execute_adaptive_script sample invocation.
        # Look for the opening `execute_adaptive_script({` and capture
        # through the closing `})`.
        import re
        match = re.search(
            r"execute_adaptive_script\s*\(\s*\{.*?\}\s*\)",
            body,
            re.DOTALL,
        )
        assert match is not None, (
            f"{agent}: could not find execute_adaptive_script invocation "
            f"in adaptive section"
        )
        invocation = match.group(0)
        # session_id must NOT appear as a key in this invocation
        assert '"session_id"' not in invocation, (
            f"{agent}: execute_adaptive_script invocation includes "
            f"session_id — server.py signature only accepts "
            f"project_root/script_name/wall_clock_s. Remove session_id "
            f"from this specific call (other MCP tool calls still pass "
            f"session_id, but not this one)."
        )
