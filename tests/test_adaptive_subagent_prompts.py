"""Format smoke tests for the `--adaptive` prompt surface.

Post-C2 (Phase 3b-C2 Nested Subagent Dispatch Fix): the 4 per-agent injection
subagents emit a structured pending_review payload and RETURN to main session;
they DO NOT stage/promote/reject/execute scripts, DO NOT dispatch the
screw:screw-script-reviewer subagent (nested dispatch is architecturally
blocked — docs/en/sub-agents.md line 711). Post-generation flow (reviewer
dispatch, staging, 5-section review, approve/reject, promote/execute/accumulate)
lives in scan.md's main-session prompt.

These tests are NOT semantic — they lock markdown structure and tool-surface
absence (scan subagents) / presence (scan.md) so a future edit can't silently
reintroduce the nested-dispatch pattern. Runtime dispatch correctness is
validated by the live round-trip protocol in spec §8 — NOT by this file.

Design decisions locked here:

- Per-agent subagent adaptive sections: byte-identical across the 4
  modulo agent-name substitution. Drift is a regression.
- The orchestrator (screw-injection.md) has its own adaptive section because
  it implements the shared Layer 0f quota. We only check for section presence
  and shared-quota language.
- scan.md documents --adaptive flag + phrase grammar including confirm-high
  (C2 UX friction for HIGH-risk scripts per spec §4.2 D2).
- scan.md owns post-generation MCP tool calls (stage/promote/reject/execute);
  per-agent + orchestrator files do NOT list these tools.
- screw-full-review.md is DELETED (C2 Option A fold+delete per spec §4.3).
"""

from __future__ import annotations

from pathlib import Path

import pytest
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

# Tools required in all 5 adaptive-mode subagent files (4 per-agent +
# orchestrator). Post-C2 (Phase 3b-C2): the scan subagents no longer
# own the post-generation MCP surface. Stage/promote/reject/execute/Task
# move to scan.md's main-session orchestrator (chain-subagents pattern
# per sub-agents.md:683-689); they MUST NOT appear in per-agent or
# orchestrator frontmatter or body.
_ADAPTIVE_MCP_TOOLS_REQUIRED_PER_AGENT = [
    "mcp__screw-agents__record_context_required_match",
    "mcp__screw-agents__detect_coverage_gaps",
    "mcp__screw-agents__lint_adaptive_script",
    "mcp__screw-agents__accumulate_findings",
]

_ADAPTIVE_MCP_TOOLS_FORBIDDEN_ON_PER_AGENT = [
    "mcp__screw-agents__stage_adaptive_script",
    "mcp__screw-agents__promote_staged_script",
    "mcp__screw-agents__reject_staged_script",
    "mcp__screw-agents__execute_adaptive_script",
    "mcp__screw-agents__finalize_scan_results",
    "Task",
]

# Tools required on scan.md (main session orchestrator) — the inverse of
# _ADAPTIVE_MCP_TOOLS_FORBIDDEN_ON_PER_AGENT plus accumulate_findings +
# finalize (main session owns the two-phase persist pattern post-C2).
_ADAPTIVE_MCP_TOOLS_REQUIRED_ON_SCAN_MD = [
    "mcp__screw-agents__stage_adaptive_script",
    "mcp__screw-agents__promote_staged_script",
    "mcp__screw-agents__reject_staged_script",
    "mcp__screw-agents__execute_adaptive_script",
    "mcp__screw-agents__accumulate_findings",
    "mcp__screw-agents__finalize_scan_results",
    "mcp__screw-agents__list_domains",
]


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


def test_tools_frontmatter_per_agent_positive_and_negative() -> None:
    """Post-C2: scan subagents (per-agent + orchestrator) retain
    record_context_required_match / detect_coverage_gaps / lint_adaptive_script
    / accumulate_findings; MUST NOT list stage/promote/reject/execute /
    finalize / Task (those moved to scan.md)."""
    all_files = {f"screw-{a}.md": p for a, p in _PER_AGENT_FILES.items()}
    all_files["screw-injection.md"] = _ORCHESTRATOR_FILE
    for name, path in all_files.items():
        frontmatter, _ = _parse_subagent_file(path)
        tools = frontmatter.get("tools", [])
        assert isinstance(tools, list), f"{name} tools must be a list"
        for required in _ADAPTIVE_MCP_TOOLS_REQUIRED_PER_AGENT:
            assert required in tools, (
                f"{name} tools frontmatter missing required tool: {required}"
            )
        for forbidden in _ADAPTIVE_MCP_TOOLS_FORBIDDEN_ON_PER_AGENT:
            assert forbidden not in tools, (
                f"{name} tools frontmatter still lists forbidden tool: {forbidden} "
                f"— Phase 3b-C2 moved this to scan.md's main-session orchestrator"
            )
        # Option D (C1) isolation guard stays — sign_adaptive_script reserved
        # for non-LLM callers; not permitted in any LLM-flow file.
        assert "mcp__screw-agents__sign_adaptive_script" not in tools, (
            f"{name} tools frontmatter lists sign_adaptive_script — "
            f"Option D isolation regressed (spec §3.2)"
        )


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


# ---- Test 6: per-agent adaptive sections reference only required tools -----


def test_adaptive_section_per_agent_references_only_required_tools() -> None:
    """Post-C2: per-agent adaptive sections reference required tools;
    MUST NOT reference stage/promote/reject/execute or the reviewer subagent
    (those moved to scan.md)."""
    required = set(_ADAPTIVE_MCP_TOOLS_REQUIRED_PER_AGENT)
    forbidden = set(_ADAPTIVE_MCP_TOOLS_FORBIDDEN_ON_PER_AGENT) | {
        "screw-script-reviewer",
        "screw:screw-script-reviewer",
    }
    for agent, path in _PER_AGENT_FILES.items():
        _, body = _parse_subagent_file(path)
        section = _extract_adaptive_section(body, "### Step 3.5: Adaptive Mode")
        for token in required:
            assert token in section, (
                f"screw-{agent}.md adaptive section missing required: `{token}`"
            )
        for token in forbidden:
            assert token not in section, (
                f"screw-{agent}.md adaptive section still references forbidden: "
                f"`{token}` — Phase 3b-C2 moved it to scan.md orchestrator"
            )
        assert "sign_adaptive_script" not in section, (
            f"screw-{agent}.md still references sign_adaptive_script — "
            f"Option D isolation regressed"
        )
    # Orchestrator: same negative guards; positive assertion is delegated to
    # test_injection_orchestrator_has_adaptive_section for its own content.
    _, body = _parse_subagent_file(_ORCHESTRATOR_FILE)
    section = _extract_adaptive_section(body, "### Step 2.5: Adaptive Mode")
    for token in forbidden:
        assert token not in section, (
            f"screw-injection.md adaptive section still references forbidden: "
            f"`{token}`"
        )
    assert "sign_adaptive_script" not in section


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


# ---- Whole-file format-smoke assertions (post-C2: per-agent + orchestrator scope only) ----


def _read_agent_content(path: Path) -> str:
    """Return the full markdown file content (frontmatter + body).

    Distinct from `_parse_subagent_file(path)` which splits into (frontmatter,
    body); these tests assert on the whole file so a single string is simpler.
    """
    return path.read_text(encoding="utf-8")


@pytest.mark.parametrize("agent,path", sorted(_PER_AGENT_FILES.items()))
def test_adaptive_prompt_does_not_reference_sign_adaptive_script(agent: str, path: Path) -> None:
    """Option D isolation: LLM flow must NEVER reach sign_adaptive_script
    (the direct-path tool). If this test fails, the C1 regeneration-surface
    closure has regressed. This is the whole-file form; section-level and
    frontmatter-level guards exist above at lines 217-221 and 156-159."""
    content = _read_agent_content(path)
    assert "sign_adaptive_script" not in content, (
        f"screw-{agent}.md references sign_adaptive_script — LLM-flow isolation "
        f"regressed. Use stage + promote instead (spec §3.2)."
    )


@pytest.mark.parametrize("agent,path", sorted(_PER_AGENT_FILES.items()))
def test_adaptive_prompt_contains_must_import_only_phrase(agent: str, path: Path) -> None:
    """I5: prompt enforces the allowlist loudly. Case-sensitive — the
    uppercase form is the intentional hardening signal."""
    content = _read_agent_content(path)
    assert "MUST import ONLY" in content, (
        f"screw-{agent}.md missing 'MUST import ONLY' hardening phrase (I5)"
    )


@pytest.mark.parametrize("agent,path", sorted(_PER_AGENT_FILES.items()))
def test_adaptive_prompt_lists_all_adaptive_exports(agent: str, path: Path) -> None:
    """I5: every name in adaptive.__all__ must appear in the generation prompt.
    At PR #6 HEAD `adaptive.__all__` has 18 entries; this test auto-tracks any
    additions so the prompt stays in sync with the public surface."""
    from screw_agents import adaptive as adaptive_pkg
    content = _read_agent_content(path)
    for name in adaptive_pkg.__all__:
        assert name in content, (
            f"screw-{agent}.md missing adaptive.__all__ entry {name!r} in prompt (I5)"
        )


@pytest.mark.parametrize("agent,path", sorted(_PER_AGENT_FILES.items()))
def test_adaptive_prompt_contains_negative_examples_block(agent: str, path: Path) -> None:
    """I5: negative examples mention common hallucinated names so the LLM
    sees canonical don't-invent-these examples."""
    content = _read_agent_content(path)
    assert "DO NOT invent helper names" in content, (
        f"screw-{agent}.md missing negative-examples header phrase (I5)"
    )
    for hallucinated in ("read_source", "parse_module", "walk_module"):
        assert hallucinated in content, (
            f"screw-{agent}.md missing hallucinated name example {hallucinated!r} (I5)"
        )


# ---- C2 NEW: scan.md main-session orchestrator assertions -------------------


def test_scan_md_references_all_required_orchestration_mcp_tools() -> None:
    """Post-C2: scan.md's main-session prompt must reference every MCP tool
    the orchestrator calls directly: stage/promote/reject/execute +
    accumulate + finalize + list_domains (for full-scope branch)."""
    _, body = _parse_subagent_file(_SCAN_COMMAND_FILE)
    for required in _ADAPTIVE_MCP_TOOLS_REQUIRED_ON_SCAN_MD:
        tool_basename = required.replace("mcp__screw-agents__", "")
        assert tool_basename in body, (
            f"scan.md missing reference to {tool_basename} "
            f"(Phase 3b-C2: main session owns post-generation flow)"
        )


def test_scan_md_dispatches_plugin_namespaced_reviewer() -> None:
    """Post-C2: scan.md dispatches screw:screw-script-reviewer from main
    session via the Task tool. The `subagent_type` literal must be the
    plugin-namespaced form (I1 hardening from C1 PR #6, preserved here)."""
    _, body = _parse_subagent_file(_SCAN_COMMAND_FILE)
    assert "screw:screw-script-reviewer" in body, (
        "scan.md missing plugin-namespaced reviewer dispatch (I1)"
    )
    # The bare name (without plugin prefix) must not appear as subagent_type.
    import re
    bare_refs = re.findall(
        r'subagent_type[\'": ]+\s*"screw-script-reviewer"', body
    )
    assert not bare_refs, (
        "scan.md uses bare screw-script-reviewer as subagent_type (I1 regressed)"
    )


def test_scan_md_phrase_grammar_locked() -> None:
    """Post-C2 spec §4.2 D2: phrase grammar includes approve, confirm-high
    (C2-new for HIGH-risk UX friction), confirm-stale, confirm-<8hex>, reject."""
    _, body = _parse_subagent_file(_SCAN_COMMAND_FILE)
    required_phrases = [
        "approve",
        "reject",
        "confirm-high",
        "confirm-stale",
        "confirm-",
    ]
    for phrase in required_phrases:
        assert phrase in body, (
            f"scan.md missing approval phrase token: `{phrase}`"
        )


def test_scan_md_contains_subagent_return_schema_keys() -> None:
    """Post-C2: scan.md parses scan-subagent fenced JSON return. The schema's
    top-level keys (from spec §5.1) must be visible in scan.md so the
    orchestrator knows what to parse."""
    _, body = _parse_subagent_file(_SCAN_COMMAND_FILE)
    required_keys = [
        "pending_reviews",
        "session_id",
        "trust_status",
        "scan_subagent",
        "scan_metadata",
    ]
    for key in required_keys:
        assert key in body, (
            f"scan.md missing subagent-return schema key: `{key}`"
        )


def test_scan_md_does_not_reference_deleted_full_review_subagent() -> None:
    """Post-C2: screw-full-review.md is deleted (Option A fold+delete).
    scan.md MUST NOT reference it."""
    _, body = _parse_subagent_file(_SCAN_COMMAND_FILE)
    assert "screw-full-review" not in body, (
        "scan.md still references deleted screw-full-review subagent "
        "(Phase 3b-C2 Option A: full scope folded into scan.md)"
    )


def test_screw_full_review_md_file_is_deleted() -> None:
    """Post-C2: screw-full-review.md file does not exist on disk."""
    deleted_path = _AGENTS_DIR / "screw-full-review.md"
    assert not deleted_path.exists(), (
        f"{deleted_path} still exists — Phase 3b-C2 Option A requires deletion "
        f"(second nested-subagent-dispatch instance per spec §1.4)"
    )


def test_per_agent_files_instruct_fenced_json_return() -> None:
    """Post-C2: per-agent + orchestrator scan subagents end their turn with
    a fenced JSON code block per spec §5.1 schema. The instruction to do so
    must be discoverable in the prompt."""
    all_files = {f"screw-{a}.md": p for a, p in _PER_AGENT_FILES.items()}
    all_files["screw-injection.md"] = _ORCHESTRATOR_FILE
    for name, path in all_files.items():
        content = _read_agent_content(path)
        assert "pending_reviews" in content, (
            f"{name} missing pending_reviews reference — structured return "
            f"schema (spec §5.1) not discoverable"
        )
        assert "scan_subagent" in content, (
            f"{name} missing scan_subagent reference"
        )
        # Instruct the subagent to emit the fenced JSON block (rough
        # regex — exact phrase is implementer-authored; this is a
        # substring heuristic).
        assert ("fenced JSON" in content or "fenced json" in content.lower()
                or "```json" in content), (
            f"{name} missing instruction to emit fenced JSON return block"
        )


def test_scan_md_contains_full_scope_list_domains_branch() -> None:
    """Post-C2 Option A: scan.md's `full` branch dispatches domain
    orchestrators via list_domains (no more screw-full-review). The branch
    must reference list_domains and iterate per-domain dispatch."""
    _, body = _parse_subagent_file(_SCAN_COMMAND_FILE)
    assert "list_domains" in body, (
        "scan.md missing list_domains reference (full scope branch)"
    )
    # Sanity: full scope is documented
    assert "full" in body.lower()
