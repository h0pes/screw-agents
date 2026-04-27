"""Format smoke tests for the universal `screw-scan` subagent.

T-SCAN-REFACTOR Task 7: collapses 4 per-agent injection subagents (sqli, cmdi,
ssti, xss) and 1 domain orchestrator (screw-injection) into a single universal
`screw-scan.md` parameterized by an `agents: list[str]` from the dispatch
prompt.

These tests lock:

- File presence + retired-file deletion (file-presence registration model).
- YAML frontmatter shape (name match, required tools, no dispatch/mutation
  tools, `model: opus`).
- Body invariants (no nested dispatch language, Layer 0a-f markers, fence
  token + UNTRUSTED_CODE_ delimiter, regenerate-once policy, hash6 derivation,
  script-name regex, no `finalize_scan_results` call, no inline findings).
- Return-schema contract (C2-required keys per spec §5.1, mirrored in the
  prior per-agent return so `scan.md`'s parser keeps working).

These migrated assertions originated in `tests/test_adaptive_subagent_prompts.py`
where they were parametrized over the 5 deleted files; here they assert once
on the universal subagent. scan.md / orchestrator-asserting tests stay in
`test_adaptive_subagent_prompts.py` (Task 8 will update them when scan.md is
rewritten).
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml


_REPO_ROOT = Path(__file__).parent.parent
_AGENTS_DIR = _REPO_ROOT / "plugins" / "screw" / "agents"
_SCAN_SUBAGENT_FILE = _AGENTS_DIR / "screw-scan.md"

# The 5 retired files — must NOT exist on disk after Task 7.
_RETIRED_SUBAGENT_FILES = [
    _AGENTS_DIR / "screw-sqli.md",
    _AGENTS_DIR / "screw-cmdi.md",
    _AGENTS_DIR / "screw-ssti.md",
    _AGENTS_DIR / "screw-xss.md",
    _AGENTS_DIR / "screw-injection.md",
]

# Other subagents that survive Task 7 (separate concerns; not dispatch tools).
_UNCHANGED_SUBAGENT_FILES = [
    _AGENTS_DIR / "screw-script-reviewer.md",
    _AGENTS_DIR / "screw-learning-analyst.md",
]

# Tools the universal subagent MUST declare.
_REQUIRED_TOOLS = [
    "Read",
    "Glob",
    "Grep",
    "mcp__screw-agents__scan_agents",
    "mcp__screw-agents__get_agent_prompt",
    "mcp__screw-agents__accumulate_findings",
    "mcp__screw-agents__record_context_required_match",
    "mcp__screw-agents__verify_trust",
    "mcp__screw-agents__detect_coverage_gaps",
    "mcp__screw-agents__lint_adaptive_script",
]

# Tools the universal subagent MUST NOT declare. The negative set guards
# Layer 0b/0c invariants (no nested dispatch, read-only) AND the C1/C2
# isolation envelope (no direct sign / stage / promote / reject / execute /
# finalize from within an LLM-flow subagent).
_FORBIDDEN_TOOLS = [
    "Edit",
    "Write",
    "Bash",
    "Task",
    "Agent",
    "mcp__screw-agents__stage_adaptive_script",
    "mcp__screw-agents__promote_staged_script",
    "mcp__screw-agents__reject_staged_script",
    "mcp__screw-agents__execute_adaptive_script",
    "mcp__screw-agents__sign_adaptive_script",
    "mcp__screw-agents__finalize_scan_results",
]

# C2 contract keys — locked by `tests/test_adaptive_subagent_prompts.py:497-512`
# parser. Renaming or omitting any of these breaks `scan.md`'s orchestrator.
_C2_RETURN_SCHEMA_KEYS = [
    "schema_version",
    "scan_subagent",
    "session_id",
    "trust_status",
    "yaml_findings_accumulated",
    "adaptive_mode_engaged",
    "pending_reviews",
    "scan_metadata",
]


def _read_frontmatter(path: Path) -> dict:
    """Parse YAML frontmatter between leading/trailing `---` lines.

    Mirrors the helper pattern in `tests/test_adaptive_subagent_prompts.py`
    so tests stay consistent.
    """
    content = path.read_text(encoding="utf-8")
    assert content.startswith("---\n"), f"{path.name} must start with YAML frontmatter"
    end = content.index("\n---\n", 4)
    frontmatter_text = content[4:end]
    return yaml.safe_load(frontmatter_text)


def _read_body(path: Path) -> str:
    """Return the markdown body (post-frontmatter) of a subagent file."""
    content = path.read_text(encoding="utf-8")
    assert content.startswith("---\n"), f"{path.name} must start with YAML frontmatter"
    end = content.index("\n---\n", 4)
    return content[end + len("\n---\n") :]


def _read_full(path: Path) -> str:
    """Return the full markdown content (frontmatter + body)."""
    return path.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# File presence / deletion
# ---------------------------------------------------------------------------


def test_screw_scan_subagent_file_exists() -> None:
    """Plan Task 7 Step 6 #1: the universal subagent file is on disk."""
    assert _SCAN_SUBAGENT_FILE.exists(), (
        f"{_SCAN_SUBAGENT_FILE} must exist — universal subagent registration "
        f"is by file presence."
    )


def test_retired_per_agent_subagents_are_deleted() -> None:
    """Plan Task 7 Step 6 #2: the 5 retired subagent files are removed.

    Subagent registration is by file presence — leaving these files behind
    would mean Claude Code still dispatches them, defeating the consolidation.
    """
    for path in _RETIRED_SUBAGENT_FILES:
        assert not path.exists(), (
            f"{path} still exists — Task 7 requires deletion of retired "
            f"per-agent and orchestrator subagents."
        )


def test_other_subagents_unchanged() -> None:
    """Plan Task 7 Step 6 #3: subagents with separate concerns survive.

    `screw-script-reviewer` is dispatched by main session for adaptive script
    review (Layer 0d). `screw-learning-analyst` is the autoresearch consumer.
    Neither dispatches scan tools; both stay.
    """
    for path in _UNCHANGED_SUBAGENT_FILES:
        assert path.exists(), (
            f"{path} must still exist — separate concern from scan dispatch."
        )


# ---------------------------------------------------------------------------
# Frontmatter
# ---------------------------------------------------------------------------


def test_screw_scan_frontmatter_parses_yaml() -> None:
    """Plan Task 7 Step 6 #4: frontmatter is valid YAML between `---` lines."""
    fm = _read_frontmatter(_SCAN_SUBAGENT_FILE)
    assert isinstance(fm, dict), "frontmatter must parse to a dict"


def test_screw_scan_frontmatter_name_matches_filename_stem() -> None:
    """Plan Task 7 Step 6 #5: Task 1 invariant — `name` matches file stem."""
    fm = _read_frontmatter(_SCAN_SUBAGENT_FILE)
    assert fm.get("name") == "screw-scan", (
        f"frontmatter `name` must equal file stem 'screw-scan'; got {fm.get('name')!r}"
    )


def test_screw_scan_frontmatter_declares_required_tools() -> None:
    """Plan Task 7 Step 6 #6: tools list includes Read/Glob/Grep + 7 MCP tools.

    Glob is required because the user can pass glob target specs (e.g.,
    `src/api/**`). The 2 adaptive tools (`detect_coverage_gaps`,
    `lint_adaptive_script`) are required for Step 3.5's E1=A inline body.
    """
    fm = _read_frontmatter(_SCAN_SUBAGENT_FILE)
    tools = fm.get("tools", [])
    assert isinstance(tools, list), "frontmatter `tools` must be a list"
    for required in _REQUIRED_TOOLS:
        assert required in tools, (
            f"frontmatter `tools` missing required tool: {required}"
        )


def test_screw_scan_frontmatter_excludes_dispatch_or_mutation_tools() -> None:
    """Plan Task 7 Step 6 #7: tools list MUST NOT contain Edit/Write/Bash/Task
    or the post-generation MCP surface.

    Layer 0b: subagent does not dispatch other subagents (no Task/Agent).
    Layer 0c: subagent is read-only (no Edit/Write/Bash).
    C1/C2 isolation: stage/promote/reject/execute/finalize/sign live on
    main session, not on LLM-flow subagents.
    """
    fm = _read_frontmatter(_SCAN_SUBAGENT_FILE)
    tools = fm.get("tools", [])
    for forbidden in _FORBIDDEN_TOOLS:
        assert forbidden not in tools, (
            f"frontmatter `tools` lists forbidden tool: {forbidden} — violates "
            f"Layer 0b/0c invariants or C1/C2 isolation envelope."
        )


def test_screw_scan_uses_opus_model() -> None:
    """Plan Task 7 Step 6 #8: `model: opus` per Marco's best-in-class directive
    (memory `feedback_opus_for_all_subagents`)."""
    fm = _read_frontmatter(_SCAN_SUBAGENT_FILE)
    assert fm.get("model") == "opus", (
        f"frontmatter `model` must be 'opus' (Marco's best-in-class directive); "
        f"got {fm.get('model')!r}"
    )


# ---------------------------------------------------------------------------
# Body — security invariants migrated from test_adaptive_subagent_prompts.py
# ---------------------------------------------------------------------------


def test_screw_scan_body_states_no_nested_dispatch() -> None:
    """Plan Task 7 Step 6 #9: C2 invariant.

    The subagent must explicitly say it does NOT dispatch other subagents.
    Per `sub-agents.md:711`, subagents cannot spawn other subagents; the
    Layer 0d reviewer dispatch lives on main session (chain-subagents pattern).
    """
    body = _read_body(_SCAN_SUBAGENT_FILE)
    body_lower = body.lower()
    assert "do not dispatch other subagents" in body_lower or (
        "do not" in body_lower and "dispatch" in body_lower and "subagent" in body_lower
    ), (
        "screw-scan.md body must explicitly say it does not dispatch other "
        "subagents (C2 chain-subagents invariant per sub-agents.md:711)."
    )


def test_screw_scan_body_contains_adaptive_layer_markers() -> None:
    """Plan Task 7 Step 6 #10: body names Layer 0a-f markers ported verbatim
    from screw-sqli.md:85-353 (security invariants).

    Each layer addresses a specific defense:
      0a — UNTRUSTED_CODE_ fence (prompt-injection guard)
      0b — curated imports
      0c — templated scaffold
      0d — semantic reviewer (dispatched by main session, not us)
      0e — injection blocklist
      0f — per-session quota
    """
    body = _read_body(_SCAN_SUBAGENT_FILE).lower()
    for marker in ("layer 0a", "layer 0b", "layer 0c", "layer 0d", "layer 0e", "layer 0f"):
        assert marker in body, (
            f"screw-scan.md body must reference {marker} (security invariant)"
        )


def test_screw_scan_body_states_next_cursor_stop_condition() -> None:
    """Plan Task 7 Step 6 #11: explicit termination of pagination loop.

    The body must document that pagination stops when `next_cursor` is null —
    otherwise the LLM may infinitely re-call `scan_agents`.
    """
    body = _read_body(_SCAN_SUBAGENT_FILE)
    assert "next_cursor" in body, "screw-scan.md must reference `next_cursor`"
    body_lower = body.lower()
    # Must document either "while next_cursor is non-null" or "next_cursor is null"
    # to mark loop termination.
    assert (
        "next_cursor is null" in body_lower
        or "next_cursor is non-null" in body_lower
        or "next_cursor` is null" in body_lower
        or "next_cursor` is non-null" in body_lower
    ), (
        "screw-scan.md must explicitly document the next_cursor stop condition "
        "(prevents infinite pagination)."
    )


def test_screw_scan_body_does_not_call_finalize_scan_results() -> None:
    """Plan Task 7 Step 6 #12: subagent MUST NOT call finalize_scan_results.

    The two-phase persist pattern (per C2): subagent calls accumulate_findings
    (idempotent stage) and returns; main session owns the finalize call so it
    can consolidate YAML findings with adaptive-script-produced findings in
    the same session. Subagent finalize would race that consolidation.

    The body MAY mention finalize_scan_results in a "Do NOT call" instruction;
    we only forbid an instruction that says the subagent SHOULD call it.
    """
    body = _read_body(_SCAN_SUBAGENT_FILE)
    # The body mentions `finalize_scan_results` only in negative contexts
    # ("Do NOT call finalize_scan_results", "main session calls finalize_scan_results").
    # An affirmative call instruction (e.g., "Call mcp__screw-agents__finalize_scan_results")
    # would be a regression. We assert the negative-context phrase is present
    # and ensure no affirmative call instruction is present.
    assert "Do NOT call" in body and "finalize_scan_results" in body, (
        "screw-scan.md must explicitly say 'Do NOT call finalize_scan_results' — "
        "main session owns finalize per C2 chain-subagents pattern."
    )
    # No affirmative call patterns.
    forbidden_call_patterns = [
        "mcp__screw-agents__finalize_scan_results({",
        "Call finalize_scan_results",
        "call finalize_scan_results",
    ]
    for pat in forbidden_call_patterns:
        assert pat not in body, (
            f"screw-scan.md contains an affirmative finalize call instruction: {pat!r}"
        )


def test_screw_scan_return_schema_includes_c2_contract_keys() -> None:
    """Plan Task 7 Step 6 #13: C2 contract keys present in body's return schema.

    Locked by parser at `tests/test_adaptive_subagent_prompts.py:497-512`.
    Renaming/omitting these keys breaks scan.md's main-session parser.
    """
    body = _read_body(_SCAN_SUBAGENT_FILE)
    for key in _C2_RETURN_SCHEMA_KEYS:
        assert key in body, (
            f"screw-scan.md return-schema documentation missing C2 contract key: "
            f"`{key}` (locked by parser at test_adaptive_subagent_prompts.py:497-512)."
        )


def test_screw_scan_body_uses_untrusted_code_delimiter() -> None:
    """Plan Task 7 Step 6 #14: Layer 0a fence delimiter present.

    The `UNTRUSTED_CODE_<fence_token>` convention is the prompt-injection
    guard — target source goes inside the fence, treated as data not
    instructions. An attacker embedded in target code cannot close the fence
    without knowing the fence_token (a sha256 prefix over session_id +
    gap location + timestamp).
    """
    body = _read_body(_SCAN_SUBAGENT_FILE)
    assert "UNTRUSTED_CODE_" in body, (
        "screw-scan.md must include the UNTRUSTED_CODE_<fence> Layer 0a "
        "construct (prompt-injection guard)."
    )
    # Explicit "treat as data, NOT instructions" framing.
    body_lower = body.lower()
    assert (
        "treat as data, not instructions" in body_lower
        or "treat as data, not instructions" in body_lower.replace(",", ", ")
    ), (
        "screw-scan.md must explicitly frame target code as data, NOT "
        "instructions (Layer 0a discipline)."
    )
    # Fence token derivation is sha256-based (not a hardcoded constant).
    assert "fence_token" in body, "screw-scan.md must reference fence_token"
    assert "sha256" in body_lower, (
        "screw-scan.md must derive fence_token via sha256 (entropy from "
        "session_id makes the fence unguessable)."
    )


def test_screw_scan_body_forbids_inline_findings() -> None:
    """Plan Task 7 Step 6 #15: Concern A from spec §11.2.

    Findings live in `.screw/staging/{session_id}/findings.json` after
    accumulate_findings. The structured return is a SUMMARY only —
    inlining findings would balloon the return payload and bypass the
    staging file as the source of truth.
    """
    body = _read_body(_SCAN_SUBAGENT_FILE)
    assert "MUST NOT" in body, (
        "screw-scan.md must include a MUST NOT instruction (Concern A discipline)."
    )
    assert "accumulate_findings" in body, (
        "screw-scan.md must reference accumulate_findings as the staging path."
    )
    assert "staging" in body, (
        "screw-scan.md must explain that findings live in the staging directory."
    )


# ---------------------------------------------------------------------------
# Migrated from test_adaptive_subagent_prompts.py: prompt-injection
# resistance + I5 hardening + script naming regex + non-interactive language
# ---------------------------------------------------------------------------


def test_screw_scan_body_documents_15_layer_stack() -> None:
    """Migrated from test_adaptive_section_documents_15_layer_stack.

    Regression guard against an old `7-layer` count. Must reference at least
    3 specific Layer IDs.
    """
    body = _read_body(_SCAN_SUBAGENT_FILE).lower()
    assert "15-layer" in body or "15 layer" in body, (
        "screw-scan.md must reference the canonical 15-layer defense stack."
    )
    assert "7-layer" not in body and "7 layer" not in body, (
        "screw-scan.md must not reference the wrong '7-layer' count."
    )
    layer_ids = [
        "layer 0a",
        "layer 0b",
        "layer 0c",
        "layer 0d",
        "layer 0e",
        "layer 0f",
        "layer 1",
        "layer 5",
    ]
    present = sum(1 for lid in layer_ids if lid in body)
    assert present >= 3, (
        f"screw-scan.md names {present} layer IDs; must name at least 3 of {layer_ids}"
    )


def test_screw_scan_body_documents_script_naming_regex() -> None:
    """Migrated from test_adaptive_section_documents_script_naming_regex.

    The regex `^[a-z0-9][a-z0-9-]{2,62}$` matches the engine's
    sign_adaptive_script validation (signing.py / models.py).
    """
    body = _read_body(_SCAN_SUBAGENT_FILE)
    assert "^[a-z0-9][a-z0-9-]{2,62}$" in body, (
        "screw-scan.md must document the script-name regex "
        "`^[a-z0-9][a-z0-9-]{2,62}$` (matches engine validation)."
    )
    assert "hash6" in body, "screw-scan.md must mention hash6 derivation."
    assert "sha256" in body.lower(), "screw-scan.md must derive hash6 via sha256."


def test_screw_scan_body_removes_noninteractive_detection() -> None:
    """Migrated from test_adaptive_section_removes_noninteractive_detection.

    The `--adaptive` flag IS the user consent — no runtime non-interactivity
    probing. Hand-wavy phrases like "if the session appears non-interactive"
    must not reappear.
    """
    body = _read_body(_SCAN_SUBAGENT_FILE).lower()
    forbidden_phrases = [
        "if the session appears non-interactive",
        "session appears non-interactive",
        "appears to be non-interactive",
        "detect non-interactive",
    ]
    for phrase in forbidden_phrases:
        assert phrase not in body, (
            f"screw-scan.md contains forbidden hand-wavy non-interactive-"
            f"detection phrase: `{phrase}`. The `--adaptive` flag IS the "
            f"user consent — do not reintroduce runtime probing."
        )
    assert "--adaptive" in body, "screw-scan.md must mention the --adaptive flag"
    # Must explicitly frame the flag as consent.
    assert (
        "flag is consent" in body
        or "flag is user consent" in body
        or "flag is the user consent" in body
    ), (
        "screw-scan.md must explicitly frame `--adaptive` as the user consent "
        "(no runtime non-interactivity probe)."
    )


def test_screw_scan_body_does_not_reference_sign_adaptive_script() -> None:
    """Migrated from test_adaptive_prompt_does_not_reference_sign_adaptive_script.

    Option D isolation: LLM flow must NEVER reach sign_adaptive_script (the
    direct-path tool). Use stage + promote instead (spec §3.2). C1 closure
    in PR #14 retired sign_adaptive_script entirely; this guard is a
    regression watchdog.
    """
    full = _read_full(_SCAN_SUBAGENT_FILE)
    assert "sign_adaptive_script" not in full, (
        "screw-scan.md references sign_adaptive_script — LLM-flow isolation "
        "regressed. Use stage + promote instead (spec §3.2)."
    )


def test_screw_scan_body_contains_must_import_only_phrase() -> None:
    """Migrated from test_adaptive_prompt_contains_must_import_only_phrase.

    I5: prompt enforces the allowlist loudly. Case-sensitive — the uppercase
    form is the intentional hardening signal.
    """
    full = _read_full(_SCAN_SUBAGENT_FILE)
    assert "MUST import ONLY" in full, (
        "screw-scan.md missing 'MUST import ONLY' hardening phrase (I5)."
    )


def test_screw_scan_body_lists_all_adaptive_exports() -> None:
    """Migrated from test_adaptive_prompt_lists_all_adaptive_exports.

    I5: every name in adaptive.__all__ must appear in the generation prompt.
    Auto-tracks any additions so the prompt stays in sync with the public
    surface.
    """
    from screw_agents import adaptive as adaptive_pkg

    full = _read_full(_SCAN_SUBAGENT_FILE)
    for name in adaptive_pkg.__all__:
        assert name in full, (
            f"screw-scan.md missing adaptive.__all__ entry {name!r} in prompt (I5)."
        )


def test_screw_scan_body_contains_negative_examples_block() -> None:
    """Migrated from test_adaptive_prompt_contains_negative_examples_block.

    I5: negative examples mention common hallucinated names so the LLM sees
    canonical don't-invent-these examples.
    """
    full = _read_full(_SCAN_SUBAGENT_FILE)
    assert "DO NOT invent helper names" in full, (
        "screw-scan.md missing negative-examples header phrase (I5)."
    )
    for hallucinated in ("read_source", "parse_module", "walk_module"):
        assert hallucinated in full, (
            f"screw-scan.md missing hallucinated name example {hallucinated!r} (I5)."
        )


def test_screw_scan_body_instructs_fenced_json_return() -> None:
    """Migrated from test_per_agent_files_instruct_fenced_json_return.

    The subagent ends its turn with a fenced JSON code block per spec §5.1.
    The instruction must be discoverable in the prompt.
    """
    full = _read_full(_SCAN_SUBAGENT_FILE)
    assert "pending_reviews" in full, (
        "screw-scan.md missing pending_reviews reference — structured return "
        "schema (spec §5.1) not discoverable."
    )
    assert "scan_subagent" in full, "screw-scan.md missing scan_subagent reference."
    assert (
        "fenced JSON" in full
        or "fenced json" in full.lower()
        or "```json" in full
    ), "screw-scan.md missing instruction to emit fenced JSON return block."


def test_skill_md_references_screw_scan_only() -> None:
    """SKILL.md references the universal screw-scan subagent, not the deleted per-agent ones.

    Regression guard: a bad merge could re-introduce deleted subagent names into SKILL.md
    without breaking any other test. This test locks the post-Task-7 references.
    """
    skill_path = (
        Path(__file__).parents[1]
        / "plugins"
        / "screw"
        / "skills"
        / "screw-review"
        / "SKILL.md"
    )
    body = skill_path.read_text(encoding="utf-8")

    assert "screw-scan" in body, (
        "SKILL.md must reference the universal screw-scan subagent"
    )
    for retired in ("screw-sqli", "screw-cmdi", "screw-ssti", "screw-xss", "screw-injection"):
        assert retired not in body, (
            f"SKILL.md must not reference deleted subagent {retired!r}"
        )
