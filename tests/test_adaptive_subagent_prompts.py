"""Format smoke tests for the `--adaptive` prompt surface — scan.md scope.

T-SCAN-REFACTOR Task 7 (this file's current scope): the per-agent and
orchestrator subagent assertions migrated to `tests/test_screw_scan_subagent.py`
when the 5 deleted subagent files (sqli, cmdi, ssti, xss, injection) collapsed
into the universal `screw-scan.md` subagent.

What stays here: scan.md / main-session orchestrator assertions. These test
the slash-command-side parser/orchestrator behavior — Task 8 will REWRITE
scan.md (multi-scope syntax + new parser + summary line) and at that point
the assertions in this file will be updated. Through Task 7 they MUST keep
passing because the universal subagent's hybrid return schema (E2=C)
preserves every C2 contract key the parser reads (lines 80-94 below).

Post-C2 (Phase 3b-C2 Nested Subagent Dispatch Fix): post-generation flow
(reviewer dispatch, staging, 5-section review, approve/reject,
promote/execute/accumulate) lives in scan.md's main-session prompt — NOT in
scan subagents. These tests lock the tool surface that scan.md must declare
+ instruct.

Runtime dispatch correctness is validated by the live round-trip protocol in
spec §8 — NOT by this file.
"""

from __future__ import annotations

from pathlib import Path

import yaml


_REPO_ROOT = Path(__file__).parent.parent
_AGENTS_DIR = _REPO_ROOT / "plugins" / "screw" / "agents"
_COMMANDS_DIR = _REPO_ROOT / "plugins" / "screw" / "commands"

_SCAN_COMMAND_FILE = _COMMANDS_DIR / "scan.md"

# Tools required on scan.md (main session orchestrator) — main session owns
# the post-generation MCP surface (stage/promote/reject/execute) plus
# accumulate_findings + finalize (two-phase persist) + list_domains for the
# `full` scope branch.
#
# T-SCAN-REFACTOR Task 8 plan-fix Edit 3: post-rewrite the body now also
# invokes scan_agents (init-page call from main session per E2=A),
# resolve_scope (new MCP tool replacing shell-out per E1=A), and
# verify_trust (per-review trust re-check per spec §4.7 D7).
_ADAPTIVE_MCP_TOOLS_REQUIRED_ON_SCAN_MD = [
    "mcp__screw-agents__stage_adaptive_script",
    "mcp__screw-agents__promote_staged_script",
    "mcp__screw-agents__reject_staged_script",
    "mcp__screw-agents__execute_adaptive_script",
    "mcp__screw-agents__accumulate_findings",
    "mcp__screw-agents__finalize_scan_results",
    "mcp__screw-agents__list_domains",
    "mcp__screw-agents__scan_agents",
    "mcp__screw-agents__resolve_scope",
    "mcp__screw-agents__verify_trust",
]


def _parse_subagent_file(path: Path) -> tuple[dict, str]:
    """Parse a Claude Code subagent/command markdown file into (frontmatter, body)."""
    content = path.read_text(encoding="utf-8")
    assert content.startswith("---\n"), f"{path.name} must start with YAML frontmatter"
    end = content.index("\n---\n", 4)
    frontmatter_text = content[4:end]
    body = content[end + len("\n---\n") :]
    return yaml.safe_load(frontmatter_text), body


# ---- scan.md documents --adaptive flag --------------------------------------


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


# ---- C2: scan.md main-session orchestrator assertions ----------------------


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
    (C2-new for HIGH-risk UX friction), confirm-stale, confirm-<8hex>, reject.

    Uses word-boundary matching so `approve` doesn't match `disapprove` and
    `reject` doesn't match `rejection`. For `confirm-` family: `\\bconfirm-\\b`
    matches any `confirm-<wordchar...>` form (e.g., `confirm-high`,
    `confirm-stale`, `confirm-a…` hex) — the trailing `\\b` matches the
    non-word→word transition between `-` and the first char of the suffix.
    """
    import re
    _, body = _parse_subagent_file(_SCAN_COMMAND_FILE)
    required_phrases = [
        "approve",
        "reject",
        "confirm-high",
        "confirm-stale",
        "confirm-",
    ]
    for phrase in required_phrases:
        assert re.search(rf"\b{re.escape(phrase)}\b", body), (
            f"scan.md missing approval phrase token: `{phrase}` "
            f"(word-boundary match)"
        )


def test_scan_md_contains_subagent_return_schema_keys() -> None:
    """Post-C2: scan.md parses scan-subagent fenced JSON return. The schema's
    top-level keys (from spec §5.1) must be visible in scan.md so the
    orchestrator knows what to parse.

    These keys are also asserted on the universal subagent's body in
    `tests/test_screw_scan_subagent.py::test_screw_scan_return_schema_includes_c2_contract_keys`
    so the contract holds at both ends.

    T-SCAN-REFACTOR Task 8 plan-fix Edit 3: post-rewrite, scan.md must
    additionally document the Task-7 hybrid-schema enrichment keys
    (`schema_version`, `yaml_findings_accumulated`, `adaptive_mode_engaged`,
    plus `summary_counts`, `classification_summary`,
    `agents_excluded_by_relevance`, `context_required_matches_recorded`,
    `exclusions_applied_count`) so the orchestrator surfaces them.
    """
    _, body = _parse_subagent_file(_SCAN_COMMAND_FILE)
    required_keys = [
        # C2 contract keys
        "schema_version",
        "scan_subagent",
        "session_id",
        "trust_status",
        "yaml_findings_accumulated",
        "adaptive_mode_engaged",
        "pending_reviews",
        "scan_metadata",
        # Task-7 hybrid-schema enrichment keys
        "summary_counts",
        "classification_summary",
        "agents_excluded_by_relevance",
        "context_required_matches_recorded",
        "exclusions_applied_count",
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


def test_scan_md_contains_full_scope_list_domains_branch() -> None:
    """Post-C2 Option A: scan.md's `full` branch dispatches domain
    orchestrators via list_domains (no more screw-full-review). The branch
    must reference list_domains; the `list_domains` assertion alone
    covers the full-scope branch (the MCP tool is only invoked there)."""
    _, body = _parse_subagent_file(_SCAN_COMMAND_FILE)
    assert "list_domains" in body, (
        "scan.md missing list_domains reference (full scope branch)"
    )


def test_scan_md_verifies_trust_before_promote() -> None:
    """Post-C2 spec §4.7 D7 (per-review trust re-check): main session calls
    `verify_trust` AFTER stage and BEFORE compose-review. Non-zero quarantine
    counts surface a loud banner before the user sees the 5-section review.

    This is advisory-loud, NOT fail-closed — promote_staged_script remains
    the cryptographic gate via its internal tamper_detected check
    (engine.py:509-588). verify_trust reports ENVIRONMENT state
    (script_quarantine_count, exclusion_quarantine_count); promote's check
    validates THIS SPECIFIC staged script. The two are complementary.

    This assertion locks the ordering invariant: first `verify_trust` reference
    in scan.md MUST precede the last `promote_staged_script` reference — so the
    main-session LLM cannot skip the per-review environmental advisory.
    """
    _, body = _parse_subagent_file(_SCAN_COMMAND_FILE)
    assert "verify_trust" in body, (
        "scan.md missing verify_trust reference — spec §4.7 D7: main session "
        "must call verify_trust between stage and promote for per-review "
        "environmental trust advisory "
        "(security: per-review environment visibility; promote's "
        "tamper_detected is the cryptographic gate)"
    )
    # Ordering smoke: first verify_trust mention must precede the LAST
    # promote_staged_script mention. Not a strict proof of correct sequencing
    # (T10 live round-trip validates runtime order), but catches the gross
    # case where verify_trust is only documented after promote.
    first_verify = body.find("verify_trust")
    last_promote = body.rfind("promote_staged_script")
    assert first_verify >= 0 and last_promote >= 0, (
        "scan.md must reference both verify_trust and promote_staged_script"
    )
    assert first_verify < last_promote, (
        "scan.md's first verify_trust reference comes AFTER the last "
        "promote_staged_script reference — ordering suggests verify_trust "
        "isn't instructed before promote (spec §4.7 D7 violated)"
    )
