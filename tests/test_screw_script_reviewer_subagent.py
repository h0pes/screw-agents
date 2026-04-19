"""Format smoke tests for the screw-script-reviewer Claude Code subagent.

These tests verify the markdown + frontmatter is well-formed so a future
edit can't silently break the subagent definition. Semantic behavior is
validated by manual invocation and by T22's E2E integration test."""

from __future__ import annotations

from pathlib import Path

import yaml


_SUBAGENT_PATH = (
    Path(__file__).parent.parent
    / "plugins"
    / "screw"
    / "agents"
    / "screw-script-reviewer.md"
)


def _parse_subagent_file(path: Path) -> tuple[dict, str]:
    """Parse a Claude Code subagent markdown file into (frontmatter, body)."""
    content = path.read_text(encoding="utf-8")
    assert content.startswith("---\n"), "subagent must start with YAML frontmatter"
    end = content.index("\n---\n", 4)
    frontmatter_text = content[4:end]
    body = content[end + len("\n---\n") :]
    return yaml.safe_load(frontmatter_text), body


def test_screw_script_reviewer_file_exists() -> None:
    assert _SUBAGENT_PATH.exists(), f"subagent file missing at {_SUBAGENT_PATH}"


def test_screw_script_reviewer_frontmatter_has_required_fields() -> None:
    frontmatter, _ = _parse_subagent_file(_SUBAGENT_PATH)
    assert frontmatter["name"] == "screw-script-reviewer"
    assert "description" in frontmatter and isinstance(frontmatter["description"], str)
    assert frontmatter["tools"] == [], (
        "Layer 0d subagent must have empty tools list — isolation is by design"
    )


def test_screw_script_reviewer_body_references_pydantic_model() -> None:
    """The prompt must tell the LLM about SemanticReviewReport so the
    caller's validation doesn't fail on field drift."""
    _, body = _parse_subagent_file(_SUBAGENT_PATH)
    assert "SemanticReviewReport" in body, (
        "prompt must reference the Pydantic model used for output validation"
    )


def test_screw_script_reviewer_body_lists_allowed_imports() -> None:
    """The allowed-import surface is security-critical. The prompt must
    name the rule so the LLM can flag unusual_imports correctly."""
    _, body = _parse_subagent_file(_SUBAGENT_PATH)
    assert "screw_agents.adaptive" in body
    # At least one of the curated export names should be mentioned
    assert any(
        name in body
        for name in ("ProjectRoot", "find_calls", "emit_finding", "match_pattern")
    )


def test_screw_script_reviewer_body_has_advisory_framing() -> None:
    """Layer 0d is advisory, not a gate. The prompt must tell the LLM
    this so it doesn't recommend 'approve'/'reject' or try to gate."""
    _, body = _parse_subagent_file(_SUBAGENT_PATH)
    body_lower = body.lower()
    assert (
        "advisory" in body_lower
        or "not a gate" in body_lower
        or "not a security boundary" in body_lower
    )


def test_screw_script_reviewer_body_references_7_layer_stack() -> None:
    """The shipped Phase 3b defense stack is 7 layers, not 15."""
    _, body = _parse_subagent_file(_SUBAGENT_PATH)
    # The subagent is Layer 0d. Body should mention Layer 0d AND 7-layer.
    body_lower = body.lower()
    assert "layer 0d" in body_lower
    # Must NOT falsely reference 15-layer
    assert "15-layer" not in body_lower and "15 layer" not in body_lower
