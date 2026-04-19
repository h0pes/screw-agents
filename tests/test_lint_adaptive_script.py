"""Tests for ``ScanEngine.lint_adaptive_script`` — Phase 3b T18a.

Thin engine-level wrapper over ``screw_agents.adaptive.lint.lint_script``.
Full behavior of the underlying allowlist walk is covered in
``test_adaptive_lint.py``; these tests pin only the MCP-tool contract:

- Clean script → ``status="pass"``, empty violations list.
- Disallowed import → ``status="fail"`` with violation entries.
- Forbidden builtin (``exec``) → ``status="fail"`` with violations.
- Non-parseable source → ``status="syntax_error"`` with details (not
  the generic ``fail`` status, since syntax and allowlist violations
  are distinct failure classes for the reviewer).
- Dispatcher smoke test via ``server._dispatch_tool``.
"""

from __future__ import annotations


_CLEAN_SOURCE = (
    "from screw_agents.adaptive import emit_finding\n"
    "def analyze(project):\n"
    "    pass\n"
)


class TestLintAdaptiveScript:
    """Phase 3b T18a: lint_adaptive_script pre-approval review tool."""

    def test_lint_clean_script_passes(self) -> None:
        """Valid adaptive script (allowed imports, has analyze) → pass."""
        from screw_agents.engine import ScanEngine

        engine = ScanEngine.from_defaults()
        result = engine.lint_adaptive_script(source=_CLEAN_SOURCE)

        assert result["status"] == "pass"
        assert result["violations"] == []

    def test_lint_rejects_disallowed_import(self) -> None:
        """`import requests` at top level violates the allowlist."""
        from screw_agents.engine import ScanEngine

        engine = ScanEngine.from_defaults()
        source = (
            "import requests\n"
            "from screw_agents.adaptive import emit_finding\n"
            "def analyze(project):\n"
            "    pass\n"
        )
        result = engine.lint_adaptive_script(source=source)

        assert result["status"] == "fail"
        assert len(result["violations"]) >= 1
        rules = {v["rule"] for v in result["violations"]}
        assert "disallowed_import" in rules
        # Every violation dict carries the 3-field contract.
        for v in result["violations"]:
            assert "rule" in v
            assert "message" in v
            assert "line" in v

    def test_lint_rejects_forbidden_name(self) -> None:
        """`exec(...)` inside analyze is a forbidden builtin name lookup."""
        from screw_agents.engine import ScanEngine

        engine = ScanEngine.from_defaults()
        source = (
            "from screw_agents.adaptive import emit_finding\n"
            "def analyze(project):\n"
            "    exec('1 + 1')\n"
        )
        result = engine.lint_adaptive_script(source=source)

        assert result["status"] == "fail"
        rules = {v["rule"] for v in result["violations"]}
        assert "forbidden_name" in rules
        # At least one violation mentions `exec`.
        messages = [v["message"] for v in result["violations"]]
        assert any("exec" in m for m in messages)

    def test_lint_syntax_error_returns_syntax_error_status(self) -> None:
        """Unparseable Python → status="syntax_error", details non-empty.

        Distinct from status="fail" because syntax errors and allowlist
        violations are different failure classes for the human reviewer
        (fix-the-python vs fix-the-dependency-graph).
        """
        from screw_agents.engine import ScanEngine

        engine = ScanEngine.from_defaults()
        # Unclosed function body / stray characters — guaranteed parse fail.
        bad_source = "def analyze(project:\n    this isn't python\n"
        result = engine.lint_adaptive_script(source=bad_source)

        assert result["status"] == "syntax_error"
        assert "details" in result
        assert len(result["details"]) > 0
        # Must NOT leak a violations list in the syntax-error branch.
        assert "violations" not in result

    def test_lint_via_dispatcher_smoke(self) -> None:
        """End-to-end: invoke through server._dispatch_tool. Confirms the
        tool registration + schema wiring is intact."""
        from screw_agents.engine import ScanEngine
        from screw_agents.server import _dispatch_tool

        engine = ScanEngine.from_defaults()
        result = _dispatch_tool(
            engine,
            "lint_adaptive_script",
            {"source": _CLEAN_SOURCE},
        )

        assert result["status"] == "pass"
        # Confirm registration via engine.list_tool_definitions too.
        tool_names = {t["name"] for t in engine.list_tool_definitions()}
        assert "lint_adaptive_script" in tool_names
