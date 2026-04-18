"""Unit tests for screw_agents.adaptive.lint — AST allowlist (Layer 1).

Every forbidden construct gets its own test. These tests ARE the security boundary
— if one of them passes when the lint should reject, that's a Layer 1 escape.
"""

from __future__ import annotations

import pytest

from screw_agents.adaptive.lint import LintError, LintReport, lint_script


def _valid_script() -> str:
    return (
        "from screw_agents.adaptive import ProjectRoot, find_calls, emit_finding\n"
        "\n"
        "def analyze(project: ProjectRoot) -> None:\n"
        "    for call in find_calls(project, 'db.execute'):\n"
        "        emit_finding(\n"
        "            cwe='CWE-89',\n"
        "            file=call.file,\n"
        "            line=call.line,\n"
        "            message='test',\n"
        "            severity='high',\n"
        "        )\n"
    )


def test_lint_accepts_valid_script():
    report = lint_script(_valid_script())
    assert report.passed is True
    assert report.violations == []


def test_lint_rejects_disallowed_import():
    script = "import subprocess\ndef analyze(project):\n    pass\n"
    report = lint_script(script)
    assert report.passed is False
    assert any("subprocess" in v.message for v in report.violations)


def test_lint_rejects_import_os():
    script = "import os\ndef analyze(project):\n    pass\n"
    report = lint_script(script)
    assert report.passed is False


def test_lint_rejects_eval():
    script = "def analyze(project):\n    eval('1+1')\n"
    report = lint_script(script)
    assert report.passed is False
    assert any("eval" in v.message for v in report.violations)


def test_lint_rejects_exec():
    script = "def analyze(project):\n    exec('pass')\n"
    report = lint_script(script)
    assert report.passed is False


def test_lint_rejects_compile():
    script = "def analyze(project):\n    compile('1', '<s>', 'eval')\n"
    report = lint_script(script)
    assert report.passed is False


def test_lint_rejects_getattr_with_non_literal():
    script = "def analyze(project):\n    getattr(x, 'ev' + 'al')\n"
    report = lint_script(script)
    assert report.passed is False
    assert any("getattr" in v.message for v in report.violations)


def test_lint_rejects_dunder_access():
    script = "def analyze(project):\n    x.__class__.__bases__\n"
    report = lint_script(script)
    assert report.passed is False


def test_lint_rejects_raw_open():
    script = "def analyze(project):\n    open('/etc/passwd')\n"
    report = lint_script(script)
    assert report.passed is False


def test_lint_rejects_module_level_code():
    """Only `from screw_agents.adaptive import ...` and `def analyze` are allowed at module level."""
    script = (
        "from screw_agents.adaptive import ProjectRoot\n"
        "x = 1\n"  # module-level statement is forbidden
        "def analyze(project):\n    pass\n"
    )
    report = lint_script(script)
    assert report.passed is False
    assert any("top-level" in v.message.lower() for v in report.violations)


def test_lint_rejects_missing_analyze_function():
    script = "from screw_agents.adaptive import ProjectRoot\n"
    report = lint_script(script)
    assert report.passed is False
    assert any("analyze" in v.message for v in report.violations)


def test_lint_rejects_async_def():
    script = (
        "from screw_agents.adaptive import ProjectRoot\n"
        "async def analyze(project):\n    pass\n"
    )
    report = lint_script(script)
    assert report.passed is False


def test_lint_rejects_try_except_star():
    """CVE-2025-22153 used try/except* to escape RestrictedPython. Defense in depth."""
    script = (
        "from screw_agents.adaptive import ProjectRoot\n"
        "def analyze(project):\n"
        "    try:\n"
        "        pass\n"
        "    except* Exception:\n"
        "        pass\n"
    )
    report = lint_script(script)
    assert report.passed is False
    assert any("except*" in v.message or "exception group" in v.message.lower()
               for v in report.violations)
