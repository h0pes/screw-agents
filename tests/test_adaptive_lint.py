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


def test_lint_rejects_nested_import():
    """Nested `import subprocess` inside analyze must be rejected — was the
    most damaging Layer 1 escape per security review (PR #4 exit criteria
    require socket/subprocess attempts to fail at lint OR sandbox)."""
    script = (
        "from screw_agents.adaptive import ProjectRoot\n"
        "def analyze(project):\n"
        "    import subprocess\n"
        "    subprocess.run(['echo', 'pwned'])\n"
    )
    report = lint_script(script)
    assert report.passed is False
    assert any("subprocess" in v.message and v.rule == "disallowed_import"
               for v in report.violations)


def test_lint_rejects_nested_importfrom():
    """`from os import system` inside analyze must be rejected (same gap as
    above, ImportFrom variant)."""
    script = (
        "from screw_agents.adaptive import ProjectRoot\n"
        "def analyze(project):\n"
        "    from os import system\n"
        "    system('id')\n"
    )
    report = lint_script(script)
    assert report.passed is False
    assert any(v.rule == "disallowed_import" and "os" in v.message
               for v in report.violations)


def test_lint_rejects_nested_import_in_branch():
    """Nested import inside conditional branches still rejected."""
    script = (
        "from screw_agents.adaptive import ProjectRoot\n"
        "def analyze(project):\n"
        "    if True:\n"
        "        import socket\n"
    )
    report = lint_script(script)
    assert report.passed is False
    assert any(v.rule == "disallowed_import" for v in report.violations)


def test_lint_rejects_class_definition():
    """`class C: ...` anywhere is forbidden — class bodies enable the
    custom-__getattribute__ escape that bypasses dunder checks on the AST."""
    script = (
        "from screw_agents.adaptive import ProjectRoot\n"
        "def analyze(project):\n"
        "    class Sneaky:\n"
        "        def __getattribute__(self, name):\n"
        "            return type.__call__\n"
    )
    report = lint_script(script)
    assert report.passed is False
    assert any(v.rule == "forbidden_classdef" for v in report.violations)


def test_lint_rejects_breakpoint():
    """breakpoint() launches pdb (or PYTHONBREAKPOINT-configured callable) — escape vector."""
    script = (
        "from screw_agents.adaptive import ProjectRoot\n"
        "def analyze(project):\n"
        "    breakpoint()\n"
    )
    report = lint_script(script)
    assert report.passed is False
    assert any("breakpoint" in v.message for v in report.violations)


def test_lint_rejects_help():
    """help() opens a pager which under some configurations forks less/more."""
    script = (
        "from screw_agents.adaptive import ProjectRoot\n"
        "def analyze(project):\n"
        "    help('os.system')\n"
    )
    report = lint_script(script)
    assert report.passed is False
    assert any("help" in v.message for v in report.violations)


def test_lint_rejects_super():
    """super() reaches object dunders if a class slips through — defense in depth."""
    script = (
        "from screw_agents.adaptive import ProjectRoot\n"
        "def analyze(project):\n"
        "    super().__init__()\n"
    )
    report = lint_script(script)
    assert report.passed is False
    assert any("super" in v.message for v in report.violations)


def test_lint_rejects_dunder_name_lookup():
    """`__builtins__` (Name lookup, not Attribute access) must be flagged
    via the blanket dunder-name rule. Same for __import__, etc."""
    script = (
        "from screw_agents.adaptive import ProjectRoot\n"
        "def analyze(project):\n"
        "    x = __builtins__\n"
    )
    report = lint_script(script)
    assert report.passed is False
    assert any(v.rule == "forbidden_dunder_name" and "__builtins__" in v.message
               for v in report.violations)


def test_lint_rejects_arbitrary_dunder_attribute():
    """Blanket dunder-attribute rule catches ANY __x__ access, not just the
    handful that were on the previous _FORBIDDEN_DUNDERS list. e.g. obj.__dict__."""
    script = (
        "from screw_agents.adaptive import ProjectRoot\n"
        "def analyze(project):\n"
        "    x = project.__dict__\n"
    )
    report = lint_script(script)
    assert report.passed is False
    assert any(v.rule == "forbidden_dunder_attr" and "__dict__" in v.message
               for v in report.violations)


def test_lint_rejects_getattribute_method_call():
    """obj.__getattribute__('x') is a dunder attribute access — caught
    by blanket rule even though it's a 'method' not a typical dunder."""
    script = (
        "from screw_agents.adaptive import ProjectRoot\n"
        "def analyze(project):\n"
        "    x = project.__getattribute__('something')\n"
    )
    report = lint_script(script)
    assert report.passed is False
    assert any(v.rule == "forbidden_dunder_attr" and "__getattribute__" in v.message
               for v in report.violations)


def test_lint_rejects_global_statement():
    """`global x` reaches module-level namespace; combined with nested imports
    enables more flexible escape patterns."""
    script = (
        "from screw_agents.adaptive import ProjectRoot\n"
        "def analyze(project):\n"
        "    global x\n"
        "    x = 1\n"
    )
    report = lint_script(script)
    assert report.passed is False
    assert any(v.rule == "forbidden_global" for v in report.violations)


def test_lint_rejects_yield_in_analyze():
    """yield turns analyze into a generator → executor never iterates → silent
    no-op (no findings emitted). Behavioral footgun caught at lint time."""
    script = (
        "from screw_agents.adaptive import ProjectRoot\n"
        "def analyze(project):\n"
        "    yield 1\n"
    )
    report = lint_script(script)
    assert report.passed is False
    assert any(v.rule == "forbidden_yield" for v in report.violations)


def test_lint_rejects_exception_group_construction():
    """try/except* is blocked, but `raise ExceptionGroup(...)` constructs
    the same class directly — close the loop."""
    script = (
        "from screw_agents.adaptive import ProjectRoot\n"
        "def analyze(project):\n"
        "    raise ExceptionGroup('x', [Exception()])\n"
    )
    report = lint_script(script)
    assert report.passed is False
    assert any("ExceptionGroup" in v.message for v in report.violations)
