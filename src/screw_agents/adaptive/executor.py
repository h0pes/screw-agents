"""End-to-end executor for adaptive analysis scripts.

Orchestrates the full defense-in-depth pipeline for a single script:

1. Layer 1: AST allowlist lint on the user's script source
2. Layer 2: SHA-256 hash pin verification against meta.sha256
3. Layer 3: Ed25519 signature verification against config.script_reviewers
4. Stale check: verify target_patterns still exist in the codebase
5. Wrap user script with entry-point template (analyze + flush)
6. Layer 5+6: launch wrapped script under sandbox (bwrap on Linux, sandbox-exec
   on macOS) with wall-clock kill; script path is in an opaque mkdtemp
   directory to close the T8-deferred /proc/1/cmdline path-leak vector
7. Layer 7: JSON schema validation of emitted findings + lift into Finding
   objects

Any layer failure raises a specific exception or returns an AdaptiveScriptResult
with stale=True. The executor is the single choke point for script execution —
no other code path bypasses these layers.
"""

from __future__ import annotations

import datetime
import hashlib
import json
import shutil
import tempfile
from pathlib import Path
from time import monotonic

import yaml

from screw_agents.adaptive.ast_walker import find_calls
from screw_agents.adaptive.lint import LintReport, lint_script
from screw_agents.adaptive.project import ProjectRoot
from screw_agents.adaptive.sandbox import run_in_sandbox
from screw_agents.cwe_names import long_name as cwe_long_name
from screw_agents.models import (
    AdaptiveScriptMeta,
    AdaptiveScriptResult,
    Finding,
    FindingAnalysis,
    FindingClassification,
    FindingLocation,
    FindingRemediation,
    FindingTriage,
    SandboxResult,
)
from screw_agents.trust import load_config, verify_script


class LintFailure(RuntimeError):
    """Raised when a script fails AST lint (Layer 1)."""

    def __init__(self, report: LintReport):
        self.report = report
        super().__init__(
            f"script failed lint: {len(report.violations)} violations"
        )


class HashMismatch(RuntimeError):
    """Raised when a script's SHA-256 does not match its metadata (Layer 2)."""


class SignatureFailure(RuntimeError):
    """Raised when a script's signature verification fails (Layer 3)."""


# Entry-point template appended to the user's script inside the sandbox.
# This is trusted executor output — NOT subject to Layer 1 lint (which only
# inspects the user's script source). The `if True:` block avoids __name__
# dependency and keeps the invocation tightly scoped.
#
# SAFETY INVARIANT: this template's injection-safety depends on Layer 1 lint
# catching malformed user scripts (unclosed strings, trailing backslashes,
# unindented def bodies) as SyntaxError BEFORE the template is appended.
# Python's ast.parse raises SyntaxError which the lint returns as a
# rule="syntax" violation → LintFailure is raised in execute_script BEFORE
# the template is written. If lint_script is ever weakened to tolerate
# syntax errors (e.g., "warn only"), the template becomes an injection
# surface — re-audit.
_ENTRY_POINT_TEMPLATE = """

# --- executor-injected entry-point template (post-lint; trusted) ---
if True:
    import os as __screw_os  # noqa
    from pathlib import Path as __screw_Path  # noqa
    from screw_agents.adaptive.project import ProjectRoot as __screw_ProjectRoot  # noqa
    from screw_agents.adaptive.findings import flush_to_path as __screw_flush  # noqa
    __screw_project = __screw_ProjectRoot(__screw_Path(__screw_os.environ["SCREW_PROJECT_ROOT"]))
    analyze(__screw_project)
    __screw_flush(__screw_os.environ["SCREW_FINDINGS_PATH"])
"""


def execute_script(
    *,
    script_path: Path,
    meta_path: Path,
    project_root: Path,
    wall_clock_s: int = 30,
    skip_trust_checks: bool = False,
) -> AdaptiveScriptResult:
    """Run an adaptive script through the full defense pipeline.

    Args:
        script_path: path to the .py file to execute.
        meta_path: path to the .meta.yaml metadata file.
        project_root: path to the target project the script will analyze.
        wall_clock_s: parent-side kill timer for the sandbox.
        skip_trust_checks: if True, bypass hash + signature verification.
            USED BY TESTS ONLY. Production callers must never set True.

    Returns:
        AdaptiveScriptResult with script_name, findings, sandbox_result,
        stale flag, and execution_time_ms.

    Raises:
        LintFailure: Layer 1 rejected the user's script.
        HashMismatch: Layer 2 computed SHA-256 != meta.sha256.
        SignatureFailure: Layer 3 signature verification failed.
    """
    start = monotonic()

    # Layer 1: AST lint on the USER's original source (the injection template
    # is executor-trusted and NOT linted)
    script_source = script_path.read_text(encoding="utf-8")
    lint_report = lint_script(script_source)
    if not lint_report.passed:
        raise LintFailure(lint_report)

    meta_raw = yaml.safe_load(meta_path.read_text(encoding="utf-8"))
    meta = AdaptiveScriptMeta(**meta_raw)

    # Layer 2: hash pin (skipped by tests)
    if not skip_trust_checks:
        computed = hashlib.sha256(script_source.encode("utf-8")).hexdigest()
        if computed != meta.sha256:
            raise HashMismatch(
                f"script {script_path.name} hash mismatch: "
                f"expected {meta.sha256}, computed {computed}"
            )

    # Layer 3: signature verification (skipped by tests)
    if not skip_trust_checks:
        config = load_config(project_root)
        ver_result = verify_script(
            source=script_source,
            meta=meta.model_dump(),
            config=config,
        )
        if not ver_result.valid:
            raise SignatureFailure(
                f"script {script_path.name} signature verification failed: "
                f"{ver_result.reason}"
            )

    # Stale check: if ANY target_pattern is missing from the codebase, skip
    # execution (the script targets a pattern that no longer exists).
    if _is_stale(meta, project_root):
        return AdaptiveScriptResult(
            script_name=meta.name,
            findings=[],
            sandbox_result=_sentinel_sandbox_result(),
            stale=True,
            execution_time_ms=int((monotonic() - start) * 1000),
        )

    # Wrap the user script with the entry-point template so analyze() gets
    # called and findings get flushed. Place the wrapped file in an OPAQUE
    # mkdtemp directory (prefix="screw_") to close the T8-deferred path-leak
    # vector — the bwrap argv embeds this path and is visible to the script
    # via /proc/1/cmdline. Opaque path prevents the script from learning
    # the user's `.screw/custom-scripts/<name>.py` naming convention.
    wrapped_source = script_source + _ENTRY_POINT_TEMPLATE
    opaque_script_dir = Path(tempfile.mkdtemp(prefix="screw_"))
    try:
        opaque_script_path = opaque_script_dir / "screw_adaptive_script.py"
        opaque_script_path.write_text(wrapped_source, encoding="utf-8")

        # Layer 5+6: sandbox launch. findings_path is also a fresh tempdir
        # so the sandbox can't escape via residual findings from prior runs.
        with tempfile.TemporaryDirectory(prefix="screw_findings_") as findings_tmpdir:
            findings_path = Path(findings_tmpdir)
            sandbox_result = run_in_sandbox(
                script_path=opaque_script_path,
                project_root=project_root,
                findings_path=findings_path,
                wall_clock_s=wall_clock_s,
            )
    finally:
        # Clean up the opaque script directory unconditionally
        shutil.rmtree(opaque_script_dir, ignore_errors=True)

    # Layer 7: JSON schema validation + lift flat emit_finding dicts into
    # proper nested Finding objects
    findings = _parse_findings(sandbox_result.findings_json, meta)

    return AdaptiveScriptResult(
        script_name=meta.name,
        findings=findings,
        sandbox_result=sandbox_result,
        stale=False,
        execution_time_ms=int((monotonic() - start) * 1000),
    )


def _is_stale(meta: AdaptiveScriptMeta, project_root: Path) -> bool:
    """Check if any target_patterns from metadata exist in the project.

    Returns True if target_patterns is non-empty AND none of them match any
    call site in the project. Empty target_patterns means "always run" —
    returns False (not stale).
    """
    if not meta.target_patterns:
        return False
    project = ProjectRoot(project_root)
    for pattern in meta.target_patterns:
        if any(True for _ in find_calls(project, pattern)):
            return False  # at least one pattern still present
    return True


def _sentinel_sandbox_result() -> SandboxResult:
    """Placeholder SandboxResult for the stale path — no execution happened."""
    return SandboxResult(
        stdout=b"",
        stderr=b"",
        returncode=0,
        wall_clock_s=0.0,
        killed_by_timeout=False,
        findings_json=None,
    )


def _parse_findings(findings_json: str | None, meta: AdaptiveScriptMeta) -> list[Finding]:
    """Parse the sandbox's findings.json and lift flat emit_finding dicts into
    proper nested Finding objects.

    The emit_finding helper (Task 5) writes flat dicts with keys: cwe, file,
    line, column, message, severity, code_snippet. The Finding model has
    nested structure: location, classification, analysis, remediation, triage.
    The executor is the boundary that lifts flat -> nested, adding executor-
    owned fields: id (content-hash), agent (adaptive_script:<name>), domain
    (from meta), timestamp (now).
    """
    if not findings_json:
        return []

    try:
        raw_entries = json.loads(findings_json)
    except json.JSONDecodeError:
        return []

    if not isinstance(raw_entries, list):
        return []

    findings: list[Finding] = []
    timestamp = datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    agent_label = f"adaptive_script:{meta.name}"

    for entry in raw_entries:
        if not isinstance(entry, dict):
            continue
        try:
            cwe = entry["cwe"]
            finding_id = _compute_finding_id(
                agent=agent_label,
                file=entry["file"],
                line=entry["line"],
                cwe=cwe,
                message=entry["message"],
                column=entry.get("column", 0),
            )
            findings.append(Finding(
                id=finding_id,
                agent=agent_label,
                domain=meta.domain,
                timestamp=timestamp,
                location=FindingLocation(
                    file=entry["file"],
                    line_start=entry["line"],
                    code_snippet=entry.get("code_snippet") or None,
                ),
                classification=FindingClassification(
                    cwe=cwe,
                    cwe_name=cwe_long_name(cwe),
                    # Map adaptive vocab → project Finding vocab.
                    # emit_finding allows {high, medium, low, info}; Finding expects
                    # {critical, high, medium, low}. `info` → `low` per the contract
                    # documented in findings.py's module docstring.
                    severity="low" if entry["severity"] == "info" else entry["severity"],
                    confidence="medium",  # adaptive scripts don't carry confidence; default medium
                ),
                analysis=FindingAnalysis(description=entry["message"]),
                remediation=FindingRemediation(recommendation=""),
                triage=FindingTriage(),
            ))
        except (KeyError, ValueError, TypeError):
            # Malformed entry — drop silently. The sandbox stderr captures
            # the details; the orchestrator returns what it can validate.
            continue

    return findings


def _compute_finding_id(*, agent: str, file: str, line: int, cwe: str, message: str, column: int = 0) -> str:
    """Content-hash-based ID for a Finding. Stable across runs of the same
    script against the same code + column (so duplicate findings across
    scans dedupe naturally via id equality; different-column findings at
    the same line get distinct IDs)."""
    key = f"{agent}|{file}|{line}|{column}|{cwe}|{message}".encode("utf-8")
    return hashlib.sha256(key).hexdigest()[:16]
