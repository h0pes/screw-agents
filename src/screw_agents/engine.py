"""Scan engine — ties registry, resolver, and formatter together.

Assembles detection prompts from agent YAML + resolved code. Does NOT
call Claude — the MCP tool returns the assembled prompt for Claude to
process. Claude then returns structured findings which are passed to
format_findings() for output formatting.
"""

from __future__ import annotations

import base64
import hashlib
import json as _json
import os
import re
from pathlib import Path
from typing import Any

import yaml

from screw_agents.adaptive.executor import execute_script
from screw_agents.adaptive.signing import (
    build_signed_script_meta,
    compute_script_sha256,
)
from screw_agents.aggregation import (
    aggregate_directory_suggestions,
    aggregate_fp_report,
    aggregate_pattern_confidence,
)
from screw_agents.formatter import format_findings
from screw_agents.learning import (
    _get_or_create_local_private_key,
    load_exclusions,
)
from screw_agents.models import AgentDefinition, Exclusion, Finding, HeuristicEntry
from screw_agents.registry import AgentRegistry
from screw_agents.resolver import ResolvedCode, filter_by_relevance, resolve_target
from screw_agents.trust import (
    _find_matching_reviewer,
    _fingerprint_public_key,
    _load_public_keys_with_reviewers,
    load_config,
    verify_script,
)

# Filesystem-safe script name regex: lowercase alphanum + dash, 3-63 chars,
# must start with alphanumeric. Mirrors the safety envelope used elsewhere
# in adaptive scripts — conservative to avoid path traversal / shell
# metacharacters / Windows reserved names when these land on disk.
_SCRIPT_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]{2,62}$")

_DEFAULT_DOMAINS_DIR = Path(__file__).resolve().parent.parent.parent / "domains"


class ScanEngine:
    """Orchestrates scan assembly across registry, resolver, and formatter."""

    def __init__(self, registry: AgentRegistry) -> None:
        self._registry = registry

    @classmethod
    def from_defaults(cls, domains_dir: Path | None = None) -> ScanEngine:
        """Construct a ScanEngine backed by the repo's default domains directory.

        Convenience constructor for tests and callers that don't need to
        override the domains directory. Mirrors the default used by
        ``server.create_server`` so tool behavior matches between MCP
        invocations and direct engine-level tests.

        Args:
            domains_dir: Optional override for the domains directory.
                Defaults to the repo-root ``domains/`` directory.
        """
        if domains_dir is None:
            domains_dir = _DEFAULT_DOMAINS_DIR
        return cls(AgentRegistry(domains_dir))

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def list_domains(self) -> dict[str, int]:
        """Return a mapping of domain names to agent counts."""
        return self._registry.list_domains()

    def list_agents(self, domain: str | None = None) -> list[dict]:
        """Return agent metadata dicts, optionally filtered by domain."""
        return self._registry.list_agents(domain=domain)

    def verify_trust(
        self,
        *,
        project_root: Path,
        exclusions: list[Exclusion] | None = None,
    ) -> dict[str, int]:
        """Compute a summary of trust status for the project's .screw/ content.

        Returns counts of active vs quarantined entries for both exclusions and
        scripts. Exclusion counts come from `learning.load_exclusions` (applies
        signature verification + legacy policy). Script counts iterate
        `.screw/custom-scripts/*.meta.yaml` and run `trust.verify_script` on
        each; malformed metadata, a missing companion .py, or signature
        failure counts as quarantined. Phase 3b PR#4 Task 12 wires in the
        real script counts (previously stubbed to 0).

        The optional `exclusions` parameter lets callers that already have a
        loaded-and-verified list reuse it to avoid a duplicate YAML parse and
        Ed25519 verification pass. `assemble_scan` passes this through to avoid
        paying the load cost twice on every scan invocation. MCP tool callers
        (server.py) omit it and let this function self-load.

        Raises:
            ValueError: Propagated from `learning.load_exclusions` when
                `.screw/learning/exclusions.yaml` is malformed or
                `.screw/config.yaml` is schema-invalid. Callers should
                surface this as a loud trust-relevant error rather than
                degrade to zero counts.
        """
        if exclusions is None:
            exclusions = load_exclusions(project_root)
        exclusion_quarantine_count = sum(1 for e in exclusions if e.quarantined)
        exclusion_active_count = len(exclusions) - exclusion_quarantine_count

        # Phase 3b PR#4 Task 12: count adaptive scripts. Iterate
        # .screw/custom-scripts/*.meta.yaml and run verify_script on each.
        # Missing companion .py, malformed YAML, or signature failure →
        # quarantined. Absent .screw/custom-scripts/ directory → zero counts
        # (graceful). Config load failure also → zero counts (treat as "no
        # reviewer keys configured" rather than a hard error; load_exclusions
        # above already raises loudly on malformed config when it applies).
        script_dir = project_root / ".screw" / "custom-scripts"
        script_active_count = 0
        script_quarantine_count = 0
        if script_dir.exists():
            try:
                config = load_config(project_root)
            except Exception:
                config = None
            if config is not None:
                for meta_file in script_dir.glob("*.meta.yaml"):
                    source_file = (
                        meta_file.parent
                        / f"{meta_file.stem.removesuffix('.meta')}.py"
                    )
                    if not source_file.exists():
                        script_quarantine_count += 1
                        continue
                    try:
                        meta_data = yaml.safe_load(
                            meta_file.read_text(encoding="utf-8")
                        )
                        script_source = source_file.read_text(encoding="utf-8")
                        verification = verify_script(
                            source=script_source,
                            meta=meta_data,
                            config=config,
                        )
                        if verification.valid:
                            script_active_count += 1
                        else:
                            script_quarantine_count += 1
                    except Exception:
                        script_quarantine_count += 1

        return {
            "exclusion_quarantine_count": exclusion_quarantine_count,
            "exclusion_active_count": exclusion_active_count,
            "script_quarantine_count": script_quarantine_count,
            "script_active_count": script_active_count,
        }

    def execute_adaptive_script(
        self,
        *,
        project_root: Path,
        script_name: str,
        wall_clock_s: int = 30,
        skip_trust_checks: bool = False,
    ) -> dict[str, Any]:
        """Execute an adaptive script by name under the full defense pipeline.

        Looks up the script at
        ``.screw/custom-scripts/<script_name>.py`` plus its companion
        ``<script_name>.meta.yaml`` and runs the resulting script through
        ``adaptive.executor.execute_script`` (which applies all 7 defense
        layers: AST lint, SHA-256 pin, Ed25519 signature, stale check,
        sandbox launch, wall-clock kill, JSON-schema validation). Returns
        a JSON-serializable dict suitable for marshaling over MCP.

        Args:
            project_root: Absolute path to the project root. Used both as
                the script lookup base (``.screw/custom-scripts/``) and as
                the sandbox's view of the target codebase.
            script_name: Script basename WITHOUT the ``.py`` extension
                (e.g., ``"querybuilder-sqli-check"``).
            wall_clock_s: Parent-side sandbox kill timer. Defaults to 30s.
            skip_trust_checks: TESTS ONLY — bypasses Layer 2 (hash pin) and
                Layer 3 (signature). Production callers must never set True.

        Returns:
            Dict with keys: ``script_name``, ``findings`` (list of finding
            dicts), ``stale`` (bool), ``execution_time_ms`` (int),
            ``sandbox_result`` (dict, stdout/stderr excluded since they are
            bytes). ``model_dump(mode="json")`` is used so nested datetimes
            and other non-JSON-native types serialize correctly.

        Raises:
            FileNotFoundError: Script source or metadata file missing.
            LintFailure: Layer 1 rejected the script.
            HashMismatch: Layer 2 rejected the script.
            SignatureFailure: Layer 3 rejected the script.
        """
        script_dir = project_root / ".screw" / "custom-scripts"
        script_path = script_dir / f"{script_name}.py"
        meta_path = script_dir / f"{script_name}.meta.yaml"

        if not script_path.exists():
            raise FileNotFoundError(
                f"adaptive script not found: {script_path}"
            )
        if not meta_path.exists():
            raise FileNotFoundError(
                f"adaptive script metadata not found: {meta_path}"
            )

        result = execute_script(
            script_path=script_path,
            meta_path=meta_path,
            project_root=project_root,
            wall_clock_s=wall_clock_s,
            skip_trust_checks=skip_trust_checks,
        )

        return {
            "script_name": result.script_name,
            "findings": [f.model_dump(mode="json") for f in result.findings],
            "stale": result.stale,
            "execution_time_ms": result.execution_time_ms,
            "sandbox_result": result.sandbox_result.model_dump(
                mode="json", exclude={"stdout", "stderr"}
            ),
        }

    def sign_adaptive_script(
        self,
        *,
        project_root: Path,
        script_name: str,
        source: str,
        meta: dict[str, Any],
        session_id: str,
    ) -> dict[str, Any]:
        """Sign a freshly-generated adaptive script and write to disk.

        Called from the approve-path of the adaptive review flow (Phase 3b
        T18a/T18b): the subagent generated a script, the user typed
        ``approve <name>``, and this tool does the atomic persist + sign.
        Fresh-script-only — a name collision is an error, NOT an idempotent
        re-sign. Use ``cli.validate_script.run_validate_script`` for the
        re-sign path on an existing quarantined script.

        Args:
            project_root: Project root with ``.screw/`` directory.
            script_name: Filesystem-safe name
                (regex ``^[a-z0-9][a-z0-9-]{2,62}$``); produces
                ``<name>.py`` + ``<name>.meta.yaml`` in
                ``.screw/custom-scripts/``.
            source: Python source code. Not validated to be syntactically
                valid Python or lint-clean — caller (subagent) is
                responsible for invoking ``lint_adaptive_script`` before
                approval; this tool assumes human review already passed.
            meta: Partial meta dict conforming to AdaptiveScriptMeta minus
                signing fields. Must include ``name``, ``created``,
                ``created_by``, ``domain``; may include ``description``,
                ``target_patterns``. Tool computes ``sha256``, sets
                ``validated=True``, signs, and writes.
            session_id: Scan session the script was generated for. Echoed
                in the response for orchestrator correlation; NOT written
                to disk and NOT used to modify session staging. A future
                commit may persist the association in ``.screw/local/`` —
                plumbing the id through now avoids a follow-on API change.

        Returns:
            Dict with keys:
                - ``status``: ``"signed"`` on success, ``"error"`` on
                  recoverable failure (name collision, missing reviewers,
                  local key not in reviewers, meta schema failure).
                - ``message``: human-readable summary.
                - On ``signed``: also includes ``script_path``,
                  ``meta_path``, ``signed_by``, ``sha256``, ``session_id``.

        Raises:
            ValueError: On filesystem shape errors
                (PermissionError / IsADirectoryError / NotADirectoryError
                while accessing ``.screw/config.yaml`` or writing script
                files), wrapped via the shared T13 I1 discipline.
            RuntimeError: On local key generation failure (permission /
                OS error under ``.screw/local/keys/``).

        Atomic-write contract: both ``.py`` and ``.meta.yaml`` are written
        via tmp file + ``os.replace`` swap. ORDER matters — the source
        file is written FIRST, then the meta. If the meta write fails
        after the source landed, the source file is best-effort unlinked
        to avoid the "script exists but meta missing" partial state that
        Layer 3 verification would fail on the next executor call. The
        reverse failure mode (source write fails) leaves no partial
        state because the tmp file is deleted before any commit.
        """
        # Name validation — reject anything that could turn into path
        # traversal, shell metacharacters, or Windows reserved names
        # when these land on disk.
        if not _SCRIPT_NAME_RE.match(script_name):
            return {
                "status": "error",
                "message": (
                    f"Invalid script name {script_name!r}. Must match "
                    f"regex {_SCRIPT_NAME_RE.pattern!r} "
                    f"(lowercase alphanumeric + dashes, 3-63 chars, "
                    f"starts with alphanumeric)."
                ),
            }

        script_dir = project_root / ".screw" / "custom-scripts"
        script_path = script_dir / f"{script_name}.py"
        meta_path = script_dir / f"{script_name}.meta.yaml"

        # Fresh-script semantics: if EITHER file already exists, refuse.
        # Idempotent re-sign is the validate-script CLI's job, not this
        # tool's — bailing cleanly prevents the subagent accidentally
        # overwriting a user's hand-edited custom script.
        if script_path.exists() or meta_path.exists():
            return {
                "status": "error",
                "message": (
                    f"Script {script_name} already exists at "
                    f"{script_path} or {meta_path}. Refusing to overwrite; "
                    f"use `screw-agents validate-script {script_name}` to "
                    f"re-sign an existing script."
                ),
            }

        # Ensure the target directory exists — a fresh project may not
        # have .screw/custom-scripts/ yet.
        try:
            script_dir.mkdir(parents=True, exist_ok=True)
        except PermissionError as exc:
            raise ValueError(
                f"Cannot create adaptive script directory at {script_dir}: "
                f"permission denied. Original error: {exc}"
            ) from exc
        except OSError as exc:
            raise ValueError(
                f"Cannot create adaptive script directory at {script_dir}: "
                f"filesystem shape error ({type(exc).__name__}). "
                f"Original error: {exc}"
            ) from exc

        # T13 I1 discipline — friendly error wrapping around load_config.
        # Mirrors validate_script.py:229-247.
        try:
            config = load_config(project_root)
        except PermissionError as exc:
            raise ValueError(
                f"Cannot access `.screw/config.yaml` at "
                f"{project_root / '.screw' / 'config.yaml'}: "
                f"permission denied. Check directory permissions or run "
                f"with appropriate user. Original error: {exc}"
            ) from exc
        except OSError as exc:
            raise ValueError(
                f"Cannot access `.screw/config.yaml` at "
                f"{project_root / '.screw' / 'config.yaml'}: filesystem "
                f"shape error ({type(exc).__name__}). The `.screw` path "
                f"or config.yaml may be the wrong type (file vs. "
                f"directory). Original error: {exc}"
            ) from exc

        if not config.script_reviewers:
            return {
                "status": "error",
                "message": (
                    "No script_reviewers configured in .screw/config.yaml. "
                    "Run `screw-agents init-trust --name <name> "
                    "--email <email>` first to register your local "
                    "signing key."
                ),
            }

        # T13 I1 discipline — friendly error wrapping around
        # _get_or_create_local_private_key.
        try:
            priv, _pub_line = _get_or_create_local_private_key(project_root)
        except PermissionError as exc:
            raise RuntimeError(
                f"Cannot create local signing key at "
                f"{project_root / '.screw' / 'local' / 'keys'}: permission "
                f"denied. Check directory permissions. Original: {exc}"
            ) from exc
        except OSError as exc:
            raise RuntimeError(
                f"Failed to create local signing key at "
                f"{project_root / '.screw' / 'local' / 'keys'}: {exc}. "
                f"Check disk space and filesystem state."
            ) from exc

        # Model A fingerprint-based signer identity selection.
        # Matching against config.script_reviewers[0].email is WRONG on
        # multi-reviewer projects (the local key may not be [0]).
        keys_with_reviewers, _dropped = _load_public_keys_with_reviewers(
            config.script_reviewers
        )
        local_fingerprint = _fingerprint_public_key(priv.public_key())
        matching_reviewer = _find_matching_reviewer(
            local_fingerprint, keys_with_reviewers
        )

        if matching_reviewer is None:
            return {
                "status": "error",
                "message": (
                    "Local signing key does not match any registered "
                    "reviewer in script_reviewers. Run "
                    "`screw-agents init-trust` to register this machine's "
                    "key before signing scripts."
                ),
            }

        signer_email = matching_reviewer.email
        current_sha256 = compute_script_sha256(source)

        # Delegate canonicalization + signing to the shared helper so the
        # approve-path and the validate-script CLI produce byte-identical
        # canonical input to the executor's Layer 3 verification.
        try:
            meta_for_persist = build_signed_script_meta(
                meta_raw=meta,
                source=source,
                current_sha256=current_sha256,
                signer_email=signer_email,
                private_key=priv,
            )
        except ValueError as exc:
            return {
                "status": "error",
                "message": (
                    f"Meta dict failed AdaptiveScriptMeta schema: {exc}"
                ),
            }

        # Atomic write, ORDER-SENSITIVE: source file first, then meta.
        # Rationale: if the meta landed first but source failed, the
        # executor's Layer 2 hash pin would never be checked (no source
        # file to hash). If the source lands but meta fails, Layer 2
        # would fail on next executor run — same partial-state bug class.
        # Writing source first + best-effort rollback on meta failure
        # ensures either BOTH files are present and consistent, or
        # NEITHER is (modulo the best-effort rollback itself racing).
        script_tmp = script_dir / f"{script_name}.py.tmp"
        meta_tmp = script_dir / f"{script_name}.meta.yaml.tmp"
        try:
            script_tmp.write_text(source, encoding="utf-8")
            os.replace(script_tmp, script_path)
        except PermissionError as exc:
            if script_tmp.exists():
                try:
                    script_tmp.unlink()
                except OSError:
                    pass
            raise ValueError(
                f"Cannot write script source at {script_path}: "
                f"permission denied. Check directory permissions. "
                f"Original error: {exc}"
            ) from exc

        try:
            meta_tmp.write_text(
                yaml.dump(
                    meta_for_persist,
                    default_flow_style=False,
                    sort_keys=False,
                ),
                encoding="utf-8",
            )
            os.replace(meta_tmp, meta_path)
        except (PermissionError, OSError) as exc:
            # Best-effort rollback: we succeeded writing the script but
            # failed on the meta. Leaving the orphaned .py creates a
            # partial-state bug (Layer 2 would fail on next executor
            # call). Unlink the orphan; if the unlink itself fails,
            # swallow — the user will see both the script and our
            # error message and can clean up manually.
            if meta_tmp.exists():
                try:
                    meta_tmp.unlink()
                except OSError:
                    pass
            try:
                script_path.unlink()
            except OSError:
                pass
            raise ValueError(
                f"Cannot write script metadata at {meta_path}: "
                f"{type(exc).__name__}. Script file at {script_path} was "
                f"rolled back best-effort. Original error: {exc}"
            ) from exc

        return {
            "status": "signed",
            "message": (
                f"Signed adaptive script {script_name} with {signer_email} "
                f"(sha256={current_sha256[:12]}...)."
            ),
            "script_path": str(script_path),
            "meta_path": str(meta_path),
            "signed_by": signer_email,
            "sha256": current_sha256,
            "session_id": session_id,
        }

    def lint_adaptive_script(self, *, source: str) -> dict[str, Any]:
        """Run Layer 1 AST allowlist lint on a script source WITHOUT executing it.

        Called from the pre-approval path of the adaptive review flow: the
        subagent just generated a script and wants to show the human
        reviewer the lint result in the 5-section review BEFORE approval.
        Distinct from the lint that runs inside ``execute_script`` (which
        happens AFTER human approval and would surface failures too late
        for the reviewer to decline).

        The underlying ``screw_agents.adaptive.lint.lint_script`` already
        catches ``SyntaxError`` internally and returns a ``LintReport``
        with a single ``rule="syntax"`` violation. This wrapper promotes
        that single-violation case to a dedicated ``status="syntax_error"``
        response so reviewers can distinguish "this isn't valid Python
        yet" from "this Python is valid but violates the allowlist".

        Args:
            source: Python source code to lint. Not modified.

        Returns:
            Dict with:
                - ``status``: ``"pass"`` | ``"fail"`` | ``"syntax_error"``
                - ``violations`` (when status="fail"): list of dicts with
                  ``rule``, ``message``, ``line`` keys.
                - ``details`` (when status="syntax_error"): str describing
                  the parse error (``"<msg> at line <N>"``).

        No side effects. Pure function. Safe to call any number of times.
        """
        from screw_agents.adaptive.lint import lint_script

        report = lint_script(source)

        if report.passed:
            return {"status": "pass", "violations": []}

        # Promote the single-violation syntax case to status="syntax_error".
        # lint_script returns exactly one violation with rule="syntax" when
        # the source doesn't parse — any other violations are allowlist
        # fails, and parseable-but-disallowed scripts produce at least the
        # structural violations and never a `syntax` rule.
        if (
            len(report.violations) == 1
            and report.violations[0].rule == "syntax"
        ):
            v = report.violations[0]
            return {
                "status": "syntax_error",
                "details": f"{v.message} at line {v.line}",
            }

        return {
            "status": "fail",
            "violations": [
                {"rule": v.rule, "message": v.message, "line": v.line}
                for v in report.violations
            ],
        }

    def aggregate_learning(
        self,
        *,
        project_root: Path,
        report_type: str = "all",
    ) -> dict[str, Any]:
        """Compute learning reports from the project's exclusions database.

        Args:
            project_root: project root directory.
            report_type: one of "all", "pattern_confidence",
                "directory_suggestions", "fp_report".

        Returns:
            Dict containing the requested report sections plus a
            ``trust_status`` key. Sections not requested are omitted
            entirely (not empty — absent). ``"all"`` returns all three
            report sections. ``trust_status`` is ALWAYS present regardless
            of ``report_type`` so callers can surface quarantine counts
            honestly: aggregation silently skips quarantined exclusions,
            so the tool must report how many were skipped. Mirrors the
            scan-response ``trust_status`` contract from PR#1 Task 10.
            The ``trust_status`` dict ALWAYS contains a ``notice_markdown: str``
            key (T21-m2): an empty string when ``exclusion_quarantine_count == 0``,
            or a pre-rendered Markdown block when > 0 that the subagent outputs
            verbatim. Prevents cross-model-version paraphrasing drift observed
            in PR#2 round-trip testing.

        Raises:
            ValueError: If `report_type` is not a recognised value, OR
                propagated from `learning.load_exclusions` when
                `.screw/learning/exclusions.yaml` is malformed or
                `.screw/config.yaml` is schema-invalid. Callers should
                surface trust-relevant errors loudly rather than degrade
                to empty reports.
        """
        valid_report_types = ("all", "pattern_confidence", "directory_suggestions", "fp_report")
        if report_type not in valid_report_types:
            raise ValueError(
                f"Unknown report_type: {report_type!r}. "
                f"Must be one of {valid_report_types}."
            )
        exclusions = load_exclusions(project_root)

        result: dict[str, Any] = {}
        if report_type in ("all", "pattern_confidence"):
            result["pattern_confidence"] = [
                s.model_dump() for s in aggregate_pattern_confidence(exclusions)
            ]
        if report_type in ("all", "directory_suggestions"):
            result["directory_suggestions"] = [
                s.model_dump() for s in aggregate_directory_suggestions(exclusions)
            ]
        if report_type in ("all", "fp_report"):
            result["fp_report"] = aggregate_fp_report(exclusions).model_dump()

        # Reuse the already-loaded list to avoid a duplicate YAML parse + verify pass.
        result["trust_status"] = self.verify_trust(
            project_root=project_root, exclusions=exclusions
        )

        # T21-m2: render the trust notice server-side so the subagent outputs
        # it verbatim instead of paraphrasing (LLM versions drift when asked
        # to render a Markdown template character-for-character). Only
        # populated when there's content; empty string for clean states so
        # the subagent can truthy-check without KeyError handling.
        # Note: this ADDS a fifth key to the aggregate_learning trust_status
        # dict; verify_trust's scan-facing surface (assemble_scan /
        # assemble_domain_scan) intentionally does NOT get this field — scan
        # reports render their own trust block elsewhere.
        trust_status = result["trust_status"]
        quarantine_count = trust_status.get("exclusion_quarantine_count", 0)
        if quarantine_count > 0:
            noun = "exclusion" if quarantine_count == 1 else "exclusions"
            trust_status["notice_markdown"] = (
                f"⚠ **{quarantine_count} {noun} quarantined** "
                f"(unsigned or signed by an untrusted key). "
                f"Review with `screw-agents validate-exclusion <id>` "
                f"or bulk-sign with `screw-agents migrate-exclusions`."
            )
        else:
            trust_status["notice_markdown"] = ""
        return result

    def assemble_scan(
        self,
        agent_name: str,
        target: dict[str, Any],
        thoroughness: str = "standard",
        project_root: Path | None = None,
        *,
        preloaded_codes: list[ResolvedCode] | None = None,
        _preloaded_exclusions: list[Exclusion] | None = None,
        include_prompt: bool = True,
    ) -> dict[str, Any]:
        """Assemble a scan payload for a single agent.

        Args:
            agent_name: Registered agent identifier (e.g. "sqli").
            target: Target spec dict (PRD §5 format).
            thoroughness: One of "standard", "deep". Controls which
                heuristic tiers are included in the prompt.
            project_root: Optional project root for exclusion loading.
                When provided, exclusions from .screw/learning/exclusions.yaml
                are filtered by agent and included in the payload.
            preloaded_codes: Internal optimization -- when provided, skip
                resolve_target and use this pre-resolved list. Used by
                ``assemble_domain_scan`` to avoid re-reading files per agent
                on a paginated domain scan.
            include_prompt: When True (default), the response dict contains
                ``core_prompt``. When False, ``core_prompt`` is omitted
                entirely (not empty string — key absent). Used by
                ``assemble_domain_scan`` on code pages and by
                ``assemble_full_scan``'s per-agent fan-out.

        Returns:
            Dict with keys:
                - agent_name: str
                - core_prompt: str  (assembled prompt; only when include_prompt=True)
                - code: str         (formatted code context)
                - resolved_files: list[str]
                - meta: dict        (agent metadata summary)
                - exclusions: list[dict]  (only when project_root is provided)

        Raises:
            ValueError: If agent_name is not registered.
        """
        agent = self._registry.get_agent(agent_name)
        if agent is None:
            raise ValueError(f"Unknown agent: {agent_name!r}")

        # Resolve target to code chunks (or use pre-resolved list from domain-level caller)
        if preloaded_codes is not None:
            codes = preloaded_codes
        else:
            codes = resolve_target(target)

        # Per-agent relevance filter still applies for broad targets (including paged slices)
        target_type = target.get("type", "")
        if target_type in ("codebase", "glob"):
            signals = agent.target_strategy.relevance_signals
            codes = filter_by_relevance(codes, signals)

        code_context = self._format_code_context(codes)

        result: dict[str, Any] = {
            "agent_name": agent_name,
            "code": code_context,
            "resolved_files": [c.file_path for c in codes],
            "meta": self._agent_meta_summary(agent),
        }
        if include_prompt:
            result["core_prompt"] = self._build_prompt(agent, thoroughness)
        if project_root is not None:
            all_exclusions = _preloaded_exclusions if _preloaded_exclusions is not None else load_exclusions(project_root)
            # Subagent-facing exclusions list excludes quarantined entries —
            # exposing tampered/unsigned-under-reject entries here risks the
            # subagent (or a downstream consumer) treating them as actionable.
            # trust_status (computed below from the unfiltered list) still
            # reports the quarantine count separately so the conversational
            # summary surfaces the warning.
            agent_exclusions = [
                e for e in all_exclusions
                if e.agent == agent_name and not e.quarantined
            ]
            result["exclusions"] = [e.model_dump() for e in agent_exclusions]
            # Reuse the already-loaded list to avoid a duplicate YAML parse + verify pass.
            result["trust_status"] = self.verify_trust(
                project_root=project_root, exclusions=all_exclusions
            )
        return result

    def assemble_domain_scan(
        self,
        domain: str,
        target: dict[str, Any],
        thoroughness: str = "standard",
        project_root: Path | None = None,
        *,
        cursor: str | None = None,
        page_size: int = 50,
    ) -> dict[str, Any]:
        """Assemble paginated scan payloads for every agent in a domain.

        The response has TWO shapes keyed by the cursor discriminator:

        **Init page (cursor is None):** Returns per-agent metadata (and,
        if ``project_root`` is set, agent-scoped exclusions) without any
        code. Each per-agent ``agents`` entry carries ``agent_name`` and
        ``meta`` but NO ``core_prompt`` and NO ``code``. There is NO
        top-level ``prompts`` dict — orchestrators fetch each agent's
        prompt lazily via the ``get_agent_prompt`` MCP tool on first
        encounter and cache for reuse across code pages (the aggregate
        prompts dict exceeded Claude Code's inline tool-response budget,
        triggering cache-to-file fallback; shipping prompts lazily keeps
        every response under the ceiling). ``code_chunks_on_page == 0``
        and ``offset == 0``. ``next_cursor`` encodes offset=0 when files
        exist (pointing at the first code page); it is None when there
        is nothing to paginate.

        **Code page (cursor is set):** Emits a paged slice of code chunks
        fanned out per agent. Per-agent entries carry ``code``,
        ``resolved_files``, ``meta`` — but no ``core_prompt`` and no
        ``exclusions`` (exclusions are init-only). ``trust_status`` is
        re-emitted at the top level when ``project_root`` is provided so
        any single page carries the quarantine counts.

        The cursor is an opaque base64url-encoded JSON token encoding
        ``{"target_hash": str, "offset": int}``. Cursors are bound to their
        originating target: replaying a cursor against a different target
        raises ``ValueError``.

        Args:
            domain: CWE-1400 domain name (e.g. "injection-input-handling").
            target: Target spec dict (PRD S5).
            thoroughness: Per-agent tier control ("standard" | "deep").
            project_root: Optional project root for exclusions + trust.
            cursor: Opaque pagination token from a previous call; None
                requests the init page.
            page_size: Max number of resolved code chunks per page
                (default 50).

        Returns:
            Dict with keys shared across both shapes:
                domain: str
                agents: list[dict[str, Any]]
                next_cursor: str | None
                page_size: int
                total_files: int
                offset: int
                code_chunks_on_page: int
                trust_status: dict  (only when project_root is provided)
            Neither shape emits a top-level ``prompts`` key; callers must
            use ``get_agent_prompt(agent_name, thoroughness)`` instead.

        Note: if files are deleted between page requests, the cursor's offset may
        exceed the current file count. This results in an empty ``agents`` list
        with ``next_cursor=None`` — clean termination rather than an error. The
        caller's accumulated results from prior pages remain valid but may be
        incomplete. This is expected behavior for a stateless cursor scheme.

        Raises:
            ValueError: If cursor is bound to a different target, or is
                malformed.
        """
        if page_size < 1:
            raise ValueError(f"page_size must be >= 1, got {page_size}")

        # Canonical target hash binds the cursor to the target -- rejects replay across targets
        canonical = _json.dumps(target, sort_keys=True, separators=(",", ":"))
        target_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]

        # Decode cursor — preserves existing ValueError semantics
        if cursor:
            try:
                decoded = _json.loads(
                    base64.urlsafe_b64decode(cursor.encode("ascii")).decode("utf-8")
                )
                if decoded.get("target_hash") != target_hash:
                    raise ValueError(
                        "cursor is bound to a different target; refusing to use"
                    )
                offset = int(decoded["offset"])
                if offset < 0:
                    raise ValueError("cursor offset is negative")
            except ValueError:
                raise
            except Exception as exc:
                raise ValueError(f"Invalid cursor: {exc}") from exc
        else:
            offset = 0

        agents = self._registry.get_agents_by_domain(domain)

        # Resolve target once — both branches need total_files.
        all_codes = resolve_target(target)
        total_files = len(all_codes)

        is_init_page = cursor is None

        # Load exclusions only on the init page — project-wide, included once
        # in the subagent's context. Code pages do NOT re-ship exclusions.
        if project_root is not None and is_init_page:
            domain_exclusions: list[Exclusion] | None = load_exclusions(project_root)
        else:
            domain_exclusions = None

        if is_init_page:
            agents_responses: list[dict[str, Any]] = []
            for a in agents:
                entry: dict[str, Any] = {
                    "agent_name": a.meta.name,
                    "meta": self._agent_meta_summary(a),
                }
                if project_root is not None and domain_exclusions is not None:
                    agent_exclusions = [
                        e for e in domain_exclusions
                        if e.agent == a.meta.name and not e.quarantined
                    ]
                    entry["exclusions"] = [e.model_dump() for e in agent_exclusions]
                agents_responses.append(entry)

            if total_files > 0:
                next_cursor: str | None = base64.urlsafe_b64encode(
                    _json.dumps(
                        {"target_hash": target_hash, "offset": 0},
                        separators=(",", ":"),
                    ).encode("utf-8")
                ).decode("ascii")
            else:
                next_cursor = None

            result: dict[str, Any] = {
                "domain": domain,
                "agents": agents_responses,
                "next_cursor": next_cursor,
                "page_size": page_size,
                "total_files": total_files,
                "code_chunks_on_page": 0,
                "offset": 0,
            }
            if project_root is not None:
                result["trust_status"] = self.verify_trust(
                    project_root=project_root, exclusions=domain_exclusions
                )
            return result

        # Code-page branch (cursor was non-None)
        page_codes = all_codes[offset : offset + page_size]
        next_offset = offset + len(page_codes)
        if next_offset < total_files:
            next_cursor = base64.urlsafe_b64encode(
                _json.dumps(
                    {"target_hash": target_hash, "offset": next_offset},
                    separators=(",", ":"),
                ).encode("utf-8")
            ).decode("ascii")
        else:
            next_cursor = None

        agents_responses = [
            self.assemble_scan(
                a.meta.name,
                target,
                thoroughness,
                project_root,
                preloaded_codes=page_codes,
                _preloaded_exclusions=[],
                include_prompt=False,
            )
            for a in agents
        ]

        for entry in agents_responses:
            entry.pop("exclusions", None)
            entry.pop("trust_status", None)

        result = {
            "domain": domain,
            "agents": agents_responses,
            "next_cursor": next_cursor,
            "page_size": page_size,
            "total_files": total_files,
            "code_chunks_on_page": len(page_codes),
            "offset": offset,
        }
        if project_root is not None:
            result["trust_status"] = self.verify_trust(project_root=project_root)
        return result

    def assemble_full_scan(
        self,
        target: dict[str, Any],
        thoroughness: str = "standard",
        project_root: Path | None = None,
    ) -> dict[str, Any]:
        """Assemble scan payloads for all registered agents.

        Returns a single response dict with ``agents`` (list of per-agent
        code + metadata entries, no core_prompt). Per-agent detection
        prompts are NOT emitted inline — subagents must fetch each agent's
        prompt lazily via the ``get_agent_prompt`` MCP tool on first
        encounter and cache it for reuse across all code entries for that
        agent. This matches the X1-M1 T13 pattern used by
        ``assemble_domain_scan`` and keeps the response under Claude Code's
        inline tool-response token budget.

        Note: this function is NOT paginated — it returns all code for all
        files for all agents in one response. On large codebases (especially
        at CWE-1400 expansion scale, 41 agents per ``docs/AGENT_CATALOG.md``)
        the code payload may exceed the caller's token budget even with
        prompts deduped via lazy fetch. Tracked as ``T-FULL-P1`` in
        ``docs/DEFERRED_BACKLOG.md`` for Phase 4+ (pagination +
        agent-relevance pre-filter).

        Args:
            target: Target spec dict.
            thoroughness: Passed through to assemble_scan.
            project_root: Optional project root for exclusion loading.

        Returns:
            Dict with keys:
                agents: list[dict] -- per-agent code + meta (no core_prompt);
                    each entry has agent_name, code, resolved_files, meta,
                    and exclusions when project_root is set
                trust_status: dict -- only when project_root is provided
        """
        all_agent_names = list(self._registry.agents)
        agents = [self._registry.get_agent(name) for name in all_agent_names]

        if project_root is not None:
            all_exclusions = load_exclusions(project_root)
        else:
            all_exclusions = None

        agents_responses = [
            self.assemble_scan(
                a.meta.name,
                target,
                thoroughness,
                project_root,
                _preloaded_exclusions=all_exclusions,
                include_prompt=False,
            )
            for a in agents
        ]

        for entry in agents_responses:
            entry.pop("trust_status", None)

        result: dict[str, Any] = {
            "agents": agents_responses,
        }
        if project_root is not None:
            result["trust_status"] = self.verify_trust(
                project_root=project_root, exclusions=all_exclusions
            )
        return result

    def get_agent_prompt(
        self,
        agent_name: str,
        thoroughness: str = "standard",
    ) -> dict[str, Any]:
        """Return the detection prompt and metadata for a single agent.

        Used by orchestrator subagents to fetch prompts lazily per-agent,
        avoiding the tool-response token budget blow-up of emitting all
        agent prompts in one ``scan_domain`` init-page response.

        Args:
            agent_name: Registered agent identifier (e.g. "sqli").
            thoroughness: One of "quick", "standard", "deep".

        Returns:
            Dict with keys:
                agent_name: str
                core_prompt: str -- assembled detection prompt (same shape as
                    the legacy ``assemble_scan`` ``core_prompt`` field)
                meta: dict -- {name, display_name, domain, cwe_primary,
                    cwe_related} (same shape as assemble_scan's meta)

        Raises:
            ValueError: If agent_name is not registered, or if thoroughness
                is not one of ``"quick"``, ``"standard"``, ``"deep"``.
        """
        agent = self._registry.get_agent(agent_name)
        if agent is None:
            raise ValueError(f"Unknown agent: {agent_name!r}")

        if thoroughness not in {"quick", "standard", "deep"}:
            raise ValueError(
                f"Invalid thoroughness: {thoroughness!r}. "
                f"Must be one of: 'quick', 'standard', 'deep'."
            )

        return {
            "agent_name": agent_name,
            "core_prompt": self._build_prompt(agent, thoroughness),
            "meta": self._agent_meta_summary(agent),
        }

    def record_context_required_match(
        self,
        project_root: Path,
        match: dict[str, Any],
        session_id: str | None = None,
    ) -> dict[str, Any]:
        """Append a dropped context-required pattern match to staging.

        Phase 3b T16 (part 2): called by orchestrator subagents during an
        --adaptive scan each time they investigate a
        `severity: context-required` pattern match and decide NOT to emit
        a finding. The match is recorded under
        ``.screw/staging/{session_id}/context_required_matches.json`` with
        the same atomic-write + session-carryforward + finalization-lock
        semantics as ``accumulate_findings``. Dedup is by the 4-tuple
        ``(agent, file, line, pattern)`` so idempotent re-reports do not
        inflate the count.

        `detect_coverage_gaps` (T16 part 3) reads this file back at
        finalize time and feeds it to D1
        (``detect_d1_context_required_gaps``) to emit the gap.

        Args:
            project_root: Absolute path to the project root.
            match: Dict with required keys ``agent: str``, ``file: str``,
                ``line: int``, ``pattern: str``. Structural match matches
                ``ContextRequiredMatch`` TypedDict in
                ``screw_agents.gap_signal``.
            session_id: Opaque session token. Pass None on the first call
                — server generates a fresh id and returns it. Pass the
                returned id on subsequent calls to append to the same
                session. Idempotent with respect to the 4-tuple key.

        Returns:
            Dict with keys:
                session_id: str -- echoed or newly generated
                matches_recorded: int -- total matches in staging after
                    merge (not just this call)

        Raises:
            ValueError: On malformed ``match`` (missing required key,
                wrong type) or when the session was already finalized.
        """
        from screw_agents.staging import accumulate_context_required_match
        new_session_id, count = accumulate_context_required_match(
            project_root, match, session_id
        )
        return {"session_id": new_session_id, "matches_recorded": count}

    def detect_coverage_gaps(
        self,
        *,
        agent_name: str,
        project_root: Path,
        session_id: str,
    ) -> list["CoverageGap"]:
        """Compute D1 + D2 coverage gaps for a single agent within a scan session.

        Phase 3b T16 (part 3): closes the adaptive end-to-end loop. Reads
        context-required matches from
        ``.screw/staging/{session_id}/context_required_matches.json``
        (populated by ``record_context_required_match`` during the scan)
        and combines with D2 output from AST analysis using the agent's
        ``adaptive_inputs`` YAML declaration.

        Per-agent contract: returns ONLY the gaps attributable to
        ``agent_name``. D1 matches whose recorded ``agent`` field is some
        OTHER agent are filtered out — the recorded match carries its own
        attribution, and per-agent callers (MCP tool, T17/T18) must not
        see another agent's gaps. C1 post-review hardening (see
        gap-integration block in ``finalize_scan_results`` for the
        multi-agent-session integration that runs D1 once globally).

        D1 correlation note: with the current producer contract, subagents
        only call ``record_context_required_match`` for DROPPED matches
        (not emitted ones), so ``emitted_findings_by_match`` is always
        empty. T14's API still accepts the mapping for forward-
        compatibility with a future producer that tracks both sides.

        Args:
            agent_name: Registered agent identifier (e.g. ``"sqli"``).
            project_root: Absolute path to the project root.
            session_id: The session id returned by
                ``accumulate_findings`` or ``record_context_required_match``.

        Returns:
            Combined list of CoverageGap attributable to ``agent_name``.
            Empty list when the staging file is missing (scan never
            recorded a match for this agent), the agent has no
            ``adaptive_inputs`` (opted out of D2), and no matches were
            recorded for this agent.

        Raises:
            KeyError: Unknown ``agent_name`` (not in the registry). Raised
                as KeyError rather than ValueError to distinguish
                "caller passed a bogus name" from "staging is malformed".
        """
        from screw_agents.gap_signal import (
            detect_d1_context_required_gaps,
            detect_d2_unresolved_sink_gaps,
        )
        from screw_agents.models import CoverageGap
        from screw_agents.staging import load_context_required_matches

        agent = self._registry.get_agent(agent_name)
        if agent is None:
            raise KeyError(
                f"Unknown agent {agent_name!r}; "
                f"not in registry. Known agents: "
                f"{sorted(self._registry.agents.keys())}"
            )

        # D1 from staging, FILTERED by agent_name so this method returns a
        # clean per-agent view. Missing staging file is valid (scan never
        # recorded a context-required match).
        all_matches = load_context_required_matches(project_root, session_id)
        matches = [m for m in all_matches if m.get("agent") == agent_name]
        gaps: list[CoverageGap] = list(
            detect_d1_context_required_gaps(
                context_required_matches=matches,  # type: ignore[arg-type]
                emitted_findings_by_match={},
            )
        )

        # D2 from YAML `adaptive_inputs`. Agents that opted out (no
        # adaptive_inputs block) skip D2 gracefully.
        if agent.adaptive_inputs is not None:
            gaps.extend(
                detect_d2_unresolved_sink_gaps(
                    project_root=project_root,
                    agent=agent_name,
                    sink_regex=agent.adaptive_inputs.sink_regex,
                    known_receivers=agent.adaptive_inputs.known_receivers,
                    known_sources=agent.adaptive_inputs.known_sources,
                )
            )

        return gaps

    def accumulate_findings(
        self,
        project_root: Path,
        findings_chunk: list[dict[str, Any]],
        session_id: str | None = None,
    ) -> dict[str, Any]:
        """Append a chunk of findings to the per-session staging buffer.

        Part of the accumulate + finalize protocol (paired with
        ``finalize_scan_results``). Called by orchestrator subagents as many
        times as convenient during a scan — once per agent pass, once per
        code page, per batch, whatever matches the subagent's mental model.
        Dedup by finding.id: re-accumulating the same id REPLACES the prior
        entry (allowing corrections / reclassifications mid-scan).

        Args:
            project_root: Absolute path to project root. Staging lives under
                ``.screw/staging/{session_id}/findings.json``.
            findings_chunk: List of finding dicts (each must have an 'id'
                field). Shape matches ``Finding.model_dump()``.
            session_id: Opaque session token. Pass None on the FIRST call of
                a scan — server generates a fresh id and returns it. Pass
                the returned id on subsequent calls to append to the same
                session.

        Returns:
            Dict with keys:
                session_id: str -- echoed or newly generated
                accumulated_count: int -- total findings in staging after
                    merge (not just this chunk)
        """
        from screw_agents.staging import accumulate
        new_session_id, count = accumulate(project_root, findings_chunk, session_id)
        return {"session_id": new_session_id, "accumulated_count": count}

    def finalize_scan_results(
        self,
        project_root: Path,
        session_id: str,
        agent_names: list[str],
        scan_metadata: dict[str, Any] | None = None,
        formats: list[str] | None = None,
    ) -> dict[str, Any]:
        """Read the staging buffer for a session, render reports, cache result.

        Paired with ``accumulate_findings``. Call ONCE at the end of a scan
        after all pagination + analysis is complete. Produces JSON, Markdown,
        optional SARIF, and optional CSV reports, applies server-side
        exclusion matching, and caches the result dict in
        ``.screw/staging/{session_id}/result.json`` for idempotent re-calls.

        Idempotent — subsequent calls with the same session_id return the
        cached result dict without re-rendering. The staging directory
        persists (it holds the result.json sidecar); only findings.json is
        consumed on the first call. ValueError is raised only if the
        session_id is truly unknown (neither staged nor finalized).

        Args:
            project_root: Absolute path to project root.
            session_id: The id returned by the first ``accumulate_findings``
                call (or echoed on subsequent accumulate calls).
            agent_names: Agent names that produced findings (e.g. ["sqli"]).
            scan_metadata: Optional metadata (target, timestamp).
            formats: Output formats. Defaults to ["json", "markdown"].
                Accepted: "json", "markdown", "sarif", "csv".

        Returns:
            Dict with:
                files_written: dict[str, str] -- format name → file path
                summary: dict -- total, suppressed, active, by_severity
                exclusions_applied: list[dict] -- finding_id + exclusion_ref pairs
                trust_status: dict -- 4-field trust verification counts

        Raises:
            ValueError: If session_id does not correspond to any staging
                session (neither a staged findings.json nor a cached
                result.json exists).
        """
        from screw_agents.gap_signal import (
            detect_d1_context_required_gaps,
            detect_d2_unresolved_sink_gaps,
        )
        from screw_agents.models import CoverageGap
        from screw_agents.results import render_and_write
        from screw_agents.staging import (
            finalize_result_cached,
            has_context_required_staging,
            load_context_required_matches,
            read_for_finalize,
            save_finalize_result,
        )

        # Idempotent re-call path: if the session was already finalized,
        # return the cached result without re-rendering or erroring.
        cached = finalize_result_cached(project_root, session_id)
        if cached is not None:
            return cached

        # Normal first-call path: read staged findings, render reports,
        # cache the result for idempotent re-calls.
        findings_raw = read_for_finalize(project_root, session_id)
        result = render_and_write(
            project_root=project_root,
            findings_raw=findings_raw,
            agent_names=agent_names,
            scan_metadata=scan_metadata,
            formats=formats,
            agent_registry=self._registry,
        )

        # Phase 3b T16: attach coverage-gap detection to the finalize
        # response. MUST happen before `save_finalize_result` so the
        # context_required_matches.json staging is still present (the save
        # cleans it up).
        #
        # C1 post-review hardening — D1 runs ONCE globally per session,
        # D2 runs per-agent:
        #
        #   * D1 matches carry their own `agent` attribution (the
        #     subagent recorded it at investigation time). Running D1
        #     per-agent-in-agent_names would duplicate every gap by the
        #     loop cardinality — a single sqli match + agent_names=
        #     ["sqli","cmdi","ssti","xss"] would yield 4 identical
        #     entries. That's silent count inflation downstream.
        #
        #   * D2 inputs (sink_regex, known_receivers, known_sources)
        #     live in each agent's adaptive_inputs YAML, so D2 is
        #     inherently per-agent-config.
        #
        # The per-agent `ScanEngine.detect_coverage_gaps` method still
        # exists (exposed as an MCP tool, used by external callers) with
        # a clean per-agent contract — see its docstring for the filter
        # semantics.
        #
        # Inclusion rule (backward compat): `coverage_gaps` key appears in
        # the response ONLY when the scan had adaptive signal — either at
        # least one agent has `adaptive_inputs` declared (D2-capable), or
        # the scan session recorded context-required matches (D1-capable).
        # Non-adaptive scans see no schema change.
        has_staged_matches = has_context_required_staging(project_root, session_id)
        adaptive_agents = [
            name for name in agent_names
            if (a := self._registry.get_agent(name)) is not None
            and a.adaptive_inputs is not None
        ]
        if adaptive_agents or has_staged_matches:
            coverage_gaps: list[CoverageGap] = []

            # D1 — one pass over staging for ALL agents in this session.
            # Each recorded match carries its own `agent` field; no
            # filtering by agent_names (a future match recorded by an
            # agent not currently listed in agent_names is still surfaced
            # — its existence is the signal).
            if has_staged_matches:
                matches = load_context_required_matches(project_root, session_id)
                coverage_gaps.extend(
                    detect_d1_context_required_gaps(
                        context_required_matches=matches,  # type: ignore[arg-type]
                        emitted_findings_by_match={},
                    )
                )

            # D2 — per-agent, driven by each agent's adaptive_inputs.
            # Unknown agent names in agent_names are skipped silently
            # (the renderer above already tolerates them).
            for name in agent_names:
                agent = self._registry.get_agent(name)
                if agent is None or agent.adaptive_inputs is None:
                    continue
                coverage_gaps.extend(
                    detect_d2_unresolved_sink_gaps(
                        project_root=project_root,
                        agent=name,
                        sink_regex=agent.adaptive_inputs.sink_regex,
                        known_receivers=agent.adaptive_inputs.known_receivers,
                        known_sources=agent.adaptive_inputs.known_sources,
                    )
                )

            result["coverage_gaps"] = [g.model_dump() for g in coverage_gaps]

        save_finalize_result(project_root, session_id, result)
        return result

    def format_output(
        self,
        findings: list[Finding],
        output_format: str = "json",
        scan_metadata: dict[str, Any] | None = None,
    ) -> str:
        """Format scan findings via the formatter module.

        Args:
            findings: List of Finding objects.
            output_format: "json", "sarif", or "markdown".
            scan_metadata: Optional metadata dict for the report header.

        Returns:
            Formatted string output.
        """
        return format_findings(
            findings,
            format=output_format,
            scan_metadata=scan_metadata,
            agent_registry=self._registry,
        )

    def list_tool_definitions(self) -> list[dict[str, Any]]:
        """Return MCP tool definitions for all registered agents + static tools.

        Returns a list of tool definition dicts, each with:
            - name: str
            - description: str
            - input_schema: JSON Schema dict
        """
        tools: list[dict[str, Any]] = []

        # Static tools
        tools.append({
            "name": "list_domains",
            "description": "List all available vulnerability domain groups with agent counts.",
            "input_schema": self._scan_input_schema(extra_required=[], extra_props={}),
        })
        tools.append({
            "name": "list_agents",
            "description": "List all registered security agents, optionally filtered by domain.",
            "input_schema": self._scan_input_schema(
                extra_required=[],
                extra_props={
                    "domain": {
                        "type": "string",
                        "description": "Filter by domain name (optional).",
                    }
                },
            ),
        })
        tools.append({
            "name": "scan_domain",
            "description": (
                "Run all agents in a vulnerability domain against the target. "
                "Returns a paginated response: {agents, next_cursor, page_size, total_files, "
                "offset, trust_status?}. Subagents MUST loop until next_cursor is None "
                "before calling finalize_scan_results."
            ),
            "input_schema": self._scan_input_schema(
                extra_required=["target", "domain"],
                extra_props={
                    "target": _target_schema(),
                    "domain": {
                        "type": "string",
                        "description": "Domain name (e.g. 'injection-input-handling').",
                    },
                    "thoroughness": _thoroughness_schema(),
                    "project_root": _project_root_schema(),
                    "cursor": {
                        "type": ["string", "null"],
                        "description": (
                            "Opaque pagination token from a previous scan_domain call. "
                            "Pass null (or omit) on the first call. When next_cursor in the "
                            "response is null, pagination is complete."
                        ),
                        "default": None,
                    },
                    "page_size": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 500,
                        "description": "Max resolved code chunks per page (default 50).",
                        "default": 50,
                    },
                },
            ),
        })
        tools.append({
            "name": "scan_full",
            "description": (
                "Run all registered agents against the target. "
                "Use for comprehensive security audits."
            ),
            "input_schema": self._scan_input_schema(
                extra_required=["target"],
                extra_props={
                    "target": _target_schema(),
                    "thoroughness": _thoroughness_schema(),
                    "project_root": _project_root_schema(),
                },
            ),
        })

        # Phase 3a X1-M1 (T12): per-agent prompt fetch
        tools.append({
            "name": "get_agent_prompt",
            "description": (
                "Return the detection prompt + metadata for a single registered "
                "agent. Used by orchestrator subagents to fetch prompts lazily "
                "per-agent, avoiding the tool-response token budget ceiling "
                "that scan_domain init pages used to hit when shipping all "
                "domain prompts at once."
            ),
            "input_schema": {
                "type": "object",
                "properties": {
                    "agent_name": {
                        "type": "string",
                        "description": "Registered agent identifier (e.g. 'sqli').",
                    },
                    "thoroughness": {
                        "type": "string",
                        "enum": ["quick", "standard", "deep"],
                        "default": "standard",
                        "description": "Prompt-tier control. Default 'standard'.",
                    },
                },
                "required": ["agent_name"],
            },
        })

        # Per-agent scan tools
        for agent in self._registry.agents.values():
            tools.append({
                "name": f"scan_{agent.meta.name}",
                "description": (
                    f"Run the {agent.meta.display_name} against the target. "
                    f"Detects {agent.meta.cwes.primary} vulnerabilities."
                ),
                "input_schema": self._scan_input_schema(
                    extra_required=["target"],
                    extra_props={
                        "target": _target_schema(),
                        "thoroughness": _thoroughness_schema(),
                        "project_root": _project_root_schema(),
                    },
                ),
            })

        # Phase 3a X1-M1 (T18): accumulate_findings + finalize_scan_results
        # (replaces the legacy single-shot write_scan_results tool).
        tools.append({
            "name": "accumulate_findings",
            "description": (
                "Append a chunk of findings to the per-session staging buffer. "
                "Called incrementally by orchestrator subagents as they produce "
                "findings — once per agent pass, once per code page, per batch, "
                "whatever matches the subagent's mental model. Dedup is by "
                "finding.id (re-accumulating replaces the prior entry). Pair "
                "with `finalize_scan_results` (call once at the end of the scan)."
            ),
            "input_schema": {
                "type": "object",
                "properties": {
                    "project_root": {
                        "type": "string",
                        "description": "Absolute path to the project root.",
                    },
                    "findings_chunk": {
                        "type": "array",
                        "items": {"type": "object"},
                        "description": (
                            "List of finding dicts (each must have an 'id' field). "
                            "Shape matches the Finding Pydantic model."
                        ),
                    },
                    "session_id": {
                        "type": ["string", "null"],
                        "description": (
                            "Pass null (or omit) on the FIRST call of a scan — "
                            "server generates a fresh id and returns it. Pass "
                            "the returned id on subsequent calls to append to "
                            "the same session."
                        ),
                    },
                },
                "required": ["project_root", "findings_chunk"],
            },
        })
        tools.append({
            "name": "finalize_scan_results",
            "description": (
                "Read the staging buffer for a scan session, render reports "
                "(JSON/Markdown/SARIF/CSV), apply server-side exclusion matching, "
                "write to .screw/findings/, and clean up staging. Call ONCE at "
                "the end of a scan after all pagination + analysis is complete. "
                "Paired with `accumulate_findings` (called incrementally during "
                "the scan)."
            ),
            "input_schema": {
                "type": "object",
                "properties": {
                    "project_root": {
                        "type": "string",
                        "description": "Absolute path to the project root.",
                    },
                    "session_id": {
                        "type": "string",
                        "description": "The session id returned by accumulate_findings.",
                    },
                    "agent_names": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Agent names that produced findings (e.g. ['sqli']).",
                    },
                    "scan_metadata": {
                        "type": ["object", "null"],
                        "description": "Optional metadata (target, timestamp).",
                    },
                    "formats": {
                        "type": ["array", "null"],
                        "items": {"type": "string", "enum": ["json", "markdown", "sarif", "csv"]},
                        "description": (
                            "Output formats to write. Defaults to ['json', 'markdown'] "
                            "when null/omitted."
                        ),
                    },
                },
                "required": ["project_root", "session_id", "agent_names"],
            },
        })

        # Phase 2: format_output
        tools.append({
            "name": "format_output",
            "description": (
                "Format scan findings as JSON, SARIF 2.1.0, or Markdown report. "
                "Pass the structured findings array from your analysis."
            ),
            "input_schema": {
                "type": "object",
                "properties": {
                    "findings": {
                        "type": "array",
                        "description": "Array of Finding objects (see models.py Finding schema).",
                    },
                    "format": {
                        "type": "string",
                        "enum": ["json", "sarif", "markdown"],
                        "description": "Output format.",
                        "default": "json",
                    },
                    "scan_metadata": {
                        "type": "object",
                        "description": "Optional metadata (target, agents, timestamp) for report header.",
                    },
                },
                "required": ["findings"],
            },
        })

        # Phase 2: record_exclusion
        tools.append({
            "name": "record_exclusion",
            "description": (
                "Record a false positive exclusion in .screw/learning/exclusions.yaml. "
                "Call this when the user marks a finding as a false positive."
            ),
            "input_schema": {
                "type": "object",
                "properties": {
                    "project_root": {
                        "type": "string",
                        "description": "Absolute path to the project root directory.",
                    },
                    "exclusion": {
                        "type": "object",
                        "description": "Exclusion data: agent, finding, reason, scope.",
                        "properties": {
                            "agent": {"type": "string"},
                            "finding": {
                                "type": "object",
                                "properties": {
                                    "file": {"type": "string"},
                                    "line": {"type": "integer"},
                                    "code_pattern": {"type": "string"},
                                    "cwe": {"type": "string"},
                                },
                                "required": ["file", "line", "code_pattern", "cwe"],
                            },
                            "reason": {"type": "string"},
                            "scope": {
                                "type": "object",
                                "properties": {
                                    "type": {
                                        "type": "string",
                                        "enum": ["exact_line", "pattern", "function", "file", "directory"],
                                    },
                                    "pattern": {"type": "string"},
                                    "path": {"type": "string"},
                                    "name": {"type": "string"},
                                },
                                "required": ["type"],
                            },
                        },
                        "required": ["agent", "finding", "reason", "scope"],
                    },
                },
                "required": ["project_root", "exclusion"],
            },
        })

        # Phase 2: check_exclusions
        tools.append({
            "name": "check_exclusions",
            "description": (
                "Load exclusions from .screw/learning/exclusions.yaml, "
                "optionally filtered by agent name."
            ),
            "input_schema": {
                "type": "object",
                "properties": {
                    "project_root": {
                        "type": "string",
                        "description": "Absolute path to the project root directory.",
                    },
                    "agent": {
                        "type": "string",
                        "description": "Filter exclusions to this agent (optional).",
                    },
                },
                "required": ["project_root"],
            },
        })

        # Phase 3a: verify_trust
        tools.append({
            "name": "verify_trust",
            "description": (
                "Return a summary of .screw/ content trust status — counts of "
                "active vs quarantined exclusions and (Phase 3b) adaptive scripts. "
                "Use this to surface trust issues in the scan report header."
            ),
            "input_schema": {
                "type": "object",
                "properties": {
                    "project_root": {
                        "type": "string",
                        "description": "Absolute path to the project root directory.",
                    },
                },
                "required": ["project_root"],
            },
        })

        # Phase 3b PR#4 Task 12: execute_adaptive_script
        tools.append({
            "name": "execute_adaptive_script",
            "description": (
                "Execute a previously-validated adaptive analysis script "
                "under the sandbox and return its findings. Runs the full "
                "defense pipeline: AST lint, SHA-256 hash pin, Ed25519 "
                "signature verification, stale-target check, sandbox launch "
                "with wall-clock kill, and JSON-schema validation of the "
                "emitted findings. Requires the script to be signed by a "
                "key listed in .screw/config.yaml's script_reviewers."
            ),
            "input_schema": {
                "type": "object",
                "properties": {
                    "project_root": {
                        "type": "string",
                        "description": "Absolute path to the project root.",
                    },
                    "script_name": {
                        "type": "string",
                        "description": (
                            "Script basename without the .py extension "
                            "(e.g., 'querybuilder-sqli-check'). Resolved "
                            "under .screw/custom-scripts/<name>.py + "
                            "<name>.meta.yaml."
                        ),
                    },
                    "wall_clock_s": {
                        "type": "integer",
                        "minimum": 1,
                        "default": 30,
                        "description": (
                            "Parent-side sandbox kill timer in seconds. "
                            "Defaults to 30s."
                        ),
                    },
                },
                "required": ["project_root", "script_name"],
            },
        })

        # Phase 3b T18a: sign_adaptive_script — approve-path MCP tool for
        # the adaptive review flow. Subagent generated a fresh script, user
        # approved, this tool writes + signs + stages. Distinct from the
        # `validate-script` CLI (which re-signs existing scripts); this
        # tool is fresh-only and returns status="error" on name collision.
        tools.append({
            "name": "sign_adaptive_script",
            "description": (
                "Sign a freshly-generated adaptive analysis script and "
                "write it to .screw/custom-scripts/. Called from the "
                "approve-path of the adaptive review flow (after human "
                "review + `approve <name>`). Atomic write: both .py and "
                ".meta.yaml land via os.replace; rollback on meta "
                "failure keeps the filesystem in a consistent state. "
                "Requires the local machine's signing key to match a "
                "registered reviewer in .screw/config.yaml's "
                "script_reviewers (Model A fingerprint matching). "
                "Fresh-script only — name collisions return "
                "status=\"error\"; use `validate-script` CLI to re-sign "
                "an existing script."
            ),
            "input_schema": {
                "type": "object",
                "properties": {
                    "project_root": {
                        "type": "string",
                        "description": "Absolute path to the project root.",
                    },
                    "script_name": {
                        "type": "string",
                        "description": (
                            "Filesystem-safe name (regex "
                            "`^[a-z0-9][a-z0-9-]{2,62}$`). Produces "
                            "<name>.py + <name>.meta.yaml in "
                            ".screw/custom-scripts/."
                        ),
                    },
                    "source": {
                        "type": "string",
                        "description": (
                            "Python source code for the adaptive script. "
                            "Caller is responsible for validating with "
                            "`lint_adaptive_script` before approval."
                        ),
                    },
                    "meta": {
                        "type": "object",
                        "description": (
                            "Partial meta dict conforming to "
                            "AdaptiveScriptMeta minus signing fields. "
                            "Must include name, created, created_by, "
                            "domain; may include description, "
                            "target_patterns. Tool computes sha256, sets "
                            "validated=True, signs, and writes."
                        ),
                    },
                    "session_id": {
                        "type": "string",
                        "description": (
                            "Scan session id the script was generated for. "
                            "Echoed in the response; not used to modify "
                            "session staging."
                        ),
                    },
                },
                "required": [
                    "project_root",
                    "script_name",
                    "source",
                    "meta",
                    "session_id",
                ],
            },
        })

        # Phase 3b T18a: lint_adaptive_script — pre-approval Layer 1 AST
        # lint (pure function). Distinct from the lint inside
        # execute_script which runs AFTER approval; this tool surfaces
        # lint results in the 5-section review BEFORE the reviewer decides.
        tools.append({
            "name": "lint_adaptive_script",
            "description": (
                "Run the Layer 1 AST allowlist lint on adaptive-script "
                "source WITHOUT executing it. Used during the pre-approval "
                "review path so the human reviewer sees lint results "
                "BEFORE approval (execute_script also runs lint, but only "
                "after human approval — too late to decline). Returns "
                "status='pass' | 'fail' | 'syntax_error'. Pure function: "
                "no side effects, safe to call repeatedly."
            ),
            "input_schema": {
                "type": "object",
                "properties": {
                    "source": {
                        "type": "string",
                        "description": (
                            "Python source code to lint. Not modified."
                        ),
                    },
                },
                "required": ["source"],
            },
        })

        # Phase 3b T16: record_context_required_match + detect_coverage_gaps
        # (closes the adaptive E2E loop: scan records dropped
        # context-required matches → finalize runs gap detection → orchestrator
        # reads gaps to decide whether to generate an adaptive script).
        tools.append({
            "name": "record_context_required_match",
            "description": (
                "Record a context-required pattern match that the subagent "
                "investigated but decided NOT to emit as a finding. During an "
                "--adaptive scan, call this once per dropped match so the D1 "
                "coverage-gap signal can fire at finalize time. Dedup is by "
                "(agent, file, line, pattern); idempotent re-recording is a "
                "no-op. Pair with `detect_coverage_gaps` (called implicitly by "
                "`finalize_scan_results` for adaptive-capable agents)."
            ),
            "input_schema": {
                "type": "object",
                "properties": {
                    "project_root": {
                        "type": "string",
                        "description": "Absolute path to the project root.",
                    },
                    "match": {
                        "type": "object",
                        "description": (
                            "Context-required match with keys agent, file, "
                            "line, pattern. Shape matches the "
                            "ContextRequiredMatch TypedDict in gap_signal.py."
                        ),
                        "properties": {
                            "agent": {"type": "string"},
                            "file": {"type": "string"},
                            "line": {"type": "integer"},
                            "pattern": {"type": "string"},
                        },
                        "required": ["agent", "file", "line", "pattern"],
                    },
                    "session_id": {
                        "type": ["string", "null"],
                        "description": (
                            "Pass null (or omit) on the FIRST call — server "
                            "generates a fresh id and returns it. Pass the "
                            "returned id on subsequent calls to append to the "
                            "same session. For a scan that also uses "
                            "accumulate_findings, pass that tool's returned "
                            "session_id here so both staging files share the "
                            "same session directory."
                        ),
                    },
                },
                "required": ["project_root", "match"],
            },
        })
        tools.append({
            "name": "detect_coverage_gaps",
            "description": (
                "Compute D1 + D2 coverage gaps for a completed adaptive scan. "
                "D1 reads context-required matches recorded during the scan "
                "via `record_context_required_match`; D2 runs AST taint "
                "analysis using the agent's YAML `adaptive_inputs`. Returns "
                "the combined gap list. Raises KeyError on unknown agent. "
                "Note: `finalize_scan_results` invokes this automatically for "
                "adaptive-capable agents and includes gaps in its response; "
                "call this tool directly only when you need gaps without "
                "finalizing the scan."
            ),
            "input_schema": {
                "type": "object",
                "properties": {
                    "agent_name": {
                        "type": "string",
                        "description": "Registered agent identifier (e.g. 'sqli').",
                    },
                    "project_root": {
                        "type": "string",
                        "description": "Absolute path to the project root.",
                    },
                    "session_id": {
                        "type": "string",
                        "description": (
                            "Session id from accumulate_findings / "
                            "record_context_required_match."
                        ),
                    },
                },
                "required": ["agent_name", "project_root", "session_id"],
            },
        })

        # Phase 3a PR#2: aggregate_learning
        tools.append({
            "name": "aggregate_learning",
            "description": (
                "Compute learning reports from the project's exclusions database. "
                "Returns pattern-confidence suggestions, directory-scope exclusion "
                "candidates, and a false-positive report for agent refinement. "
                "Always includes a trust_status section. "
                "This is on-demand only; do NOT call after every scan."
            ),
            "input_schema": {
                "type": "object",
                "properties": {
                    "project_root": {
                        "type": "string",
                        "description": "Absolute path to the project root directory.",
                    },
                    "report_type": {
                        "type": "string",
                        "enum": [
                            "all",
                            "pattern_confidence",
                            "directory_suggestions",
                            "fp_report",
                        ],
                        "default": "all",
                        "description": (
                            "Which report sections to include. 'all' is the default."
                        ),
                    },
                },
                "required": ["project_root"],
            },
        })

        return tools

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _agent_meta_summary(self, agent: AgentDefinition) -> dict[str, Any]:
        """Return the canonical 5-field meta summary for an agent response entry.

        Used by assemble_scan, assemble_domain_scan (init branch), and
        get_agent_prompt so the meta shape is defined in one place.
        """
        return {
            "name": agent.meta.name,
            "display_name": agent.meta.display_name,
            "domain": agent.meta.domain,
            "cwe_primary": agent.meta.cwes.primary,
            "cwe_related": agent.meta.cwes.related,
        }

    def _build_prompt(self, agent: AgentDefinition, thoroughness: str) -> str:
        """Assemble the detection prompt from agent fields.

        Includes core_prompt, detection heuristics (high + medium always;
        context_required only for "deep"), bypass techniques, and
        few-shot examples (up to 3 vulnerable + 3 safe).
        """
        parts: list[str] = []

        # Core prompt
        parts.append(agent.core_prompt.strip())

        # Detection Heuristics
        heuristics = agent.detection_heuristics
        heuristic_lines: list[str] = []

        high = heuristics.high_confidence
        # quick: high-confidence only; standard/deep: include medium; deep: also context_required
        medium = [] if thoroughness == "quick" else heuristics.medium_confidence
        context_req = heuristics.context_required if thoroughness == "deep" else []

        if high:
            heuristic_lines.append("### High Confidence")
            for item in high:
                heuristic_lines.append(_format_heuristic_item(item))

        if medium:
            heuristic_lines.append("### Medium Confidence")
            for item in medium:
                heuristic_lines.append(_format_heuristic_item(item))

        if context_req:
            heuristic_lines.append("### Context Required")
            for item in context_req:
                heuristic_lines.append(_format_heuristic_item(item))

        if heuristic_lines:
            parts.append("## Detection Heuristics\n\n" + "\n".join(heuristic_lines))

        # Bypass techniques — omitted for quick scans
        if agent.bypass_techniques and thoroughness != "quick":
            bypass_lines = ["## Bypass Techniques to Watch For"]
            for bt in agent.bypass_techniques:
                bypass_lines.append(f"**{bt.name}:** {bt.description}")
                if bt.detection_hint:
                    bypass_lines.append(f"  Detection hint: {bt.detection_hint}")
            parts.append("\n".join(bypass_lines))

        # Few-shot examples — omitted for quick scans
        vulnerable_examples = [] if thoroughness == "quick" else agent.few_shot_examples.vulnerable[:3]
        safe_examples = [] if thoroughness == "quick" else agent.few_shot_examples.safe[:3]

        if vulnerable_examples or safe_examples:
            example_lines = ["## Examples"]

            if vulnerable_examples:
                example_lines.append("### Vulnerable Patterns")
                for ex in vulnerable_examples:
                    label = ex.label or "Vulnerable"
                    example_lines.append(f"**{label}** ({ex.language})")
                    example_lines.append(f"```{ex.language}")
                    example_lines.append(ex.code.strip())
                    example_lines.append("```")
                    if ex.explanation:
                        example_lines.append(ex.explanation)

            if safe_examples:
                example_lines.append("### Safe Patterns")
                for ex in safe_examples:
                    label = ex.label or "Safe"
                    example_lines.append(f"**{label}** ({ex.language})")
                    example_lines.append(f"```{ex.language}")
                    example_lines.append(ex.code.strip())
                    example_lines.append("```")
                    if ex.explanation:
                        example_lines.append(ex.explanation)

            parts.append("\n".join(example_lines))

        return "\n\n".join(parts)

    def _format_code_context(self, codes: list[ResolvedCode]) -> str:
        """Format resolved code chunks with file headers into a single string."""
        if not codes:
            return ""

        sections: list[str] = []
        for code in codes:
            header_parts = [f"## File: {code.file_path}"]
            if code.language:
                header_parts.append(f"Language: {code.language}")
            if code.line_start is not None:
                loc = f"Lines: {code.line_start}"
                if code.line_end is not None:
                    loc += f"–{code.line_end}"
                header_parts.append(loc)

            lang_tag = code.language or ""
            sections.append(
                "\n".join(header_parts)
                + f"\n\n```{lang_tag}\n{code.content}\n```"
            )

        return "\n\n---\n\n".join(sections)

    def _scan_input_schema(
        self,
        extra_required: list[str],
        extra_props: dict[str, Any],
    ) -> dict[str, Any]:
        """Build a JSON Schema dict for scan tool inputs.

        Args:
            extra_required: Additional required field names.
            extra_props: Additional property definitions to merge in.

        Returns:
            A JSON Schema object dict.
        """
        schema: dict[str, Any] = {
            "type": "object",
            "properties": dict(extra_props),
        }
        if extra_required:
            schema["required"] = extra_required
        return schema


# ------------------------------------------------------------------
# Module-level helpers
# ------------------------------------------------------------------


def _format_heuristic_item(item: Any) -> str:
    """Format a heuristic item (str or HeuristicEntry) as a bullet string."""
    if isinstance(item, str):
        return f"- {item}"
    if isinstance(item, HeuristicEntry):
        langs = f" [{', '.join(item.languages)}]" if item.languages else ""
        return f"- {item.id}: {item.pattern}{langs}"
    # Fallback: duck-type for dict-like objects
    if hasattr(item, "pattern"):
        pattern = item.pattern
        item_id = getattr(item, "id", "")
        langs = getattr(item, "languages", [])
        lang_str = f" [{', '.join(langs)}]" if langs else ""
        prefix = f"{item_id}: " if item_id else ""
        return f"- {prefix}{pattern}{lang_str}"
    return f"- {item}"


def _project_root_schema() -> dict[str, Any]:
    """JSON Schema for the optional 'project_root' parameter."""
    return {
        "type": "string",
        "description": (
            "Absolute path to the project root directory. When provided, "
            "exclusions from .screw/learning/exclusions.yaml are loaded "
            "and included in the scan payload."
        ),
    }


def _target_schema() -> dict[str, Any]:
    """JSON Schema for the 'target' parameter."""
    return {
        "type": "object",
        "description": (
            "Target specification. Must include 'type' (one of: file, glob, lines, "
            "function, class, codebase, git_diff, git_commits, pull_request) "
            "plus type-specific fields."
        ),
        "properties": {
            "type": {"type": "string"},
        },
        "required": ["type"],
    }


def _thoroughness_schema() -> dict[str, Any]:
    """JSON Schema for the 'thoroughness' parameter."""
    return {
        "type": "string",
        "enum": ["quick", "standard", "deep"],
        "description": (
            "Scan depth. 'quick' includes high-confidence heuristics only. "
            "'standard' includes high + medium confidence heuristics. "
            "'deep' also includes context-required heuristics."
        ),
        "default": "standard",
    }
