"""Scan engine — ties registry, resolver, and formatter together.

Assembles detection prompts from agent YAML + resolved code. Does NOT
call Claude — the MCP tool returns the assembled prompt for Claude to
process. Claude then returns structured findings which are passed to
format_findings() for output formatting.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json as _json
import logging
import os
from pathlib import Path
from typing import Any

import yaml

from screw_agents.adaptive.executor import execute_script
from screw_agents.adaptive.signing import (
    _sign_script_bytes,
)
from screw_agents.aggregation import (
    aggregate_directory_suggestions,
    aggregate_fp_report,
    aggregate_pattern_confidence,
)
from screw_agents.formatter import format_findings
from screw_agents.learning import (
    load_exclusions,
)
from screw_agents.models import AgentDefinition, Exclusion, Finding, HeuristicEntry
from screw_agents.registry import AgentRegistry
from screw_agents.resolver import ResolvedCode, filter_by_relevance, resolve_target
from screw_agents.treesitter import language_from_shebang
from screw_agents.trust import (
    load_config,
    verify_script,
)

logger = logging.getLogger(__name__)

_DEFAULT_DOMAINS_DIR = Path(__file__).resolve().parent.parent.parent / "domains"


def _agent_supported_languages(agent: AgentDefinition) -> set[str]:
    """Union of `languages` declarations across all HeuristicEntry items
    in the agent's three detection_heuristics buckets.

    Plain string heuristic entries (HeuristicItem = str | HeuristicEntry per
    models.py:76) contribute nothing — they have no language metadata.

    Returns:
        Set of canonical language names (from treesitter.SUPPORTED_LANGUAGES).
        Empty set when the agent declares no languages on any heuristic entry.
    """
    langs: set[str] = set()
    for bucket in (
        agent.detection_heuristics.high_confidence,
        agent.detection_heuristics.medium_confidence,
        agent.detection_heuristics.context_required,
    ):
        for entry in bucket:
            if isinstance(entry, HeuristicEntry):
                langs.update(entry.languages)
    return langs


def _filter_relevant_agents(
    target_codes: list[ResolvedCode],
    agents: list[AgentDefinition],
) -> tuple[list[AgentDefinition], list[dict[str, Any]]]:
    """Drop agents whose declared languages don't intersect target's detected languages.

    Spec section 8.2. Two fail-open paths:
    1. Empty `target_languages` (target is non-code or unknown): keep all agents.
    2. Empty `agent_languages` (agent declares no per-heuristic languages): keep
       agent (D6 default; new agents without language declarations are not
       silently excluded).

    Args:
        target_codes: list of ResolvedCode chunks (already populated by resolve_target).
        agents: candidate agent list.

    Returns:
        (kept, excluded) where:
            kept = list of AgentDefinition surviving the filter.
            excluded = list of dicts with keys:
                agent_name, reason ("language_mismatch"),
                agent_languages (sorted list), target_languages (sorted list).
    """
    target_languages: set[str] = set()
    for code in target_codes:
        if code.language is not None:
            target_languages.add(code.language)
            continue
        # Fallback: shebang on first line of content. The resolver already
        # populates code.language for every chunk it produces, so this branch
        # only fires for callers that construct ResolvedCode manually with
        # language=None (e.g., test fixtures or future programmatic callers).
        first_line = code.content.split("\n", 1)[0] if code.content else ""
        lang = language_from_shebang(first_line)
        if lang is not None:
            target_languages.add(lang)

    if not target_languages:
        # Spec §8.2 / §8.5 row 3 — log a WARN when no target languages detected.
        # Caller (assemble_agents_scan in Task 3) decides how to surface this to
        # the user. See D6 for the fail-open contract.
        logger.warning(
            "Relevance filter: no target languages detected (target may be non-code); "
            "keeping all %d agents (fail-open per D6).",
            len(agents),
        )
        return list(agents), []

    kept: list[AgentDefinition] = []
    excluded: list[dict[str, Any]] = []
    for agent in agents:
        agent_languages = _agent_supported_languages(agent)
        if not agent_languages:
            # D6 fail-open: agent with no language declarations is always kept.
            kept.append(agent)
            continue
        if agent_languages & target_languages:
            kept.append(agent)
        else:
            excluded.append(
                {
                    "agent_name": agent.meta.name,
                    "reason": "language_mismatch",
                    "agent_languages": sorted(agent_languages),
                    "target_languages": sorted(target_languages),
                }
            )
    return kept, excluded


def _read_stale_staging_hours(project_root: Path) -> int:
    """Return ``stale_staging_hours`` from ``.screw/config.yaml``.

    Lightweight ad-hoc read (not through the ``ScrewConfig`` Pydantic
    schema) because a fresh project may not have a config file yet; we
    want a sane default (24h) rather than an error. When the config file
    is present, the schema-level validator in ``ScrewConfig`` (I1)
    guarantees ``stale_staging_hours`` is in [1, 168] at config-load time;
    we still clamp here as defense-in-depth against hand-edited YAML that
    bypassed the Pydantic load path.

    Returns:
        Hours threshold for staleness check. 24 by default; clamped to
        [1, 168] (1 hour to 1 week) on malformed values.
    """
    try:
        config_path = project_root / ".screw" / "config.yaml"
        if not config_path.exists():
            return 24
        with open(config_path, encoding="utf-8") as f:
            cfg = yaml.safe_load(f) or {}
        val = int(cfg.get("stale_staging_hours", 24))
        return max(1, min(168, val))
    except (ValueError, TypeError, OSError, yaml.YAMLError):
        return 24


def _read_staging_max_age_days(project_root: Path) -> int:
    """Return ``staging_max_age_days`` from ``.screw/config.yaml``.

    Module-level helper symmetric with ``_read_stale_staging_hours``
    above (T4 precedent). Used by ``sweep_stale_staging`` to decide the
    orphan-age threshold when the caller passes ``max_age_days=None``.

    Lightweight ad-hoc read (not through the ``ScrewConfig`` Pydantic
    schema) because a fresh project may not have a config file yet; we
    want a sane default (14d) rather than an error. The canonical
    schema-level validator in ``ScrewConfig.staging_max_age_days``
    (T4-part-2 I1) clamps to [1, 365] at config-load time; we still
    clamp here as defense-in-depth against hand-edited YAML that
    bypassed the Pydantic load path.

    Returns:
        Days threshold for staleness check. 14 by default; clamped to
        [1, 365] (1 day to 1 year) on malformed values.
    """
    try:
        import yaml as _yaml

        config_path = project_root / ".screw" / "config.yaml"
        if not config_path.exists():
            return 14
        with open(config_path, encoding="utf-8") as f:
            cfg = _yaml.safe_load(f) or {}
        return max(1, min(365, int(cfg.get("staging_max_age_days", 14))))
    except (PermissionError, OSError, ValueError):
        return 14


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
            Dict with keys: ``status`` (``"ok"`` when the sandbox returncode
            is 0, else ``"sandbox_failure"``), ``script_name``, ``findings``
            (list of finding dicts), ``stale`` (bool), ``execution_time_ms``
            (int), ``stderr`` (top-level decoded stderr string — empty on
            success, populated with tracebacks/messages on sandbox failure
            so the T18b failure-render path has something to show the user),
            and ``sandbox_result`` (dict). Inside ``sandbox_result`` the
            decoded ``stderr`` is duplicated for convenience; ``stdout`` is
            intentionally excluded because adaptive scripts communicate via
            ``findings.json`` rather than stdout. ``model_dump(mode="json")``
            is used so nested datetimes and other non-JSON-native types
            serialize correctly. T11 (I3) — Phase 3b PR #6.

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

        # Decode stderr bytes -> str for JSON payload (T11 plan-fix #2).
        # errors="replace" so a binary-writing malicious script can't raise
        # UnicodeDecodeError and break the response.
        stderr_str = result.sandbox_result.stderr.decode(
            "utf-8", errors="replace"
        )

        # Top-level status: "ok" on clean returncode, "sandbox_failure"
        # otherwise (T11 plan-fix #3). killed_by_timeout yields
        # returncode=-1, so it's already covered by the != 0 check.
        status = (
            "ok"
            if result.sandbox_result.returncode == 0
            else "sandbox_failure"
        )

        return {
            "status": status,  # T11 plan-fix #3: top-level
            "script_name": result.script_name,
            "findings": [f.model_dump(mode="json") for f in result.findings],
            "stale": result.stale,
            "execution_time_ms": result.execution_time_ms,
            "stderr": stderr_str,  # T11 plan-fix #4: top-level alias
            "sandbox_result": {
                **result.sandbox_result.model_dump(
                    mode="json", exclude={"stdout", "stderr"}
                ),
                "stderr": stderr_str,  # T11 plan-fix #4: also inside
            },
        }

    def stage_adaptive_script(
        self,
        *,
        project_root: Path,
        script_name: str,
        source: str,
        meta: dict[str, Any],
        session_id: str,
        target_gap: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Atomically write an unsigned adaptive script to session-scoped staging.

        The LLM-driven review path (Phase 3b C1 staging architecture):
        subagent calls this BEFORE composing the 5-section human review.
        The staged bytes are the source of truth for the subsequent
        ``promote_staged_script`` call — the user reviews what is staged,
        and promote signs what is staged, with sha256 verification
        preventing tamper (C1 trust invariant).

        Writes ``.py`` + ``.meta.yaml`` into
        ``.screw/staging/{session_id}/adaptive-scripts/`` and appends a
        ``staged`` event to ``.screw/local/pending-approvals.jsonl``.

        Args:
            project_root: Project root with ``.screw/`` directory.
            script_name: Filesystem-safe name
                (regex ``^[a-z0-9][a-z0-9-]{2,62}$``). Validated via the
                shared ``adaptive.script_name.validate_script_name`` (T2
                consolidation) before any filesystem op.
            source: Python source for the adaptive script. Caller
                SHOULD have run ``lint_adaptive_script`` before staging
                (pre-review), though staging itself does not enforce
                this.
            meta: Partial meta dict that will eventually conform to
                ``AdaptiveScriptMeta`` (minus signing fields). Must
                include ``name``, ``created``, ``created_by``, ``domain``;
                may include ``description``, ``target_patterns``.
            session_id: Scan session id. Validated by
                ``resolve_staging_dir`` against the
                ``\\A[A-Za-z0-9_-]{1,64}\\Z`` allowlist (T1 part 4,
                I-opus-1/2 fix). Scopes the staging directory —
                different session_ids get different dirs.
            target_gap: Optional coverage-gap metadata recorded in the
                registry entry. Shape:
                ``{type, file, line, agent}``. ``None`` for non-gap
                stages.

        Returns:
            Dict with:
              - ``status``: ``"staged"`` on success, ``"error"`` on
                validation / collision failure.
              - On ``"staged"``: ``script_name``, ``stage_path``,
                ``script_sha256``, ``script_sha256_prefix``,
                ``session_id``, ``session_id_short``.
              - On ``"error"``: ``error``, ``message``, and (for
                collision) ``existing_sha256_prefix``.

        Spec §3.1. Raises ValueError wrapping filesystem errors per
        T13-C1. Returns domain-error dict on name/session validation
        failures (callers compose error-dicts into the MCP tool
        response; distinct from Python raises which would propagate
        and fail the whole tool call).

        Idempotency contract:
          - Same ``script_name`` + same ``sha256(source)``: proceeds
            through re-write + re-appends a second ``staged`` registry
            entry. Downstream ``query_registry_most_recent`` returns
            the last entry.
          - Same ``script_name`` + different ``sha256``: returns
            ``{"status": "error", "error": "stage_name_collision"}``
            WITHOUT touching the filesystem.

        Partial-state contract (cross-reference
        ``append_registry_entry``): if the filesystem writes succeed but
        the registry append raises, the staged files remain on disk.
        This is deliberate — the filesystem is the source of truth;
        T6 sweep recovers orphans by age.
        """
        import yaml

        from screw_agents.adaptive.script_name import validate_script_name
        from screw_agents.adaptive.signing import compute_script_sha256
        from screw_agents.adaptive.staging import (
            _utc_now_iso,
            append_registry_entry,
            resolve_staging_dir,
            write_staged_files,
        )

        # Name validation (delegates to shared `adaptive.script_name` per
        # T2 consolidation). Raises ValueError on mismatch — catch and
        # convert to the existing error-dict contract callers depend on.
        try:
            validate_script_name(script_name)
        except ValueError as exc:
            return {
                "status": "error",
                "error": "invalid_script_name",
                "message": str(exc),
            }

        # Session_id validation is enforced by ``resolve_staging_dir``
        # (uses the ``\\A[A-Za-z0-9_-]{1,64}\\Z`` allowlist regex added
        # in T1 part 4 for I-opus-1/2). Catch the ValueError it raises
        # and convert to the error-dict contract. Do NOT re-implement a
        # denylist here — that would diverge from the allowlist and
        # re-open I-opus-1.
        try:
            stage_dir = resolve_staging_dir(project_root, session_id)
        except ValueError as exc:
            return {
                "status": "error",
                "error": "invalid_session_id",
                "message": str(exc),
            }

        # Compute sha256 via the shared helper (T2 consolidation — do
        # NOT introduce a duplicate here).
        script_sha256 = compute_script_sha256(source)

        # Collision check: same script_name exists under this session?
        py_path = stage_dir / f"{script_name}.py"
        if py_path.exists():
            try:
                existing = py_path.read_text(encoding="utf-8")
            except UnicodeDecodeError as exc:
                return {
                    "status": "error",
                    "error": "stage_corrupted",
                    "message": (
                        f"staged file {py_path} is not valid UTF-8 "
                        f"({type(exc).__name__}: {exc}). Run sweep_stale_staging "
                        f"to clean up, or delete the file manually."
                    ),
                }
            existing_sha = compute_script_sha256(existing)
            if existing_sha != script_sha256:
                return {
                    "status": "error",
                    "error": "stage_name_collision",
                    "message": (
                        f"{script_name} already staged in {session_id} "
                        f"with different content"
                    ),
                    "existing_sha256_prefix": existing_sha[:8],
                }
            # Same content — idempotent; proceed to re-write + re-record.

        # Serialize meta to YAML (simple sanitization: ensure round-trip).
        meta_yaml = yaml.safe_dump(
            meta, sort_keys=True, default_flow_style=False
        )

        # Atomic write (staging.py helper; raises ValueError on fs
        # errors via T13-C1 discipline).
        write_staged_files(
            project_root=project_root,
            script_name=script_name,
            source=source,
            meta_yaml=meta_yaml,
            session_id=session_id,
        )

        # Append registry entry. Partial-state semantics: if this
        # fails, the staged files remain on disk (T6 sweep recovers
        # them by age). See ``append_registry_entry``'s docstring.
        entry = {
            "event": "staged",
            "script_name": script_name,
            "session_id": session_id,
            "script_sha256": script_sha256,
            "target_gap": target_gap or {},
            "staged_at": _utc_now_iso(),
            "schema_version": 1,
        }
        append_registry_entry(project_root, entry)

        return {
            "status": "staged",
            "script_name": script_name,
            "stage_path": str(py_path),
            "script_sha256": script_sha256,
            "script_sha256_prefix": script_sha256[:8],
            "session_id": session_id,
            "session_id_short": (
                session_id[:12] if len(session_id) > 12 else session_id
            ),
        }

    def promote_staged_script(
        self,
        *,
        project_root: Path,
        script_name: str,
        session_id: str,
        confirm_sha_prefix: str | None = None,
        confirm_stale: bool = False,
    ) -> dict[str, Any]:
        """Sign + promote a staged script to .screw/custom-scripts/.

        THE C1 FIX. Does NOT accept a ``source`` or ``meta`` parameter — both
        are read from the staging directory on disk. This is the architectural
        closure of the regeneration vulnerability: the bytes the user reviewed
        at stage-time are the bytes that get signed. A subagent (even a
        compromised one) cannot re-ship different source under the same
        script_name, because promote compares the staged bytes' sha256 against
        the registry-recorded sha256 and refuses mismatches.

        Flow (design spec §3.2):
          1. Resolve staging paths; missing → ``staging_not_found``.
          2. Read .py + .meta.yaml bytes from staging.
          3. Compute ``actual_sha256`` from staged source bytes.
          4. Registry lookup; most-recent ``(script_name, session_id)`` entry.
          4b. Staleness check (``stale_staging_hours`` default 24;
              ``confirm_stale=True`` bypasses, emits ``promoted_confirm_stale``
              audit event). I3 hardening: malformed/missing ``staged_at`` is
              an explicit ``invalid_registry_entry`` error (no silent bypass).
          5. Primary path: sha match → proceed; mismatch → ``tamper_detected``
             (preserves staging bytes + writes ``.TAMPERED`` marker + appends
             ``tamper_detected`` audit event).
          6. Fallback path: registry missing / no matching entry →
             requires caller to re-supply ``confirm_sha_prefix``. On match,
             audit event is ``promoted_via_fallback``.
          7. Delegate to ``_sign_script_bytes`` (shared signing helper, T2
             consolidation). I2 hardening: when the helper returns a
             status-error dict without an ``error`` key, inject
             ``error="sign_failed"`` so callers pattern-matching on
             ``response["error"]`` do not KeyError.
          8. Delete staging files (idempotent).
          9. Append ``promoted`` / ``promoted_via_fallback`` /
             ``promoted_confirm_stale`` audit event.

        Args:
            project_root: Project root with ``.screw/`` directory.
            script_name: Filesystem-safe name (regex
                ``^[a-z0-9][a-z0-9-]{2,62}$``). Validated via the shared
                ``adaptive.script_name.validate_script_name`` by
                ``resolve_staging_dir`` → ``read_staged_files`` →
                ``_sign_script_bytes`` (defense in depth).
            session_id: Scan session id the script was staged under.
                Validated by ``resolve_staging_dir`` against the
                ``\\A[A-Za-z0-9_-]{1,64}\\Z`` allowlist.
            confirm_sha_prefix: Short sha256 prefix (first 8 hex chars)
                re-supplied by the caller when the registry lookup failed
                and a filesystem fallback walk is used. ``None`` for the
                normal registry-hit path.
            confirm_stale: When ``True``, allows promotion even if the
                staging entry is older than ``stale_staging_hours`` (default
                24). Caller must re-type an explicit
                ``approve {name} confirm-stale`` phrase.

        Returns:
            On ``"signed"``: ``status``, ``script_name``, ``script_path``,
            ``meta_path``, ``signed_by``, ``sha256``, ``session_id``,
            ``promoted_via_fallback``.
            On error: ``status="error"`` plus ``error`` + ``message``; error
            taxonomy: ``staging_not_found``, ``stale_staging``,
            ``invalid_registry_entry``, ``tamper_detected``,
            ``invalid_lifecycle_state``, ``fallback_required``,
            ``fallback_sha_mismatch``, ``invalid_staged_meta``,
            ``sign_failed``, ``invalid_session_id``.

        Raises:
            ValueError: Wrapping filesystem errors per T13-C1 discipline
                (propagates from ``read_staged_files``,
                ``append_registry_entry``, ``delete_staged_files``).

        Spec §3.2.
        """
        import yaml
        from datetime import datetime, timedelta, timezone

        from screw_agents.adaptive.signing import (
            _sign_script_bytes,
            compute_script_sha256,
        )
        from screw_agents.adaptive.staging import (
            _utc_now_iso,
            append_registry_entry,
            delete_staged_files,
            fallback_walk_for_script,
            query_registry_most_recent,
            read_staged_files,
            resolve_staging_dir,
        )

        # Step 1: resolve + verify staging exists. session_id validation is
        # enforced by resolve_staging_dir (allowlist regex, I-opus-1 fix).
        # Catch the ValueError and surface the error-dict contract callers
        # depend on — do NOT re-implement a denylist here.
        try:
            stage_dir = resolve_staging_dir(project_root, session_id)
        except ValueError as exc:
            return {
                "status": "error",
                "error": "invalid_session_id",
                "message": str(exc),
            }

        py_path = stage_dir / f"{script_name}.py"
        meta_path = stage_dir / f"{script_name}.meta.yaml"
        if not (py_path.exists() and meta_path.exists()):
            return {
                "status": "error",
                "error": "staging_not_found",
                "message": (
                    f"No staged script named {script_name!r} in "
                    f"session {session_id!r}"
                ),
            }

        # Step 2 + 3: read staged bytes + compute sha.
        try:
            source, meta_yaml = read_staged_files(
                project_root=project_root,
                script_name=script_name,
                session_id=session_id,
            )
        except FileNotFoundError:
            # Race between exists-check and read; rare but possible.
            return {
                "status": "error",
                "error": "staging_not_found",
                "message": (
                    f"Staged files vanished between check and read "
                    f"for {script_name!r}"
                ),
            }
        actual_sha256 = compute_script_sha256(source)

        # Step 4: registry lookup (most-recent matching entry).
        registry_entry = query_registry_most_recent(
            project_root, script_name=script_name, session_id=session_id
        )

        # Step 4b: staleness check when we have a staged_at timestamp.
        stale_threshold_hours = _read_stale_staging_hours(project_root)
        if registry_entry and registry_entry.get("event") == "staged":
            staged_at_str = registry_entry.get("staged_at")
            if staged_at_str is None:
                # I3 hardening: registry entry missing staged_at is a schema
                # violation (validate_pending_approval should have caught
                # this on write; if we see it at read time, the registry
                # has been tampered or a legacy entry predates the
                # validator). Force ops to investigate rather than
                # silently bypass the staleness check.
                return {
                    "status": "error",
                    "error": "invalid_registry_entry",
                    "message": (
                        f"Registry entry for {script_name!r}/"
                        f"{session_id!r} is missing the 'staged_at' field "
                        f"required for staleness check. Registry may be "
                        f"corrupted or written by an older schema version. "
                        f"Inspect `.screw/local/pending-approvals.jsonl` "
                        f"and run `sweep_stale_staging` to recover orphans."
                    ),
                }
            try:
                staged_at = datetime.strptime(
                    staged_at_str, "%Y-%m-%dT%H:%M:%SZ"
                ).replace(tzinfo=timezone.utc)
            except ValueError as exc:
                # I3 hardening: malformed staged_at must NOT silently bypass
                # the staleness check. Fail loudly so ops can investigate.
                return {
                    "status": "error",
                    "error": "invalid_registry_entry",
                    "message": (
                        f"Registry entry for {script_name!r}/"
                        f"{session_id!r} has malformed staged_at "
                        f"({staged_at_str!r}; expected ISO8601 with Z "
                        f"suffix). Parse error: {exc}. "
                        f"Inspect `.screw/local/pending-approvals.jsonl`."
                    ),
                }
            age = datetime.now(timezone.utc) - staged_at
            if (
                age > timedelta(hours=stale_threshold_hours)
                and not confirm_stale
            ):
                return {
                    "status": "error",
                    "error": "stale_staging",
                    "message": (
                        f"Staged {script_name!r} is "
                        f"{age.total_seconds() / 3600:.1f}h old "
                        f"(staged_at: {staged_at_str}); "
                        f"threshold is {stale_threshold_hours}h. "
                        f"Re-type `approve {script_name} confirm-stale` "
                        f"to proceed anyway."
                    ),
                    "hours_old": round(age.total_seconds() / 3600, 1),
                    "threshold_hours": stale_threshold_hours,
                }

        # Step 4b-5: lifecycle + primary/tamper.
        audit_event = "promoted"
        if registry_entry:
            last_event = registry_entry.get("event")
            if last_event != "staged":
                return {
                    "status": "error",
                    "error": "invalid_lifecycle_state",
                    "message": (
                        f"Most-recent registry event for {script_name!r} "
                        f"in {session_id!r} is {last_event!r}; expected "
                        f"'staged'. Staging should not exist."
                    ),
                    "last_event": last_event,
                }
            registry_sha = registry_entry.get("script_sha256")
            if registry_sha is None:
                # I-opus-1 hardening: symmetric to I3's staged_at check. A `staged`
                # entry missing `script_sha256` is a schema violation (T3's
                # validate_pending_approval should catch this on write). If we see
                # it at read time, the registry has been tampered or a legacy entry
                # predates the validator. Force ops to investigate rather than
                # crash on registry_sha[:8] later.
                return {
                    "status": "error",
                    "error": "invalid_registry_entry",
                    "message": (
                        f"Registry entry for {script_name!r}/{session_id!r} is "
                        f"missing the 'script_sha256' field required for tamper "
                        f"detection. Registry may be corrupted or written by an "
                        f"older schema version. Inspect "
                        f"`.screw/local/pending-approvals.jsonl`."
                    ),
                }
            if actual_sha256 != registry_sha:
                # TAMPER DETECTED. Preserve the staging bytes for forensic
                # inspection + write a .TAMPERED marker + append a
                # tamper_detected audit event.
                marker = stage_dir / f"{script_name}.TAMPERED"
                try:
                    marker.touch()
                except OSError:
                    pass  # best-effort marker; do not fail the tamper path
                tamper_entry = {
                    "event": "tamper_detected",
                    "script_name": script_name,
                    "session_id": session_id,
                    "expected_sha256": registry_sha,
                    "actual_sha256": actual_sha256,
                    "evidence_path": str(py_path),
                    "tampered_at": _utc_now_iso(),
                    "schema_version": 1,
                }
                append_registry_entry(project_root, tamper_entry)
                return {
                    "status": "error",
                    "error": "tamper_detected",
                    "message": (
                        f"Staged content sha256 does not match staging "
                        f"registry. Expected {registry_sha[:8]}; got "
                        f"{actual_sha256[:8]}. Approval REJECTED for "
                        f"safety. Tampered bytes preserved at {py_path} "
                        f"for forensic inspection. Re-run scan."
                    ),
                    "expected_sha256_prefix": registry_sha[:8],
                    "actual_sha256_prefix": actual_sha256[:8],
                    "evidence_path": str(py_path),
                }
        else:
            # Step 6: fallback path (registry missing / no matching entry).
            if confirm_sha_prefix is None:
                matches = fallback_walk_for_script(
                    project_root, script_name=script_name
                )
                if not matches:
                    return {
                        "status": "error",
                        "error": "staging_not_found",
                        "message": (
                            f"No staged script named {script_name!r} "
                            f"anywhere"
                        ),
                    }
                # We already know py_path exists (verified in Step 1); use
                # its sha as the recovery prefix for the caller to echo back.
                return {
                    "status": "error",
                    "error": "fallback_required",
                    "message": (
                        f"Registry lookup failed. Staging file found "
                        f"with sha256 prefix {actual_sha256[:8]}. "
                        f"Re-type `approve {script_name} "
                        f"confirm-{actual_sha256[:8]}` to proceed."
                    ),
                    "recovered_sha256_prefix": actual_sha256[:8],
                }
            if confirm_sha_prefix != actual_sha256[:8]:
                return {
                    "status": "error",
                    "error": "fallback_sha_mismatch",
                    "message": (
                        f"Confirm phrase sha prefix does not match the "
                        f"recovered staging file. Re-run scan."
                    ),
                    "expected_in_phrase": actual_sha256[:8],
                    "got_in_phrase": confirm_sha_prefix,
                }
            audit_event = "promoted_via_fallback"

        # Confirm-stale variant of audit event (I5 audit-event taxonomy).
        # Only upgrades the default "promoted" event; fallback path retains
        # its own event name.
        if confirm_stale and audit_event == "promoted":
            audit_event = "promoted_confirm_stale"

        # Step 7: parse staged meta + delegate to shared signing helper.
        try:
            meta_dict = yaml.safe_load(meta_yaml)
        except yaml.YAMLError as exc:
            return {
                "status": "error",
                "error": "invalid_staged_meta",
                "message": f"staged meta YAML is malformed: {exc}",
            }

        sign_result = _sign_script_bytes(
            project_root=project_root,
            script_name=script_name,
            source=source,
            meta_dict=meta_dict,
            session_id=session_id,
        )
        if sign_result.get("status") != "signed":
            # I2 taxonomy-normalization: _sign_script_bytes returns
            # {"status": "error", "message": "..."} without an "error" key
            # (collision, no_matching_reviewer, meta_schema_fail, etc.).
            # Inject a stable error-key so callers pattern-matching on
            # response["error"] don't KeyError. Preserve the original dict
            # in "detail" for operators.
            return {
                "status": "error",
                "error": "sign_failed",
                "message": sign_result.get(
                    "message", "Signing failed with no message"
                ),
                "detail": sign_result,
            }

        # Step 8: delete staging (idempotent). If this fails, the sign
        # already succeeded — the promote is still successful; the staging
        # orphan will be collected by sweep_stale_staging on the next run.
        try:
            delete_staged_files(
                project_root=project_root,
                script_name=script_name,
                session_id=session_id,
            )
        except ValueError:
            # Intentional swallow: promote succeeded, staging cleanup
            # failed, sweep will pick up the orphan by age.
            pass

        # Step 9: append promoted audit event.
        promoted_entry = {
            "event": audit_event,
            "script_name": script_name,
            "session_id": session_id,
            "script_sha256": sign_result["sha256"],
            "signed_by": sign_result["signed_by"],
            "promoted_at": _utc_now_iso(),
            "schema_version": 1,
        }
        append_registry_entry(project_root, promoted_entry)

        return {
            "status": "signed",
            "script_name": script_name,
            "script_path": sign_result["script_path"],
            "meta_path": sign_result["meta_path"],
            "signed_by": sign_result["signed_by"],
            "sha256": sign_result["sha256"],
            "session_id": session_id,
            "promoted_via_fallback": audit_event == "promoted_via_fallback",
        }

    def reject_staged_script(
        self,
        *,
        project_root: Path,
        script_name: str,
        session_id: str,
        reason: str | None = None,
    ) -> dict[str, Any]:
        """Delete staging files and record a rejection audit event.

        Idempotent: a second reject on already-deleted staging returns
        ``status=already_rejected`` (success). Also updates the existing T18b
        decline-tracking file ``.screw/local/adaptive_prompts.json`` to mark
        this target as declined so the same target isn't re-proposed on the
        next scan.

        Flow (design spec §3.3):
          1. Validate ``script_name`` via the shared validator; ValueError →
             ``invalid_script_name`` error-dict (I1 defense-in-depth, symmetric
             to T3/T4).
          2. Resolve staging dir; ValueError (invalid ``session_id``) →
             ``invalid_session_id`` error-dict.
          3. If staging .py does not exist → ``already_rejected`` (idempotent
             success — a second reject after first reject, or reject before
             any stage, is not an error).
          4. Delete staged files + append ``rejected`` audit event to the
             pending-approvals registry.
          5. Best-effort update of ``.screw/local/adaptive_prompts.json``
             (T18b decline tracking) — swallow filesystem errors so a flaky
             prompts file never breaks the reject flow's correctness.

        Args:
            project_root: Project root with ``.screw/`` directory.
            script_name: Filesystem-safe name (regex
                ``^[a-z0-9][a-z0-9-]{2,62}$``). Validated via the shared
                ``adaptive.script_name.validate_script_name``.
            session_id: Scan session id the script was staged under.
                Validated by ``resolve_staging_dir`` against the
                ``\\A[A-Za-z0-9_-]{1,64}\\Z`` allowlist.
            reason: Optional short rationale recorded in the audit event.

        Returns:
            On success: ``status="rejected"`` with ``script_name``,
            ``session_id``, ``reason``.
            On idempotent re-reject: ``status="already_rejected"`` with same
            fields.
            On error: ``status="error"`` plus ``error`` (``invalid_script_name``
            or ``invalid_session_id``) + ``message``.

        Spec §3.3.
        """
        import json

        from screw_agents.adaptive.script_name import validate_script_name
        from screw_agents.adaptive.staging import (
            _utc_now_iso,
            append_registry_entry,
            delete_staged_files,
            resolve_staging_dir,
        )

        # I1 defense-in-depth: symmetric script_name validation (T3/T4 pattern).
        # Catch ValueError + convert to error-dict so callers pattern-matching
        # on response["error"] don't see a leaked ValueError.
        try:
            validate_script_name(script_name)
        except ValueError as exc:
            return {
                "status": "error",
                "error": "invalid_script_name",
                "message": str(exc),
            }

        # I1 defense-in-depth: resolve_staging_dir raises ValueError on invalid
        # session_id (T1-part-4 allowlist). Catch + convert to error-dict for
        # consistency with T3/T4's engine-layer contract — no ValueError leak.
        try:
            stage_dir = resolve_staging_dir(project_root, session_id)
        except ValueError as exc:
            return {
                "status": "error",
                "error": "invalid_session_id",
                "message": str(exc),
            }

        py_path = stage_dir / f"{script_name}.py"
        if not py_path.exists():
            return {
                "status": "already_rejected",
                "script_name": script_name,
                "session_id": session_id,
                "reason": reason or "",
            }

        try:
            delete_staged_files(
                project_root=project_root,
                script_name=script_name,
                session_id=session_id,
            )
        except ValueError as exc:
            # Reject semantics require delete to succeed. If it fails (EBUSY,
            # permission, etc.), return error-dict; do NOT append audit event
            # or update decline-tracking for a half-deleted state.
            return {
                "status": "error",
                "error": "delete_failed",
                "message": str(exc),
                "script_name": script_name,
                "session_id": session_id,
            }

        reject_entry = {
            "event": "rejected",
            "script_name": script_name,
            "session_id": session_id,
            "reason": reason or "",
            "rejected_at": _utc_now_iso(),
            "schema_version": 1,
        }
        append_registry_entry(project_root, reject_entry)

        # Update adaptive_prompts.json — existing T18b decline-tracking artifact.
        # Best-effort: the reject flow's correctness (files deleted + audit
        # event appended) does NOT depend on this file; a flaky prompts file
        # must not break the reject.
        prompts_path = project_root / ".screw" / "local" / "adaptive_prompts.json"
        # T18b decline-tracking update — best-effort per docstring. Must self-heal
        # corrupted files (JSONDecodeError, shape drift) so flaky prompts state
        # never breaks reject correctness.
        try:
            if prompts_path.exists():
                try:
                    state = json.loads(prompts_path.read_text(encoding="utf-8"))
                except ValueError:
                    state = {"declined": []}  # self-heal: invalid JSON
                if not isinstance(state, dict):
                    state = {"declined": []}
            else:
                state = {"declined": []}
            declined = state.setdefault("declined", [])
            if not isinstance(declined, list):
                declined = []
                state["declined"] = declined
            if script_name not in declined:
                declined.append(script_name)
            prompts_path.parent.mkdir(parents=True, exist_ok=True)
            tmp = prompts_path.with_suffix(".json.tmp")
            tmp.write_text(json.dumps(state, indent=2), encoding="utf-8")
            os.replace(tmp, prompts_path)
        except (PermissionError, OSError, ValueError):
            pass  # best-effort: file corruption or fs failure does not fail reject

        return {
            "status": "rejected",
            "script_name": script_name,
            "session_id": session_id,
            "reason": reason or "",
        }

    def sweep_stale_staging(
        self,
        *,
        project_root: Path,
        max_age_days: int | None = None,
        dry_run: bool = False,
    ) -> dict[str, Any]:
        """Clean up orphaned staging entries under ``.screw/staging/``.

        User-invoked orphan GC. Absorbs ``T-STAGING-ORPHAN-GC`` from the
        Phase 4+ backlog — covers both new C1 staging artifacts (T3-T5)
        and legacy session-scoped finalize-never-called dirs.

        Reads ``staging_max_age_days`` from ``.screw/config.yaml`` when
        ``max_age_days`` is None (default 14, clamped [1, 365]).
        ``dry_run=True`` reports what would be removed without touching
        the filesystem or registry. See design spec §3.4.

        Args:
            project_root: Project root with ``.screw/`` directory.
            max_age_days: Override the config threshold (days). None
                falls back to ``_read_staging_max_age_days``.
            dry_run: When True, populates the report but makes no
                filesystem changes and appends no ``swept`` audit
                events.

        Returns:
            ``StaleStagingReport`` dict: ``status``, ``max_age_days``,
            ``dry_run``, ``sessions_scanned``, ``sessions_removed``,
            ``scripts_removed``, ``tampered_preserved``.
        """
        from screw_agents.adaptive.staging import sweep_stale

        if max_age_days is None:
            max_age_days = _read_staging_max_age_days(project_root)
        max_age_days = max(1, min(365, int(max_age_days)))

        return sweep_stale(
            project_root=project_root,
            max_age_days=max_age_days,
            dry_run=dry_run,
        )

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

    def list_adaptive_scripts(
        self,
        *,
        project_root: Path,
    ) -> dict[str, Any]:
        """List every adaptive script in ``.screw/custom-scripts/`` with
        metadata AND per-script stale status.

        Promoted from ``cli/adaptive_cleanup.py`` in PR #6 per I6 — the
        slash-command ``uv run python -c "from screw_agents.cli..."``
        invocation was breaking when ``cwd != worktree``. Promoting to an
        MCP tool resolves that: ``.mcp.json`` already carries the correct
        ``--project`` argument, so the engine-level entry point is
        cwd-independent.

        Behavior unchanged from T21. The per-script stale detection goes
        through ``adaptive.executor._check_stale`` (co-located with
        ``_is_stale`` as of T7 plan-fix #1).

        Args:
            project_root: Absolute path to the project root.

        Returns:
            ``{"status": "ok", "scripts": [...]}`` per spec §3.5. Each
            entry carries the 12 fields: ``name``, ``created``,
            ``created_by``, ``domain``, ``description``,
            ``target_patterns``, ``findings_produced``, ``last_used``,
            ``validated``, ``signed_by``, ``stale``, ``stale_reason``.

            ``scripts`` is empty when ``.screw/custom-scripts/`` does not
            exist. Entries with missing companion ``.py``, malformed YAML,
            or non-dict meta are skipped silently (the user can surface
            those via ``verify_trust``).

            Sort order: alphabetical by ``name`` for deterministic output.
            None-named entries (malformed-but-parsed YAML) are sorted to
            the end so ordering stays total.
        """
        custom_scripts_dir = project_root / ".screw" / "custom-scripts"
        if not custom_scripts_dir.exists():
            return {"status": "ok", "scripts": []}

        scripts: list[dict[str, Any]] = []
        for meta_file in sorted(custom_scripts_dir.glob("*.meta.yaml")):
            # meta_file has two suffixes (".meta.yaml"); stripping both
            # yields the bare script name. Explicit string handling avoids
            # path-suffix ambiguity across Python versions.
            stem = meta_file.name[: -len(".meta.yaml")]
            source_file = custom_scripts_dir / f"{stem}.py"
            if not source_file.exists():
                continue
            entry = self._inspect_adaptive_script(
                project_root, source_file, meta_file
            )
            if entry is None:
                continue
            scripts.append(entry)

        scripts.sort(key=lambda s: (s["name"] is None, s["name"] or ""))
        return {"status": "ok", "scripts": scripts}

    def _inspect_adaptive_script(
        self,
        project_root: Path,
        source_file: Path,
        meta_file: Path,
    ) -> dict[str, Any] | None:
        """Build one per-script entry for ``list_adaptive_scripts``.

        Returns ``None`` for orphans that should be skipped (malformed YAML,
        non-dict meta). Verbatim lift from the former CLI helper — every
        one of the 12 fields survives unchanged.
        """
        from screw_agents.adaptive.executor import _check_stale

        try:
            meta = yaml.safe_load(meta_file.read_text(encoding="utf-8"))
        except (yaml.YAMLError, OSError):
            return None
        if not isinstance(meta, dict):
            return None

        target_patterns = meta.get("target_patterns", []) or []
        stale, stale_reason = _check_stale(project_root, target_patterns)

        return {
            "name": meta.get("name"),
            "created": meta.get("created"),
            "created_by": meta.get("created_by"),
            "domain": meta.get("domain"),
            "description": meta.get("description", ""),
            "target_patterns": target_patterns,
            "findings_produced": meta.get("findings_produced", 0),
            "last_used": meta.get("last_used"),
            "validated": meta.get("validated", False),
            "signed_by": meta.get("signed_by"),
            "stale": stale,
            "stale_reason": stale_reason,
        }

    def remove_adaptive_script(
        self,
        *,
        project_root: Path,
        script_name: str,
        confirmed: bool = False,
    ) -> dict[str, Any]:
        """Delete an adaptive script pair from ``.screw/custom-scripts/``.

        T21 confirmation gate preserved: ``confirmed=False`` returns
        ``{"status":"error","error":"confirmation_required"}``. Caller is
        expected to prompt the user for "yes" before passing
        ``confirmed=True``.

        Promoted from ``cli/adaptive_cleanup.py`` in PR #6 per I6 — the
        former slash-command invocation broke when ``cwd != worktree``.
        See design spec §3.6.

        Args:
            project_root: Absolute path to the project root.
            script_name: Filesystem-safe name of the script to delete
                (without the ``.py`` / ``.meta.yaml`` suffix).
            confirmed: Must be ``True`` to actually delete. ``False`` (or
                omitted) returns the confirmation-required error-dict
                without touching the filesystem.

        Returns:
            On success: ``{"status": "removed", "script_name": <name>}``.
            On the confirmation gate: ``{"status": "error",
            "error": "confirmation_required", "message": ...}``.
            When neither companion file exists: ``{"status": "error",
            "error": "not_found", "message": ...}``.
            On filesystem failure mid-delete: ``{"status": "error",
            "error": "delete_failed", "message": <OS error>,
            "script_name": <name>}``.
        """
        if not confirmed:
            return {
                "status": "error",
                "error": "confirmation_required",
                "message": "remove_adaptive_script requires confirmed=True",
            }

        custom_scripts_dir = project_root / ".screw" / "custom-scripts"
        py_path = custom_scripts_dir / f"{script_name}.py"
        meta_path = custom_scripts_dir / f"{script_name}.meta.yaml"

        # Plan-fix #2: check BOTH — either-present means there is still state
        # to clean up. Only both-absent is a genuine not_found. This restores
        # T21's orphan-meta cleanup for the crash-between-unlinks scenario.
        if not py_path.exists() and not meta_path.exists():
            return {
                "status": "error",
                "error": "not_found",
                "message": f"{script_name} not found in custom-scripts/",
            }

        try:
            py_path.unlink(missing_ok=True)
            meta_path.unlink(missing_ok=True)
        except (PermissionError, OSError) as exc:
            # Plan-fix #1: error-dict per T5 delete_failed precedent
            # (engine.py:977-983). NOT a raise — callers pattern-match on
            # response["status"].
            return {
                "status": "error",
                "error": "delete_failed",
                "message": str(exc),
                "script_name": script_name,
            }

        return {"status": "removed", "script_name": script_name}

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
        """Convenience wrapper: scan all agents in a CWE-1400 domain.

        T-SCAN-REFACTOR Task 4: now a thin shortcut over ``assemble_agents_scan``.
        Equivalent to:

            scan_agents(
                agents=[a.meta.name for a in registry.get_agents_by_domain(domain)],
                ...
            )

        The response shape additions versus pre-T-SCAN-REFACTOR:
        - Init-page now carries ``agents_excluded_by_relevance`` (the per-agent
          language relevance filter is applied via the underlying primitive).

        The response shape additions versus the old domain-scoped scan are
        purely additive; no existing key changed type or semantics.

        Use ``scan_agents`` directly to scan an arbitrary subset of agents
        (e.g., 2 of 10 in a domain, or agents from multiple domains).

        Args:
            domain: CWE-1400 domain name (e.g. "injection-input-handling").
            target: PRD §5 target spec dict.
            thoroughness: passed through ("standard" | "deep").
            project_root: optional project root for exclusions + trust_status.
            cursor: opaque pagination token; None requests init page.
            page_size: max code chunks per page (default 50).

        Returns:
            Same shape as ``assemble_agents_scan``.

        Raises:
            ValueError: if domain is unknown or the underlying agents-scan
                raises (cursor binding mismatch, etc.).
        """
        agents_in_domain = self._registry.get_agents_by_domain(domain)
        if not agents_in_domain:
            available = sorted(self._registry.list_domains().keys())
            raise ValueError(
                f"Unknown or empty domain: {domain!r}. "
                f"Available domains: {available}."
            )
        agent_names = [a.meta.name for a in agents_in_domain]

        return self.assemble_agents_scan(
            agents=agent_names,
            target=target,
            thoroughness=thoroughness,
            project_root=project_root,
            cursor=cursor,
            page_size=page_size,
        )

    def assemble_agents_scan(
        self,
        agents: list[str],
        target: dict[str, Any],
        thoroughness: str = "standard",
        project_root: Path | None = None,
        *,
        cursor: str | None = None,
        page_size: int = 50,
    ) -> dict[str, Any]:
        """Assemble paginated scan payloads for a custom selection of agents.

        T-SCAN-REFACTOR primitive (spec section 5.1). Generalizes
        ``assemble_domain_scan`` to an arbitrary agents list; the cursor binds
        to ``(target_hash, agents_hash)`` (Option β) rather than just the
        target. Per-agent language relevance filter applied on init page;
        excluded agents surface in ``agents_excluded_by_relevance`` field.

        The response has TWO shapes keyed by the cursor discriminator:

        **Init page (cursor is None):** Returns per-agent metadata (and, if
        ``project_root`` is set, agent-scoped exclusions) without any code,
        plus the relevance-filter exclusion list. Each per-agent ``agents``
        entry carries ``agent_name`` and ``meta`` but NO ``core_prompt`` and
        NO ``code``. There is NO top-level ``prompts`` dict — orchestrators
        fetch each agent's prompt lazily via ``get_agent_prompt`` on first
        encounter and cache for reuse across code pages.
        ``code_chunks_on_page == 0`` and ``offset == 0``. ``next_cursor``
        encodes offset=0 when files exist (pointing at the first code page);
        it is None when there is nothing to paginate (empty target or all
        agents filtered out).

        **Code page (cursor is set):** Emits a paged slice of code chunks
        fanned out per agent. Per-agent entries carry ``code``,
        ``resolved_files``, ``meta`` — no ``core_prompt``, no ``exclusions``
        (exclusions are init-only). ``trust_status`` is re-emitted at the
        top level when ``project_root`` is provided so any single page
        carries the quarantine counts. Code pages do NOT re-emit
        ``agents_excluded_by_relevance``; the cursor's ``agents_hash``
        already binds the kept set so it cannot drift between pages.

        ``agents_excluded_by_relevance`` (init page only, top-level): list
        of dicts describing agents dropped by the relevance filter (each
        with ``agent_name``, ``reason``, ``agent_languages``,
        ``target_languages``). Code pages do NOT re-emit this field; the
        cursor's ``agents_hash`` already binds the kept set.

        Note: if files are added/deleted between init and code pages,
        ``total_files`` may shift but the cursor ``offset`` is interpreted
        on the current page's resolved file list. An out-of-bounds offset
        (e.g., file deleted under the cursor) results in an empty page and
        ``next_cursor=None`` — clean termination rather than an error. The
        caller's accumulated results from prior pages remain valid but may
        be incomplete. This is expected behavior for a stateless cursor
        scheme.

        Cursor encoding (Option β):
            cursor = base64url(json({
                "target_hash":  sha256(canonical_target_json)[:16],
                "agents_hash":  sha256(",".join(sorted(agents)))[:16],
                "offset":       <int>
            }))

        Args:
            agents: list of registered agent names. Must be non-empty; every
                name must exist in the registry.
            target: PRD §5 target spec dict.
            thoroughness: passed through to per-agent assemble_scan
                ("standard" | "deep").
            project_root: optional project root for exclusions + trust_status.
            cursor: opaque pagination token from a previous call; None
                requests the init page.
            page_size: max number of resolved code chunks per page (default 50).

        Returns:
            Dict with keys shared across both shapes:
                agents: list[dict[str, Any]]
                next_cursor: str | None
                page_size: int
                total_files: int
                offset: int
                code_chunks_on_page: int
                trust_status: dict  (only when project_root is provided)
            Init-page only:
                agents_excluded_by_relevance: list[dict] -- {agent_name, reason,
                    agent_languages, target_languages}
            Neither shape emits a top-level ``prompts`` key; callers must use
            ``get_agent_prompt(agent_name, thoroughness)`` instead.

        Validation order (errors raise in this priority — test order matters):
            1. agents list non-empty
            2. agents list contains no non-string elements (E1)
            3. agents list contains no duplicates (E1)
            4. page_size in [1, 500] (E2: lower + upper bound)
            5. all agent names resolve in the registry

        Errors raise as ValueError with messages telling the caller (a) what
        is wrong and (b) how to fix it.

        Raises:
            ValueError: if `agents` is empty, contains a non-string element,
                contains duplicates, contains an unknown agent name, if
                `page_size` is outside [1, 500], or if cursor is bound to a
                different target / agents list / is malformed.
        """
        # ---- Validation (order documented in docstring above) ----
        # Priority 1: agents list non-empty.
        if not agents:
            raise ValueError(
                "agents list is empty; pass at least one registered agent name. "
                "Use list_agents() to discover names."
            )
        # Priority 2: E1 (Marco approved Option B) — reject non-string entries
        # with actionable error.
        non_string = [a for a in agents if not isinstance(a, str)]
        if non_string:
            raise ValueError(
                f"agents must be a list of strings; got non-string element(s): "
                f"{non_string!r}. Pass agent names as strings (e.g., 'sqli')."
            )
        # Priority 3: E1 — reject duplicates with actionable error.
        duplicates = sorted({a for a in agents if agents.count(a) > 1})
        if duplicates:
            raise ValueError(
                f"agents list contains duplicate name(s): {duplicates}. "
                f"Each agent must appear at most once. "
                f"Deduplicate the input list before calling assemble_agents_scan."
            )
        # Priority 4: E2 (Marco approved Option B) — enforce page_size bounds at
        # engine layer for symmetry with JSON-schema constraint on MCP callers.
        if page_size < 1 or page_size > 500:
            raise ValueError(
                f"page_size must be in [1, 500]; got {page_size}. "
                f"The 500-item ceiling protects against oversize tool responses "
                f"(per X1-M1 finding). Reduce page_size or paginate via cursor."
            )
        # Priority 5: all agent names resolve in the registry.
        # Validate ALL unknown agents in one pass (friendlier for callers
        # passing several names — surface every unknown at once instead of
        # forcing N round-trips).
        unknown = [name for name in agents if self._registry.get_agent(name) is None]
        if unknown:
            raise ValueError(
                f"Unknown agent name(s): {sorted(unknown)}. "
                f"Use list_agents() to discover available names."
            )

        # ---- Hashing inputs (cursor binding — Option β) ----
        canonical_target = _json.dumps(target, sort_keys=True, separators=(",", ":"))
        target_hash = hashlib.sha256(canonical_target.encode("utf-8")).hexdigest()[:16]
        sorted_agents = sorted(agents)
        agents_hash = hashlib.sha256(",".join(sorted_agents).encode("utf-8")).hexdigest()[:16]

        # D1: treat empty-string cursor as None (init-page request).
        # MCP / JSON-RPC clients sometimes pass "" rather than null; the
        # original `if cursor:` truthiness check skipped decode but
        # `is_init_page = cursor is None` would have been False, sending
        # the function down the code-page branch with no binding validated.
        if cursor == "":
            cursor = None

        # ---- Cursor decode (preserves existing ValueError semantics) ----
        if cursor:
            try:
                raw = base64.urlsafe_b64decode(cursor.encode("ascii")).decode("utf-8")
                decoded = _json.loads(raw)
                cursor_target = decoded["target_hash"]
                cursor_agents = decoded["agents_hash"]
                offset = int(decoded["offset"])
            except (
                binascii.Error,
                _json.JSONDecodeError,
                UnicodeDecodeError,
                KeyError,
                TypeError,
                ValueError,
            ) as exc:
                raise ValueError(f"Invalid cursor: {exc}") from exc

            if cursor_target != target_hash:
                raise ValueError(
                    "cursor is bound to a different target; refusing to use"
                )
            if cursor_agents != agents_hash:
                raise ValueError(
                    "cursor is bound to a different agents list; refusing to use"
                )
            if offset < 0:
                raise ValueError("cursor offset is negative")
        else:
            offset = 0

        # ---- Resolve agents from registry; resolve target once ----
        agent_defs = [self._registry.get_agent(n) for n in agents]
        all_codes = resolve_target(target)
        total_files = len(all_codes)

        is_init_page = cursor is None

        # ---- Init page: relevance filter + metadata + exclusions ----
        if is_init_page:
            kept_agents, excluded = _filter_relevant_agents(all_codes, agent_defs)
            # D2: sort kept_agents alphabetically by meta.name so response
            # order is input-order-invariant. Cursor's agents_hash is already
            # built from sorted(agents), so this mirrors the binding contract:
            # same input set → same cursor → same response order regardless
            # of caller's input list ordering.
            kept_agents = sorted(kept_agents, key=lambda a: a.meta.name)

            if project_root is not None:
                all_exclusions: list[Exclusion] | None = load_exclusions(project_root)
            else:
                all_exclusions = None

            agents_responses: list[dict[str, Any]] = []
            for a in kept_agents:
                entry: dict[str, Any] = {
                    "agent_name": a.meta.name,
                    "meta": self._agent_meta_summary(a),
                }
                if project_root is not None and all_exclusions is not None:
                    agent_exclusions = [
                        e for e in all_exclusions
                        if e.agent == a.meta.name and not e.quarantined
                    ]
                    entry["exclusions"] = [e.model_dump() for e in agent_exclusions]
                agents_responses.append(entry)

            # Compute next_cursor — None when nothing to paginate.
            # Note: kept_agents may be empty (all filtered out) — in that
            # case there's nothing to scan even if files exist.
            if total_files > 0 and kept_agents:
                next_cursor: str | None = base64.urlsafe_b64encode(
                    _json.dumps(
                        {
                            "target_hash": target_hash,
                            "agents_hash": agents_hash,
                            "offset": 0,
                        },
                        separators=(",", ":"),
                    ).encode("utf-8")
                ).decode("ascii")
            else:
                next_cursor = None

            result: dict[str, Any] = {
                "agents": agents_responses,
                "agents_excluded_by_relevance": excluded,
                "next_cursor": next_cursor,
                "page_size": page_size,
                "total_files": total_files,
                "code_chunks_on_page": 0,
                "offset": 0,
            }
            if project_root is not None:
                result["trust_status"] = self.verify_trust(
                    project_root=project_root, exclusions=all_exclusions
                )
            return result

        # ---- Code page (cursor was non-None) ----
        # Re-apply the relevance filter so the same kept_agents set is
        # iterated — must match init-page result deterministically since
        # cursor's agents_hash already binds the call.
        kept_agents, _excluded_unused = _filter_relevant_agents(all_codes, agent_defs)
        # D2: sort kept_agents alphabetically by meta.name so response
        # order is input-order-invariant (mirrors init-page sort + cursor
        # agents_hash contract).
        kept_agents = sorted(kept_agents, key=lambda a: a.meta.name)

        page_codes = all_codes[offset : offset + page_size]
        next_offset = offset + len(page_codes)
        if next_offset < total_files:
            next_cursor = base64.urlsafe_b64encode(
                _json.dumps(
                    {
                        "target_hash": target_hash,
                        "agents_hash": agents_hash,
                        "offset": next_offset,
                    },
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
            for a in kept_agents
        ]

        for entry in agents_responses:
            entry.pop("exclusions", None)
            entry.pop("trust_status", None)

        result = {
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

        # Phase 3b T3: stage_adaptive_script — C1 staging-path MCP tool.
        # Writes an UNSIGNED script to session-scoped staging so the
        # user reviews what is staged and promote_staged_script signs
        # what is staged (sha256-verified). Closes the C1 regeneration
        # vulnerability where approve-path LLM re-sent the source.
        tools.append({
            "name": "stage_adaptive_script",
            "description": (
                "Atomically write an unsigned adaptive analysis script to "
                "session-scoped staging (`.screw/staging/{session_id}/"
                "adaptive-scripts/`). Called by the generating subagent BEFORE "
                "composing the human review. The staged bytes persist on disk "
                "and become the source of truth for the subsequent "
                "promote_staged_script call — the user reviews what is staged, "
                "and promote signs what is staged, with sha256 verification "
                "preventing tamper (C1 trust invariant). Appends a `staged` "
                "event to .screw/local/pending-approvals.jsonl for audit. "
                "Idempotent on byte-identical re-stage; returns status=\"error\" "
                "with error=\"stage_name_collision\" on same name + different "
                "content. See design spec §3.1."
            ),
            "input_schema": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "project_root": {
                        "type": "string",
                        "description": "Absolute path to the project root.",
                    },
                    "script_name": {
                        "type": "string",
                        "description": (
                            "Filesystem-safe name (regex "
                            "`^[a-z0-9][a-z0-9-]{2,62}$`). Validated by the "
                            "shared `adaptive.script_name.validate_script_name` "
                            "(T2 consolidation) before any filesystem op."
                        ),
                    },
                    "source": {
                        "type": "string",
                        "description": (
                            "Python source code for the adaptive script. "
                            "Caller should have run `lint_adaptive_script` "
                            "BEFORE staging (pre-review), though staging itself "
                            "does not enforce this."
                        ),
                    },
                    "meta": {
                        "type": "object",
                        "description": (
                            "Partial meta dict that will eventually conform to "
                            "AdaptiveScriptMeta (minus signing fields). Must "
                            "include name, created, created_by, domain; may "
                            "include description, target_patterns."
                        ),
                    },
                    "session_id": {
                        "type": "string",
                        "description": (
                            "Scan session id. Validated against "
                            "`^[A-Za-z0-9_-]{1,64}$` (T1 part 4 allowlist, "
                            "I-opus-1/2 fix). Scopes the staging directory — "
                            "different session_ids get different dirs."
                        ),
                    },
                    "target_gap": {
                        "type": "object",
                        "description": (
                            "Optional coverage-gap metadata recorded in the "
                            "registry entry. Shape: "
                            "{type, file, line, agent}. Null for non-gap stages."
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

        # Phase 3b T4: promote_staged_script — THE C1 FIX. Sign + promote a
        # staged adaptive script, reading source + meta from the staging
        # directory on disk (no source/meta parameter, by construction).
        # The trust invariant: bytes_reviewed == bytes_signed == bytes_executed.
        tools.append({
            "name": "promote_staged_script",
            "description": (
                "Sign and promote a staged adaptive script — THE C1 FIX. Reads "
                "source and meta from the session-scoped staging directory on "
                "disk (no source/meta parameter, by construction), verifies the "
                "staging bytes match the registry-recorded sha256 (tamper-detect), "
                "then delegates to the shared _sign_script_bytes helper and "
                "appends a promoted/promoted_via_fallback/promoted_confirm_stale "
                "audit event. Promoted artifacts land in `.screw/custom-scripts/`. "
                "Returns status=\"error\" with error=\"tamper_detected\" on sha "
                "mismatch (preserves bytes for forensics), error=\"stale_staging\" "
                "when staged_at age exceeds the configured threshold unless "
                "confirm_stale=true, and error=\"fallback_required\" when the "
                "registry entry is missing (caller re-invokes with "
                "confirm_sha_prefix). See design spec §3.2."
            ),
            "input_schema": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "project_root": {
                        "type": "string",
                        "description": "Absolute path to the project root.",
                    },
                    "script_name": {
                        "type": "string",
                        "description": (
                            "Filesystem-safe name (regex "
                            "`^[a-z0-9][a-z0-9-]{2,62}$`) of the staged "
                            "script to promote."
                        ),
                    },
                    "session_id": {
                        "type": "string",
                        "description": (
                            "Scan session id the script was staged under "
                            "(allowlist `^[A-Za-z0-9_-]{1,64}$`)."
                        ),
                    },
                    "confirm_sha_prefix": {
                        "type": ["string", "null"],
                        "description": (
                            "Short sha256 prefix (first 8 hex chars) "
                            "re-supplied by the caller when the registry "
                            "lookup failed and a filesystem fallback walk "
                            "is used (Q3 fallback path). Null for the "
                            "normal registry-hit path."
                        ),
                    },
                    "confirm_stale": {
                        "type": "boolean",
                        "description": (
                            "When true, allows promotion even if the "
                            "staging entry is older than "
                            "`stale_staging_hours` (default 24). Caller "
                            "must re-type an explicit "
                            "`approve {name} confirm-stale` phrase."
                        ),
                    },
                },
                "required": [
                    "project_root",
                    "script_name",
                    "session_id",
                ],
            },
        })

        # Phase 3b T5: reject_staged_script — C1 staging-path decline tool.
        # Symmetric to promote_staged_script on the reject branch: deletes
        # staging files, appends a `rejected` audit event, and updates the
        # T18b decline tracking (.screw/local/adaptive_prompts.json) so the
        # same target is not re-proposed on the next scan. Idempotent:
        # re-rejecting after files are gone returns already_rejected.
        tools.append({
            "name": "reject_staged_script",
            "description": (
                "Delete the staging files for a rejected adaptive script and "
                "record a `rejected` audit event in the pending-approvals "
                "registry. Idempotent: a second reject on already-deleted "
                "staging returns status=\"already_rejected\" (success). Also "
                "updates `.screw/local/adaptive_prompts.json` — the existing "
                "T18b decline-tracking artifact — to add the target to the "
                "`declined` list so it is not re-proposed. See design spec §3.3."
            ),
            "input_schema": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "project_root": {
                        "type": "string",
                        "description": "Absolute path to the project root.",
                    },
                    "script_name": {
                        "type": "string",
                        "description": (
                            "Filesystem-safe name of the staged script to reject."
                        ),
                    },
                    "session_id": {
                        "type": "string",
                        "description": (
                            "Scan session id the script was staged under."
                        ),
                    },
                    "reason": {
                        "type": ["string", "null"],
                        "description": (
                            "Optional short rationale recorded in the audit "
                            "event (why the reviewer declined this script)."
                        ),
                    },
                },
                "required": [
                    "project_root",
                    "script_name",
                    "session_id",
                ],
            },
        })

        # Phase 3b T6: sweep_stale_staging — orphan GC for .screw/staging/.
        # Absorbs T-STAGING-ORPHAN-GC from the Phase 4+ backlog; covers both
        # new C1 staging artifacts (T3-T5) and legacy session-scoped
        # finalize-never-called dirs. See design spec §3.4.
        tools.append({
            "name": "sweep_stale_staging",
            "description": (
                "Clean up orphaned staging entries — session directories under "
                "`.screw/staging/` that are stale (older than max_age_days) or "
                "whose most-recent registry event is a terminal state "
                "(promoted / rejected / swept) but whose files were left behind. "
                "Absorbs the deferred T-STAGING-ORPHAN-GC backlog item: covers "
                "both the new C1 staging artifacts and legacy session-scoped "
                "finalize-never-called staging dirs. When dry_run=true, reports "
                "what would be removed without deleting anything. See design "
                "spec §3.4."
            ),
            "input_schema": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "project_root": {
                        "type": "string",
                        "description": "Absolute path to the project root.",
                    },
                    "max_age_days": {
                        "type": ["integer", "null"],
                        "description": (
                            "Maximum age (in days) before a staging entry is "
                            "considered stale. Null means read from config "
                            "(`staging_max_age_days`, default 14). Clamped to "
                            "[1, 365]."
                        ),
                    },
                    "dry_run": {
                        "type": "boolean",
                        "description": (
                            "When true, returns the list of entries that would "
                            "be removed without actually deleting files. Useful "
                            "for preview / CI assertions."
                        ),
                    },
                },
                "required": [
                    "project_root",
                ],
            },
        })

        # Phase 3b T7: list_adaptive_scripts — I6 MCP promotion of the
        # former cli/adaptive_cleanup entry point. Slash command was breaking
        # on cwd mismatch; the MCP tool resolves that because .mcp.json
        # already carries the correct --project argument.
        tools.append({
            "name": "list_adaptive_scripts",
            "description": (
                "List all adaptive scripts present at `.screw/custom-scripts/` "
                "with their validation status and per-script staleness "
                "information. Promoted from `cli/adaptive_cleanup.py` in PR #6 "
                "per I6 — slash-command invocation was breaking on `cwd` "
                "mismatch. Returns `{\"status\": \"ok\", \"scripts\": [{name, "
                "validated, signed_by, stale, stale_reason, ...}]}`. Behavior "
                "unchanged from T21. See design spec §3.5."
            ),
            "input_schema": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "project_root": {
                        "type": "string",
                        "description": "Absolute path to the project root.",
                    },
                },
                "required": [
                    "project_root",
                ],
            },
        })

        # Phase 3b T8: remove_adaptive_script — I6 MCP promotion (part 2)
        # of the former cli/adaptive_cleanup entry point. Confirmation-gated
        # (T21 semantics preserved): the caller must pass confirmed=true
        # after prompting the user for "yes" before any files are deleted.
        tools.append({
            "name": "remove_adaptive_script",
            "description": (
                "Delete an adaptive script pair (`{name}.py` + `{name}.meta.yaml`) "
                "from `.screw/custom-scripts/`, gated by an explicit "
                "`confirmed=true` flag (T21 confirmation-gate semantics "
                "preserved). Returns status=\"error\" / "
                "error=\"confirmation_required\" when confirmed is False or "
                "omitted, status=\"error\" / error=\"not_found\" when the "
                "script is missing, otherwise status=\"removed\". Promoted from "
                "`cli/adaptive_cleanup.py` in PR #6 per I6. See design spec §3.6."
            ),
            "input_schema": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "project_root": {
                        "type": "string",
                        "description": "Absolute path to the project root.",
                    },
                    "script_name": {
                        "type": "string",
                        "description": (
                            "Filesystem-safe name of the adaptive script to "
                            "remove (without `.py` / `.meta.yaml` suffix)."
                        ),
                    },
                    "confirmed": {
                        "type": "boolean",
                        "description": (
                            "Must be true to actually delete. False (or absent) "
                            "returns error=\"confirmation_required\" — the "
                            "caller is expected to prompt the user for \"yes\" "
                            "before retrying with confirmed=true."
                        ),
                    },
                },
                "required": [
                    "project_root",
                    "script_name",
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
