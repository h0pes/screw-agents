"""Render + write helper used by ``ScanEngine.finalize_scan_results``.

Produces JSON, Markdown, optional SARIF, and optional CSV reports under
``.screw/findings/`` with server-side exclusion matching and trust-status
accounting. The canonical entry point is
:meth:`screw_agents.engine.ScanEngine.finalize_scan_results`; this module
implements the rendering + file I/O half of the protocol while
``screw_agents.staging`` owns the incremental accumulation half.
"""

from __future__ import annotations

from collections import OrderedDict
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

from screw_agents.formatter import format_csv, format_findings
from screw_agents.learning import load_exclusions, match_exclusions
from screw_agents.models import Finding, MergedSource

if TYPE_CHECKING:
    from screw_agents.registry import AgentRegistry


# Phase 3b T19: severity rank for primary-finding selection within a merge
# bucket. Lower rank = higher priority. Anything not in the map (unknown or
# missing severity) ranks last via the dict.get default of 5 — this prevents
# an ill-formed severity from promoting to primary by accident. Lookup is
# case-normalized (``severity.lower()``) at the call site so a YAML agent
# emitting ``"High"`` (capitalized prose drift) still ranks as ``"high"``.
_SEVERITY_RANK: dict[str, int] = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}


def _merge_findings_augmentatively(findings: list[Finding]) -> list[Finding]:
    """Merge findings that represent the same vulnerability detected by
    multiple scan sources (e.g., a YAML agent AND an adaptive script).

    Dedup key: ``(location.file, location.line_start, classification.cwe)``.
    ``line_end`` is deliberately NOT part of the key — different scanners
    compute different line ranges for the same underlying issue and adding
    it would reduce merge rate, defeating the augmentative-merge goal.

    When duplicates exist, the function:

    1. Picks a primary finding by highest severity (critical > high > medium
       > low > info > unknown), then alphabetical agent name ascending, then
       first-in-input order (Python stable sort).
    2. Attaches a populated ``merged_from_sources`` list to the primary,
       typed as ``list[MergedSource]`` where each entry carries an
       ``agent`` + ``severity`` pair. The list includes ALL entries in
       the bucket — the primary's own detection is also represented as
       one ``MergedSource`` entry, so the list is the complete
       provenance of this merged finding. Order follows the ORIGINAL
       input order of the bucket, not sorted order — downstream
       consumers see the natural insertion ordering.
    3. Returns exactly one :class:`Finding` per ``(file, line_start, cwe)``
       bucket.

    Unmerged findings (single-entry buckets) pass through unchanged with
    ``merged_from_sources = None``. Bucket output order follows insertion
    order of the FIRST finding per key (``OrderedDict`` semantics).

    Args:
        findings: List of :class:`Finding` objects, possibly with duplicates.

    Returns:
        List of :class:`Finding` objects with duplicates merged.
    """
    buckets: OrderedDict[tuple[str, int, str], list[Finding]] = OrderedDict()
    for f in findings:
        key = (f.location.file, f.location.line_start, f.classification.cwe)
        buckets.setdefault(key, []).append(f)

    merged: list[Finding] = []
    for _key, group in buckets.items():
        if len(group) == 1:
            merged.append(group[0])
            continue

        # Deterministic primary selection: highest severity → alphabetical
        # agent → first-in-input (Python's sorted() is stable, so the
        # original list order resolves final ties).
        def _sort_key(f: Finding) -> tuple[int, str]:
            return (
                _SEVERITY_RANK.get(f.classification.severity.lower(), 5),
                f.agent,
            )

        primary = sorted(group, key=_sort_key)[0]

        # Build source list from the ORIGINAL group (preserves input order),
        # not from sorted order — this gives downstream consumers the
        # natural ordering they'd expect from insertion.
        sources = [
            MergedSource(agent=f.agent, severity=f.classification.severity)
            for f in group
        ]

        merged.append(
            primary.model_copy(update={"merged_from_sources": sources})
        )

    return merged

_GITIGNORE_CONTENT = (
    "# Scan results are point-in-time — don't track in version control\n"
    "findings/\n"
    "# Exclusions are curated team knowledge — DO track\n"
    "!learning/\n"
)


def render_and_write(
    project_root: Path,
    findings_raw: list[dict[str, Any]],
    agent_names: list[str],
    scan_metadata: dict[str, Any] | None = None,
    formats: list[str] | None = None,
    agent_registry: "AgentRegistry | None" = None,
) -> dict[str, Any]:
    """Render findings to disk under ``.screw/findings/`` and apply
    server-side exclusion matching.

    Called by :meth:`screw_agents.engine.ScanEngine.finalize_scan_results`
    once the staging buffer has been drained for a session. Kept as a
    module-level function (rather than an engine method) so unit tests can
    exercise the render/exclusion pipeline without constructing an engine
    and a session.

    Args:
        project_root: Absolute path to the project root.
        findings_raw: List of finding dicts (parsed as Finding models).
        agent_names: Agent names that produced findings (e.g. ["sqli"]).
        scan_metadata: Optional metadata dict (target, timestamp).
        formats: Output formats to write. Defaults to ``["json", "markdown"]``.
            Accepted values: ``"json"``, ``"markdown"``, ``"sarif"``, ``"csv"``.
        agent_registry: Optional registry threaded to ``format_findings`` for
            SARIF output (provides ``agent.meta.short_description`` per rule).

    Returns:
        Dict with keys:
            - files_written: dict[str, str] -- format name → file path
            - summary: dict -- total, suppressed, active, by_severity counts
            - exclusions_applied: list[dict] -- finding_id + exclusion_ref pairs
            - trust_status: dict -- 4-field trust verification counts
              (matches :meth:`ScanEngine.verify_trust` shape)

    Raises:
        ValueError: If ``.screw/`` exists as a non-directory (T6-I1) or is
            not accessible due to permissions (T6-I2).
    """
    if formats is None:
        formats = ["json", "markdown", "csv"]  # T19-M1 D7 (2026-04-24)
    # Parse findings via Pydantic
    findings = [Finding(**f) for f in findings_raw]

    # Phase 3b T19: augmentative merge BEFORE exclusion matching + format.
    # Findings that share (file, line_start, cwe) from different scan sources
    # (e.g., a YAML agent AND an adaptive script) collapse to a single primary
    # finding with `merged_from_sources` populated. Exclusion matching runs
    # against the merged set so an exclusion matching the primary's
    # `(file, line, agent)` still suppresses correctly; the primary's agent
    # field is retained as the severity/alphabetical winner.
    findings = _merge_findings_augmentatively(findings)

    # Apply exclusions server-side (correct scope semantics).
    # Wrap FileExistsError (T6-I1) and PermissionError (T6-I2) from the
    # learning → trust.load_config chain with actionable messages.
    try:
        exclusions = load_exclusions(project_root)
    except FileExistsError as exc:
        raise ValueError(
            f"A `.screw` path exists at {project_root / '.screw'} but is not a "
            f"directory. Remove or rename it before running screw-agents. "
            f"Original error: {exc}"
        ) from exc
    except PermissionError as exc:
        raise ValueError(
            f"Cannot access `.screw/` at {project_root / '.screw'}: permission "
            f"denied. Check directory permissions or run with appropriate user. "
            f"Original error: {exc}"
        ) from exc

    # Compute trust_status inline from the already-loaded exclusions (no
    # duplicate load_exclusions call). The 4-key shape matches
    # `ScanEngine.verify_trust` exactly — Phase 3b Task 14 will populate
    # the script_* fields; for now they are always 0.
    exclusion_quarantine_count = sum(1 for e in exclusions if e.quarantined)
    exclusion_active_count = len(exclusions) - exclusion_quarantine_count
    trust_status: dict[str, int] = {
        "exclusion_quarantine_count": exclusion_quarantine_count,
        "exclusion_active_count": exclusion_active_count,
        "script_quarantine_count": 0,  # Phase 3b populates
        "script_active_count": 0,  # Phase 3b populates
    }

    suppressed_count = 0
    exclusions_applied: list[dict[str, str]] = []

    for finding in findings:
        matches = match_exclusions(
            exclusions,
            file=finding.location.file,
            line=finding.location.line_start,
            code=finding.location.code_snippet or "",
            agent=finding.agent,
            function=finding.location.function,
        )
        if matches:
            finding.triage.excluded = True
            finding.triage.exclusion_ref = matches[0].id
            finding.triage.status = "suppressed"
            suppressed_count += 1
            exclusions_applied.append({
                "finding_id": finding.id,
                "exclusion_ref": matches[0].id,
            })

    # Create .screw/ directory structure. Wrap NotADirectoryError (when
    # `.screw` exists as a FILE — T6-I1) and PermissionError (T6-I2) with
    # actionable messages so users get remediation guidance, not a bare
    # OSError traceback.
    screw_dir = project_root / ".screw"
    findings_dir = screw_dir / "findings"
    learning_dir = screw_dir / "learning"
    try:
        findings_dir.mkdir(parents=True, exist_ok=True)
        learning_dir.mkdir(parents=True, exist_ok=True)
    except (FileExistsError, NotADirectoryError) as exc:
        raise ValueError(
            f"A `.screw` path exists at {screw_dir} but is not a directory. "
            f"Remove or rename it before running screw-agents. "
            f"Original error: {exc}"
        ) from exc
    except PermissionError as exc:
        raise ValueError(
            f"Cannot create `.screw/` at {screw_dir}: permission denied. "
            f"Check directory permissions or run with appropriate user. "
            f"Original error: {exc}"
        ) from exc

    gitignore = screw_dir / ".gitignore"
    if not gitignore.exists():
        gitignore.write_text(_GITIGNORE_CONTENT)

    # Determine file prefix
    agent_set = set(agent_names)
    if len(agent_set) == 1:
        prefix = agent_names[0]
    elif agent_set == {"sqli", "cmdi", "ssti", "xss"}:
        prefix = "injection"
    else:
        prefix = "scan"

    # Build metadata
    now = datetime.now(timezone.utc)
    ts = now.strftime("%Y-%m-%dT%H-%M-%S")
    meta = dict(scan_metadata or {})
    meta.setdefault("agents", agent_names)
    meta.setdefault("timestamp", now.strftime("%Y-%m-%dT%H:%M:%SZ"))

    # Format and write
    files_written: dict[str, str] = {}

    if "json" in formats:
        json_content = format_findings(
            findings, format="json", scan_metadata=meta,
            agent_registry=agent_registry,
        )
        json_path = findings_dir / f"{prefix}-{ts}.json"
        json_path.write_text(json_content)
        files_written["json"] = str(json_path)

    if "markdown" in formats:
        md_content = format_findings(
            findings, format="markdown", scan_metadata=meta,
            trust_status=trust_status, agent_registry=agent_registry,
        )
        md_path = findings_dir / f"{prefix}-{ts}.md"
        md_path.write_text(md_content)
        files_written["markdown"] = str(md_path)

    if "sarif" in formats:
        sarif_content = format_findings(
            findings, format="sarif", scan_metadata=meta,
            agent_registry=agent_registry,
        )
        sarif_path = findings_dir / f"{prefix}-{ts}.sarif.json"
        sarif_path.write_text(sarif_content)
        files_written["sarif"] = str(sarif_path)

    if "csv" in formats:
        csv_content = format_csv(findings, scan_metadata=meta)
        csv_path = findings_dir / f"{prefix}-{ts}.csv"
        csv_path.write_text(csv_content)
        files_written["csv"] = str(csv_path)

    # Build summary
    active_findings = [f for f in findings if not f.triage.excluded]
    by_severity: dict[str, int] = {}
    for f in active_findings:
        sev = f.classification.severity
        by_severity[sev] = by_severity.get(sev, 0) + 1

    return {
        "files_written": files_written,
        "summary": {
            "total": len(findings),
            "suppressed": suppressed_count,
            "active": len(active_findings),
            "by_severity": by_severity,
        },
        "exclusions_applied": exclusions_applied,
        "trust_status": trust_status,
    }
