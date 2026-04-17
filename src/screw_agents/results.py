"""Scan results writer — formats, applies exclusions, writes to .screw/.

Collapses the subagent workflow steps (exclusion matching, formatting,
directory creation, file writing) into a single server-side operation.
This ensures results are always persisted regardless of subagent behavior.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from screw_agents.formatter import format_csv, format_findings
from screw_agents.learning import load_exclusions, match_exclusions
from screw_agents.models import Finding

_GITIGNORE_CONTENT = (
    "# Scan results are point-in-time — don't track in version control\n"
    "findings/\n"
    "# Exclusions are curated team knowledge — DO track\n"
    "!learning/\n"
)


def write_scan_results(
    project_root: Path,
    findings_raw: list[dict[str, Any]],
    agent_names: list[str],
    scan_metadata: dict[str, Any] | None = None,
    formats: list[str] | None = None,
) -> dict[str, Any]:
    """Write scan findings to .screw/findings/ with server-side exclusion matching.

    Creates .screw/ directory structure, applies exclusion matching using
    correct scope semantics, formats requested output files, writes them.

    Args:
        project_root: Absolute path to the project root.
        findings_raw: List of finding dicts (parsed as Finding models).
        agent_names: Agent names that produced findings (e.g. ["sqli"]).
        scan_metadata: Optional metadata dict (target, timestamp).
        formats: Output formats to write. Defaults to ``["json", "markdown"]``.
            Accepted values: ``"json"``, ``"markdown"``, ``"sarif"``, ``"csv"``.

    Returns:
        Dict with keys:
            - files_written: dict[str, str] — format name → file path
            - summary: dict — total, suppressed, active, by_severity counts
            - exclusions_applied: list[dict] — finding_id + exclusion_ref pairs
            - trust_status: dict — 4-field trust verification counts
              (matches `ScanEngine.verify_trust` shape)

    Raises:
        ValueError: If `.screw/` exists as a non-directory (T6-I1) or is not
            accessible due to permissions (T6-I2).
    """
    if formats is None:
        formats = ["json", "markdown"]
    # Parse findings via Pydantic
    findings = [Finding(**f) for f in findings_raw]

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
        json_content = format_findings(findings, format="json", scan_metadata=meta)
        json_path = findings_dir / f"{prefix}-{ts}.json"
        json_path.write_text(json_content)
        files_written["json"] = str(json_path)

    if "markdown" in formats:
        md_content = format_findings(
            findings, format="markdown", scan_metadata=meta, trust_status=trust_status
        )
        md_path = findings_dir / f"{prefix}-{ts}.md"
        md_path.write_text(md_content)
        files_written["markdown"] = str(md_path)

    if "sarif" in formats:
        sarif_content = format_findings(findings, format="sarif", scan_metadata=meta)
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
