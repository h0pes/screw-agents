"""Scan results writer — formats, applies exclusions, writes to .screw/.

Collapses the subagent workflow steps (exclusion matching, formatting,
directory creation, file writing) into a single server-side operation.
This ensures results are always persisted regardless of subagent behavior.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from screw_agents.formatter import format_findings
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
) -> dict[str, Any]:
    """Write scan findings to .screw/findings/ with server-side exclusion matching.

    Creates .screw/ directory structure, applies exclusion matching using
    correct scope semantics, formats as JSON + Markdown, writes files.

    Args:
        project_root: Absolute path to the project root.
        findings_raw: List of finding dicts (parsed as Finding models).
        agent_names: Agent names that produced findings (e.g. ["sqli"]).
        scan_metadata: Optional metadata dict (target, timestamp).

    Returns:
        Dict with keys:
            - files_written: list[str] — paths to JSON and Markdown files
            - summary: dict — total, suppressed, active, by_severity counts
            - exclusions_applied: list[dict] — finding_id + exclusion_ref pairs
    """
    # Parse findings via Pydantic
    findings = [Finding(**f) for f in findings_raw]

    # Apply exclusions server-side (correct scope semantics)
    exclusions = load_exclusions(project_root)
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

    # Create .screw/ directory structure
    screw_dir = project_root / ".screw"
    findings_dir = screw_dir / "findings"
    learning_dir = screw_dir / "learning"
    findings_dir.mkdir(parents=True, exist_ok=True)
    learning_dir.mkdir(parents=True, exist_ok=True)

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
    json_content = format_findings(findings, format="json", scan_metadata=meta)
    md_content = format_findings(findings, format="markdown", scan_metadata=meta)

    json_path = findings_dir / f"{prefix}-{ts}.json"
    md_path = findings_dir / f"{prefix}-{ts}.md"
    json_path.write_text(json_content)
    md_path.write_text(md_content)

    # Build summary
    active_findings = [f for f in findings if not f.triage.excluded]
    by_severity: dict[str, int] = {}
    for f in active_findings:
        sev = f.classification.severity
        by_severity[sev] = by_severity.get(sev, 0) + 1

    return {
        "files_written": [str(json_path), str(md_path)],
        "summary": {
            "total": len(findings),
            "suppressed": suppressed_count,
            "active": len(active_findings),
            "by_severity": by_severity,
        },
        "exclusions_applied": exclusions_applied,
    }
