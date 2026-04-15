"""Output formatter for scan findings.

Supports three output formats:
- json: Pydantic model_dump serialization
- sarif: SARIF 2.1.0 (OASIS standard)
- markdown: Human-readable report with summary table and per-finding detail
"""

from __future__ import annotations

import json
from collections import Counter
from typing import Any

from screw_agents.models import Finding

_SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/"
    "sarif-2.1/schema/sarif-schema-2.1.0.json"
)

_SEVERITY_TO_SARIF_LEVEL: dict[str, str] = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
}

_SEVERITY_ORDER = ["critical", "high", "medium", "low"]


def format_findings(
    findings: list[Finding],
    *,
    format: str = "json",
    scan_metadata: dict[str, Any] | None = None,
    trust_status: dict[str, int] | None = None,
) -> str:
    """Dispatch findings to the requested output formatter.

    Args:
        findings: List of Finding objects to format.
        format: One of "json", "sarif", or "markdown".
        scan_metadata: Optional dict with keys like "target", "agents", "timestamp".
        trust_status: Optional trust verification counts with the 4-key shape
            returned by `ScanEngine.verify_trust`. Only the markdown formatter
            surfaces this (as a "Trust verification" section); JSON and SARIF
            ignore it.

    Returns:
        Formatted string output.

    Raises:
        ValueError: If format is not one of the supported values.
    """
    meta = scan_metadata or {}
    if format == "json":
        return _format_json(findings)
    if format == "sarif":
        return _format_sarif(findings, meta)
    if format == "markdown":
        return _format_markdown(findings, meta, trust_status=trust_status)
    raise ValueError(f"Unsupported format: {format!r}. Choose 'json', 'sarif', or 'markdown'.")


# ---------------------------------------------------------------------------
# JSON formatter
# ---------------------------------------------------------------------------


def _format_json(findings: list[Finding]) -> str:
    """Serialize findings as a JSON array using Pydantic model_dump."""
    data = [f.model_dump() for f in findings]
    return json.dumps(data, indent=2)


# ---------------------------------------------------------------------------
# SARIF 2.1.0 formatter
# ---------------------------------------------------------------------------


def _format_sarif(findings: list[Finding], metadata: dict[str, Any]) -> str:
    """Produce a SARIF 2.1.0 document from findings."""
    rules = _sarif_rules(findings)
    results = [_sarif_result(f) for f in findings]

    doc: dict[str, Any] = {
        "$schema": _SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "screw-agents",
                        "informationUri": "https://github.com/h0pes/screw-agents",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(doc, indent=2)


def _sarif_rules(findings: list[Finding]) -> list[dict[str, Any]]:
    """Build deduplicated rules list from the findings' CWE IDs."""
    seen: dict[str, dict[str, Any]] = {}
    for f in findings:
        cwe = f.classification.cwe
        if cwe not in seen:
            seen[cwe] = {
                "id": cwe,
                "name": f.classification.cwe_name,
                "shortDescription": {"text": f.classification.cwe_name},
                "helpUri": (
                    f"https://cwe.mitre.org/data/definitions/{cwe.replace('CWE-', '')}.html"
                ),
                "properties": {
                    "tags": [f.classification.severity],
                },
            }
    return list(seen.values())


def _sarif_result(finding: Finding) -> dict[str, Any]:
    """Convert a single Finding to a SARIF result object."""
    level = _SEVERITY_TO_SARIF_LEVEL.get(finding.classification.severity, "warning")

    loc = finding.location
    physical_location: dict[str, Any] = {
        "artifactLocation": {"uri": loc.file},
        "region": {"startLine": loc.line_start},
    }
    if loc.line_end is not None:
        physical_location["region"]["endLine"] = loc.line_end

    result: dict[str, Any] = {
        "ruleId": finding.classification.cwe,
        "level": level,
        "message": {"text": finding.analysis.description},
        "locations": [{"physicalLocation": physical_location}],
        "fingerprints": {"finding/v1": finding.id},
    }

    if loc.data_flow is not None:
        df = loc.data_flow
        result["relatedLocations"] = [
            {
                "id": 0,
                "message": {"text": f"Source: {df.source} at {df.source_location}"},
            },
            {
                "id": 1,
                "message": {"text": f"Sink: {df.sink} at {df.sink_location}"},
            },
        ]

    return result


# ---------------------------------------------------------------------------
# Markdown formatter
# ---------------------------------------------------------------------------


def _render_trust_section_markdown(trust_status: dict[str, int]) -> list[str]:
    """Render a Trust verification section for scan reports.

    Surfaces:
    - quarantined exclusions (untrusted/unsigned/signature failure)
    - active (trusted) exclusion count
    - Phase 3b placeholder for quarantined scripts
    - pointers to the CLI remediation subcommands

    Returns an empty list when trust_status is a no-op (all-zero). Callers
    should still get the clean no-op behavior (no section rendered).
    """
    quarantine = trust_status.get("exclusion_quarantine_count", 0)
    active = trust_status.get("exclusion_active_count", 0)
    script_quarantine = trust_status.get("script_quarantine_count", 0)
    script_active = trust_status.get("script_active_count", 0)

    if (
        quarantine == 0
        and active == 0
        and script_quarantine == 0
        and script_active == 0
    ):
        return []

    lines: list[str] = ["## Trust verification", ""]
    if quarantine > 0:
        noun = "exclusion" if quarantine == 1 else "exclusions"
        lines.append(
            f"- **{quarantine} {noun} quarantined** "
            f"(unsigned or signed by untrusted key)"
        )
        lines.append(
            "  - Review each with `screw-agents validate-exclusion <id>` "
            "or run `screw-agents migrate-exclusions` to sign them in bulk"
        )
    if active > 0:
        noun = "exclusion" if active == 1 else "exclusions"
        lines.append(f"- {active} trusted {noun} applied")
    if script_quarantine > 0:
        noun = "script" if script_quarantine == 1 else "scripts"
        lines.append(
            f"- **{script_quarantine} adaptive {noun} quarantined** "
            "(Phase 3b — see `screw-agents validate-script <name>`)"
        )
    if script_active > 0:
        noun = "script" if script_active == 1 else "scripts"
        lines.append(f"- {script_active} trusted adaptive {noun} loaded")
    lines.append("")  # trailing blank line before next section
    return lines


def _format_markdown(
    findings: list[Finding],
    metadata: dict[str, Any],
    trust_status: dict[str, int] | None = None,
) -> str:
    """Build a human-readable Markdown security scan report."""
    lines: list[str] = []

    # --- Header ---
    lines.append("# Security Scan Report")
    lines.append("")

    target = metadata.get("target", "")
    agents = metadata.get("agents", [])
    timestamp = metadata.get("timestamp", "")

    if target or agents or timestamp:
        if target:
            lines.append(f"**Target:** `{target}`")
        if agents:
            lines.append(f"**Agents:** {', '.join(agents)}")
        if timestamp:
            lines.append(f"**Scan date:** {timestamp}")
        lines.append("")

    # --- Trust verification (Task 11) ---
    if trust_status is not None:
        lines.extend(_render_trust_section_markdown(trust_status))

    # --- Summary ---
    lines.append("## Summary")
    lines.append("")

    if not findings:
        lines.append("No findings detected.")
        return "\n".join(lines)

    counts: Counter[str] = Counter(f.classification.severity for f in findings)
    total = len(findings)

    lines.append(f"**Total findings:** {total}")
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("| -------- | ----- |")
    for sev in _SEVERITY_ORDER:
        count = counts.get(sev, 0)
        if count:
            lines.append(f"| {sev.capitalize()} | {count} |")
    lines.append("")

    # --- Findings Overview table ---
    lines.append("## Findings Overview")
    lines.append("")
    lines.append("| ID | Severity | Confidence | Agent | CWE | File | Line |")
    lines.append("| -- | -------- | ---------- | ----- | --- | ---- | ---- |")
    for f in findings:
        loc = f.location
        cwe = f.classification.cwe
        cwe_link = (
            f"[{cwe}](https://cwe.mitre.org/data/definitions/{cwe.replace('CWE-', '')}.html)"
        )
        lines.append(
            f"| {f.id} | {f.classification.severity.capitalize()} "
            f"| {f.classification.confidence.capitalize()} "
            f"| {f.agent} | {cwe_link} | `{loc.file}` | {loc.line_start} |"
        )
    lines.append("")

    # --- Detailed Findings ---
    lines.append("## Detailed Findings")
    lines.append("")

    for f in findings:
        _append_finding_detail(lines, f)

    return "\n".join(lines)


def _append_finding_detail(lines: list[str], f: Finding) -> None:
    """Append the detail section for a single finding."""
    cwe = f.classification.cwe
    cwe_url = f"https://cwe.mitre.org/data/definitions/{cwe.replace('CWE-', '')}.html"

    lines.append(f"### {f.id} — {f.classification.cwe_name}")
    lines.append("")

    # Classification badge row
    lines.append(
        f"**Severity:** {f.classification.severity.upper()}  "
        f"**Confidence:** {f.classification.confidence.capitalize()}  "
        f"**CWE:** [{cwe}]({cwe_url})"
    )
    if f.classification.owasp_top10:
        lines.append(f"**OWASP Top 10:2025:** {f.classification.owasp_top10}")
    lines.append("")

    # Location
    loc = f.location
    loc_line = f"**File:** `{loc.file}` **Line:** {loc.line_start}"
    if loc.line_end is not None:
        loc_line += f"–{loc.line_end}"
    if loc.function:
        loc_line += f"  **Function:** `{loc.function}`"
    if loc.class_name:
        loc_line += f"  **Class:** `{loc.class_name}`"
    lines.append(loc_line)
    lines.append("")

    # Analysis
    lines.append(f"**Description:** {f.analysis.description}")
    lines.append("")
    if f.analysis.impact:
        lines.append(f"**Impact:** {f.analysis.impact}")
        lines.append("")
    if f.analysis.exploitability:
        lines.append(f"**Exploitability:** {f.analysis.exploitability}")
        lines.append("")

    # Data flow table
    if loc.data_flow is not None:
        df = loc.data_flow
        lines.append("**Data Flow:**")
        lines.append("")
        lines.append("| | Location | Expression |")
        lines.append("| -- | -------- | ---------- |")
        lines.append(f"| **Source** | `{df.source_location}` | `{df.source}` |")
        lines.append(f"| **Sink** | `{df.sink_location}` | `{df.sink}` |")
        lines.append("")

    # Code snippet
    if loc.code_snippet:
        lines.append("**Code Snippet:**")
        lines.append("")
        lines.append("```")
        lines.append(loc.code_snippet)
        lines.append("```")
        lines.append("")

    # Remediation
    lines.append(f"**Recommendation:** {f.remediation.recommendation}")
    lines.append("")

    if f.remediation.fix_code:
        lines.append("**Fix:**")
        lines.append("")
        lines.append("```")
        lines.append(f.remediation.fix_code)
        lines.append("```")
        lines.append("")

    if f.remediation.references:
        lines.append("**References:**")
        lines.append("")
        for ref in f.remediation.references:
            lines.append(f"- {ref}")
        lines.append("")

    # False-positive reasoning
    if f.analysis.false_positive_reasoning:
        lines.append(f"**FP Reasoning:** {f.analysis.false_positive_reasoning}")
        lines.append("")

    lines.append("---")
    lines.append("")
