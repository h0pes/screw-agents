"""Output formatter for scan findings.

Supports three output formats:
- json: Pydantic model_dump serialization
- sarif: SARIF 2.1.0 (OASIS standard)
- markdown: Human-readable report with summary table and per-finding detail
"""

from __future__ import annotations

import json
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


def format_findings(
    findings: list[Finding],
    *,
    format: str = "json",
    scan_metadata: dict[str, Any] | None = None,
) -> str:
    """Dispatch findings to the requested output formatter.

    Args:
        findings: List of Finding objects to format.
        format: One of "json", "sarif", or "markdown".
        scan_metadata: Optional dict with keys like "target", "agents", "timestamp".

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
        return _format_markdown(findings, meta)
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
                "id": 1,
                "message": {"text": f"Source: {df.source}"},
                "physicalLocation": {"artifactLocation": {"uri": df.source_location}},
            },
            {
                "id": 2,
                "message": {"text": f"Sink: {df.sink}"},
                "physicalLocation": {"artifactLocation": {"uri": df.sink_location}},
            },
        ]

    return result


# ---------------------------------------------------------------------------
# Markdown formatter (stub — implemented in next commit)
# ---------------------------------------------------------------------------


def _format_markdown(findings: list[Finding], metadata: dict[str, Any]) -> str:
    raise NotImplementedError("Markdown formatter not yet implemented")
