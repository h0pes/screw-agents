"""bentoo-sarif read/write.

bentoo-sarif is plain SARIF 2.1.0 with a minimal subset:
    runs[0].results[*] each with:
        ruleId       — "CWE-<id>"
        kind         — "fail" or "pass"
        message.text — CVE ID or free-form
        locations[*].physicalLocation.artifactLocation.uri
        locations[*].physicalLocation.region.{startLine, endLine}
        locations[*].logicalLocations[*].name   (function name, optional)

We parse/emit with stdlib json + pydantic models, no external SARIF library
(sarif-om on PyPI is unmaintained; hand-roll is 120 lines).
"""
from __future__ import annotations

import json
from pathlib import Path

from benchmarks.runner.models import CodeLocation, Finding, FindingKind


def load_bentoo_sarif(path: Path) -> list[Finding]:
    """Parse a bentoo-sarif file into a flat list of Finding objects.

    Raises ValueError on malformed input (missing ruleId, unknown kind, etc.).
    """
    raw = json.loads(Path(path).read_text())
    findings: list[Finding] = []
    runs = raw.get("runs", [])
    for run in runs:
        for result in run.get("results", []):
            findings.extend(_result_to_findings(result))
    return findings


def _result_to_findings(result: dict) -> list[Finding]:
    """Convert one SARIF result (may have multiple locations) to Findings."""
    rule_id = result.get("ruleId")
    if not rule_id:
        raise ValueError("SARIF result missing ruleId")
    kind_str = result.get("kind", "fail")
    try:
        kind = FindingKind(kind_str)
    except ValueError as exc:
        raise ValueError(f"Unknown SARIF kind: {kind_str!r}") from exc

    message_text = result.get("message", {}).get("text", "")
    cve_id = message_text if message_text.startswith("CVE-") else None

    findings: list[Finding] = []
    for loc in result.get("locations", []):
        phys = loc.get("physicalLocation", {})
        art = phys.get("artifactLocation", {})
        region = phys.get("region", {})
        logical = loc.get("logicalLocations") or []
        function_name = logical[0].get("name") if logical else None

        findings.append(Finding(
            cwe_id=rule_id,
            kind=kind,
            cve_id=cve_id,
            message=message_text or None,
            location=CodeLocation(
                file=art.get("uri", "<unknown>"),
                start_line=int(region.get("startLine", 0)),
                end_line=int(region.get("endLine", region.get("startLine", 0))),
                function_name=function_name,
            ),
        ))
    return findings


def write_bentoo_sarif(
    path: Path,
    findings: list[Finding],
    *,
    tool_name: str = "screw-agents",
) -> None:
    """Serialize Findings as a bentoo-sarif document."""
    results = [_finding_to_result(f) for f in findings]
    doc = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": tool_name}},
                "results": results,
            }
        ],
    }
    Path(path).write_text(json.dumps(doc, indent=2))


def _finding_to_result(f: Finding) -> dict:
    logical = []
    if f.location.function_name:
        logical.append({"name": f.location.function_name, "kind": "function"})
    result = {
        "kind": f.kind.value,
        "message": {"text": f.message or f.cve_id or ""},
        "ruleId": f.cwe_id,
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": f.location.file},
                    "region": {
                        "startLine": f.location.start_line,
                        "endLine": f.location.end_line,
                    },
                },
                **({"logicalLocations": logical} if logical else {}),
            }
        ],
    }
    return result
