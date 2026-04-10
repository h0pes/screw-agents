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
# SARIF 2.1.0 formatter (stub — implemented in next commit)
# ---------------------------------------------------------------------------


def _format_sarif(findings: list[Finding], metadata: dict[str, Any]) -> str:
    raise NotImplementedError("SARIF formatter not yet implemented")


# ---------------------------------------------------------------------------
# Markdown formatter (stub — implemented in next commit)
# ---------------------------------------------------------------------------


def _format_markdown(findings: list[Finding], metadata: dict[str, Any]) -> str:
    raise NotImplementedError("Markdown formatter not yet implemented")
