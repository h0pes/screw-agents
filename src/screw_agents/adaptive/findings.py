"""emit_finding and output buffer for adaptive scripts.

Scripts call `emit_finding(...)` to record a finding. The findings are collected
in a module-level buffer and serialized to JSON at script exit. The executor
(adaptive/executor.py) reads the JSON from the findings buffer path inside the
sandbox after the script terminates.

`emit_finding` does schema validation at call time — malformed arguments raise
ValueError immediately so bugs in generated scripts surface as runtime errors
with clear messages, not as malformed JSON blobs for the executor to puzzle over.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from typing import Literal


_CWE_PATTERN = re.compile(r"^CWE-\d+$")
_VALID_SEVERITIES = {"high", "medium", "low", "info"}


@dataclass
class FindingBuffer:
    """In-memory buffer for findings emitted by an adaptive script."""

    findings: list[dict] = field(default_factory=list)

    def to_json(self) -> str:
        return json.dumps(self.findings, sort_keys=True)


# Module-level singleton — one buffer per script execution. Reset before each run.
_buffer = FindingBuffer()


def get_buffer() -> FindingBuffer:
    """Return the current script's findings buffer."""
    return _buffer


def reset_buffer() -> None:
    """Clear the findings buffer. Called by the executor between script runs."""
    _buffer.findings.clear()


def emit_finding(
    *,
    cwe: str,
    file: str,
    line: int,
    message: str,
    severity: Literal["high", "medium", "low", "info"],
    code_snippet: str = "",
    column: int = 0,
) -> None:
    """Record a finding produced by an adaptive script.

    Validates every argument at emit time — a malformed call raises ValueError
    immediately, so bugs in generated scripts surface with clear error messages.

    Args:
        cwe: CWE identifier in the form "CWE-N".
        file: path relative to project root where the finding was detected.
        line: 1-indexed line number.
        message: human-readable description of the finding.
        severity: one of "high", "medium", "low", "info".
        code_snippet: optional excerpt of the offending code.
        column: 0-indexed column number.
    """
    if not _CWE_PATTERN.match(cwe):
        raise ValueError(f"invalid CWE identifier (must match 'CWE-\\d+'): {cwe!r}")
    if severity not in _VALID_SEVERITIES:
        raise ValueError(f"invalid severity (must be one of {_VALID_SEVERITIES}): {severity!r}")
    if not isinstance(line, int) or line < 1:
        raise ValueError(f"line must be a positive integer: {line!r}")

    _buffer.findings.append({
        "cwe": cwe,
        "file": file,
        "line": line,
        "column": column,
        "message": message,
        "severity": severity,
        "code_snippet": code_snippet,
    })


def flush_to_path(path: str) -> None:
    """Write the findings buffer to a JSON file. Called by the executor post-run.

    The executor sets up a sandbox-accessible write path and tells the script
    to flush to it. In practice, the script's `analyze()` entry point returns
    normally and the executor calls flush_to_path after.
    """
    with open(path, "w", encoding="utf-8") as f:
        f.write(_buffer.to_json())
