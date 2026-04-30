"""Wrapper around `claude -p` for batch benchmark evaluation.

Handles JSON output parsing, retry with backoff, and throttling.
"""
from __future__ import annotations

import json
import logging
import subprocess
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

logger = logging.getLogger(__name__)


@dataclass
class InvokerConfig:
    """Configuration for the Claude invoker."""
    max_retries: int = 3
    retry_delay: float = 2.0       # seconds, doubles each retry
    throttle_delay: float = 2.0    # seconds between calls
    timeout: int = 300             # seconds per call
    max_turns: int = 1
    progress_log_path: Path | None = None


@dataclass
class InvokeResult:
    """Result from a single Claude invocation."""
    success: bool
    findings: list[dict] = field(default_factory=list)
    raw_output: str = ""
    error: str = ""
    duration_seconds: float = 0.0


def invoke_claude(
    prompt: str,
    config: InvokerConfig,
    context: dict[str, Any] | None = None,
) -> InvokeResult:
    """Send a prompt to Claude via `claude -p` and parse structured findings.

    Args:
        prompt: The full prompt including detection knowledge and code.
        config: Invoker configuration.

    Returns:
        InvokeResult with parsed findings or error details.
    """
    last_error = ""
    for attempt in range(config.max_retries):
        if attempt > 0:
            delay = config.retry_delay * (2 ** (attempt - 1))
            logger.info("Retry %d/%d after %.1fs", attempt + 1, config.max_retries, delay)
            time.sleep(delay)

        start = time.monotonic()
        invocation_id = uuid4().hex
        _write_progress_event(
            config.progress_log_path,
            {
                "status": "started",
                "invocation_id": invocation_id,
                "attempt": attempt + 1,
                "max_retries": config.max_retries,
                "timeout_seconds": config.timeout,
                "prompt_chars": len(prompt),
                **(context or {}),
            },
        )
        try:
            proc = subprocess.run(  # noqa: S603, S607
                [  # noqa: S607
                    "claude", "-p",
                    "--output-format", "json",
                    "--max-turns", str(config.max_turns),
                ],
                input=prompt,
                capture_output=True,
                text=True,
                timeout=config.timeout,
            )
        except subprocess.TimeoutExpired:
            elapsed = time.monotonic() - start
            last_error = f"Timeout after {config.timeout}s"
            _write_progress_event(
                config.progress_log_path,
                {
                    "status": "timeout",
                    "invocation_id": invocation_id,
                    "attempt": attempt + 1,
                    "elapsed_seconds": round(elapsed, 3),
                    "error": last_error,
                    **(context or {}),
                },
            )
            logger.warning("Attempt %d: %s", attempt + 1, last_error)
            continue

        elapsed = time.monotonic() - start

        if proc.returncode != 0:
            last_error = f"Exit code {proc.returncode}: {proc.stderr[:200]}"
            _write_progress_event(
                config.progress_log_path,
                {
                    "status": "failed",
                    "invocation_id": invocation_id,
                    "attempt": attempt + 1,
                    "elapsed_seconds": round(elapsed, 3),
                    "returncode": proc.returncode,
                    "error": last_error,
                    **(context or {}),
                },
            )
            logger.warning("Attempt %d: %s", attempt + 1, last_error)
            continue

        result = _parse_output(proc.stdout, elapsed)
        _write_progress_event(
            config.progress_log_path,
            {
                "status": "completed" if result.success else "failed",
                "invocation_id": invocation_id,
                "attempt": attempt + 1,
                "elapsed_seconds": round(elapsed, 3),
                "finding_count": len(result.findings),
                "error": result.error,
                **(context or {}),
            },
        )
        return result

    return InvokeResult(success=False, error=last_error)


def _write_progress_event(path: Path | None, event: dict[str, Any]) -> None:
    if path is None:
        return
    payload = {
        "timestamp": datetime.now(UTC).isoformat(timespec="seconds"),
        **event,
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(payload, sort_keys=True) + "\n")


def _parse_output(stdout: str, elapsed: float) -> InvokeResult:
    """Parse claude --output-format json stdout into findings."""
    try:
        data = json.loads(stdout)
    except (json.JSONDecodeError, ValueError) as exc:
        return InvokeResult(
            success=False, raw_output=stdout[:500],
            error=f"JSON parse error: {exc}", duration_seconds=elapsed,
        )

    # claude --output-format json returns {"result": "...", "structured_output": ...}
    findings_raw = data.get("structured_output")
    if findings_raw is None:
        findings_raw = data.get("result", "")

    # If structured_output is a string, try to parse it as JSON
    if isinstance(findings_raw, str):
        try:
            findings_raw = json.loads(findings_raw)
        except (json.JSONDecodeError, ValueError):
            findings_raw = _extract_json_array(findings_raw)

    if isinstance(findings_raw, list):
        return InvokeResult(
            success=True, findings=findings_raw,
            raw_output=stdout[:500], duration_seconds=elapsed,
        )

    if isinstance(findings_raw, dict) and "findings" in findings_raw:
        return InvokeResult(
            success=True, findings=findings_raw["findings"],
            raw_output=stdout[:500], duration_seconds=elapsed,
        )

    return InvokeResult(
        success=False, raw_output=stdout[:500],
        error="Could not extract findings array from response",
        duration_seconds=elapsed,
    )


def _extract_json_array(text: str) -> list | str:
    """Try to find a JSON array in free-form text."""
    start = text.find("[")
    if start == -1:
        return text
    depth = 0
    for i in range(start, len(text)):
        if text[i] == "[":
            depth += 1
        elif text[i] == "]":
            depth -= 1
            if depth == 0:
                try:
                    return json.loads(text[start:i + 1])
                except json.JSONDecodeError:
                    return text
    return text
