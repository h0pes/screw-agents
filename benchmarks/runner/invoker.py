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
    failure_artifact_dir: Path | None = None


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
                    "--tools", "",
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
            artifact_path = _write_failure_artifact(
                config,
                invocation_id=invocation_id,
                attempt=attempt + 1,
                error=last_error,
                stdout=proc.stdout,
                stderr=proc.stderr,
                context=context,
            )
            _write_progress_event(
                config.progress_log_path,
                {
                    "status": "failed",
                    "invocation_id": invocation_id,
                    "attempt": attempt + 1,
                    "elapsed_seconds": round(elapsed, 3),
                    "returncode": proc.returncode,
                    "error": last_error,
                    **({"failure_artifact": str(artifact_path)} if artifact_path else {}),
                    **(context or {}),
                },
            )
            logger.warning("Attempt %d: %s", attempt + 1, last_error)
            continue

        result = _parse_output(proc.stdout, elapsed)
        artifact_path = None
        if not result.success:
            artifact_path = _write_failure_artifact(
                config,
                invocation_id=invocation_id,
                attempt=attempt + 1,
                error=result.error,
                stdout=proc.stdout,
                stderr=proc.stderr,
                context=context,
            )
        _write_progress_event(
            config.progress_log_path,
            {
                "status": "completed" if result.success else "failed",
                "invocation_id": invocation_id,
                "attempt": attempt + 1,
                "elapsed_seconds": round(elapsed, 3),
                "finding_count": len(result.findings),
                "error": result.error,
                **({"failure_artifact": str(artifact_path)} if artifact_path else {}),
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


def _write_failure_artifact(
    config: InvokerConfig,
    *,
    invocation_id: str,
    attempt: int,
    error: str,
    stdout: str,
    stderr: str,
    context: dict[str, Any] | None,
) -> Path | None:
    artifact_dir = config.failure_artifact_dir
    if artifact_dir is None and config.progress_log_path is not None:
        artifact_dir = config.progress_log_path.parent / "invocation_failures"
    if artifact_dir is None:
        return None

    artifact_dir.mkdir(parents=True, exist_ok=True)
    path = artifact_dir / f"{invocation_id}-attempt-{attempt}.json"
    payload = {
        "timestamp": datetime.now(UTC).isoformat(timespec="seconds"),
        "invocation_id": invocation_id,
        "attempt": attempt,
        "error": error,
        "context": context or {},
        "stdout": stdout,
        "stderr": stderr,
    }
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    return path


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
    findings_raw = _extract_findings_from_claude_payload(data)
    if findings_raw is not None:
        return InvokeResult(
            success=True, findings=findings_raw,
            raw_output=stdout[:500], duration_seconds=elapsed,
        )

    return InvokeResult(
        success=False, raw_output=stdout[:500],
        error="Could not extract findings array from response",
        duration_seconds=elapsed,
    )


def _extract_findings_from_claude_payload(data: dict[str, Any]) -> list[dict] | None:
    for key in ("structured_output", "result", "output", "response"):
        if key not in data:
            continue
        findings = _extract_findings_from_value(data[key])
        if findings is not None:
            return findings
    return None


def _extract_findings_from_value(value: Any) -> list[dict] | None:
    if isinstance(value, list) and _looks_like_findings_list(value):
        return value

    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except (json.JSONDecodeError, ValueError):
            parsed = _extract_json_value(value)
        if parsed is value:
            return None
        return _extract_findings_from_value(parsed)

    if isinstance(value, dict):
        for key in (
            "findings",
            "results",
            "vulnerabilities",
            "issues",
            "data",
            "response",
            "output",
            "structured_output",
            "result",
        ):
            if key not in value:
                continue
            findings = _extract_findings_from_value(value[key])
            if findings is not None:
                return findings

    return None


def _looks_like_findings_list(value: list[Any]) -> bool:
    if not value:
        return True
    expected_keys = {
        "cwe_id",
        "file",
        "start_line",
        "end_line",
        "message",
        "confidence",
        "kind",
        "location",
    }
    return all(isinstance(item, dict) and bool(expected_keys & item.keys()) for item in value)


def _extract_json_value(text: str) -> Any:
    """Try to find a JSON object or array in free-form text."""
    decoder = json.JSONDecoder()
    for index, char in enumerate(text):
        if char not in "[{":
            continue
        try:
            value, _ = decoder.raw_decode(text[index:])
        except json.JSONDecodeError:
            continue
        findings = _extract_findings_from_value(value)
        if findings is not None:
            return value
    return text
