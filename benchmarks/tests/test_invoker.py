"""Tests for the claude -p invoker."""
from __future__ import annotations

import json
import subprocess
from unittest.mock import patch, MagicMock

import pytest

from benchmarks.runner.invoker import invoke_claude, InvokerConfig, InvokeResult


def _mock_completed_process(stdout: str, returncode: int = 0):
    proc = MagicMock()
    proc.stdout = stdout
    proc.stderr = ""
    proc.returncode = returncode
    return proc


class TestInvokeClaude:
    def test_successful_invocation_returns_parsed_findings(self):
        findings_json = json.dumps({
            "result": "",
            "structured_output": [
                {"cwe_id": "CWE-79", "file": "view.js", "start_line": 10,
                 "end_line": 15, "confidence": 0.9, "message": "XSS via innerHTML"}
            ]
        })
        with patch("subprocess.run", return_value=_mock_completed_process(findings_json)):
            result = invoke_claude("Scan this code", InvokerConfig())
        assert result.success is True
        assert len(result.findings) == 1
        assert result.findings[0]["cwe_id"] == "CWE-79"

    def test_empty_findings_returns_empty_list(self):
        stdout = json.dumps({"result": "", "structured_output": []})
        with patch("subprocess.run", return_value=_mock_completed_process(stdout)):
            result = invoke_claude("Scan this code", InvokerConfig())
        assert result.success is True
        assert result.findings == []

    def test_non_json_stdout_returns_failure(self):
        with patch("subprocess.run", return_value=_mock_completed_process("not json")):
            result = invoke_claude("Scan this code", InvokerConfig())
        assert result.success is False
        assert result.findings == []
        assert "JSON" in result.error

    def test_nonzero_returncode_returns_failure(self):
        with patch("subprocess.run", return_value=_mock_completed_process("", returncode=1)):
            result = invoke_claude("Scan this code", InvokerConfig())
        assert result.success is False

    def test_retry_on_failure(self):
        fail = _mock_completed_process("", returncode=1)
        ok = _mock_completed_process(json.dumps({"result": "", "structured_output": []}))
        with patch("subprocess.run", side_effect=[fail, ok]):
            result = invoke_claude("Scan this code", InvokerConfig(max_retries=2, retry_delay=0.0))
        assert result.success is True

    def test_timeout_returns_failure(self):
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="claude", timeout=5)):
            result = invoke_claude("Scan this code", InvokerConfig(max_retries=1, retry_delay=0.0))
        assert result.success is False
        assert "Timeout" in result.error
