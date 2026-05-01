"""Tests for the claude -p invoker."""
# ruff: noqa: S101

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

from benchmarks.runner.invoker import InvokerConfig, invoke_claude
from benchmarks.scripts.show_invocation_progress import summarize_progress


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

    def test_invocation_disables_claude_tools(self):
        stdout = json.dumps({"result": "", "structured_output": []})
        with patch("subprocess.run", return_value=_mock_completed_process(stdout)) as run:
            result = invoke_claude("Scan this code", InvokerConfig())

        assert result.success is True
        command = run.call_args.args[0]
        assert command[command.index("--tools") + 1] == ""

    def test_empty_findings_returns_empty_list(self):
        stdout = json.dumps({"result": "", "structured_output": []})
        with patch("subprocess.run", return_value=_mock_completed_process(stdout)):
            result = invoke_claude("Scan this code", InvokerConfig())
        assert result.success is True
        assert result.findings == []

    def test_result_markdown_object_returns_parsed_findings(self):
        stdout = json.dumps(
            {
                "result": (
                    "```json\n"
                    "{\"findings\":[{\"cwe_id\":\"CWE-89\",\"file\":\"db.py\","
                    "\"start_line\":7,\"end_line\":7}]}\n"
                    "```"
                ),
            }
        )
        with patch("subprocess.run", return_value=_mock_completed_process(stdout)):
            result = invoke_claude("Scan this code", InvokerConfig())
        assert result.success is True
        assert result.findings[0]["cwe_id"] == "CWE-89"

    def test_nested_structured_output_returns_parsed_findings(self):
        stdout = json.dumps(
            {
                "result": "",
                "structured_output": {
                    "response": {
                        "findings": [
                            {
                                "cwe_id": "CWE-78",
                                "file": "shell.java",
                                "start_line": 12,
                                "end_line": 12,
                            }
                        ]
                    }
                },
            }
        )
        with patch("subprocess.run", return_value=_mock_completed_process(stdout)):
            result = invoke_claude("Scan this code", InvokerConfig())
        assert result.success is True
        assert result.findings[0]["cwe_id"] == "CWE-78"

    def test_non_finding_list_is_not_accepted_as_findings(self):
        stdout = json.dumps(
            {
                "result": "",
                "structured_output": {
                    "data": [{"token_count": 10}],
                },
            }
        )
        with patch("subprocess.run", return_value=_mock_completed_process(stdout)):
            result = invoke_claude("Scan this code", InvokerConfig())
        assert result.success is False
        assert "findings array" in result.error

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
        with patch(
            "subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd="claude", timeout=5),
        ):
            result = invoke_claude("Scan this code", InvokerConfig(max_retries=1, retry_delay=0.0))
        assert result.success is False
        assert "Timeout" in result.error

    def test_progress_log_records_completed_invocation(self, tmp_path):
        progress_log = tmp_path / "invocation_progress.jsonl"
        stdout = json.dumps({"result": "", "structured_output": []})
        with patch("subprocess.run", return_value=_mock_completed_process(stdout)):
            result = invoke_claude(
                "Scan this code",
                InvokerConfig(progress_log_path=progress_log),
                context={
                    "agent": "sqli",
                    "case_id": "case-1",
                    "variant": "vulnerable",
                    "file": "app.py",
                },
            )

        assert result.success is True
        events = [
            json.loads(line)
            for line in progress_log.read_text(encoding="utf-8").splitlines()
        ]
        assert [event["status"] for event in events] == ["started", "completed"]
        assert events[0]["case_id"] == "case-1"
        assert events[0]["prompt_chars"] == len("Scan this code")
        assert events[1]["finding_count"] == 0

    def test_parse_failure_writes_artifact_next_to_progress_log(self, tmp_path):
        progress_log = tmp_path / "invocation_progress.jsonl"
        stdout = json.dumps({"result": "I could not produce JSON findings."})
        with patch("subprocess.run", return_value=_mock_completed_process(stdout)):
            result = invoke_claude(
                "Scan this code",
                InvokerConfig(progress_log_path=progress_log),
                context={"case_id": "case-1", "variant": "patched"},
            )

        assert result.success is False
        events = [
            json.loads(line)
            for line in progress_log.read_text(encoding="utf-8").splitlines()
        ]
        assert [event["status"] for event in events] == ["started", "failed"]
        artifact_path = events[1]["failure_artifact"]
        artifact = json.loads(Path(artifact_path).read_text(encoding="utf-8"))
        assert artifact["context"]["case_id"] == "case-1"
        assert artifact["stdout"] == stdout

    def test_progress_summary_marks_stale_started_invocation(self, tmp_path):
        progress_log = tmp_path / "invocation_progress.jsonl"
        progress_log.write_text(
            json.dumps(
                {
                    "timestamp": "2026-04-30T00:00:00+00:00",
                    "status": "started",
                    "invocation_id": "abc",
                    "case_id": "case-1",
                    "variant": "patched",
                    "file": "app.py",
                    "attempt": 1,
                    "timeout_seconds": 1,
                }
            )
            + "\n",
            encoding="utf-8",
        )

        summary = summarize_progress(progress_log, stale_grace_seconds=0)

        assert summary["invocation_count"] == 1
        assert summary["active"] == []
        assert summary["stale"][0]["case_id"] == "case-1"
