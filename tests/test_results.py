"""Tests for the results module — write_scan_results."""

import json

import pytest
import yaml
from pathlib import Path

from screw_agents.results import write_scan_results


@pytest.fixture
def finding_sqli():
    """A minimal valid finding dict."""
    return {
        "id": "sqli-001",
        "agent": "sqli",
        "domain": "injection-input-handling",
        "timestamp": "2026-04-11T14:30:00Z",
        "location": {
            "file": "src/api.py",
            "line_start": 42,
            "code_snippet": "cursor.execute(f\"SELECT * FROM users WHERE id = {user_id}\")",
            "function": "get_user",
        },
        "classification": {
            "cwe": "CWE-89",
            "cwe_name": "SQL Injection",
            "severity": "high",
            "confidence": "high",
        },
        "analysis": {"description": "SQL injection via f-string"},
        "remediation": {"recommendation": "Use parameterized queries"},
    }


@pytest.fixture
def finding_sqli_line30():
    """A second finding in the same file at line 30."""
    return {
        "id": "sqli-002",
        "agent": "sqli",
        "domain": "injection-input-handling",
        "timestamp": "2026-04-11T14:30:00Z",
        "location": {
            "file": "src/api.py",
            "line_start": 30,
            "code_snippet": "cursor.execute(query)",
        },
        "classification": {
            "cwe": "CWE-89",
            "cwe_name": "SQL Injection",
            "severity": "high",
            "confidence": "medium",
        },
        "analysis": {"description": "SQL injection via %-formatting"},
        "remediation": {"recommendation": "Use parameterized queries"},
    }


class TestWriteScanResults:
    def test_creates_screw_directory_structure(self, tmp_path, finding_sqli):
        result = write_scan_results(
            project_root=tmp_path,
            findings_raw=[finding_sqli],
            agent_names=["sqli"],
        )
        assert (tmp_path / ".screw" / "findings").is_dir()
        assert (tmp_path / ".screw" / "learning").is_dir()
        assert (tmp_path / ".screw" / ".gitignore").exists()

    def test_gitignore_content(self, tmp_path, finding_sqli):
        write_scan_results(
            project_root=tmp_path,
            findings_raw=[finding_sqli],
            agent_names=["sqli"],
        )
        content = (tmp_path / ".screw" / ".gitignore").read_text()
        assert "findings/" in content
        assert "!learning/" in content

    def test_gitignore_not_overwritten(self, tmp_path, finding_sqli):
        """Existing .gitignore should not be overwritten."""
        screw_dir = tmp_path / ".screw"
        screw_dir.mkdir()
        (screw_dir / ".gitignore").write_text("custom content\n")
        write_scan_results(
            project_root=tmp_path,
            findings_raw=[finding_sqli],
            agent_names=["sqli"],
        )
        assert (screw_dir / ".gitignore").read_text() == "custom content\n"

    def test_writes_json_and_markdown_files(self, tmp_path, finding_sqli):
        result = write_scan_results(
            project_root=tmp_path,
            findings_raw=[finding_sqli],
            agent_names=["sqli"],
        )
        files = result["files_written"]
        assert len(files) == 2
        json_file = [f for f in files if f.endswith(".json")][0]
        md_file = [f for f in files if f.endswith(".md")][0]
        assert Path(json_file).exists()
        assert Path(md_file).exists()
        # JSON is valid
        data = json.loads(Path(json_file).read_text())
        assert len(data) == 1
        assert data[0]["id"] == "sqli-001"
        # Markdown has report header
        md = Path(md_file).read_text()
        assert "Security Scan Report" in md

    def test_filename_prefix_single_agent(self, tmp_path, finding_sqli):
        result = write_scan_results(
            project_root=tmp_path,
            findings_raw=[finding_sqli],
            agent_names=["sqli"],
        )
        json_file = result["files_written"][0]
        assert "/sqli-" in json_file

    def test_filename_prefix_injection_domain(self, tmp_path, finding_sqli):
        result = write_scan_results(
            project_root=tmp_path,
            findings_raw=[finding_sqli],
            agent_names=["sqli", "cmdi", "ssti", "xss"],
        )
        json_file = result["files_written"][0]
        assert "/injection-" in json_file

    def test_summary_counts(self, tmp_path, finding_sqli, finding_sqli_line30):
        result = write_scan_results(
            project_root=tmp_path,
            findings_raw=[finding_sqli, finding_sqli_line30],
            agent_names=["sqli"],
        )
        summary = result["summary"]
        assert summary["total"] == 2
        assert summary["active"] == 2
        assert summary["suppressed"] == 0
        assert summary["by_severity"]["high"] == 2

    def test_empty_findings(self, tmp_path):
        result = write_scan_results(
            project_root=tmp_path,
            findings_raw=[],
            agent_names=["sqli"],
        )
        assert result["summary"]["total"] == 0
        assert result["summary"]["active"] == 0
        assert len(result["files_written"]) == 2  # still writes empty report

    def test_scan_metadata_passed_through(self, tmp_path, finding_sqli):
        result = write_scan_results(
            project_root=tmp_path,
            findings_raw=[finding_sqli],
            agent_names=["sqli"],
            scan_metadata={"target": "src/api.py"},
        )
        md_file = [f for f in result["files_written"] if f.endswith(".md")][0]
        md = Path(md_file).read_text()
        assert "src/api.py" in md


class TestWriteScanResultsExclusions:
    """D5 fix: write_scan_results applies exclusions server-side."""

    def _setup_exclusion(self, tmp_path, scope_type, **scope_kwargs):
        """Write an exclusion to .screw/learning/exclusions.yaml."""
        learning_dir = tmp_path / ".screw" / "learning"
        learning_dir.mkdir(parents=True, exist_ok=True)
        data = {
            "exclusions": [
                {
                    "id": "fp-2026-04-11-001",
                    "created": "2026-04-11T14:35:00Z",
                    "agent": "sqli",
                    "finding": {
                        "file": "src/api.py",
                        "line": 42,
                        "code_pattern": "cursor.execute(f\"...\")",
                        "cwe": "CWE-89",
                    },
                    "reason": "testing only",
                    "scope": {"type": scope_type, **scope_kwargs},
                    "times_suppressed": 0,
                    "last_suppressed": None,
                }
            ]
        }
        (learning_dir / "exclusions.yaml").write_text(yaml.dump(data))

    def test_file_scope_suppresses_all_findings_in_file(
        self, tmp_path, finding_sqli, finding_sqli_line30
    ):
        """D5 core test: file scope must suppress ALL findings in that file."""
        self._setup_exclusion(tmp_path, "file", path="src/api.py")
        result = write_scan_results(
            project_root=tmp_path,
            findings_raw=[finding_sqli, finding_sqli_line30],
            agent_names=["sqli"],
        )
        assert result["summary"]["suppressed"] == 2
        assert result["summary"]["active"] == 0
        assert len(result["exclusions_applied"]) == 2

    def test_exact_line_suppresses_only_matching_line(
        self, tmp_path, finding_sqli, finding_sqli_line30
    ):
        self._setup_exclusion(tmp_path, "exact_line", path="src/api.py")
        result = write_scan_results(
            project_root=tmp_path,
            findings_raw=[finding_sqli, finding_sqli_line30],
            agent_names=["sqli"],
        )
        # exact_line matches on finding.line (42) — only sqli-001 suppressed
        assert result["summary"]["suppressed"] == 1
        assert result["summary"]["active"] == 1

    def test_directory_scope_suppresses_findings_in_dir(
        self, tmp_path, finding_sqli
    ):
        self._setup_exclusion(tmp_path, "directory", path="src/")
        result = write_scan_results(
            project_root=tmp_path,
            findings_raw=[finding_sqli],
            agent_names=["sqli"],
        )
        assert result["summary"]["suppressed"] == 1

    def test_no_exclusions_file_no_suppressions(self, tmp_path, finding_sqli):
        result = write_scan_results(
            project_root=tmp_path,
            findings_raw=[finding_sqli],
            agent_names=["sqli"],
        )
        assert result["summary"]["suppressed"] == 0
        assert result["summary"]["active"] == 1

    def test_wrong_agent_exclusion_no_suppression(
        self, tmp_path, finding_sqli
    ):
        """Exclusion for agent 'xss' should not suppress 'sqli' finding."""
        learning_dir = tmp_path / ".screw" / "learning"
        learning_dir.mkdir(parents=True, exist_ok=True)
        data = {
            "exclusions": [
                {
                    "id": "fp-2026-04-11-001",
                    "created": "2026-04-11T14:35:00Z",
                    "agent": "xss",
                    "finding": {
                        "file": "src/api.py",
                        "line": 42,
                        "code_pattern": "x",
                        "cwe": "CWE-79",
                    },
                    "reason": "safe",
                    "scope": {"type": "file", "path": "src/api.py"},
                    "times_suppressed": 0,
                    "last_suppressed": None,
                }
            ]
        }
        (learning_dir / "exclusions.yaml").write_text(yaml.dump(data))
        result = write_scan_results(
            project_root=tmp_path,
            findings_raw=[finding_sqli],
            agent_names=["sqli"],
        )
        assert result["summary"]["suppressed"] == 0

    def test_excluded_findings_in_json_output(
        self, tmp_path, finding_sqli, finding_sqli_line30
    ):
        """Excluded findings should appear in JSON with excluded=true."""
        self._setup_exclusion(tmp_path, "file", path="src/api.py")
        result = write_scan_results(
            project_root=tmp_path,
            findings_raw=[finding_sqli, finding_sqli_line30],
            agent_names=["sqli"],
        )
        json_file = [f for f in result["files_written"] if f.endswith(".json")][0]
        data = json.loads(Path(json_file).read_text())
        assert all(f["triage"]["excluded"] for f in data)
        assert all(f["triage"]["exclusion_ref"] == "fp-2026-04-11-001" for f in data)
