"""Tests for the learning module — exclusion storage and matching."""

import pytest
import yaml
from pathlib import Path

from screw_agents.learning import load_exclusions, record_exclusion, match_exclusions
from screw_agents.models import Exclusion, ExclusionInput, ExclusionFinding, ExclusionScope


@pytest.fixture
def project_root(tmp_path):
    """A temporary project root with .screw/learning/ directory."""
    return tmp_path


@pytest.fixture
def exclusion_input_pattern():
    """A sample ExclusionInput with pattern scope."""
    return ExclusionInput(
        agent="sqli",
        finding=ExclusionFinding(
            file="src/api.py", line=42, code_pattern="db.text_search(*)", cwe="CWE-89"
        ),
        reason="db.text_search() uses parameterized queries internally",
        scope=ExclusionScope(type="pattern", pattern="db.text_search(*)"),
    )


@pytest.fixture
def exclusion_input_file():
    """A sample ExclusionInput with file scope."""
    return ExclusionInput(
        agent="xss",
        finding=ExclusionFinding(
            file="src/generated.py", line=10, code_pattern="render(*)", cwe="CWE-79"
        ),
        reason="generated code, not user-facing",
        scope=ExclusionScope(type="file", path="src/generated.py"),
    )


class TestLoadExclusions:
    def test_load_nonexistent_returns_empty(self, project_root):
        result = load_exclusions(project_root)
        assert result == []

    def test_load_empty_file(self, project_root):
        learning_dir = project_root / ".screw" / "learning"
        learning_dir.mkdir(parents=True)
        (learning_dir / "exclusions.yaml").write_text("exclusions: []\n")
        result = load_exclusions(project_root)
        assert result == []

    def test_load_valid_exclusions(self, project_root):
        learning_dir = project_root / ".screw" / "learning"
        learning_dir.mkdir(parents=True)
        data = {
            "exclusions": [
                {
                    "id": "fp-2026-04-11-001",
                    "created": "2026-04-11T14:35:00Z",
                    "agent": "sqli",
                    "finding": {
                        "file": "src/api.py",
                        "line": 42,
                        "code_pattern": "db.query(*)",
                        "cwe": "CWE-89",
                    },
                    "reason": "safe",
                    "scope": {"type": "pattern", "pattern": "db.query(*)"},
                    "times_suppressed": 0,
                    "last_suppressed": None,
                }
            ]
        }
        (learning_dir / "exclusions.yaml").write_text(yaml.dump(data))
        result = load_exclusions(project_root)
        assert len(result) == 1
        assert result[0].id == "fp-2026-04-11-001"
        assert result[0].agent == "sqli"

    def test_load_malformed_yaml_raises(self, project_root):
        learning_dir = project_root / ".screw" / "learning"
        learning_dir.mkdir(parents=True)
        (learning_dir / "exclusions.yaml").write_text(": : invalid yaml [[[")
        with pytest.raises(ValueError, match="[Mm]alformed"):
            load_exclusions(project_root)


class TestRecordExclusion:
    def test_record_creates_file_and_dirs(self, project_root, exclusion_input_pattern):
        result = record_exclusion(project_root, exclusion_input_pattern)
        assert result.id.startswith("fp-")
        assert result.agent == "sqli"
        assert result.times_suppressed == 0
        path = project_root / ".screw" / "learning" / "exclusions.yaml"
        assert path.exists()
        loaded = load_exclusions(project_root)
        assert len(loaded) == 1
        assert loaded[0].id == result.id

    def test_record_appends_to_existing(self, project_root, exclusion_input_pattern, exclusion_input_file):
        first = record_exclusion(project_root, exclusion_input_pattern)
        second = record_exclusion(project_root, exclusion_input_file)
        assert first.id != second.id
        loaded = load_exclusions(project_root)
        assert len(loaded) == 2

    def test_record_sequential_ids_same_day(self, project_root, exclusion_input_pattern, exclusion_input_file):
        first = record_exclusion(project_root, exclusion_input_pattern)
        second = record_exclusion(project_root, exclusion_input_file)
        first_seq = int(first.id.split("-")[-1])
        second_seq = int(second.id.split("-")[-1])
        assert second_seq == first_seq + 1

    def test_record_sets_created_timestamp(self, project_root, exclusion_input_pattern):
        result = record_exclusion(project_root, exclusion_input_pattern)
        assert "T" in result.created
        assert result.created.endswith("Z")


class TestMatchExclusions:
    def _make_exclusion(self, scope_type, agent="sqli", **scope_kwargs):
        return Exclusion(
            id="fp-2026-04-11-001",
            created="2026-04-11T14:35:00Z",
            agent=agent,
            finding=ExclusionFinding(
                file="src/api.py", line=42, code_pattern="db.query(*)", cwe="CWE-89"
            ),
            reason="test",
            scope=ExclusionScope(type=scope_type, **scope_kwargs),
        )

    def test_exact_line_match(self):
        exc = self._make_exclusion("exact_line", path="src/api.py")
        matches = match_exclusions([exc], file="src/api.py", line=42, code="db.query(x)", agent="sqli")
        assert len(matches) == 1

    def test_exact_line_no_match_different_line(self):
        exc = self._make_exclusion("exact_line", path="src/api.py")
        matches = match_exclusions([exc], file="src/api.py", line=99, code="db.query(x)", agent="sqli")
        assert len(matches) == 0

    def test_exact_line_no_match_different_file(self):
        exc = self._make_exclusion("exact_line", path="src/api.py")
        matches = match_exclusions([exc], file="src/other.py", line=42, code="db.query(x)", agent="sqli")
        assert len(matches) == 0

    def test_pattern_match(self):
        exc = self._make_exclusion("pattern", pattern="db.text_search(*)")
        matches = match_exclusions([exc], file="src/any.py", line=10, code="result = db.text_search(user_input)", agent="sqli")
        assert len(matches) == 1

    def test_pattern_no_match(self):
        exc = self._make_exclusion("pattern", pattern="db.text_search(*)")
        matches = match_exclusions([exc], file="src/any.py", line=10, code="cursor.execute(query)", agent="sqli")
        assert len(matches) == 0

    def test_file_match(self):
        exc = self._make_exclusion("file", path="src/generated.py")
        matches = match_exclusions([exc], file="src/generated.py", line=1, code="anything", agent="sqli")
        assert len(matches) == 1

    def test_file_no_match(self):
        exc = self._make_exclusion("file", path="src/generated.py")
        matches = match_exclusions([exc], file="src/other.py", line=1, code="anything", agent="sqli")
        assert len(matches) == 0

    def test_directory_match(self):
        exc = self._make_exclusion("directory", path="test/")
        matches = match_exclusions([exc], file="test/test_api.py", line=1, code="anything", agent="sqli")
        assert len(matches) == 1

    def test_directory_nested_match(self):
        exc = self._make_exclusion("directory", path="test/")
        matches = match_exclusions([exc], file="test/unit/test_deep.py", line=1, code="anything", agent="sqli")
        assert len(matches) == 1

    def test_directory_no_match(self):
        exc = self._make_exclusion("directory", path="test/")
        matches = match_exclusions([exc], file="src/api.py", line=1, code="anything", agent="sqli")
        assert len(matches) == 0

    def test_function_match(self):
        exc = self._make_exclusion("function", path="src/api.py", name="get_user")
        matches = match_exclusions(
            [exc], file="src/api.py", line=42, code="anything", agent="sqli", function="get_user"
        )
        assert len(matches) == 1

    def test_function_no_match_different_function(self):
        exc = self._make_exclusion("function", path="src/api.py", name="get_user")
        matches = match_exclusions(
            [exc], file="src/api.py", line=42, code="anything", agent="sqli", function="delete_user"
        )
        assert len(matches) == 0

    def test_wrong_agent_no_match(self):
        exc = self._make_exclusion("file", path="src/api.py", agent="sqli")
        matches = match_exclusions([exc], file="src/api.py", line=1, code="anything", agent="xss")
        assert len(matches) == 0

    def test_multiple_exclusions_partial_match(self):
        exc1 = self._make_exclusion("file", path="src/api.py")
        exc2 = self._make_exclusion("file", path="src/other.py")
        matches = match_exclusions([exc1, exc2], file="src/api.py", line=1, code="anything", agent="sqli")
        assert len(matches) == 1
