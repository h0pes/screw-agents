"""Tests for the adaptive_cleanup listing + removal backend (T21).

Covers:

- ``list_adaptive_scripts`` — empty project, metadata extraction,
  skipping malformed or orphaned entries, sort order.
- ``_check_stale`` via the ``stale`` / ``stale_reason`` fields in the
  list output — empty patterns, all-dead patterns, any-live pattern,
  invalid project root.
- ``remove_adaptive_script`` — both-present happy path, not-found,
  partial-state recovery.

Staleness semantic matches ``src/screw_agents/adaptive/executor.py``'s
``_is_stale``; drift check recommended if either function is refactored.
"""

from __future__ import annotations

from pathlib import Path

import pytest


def _write_script_pair(
    script_dir: Path,
    name: str,
    *,
    target_patterns: list[str],
    source: str = "def analyze(project): pass\n",
    findings_produced: int = 0,
    validated: bool = False,
    signed_by: str | None = None,
) -> None:
    """Helper: write a .py + .meta.yaml pair under script_dir."""
    (script_dir / f"{name}.py").write_text(source, encoding="utf-8")
    meta_lines = [
        f"name: {name}",
        # Quote the timestamp so PyYAML preserves it as a string
        # (matches AdaptiveScriptMeta.created: str).
        "created: \"2026-04-14T10:00:00Z\"",
        "created_by: marco@example.com",
        "domain: injection-input-handling",
        f"description: {name} test script",
        f"target_patterns: {target_patterns!r}",
        "sha256: stub",
        f"findings_produced: {findings_produced}",
        f"validated: {str(validated).lower()}",
    ]
    if signed_by is not None:
        meta_lines.append(f"signed_by: {signed_by}")
    (script_dir / f"{name}.meta.yaml").write_text(
        "\n".join(meta_lines) + "\n", encoding="utf-8"
    )


class TestListAdaptiveScripts:
    """list_adaptive_scripts covers metadata extraction + hygiene."""

    def test_list_empty_project_returns_empty_list(self, tmp_path: Path):
        """No .screw/custom-scripts/ directory → return []."""
        from screw_agents.cli.adaptive_cleanup import list_adaptive_scripts

        assert list_adaptive_scripts(tmp_path) == []

    def test_list_two_scripts_returns_metadata(self, tmp_path: Path):
        """Two scripts with meta; output has 2 entries with correct
        names/metadata and is sorted alphabetically."""
        from screw_agents.cli.adaptive_cleanup import list_adaptive_scripts

        script_dir = tmp_path / ".screw" / "custom-scripts"
        script_dir.mkdir(parents=True)
        _write_script_pair(
            script_dir, "b-second", target_patterns=["y"], findings_produced=0
        )
        _write_script_pair(
            script_dir,
            "a-first",
            target_patterns=["x"],
            findings_produced=5,
            validated=True,
            signed_by="marco@example.com",
        )

        scripts = list_adaptive_scripts(tmp_path)
        assert len(scripts) == 2
        # alphabetical sort
        assert [s["name"] for s in scripts] == ["a-first", "b-second"]

        first = scripts[0]
        assert first["created"] == "2026-04-14T10:00:00Z"
        assert first["created_by"] == "marco@example.com"
        assert first["domain"] == "injection-input-handling"
        assert first["description"] == "a-first test script"
        assert first["target_patterns"] == ["x"]
        assert first["findings_produced"] == 5
        assert first["last_used"] is None
        assert first["validated"] is True
        assert first["signed_by"] == "marco@example.com"
        # stale fields always present
        assert "stale" in first
        assert "stale_reason" in first

    def test_list_script_missing_py_is_skipped(self, tmp_path: Path):
        """meta.yaml present, .py absent → skip (don't include in output)."""
        from screw_agents.cli.adaptive_cleanup import list_adaptive_scripts

        script_dir = tmp_path / ".screw" / "custom-scripts"
        script_dir.mkdir(parents=True)
        # Write only the meta, no .py
        (script_dir / "orphan.meta.yaml").write_text(
            "name: orphan\ncreated: 2026-04-14T10:00:00Z\n"
            "created_by: marco@example.com\n"
            "domain: injection-input-handling\n"
            "description: orphan\ntarget_patterns: []\nsha256: stub\n",
            encoding="utf-8",
        )

        scripts = list_adaptive_scripts(tmp_path)
        assert scripts == []

    def test_list_script_malformed_yaml_is_skipped(self, tmp_path: Path):
        """Unparseable YAML → skip silently."""
        from screw_agents.cli.adaptive_cleanup import list_adaptive_scripts

        script_dir = tmp_path / ".screw" / "custom-scripts"
        script_dir.mkdir(parents=True)
        (script_dir / "broken.py").write_text(
            "def analyze(project): pass\n", encoding="utf-8"
        )
        # Invalid YAML (unclosed quote on a value that would parse as a mapping)
        (script_dir / "broken.meta.yaml").write_text(
            "name: broken\ncreated: \"unclosed\n", encoding="utf-8"
        )
        # And a good script that should still show up
        _write_script_pair(script_dir, "good", target_patterns=[])

        scripts = list_adaptive_scripts(tmp_path)
        assert [s["name"] for s in scripts] == ["good"]


class TestCheckStale:
    """Stale-detection semantic matches executor._is_stale."""

    def test_stale_empty_target_patterns_not_stale(self, tmp_path: Path):
        """Script with target_patterns: [] → stale=False, reason explains."""
        from screw_agents.cli.adaptive_cleanup import list_adaptive_scripts

        script_dir = tmp_path / ".screw" / "custom-scripts"
        script_dir.mkdir(parents=True)
        _write_script_pair(script_dir, "no-patterns", target_patterns=[])

        scripts = list_adaptive_scripts(tmp_path)
        assert len(scripts) == 1
        entry = scripts[0]
        assert entry["stale"] is False
        assert entry["stale_reason"] == "no target_patterns declared"

    def test_stale_all_patterns_dead(self, tmp_path: Path):
        """Script declares target_patterns with no matching call sites.
        Project has no such calls → stale=True, reason names the
        pattern."""
        from screw_agents.cli.adaptive_cleanup import list_adaptive_scripts

        # Project contains a Python file with unrelated calls only
        (tmp_path / "src.py").write_text(
            "def hello():\n    print('hi')\n", encoding="utf-8"
        )
        script_dir = tmp_path / ".screw" / "custom-scripts"
        script_dir.mkdir(parents=True)
        _write_script_pair(
            script_dir,
            "dead-target",
            target_patterns=["DoesNotExistClass.method"],
        )

        scripts = list_adaptive_scripts(tmp_path)
        assert len(scripts) == 1
        entry = scripts[0]
        assert entry["stale"] is True
        assert entry["stale_reason"] is not None
        assert "DoesNotExistClass.method" in entry["stale_reason"]
        assert "0 of 1 target_patterns" in entry["stale_reason"]

    def test_stale_any_pattern_live_not_stale(self, tmp_path: Path):
        """Script declares 2 patterns; project has a call site for ONE.
        Script is NOT stale."""
        from screw_agents.cli.adaptive_cleanup import list_adaptive_scripts

        # Project file contains a db.execute call — matches one of the
        # declared patterns; NonExistent.method has no call site.
        (tmp_path / "src.py").write_text(
            "def handler(request):\n"
            "    db.execute('SELECT 1')\n",
            encoding="utf-8",
        )
        script_dir = tmp_path / ".screw" / "custom-scripts"
        script_dir.mkdir(parents=True)
        _write_script_pair(
            script_dir,
            "mixed",
            target_patterns=["db.execute", "NonExistent.method"],
        )

        scripts = list_adaptive_scripts(tmp_path)
        assert len(scripts) == 1
        entry = scripts[0]
        assert entry["stale"] is False
        assert entry["stale_reason"] is None

    def test_stale_check_on_invalid_project_root_returns_not_stale_with_reason(
        self, tmp_path: Path
    ):
        """Pass a non-existent project_root. The listing machinery requires
        the ``.screw/custom-scripts/`` directory to exist, so we build a
        meta pair in a REAL directory but point ``_check_stale`` itself
        at an unreadable path by calling it directly. This keeps the
        graceful-failure contract testable without disturbing the rest
        of the list path."""
        from screw_agents.cli.adaptive_cleanup import _check_stale

        nonexistent = tmp_path / "does-not-exist"
        # Should NOT raise; returns (False, reason string)
        stale, reason = _check_stale(nonexistent, ["foo.bar"])
        assert stale is False
        assert reason == "cannot compute: project_root unreadable"


class TestRemoveAdaptiveScript:
    """Removal covers happy path, missing, and partial-state recovery."""

    def test_remove_deletes_both_files(self, tmp_path: Path):
        """Both .py and .meta.yaml present → both deleted, status='removed'."""
        from screw_agents.cli.adaptive_cleanup import remove_adaptive_script

        script_dir = tmp_path / ".screw" / "custom-scripts"
        script_dir.mkdir(parents=True)
        _write_script_pair(script_dir, "bad", target_patterns=[])

        result = remove_adaptive_script(tmp_path, script_name="bad")
        assert result["status"] == "removed"
        assert "bad" in result["message"]
        assert not (script_dir / "bad.py").exists()
        assert not (script_dir / "bad.meta.yaml").exists()
        # Both files should appear in removed_files
        assert len(result["removed_files"]) == 2

    def test_remove_not_found_returns_status(self, tmp_path: Path):
        """Neither file present → status='not_found', no errors."""
        from screw_agents.cli.adaptive_cleanup import remove_adaptive_script

        script_dir = tmp_path / ".screw" / "custom-scripts"
        script_dir.mkdir(parents=True)

        result = remove_adaptive_script(tmp_path, script_name="ghost")
        assert result["status"] == "not_found"
        assert "ghost" in result["message"]
        assert result["removed_files"] == []

    def test_remove_partial_state_is_handled(self, tmp_path: Path):
        """Only .py present, .meta.yaml missing → status='partial',
        .py is deleted, message mentions the partial state."""
        from screw_agents.cli.adaptive_cleanup import remove_adaptive_script

        script_dir = tmp_path / ".screw" / "custom-scripts"
        script_dir.mkdir(parents=True)
        (script_dir / "lonely.py").write_text(
            "def analyze(project): pass\n", encoding="utf-8"
        )
        # No .meta.yaml companion

        result = remove_adaptive_script(tmp_path, script_name="lonely")
        assert result["status"] == "partial"
        assert "partial" in result["message"].lower()
        assert not (script_dir / "lonely.py").exists()
        assert len(result["removed_files"]) == 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
