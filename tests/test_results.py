"""Tests for the results module — render_and_write.

Migrated from the legacy ``write_scan_results`` tests (X1-M1 T18). The
rendering pipeline is now reached via :meth:`ScanEngine.finalize_scan_results`;
these tests call the lower-level :func:`render_and_write` helper directly
so they exercise exclusion matching, trust-status accounting, and file
I/O without the staging round-trip (covered separately in
``test_accumulate_finalize.py``).
"""

import json

import pytest
import yaml
from pathlib import Path

from screw_agents.models import Finding, MergedSource
from screw_agents.results import _merge_findings_augmentatively, render_and_write


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


class TestRenderAndWrite:
    def test_creates_screw_directory_structure(self, tmp_path, finding_sqli):
        result = render_and_write(
            project_root=tmp_path,
            findings_raw=[finding_sqli],
            agent_names=["sqli"],
        )
        assert (tmp_path / ".screw" / "findings").is_dir()
        assert (tmp_path / ".screw" / "learning").is_dir()
        assert (tmp_path / ".screw" / ".gitignore").exists()

    def test_gitignore_content(self, tmp_path, finding_sqli):
        render_and_write(
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
        render_and_write(
            project_root=tmp_path,
            findings_raw=[finding_sqli],
            agent_names=["sqli"],
        )
        assert (screw_dir / ".gitignore").read_text() == "custom content\n"

    def test_writes_json_and_markdown_files(self, tmp_path, finding_sqli):
        result = render_and_write(
            project_root=tmp_path,
            findings_raw=[finding_sqli],
            agent_names=["sqli"],
        )
        files = result["files_written"]
        assert len(files) == 2
        assert "json" in files
        assert "markdown" in files
        json_file = files["json"]
        md_file = files["markdown"]
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
        result = render_and_write(
            project_root=tmp_path,
            findings_raw=[finding_sqli],
            agent_names=["sqli"],
        )
        json_file = result["files_written"]["json"]
        assert "/sqli-" in json_file

    def test_filename_prefix_injection_domain(self, tmp_path, finding_sqli):
        result = render_and_write(
            project_root=tmp_path,
            findings_raw=[finding_sqli],
            agent_names=["sqli", "cmdi", "ssti", "xss"],
        )
        json_file = result["files_written"]["json"]
        assert "/injection-" in json_file

    def test_summary_counts(self, tmp_path, finding_sqli, finding_sqli_line30):
        result = render_and_write(
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
        result = render_and_write(
            project_root=tmp_path,
            findings_raw=[],
            agent_names=["sqli"],
        )
        assert result["summary"]["total"] == 0
        assert result["summary"]["active"] == 0
        assert len(result["files_written"]) == 2  # still writes empty report

    def test_scan_metadata_passed_through(self, tmp_path, finding_sqli):
        result = render_and_write(
            project_root=tmp_path,
            findings_raw=[finding_sqli],
            agent_names=["sqli"],
            scan_metadata={"target": "src/api.py"},
        )
        md_file = result["files_written"]["markdown"]
        md = Path(md_file).read_text()
        assert "src/api.py" in md


class TestRenderAndWriteExclusions:
    """D5 fix: render_and_write applies exclusions server-side."""

    def _setup_exclusion(self, tmp_path, scope_type, **scope_kwargs):
        """Write an exclusion to .screw/learning/exclusions.yaml.

        Writes config.yaml with ``legacy_unsigned_exclusions: warn`` so the
        unsigned entry is treated as ``warned`` (active) and remains
        applicable. These tests verify scope-matching semantics — they
        intentionally do not exercise the trust pipeline. Without the warn
        config, the default ``reject`` policy quarantines the entry and
        match_exclusions correctly skips it (per the round-trip defect fix).
        """
        screw_dir = tmp_path / ".screw"
        screw_dir.mkdir(exist_ok=True)
        (screw_dir / "config.yaml").write_text(
            "version: 1\n"
            "exclusion_reviewers: []\n"
            "script_reviewers: []\n"
            "legacy_unsigned_exclusions: warn\n"
        )
        learning_dir = screw_dir / "learning"
        learning_dir.mkdir(exist_ok=True)
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
        result = render_and_write(
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
        result = render_and_write(
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
        result = render_and_write(
            project_root=tmp_path,
            findings_raw=[finding_sqli],
            agent_names=["sqli"],
        )
        assert result["summary"]["suppressed"] == 1

    def test_no_exclusions_file_no_suppressions(self, tmp_path, finding_sqli):
        result = render_and_write(
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
        result = render_and_write(
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
        result = render_and_write(
            project_root=tmp_path,
            findings_raw=[finding_sqli, finding_sqli_line30],
            agent_names=["sqli"],
        )
        json_file = result["files_written"]["json"]
        data = json.loads(Path(json_file).read_text())
        assert all(f["triage"]["excluded"] for f in data)
        assert all(f["triage"]["exclusion_ref"] == "fp-2026-04-11-001" for f in data)

    def test_quarantined_exclusion_does_not_suppress_findings(
        self, tmp_path, finding_sqli
    ):
        """Round-trip regression: a quarantined exclusion (default reject
        policy + unsigned entry) MUST NOT be applied to suppress findings.

        Discovered during Phase 3a PR#1 manual round-trip test: the trust
        layer correctly identified a tampered exclusion as quarantined, but
        the report writer still applied it via match_exclusions, producing
        an internally contradictory report ("1 quarantined" alongside
        "1 suppressed via the same id"). The fix landed the policy gate in
        match_exclusions; this test pins it.
        """
        # Seed an unsigned exclusion that would otherwise match the finding
        # exactly. Default config policy is reject → entry quarantines on load.
        learning_dir = tmp_path / ".screw" / "learning"
        learning_dir.mkdir(parents=True, exist_ok=True)
        (learning_dir / "exclusions.yaml").write_text(
            yaml.dump(
                {
                    "exclusions": [
                        {
                            "id": "fp-2026-04-16-001",
                            "created": "2026-04-16T07:46:50Z",
                            "agent": "sqli",
                            "finding": {
                                "file": "src/api.py",
                                "line": 42,
                                "code_pattern": "cursor.execute(*)",
                                "cwe": "CWE-89",
                            },
                            "reason": "tampered — signature stripped",
                            "scope": {"type": "exact_line", "path": "src/api.py"},
                        }
                    ]
                }
            )
        )

        result = render_and_write(
            project_root=tmp_path,
            findings_raw=[finding_sqli],
            agent_names=["sqli"],
        )

        # Trust layer correctly counts the quarantine
        assert result["trust_status"]["exclusion_quarantine_count"] == 1
        assert result["trust_status"]["exclusion_active_count"] == 0
        # And critically — the finding is NOT suppressed despite the
        # quarantined exclusion's scope matching its file/line
        assert result["summary"]["suppressed"] == 0
        assert result["summary"]["active"] == 1
        assert result["exclusions_applied"] == []
        # JSON also reflects active status
        json_file = result["files_written"]["json"]
        data = json.loads(Path(json_file).read_text())
        assert data[0]["triage"]["excluded"] is False
        assert data[0]["triage"]["exclusion_ref"] is None


class TestRenderAndWriteTrustStatus:
    """Task 11 — surface trust verification status in scan reports."""

    def test_render_and_write_returns_trust_status_in_dict(self, tmp_path, finding_sqli):
        """The return dict has a trust_status key with the 4-field shape."""
        result = render_and_write(
            project_root=tmp_path,
            findings_raw=[finding_sqli],
            agent_names=["sqli"],
        )
        assert "trust_status" in result
        ts = result["trust_status"]
        assert set(ts.keys()) == {
            "exclusion_quarantine_count",
            "exclusion_active_count",
            "script_quarantine_count",
            "script_active_count",
        }
        # No exclusions configured — all zero
        assert ts["exclusion_quarantine_count"] == 0
        assert ts["exclusion_active_count"] == 0

    def test_render_and_write_trust_section_absent_in_empty_project(
        self, tmp_path, finding_sqli
    ):
        """Empty project (no exclusions) → trust section not rendered in Markdown."""
        result = render_and_write(
            project_root=tmp_path,
            findings_raw=[finding_sqli],
            agent_names=["sqli"],
        )
        md_file = result["files_written"]["markdown"]
        md = Path(md_file).read_text()
        assert "## Trust verification" not in md

    def test_render_and_write_quarantined_exclusion_surfaces_in_markdown(
        self, tmp_path, finding_sqli
    ):
        """When an unsigned exclusion is quarantined (default reject policy),
        the Markdown report shows a Trust verification section with count
        and CLI remediation pointer."""
        # Seed an unsigned exclusion — default config.yaml has reject policy
        learning_dir = tmp_path / ".screw" / "learning"
        learning_dir.mkdir(parents=True, exist_ok=True)
        (learning_dir / "exclusions.yaml").write_text(
            yaml.dump(
                {
                    "exclusions": [
                        {
                            "id": "fp-2026-04-14-001",
                            "created": "2026-04-14T10:00:00Z",
                            "agent": "sqli",
                            "finding": {
                                "file": "src/a.py",
                                "line": 10,
                                "code_pattern": "*",
                                "cwe": "CWE-89",
                            },
                            "reason": "legacy unsigned",
                            "scope": {"type": "file", "path": "src/a.py"},
                        }
                    ]
                }
            )
        )

        result = render_and_write(
            project_root=tmp_path,
            findings_raw=[finding_sqli],
            agent_names=["sqli"],
        )

        # Return dict exposes the quarantine count
        assert result["trust_status"]["exclusion_quarantine_count"] == 1
        assert result["trust_status"]["exclusion_active_count"] == 0

        # Markdown report surfaces the section
        md_file = result["files_written"]["markdown"]
        md = Path(md_file).read_text()
        assert "## Trust verification" in md
        assert "1 exclusion quarantined" in md
        assert "screw-agents validate-exclusion" in md

    def test_render_and_write_warn_policy_surfaces_in_markdown(
        self, tmp_path, finding_sqli
    ):
        """Under warn policy, unsigned exclusions end up as trust_state='warned'
        (quarantined=False). The scan report should surface them as 'active' —
        they ARE being applied."""
        screw_dir = tmp_path / ".screw"
        screw_dir.mkdir()
        (screw_dir / "config.yaml").write_text(
            "version: 1\n"
            "exclusion_reviewers: []\n"
            "script_reviewers: []\n"
            "legacy_unsigned_exclusions: warn\n"
        )

        learning_dir = screw_dir / "learning"
        learning_dir.mkdir()
        (learning_dir / "exclusions.yaml").write_text(
            yaml.dump(
                {
                    "exclusions": [
                        {
                            "id": "fp-2026-04-14-001",
                            "created": "2026-04-14T10:00:00Z",
                            "agent": "sqli",
                            "finding": {
                                "file": "src/a.py",
                                "line": 10,
                                "code_pattern": "*",
                                "cwe": "CWE-89",
                            },
                            "reason": "legacy",
                            "scope": {"type": "file", "path": "src/a.py"},
                        }
                    ]
                }
            )
        )

        result = render_and_write(
            project_root=tmp_path,
            findings_raw=[finding_sqli],
            agent_names=["sqli"],
        )
        # Under warn policy: quarantine=0, active=1
        assert result["trust_status"]["exclusion_quarantine_count"] == 0
        assert result["trust_status"]["exclusion_active_count"] == 1

        md_file = result["files_written"]["markdown"]
        md = Path(md_file).read_text()
        assert "## Trust verification" in md
        assert "1 trusted exclusion applied" in md

    def test_render_and_write_friendly_error_when_dot_screw_is_file(
        self, tmp_path, finding_sqli
    ):
        """When `.screw` exists as a FILE (not directory), render_and_write
        raises ValueError with actionable message (T6-I1)."""
        # Create `.screw` as a file
        (tmp_path / ".screw").write_text("i am not a directory")

        with pytest.raises(ValueError, match="not a directory"):
            render_and_write(
                project_root=tmp_path,
                findings_raw=[finding_sqli],
                agent_names=["sqli"],
            )


# ---------------------------------------------------------------------------
# Phase 3b T19 — augmentative finding merge
# ---------------------------------------------------------------------------
#
# Covers the `_merge_findings_augmentatively` helper and its integration
# with `render_and_write`. The merge collapses findings that share
# `(location.file, location.line_start, classification.cwe)` from multiple
# scan sources (e.g., a YAML agent AND an adaptive script) into a single
# primary finding with a populated `merged_from_sources` list typed as
# `list[MergedSource]` (each entry a structured agent + severity pair).


def _make_finding_dict(
    *,
    finding_id: str,
    agent: str,
    file: str,
    line_start: int,
    cwe: str,
    severity: str,
    description: str,
    line_end: int | None = None,
    domain: str = "injection-input-handling",
):
    """Build a Finding-shaped dict matching the NESTED model shape.

    Used by T19 tests that need to round-trip through `Finding(**dict)`
    or hand `findings_raw` to `render_and_write`.
    """
    return {
        "id": finding_id,
        "agent": agent,
        "domain": domain,
        "timestamp": "2026-04-19T10:00:00Z",
        "location": {
            "file": file,
            "line_start": line_start,
            "line_end": line_end,
        },
        "classification": {
            "cwe": cwe,
            "cwe_name": "SQL Injection",
            "severity": severity,
            "confidence": "high",
        },
        "analysis": {
            "description": description,
        },
        "remediation": {
            "recommendation": "use parameterized queries",
        },
    }


def _make_finding(**kwargs):
    """Build a Finding model instance via the nested dict helper."""
    return Finding(**_make_finding_dict(**kwargs))


class TestMergeFindingsAugmentatively:
    """Unit tests for `_merge_findings_augmentatively`."""

    def test_merge_empty_findings_list_returns_empty(self):
        """Belt-and-suspenders edge case: empty input returns empty list."""
        assert _merge_findings_augmentatively([]) == []

    def test_merge_single_finding_unchanged(self):
        """Single finding passes through with `merged_from_sources = None`
        (no `list[MergedSource]` populated for unmerged findings)."""
        f = _make_finding(
            finding_id="f1",
            agent="sqli",
            file="src/a.py",
            line_start=10,
            cwe="CWE-89",
            severity="high",
            description="detected sqli",
        )

        result = _merge_findings_augmentatively([f])

        assert len(result) == 1
        assert result[0].merged_from_sources is None
        # Verify nothing else mutated.
        assert result[0].id == "f1"
        assert result[0].agent == "sqli"
        assert result[0].location.file == "src/a.py"
        assert result[0].location.line_start == 10
        assert result[0].classification.cwe == "CWE-89"

    def test_merge_two_findings_same_key_produces_one_merged(self):
        """Two findings at same (file, line_start, cwe) collapse to one.

        Asserts:
        - Exactly 1 finding in output.
        - `merged_from_sources == [MergedSource(agent="agent1", severity="sev1"),
          MergedSource(agent="agent2", severity="sev2")]` in INPUT order
          (not sorted).
        - Primary's `agent` field matches the severity-winning agent.
        - Primary's `analysis.description` comes from the winning finding.
        """
        yaml_finding = _make_finding(
            finding_id="f1",
            agent="sqli",
            file="src/a.py",
            line_start=10,
            cwe="CWE-89",
            severity="medium",
            description="YAML detected SQLi",
        )
        adaptive_finding = _make_finding(
            finding_id="f2",
            agent="adaptive_script:qb-check",
            file="src/a.py",
            line_start=10,
            cwe="CWE-89",
            severity="high",
            description="Adaptive detected same SQLi",
        )

        result = _merge_findings_augmentatively([yaml_finding, adaptive_finding])

        assert len(result) == 1
        merged = result[0]
        # Primary selected by higher severity → adaptive_script (high)
        # beats sqli (medium).
        assert merged.agent == "adaptive_script:qb-check"
        assert merged.analysis.description == "Adaptive detected same SQLi"
        # Source list preserves INPUT order (yaml first, adaptive second).
        assert merged.merged_from_sources == [
            MergedSource(agent="sqli", severity="medium"),
            MergedSource(agent="adaptive_script:qb-check", severity="high"),
        ]

    def test_merge_different_cwe_not_merged(self):
        """Same (file, line_start) but different CWEs → no merge."""
        f1 = _make_finding(
            finding_id="f1",
            agent="sqli",
            file="src/a.py",
            line_start=10,
            cwe="CWE-89",
            severity="high",
            description="SQLi",
        )
        f2 = _make_finding(
            finding_id="f2",
            agent="cmdi",
            file="src/a.py",
            line_start=10,
            cwe="CWE-78",
            severity="high",
            description="CMDi",
        )

        result = _merge_findings_augmentatively([f1, f2])

        assert len(result) == 2
        for finding in result:
            assert finding.merged_from_sources is None

    def test_merge_primary_selection_by_severity_then_agent_name(self):
        """Tiebreaker: same severity → alphabetical agent name ascending wins.

        Three findings at same key: z_agent(high), a_agent(high),
        m_agent(medium). Primary should be a_agent (alphabetical wins at
        high-severity tie). Source list preserves INPUT order.
        """
        z_high = _make_finding(
            finding_id="f1",
            agent="z_agent",
            file="src/a.py",
            line_start=10,
            cwe="CWE-89",
            severity="high",
            description="z says",
        )
        a_high = _make_finding(
            finding_id="f2",
            agent="a_agent",
            file="src/a.py",
            line_start=10,
            cwe="CWE-89",
            severity="high",
            description="a says",
        )
        m_medium = _make_finding(
            finding_id="f3",
            agent="m_agent",
            file="src/a.py",
            line_start=10,
            cwe="CWE-89",
            severity="medium",
            description="m says",
        )

        result = _merge_findings_augmentatively([z_high, a_high, m_medium])

        assert len(result) == 1
        merged = result[0]
        # a_agent wins: same severity tier as z_agent but alphabetically earlier.
        assert merged.agent == "a_agent"
        assert merged.analysis.description == "a says"
        # Source list preserves INPUT order: z first, a second, m third.
        assert merged.merged_from_sources == [
            MergedSource(agent="z_agent", severity="high"),
            MergedSource(agent="a_agent", severity="high"),
            MergedSource(agent="m_agent", severity="medium"),
        ]

    def test_merge_preserves_insertion_order_across_buckets(self):
        """Output list orders buckets by first-insertion (OrderedDict)."""
        bucket_a = _make_finding(
            finding_id="a1",
            agent="sqli",
            file="src/a.py",
            line_start=10,
            cwe="CWE-89",
            severity="high",
            description="A",
        )
        bucket_b = _make_finding(
            finding_id="b1",
            agent="cmdi",
            file="src/b.py",
            line_start=20,
            cwe="CWE-78",
            severity="high",
            description="B",
        )

        # Input order: A before B → output order: A before B.
        result = _merge_findings_augmentatively([bucket_a, bucket_b])

        assert len(result) == 2
        assert result[0].id == "a1"
        assert result[1].id == "b1"

        # Reverse input order: B before A → output order: B before A.
        result = _merge_findings_augmentatively([bucket_b, bucket_a])

        assert len(result) == 2
        assert result[0].id == "b1"
        assert result[1].id == "a1"

    def test_merge_severity_case_mismatch_normalizes_to_lower(self) -> None:
        """I2 regression: severity field is case-normalized before rank lookup.

        A Finding with severity='High' (capitalized) must rank as 'high' (rank 1),
        not as unknown (rank 5). Otherwise a misformed YAML finding would silently
        lose tiebreaker selection to properly-lowercased findings even when its
        true severity is higher.

        Locks the `.lower()` normalization so future refactors can't silently
        revert to the case-sensitive lookup.
        """
        from screw_agents.results import _merge_findings_augmentatively

        # Two findings at same (file, line_start, cwe) — one with "High"
        # (capitalized), one with "low" (proper). Capitalized-high SHOULD win
        # the tiebreaker.
        f_high_cap = Finding(
            **_make_finding_dict(
                finding_id="sqli-1",
                agent="sqli",
                file="src/a.py",
                line_start=10,
                cwe="CWE-89",
                severity="High",  # capitalized — would rank as unknown without .lower()
                description="SQL injection (capitalized severity)",
            )
        )
        f_low = Finding(
            **_make_finding_dict(
                finding_id="adaptive-1",
                agent="adaptive_script:qb",
                file="src/a.py",
                line_start=10,
                cwe="CWE-89",
                severity="low",
                description="Adaptive script - low severity",
            )
        )

        merged = _merge_findings_augmentatively([f_high_cap, f_low])

        assert len(merged) == 1
        primary = merged[0]
        # sqli (High→high rank 1) must win over adaptive_script:qb (low rank 3)
        assert primary.agent == "sqli", (
            f"Expected sqli to win tiebreaker (severity 'High' normalized to "
            f"'high'), got {primary.agent}"
        )
        # Source list preserves input order and ORIGINAL severity strings
        # (not the normalized lowercase): normalization happens ONLY in the
        # sort_key function; it does not alter Finding fields or source-list
        # content.
        assert primary.merged_from_sources == [
            MergedSource(agent="sqli", severity="High"),
            MergedSource(agent="adaptive_script:qb", severity="low"),
        ], (
            f"Source list should preserve original severity strings (not "
            f"normalized), got {primary.merged_from_sources}"
        )

    def test_merge_severity_rank_unknown_severity_ranks_last(self):
        """Unknown severity (not in rank map) loses to any known severity.

        Locks the `_SEVERITY_RANK.get(severity, 5)` fallback — prevents an
        ill-formed severity from promoting to primary by accident.
        """
        high_finding = _make_finding(
            finding_id="f1",
            agent="z_agent",  # alphabetically later — severity must dominate
            file="src/a.py",
            line_start=10,
            cwe="CWE-89",
            severity="high",
            description="high wins",
        )
        unknown_finding = _make_finding(
            finding_id="f2",
            agent="a_agent",  # alphabetically earlier — would win if tied on severity
            file="src/a.py",
            line_start=10,
            cwe="CWE-89",
            severity="unknown-custom",
            description="unknown loses",
        )

        result = _merge_findings_augmentatively([high_finding, unknown_finding])

        assert len(result) == 1
        merged = result[0]
        # High (rank 1) beats unknown (rank 5) despite alphabetical disadvantage.
        assert merged.agent == "z_agent"
        assert merged.analysis.description == "high wins"


class TestRenderAndWriteMerge:
    """Integration tests — `render_and_write` applies the merge end-to-end."""

    def test_render_and_write_merges_yaml_and_adaptive_findings(self, tmp_path):
        """Full integration: YAML + adaptive findings at same key merge to
        one; unique adaptive finding preserved; markdown renders a
        `**Sources:**` line on the merged finding only.
        """
        yaml_finding_dup = _make_finding_dict(
            finding_id="f1",
            agent="sqli",
            file="src/a.py",
            line_start=10,
            cwe="CWE-89",
            severity="high",
            description="YAML detected SQLi",
        )
        adaptive_finding_dup = _make_finding_dict(
            finding_id="f2",
            agent="adaptive_script:qb-check",
            file="src/a.py",
            line_start=10,
            cwe="CWE-89",
            severity="high",
            description="Adaptive detected same SQLi",
        )
        adaptive_finding_unique = _make_finding_dict(
            finding_id="f3",
            agent="adaptive_script:qb-check",
            file="src/b.py",
            line_start=20,
            cwe="CWE-89",
            severity="high",
            description="Adaptive found extra SQLi",
        )

        result = render_and_write(
            project_root=tmp_path,
            findings_raw=[
                yaml_finding_dup,
                adaptive_finding_dup,
                adaptive_finding_unique,
            ],
            agent_names=["sqli"],
            scan_metadata={"agent": "sqli", "timestamp": "2026-04-19T10:00:00Z"},
        )

        # Exactly 2 findings after merge (1 merged + 1 unique).
        assert result["summary"]["total"] == 2

        md_content = Path(result["files_written"]["markdown"]).read_text()

        # Both locations rendered.
        assert "src/a.py" in md_content
        assert "src/b.py" in md_content

        # Merged finding has Sources line with both sources in input order.
        # Primary selection: both findings are high severity; alphabetical
        # tiebreaker compares agent names — "adaptive_script:qb-check" <
        # "sqli" — so adaptive_script wins and is the primary.
        # Source list still preserves INPUT order: sqli first, adaptive
        # second.
        assert (
            "**Sources:** sqli (high), adaptive_script:qb-check (high)"
            in md_content
        )

        # The unique finding's section must NOT contain a Sources line.
        # Split by finding headers; locate the unique one by description.
        sections = md_content.split("### ")
        unique_section_candidates = [
            s for s in sections if "Adaptive found extra SQLi" in s
        ]
        assert len(unique_section_candidates) == 1
        unique_section = unique_section_candidates[0]
        assert "**Sources:**" not in unique_section

    def test_render_and_write_unmerged_finding_has_no_sources_line(self, tmp_path):
        """Single finding (no merge) renders no `**Sources:**` line and
        the JSON output carries `merged_from_sources: null` (the
        `list[MergedSource]` field is None for unmerged findings; serializes
        as JSON null regardless of element type).
        """
        f = _make_finding_dict(
            finding_id="f1",
            agent="sqli",
            file="src/a.py",
            line_start=10,
            cwe="CWE-89",
            severity="high",
            description="Only finding",
        )

        result = render_and_write(
            project_root=tmp_path,
            findings_raw=[f],
            agent_names=["sqli"],
            scan_metadata={"agent": "sqli", "timestamp": "2026-04-19T10:00:00Z"},
            formats=["json", "markdown"],
        )

        md_content = Path(result["files_written"]["markdown"]).read_text()
        assert "**Sources:**" not in md_content

        # JSON is a flat array of finding dicts at top level.
        findings_json = json.loads(Path(result["files_written"]["json"]).read_text())
        assert len(findings_json) == 1
        assert findings_json[0]["merged_from_sources"] is None
