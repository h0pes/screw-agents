"""End-to-end integration tests for Phase 3a PR #2 learning aggregation."""

from __future__ import annotations

from pathlib import Path

import pytest

from screw_agents.cli.init_trust import run_init_trust
from screw_agents.engine import ScanEngine
from screw_agents.learning import record_exclusion
from screw_agents.models import ExclusionFinding, ExclusionInput, ExclusionScope


# Fixture invariants — named for clarity and to make future extensions obvious.
_N_PATTERN_EXCLUSIONS = 12  # Hits aggregate_pattern_confidence HIGH threshold (>= 10).
_N_DIR_EXCLUSIONS = 5       # Hits aggregate_directory_suggestions MEDIUM threshold (>= 5).
_N_TOTAL_HAPPY_PATH = _N_PATTERN_EXCLUSIONS + _N_DIR_EXCLUSIONS  # 17


def test_full_aggregation_flow_signed_exclusions(tmp_path: Path):
    """End-to-end happy path: init-trust -> 17 signed exclusions -> aggregate -> all 4 sections.

    Fixture invariants:
    - 12 pattern-clustered exclusions (agent=sqli, CWE-89, pattern=db.text_search(*))
      in src/services/ — triggers HIGH-confidence pattern suggestion.
    - 5 directory-clustered exclusions (agent=sqli, CWE-89, varied patterns,
      files under test/) — triggers MEDIUM-confidence directory suggestion.
    - All 17 are signed + active; zero quarantined.
    - Single agent and single CWE (sqli / CWE-89) — mixed-state coverage
      lives in test_mixed_state_flow below.
    """
    # 1. Initialize trust
    run_init_trust(project_root=tmp_path, name="Marco", email="marco@example.com")

    # 2. Record 12 exclusions matching the same pattern
    for i in range(_N_PATTERN_EXCLUSIONS):
        record_exclusion(
            tmp_path,
            ExclusionInput(
                agent="sqli",
                finding=ExclusionFinding(
                    file=f"src/services/s{i}.py",
                    line=42,
                    code_pattern="db.text_search(*)",
                    cwe="CWE-89",
                ),
                reason="full-text search with parameterized internals",
                scope=ExclusionScope(type="pattern", pattern="db.text_search(*)"),
            ),
        )

    # 3. Record 5 exclusions concentrated in test/ directory
    for i in range(_N_DIR_EXCLUSIONS):
        record_exclusion(
            tmp_path,
            ExclusionInput(
                agent="sqli",
                finding=ExclusionFinding(
                    file=f"test/test_a{i}.py",
                    line=10,
                    code_pattern=f"fixture_query{i}(*)",
                    cwe="CWE-89",
                ),
                reason="test fixture data",
                scope=ExclusionScope(type="exact_line", path=f"test/test_a{i}.py"),
            ),
        )

    # 4. Aggregate via the engine
    # ScanEngine.from_defaults() is hermetic: it constructs a fresh registry from
    # the repo's domains/ directory with no env-var or cache dependencies, so
    # per-test calls are independent (no shared state between tests).
    engine = ScanEngine.from_defaults()
    report = engine.aggregate_learning(project_root=tmp_path, report_type="all")

    # 5. Verify all four sections + trust_status
    assert "pattern_confidence" in report
    assert "directory_suggestions" in report
    assert "fp_report" in report
    assert "trust_status" in report

    # Pattern confidence: the db.text_search pattern is surfaced with exact count
    patterns_by_name = {s["pattern"]: s for s in report["pattern_confidence"]}
    assert "db.text_search(*)" in patterns_by_name
    db_sugg = patterns_by_name["db.text_search(*)"]
    assert db_sugg["evidence"]["exclusion_count"] == _N_PATTERN_EXCLUSIONS
    assert db_sugg["confidence"] == "high"  # 12 >= _PATTERN_HIGH_COUNT

    # Directory suggestions: test/ is surfaced with exact count
    dirs_by_name = {s["directory"]: s for s in report["directory_suggestions"]}
    assert "test/" in dirs_by_name
    test_sugg = dirs_by_name["test/"]
    assert test_sugg["evidence"]["total_findings_in_directory"] == _N_DIR_EXCLUSIONS
    assert test_sugg["confidence"] == "medium"  # 5 >= _DIR_MEDIUM_COUNT, < _DIR_HIGH_COUNT

    # FP report: the pattern bucket appears with exact fp_count and the fixture reason
    fp_patterns_by_name = {p["pattern"]: p for p in report["fp_report"]["top_fp_patterns"]}
    assert "db.text_search(*)" in fp_patterns_by_name
    db_fp = fp_patterns_by_name["db.text_search(*)"]
    assert db_fp["fp_count"] == _N_PATTERN_EXCLUSIONS
    assert db_fp["agent"] == "sqli"
    assert db_fp["cwe"] == "CWE-89"
    assert "full-text search with parameterized internals" in db_fp["example_reasons"]

    # Trust status: all 17 recorded entries are active, none quarantined
    assert report["trust_status"]["exclusion_active_count"] == _N_TOTAL_HAPPY_PATH
    assert report["trust_status"]["exclusion_quarantine_count"] == 0

    # Side-effect verification: exclusions.yaml exists with the expected number of signed entries
    import yaml
    excl_path = tmp_path / ".screw" / "learning" / "exclusions.yaml"
    assert excl_path.exists(), f"Expected .screw/learning/exclusions.yaml at {excl_path}"
    loaded_yaml = yaml.safe_load(excl_path.read_text())
    assert isinstance(loaded_yaml, list) or isinstance(loaded_yaml, dict)
    entries = loaded_yaml if isinstance(loaded_yaml, list) else loaded_yaml.get("exclusions", [])
    assert len(entries) == _N_TOTAL_HAPPY_PATH
    # Each entry must have a non-empty signature field (signed on record_exclusion).
    for entry in entries:
        assert "signature" in entry
        assert entry["signature"]
        assert "signed_by" in entry
        assert entry["signed_by"]


def test_empty_exclusions_empty_reports(tmp_path: Path):
    """Empty project: no exclusions -> all sections empty + trust_status zeros.

    Verifies that the aggregation pipeline degrades gracefully when
    .screw/learning/exclusions.yaml doesn't exist — no crashes, no
    synthesized bogus data, trust_status reports zero on both axes.
    """
    engine = ScanEngine.from_defaults()
    report = engine.aggregate_learning(project_root=tmp_path, report_type="all")

    assert report["pattern_confidence"] == []
    assert report["directory_suggestions"] == []
    assert report["fp_report"]["top_fp_patterns"] == []
    assert report["trust_status"]["exclusion_active_count"] == 0
    assert report["trust_status"]["exclusion_quarantine_count"] == 0


def test_mixed_state_flow_multi_agent_multi_cwe_with_quarantine(tmp_path: Path):
    """E2E with mixed CWEs + agents + one tampered signature.

    Fixture design:
    - 10 exclusions: agent=sqli, CWE-89, pattern=shared_pattern (triggers HIGH pattern)
    - 3 exclusions:  agent=sqli, CWE-78 (cross-CWE grouping — must NOT collapse with above)
    - 3 exclusions:  agent=cmdi, CWE-78 (cross-agent grouping — must NOT collapse with prior)
    - Tamper 1 signature on one of the SQLi/CWE-89 entries -> quarantines on reload.

    Pre-tamper total: 16. Active after quarantine: 15. Quarantined: 1.

    Verifies integration invariants that unit tests cover per-function but
    that E2E wiring could still break:
    - Quarantined entries reach trust_status.quarantine_count (not silently dropped)
    - Quarantined entries are filtered OUT of pattern/directory/FP aggregation
    - Cross-CWE / cross-agent entries produce separate pattern-confidence buckets
    """
    # 1. Init trust
    run_init_trust(project_root=tmp_path, name="Marco", email="marco@example.com")

    # 2. Record 10 SQLi / CWE-89 entries hitting HIGH pattern threshold
    for i in range(10):
        record_exclusion(
            tmp_path,
            ExclusionInput(
                agent="sqli",
                finding=ExclusionFinding(
                    file=f"src/s{i}.py",
                    line=10,
                    code_pattern="shared_pattern",
                    cwe="CWE-89",
                ),
                reason="bounded internal call",
                scope=ExclusionScope(type="pattern", pattern="shared_pattern"),
            ),
        )

    # 3. Record 3 SQLi / CWE-78 entries (cross-CWE under same agent)
    for i in range(3):
        record_exclusion(
            tmp_path,
            ExclusionInput(
                agent="sqli",
                finding=ExclusionFinding(
                    file=f"src/cwe78_{i}.py",
                    line=20,
                    code_pattern="shared_pattern",
                    cwe="CWE-78",
                ),
                reason="cwe78 case",
                scope=ExclusionScope(type="pattern", pattern="shared_pattern"),
            ),
        )

    # 4. Record 3 CmdI / CWE-78 entries (cross-agent under same CWE)
    for i in range(3):
        record_exclusion(
            tmp_path,
            ExclusionInput(
                agent="cmdi",
                finding=ExclusionFinding(
                    file=f"src/cmdi_{i}.py",
                    line=30,
                    code_pattern="shared_pattern",
                    cwe="CWE-78",
                ),
                reason="cmdi case",
                scope=ExclusionScope(type="pattern", pattern="shared_pattern"),
            ),
        )

    # 5. Tamper one signature so it quarantines on reload.
    #    The YAML emitter writes bare scalars for signature values.
    excl_path = tmp_path / ".screw" / "learning" / "exclusions.yaml"
    text = excl_path.read_text()
    text = text.replace("signature: ", "signature: A", 1)
    excl_path.write_text(text)

    # 6. Aggregate via the engine
    engine = ScanEngine.from_defaults()
    report = engine.aggregate_learning(project_root=tmp_path, report_type="all")

    # 7. Trust status: exactly 1 quarantined, 15 active
    assert report["trust_status"]["exclusion_quarantine_count"] == 1
    assert report["trust_status"]["exclusion_active_count"] == 15

    # 8. Pattern confidence: three distinct buckets (agent, cwe, pattern triple)
    #    must survive the mixed fixture. Quarantined entry reduces the
    #    sqli+CWE-89 bucket from 10 -> 9 (still HIGH).
    keyed = {(s["agent"], s["cwe"], s["pattern"]): s for s in report["pattern_confidence"]}
    assert ("sqli", "CWE-89", "shared_pattern") in keyed
    assert ("sqli", "CWE-78", "shared_pattern") in keyed
    assert ("cmdi", "CWE-78", "shared_pattern") in keyed
    assert keyed[("sqli", "CWE-89", "shared_pattern")]["evidence"]["exclusion_count"] == 9
    assert keyed[("sqli", "CWE-89", "shared_pattern")]["confidence"] == "medium"  # 9 in [5,10)
    assert keyed[("sqli", "CWE-78", "shared_pattern")]["evidence"]["exclusion_count"] == 3
    assert keyed[("cmdi", "CWE-78", "shared_pattern")]["evidence"]["exclusion_count"] == 3

    # 9. FP report: three distinct (agent, cwe, pattern) buckets above threshold
    fp_keys = {(p["agent"], p["cwe"], p["pattern"]) for p in report["fp_report"]["top_fp_patterns"]}
    assert ("sqli", "CWE-89", "shared_pattern") in fp_keys
    assert ("sqli", "CWE-78", "shared_pattern") in fp_keys
    assert ("cmdi", "CWE-78", "shared_pattern") in fp_keys
