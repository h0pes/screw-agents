"""Test the CWE-1400 extraction script produces expected YAML structure."""
from pathlib import Path

import pytest
import yaml


REPO_ROOT = Path(__file__).parent.parent.parent
HIERARCHY_YAML = REPO_ROOT / "benchmarks" / "data" / "cwe-1400-hierarchy.yaml"


def test_hierarchy_yaml_exists():
    """The extracted YAML must be present (committed to the repo)."""
    assert HIERARCHY_YAML.exists(), (
        "Run `python benchmarks/scripts/extract_cwe_1400.py` to regenerate."
    )


def test_hierarchy_contains_phase1_cwes():
    """CWE-1400 view must contain all Phase 1 agent CWEs."""
    data = yaml.safe_load(HIERARCHY_YAML.read_text())
    nodes = data["nodes"]
    for cwe_id in ("CWE-79", "CWE-78", "CWE-89", "CWE-1336"):
        assert cwe_id in nodes, f"{cwe_id} missing from CWE-1400 hierarchy"


def test_hierarchy_has_category_1406():
    """CWE-1406 is the Injection category our Phase 1 agents all live under."""
    data = yaml.safe_load(HIERARCHY_YAML.read_text())
    assert "CWE-1406" in data["nodes"]
    assert data["nodes"]["CWE-1406"]["abstraction"] == "Category"


def test_hierarchy_view_members_listed():
    """Top-level view_members list must contain CWE-1406 (Injection category)."""
    data = yaml.safe_load(HIERARCHY_YAML.read_text())
    assert "CWE-1406" in data["view_members"]
