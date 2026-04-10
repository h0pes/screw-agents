"""Tests for benchmarks.runner.cwe — CWE-1400 hierarchy traversal."""
import pytest

from benchmarks.runner.cwe import Cwe1400Hierarchy, load_hierarchy


@pytest.fixture(scope="module")
def hierarchy() -> Cwe1400Hierarchy:
    return load_hierarchy()


def test_phase1_cwes_present(hierarchy: Cwe1400Hierarchy):
    for cwe in ("CWE-79", "CWE-78", "CWE-89", "CWE-1336"):
        assert cwe in hierarchy.nodes, f"{cwe} missing from hierarchy"


def test_category_1409_has_injection_children(hierarchy: Cwe1400Hierarchy):
    # CWE-1409 is "Comprehensive Categorization: Injection" (not CWE-1406
    # which is "Input Validation" — a distinct category).
    assert "CWE-1409" in hierarchy.nodes
    cat = hierarchy.nodes["CWE-1409"]
    assert cat.abstraction == "Category"
    descendants = hierarchy.descendants_of("CWE-1409")
    assert "CWE-74" in descendants or "CWE-79" in descendants, \
        "Expected CWE-1409 to reach injection CWEs transitively"


def test_broad_match_same_category(hierarchy: Cwe1400Hierarchy):
    """CWE-79 and CWE-89 are both in the injection category — broad match."""
    assert hierarchy.broad_match("CWE-79", "CWE-89") is True


def test_broad_match_different_category(hierarchy: Cwe1400Hierarchy):
    """CWE-79 (injection) and CWE-327 (crypto) should NOT broad-match."""
    if "CWE-327" in hierarchy.nodes:
        assert hierarchy.broad_match("CWE-79", "CWE-327") is False


def test_strict_match_exact(hierarchy: Cwe1400Hierarchy):
    assert hierarchy.strict_match("CWE-89", "CWE-89") is True


def test_strict_match_descendant(hierarchy: Cwe1400Hierarchy):
    """CWE-564 (Hibernate SQLi) is a variant of CWE-89."""
    if "CWE-564" in hierarchy.nodes:
        # agent=CWE-564 (more specific) vs truth=CWE-89 (parent) — matches
        assert hierarchy.strict_match(agent_cwe="CWE-564", truth_cwe="CWE-89") is True
        # agent=CWE-89 (parent) vs truth=CWE-564 (child) — does NOT match
        assert hierarchy.strict_match(agent_cwe="CWE-89", truth_cwe="CWE-564") is False


def test_unknown_cwe_returns_false(hierarchy: Cwe1400Hierarchy):
    assert hierarchy.broad_match("CWE-999999", "CWE-89") is False
    assert hierarchy.strict_match("CWE-999999", "CWE-89") is False


def test_category_of_phase1_cwes(hierarchy: Cwe1400Hierarchy):
    """All four Phase 1 CWEs should resolve to a CWE-14xx category."""
    for cwe in ("CWE-79", "CWE-78", "CWE-89", "CWE-1336"):
        cat = hierarchy.category_of(cwe)
        assert cat is not None, f"{cwe} has no CWE-1400 category"
        assert cat.startswith("CWE-14"), f"{cwe} category {cat} is not CWE-14xx"
