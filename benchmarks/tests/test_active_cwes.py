"""Tests for the central active-CWE registry."""
from benchmarks.scripts._active_cwes import (
    ACTIVE_CWE_DIGITS,
    ACTIVE_CWE_INTS,
    ACTIVE_CWES,
)


def test_phase1_cwes_present():
    for cwe in ("CWE-78", "CWE-79", "CWE-89", "CWE-94", "CWE-1336"):
        assert cwe in ACTIVE_CWES


def test_int_form_derived_from_string_form():
    assert ACTIVE_CWE_INTS == {int(c.removeprefix("CWE-")) for c in ACTIVE_CWES}


def test_digit_form_matches_int_form():
    assert ACTIVE_CWE_DIGITS == {str(n) for n in ACTIVE_CWE_INTS}


def test_sets_are_frozen():
    import pytest
    with pytest.raises((AttributeError, TypeError)):
        ACTIVE_CWES.add("CWE-999")  # type: ignore[attr-defined]
