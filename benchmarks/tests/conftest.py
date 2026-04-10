# benchmarks/tests/conftest.py
"""Shared pytest fixtures for benchmark runner tests."""
from pathlib import Path

import pytest


@pytest.fixture
def fixtures_dir() -> Path:
    """Directory containing synthetic SARIF test fixtures."""
    return Path(__file__).parent / "fixtures"
