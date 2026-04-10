"""Shared fixtures for Phase 1 tests."""

from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
DOMAINS_DIR = REPO_ROOT / "domains"
FIXTURES_DIR = REPO_ROOT / "benchmarks" / "fixtures"


@pytest.fixture
def domains_dir():
    return DOMAINS_DIR


@pytest.fixture
def sqli_yaml_path():
    return DOMAINS_DIR / "injection-input-handling" / "sqli.yaml"


@pytest.fixture
def fixtures_dir():
    return FIXTURES_DIR
