"""Smoke tests for the runner CLI."""
import subprocess
import sys
from pathlib import Path


def test_cli_help_exits_zero():
    result = subprocess.run(
        [sys.executable, "-m", "benchmarks.runner", "--help"],
        capture_output=True, text=True,
    )
    assert result.returncode == 0
    assert "run" in result.stdout
    assert "list" in result.stdout
    assert "validate" in result.stdout


def test_cli_validate_rejects_bad_sarif(tmp_path: Path):
    bad = tmp_path / "bad.sarif"
    bad.write_text("not json at all")
    result = subprocess.run(
        [sys.executable, "-m", "benchmarks.runner", "validate", str(bad)],
        capture_output=True, text=True,
    )
    assert result.returncode != 0


def test_cli_validate_accepts_mini_truth(fixtures_dir: Path):
    truth = fixtures_dir / "mini_truth.sarif"
    result = subprocess.run(
        [sys.executable, "-m", "benchmarks.runner", "validate", str(truth)],
        capture_output=True, text=True,
    )
    assert result.returncode == 0, f"stderr: {result.stderr}"
    assert "valid" in result.stdout.lower() or "ok" in result.stdout.lower()
