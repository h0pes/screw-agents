"""Tests for benchmark code extraction."""
from __future__ import annotations

from pathlib import Path

import pytest

from benchmarks.runner.code_extractor import (
    extract_code_for_case,
    CodeVariant,
)
from benchmarks.runner.models import (
    BenchmarkCase,
    CodeLocation,
    Finding,
    FindingKind,
    Language,
)


@pytest.fixture
def tmp_reality_check(tmp_path):
    """Create a minimal reality-check directory structure."""
    repo = tmp_path / "reality-check-csharp" / "repo"
    vuln_dir = repo / "csharp" / "projects" / "myproj" / "myproj-1.0.0"
    vuln_dir.mkdir(parents=True)
    (vuln_dir / "Controller.cs").write_text("public void Render() { Response.Write(input); }")
    patch_dir = repo / "csharp" / "projects" / "myproj" / "myproj-1.0.1"
    patch_dir.mkdir(parents=True)
    (patch_dir / "Controller.cs").write_text("public void Render() { Response.Write(Encode(input)); }")
    return tmp_path


@pytest.fixture
def rc_case():
    return BenchmarkCase(
        case_id="rc-csharp-myproj-CVE-2024-001",
        project="myproj",
        language=Language.CSHARP,
        vulnerable_version="myproj-1.0.0",
        patched_version="myproj-1.0.1",
        ground_truth=[
            Finding(cwe_id="CWE-79", kind=FindingKind.FAIL,
                    location=CodeLocation(file="Controller.cs", start_line=1, end_line=1)),
            Finding(cwe_id="CWE-79", kind=FindingKind.PASS,
                    location=CodeLocation(file="Controller.cs", start_line=1, end_line=1)),
        ],
        source_dataset="reality-check-csharp",
    )


@pytest.fixture
def tmp_crossvul(tmp_path):
    """Create a minimal CrossVul directory structure."""
    cwe_dir = tmp_path / "crossvul" / "CWE-79" / "php"
    cwe_dir.mkdir(parents=True)
    (cwe_dir / "bad_001.php").write_text("<?php echo $_GET['x']; ?>")
    (cwe_dir / "good_001.php").write_text("<?php echo htmlspecialchars($_GET['x']); ?>")
    return tmp_path


@pytest.fixture
def crossvul_case():
    return BenchmarkCase(
        case_id="crossvul-79-php-001.php",
        project="crossvul-php",
        language=Language.PHP,
        vulnerable_version="bad",
        patched_version="good",
        ground_truth=[
            Finding(cwe_id="CWE-79", kind=FindingKind.FAIL,
                    location=CodeLocation(file="bad_001.php", start_line=1, end_line=1),
                    message="<?php echo $_GET['x']; ?>"),
            Finding(cwe_id="CWE-79", kind=FindingKind.PASS,
                    location=CodeLocation(file="good_001.php", start_line=1, end_line=1),
                    message="<?php echo htmlspecialchars($_GET['x']); ?>"),
        ],
        source_dataset="crossvul",
    )


@pytest.fixture
def tmp_gosec(tmp_path):
    """Create a minimal go-sec-code-mutated directory structure."""
    repo = tmp_path / "go-sec-code-mutated" / "repo"
    vuln_file = repo / "cmd" / "sqli" / "main.go"
    vuln_file.parent.mkdir(parents=True)
    vuln_file.write_text('db.Query("SELECT * FROM users WHERE id=" + id)')
    return tmp_path


@pytest.fixture
def gosec_case():
    return BenchmarkCase(
        case_id="gosec-cmd-sqli",
        project="go-sec-code",
        language=Language.GO,
        vulnerable_version="HEAD",
        patched_version="HEAD-patched",
        ground_truth=[
            Finding(cwe_id="CWE-89", kind=FindingKind.FAIL,
                    location=CodeLocation(file="cmd/sqli/main.go", start_line=1, end_line=1)),
            Finding(cwe_id="CWE-89", kind=FindingKind.PASS,
                    location=CodeLocation(file="cmd/sqli/main.go", start_line=1, end_line=1)),
        ],
        source_dataset="go-sec-code-mutated",
    )


class TestExtractCodeForCase:
    def test_reality_check_extracts_vuln_and_patched(self, tmp_reality_check, rc_case):
        vuln = extract_code_for_case(rc_case, CodeVariant.VULNERABLE, tmp_reality_check)
        patched = extract_code_for_case(rc_case, CodeVariant.PATCHED, tmp_reality_check)
        assert len(vuln) == 1
        assert "Response.Write(input)" in vuln[0].content
        assert len(patched) == 1
        assert "Encode(input)" in patched[0].content

    def test_crossvul_extracts_bad_good_pairs(self, tmp_crossvul, crossvul_case):
        vuln = extract_code_for_case(crossvul_case, CodeVariant.VULNERABLE, tmp_crossvul)
        patched = extract_code_for_case(crossvul_case, CodeVariant.PATCHED, tmp_crossvul)
        assert len(vuln) == 1
        assert "$_GET" in vuln[0].content
        assert "echo" in vuln[0].content
        assert len(patched) == 1
        assert "htmlspecialchars" in patched[0].content

    def test_gosec_extracts_vuln_no_patched(self, tmp_gosec, gosec_case):
        vuln = extract_code_for_case(gosec_case, CodeVariant.VULNERABLE, tmp_gosec)
        patched = extract_code_for_case(gosec_case, CodeVariant.PATCHED, tmp_gosec)
        assert len(vuln) == 1
        assert "SELECT" in vuln[0].content
        assert len(patched) == 0

    def test_missing_dataset_dir_raises(self, tmp_path, rc_case):
        with pytest.raises(FileNotFoundError):
            extract_code_for_case(rc_case, CodeVariant.VULNERABLE, tmp_path)
