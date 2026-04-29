"""Tests for benchmark code extraction."""
from __future__ import annotations

import json
import subprocess

import pytest

from benchmarks.runner.code_extractor import (
    CodeVariant,
    extract_code_for_case,
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
    vuln_dir = repo / "csharp" / "benchmark" / "myproj" / "myproj-1.0.0"
    vuln_dir.mkdir(parents=True)
    (vuln_dir / "Controller.cs").write_text("using System;\nnamespace MyApp {\n    public class Controller {\n        public void Render(string input) {\n            Response.Write(input); // XSS vulnerability\n        }\n    }\n}")
    patch_dir = repo / "csharp" / "benchmark" / "myproj" / "myproj-1.0.1"
    patch_dir.mkdir(parents=True)
    (patch_dir / "Controller.cs").write_text("using System;\nnamespace MyApp {\n    public class Controller {\n        public void Render(string input) {\n            Response.Write(Encode(input)); // safe\n        }\n    }\n}")
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
def tmp_reality_check_java(tmp_path):
    repo = tmp_path / "reality-check-java" / "repo"
    vuln_dir = repo / "java" / "benchmark" / "plexus" / "plexus-1.0.0"
    patch_dir = repo / "java" / "benchmark" / "plexus" / "plexus-1.0.1"
    vuln_dir.mkdir(parents=True)
    patch_dir.mkdir(parents=True)
    (vuln_dir / "Shell.java").write_text(
        "class Shell {\n"
        "  String[] getCommandLine(String executable, String[] args) {\n"
        "    return new String[] { executable, String.join(\" \", args) };\n"
        "  }\n"
        "}\n"
    )
    (vuln_dir / "BourneShell.java").write_text(
        "class BourneShell extends Shell {\n"
        "  String quoteOneItem(String item) { return item; }\n"
        "}\n"
    )
    (patch_dir / "Shell.java").write_text(
        "class Shell {\n"
        "  String[] getCommandLine(String executable, String[] args) {\n"
        "    return new String[] { executable, String.join(\" \", args) };\n"
        "  }\n"
        "}\n"
    )
    (patch_dir / "BourneShell.java").write_text(
        "class BourneShell extends Shell {\n"
        "  String quoteOneItem(String item) { return \"'\" + item + \"'\"; }\n"
        "}\n"
    )
    return tmp_path


@pytest.fixture
def rc_java_case():
    return BenchmarkCase(
        case_id="rc-java-plexus-utils-CVE-2017-1000487",
        project="plexus",
        language=Language.JAVA,
        vulnerable_version="plexus-1.0.0",
        patched_version="plexus-1.0.1",
        ground_truth=[
            Finding(
                cwe_id="CWE-78",
                kind=FindingKind.FAIL,
                location=CodeLocation(file="Shell.java", start_line=1, end_line=4),
            ),
            Finding(
                cwe_id="CWE-78",
                kind=FindingKind.FAIL,
                location=CodeLocation(
                    file="BourneShell.java", start_line=1, end_line=3
                ),
            ),
            Finding(
                cwe_id="CWE-78",
                kind=FindingKind.PASS,
                location=CodeLocation(file="Shell.java", start_line=1, end_line=4),
            ),
            Finding(
                cwe_id="CWE-78",
                kind=FindingKind.PASS,
                location=CodeLocation(
                    file="BourneShell.java", start_line=1, end_line=3
                ),
            ),
        ],
        source_dataset="reality-check-java",
    )


@pytest.fixture
def tmp_crossvul(tmp_path):
    """Create a minimal CrossVul directory structure."""
    cwe_dir = tmp_path / "crossvul" / "CWE-79" / "php"
    cwe_dir.mkdir(parents=True)
    (cwe_dir / "bad_001.php").write_text("<?php\nfunction render() {\n    $name = $_GET['x'];\n    echo $name; // XSS vulnerability\n}\n?>")
    (cwe_dir / "good_001.php").write_text("<?php\nfunction render() {\n    $name = $_GET['x'];\n    echo htmlspecialchars($name); // safe\n}\n?>")
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
                    message="<?php\nfunction render() {\n    $name = $_GET['x'];\n    echo $name; // XSS vulnerability\n}\n?>"),
            Finding(cwe_id="CWE-79", kind=FindingKind.PASS,
                    location=CodeLocation(file="good_001.php", start_line=1, end_line=1),
                    message="<?php\nfunction render() {\n    $name = $_GET['x'];\n    echo htmlspecialchars($name); // safe\n}\n?>"),
        ],
        source_dataset="crossvul",
    )


@pytest.fixture
def tmp_gosec(tmp_path):
    """Create a minimal go-sec-code-mutated directory structure."""
    repo = tmp_path / "go-sec-code-mutated" / "repo"
    vuln_file = repo / "cmd" / "sqli" / "main.go"
    vuln_file.parent.mkdir(parents=True)
    vuln_file.write_text('package main\n\nimport "database/sql"\n\nfunc getUser(db *sql.DB, id string) {\n\tdb.Query("SELECT * FROM users WHERE id=" + id)\n}\n')
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


@pytest.fixture
def tmp_morefixes(tmp_path):
    case_dir = tmp_path / "morefixes" / "morefixes-CVE-2024-0001-example"
    vuln = case_dir / "code" / "vulnerable" / "src%2Fdb.php"
    patched = case_dir / "code" / "patched" / "src%2Fdb.php"
    vuln.parent.mkdir(parents=True)
    patched.parent.mkdir(parents=True)
    vuln.write_text(
        "<?php\n"
        "function user($id) {\n"
        "  return query('SELECT * FROM users WHERE id=' . $id);\n"
        "}\n"
    )
    patched.write_text(
        "<?php\n"
        "function user($db, $id) {\n"
        "  return prepared_query($db, 'SELECT * FROM users WHERE id=?', [$id]);\n"
        "}\n"
    )
    return tmp_path


@pytest.fixture
def tmp_ossf(tmp_path):
    repo = tmp_path / "ossf-cve-benchmark" / "repo"
    (repo / "lib").mkdir(parents=True)
    (repo / "lib" / "index.js").write_text(
        "\n".join([f"line {line_no}" for line_no in range(1, 41)]) + "\n",
        encoding="utf-8",
    )
    return tmp_path


@pytest.fixture
def tmp_ossf_bad_basename_fallback(tmp_path):
    repo = tmp_path / "ossf-cve-benchmark" / "repo"
    repo.mkdir(parents=True)
    (repo / "index.js").write_text("module.exports = {};\n", encoding="utf-8")
    return tmp_path


@pytest.fixture
def morefixes_case():
    return BenchmarkCase(
        case_id="morefixes-CVE-2024-0001-example",
        project="https://github.com/example/app",
        language=Language.PHP,
        vulnerable_version="pre-deadbeef",
        patched_version="deadbeef",
        ground_truth=[
            Finding(
                cwe_id="CWE-89",
                kind=FindingKind.FAIL,
                location=CodeLocation(file="src/db.php", start_line=1, end_line=3),
            ),
            Finding(
                cwe_id="CWE-89",
                kind=FindingKind.PASS,
                location=CodeLocation(file="src/db.php", start_line=1, end_line=3),
            ),
        ],
        source_dataset="morefixes",
    )


@pytest.fixture
def ossf_case():
    return BenchmarkCase(
        case_id="ossf-CVE-2018-16484",
        project="https://github.com/nunnly/m-server.git",
        language=Language.JAVASCRIPT,
        vulnerable_version="pre-patch",
        patched_version="post-patch",
        ground_truth=[
            Finding(
                cwe_id="CWE-79",
                kind=FindingKind.FAIL,
                location=CodeLocation(file="lib/index.js", start_line=39, end_line=39),
            ),
            Finding(
                cwe_id="CWE-79",
                kind=FindingKind.PASS,
                location=CodeLocation(file="lib/index.js", start_line=39, end_line=39),
            ),
        ],
        source_dataset="ossf-cve-benchmark",
    )


@pytest.fixture
def tmp_rust_d01(tmp_path):
    repo = tmp_path / "rust-d01-real-cves" / "repos" / "example__rust-app"
    repo.mkdir(parents=True)
    subprocess.run(["git", "init"], cwd=repo, check=True, capture_output=True)
    subprocess.run(
        ["git", "config", "user.email", "test@example.invalid"],
        cwd=repo,
        check=True,
    )
    subprocess.run(["git", "config", "user.name", "Test User"], cwd=repo, check=True)
    src = repo / "src"
    src.mkdir()
    (src / "lib.rs").write_text(
        "pub fn query(id: &str) -> String {\n"
        "    format!(\"SELECT * FROM users WHERE id={}\", id)\n"
        "}\n"
    )
    subprocess.run(["git", "add", "src/lib.rs"], cwd=repo, check=True)
    subprocess.run(
        ["git", "commit", "-m", "vulnerable"],
        cwd=repo,
        check=True,
        capture_output=True,
    )
    vulnerable_ref = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=repo, text=True
    ).strip()
    (src / "lib.rs").write_text(
        "pub fn query(id: &str) -> (&'static str, &str) {\n"
        "    (\"SELECT * FROM users WHERE id=?\", id)\n"
        "}\n"
    )
    subprocess.run(["git", "add", "src/lib.rs"], cwd=repo, check=True)
    subprocess.run(
        ["git", "commit", "-m", "patched"],
        cwd=repo,
        check=True,
        capture_output=True,
    )
    patched_ref = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=repo, text=True
    ).strip()

    case_dir = tmp_path / "rust-d01-real-cves" / "rust-d01-example-CVE-2024-0002"
    case_dir.mkdir()
    (case_dir / "provenance.json").write_text(
        json.dumps(
            {
                "vulnerable_ref": vulnerable_ref,
                "patched_ref": patched_ref,
            }
        )
    )
    return tmp_path


@pytest.fixture
def rust_d01_case():
    return BenchmarkCase(
        case_id="rust-d01-example-CVE-2024-0002",
        project="example/rust-app",
        language=Language.RUST,
        vulnerable_version="vulnerable",
        patched_version="patched",
        ground_truth=[
            Finding(
                cwe_id="CWE-89",
                kind=FindingKind.FAIL,
                location=CodeLocation(file="src/lib.rs", start_line=1, end_line=3),
            ),
            Finding(
                cwe_id="CWE-89",
                kind=FindingKind.PASS,
                location=CodeLocation(file="src/lib.rs", start_line=1, end_line=3),
            ),
        ],
        source_dataset="rust-d01-real-cves",
    )


class TestExtractCodeForCase:
    def test_reality_check_extracts_vuln_and_patched(self, tmp_reality_check, rc_case):
        vuln = extract_code_for_case(rc_case, CodeVariant.VULNERABLE, tmp_reality_check)
        patched = extract_code_for_case(rc_case, CodeVariant.PATCHED, tmp_reality_check)
        assert len(vuln) == 1
        assert "Response.Write(input)" in vuln[0].content
        assert len(patched) == 1
        assert "Encode(input)" in patched[0].content

    def test_reality_check_extracts_markup_layout(self, tmp_path, rc_case):
        repo = tmp_path / "reality-check-csharp" / "repo"
        vuln_dir = repo / "csharp" / "markup" / "myproj" / "myproj-1.0.0"
        patch_dir = repo / "csharp" / "markup" / "myproj" / "myproj-1.0.1"
        vuln_dir.mkdir(parents=True)
        patch_dir.mkdir(parents=True)
        (vuln_dir / "Controller.cs").write_text("Response.Write(input);")
        (patch_dir / "Controller.cs").write_text("Response.Write(Encode(input));")

        vuln = extract_code_for_case(rc_case, CodeVariant.VULNERABLE, tmp_path)
        patched = extract_code_for_case(rc_case, CodeVariant.PATCHED, tmp_path)

        assert len(vuln) == 1
        assert "Response.Write(input)" in vuln[0].content
        assert len(patched) == 1
        assert "Encode(input)" in patched[0].content

    def test_reality_check_can_attach_related_context(
        self,
        tmp_reality_check_java,
        rc_java_case,
    ):
        patched = extract_code_for_case(
            rc_java_case,
            CodeVariant.PATCHED,
            tmp_reality_check_java,
            include_related_context=True,
        )

        shell = next(piece for piece in patched if piece.file_path == "Shell.java")
        assert [piece.file_path for piece in shell.context_files] == ["BourneShell.java"]
        assert "quoteOneItem" in shell.context_files[0].content

    def test_reality_check_omits_related_context_by_default(
        self,
        tmp_reality_check_java,
        rc_java_case,
    ):
        patched = extract_code_for_case(
            rc_java_case,
            CodeVariant.PATCHED,
            tmp_reality_check_java,
        )

        assert all(piece.context_files == [] for piece in patched)

    def test_crossvul_extracts_bad_good_pairs(self, tmp_crossvul, crossvul_case):
        vuln = extract_code_for_case(crossvul_case, CodeVariant.VULNERABLE, tmp_crossvul)
        patched = extract_code_for_case(crossvul_case, CodeVariant.PATCHED, tmp_crossvul)
        assert len(vuln) == 1
        assert "$_GET" in vuln[0].content
        assert "echo $name" in vuln[0].content
        assert len(patched) == 1
        assert "htmlspecialchars" in patched[0].content

    def test_gosec_extracts_vuln_no_patched(self, tmp_gosec, gosec_case):
        vuln = extract_code_for_case(gosec_case, CodeVariant.VULNERABLE, tmp_gosec)
        patched = extract_code_for_case(gosec_case, CodeVariant.PATCHED, tmp_gosec)
        assert len(vuln) == 1
        assert "SELECT" in vuln[0].content
        assert len(patched) == 0

    def test_morefixes_extracts_materialized_snapshots(self, tmp_morefixes, morefixes_case):
        vuln = extract_code_for_case(morefixes_case, CodeVariant.VULNERABLE, tmp_morefixes)
        patched = extract_code_for_case(morefixes_case, CodeVariant.PATCHED, tmp_morefixes)
        assert len(vuln) == 1
        assert "SELECT * FROM users WHERE id=" in vuln[0].content
        assert len(patched) == 1
        assert "prepared_query" in patched[0].content

    def test_ossf_extracts_file_covering_truth_line(self, tmp_ossf, ossf_case):
        vuln = extract_code_for_case(ossf_case, CodeVariant.VULNERABLE, tmp_ossf)
        patched = extract_code_for_case(ossf_case, CodeVariant.PATCHED, tmp_ossf)

        assert [piece.file_path for piece in vuln] == ["lib/index.js"]
        assert [piece.file_path for piece in patched] == ["lib/index.js"]
        assert "line 39" in vuln[0].content

    def test_ossf_rejects_basename_fallback_that_misses_truth_line(
        self,
        tmp_ossf_bad_basename_fallback,
        ossf_case,
    ):
        vuln = extract_code_for_case(
            ossf_case,
            CodeVariant.VULNERABLE,
            tmp_ossf_bad_basename_fallback,
        )

        assert vuln == []

    def test_rust_d01_extracts_from_local_git_refs(self, tmp_rust_d01, rust_d01_case):
        vuln = extract_code_for_case(rust_d01_case, CodeVariant.VULNERABLE, tmp_rust_d01)
        patched = extract_code_for_case(rust_d01_case, CodeVariant.PATCHED, tmp_rust_d01)
        assert len(vuln) == 1
        assert "format!" in vuln[0].content
        assert len(patched) == 1
        assert "SELECT * FROM users WHERE id=?" in patched[0].content

    def test_missing_dataset_dir_raises(self, tmp_path, rc_case):
        with pytest.raises(FileNotFoundError):
            extract_code_for_case(rc_case, CodeVariant.VULNERABLE, tmp_path)
