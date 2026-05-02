"""Tests for the evaluation orchestrator."""
# ruff: noqa: S101
from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from benchmarks.runner.code_extractor import CodeVariant, ExtractedCode
from benchmarks.runner.cwe import load_hierarchy
from benchmarks.runner.evaluator import (
    EvalConfig,
    Evaluator,
    build_prompt,
    load_cases_from_manifest,
    map_case_to_agent,
    parse_findings_response,
)
from benchmarks.runner.invoker import InvokeResult
from benchmarks.runner.models import (
    BenchmarkCase,
    CodeLocation,
    Finding,
    FindingKind,
    Language,
)


@pytest.fixture
def sample_manifest(tmp_path):
    manifest = {
        "dataset_name": "test-dataset",
        "source_url": "https://example.com",
        "case_count": 2,
        "cases": [
            {
                "case_id": "test-1",
                "project": "proj",
                "language": "python",
                "vulnerable_version": "v1",
                "patched_version": "v2",
                "published_date": None,
                "fail_count": 1,
                "pass_count": 1,
            },
            {
                "case_id": "test-2",
                "project": "proj2",
                "language": "go",
                "vulnerable_version": "v1",
                "patched_version": "v2",
                "published_date": None,
                "fail_count": 1,
                "pass_count": 1,
            },
        ],
    }
    path = tmp_path / "test.manifest.json"
    path.write_text(json.dumps(manifest))
    return path


class TestLoadCases:
    def test_loads_cases_from_manifest(self, sample_manifest):
        cases = load_cases_from_manifest(sample_manifest)
        assert len(cases) == 2
        assert cases[0]["case_id"] == "test-1"
        assert cases[0]["language"] == "python"


class TestMapCaseToAgent:
    def test_maps_xss_case(self):
        case = BenchmarkCase(
            case_id="t", project="p", language=Language.PYTHON,
            vulnerable_version="v1", patched_version="v2",
            ground_truth=[
                Finding(cwe_id="CWE-79", kind=FindingKind.FAIL,
                        location=CodeLocation(file="a.py", start_line=1, end_line=1)),
            ],
            source_dataset="test",
        )
        assert map_case_to_agent(case) == "xss"

    def test_returns_none_for_unknown_cwe(self):
        case = BenchmarkCase(
            case_id="t", project="p", language=Language.PYTHON,
            vulnerable_version="v1", patched_version="v2",
            ground_truth=[
                Finding(cwe_id="CWE-502", kind=FindingKind.FAIL,
                        location=CodeLocation(file="a.py", start_line=1, end_line=1)),
            ],
            source_dataset="test",
        )
        assert map_case_to_agent(case) is None


class TestBuildPrompt:
    def test_includes_instructions_and_code(self):
        prompt = build_prompt(
            core_prompt="Detect XSS vulnerabilities.",
            code="var x = document.innerHTML;",
            file_path="view.js",
        )
        assert "Detect XSS" in prompt
        assert "document.innerHTML" in prompt
        assert "JSON" in prompt

    def test_requires_exact_sink_line_anchoring(self):
        prompt = build_prompt(
            core_prompt="Detect SQL injection vulnerabilities.",
            code="db.query(sql)",
            file_path="dao.py",
        )

        assert "Line-location discipline" in prompt
        assert "exact vulnerable expression/call" in prompt
        assert "span must cover that named call/expression" in prompt
        assert "function declaration" in prompt

    def test_includes_related_context_as_context_only(self):
        prompt = build_prompt(
            core_prompt="Detect command injection.",
            code="class Shell {}",
            file_path="Shell.java",
            context_files=[
                ExtractedCode(
                    file_path="BourneShell.java",
                    content="class BourneShell extends Shell {}",
                    language="java",
                )
            ],
        )

        assert "## Related Files For Context" in prompt
        assert "**Context file:** `BourneShell.java`" in prompt
        assert "findings only\nfor the primary file `Shell.java`" in prompt


class TestParseFindingsResponse:
    def test_parses_valid_findings(self):
        raw = [
            {"cwe_id": "CWE-79", "file": "a.js", "start_line": 10,
             "end_line": 15, "confidence": 0.9, "message": "XSS"}
        ]
        findings = parse_findings_response(raw, agent_name="xss")
        assert len(findings) == 1
        assert findings[0].cwe_id == "CWE-79"
        assert findings[0].agent_name == "xss"

    def test_skips_malformed_entries(self):
        raw = [
            {"cwe_id": "CWE-79"},  # missing required fields
            {"cwe_id": "CWE-79", "file": "a.js", "start_line": 1,
             "end_line": 5, "confidence": 0.8, "message": "ok"},
        ]
        findings = parse_findings_response(raw, agent_name="xss")
        assert len(findings) == 1


class TestEvaluatorRelatedContext:
    def test_max_files_per_variant_uses_ranked_cap_for_execution(self, tmp_path):
        case = BenchmarkCase(
            case_id="ranked-cap",
            project="p",
            language=Language.CSHARP,
            vulnerable_version="v1",
            patched_version="v2",
            ground_truth=[
                Finding(
                    cwe_id="CWE-89",
                    kind=FindingKind.FAIL,
                    location=CodeLocation(
                        file="src/App.Test/SqlBuilderFixture.cs",
                        start_line=1,
                        end_line=1,
                    ),
                ),
                Finding(
                    cwe_id="CWE-89",
                    kind=FindingKind.FAIL,
                    location=CodeLocation(
                        file="src/App/SqlBuilder.cs",
                        start_line=1,
                        end_line=1,
                    ),
                ),
            ],
            source_dataset="reality-check-csharp",
        )

        def extract(
            *_args,
            include_related_context=False,
            include_helper_context=False,
        ):
            assert include_related_context is False
            assert include_helper_context is False
            return [
                ExtractedCode(
                    file_path="src/App.Test/SqlBuilderFixture.cs",
                    content="test",
                    language="csharp",
                ),
                ExtractedCode(
                    file_path="src/App/SqlBuilder.cs",
                    content="prod",
                    language="csharp",
                ),
            ]

        invoked_files = []

        def invoke(
            prompt: str,
            _config: object,
            context: dict[str, object] | None = None,
        ) -> InvokeResult:
            assert prompt
            assert context is not None
            invoked_files.append(context["file"])
            return InvokeResult(success=True, findings=[])

        engine = MagicMock()
        engine.assemble_scan.return_value = {
            "core_prompt": "Detect SQL injection.",
            "code": "prod",
        }
        evaluator = Evaluator(
            EvalConfig(
                results_dir=tmp_path,
                max_files_per_variant=1,
            )
        )
        evaluator._cases_dir.mkdir(parents=True)

        with (
            patch("benchmarks.runner.evaluator.extract_code_for_case", side_effect=extract),
            patch("benchmarks.runner.evaluator.invoke_claude", side_effect=invoke),
        ):
            evaluator._scan_variant(case, "sqli", CodeVariant.VULNERABLE, engine)

        assert invoked_files == ["src/App/SqlBuilder.cs"]

    def test_max_files_per_variant_scopes_metrics_to_evaluated_files(self, tmp_path):
        case = BenchmarkCase(
            case_id="scored-cap",
            project="p",
            language=Language.CSHARP,
            vulnerable_version="v1",
            patched_version="v2",
            ground_truth=[
                Finding(
                    cwe_id="CWE-89",
                    kind=FindingKind.FAIL,
                    location=CodeLocation(
                        file="src/App/SqlBuilder.cs",
                        start_line=10,
                        end_line=10,
                    ),
                ),
                Finding(
                    cwe_id="CWE-89",
                    kind=FindingKind.FAIL,
                    location=CodeLocation(
                        file="src/App/OtherQuery.cs",
                        start_line=20,
                        end_line=20,
                    ),
                ),
                Finding(
                    cwe_id="CWE-89",
                    kind=FindingKind.PASS,
                    location=CodeLocation(
                        file="src/App/SqlBuilder.cs",
                        start_line=10,
                        end_line=10,
                    ),
                ),
                Finding(
                    cwe_id="CWE-89",
                    kind=FindingKind.PASS,
                    location=CodeLocation(
                        file="src/App/OtherQuery.cs",
                        start_line=20,
                        end_line=20,
                    ),
                ),
            ],
            source_dataset="reality-check-csharp",
        )

        def extract(
            *_args,
            include_related_context=False,
            include_helper_context=False,
        ):
            assert include_related_context is False
            assert include_helper_context is False
            return [
                ExtractedCode(
                    file_path="src/App/SqlBuilder.cs",
                    content="query",
                    language="csharp",
                ),
                ExtractedCode(
                    file_path="src/App/OtherQuery.cs",
                    content="other",
                    language="csharp",
                ),
            ]

        def invoke(
            _prompt: str,
            _config: object,
            context: dict[str, object] | None = None,
        ) -> InvokeResult:
            assert context is not None
            if context["variant"] == "vulnerable":
                return InvokeResult(
                    success=True,
                    findings=[
                        {
                            "cwe_id": "CWE-89",
                            "file": "ignored-by-normalizer.cs",
                            "start_line": 10,
                            "end_line": 10,
                            "confidence": 0.9,
                            "message": "SQLi",
                        }
                    ],
                )
            return InvokeResult(success=True, findings=[])

        engine = MagicMock()
        engine.assemble_scan.return_value = {
            "core_prompt": "Detect SQL injection.",
            "code": "query",
        }
        evaluator = Evaluator(
            EvalConfig(
                results_dir=tmp_path,
                max_files_per_variant=1,
            )
        )
        evaluator._cases_dir.mkdir(parents=True)

        with (
            patch("benchmarks.runner.evaluator.extract_code_for_case", side_effect=extract),
            patch("benchmarks.runner.evaluator.invoke_claude", side_effect=invoke),
        ):
            summary = evaluator._evaluate_group(
                "sqli",
                "reality-check-csharp",
                [case],
                engine,
                load_hierarchy(),
            )

        metric = next(
            metric
            for metric in summary.metrics
            if metric.cwe_id is None and metric.language is None
        )
        assert metric.true_positives == 1
        assert metric.false_negatives == 0
        assert metric.true_negatives == 1

    def test_related_context_can_be_enabled_for_one_case(self, tmp_path):
        case = BenchmarkCase(
            case_id="needs-context",
            project="p",
            language=Language.JAVA,
            vulnerable_version="v1",
            patched_version="v2",
            ground_truth=[
                Finding(
                    cwe_id="CWE-78",
                    kind=FindingKind.FAIL,
                    location=CodeLocation(file="Shell.java", start_line=1, end_line=1),
                )
            ],
            source_dataset="reality-check-java",
        )
        include_values = []

        def extract(
            *_args,
            include_related_context=False,
            include_helper_context=False,
        ):
            include_values.append(include_related_context)
            assert include_helper_context is False
            return [
                ExtractedCode(
                    file_path="Shell.java",
                    content="class Shell {}",
                    language="java",
                )
            ]

        engine = MagicMock()
        engine.assemble_scan.return_value = {
            "core_prompt": "Detect command injection.",
            "code": "class Shell {}",
        }
        evaluator = Evaluator(
            EvalConfig(
                results_dir=tmp_path,
                include_related_context_case_ids={"needs-context"},
            )
        )

        with (
            patch("benchmarks.runner.evaluator.extract_code_for_case", side_effect=extract),
            patch(
                "benchmarks.runner.evaluator.invoke_claude",
                return_value=InvokeResult(success=True, findings=[]),
            ),
        ):
            evaluator._scan_variant(case, "cmdi", CodeVariant.PATCHED, engine)

        assert include_values == [True]
