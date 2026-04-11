"""Benchmark evaluation orchestrator.

Loads cases from manifests, maps them to agents, extracts code from
benchmark datasets, assembles detection prompts via ScanEngine, invokes
Claude, and scores results through the metrics pipeline.
"""
from __future__ import annotations

import json
import logging
import tempfile
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from benchmarks.runner.code_extractor import CodeVariant, ExtractedCode, extract_code_for_case
from benchmarks.runner.cwe import Cwe1400Hierarchy, load_hierarchy
from benchmarks.runner.invoker import InvokeResult, InvokerConfig, invoke_claude
from benchmarks.runner.metrics import compute_metrics
from benchmarks.runner.models import (
    AgentRun,
    BenchmarkCase,
    CodeLocation,
    Finding,
    FindingKind,
    Language,
    Summary,
)
from benchmarks.runner.sarif import load_bentoo_sarif

logger = logging.getLogger(__name__)

_CWE_TO_AGENT: dict[str, str] = {
    "CWE-79": "xss",
    "CWE-78": "cmdi",
    "CWE-89": "sqli",
    "CWE-94": "ssti",
    "CWE-1336": "ssti",
}

REPO_ROOT = Path(__file__).resolve().parents[2]


@dataclass
class EvalConfig:
    mode: str = "sample"
    results_dir: Path = field(default_factory=lambda: REPO_ROOT / "benchmarks" / "results")
    benchmarks_external_dir: Path = field(default_factory=lambda: REPO_ROOT / "benchmarks" / "external")
    domains_dir: Path = field(default_factory=lambda: REPO_ROOT / "domains")
    invoker_config: InvokerConfig = field(default_factory=InvokerConfig)
    sample_max_per_agent: int = 5


def load_cases_from_manifest(manifest_path: Path) -> list[dict]:
    """Load raw case dicts from a manifest JSON file."""
    data = json.loads(manifest_path.read_text())
    return data.get("cases", [])


def load_full_cases_from_manifest(manifest_path: Path, truth_dir: Path) -> list[BenchmarkCase]:
    """Load fully-typed BenchmarkCase objects from a manifest, resolving ground truth."""
    data = json.loads(manifest_path.read_text())
    dataset_name = data["dataset_name"]
    cases = []
    for raw in data.get("cases", []):
        case_id = raw["case_id"]
        truth_path = truth_dir / case_id / "truth.sarif"
        if truth_path.exists():
            ground_truth = load_bentoo_sarif(truth_path)
        else:
            ground_truth = []
            logger.warning("No truth.sarif for case %s at %s", case_id, truth_path)

        try:
            lang = Language(raw["language"])
        except ValueError:
            logger.warning("Unknown language %s for case %s, skipping", raw["language"], case_id)
            continue

        cases.append(BenchmarkCase(
            case_id=case_id, project=raw["project"], language=lang,
            vulnerable_version=raw["vulnerable_version"],
            patched_version=raw["patched_version"],
            ground_truth=ground_truth, published_date=None,
            source_dataset=dataset_name,
        ))
    return cases


def map_case_to_agent(case: BenchmarkCase) -> str | None:
    """Map a benchmark case to an agent name based on CWE in ground truth."""
    for f in case.ground_truth:
        if f.kind == FindingKind.FAIL and f.cwe_id in _CWE_TO_AGENT:
            return _CWE_TO_AGENT[f.cwe_id]
    return None


def build_prompt(core_prompt: str, code: str, file_path: str) -> str:
    """Assemble a detection prompt from agent knowledge and target code."""
    return f"""{core_prompt}

## Code to Analyze

**File:** `{file_path}`

```
{code}
```

## Instructions

Analyze the code above using the detection knowledge provided. Return your findings as a JSON array. Each finding must have exactly these fields:
- "cwe_id": string (e.g., "CWE-79")
- "file": string (the file path given above)
- "start_line": integer (1-based line number where the vulnerability starts)
- "end_line": integer (1-based line number where the vulnerability ends)
- "confidence": float between 0.0 and 1.0
- "message": string (brief explanation of the vulnerability)

If no vulnerabilities are found, return an empty array: []

Return ONLY the JSON array, no other text."""


def parse_findings_response(raw_findings: list[dict], agent_name: str) -> list[Finding]:
    """Parse raw finding dicts into typed Finding objects, skipping malformed entries."""
    findings = []
    for item in raw_findings:
        try:
            findings.append(Finding(
                cwe_id=item["cwe_id"],
                kind=FindingKind.FAIL,
                location=CodeLocation(
                    file=item["file"],
                    start_line=int(item["start_line"]),
                    end_line=int(item["end_line"]),
                ),
                confidence=float(item.get("confidence", 0.5)),
                message=item.get("message"),
                agent_name=agent_name,
            ))
        except (KeyError, ValueError, TypeError) as exc:
            logger.debug("Skipping malformed finding: %s — %s", item, exc)
    return findings


class Evaluator:
    """Core orchestrator: loads cases, invokes agents, scores results."""

    def __init__(self, config: EvalConfig) -> None:
        self.config = config
        self.run_id = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        self._run_dir = config.results_dir / self.run_id
        self._cases_dir = self._run_dir / "cases"

    def run(self, cases: list[BenchmarkCase], engine: "ScanEngine") -> list[Summary]:
        """Run evaluation over all cases, returning per-agent summaries."""
        self._run_dir.mkdir(parents=True, exist_ok=True)
        self._cases_dir.mkdir(exist_ok=True)

        grouped: dict[tuple[str, str], list[BenchmarkCase]] = {}
        for case in cases:
            agent = map_case_to_agent(case)
            if agent is None:
                logger.info("Skipping case %s — no matching agent", case.case_id)
                continue
            key = (agent, case.source_dataset)
            grouped.setdefault(key, []).append(case)

        hierarchy = load_hierarchy()
        summaries = []
        for (agent_name, dataset), group_cases in grouped.items():
            logger.info("Evaluating %s on %s (%d cases)", agent_name, dataset, len(group_cases))
            summary = self._evaluate_group(agent_name, dataset, group_cases, engine, hierarchy)
            summaries.append(summary)

        return summaries

    def _evaluate_group(
        self,
        agent_name: str,
        dataset: str,
        cases: list[BenchmarkCase],
        engine: "ScanEngine",
        hierarchy: Cwe1400Hierarchy,
    ) -> Summary:
        vuln_runs = []
        patched_runs = []

        for case in cases:
            vuln_run, patched_run = self._evaluate_case(case, agent_name, engine)
            vuln_runs.append(vuln_run)
            patched_runs.append(patched_run)
            time.sleep(self.config.invoker_config.throttle_delay)

        return compute_metrics(
            cases=cases, runs_vulnerable=vuln_runs, runs_patched=patched_runs,
            hierarchy=hierarchy, agent_name=agent_name, dataset=dataset,
        )

    def _evaluate_case(
        self,
        case: BenchmarkCase,
        agent_name: str,
        engine: "ScanEngine",
    ) -> tuple[AgentRun, AgentRun]:
        vuln_result_path = self._cases_dir / f"{case.case_id}_vuln.json"
        patched_result_path = self._cases_dir / f"{case.case_id}_patched.json"

        if vuln_result_path.exists():
            vuln_findings = self._load_cached_findings(vuln_result_path)
        else:
            vuln_findings = self._scan_variant(case, agent_name, CodeVariant.VULNERABLE, engine)
            self._save_findings(vuln_result_path, vuln_findings)

        if patched_result_path.exists():
            patched_findings = self._load_cached_findings(patched_result_path)
        else:
            patched_findings = self._scan_variant(case, agent_name, CodeVariant.PATCHED, engine)
            self._save_findings(patched_result_path, patched_findings)

        vuln_run = AgentRun(case_id=case.case_id, agent_name=agent_name,
                            findings=vuln_findings, runtime_seconds=0.0)
        patched_run = AgentRun(case_id=case.case_id, agent_name=agent_name,
                               findings=patched_findings, runtime_seconds=0.0)
        return vuln_run, patched_run

    def _scan_variant(
        self,
        case: BenchmarkCase,
        agent_name: str,
        variant: CodeVariant,
        engine: "ScanEngine",
    ) -> list[Finding]:
        code_pieces = extract_code_for_case(case, variant, self.config.benchmarks_external_dir)
        if not code_pieces:
            return []

        all_findings: list[Finding] = []
        for piece in code_pieces:
            with tempfile.NamedTemporaryFile(mode="w", suffix=f".{piece.language}", delete=False) as tmp:
                tmp.write(piece.content)
                tmp_path = tmp.name

            try:
                payload = engine.assemble_scan(
                    agent_name=agent_name,
                    target={"type": "file", "path": tmp_path},
                )
                prompt = build_prompt(
                    core_prompt=payload["core_prompt"],
                    code=payload["code"],
                    file_path=piece.file_path,
                )
                result = invoke_claude(prompt, self.config.invoker_config)
                if result.success:
                    findings = parse_findings_response(result.findings, agent_name)
                    # Normalize file paths: Claude may echo the temp file path
                    # instead of the intended file_path from the prompt.
                    for f in findings:
                        f.location = CodeLocation(
                            file=piece.file_path,
                            start_line=f.location.start_line,
                            end_line=f.location.end_line,
                            function_name=f.location.function_name,
                        )
                    all_findings.extend(findings)
                else:
                    logger.warning("Claude invocation failed for %s: %s", case.case_id, result.error)
            finally:
                Path(tmp_path).unlink(missing_ok=True)

        return all_findings

    def _save_findings(self, path: Path, findings: list[Finding]) -> None:
        data = [
            {"cwe_id": f.cwe_id, "kind": f.kind.value, "file": f.location.file,
             "start_line": f.location.start_line, "end_line": f.location.end_line,
             "confidence": f.confidence, "message": f.message, "agent_name": f.agent_name}
            for f in findings
        ]
        path.write_text(json.dumps(data, indent=2))

    def _load_cached_findings(self, path: Path) -> list[Finding]:
        data = json.loads(path.read_text())
        findings = []
        for item in data:
            findings.append(Finding(
                cwe_id=item["cwe_id"], kind=FindingKind(item["kind"]),
                location=CodeLocation(file=item["file"], start_line=item["start_line"],
                                      end_line=item["end_line"]),
                confidence=item.get("confidence"), message=item.get("message"),
                agent_name=item.get("agent_name"),
            ))
        return findings
