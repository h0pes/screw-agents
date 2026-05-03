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
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING

from benchmarks.runner.code_extractor import (
    CodeVariant,
    ExtractedCode,
    extract_code_for_case,
    limit_extracted_code_for_variant,
)
from benchmarks.runner.cwe import Cwe1400Hierarchy, load_hierarchy
from benchmarks.runner.invoker import InvokerConfig, invoke_claude
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

if TYPE_CHECKING:
    from screw_agents.engine import ScanEngine

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
    results_dir: Path = field(
        default_factory=lambda: REPO_ROOT / "benchmarks" / "results"
    )
    benchmarks_external_dir: Path = field(
        default_factory=lambda: REPO_ROOT / "benchmarks" / "external"
    )
    domains_dir: Path = field(default_factory=lambda: REPO_ROOT / "domains")
    invoker_config: InvokerConfig = field(default_factory=InvokerConfig)
    sample_max_per_agent: int = 5
    include_related_context: bool = False
    include_related_context_case_ids: set[str] = field(default_factory=set)
    include_helper_context: bool = False
    max_files_per_variant: int = 0


@dataclass(frozen=True)
class EvaluatedCase:
    case: BenchmarkCase
    vulnerable_files: frozenset[str]
    patched_files: frozenset[str]


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


def build_prompt(
    core_prompt: str,
    code: str,
    file_path: str,
    context_files: list[ExtractedCode] | None = None,
) -> str:
    """Assemble a detection prompt from agent knowledge and target code."""
    related_context = _render_related_context(context_files or [])
    return f"""{core_prompt}

## Code to Analyze

**File:** `{file_path}`

```
{code}
```

{related_context}

## Instructions

Analyze the primary file above using the detection knowledge provided. Related
files, when present, are context only: use them to understand call chains,
overrides, sanitizers, wrappers, and patched behavior, but return findings only
for the primary file `{file_path}`.

Use only the source text included in this prompt. Do not call or request LSP,
language-server, workspace, filesystem, search, web, shell, or other tools. If
additional project context would be useful but is not included above, proceed
with the provided code and state nothing outside the JSON result.

Return your findings as a JSON array. Each finding must have exactly these fields:
- "cwe_id": string (e.g., "CWE-79")
- "file": string (the primary file path given above)
- "start_line": integer (1-based line number where the vulnerable sink,
  unsafe source-to-sink handoff, or unsafe security-sensitive call starts)
- "end_line": integer (1-based line number where that same vulnerable
  expression/call ends)
- "confidence": float between 0.0 and 1.0
- "message": string (brief explanation of the vulnerability)

Line-location discipline:
- Anchor the span on the exact vulnerable expression/call, not on a nearby
  function declaration, control block, closing brace, or surrounding helper.
- If your message names a sink/query/template/shell/framework call, the line
  span must cover that named call/expression.
- Prefer a narrow sink span over a broad method/function span.

If no vulnerabilities are found, return an empty array: []

Return ONLY the JSON array, no other text."""


def _render_related_context(context_files: list[ExtractedCode]) -> str:
    if not context_files:
        return ""
    rendered = ["## Related Files For Context", ""]
    for piece in context_files:
        rendered.extend(
            [
                f"**Context file:** `{piece.file_path}`",
                "",
                "```",
                piece.content,
                "```",
                "",
            ]
        )
    return "\n".join(rendered).rstrip()


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
        self.run_id = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
        self._run_dir = config.results_dir / self.run_id
        self._cases_dir = self._run_dir / "cases"

    def run(self, cases: list[BenchmarkCase], engine: ScanEngine) -> list[Summary]:
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
        engine: ScanEngine,
        hierarchy: Cwe1400Hierarchy,
    ) -> Summary:
        scored_cases: list[BenchmarkCase] = []
        vuln_runs = []
        patched_runs = []

        for case in cases:
            evaluated_case, vuln_run, patched_run = self._evaluate_case(
                case, agent_name, engine
            )
            scored_cases.append(_scope_case_to_evaluated_files(evaluated_case))
            vuln_runs.append(vuln_run)
            patched_runs.append(patched_run)
            time.sleep(self.config.invoker_config.throttle_delay)

        return compute_metrics(
            cases=scored_cases, runs_vulnerable=vuln_runs, runs_patched=patched_runs,
            hierarchy=hierarchy, agent_name=agent_name, dataset=dataset,
        )

    def _evaluate_case(
        self,
        case: BenchmarkCase,
        agent_name: str,
        engine: ScanEngine,
    ) -> tuple[EvaluatedCase, AgentRun, AgentRun]:
        vuln_result_path = self._cases_dir / f"{case.case_id}_vuln.json"
        patched_result_path = self._cases_dir / f"{case.case_id}_patched.json"
        vuln_pieces = self._code_pieces_for_variant(case, CodeVariant.VULNERABLE)
        patched_pieces = self._code_pieces_for_variant(case, CodeVariant.PATCHED)

        if vuln_result_path.exists():
            vuln_findings = self._load_cached_findings(vuln_result_path)
        else:
            vuln_findings = self._scan_variant(
                case,
                agent_name,
                CodeVariant.VULNERABLE,
                engine,
                code_pieces=vuln_pieces,
            )
            self._save_findings(vuln_result_path, vuln_findings)

        if patched_result_path.exists():
            patched_findings = self._load_cached_findings(patched_result_path)
        else:
            patched_findings = self._scan_variant(
                case,
                agent_name,
                CodeVariant.PATCHED,
                engine,
                code_pieces=patched_pieces,
            )
            self._save_findings(patched_result_path, patched_findings)

        evaluated_case = EvaluatedCase(
            case=case,
            vulnerable_files=frozenset(piece.file_path for piece in vuln_pieces),
            patched_files=frozenset(piece.file_path for piece in patched_pieces),
        )
        vuln_run = AgentRun(case_id=case.case_id, agent_name=agent_name,
                            findings=vuln_findings, runtime_seconds=0.0)
        patched_run = AgentRun(case_id=case.case_id, agent_name=agent_name,
                               findings=patched_findings, runtime_seconds=0.0)
        return evaluated_case, vuln_run, patched_run

    def _code_pieces_for_variant(
        self,
        case: BenchmarkCase,
        variant: CodeVariant,
    ) -> list[ExtractedCode]:
        code_pieces = extract_code_for_case(
            case,
            variant,
            self.config.benchmarks_external_dir,
            include_related_context=(
                self.config.include_related_context
                or case.case_id in self.config.include_related_context_case_ids
            ),
            include_helper_context=self.config.include_helper_context,
        )
        if self.config.max_files_per_variant > 0:
            code_pieces = limit_extracted_code_for_variant(
                code_pieces,
                self.config.max_files_per_variant,
                case=case,
                variant=variant,
            )
        return code_pieces

    def _scan_variant(
        self,
        case: BenchmarkCase,
        agent_name: str,
        variant: CodeVariant,
        engine: ScanEngine,
        code_pieces: list[ExtractedCode] | None = None,
    ) -> list[Finding]:
        if code_pieces is None:
            code_pieces = self._code_pieces_for_variant(case, variant)
        if not code_pieces:
            return []

        all_findings: list[Finding] = []
        for i, piece in enumerate(code_pieces):
            if i > 0:
                time.sleep(self.config.invoker_config.throttle_delay)
            with tempfile.NamedTemporaryFile(
                mode="w",
                suffix=f".{piece.language}",
                delete=False,
            ) as tmp:
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
                    context_files=piece.context_files,
                )
                result = invoke_claude(
                    prompt,
                    self.config.invoker_config,
                    context={
                        "agent": agent_name,
                        "case_id": case.case_id,
                        "dataset": case.source_dataset,
                        "variant": variant.value,
                        "file": piece.file_path,
                    },
                )
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
                    logger.warning(
                        "Claude invocation failed for %s: %s",
                        case.case_id,
                        result.error,
                    )
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


def _scope_case_to_evaluated_files(evaluated_case: EvaluatedCase) -> BenchmarkCase:
    """Keep only truth spans whose files were actually evaluated."""
    case = evaluated_case.case
    paired_fail_files = evaluated_case.vulnerable_files & evaluated_case.patched_files
    scoped_truth = [
        truth
        for truth in case.ground_truth
        if (
            truth.kind == FindingKind.FAIL
            and truth.location.file in paired_fail_files
        )
        or (
            truth.kind == FindingKind.PASS
            and truth.location.file in evaluated_case.patched_files
        )
    ]
    return BenchmarkCase(
        case_id=case.case_id,
        project=case.project,
        language=case.language,
        vulnerable_version=case.vulnerable_version,
        patched_version=case.patched_version,
        ground_truth=scoped_truth,
        published_date=case.published_date,
        source_dataset=case.source_dataset,
    )
