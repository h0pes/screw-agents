# Phase 4 Operating Map - Autoresearch

> Last updated: 2026-04-29

Phase 4 is the controlled benchmark-and-improvement loop. Its goal is not to
blindly run expensive benchmarks or automatically rewrite agent YAML. Its goal
is to turn real benchmark failures into auditable, case-level evidence before
any security-agent knowledge changes are considered.

## Mental Model

There are three separate layers:

| Layer | What it is | Git tracked? | Expensive? | Current role |
|---|---|---|---|---|
| Benchmark machinery | Runner, manifests, gates, extractors, planners, schemas | Yes | No | Already mostly built |
| External benchmark material | Downloaded repos, Docker/Postgres exports, generated `truth.sarif`, local clones | No, intentionally ignored | Sometimes slow | Must be restored/materialized locally |
| Claude benchmark execution | Running agents over vulnerable/patched cases | No result artifacts tracked by default | Yes | Controlled smoke execution is proven; failure-input payload generation is available |

The long-lived main checkout currently has the active G5 external material
restored. A fresh worktree can still report second-layer blockers because the
large/generated benchmark material is intentionally ignored and worktree-local.

## What Is Already Done

### D-01 — Rust Corpus

Status: merged in PR #17.

What exists:
- reviewed Rust real-CVE seeds;
- a materializer that writes Rust D-01 benchmark truth files;
- synthetic Rust SSTI inventory;
- extractor support that reads local git clones through `provenance.json`.

Important scope rule:
- Rust real-CVE coverage is currently SQLi/CmdI/XSS only.
- Rust SSTI remains synthetic-only unless a verified real advisory appears.

### D-02 — Autoresearch Scaffold

Status: main scaffold merged in PR #18; active G5 readiness is clean in the
long-lived main checkout after local materialization; first controlled smoke
execution completed 2026-04-29.

What exists:
- dry-run planner: inventories manifests, gates, extractor support, and lower
  bound invocation cost;
- gate correction: `G5.8` now targets `morefixes`; stale SSTI gates `G5.9` and
  `G5.10` are retired;
- failure-input schema: future YAML changes must cite concrete missed findings
  or false positives;
- controlled-run scaffold: writes a blocked smoke plan by default and refuses
  executable plans unless Claude invocation is explicitly allowed and required
  datasets are ready;
- readiness checklist: explains which local datasets must be materialized before
  a controlled run can start;
- controlled executor reporting: records overall benchmark metrics and
  vulnerable/patched finding counts for each selected case;
- failure-input payload generator: turns controlled-run misses and patched
  findings into schema-valid `phase4-autoresearch-failure-input/v1` payloads.

## Current Readiness Picture

Run the safe checks from the feature worktree:

```bash
uv run python benchmarks/scripts/plan_autoresearch.py \
  --output-dir /tmp/screw-d02-readiness-plan
uv run python benchmarks/scripts/check_autoresearch_readiness.py \
  --dry-run-plan /tmp/screw-d02-readiness-plan/run_plan.json \
  --output-dir /tmp/screw-d02-readiness
```

These commands do not invoke Claude, do not run benchmarks, do not download
datasets, and do not mutate YAML.

Long-lived main checkout result as of 2026-04-28:

| Dataset | Needed for active G5? | Current meaning |
|---|---|---|
| `ossf-cve-benchmark` | Yes | Truth ready; 118 `truth.sarif` files materialized locally, but target source snapshots are not yet materialized |
| `reality-check-csharp` | Yes | Ready; 11 `truth.sarif` files materialized locally |
| `reality-check-python` | Yes | Ready; 6 `truth.sarif` files materialized locally |
| `reality-check-java` | Yes | Ready; 9 `truth.sarif` files materialized locally |
| `morefixes` | Yes | Ready; 2,601 `truth.sarif` files and code snapshots materialized locally |
| `crossvul` | No | Useful benchmark data, but not required by active G5 gates right now |
| `go-sec-code-mutated` | No | Retained as SQLi data; no longer misused as SSTI gate evidence |
| `skf-labs-mutated` | No | Retained as SQLi data; no longer misused as SSTI gate evidence |
| `rust-d01-real-cves` | No active G5 yet | Needs materialization and local clones before Rust-scoped gates |
| `vul4j` | No | Explicitly deferred until checkout layout/extractor contract exists |

Verified core-dataset restoration as of 2026-04-28:
- `uv run python -m benchmarks.scripts.ingest_ossf` restores 118
  materialized OSSF case truth files. It does not restore vulnerable/patched
  target-project source snapshots.
- `uv run python -m benchmarks.scripts.ingest_reality_check_csharp` restores
  11 materialized C# case truth files.
- `uv run python -m benchmarks.scripts.ingest_reality_check_python` restores
  6 materialized Python case truth files.
- `uv run python -m benchmarks.scripts.ingest_reality_check_java` restores 9
  materialized Java case truth files.

After those commands, and after MoreFixes deployment/extraction, the readiness
checklist reports 5 of 5 active G5 datasets ready in the long-lived main
checkout. Because generated benchmark material is ignored and worktree-local,
run materialization commands in the checkout where the data should remain
available.

## Why The External Data Is Missing

This relates to the large Phase 0.5 / Phase 1 benchmark setup. That work built
the ingest scripts, manifests, database flow, and runner support. The generated
data itself is not committed because it can be large, environment-specific, or
reproducible from external sources.

Examples:
- MoreFixes depends on the local Docker/Postgres dump and extraction query.
- reality-check datasets depend on bootstrapped vulnerable/patched project
  material.
- Rust D-01 source extraction depends on local git clones, not tracked repos.

So a fresh worktree can be perfectly healthy while still reporting readiness
blockers. The blockers mean: "materialize the ignored local data before running
paid benchmark execution."

## Safe Versus Expensive Commands

Safe planning commands:

```bash
uv run python benchmarks/scripts/plan_autoresearch.py
uv run python benchmarks/scripts/check_autoresearch_readiness.py
uv run python benchmarks/scripts/prepare_autoresearch_run.py \
  --dry-run-plan <run_plan.json>
```

These commands write reviewable JSON/Markdown artifacts only.

Materialization commands:

```bash
uv run python -m benchmarks.scripts.ingest_ossf
uv run python -m benchmarks.scripts.ingest_reality_check_csharp
uv run python -m benchmarks.scripts.ingest_reality_check_python
uv run python -m benchmarks.scripts.ingest_reality_check_java
bash benchmarks/scripts/deploy_morefixes.sh
uv run python -m benchmarks.scripts.morefixes_extract
uv run python benchmarks/scripts/materialize_rust_d01.py
```

These may download data, use Docker/Postgres, or write ignored external
benchmark files. They still do not invoke Claude.

Implementation note: `IngestBase.write_manifest()` preserves the existing
`ingested_at` value when regenerated case metadata is unchanged, so restoring
ignored external data does not create timestamp-only manifest churn.

MoreFixes status as of 2026-04-28:
- The Docker volume `morefixes_morefixes_data` can be reused across worktrees.
- `benchmarks/scripts/deploy_morefixes.sh` now starts Postgres and checks for
  loaded tables before downloading the 3.5 GB dump.
- If the volume is initialized but empty, the script imports
  `postgrescvedumper.sql` explicitly after creating the `postgrescvedumper`
  role.
- Verified loaded DB counts: `fixes=464296`, `file_change=103703`.
- Verified materialization: 2,601 case `truth.sarif` files, 6,825 vulnerable
  snapshots, and 6,825 patched snapshots.
- `morefixes_extract.py` streams rows and writes code snapshots row-by-row.
  This reduced sampled Python peak RSS from tens of GiB to about 410 MiB on
  the verified run.

Controlled smoke preparation:

```bash
uv run python benchmarks/scripts/prepare_autoresearch_run.py \
  --dry-run-plan <run_plan.json> \
  --output-dir benchmarks/results/autoresearch-controlled/<run-id>
```

This writes a blocked, reviewable smoke plan by default. The default selection
strategy, `required-dataset-smoke`, chooses at most one case for each active
G5 dataset/agent pair, so shared agents such as `xss` do not cause required
datasets to be skipped. The plan records deterministic `selected_case_ids`
from the dataset manifests, preferring cases whose `truth.sarif` matches the
gate's CWE filter or the agent's default CWE and whose vulnerable/patched code
can be extracted from the local materialized dataset. With the current active
G5 inventory, that currently prepares five small executable-source slices:
Reality Check C#/XSS, Reality Check C#/SQLi, Reality Check Python/XSS,
Reality Check Java/CmdI, and MoreFixes/SQLi. OSSF/XSS and OSSF/CmdI remain
blocked until vulnerable/patched target source snapshots are materialized.

Executable benchmark plan preparation:

```bash
uv run python benchmarks/scripts/prepare_autoresearch_run.py \
  --dry-run-plan <run_plan.json> \
  --output-dir benchmarks/results/autoresearch-controlled/<run-id> \
  --allow-claude-invocation
```

That only prepares an executable plan. Actual benchmark execution remains a
separate step and must keep `ANTHROPIC_API_KEY` unset so the Claude Pro
subscription is used instead of API billing. Do not add
`--allow-claude-invocation` until the blocked smoke plan has been reviewed.

Controlled smoke executor validation:

```bash
uv run python benchmarks/scripts/run_controlled_autoresearch.py \
  --controlled-plan <controlled_run_plan.json> \
  --output-dir benchmarks/results/autoresearch-controlled-executor/<run-id>
```

This validates the reviewed `selected_case_ids`, loads their `truth.sarif`
files, and confirms vulnerable/patched code can be extracted. It does not
invoke Claude unless `--execute` and executor-level
`--allow-claude-invocation` are both present.

The executor validation is intentionally stricter than readiness: readiness
checks truth materialization and extractor availability, while executor
validation checks the exact reviewed cases against the local source layout.

Controlled smoke execution:

```bash
uv run python benchmarks/scripts/run_controlled_autoresearch.py \
  --controlled-plan <controlled_run_plan.json> \
  --output-dir benchmarks/results/autoresearch-controlled-executor/<run-id> \
  --execute \
  --allow-claude-invocation
```

This is the first command in the Phase 4 sequence that can invoke Claude.
Before running it, verify `ANTHROPIC_API_KEY` is unset so the Claude Pro
subscription path is used rather than API billing.

Focused controlled reruns:

```bash
uv run python benchmarks/scripts/run_controlled_autoresearch.py \
  --controlled-plan <controlled_run_plan.json> \
  --output-dir benchmarks/results/autoresearch-controlled-executor/<run-id> \
  --agent cmdi \
  --case-id rc-java-plexus-utils-CVE-2017-1000487 \
  --include-related-context
```

`--agent` and `--case-id` are repeatable filters over the reviewed
`selected_case_ids` already present in the controlled plan. They can be used in
validation mode or with `--execute --allow-claude-invocation` to rerun only a
specific diagnostic slice. The executor records active filters in the report
and blocks execution when the filters match no reviewed cases.

`--include-related-context` keeps the primary file as the only reportable
finding target, but adds same-variant related truth files to the prompt as
read-only context. Use it for multi-file benchmark evidence such as the Plexus
CmdI case, where the sink path in `Shell.java` and the effective quoting
behavior in `BourneShell.java` need to be understood together. This is a
benchmark evidence-packaging improvement, not an agent YAML change.

First verified run, 2026-04-29:
- Output directory: `/tmp/screw-d02-exec-run-restored`.
- Benchmark run ID: `20260429-062030`.
- Seven active G5 slices executed, producing 14 raw case JSON files.
- No executor issues were reported.
- The result is a triage baseline, not a YAML-mutation trigger. Use the report's
  metrics and finding-count tables to choose concrete missed-vulnerability and
  false-positive examples for the failure-input schema.

Failure-input payload generation:

```bash
uv run python benchmarks/scripts/generate_autoresearch_failure_inputs.py \
  --controlled-executor-report <controlled_executor_report.json> \
  --output-dir <failure-input-output-dir>
```

When generating from an old report created in the long-lived main checkout
while working from a fresh feature worktree, pass the materialized external data
directory explicitly:

```bash
uv run python benchmarks/scripts/generate_autoresearch_failure_inputs.py \
  --controlled-executor-report /tmp/screw-d02-exec-run-restored/controlled_executor_report.json \
  --output-dir /tmp/screw-d02-failure-inputs \
  --external-dir /home/marco/Programming/AI/screw-agents/benchmarks/external
```

Verified 2026-04-29 from the first controlled smoke output:

| Payload | Missed | False positives | Mutation allowed |
|---|---:|---:|---|
| `cmdi_failure_input.json` | 5 | 3 | no |
| `sqli_failure_input.json` | 5 | 0 | no |
| `xss_failure_input.json` | 3 | 0 | no |

First payload review, 2026-04-29:
- CmdI was reviewed first because it had both misses and patched-version
  findings.
- The OSSF CmdI miss was rejected as training evidence because the materialized
  source file did not contain the truth line.
- The Plexus Java shell-wrapper evidence supported a narrow `cmdi.yaml`
  refinement for custom shell command builders and patched single-quote wrapper
  discrimination.
- A focused rerun after the first CmdI refinement reduced the Plexus patched
  finding count but did not prove the change effective: the remaining
  vulnerable finding did not overlap the benchmark truth span, and one patched
  `Shell.java` false positive remained. Continue with targeted executor/context
  improvements before making another CmdI YAML tweak.
- Related-file prompt context is now available for that targeted rerun so the
  next CmdI/Plexus validation can test evidence packaging before any further
  `cmdi.yaml` refinement.

Focused CmdI/Plexus related-context execution, verified 2026-04-29:
- Output directory: `/tmp/screw-d02-cmdi-context-run`.
- Benchmark run ID: `20260429-090552`.
- Command shape: `--agent cmdi --case-id
  rc-java-plexus-utils-CVE-2017-1000487 --include-related-context --execute
  --allow-claude-invocation`.
- Result: TP 7, FP 2, TN 10, FN 3; TPR 70.0%, FPR 16.7%, precision 77.8%,
  F1 73.7%, accuracy 53.3%.
- Raw finding counts: 9 vulnerable-version findings, 0 patched-version
  findings. This removed the remaining patched `Shell.java` finding from the
  previous CmdI v1.0.1 focused rerun.
- Generated focused failure payload:
  `/tmp/screw-d02-cmdi-context-failure-inputs/cmdi_failure_input.json`.
- Remaining concrete misses are three vulnerable truth spans in
  `Commandline.java` and `BourneShell.java`; there are no patched-version false
  positive examples in the focused payload.
- Interpretation: related-file context materially improved the Plexus evidence
  packaging and should remain part of focused multi-file controlled reruns. Do
  not make another `cmdi.yaml` change from this run alone; first decide whether
  the remaining misses are meaningful knowledge gaps or truth-span granularity
  artifacts.

Review of the three remaining CmdI/Plexus misses:
- `BourneShell.getQuotingTriggerChars()` and the default `BourneShell()`
  constructor are truth-span granularity cases: the agent already identified
  the unsafe `unifyQuotes()`/double-quote model and the `getExecutable()` path,
  but did not place findings on the small helper spans selected by the
  benchmark.
- `Commandline.verifyShellState()` is a real bridge-method localization gap:
  it copies executable and working-directory state into the shell object before
  `getShellCommandline()`/`execute()` build and invoke the shell command.
- A trial `cmdi.yaml` v1.0.2 localization prompt was rejected. It kept patched
  findings at zero but increased vulnerable findings from 9 to 18 and regressed
  the focused metrics to TP 6, FP 12, TN 10, FN 4. The extra guidance made the
  agent over-report helper/configuration methods instead of cleanly closing the
  remaining truth spans. Keep `cmdi.yaml` at v1.0.1 and solve the remaining
  diagnostic gap in scoring/failure-analysis tooling.
- Failure payloads now include `related_agent_findings` on missed examples:
  same-file, same-CWE vulnerable findings that did not overlap the exact truth
  span. This makes truth-span granularity visible during review and avoids
  treating every non-overlap as a YAML knowledge gap.
- The payload-level `diagnostics` summary counts total misses, misses with
  nearby same-file related findings, same-file-only related findings, pure
  misses, and patched-version false positives so reviewers can triage a run
  without hand-counting every example first.

Focused SQLi/NHibernate literal-renderer execution, verified 2026-04-29:
- Output directory: `/tmp/screw-d02-sqli-nhibernate-v101-run`.
- Benchmark run ID: `20260429-132147`.
- Command shape: `--agent sqli --case-id
  rc-csharp-nhibernate-core-CVE-2024-39677 --execute
  --allow-claude-invocation`.
- `sqli.yaml` was refined narrowly from v1.0.0 to v1.0.1 to cover C# ORM
  SQL literal/comment renderers such as NHibernate `ObjectToSQLString()`.
- Result: TP 3, FP 0, TN 25, FN 22; TPR 12.0%, FPR 0.0%, precision 100.0%,
  F1 21.4%, accuracy 12.0%.
- Raw finding counts: 3 vulnerable-version findings, 0 patched-version
  findings. The previous focused baseline found only
  `AbstractStringType.ObjectToSQLString`; v1.0.1 also localized
  `AbstractCharType.ObjectToSQLString` and one low-confidence
  `DateTimeOffSetType.ObjectToSQLString` truth span without adding patched
  noise.
- Generated focused failure payload:
  `/tmp/screw-d02-sqli-nhibernate-v101-failure-inputs/sqli_failure_input.json`.
- Remaining concrete misses in the capped payload are five pure misses:
  a SQL comment builder test span, a dialect test helper, a boolean literal
  helper, `ByteType.Set()`, and `CharBooleanType.ObjectToSQLString()`.
  Treat the first three as likely truth-span or benchmark-granularity cases
  before considering another SQLi YAML change. The remaining sibling literal
  renderers may need either more focused prompt guidance or scoring/tooling
  review, but v1.0.1 is accepted because it improves recall without patched
  findings.

XSS evidence-quality triage, verified 2026-04-29:
- Regenerated payload directory:
  `/tmp/screw-d02-xss-evidence-quality-failure-inputs`.
- Failure payload examples now include `evidence_quality_flags`, and
  diagnostics count missed examples with missing code excerpts and test-file
  paths.
- XSS diagnostics from the first controlled smoke payload: total misses 3,
  pure misses 3, missing code excerpts 1, test-file paths 1, false positives 0.
- `ossf-CVE-2018-16484` is flagged `missing_code_excerpt`; do not treat it as
  XSS YAML evidence until the source/truth materialization mismatch is
  resolved.
- `rc-csharp-antisamy-dotnet-CVE-2023-51652` is flagged `test_file_path`; it
  is a sanitizer unit test span, not a normal application output sink.
- `rc-python-Zope-CVE-2009-5145` has source text and is not a test path, but
  the truth span is a Zope namespace/evaluation helper (`call_with_ns`) rather
  than a direct HTML-output sink. Review this case manually before considering
  an XSS YAML change.
- No `xss.yaml` change is accepted from this triage slice. The next XSS step is
  either source-material repair for the OSSF case or a focused Zope review that
  proves a concrete XSS data/output path.
- Focused Zope review accepted a narrow `xss.yaml` v1.0.1 refinement:
  vulnerable Zope 2.12.1 pushes raw `request` into the PageTemplate
  `TemplateDict`/`RestrictedDTML` namespace, while patched Zope 2.12.2 first
  applies `request.taintWrapper()`. The same CVE-2009-5145 function is also
  materialized in MoreFixes with CWE-79 truth, so the change is scoped to Zope
  PageTemplates request taint preservation rather than generic helper methods.
- Focused executor rerun:
  `/tmp/screw-d02-xss-zope-v101-run/controlled_executor_report.md`. Result:
  TP 1, FP 0, TN 1, FN 0; vulnerable findings 1; patched findings 0.

OSSF extraction hardening, verified 2026-04-29:
- The OSSF extractor previously fell back from a missing truth path such as
  `lib/index.js` to any same-basename file under the benchmark metadata repo.
  For `ossf-CVE-2018-16484`, that resolved to the metadata repo's one-line
  `index.js`, while the SARIF truth span points to line 39.
- The extractor now rejects OSSF fallback files that do not cover the truth
  line range. This prevents a case from being selected or validated as
  extractable when the source text cannot actually support the benchmark
  evidence.
- Re-preparing the controlled plan with materialized main external data now
  skips `ossf-CVE-2018-16484` for OSSF/XSS and selects
  `ossf-CVE-2019-13506`; OSSF/CmdI similarly selects
  `ossf-CVE-2017-16087`. Validation-only executor run:
  `/tmp/screw-d02-ossf-line-coverage-executor-validation`.
- A second OSSF/XSS validation found that `ossf-CVE-2019-13506` resolved to
  the OSSF benchmark metadata repository's reporting server code at
  `contrib/reports/explore-server/src/server/index.ts`, not the devalue target
  repository source. The extractor now refuses to read from the OSSF metadata
  clone at all. OSSF remains truth-materialized but blocked for executable
  agent-quality runs until target source snapshots are materialized from the
  recorded pre/post patch commits.
- Re-preparing the controlled plan after this stricter source resolver selects
  five non-OSSF slices and reports `case_selection_incomplete` blockers for
  OSSF/XSS (`G5.1`) and OSSF/CmdI (`G5.5`):
  `/tmp/screw-d02-ossf-source-resolver-controlled-rerun`.

## YAML Mutation Rule

Agent YAML must not change because a gate percentage is low.

YAML changes become eligible only when there is a structured
`phase4-autoresearch-failure-input/v1` payload with:
- concrete missed vulnerability examples or false-positive examples;
- dataset and case provenance;
- exact agent and YAML source version;
- benchmark split/run metadata;
- guardrail state showing human review is still required.

Even then, YAML mutation is not automatic. It is a reviewed engineering change.

## Recommended Next Sequence

1. Keep active G5 external material available in the checkout used for
   execution.
2. Re-run readiness and controlled executor validation before any new paid
   execution.
3. Generate `phase4-autoresearch-failure-input/v1` payloads from controlled
   smoke reports.
4. Review payload examples manually before considering targeted YAML
   refinements.
5. Only then consider a small, reviewed agent-knowledge change and re-run the
   same controlled smoke slice.
