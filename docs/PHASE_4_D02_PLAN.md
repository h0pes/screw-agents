# Phase 4 D-02 — Autoresearch And Gate Optimization Plan

> Status: dry-run, gate-audit, failure-input, readiness checklist,
> controlled-run scaffold, controlled smoke execution, and failure-input
> payload generation are complete. Active G5 dataset readiness is clean in the
> long-lived main checkout after local materialization.
> Scope: plan and audit expensive benchmark/autoresearch runs before invoking
> Claude or mutating agent YAML.

## Goal

D-02 takes the validated Phase 1.7 benchmark pipeline and turns it into a
controlled Phase 4 autoresearch workflow. The first milestone is not a full
benchmark run. It is a dry-run planning layer that makes cost, missing data,
gate-definition drift, and YAML-mutation guardrails explicit before any
long-running or paid work starts.

For the whole Phase 4 picture, including which commands are safe planning,
which commands materialize ignored local data, and which steps can spend Claude
time, read `docs/PHASE_4_OPERATING_MAP.md`.

## Ground Rules

- Do not invoke Claude from planning commands.
- Do not mutate `domains/**/*.yaml` from aggregate metrics alone.
- Any future YAML refinement must cite concrete missed vulnerabilities or false
  positives.
- Autoresearch-generated code hooks must use `stage_adaptive_script` →
  `promote_staged_script`; the direct-sign path is retired.
- Rust claims remain scoped: real-CVE Rust coverage exists for SQLi/CmdI/XSS;
  Rust SSTI is synthetic-only unless a verified real advisory appears.

## Task Breakdown

### Task 1 — Dry-Run Benchmark Plan

Status: implemented in `src/screw_agents/autoresearch/planner.py` and
`benchmarks/scripts/plan_autoresearch.py`.

Acceptance:
- Inventories tracked benchmark manifests without requiring external datasets.
- Reports dataset case counts, missing external directories, truth-file
  availability, extractor support, and a lower-bound invocation estimate.
- Audits G5 gate definitions against tracked manifests and known D-02 issues.
- Writes JSON and Markdown plan artifacts under `benchmarks/results/` by
  default, which remains gitignored.
- Has tests that do not invoke Claude or require downloaded datasets.

Latest dry-run result from a fresh worktree after Task 3 gate correction:
- 10 benchmark case manifests.
- 4,154 cases.
- 8,308 lower-bound Claude invocations for a full vulnerable/patched pass.
- No active G5 gate-definition issues remain in the dry-run audit.
- `G5.8` now points to `morefixes`, matching the tracked manifest and
  extractor support.
- `G5.9` and `G5.10` are retired because they targeted SSTI/CWE-1336 on SQLi
  datasets (`go-sec-code-mutated`, `skf-labs-mutated`).

### Task 2 — Dataset Readiness And Extraction Closure

Status: readiness checklist implemented; active G5 datasets materialized in the
long-lived main checkout; generated dataset contents remain local and
intentionally ignored.

Resolve the plan's dataset readiness issues before any full run:
- `morefixes` is exposed as `morefixes`; `G5.8` was updated from the stale
  `morefixes-extract` name.
- `morefixes` extraction now expects regenerated DB materialization with
  before/after code snapshots beside each case's `truth.sarif`.
- `rust-d01-real-cves` extraction now reads local git clones using each case's
  `provenance.json` refs; clones are intentionally not tracked.
- `vul4j` extraction remains explicitly deferred because the current ingest
  tracks metadata only and does not define a local vulnerable/patched checkout
  convention.
- `src/screw_agents/autoresearch/readiness.py` and
  `benchmarks/scripts/check_autoresearch_readiness.py` now turn a dry-run plan
  into JSON/Markdown readiness artifacts without downloading data, invoking
  Claude, running benchmarks, or mutating YAML.
- Current fresh-worktree readiness check reports 5 active G5 datasets required
  for a controlled run: `ossf-cve-benchmark`, `reality-check-csharp`,
  `reality-check-python`, `reality-check-java`, and `morefixes`.
- Current readiness in the long-lived main checkout reports 5 of 5 active G5
  datasets ready with no controlled-run blockers. A fresh worktree still needs
  ignored external material restored before it can run the same readiness
  check cleanly. `vul4j` remains explicitly deferred; Rust D-01 is tracked as
  a non-G5 warning until local clones are supplied.
- Core active G5 restoration path is verified: OSSF and the three
  reality-check datasets materialize cleanly with their existing ingest
  scripts. After those commands, readiness reports 4 of 5 active G5 datasets
  ready; MoreFixes remains the active G5 blocker.
- Regenerating unchanged manifests now preserves the existing `ingested_at`
  value to avoid timestamp-only churn when restoring ignored local datasets.
- MoreFixes Docker/Postgres restoration is verified: the deploy script reuses a
  loaded `morefixes_morefixes_data` Docker volume without redownloading the
  dump, imports the SQL explicitly when a volume is initialized but empty, and
  the extractor materializes 2,601 case truth files plus 6,825 vulnerable and
  6,825 patched code snapshots.
- MoreFixes extraction now streams rows and writes snapshots row-by-row to avoid
  retaining large `code_before`/`code_after` blobs in Python memory. The
  verified peak RSS dropped to roughly 410 MiB.
- Re-materialize/download required external datasets in a worktree-local,
  reproducible way.
- Keep generated external dataset contents ignored.

Readiness command:

```bash
uv run python benchmarks/scripts/plan_autoresearch.py \
  --output-dir /tmp/screw-d02-readiness-plan
uv run python benchmarks/scripts/check_autoresearch_readiness.py \
  --dry-run-plan /tmp/screw-d02-readiness-plan/run_plan.json \
  --output-dir /tmp/screw-d02-readiness
```

### Task 3 — Gate Definition Correction

Status: implemented.

Correct stale G5 definitions before treating gate results as authoritative:
- Retired SSTI gates `G5.9` and `G5.10` instead of relabelling SQLi evidence as
  SSTI coverage.
- Preserved the retirement rationale in `RETIRED_G5_GATES` and the dry-run
  planner output.
- Add Rust D-01 scoped gates only if they are labelled separately from G5
  real-CVE non-Rust thresholds and do not overclaim SSTI.
- Keep gate changes documented with rationale in `docs/PROJECT_STATUS.md`.

### Task 4 — Failure-Analysis Input Format

Status: schema implemented in `src/screw_agents/autoresearch/failure_input.py`;
controlled-run payload generation implemented in
`src/screw_agents/autoresearch/failure_payloads.py` and
`benchmarks/scripts/generate_autoresearch_failure_inputs.py`.

Define the structured payload future autoresearch steps will consume:
- missed finding examples
- false-positive examples
- dataset/case provenance
- exact agent and YAML source version
- benchmark split/run metadata
- guardrail state explaining whether YAML mutation is allowed

Acceptance:
- Payload schema is versioned as `phase4-autoresearch-failure-input/v1`.
- YAML mutation defaults to disabled.
- YAML mutation cannot be enabled from aggregate metrics alone.
- Any mutation-eligible payload must include concrete examples tied to
  `case_provenance`, must match a single agent, and must still require human
  review.
- Tests cover JSON round-trip and guardrail failures.

Generation command:

```bash
uv run python benchmarks/scripts/generate_autoresearch_failure_inputs.py \
  --controlled-executor-report <controlled_executor_report.json> \
  --output-dir <failure-input-output-dir>
```

If the controlled executor report was produced from a different checkout whose
dry-run plan used a relative `benchmarks/external` path, pass the checkout that
holds the materialized ignored data:

```bash
uv run python benchmarks/scripts/generate_autoresearch_failure_inputs.py \
  --controlled-executor-report <controlled_executor_report.json> \
  --output-dir <failure-input-output-dir> \
  --external-dir /home/marco/Programming/AI/screw-agents/benchmarks/external
```

Verified 2026-04-29 against the first controlled smoke output:
- `cmdi_failure_input.json`: 5 missed examples, 3 false-positive examples.
- `sqli_failure_input.json`: 5 missed examples, 0 false-positive examples.
- `xss_failure_input.json`: 3 missed examples, 0 false-positive examples.
- All generated payloads validate against
  `phase4-autoresearch-failure-input/v1` and keep
  `yaml_mutation_allowed=false`.

CmdI payload review, 2026-04-29:
- The OSSF `ossf-CVE-2017-1000219` miss is not accepted as agent-training
  evidence because the locally materialized source is a one-line entrypoint
  while the truth location points to line 82.
- The Reality Check Java Plexus examples are accepted as useful evidence:
  vulnerable output showed the agent understands nearby shell-wrapper sinks,
  but it missed some benchmark truth spans and still flagged patched
  `Shell.java` code without accounting for the fixed `BourneShell.quoteOneItem`
  override.
- `cmdi.yaml` was refined narrowly to cover custom Java shell-wrapper command
  builders and to treat unconditional single-quote wrapper overrides as a
  false-positive discriminator. This is a reviewed human change, not automatic
  YAML mutation.

### Task 5 — Controlled Execution

Status: guarded scaffold and first controlled smoke execution complete.
Implementation lives in `src/screw_agents/autoresearch/controlled_run.py`,
`src/screw_agents/autoresearch/controlled_executor.py`,
`benchmarks/scripts/prepare_autoresearch_run.py`, and
`benchmarks/scripts/run_controlled_autoresearch.py`.

Only after Tasks 1-4 are resolved:
- prepare a blocked controlled smoke plan first
- use the default `required-dataset-smoke` strategy to select at most one case
  for each active G5 dataset/agent pair
- require the smoke plan to record deterministic `selected_case_ids` so any
  later executor runs exactly the reviewed cases
- select only cases whose vulnerable and patched source code can be extracted
  from the local materialized benchmark data
- validate the controlled executor first; by default it resolves selected
  cases and confirms vulnerable/patched code extraction without invoking Claude
- optionally restrict validation/execution to reviewed slices with `--agent`
  and/or `--case-id` when iterating on a concrete failure payload
- optionally include same-variant related truth files as prompt context with
  `--include-related-context` for multi-file benchmark cases
- require explicit `--allow-claude-invocation` before a plan can become
  executable
- require a second executor-level `--allow-claude-invocation` with `--execute`
  before the executor can invoke Claude
- keep YAML mutation disabled in the controlled-run schema
- block execution when external dataset dirs, truth files, or extractors are
  missing
- review failures manually using
  `phase4-autoresearch-failure-input/v1` payloads
- then scale toward full D-02 threshold optimization
- keep checkpoint/resume behavior intact

The scaffold writes JSON and Markdown under ignored `benchmarks/results/`
paths, but does not invoke Claude or execute benchmarks by itself.

First controlled smoke execution, verified 2026-04-29:
- The selected seven active G5 dataset/agent slices executed successfully after
  Claude's Apr 28 service incident was resolved.
- The executor wrote 14 vulnerable/patched raw finding JSON files under an
  ignored benchmark run directory.
- The executor report now includes overall metric summaries and per-case
  vulnerable/patched finding counts, so failure triage no longer requires
  manually opening every case JSON.
- Initial signal is intentionally treated as diagnostic evidence, not as a
  reason to mutate YAML: XSS and OSSF CmdI produced no vulnerable findings;
  Reality Check Java CmdI and SQLi produced true positives but also false
  positives. The next step is to turn concrete misses/false positives into
  `phase4-autoresearch-failure-input/v1` payloads for reviewed analysis.
- Those payloads can now be generated mechanically from the controlled executor
  report and raw case JSON files. The next engineering step is human review of
  generated examples before proposing any agent-knowledge refinement.
- The controlled executor now supports focused reruns through repeatable
  `--agent <agent>` and `--case-id <case-id>` filters. Filters are recorded in
  the JSON/Markdown report and block execution if they match no reviewed
  selected cases, keeping narrow validation tied to the already approved smoke
  plan.
- The controlled executor can also enable related-file prompt context with
  `--include-related-context`. This is intended for cases like the Plexus CmdI
  benchmark where the primary file and the effective subclass/wrapper behavior
  live in separate files. The default remains single-primary-file prompts.
- Focused CmdI/Plexus execution with `--include-related-context` is verified:
  `/tmp/screw-d02-cmdi-context-run`, benchmark run `20260429-090552`. The run
  produced 9 vulnerable findings, 0 patched findings, TP 7, FP 2, TN 10, FN 3,
  and a focused failure payload at
  `/tmp/screw-d02-cmdi-context-failure-inputs/cmdi_failure_input.json`.
- Review of the remaining three misses found two truth-span granularity cases
  around `BourneShell` helper spans and one bridge-method localization gap in
  `Commandline.verifyShellState()`. A trial `cmdi.yaml` v1.0.2 localization
  prompt was rejected because it increased vulnerable-side over-reporting and
  regressed the focused metrics to TP 6, FP 12, TN 10, FN 4 while keeping the
  same zero patched findings. Keep `cmdi.yaml` at v1.0.1 and address the
  remaining diagnostic gap in scoring/failure-analysis tooling.
- Failure payloads now include `related_agent_findings` for missed examples so
  review can distinguish true misses from same-file, same-CWE vulnerable
  findings that missed only the exact benchmark truth span.
- Payloads also include a `diagnostics` count summary for missed examples:
  nearby same-file related findings, same-file-only related findings, pure
  misses, and patched-version false positives.
- Failure payload examples now include `evidence_quality_flags` and diagnostic
  counts for missing code excerpts and test-file paths. This was added after
  XSS triage showed the first three XSS misses are not clean YAML-training
  evidence: one OSSF miss has no extractable source excerpt, one AntiSamy miss
  is a sanitizer unit-test span, and the Zope miss needs manual review because
  its truth span is a framework namespace/evaluation helper rather than a
  direct HTML-output sink.
- OSSF extraction now rejects same-basename fallback files that do not cover
  the SARIF truth line range. This prevents cases such as
  `ossf-CVE-2018-16484` from being treated as extractable when `lib/index.js`
  resolves to an unrelated one-line `index.js` in the benchmark metadata repo.
- Focused SQLi/NHibernate review accepted a narrow `sqli.yaml` v1.0.1
  refinement for C# ORM SQL literal/comment renderers such as NHibernate
  `ObjectToSQLString()`. The focused rerun on
  `rc-csharp-nhibernate-core-CVE-2024-39677` improved the vulnerable-side
  result from 1 to 3 findings while keeping patched findings at 0:
  TP 3, FP 0, TN 25, FN 22. The remaining capped failure payload has five
  pure misses; several are likely truth-span/helper artifacts, so further SQLi
  YAML changes should wait for another reviewed concrete slice.

Focused rerun example:

```bash
uv run python benchmarks/scripts/run_controlled_autoresearch.py \
  --controlled-plan <controlled_run_plan.json> \
  --output-dir <focused-output-dir> \
  --agent cmdi \
  --case-id rc-java-plexus-utils-CVE-2017-1000487 \
  --include-related-context \
  --execute \
  --allow-claude-invocation
```
