# Phase 4 D-02 — Autoresearch And Gate Optimization Plan

> Status: dry-run, gate-audit, failure-input, and controlled-run scaffold merged
> in PR #18. Dataset readiness checklist active on branch
> `phase4-d02-readiness`.
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

Status: readiness checklist implemented; dataset materialization still local and
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
- Current blockers are external directory/truth materialization for OSSF and
  reality-check datasets, plus missing `truth.sarif` materialization for
  MoreFixes. `vul4j` remains explicitly deferred; Rust D-01 is tracked as a
  non-G5 warning until local clones are supplied.
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

Status: implemented in `src/screw_agents/autoresearch/failure_input.py`.

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

### Task 5 — Controlled Execution

Status: guarded scaffold implemented in
`src/screw_agents/autoresearch/controlled_run.py` and
`benchmarks/scripts/prepare_autoresearch_run.py`.

Only after Tasks 1-4 are resolved:
- prepare a small sample plan first
- require explicit `--allow-claude-invocation` before a plan can become
  executable
- keep YAML mutation disabled in the controlled-run schema
- block execution when external dataset dirs, truth files, or extractors are
  missing
- review failures manually using
  `phase4-autoresearch-failure-input/v1` payloads
- then scale toward full D-02 threshold optimization
- keep checkpoint/resume behavior intact

The scaffold writes JSON and Markdown under ignored `benchmarks/results/`
paths, but does not invoke Claude or execute benchmarks by itself.
