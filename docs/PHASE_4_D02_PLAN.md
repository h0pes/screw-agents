# Phase 4 D-02 — Autoresearch And Gate Optimization Plan

> Status: initial scaffold in progress on branch
> `phase4-d02-autoresearch-scaffold`.
> Scope: plan and audit expensive benchmark/autoresearch runs before invoking
> Claude or mutating agent YAML.

## Goal

D-02 takes the validated Phase 1.7 benchmark pipeline and turns it into a
controlled Phase 4 autoresearch workflow. The first milestone is not a full
benchmark run. It is a dry-run planning layer that makes cost, missing data,
gate-definition drift, and YAML-mutation guardrails explicit before any
long-running or paid work starts.

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

Status: partially implemented.

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
- Re-materialize/download required external datasets in a worktree-local,
  reproducible way.
- Keep generated external dataset contents ignored.

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

Status: pending.

Define the structured payload future autoresearch steps will consume:
- missed finding examples
- false-positive examples
- dataset/case provenance
- exact agent and YAML source version
- benchmark split metadata
- guardrail state explaining whether YAML mutation is allowed

### Task 5 — Controlled Execution

Status: pending.

Only after Tasks 1-4 are resolved:
- run a small sample plan first
- review failures manually
- then scale toward full D-02 threshold optimization
- keep checkpoint/resume behavior intact
