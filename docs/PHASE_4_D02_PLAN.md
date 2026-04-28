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

Latest dry-run result from a fresh worktree:
- 10 benchmark case manifests.
- 4,154 cases.
- 8,308 lower-bound Claude invocations for a full vulnerable/patched pass.
- Known gate issues surfaced before execution:
  - `G5.8` references `morefixes-extract`, but tracked manifest is
    `morefixes` and code extraction is not implemented.
  - `G5.9` and `G5.10` target SSTI on SQLi datasets
    (`go-sec-code-mutated`, `skf-labs-mutated`).

### Task 2 — Dataset Readiness And Extraction Closure

Status: pending.

Resolve the plan's dataset readiness issues before any full run:
- Decide whether `morefixes` should be exposed as `morefixes`, renamed, or
  wrapped as `morefixes-extract` for G5 compatibility.
- Add or explicitly defer code extraction for `morefixes`, `vul4j`, and
  `rust-d01-real-cves`.
- Re-materialize/download required external datasets in a worktree-local,
  reproducible way.
- Keep generated external dataset contents ignored.

### Task 3 — Gate Definition Correction

Status: pending.

Correct stale G5 definitions before treating gate results as authoritative:
- Replace or retire SSTI gates pointing at SQLi-only datasets.
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
