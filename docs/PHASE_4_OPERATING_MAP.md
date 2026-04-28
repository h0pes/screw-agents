# Phase 4 Operating Map - Autoresearch

> Last updated: 2026-04-28

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
| Claude benchmark execution | Running agents over vulnerable/patched cases | No result artifacts tracked by default | Yes | Blocked until readiness is clean |

The current blockers are in the second layer. They do not mean the benchmark
design was lost. They mean the fresh worktree does not currently contain all of
the large/generated local benchmark material needed before paid Claude runs.

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

Status: main scaffold merged in PR #18; readiness checklist is active on
`phase4-d02-readiness`.

What exists:
- dry-run planner: inventories manifests, gates, extractor support, and lower
  bound invocation cost;
- gate correction: `G5.8` now targets `morefixes`; stale SSTI gates `G5.9` and
  `G5.10` are retired;
- failure-input schema: future YAML changes must cite concrete missed findings
  or false positives;
- controlled-run scaffold: refuses execution unless Claude invocation is
  explicitly allowed and required datasets are ready;
- readiness checklist: explains which local datasets must be materialized before
  a controlled run can start.

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

Fresh-worktree result as of 2026-04-28:

| Dataset | Needed for active G5? | Current meaning |
|---|---|---|
| `ossf-cve-benchmark` | Yes | External directory and `truth.sarif` material are missing locally |
| `reality-check-csharp` | Yes | External directory and `truth.sarif` material are missing locally |
| `reality-check-python` | Yes | External directory and `truth.sarif` material are missing locally |
| `reality-check-java` | Yes | External directory and `truth.sarif` material are missing locally |
| `morefixes` | Yes | Directory exists, but regenerated `truth.sarif` plus code snapshots are missing |
| `crossvul` | No | Useful benchmark data, but not required by active G5 gates right now |
| `go-sec-code-mutated` | No | Retained as SQLi data; no longer misused as SSTI gate evidence |
| `skf-labs-mutated` | No | Retained as SQLi data; no longer misused as SSTI gate evidence |
| `rust-d01-real-cves` | No active G5 yet | Needs materialization and local clones before Rust-scoped gates |
| `vul4j` | No | Explicitly deferred until checkout layout/extractor contract exists |

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

Expensive benchmark execution:

```bash
uv run python benchmarks/scripts/prepare_autoresearch_run.py \
  --dry-run-plan <run_plan.json> \
  --allow-claude-invocation
```

That only prepares an executable plan. Actual benchmark execution remains a
separate step and must keep `ANTHROPIC_API_KEY` unset so the Claude Pro
subscription is used instead of API billing.

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

1. Merge the readiness checklist tooling.
2. Materialize active G5 datasets locally, starting with the smallest or least
   risky restoration path.
3. Re-run the readiness checklist until active blockers are gone.
4. Prepare a small controlled sample plan.
5. Discuss explicit Claude invocation before any paid benchmark execution.
6. Convert failures into `phase4-autoresearch-failure-input/v1` payloads.
7. Only then consider targeted YAML refinements.
