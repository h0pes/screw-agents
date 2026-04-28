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
| Claude benchmark execution | Running agents over vulnerable/patched cases | No result artifacts tracked by default | Yes | Next step is blocked smoke-plan review |

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
long-lived main checkout after local materialization.

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

Long-lived main checkout result as of 2026-04-28:

| Dataset | Needed for active G5? | Current meaning |
|---|---|---|
| `ossf-cve-benchmark` | Yes | Ready; 118 `truth.sarif` files materialized locally |
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
  materialized OSSF case truth files.
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
G5 inventory, that is expected to prepare seven small slices: OSSF/XSS,
OSSF/CmdI, Reality Check C#/XSS, Reality Check C#/SQLi, Reality Check
Python/XSS, Reality Check Java/CmdI, and MoreFixes/SQLi.

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
4. Prepare a blocked controlled smoke plan and review selected slices.
5. Discuss explicit Claude invocation before any paid benchmark execution.
6. Convert failures into `phase4-autoresearch-failure-input/v1` payloads.
7. Only then consider targeted YAML refinements.
