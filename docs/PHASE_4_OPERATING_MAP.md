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

## Calibration, Not Per-CVE Tuning

Phase 4 must not become a manual queue of benchmark CVEs. The external
benchmarks contain thousands of cases, and each real vulnerability has
framework, library, source-layout, and truth-span details that are too specific
to encode one by one. The durable value is not a list of CVE-specific
exceptions; it is reusable domain knowledge plus a trustworthy measurement
loop.

Controlled slices are diagnostic probes. A small case can justify one of three
outcomes:
- an agent YAML change, only when the case exposes a reusable domain-level
  vulnerability pattern;
- a benchmark machinery change, when source extraction, related-file context,
  scoring, or failure reporting is undercounting useful evidence;
- a dataset/materialization decision, when the benchmark truth or source
  snapshot is not trustworthy enough for executable scoring.

Accepted YAML refinements must generalize beyond the package or CVE that
surfaced them. For example, a Rails SQLi finding can motivate a general rule
about attacker-controlled SQL clause construction versus unchanged framework
helpers; it must not become a Rails/CVE-specific allowlist or denylist. A
Plexus CmdI finding can motivate related-file evidence accounting; it must not
teach the CmdI agent to memorize Plexus class names.

Broader benchmark runs are still useful, but they serve a different purpose:
validation and regression measurement. They should happen after the controlled
path can classify failures into real agent gaps, scoring artifacts, source
materialization problems, prompt/runtime issues, and truth-span noise. If a
large run produces hundreds or thousands of misses, the next step is clustering
and representative sampling, not manually tuning every miss.

The validation ladder is:
- focused case rerun: verify one suspected fix or failure classification;
- mini consolidation: verify the current small multi-agent slice;
- expanded stratified sample: run several trustworthy cases per executable
  dataset/agent pair within an explicit prompt budget;
- agent-level sampled benchmark: measure one agent across larger trusted slices;
- full executable corpus: periodic confidence/regression check once source
  materialization, scoring semantics, and cost controls are mature enough.

Case selection should balance two useful signals:
- priority-frontier coverage: front-load cases that are CVE-backed, known
  exploited when metadata is available, high severity/CVSS when metadata is
  available, rich in vulnerable/patched truth spans, recent, or explicitly
  marked as high-priority by a reviewed manifest;
- representative coverage: keep deterministic manifest-order or random-like
  slices available so benchmark work does not overfit to famous frameworks or
  hand-picked cases.

Use `priority-stratified` for cost-sensitive expanded batches where the first
Claude calls should buy the most security signal. Use `expanded-stratified` or
the smoke defaults when the goal is a less opinionated sample of the executable
dataset surface. Both expanded strategies record incomplete or zero-case gate
selections as warnings when the broader plan still has executable selections.
Neither mode makes YAML changes by itself; both only produce case-level
evidence for later review.

The first no-Claude `priority-stratified` probe on 2026-04-30 used the
long-lived main checkout's materialized benchmark data and produced
`/tmp/screw-d02-priority-stratified-executor-validation`. It selected seven
executable cases across XSS, CmdI, and SQLi, including three higher-priority
MoreFixes SQLi cases, but estimated 90 prompts and about 12.55M retry-budgeted
prompt characters at `--max-retries 3`. Treat that as a planning signal: run
narrower live validation slices first unless the larger prompt budget is
explicitly approved.

The refreshed no-Claude `priority-stratified` probe on 2026-05-01 after SSTI
`G5.11` produced `/tmp/screw-d02-expanded-refresh-priority-validation-v2`. It
selected seven executable cases across all four active agents, measured
72 prompts, 3,134,010 prompt characters, and 9,402,030 retry-budgeted prompt
characters at `--max-retries 3`. Executor reports now include a per-case
prompt-budget table; use it to select narrow live runs. The new Exponent CMS
SQLi case is high-cost by itself (20 prompts, 1,109,399 prompt characters), so
it should not be live-executed until that budget is accepted or packaging is
narrowed.

Controlled executor runs now have an explicit `--max-files-per-variant`
packaging cap for reviewed high-cost slices. The default `0` keeps the normal
extractor behavior. A non-zero cap must be treated as representative sampling,
not full-case coverage. No-Claude validation with cap 3 at
`/tmp/screw-d02-morefixes-packaging-priority-cap3-validation` reduced the
refreshed priority batch to 30 prompts and 4,494,636 retry-budgeted prompt
characters. Exponent CMS alone fits the default one-retry guardrail with cap 2:
`/tmp/screw-d02-morefixes-packaging-exponent-cap2-validation` measured 4
prompts and 247,637 prompt characters.

The first narrowed cross-agent live run using cap 3,
`/tmp/screw-d02-cross-agent-noncmdi-cap3-run`, benchmark run
`20260501-175446`, completed cleanly: 12 invocations, 12 completed, 0 failed,
0 timed out, and 0 stale. It covered XSS AntiSamy/Zope, SQLi NHibernate, and
SSTI MLflow while reusing the separate tool-disabled Plexus run as CmdI
related-context evidence. Its useful finding was a packaging flaw, not an
agent-knowledge signal: the initial cap truncated NHibernate to low-signal
test/support files and produced 0 SQLi vulnerable findings. The cap now ranks
files by production-path likelihood and matching truth-span count before
truncation. No-Claude validation at
`/tmp/screw-d02-nhibernate-ranked-cap3-validation-v3` shows the NHibernate cap
now selects `Dialect`, `AbstractCharType`, and `AbstractStringType`; the
updated cross-agent preflight at
`/tmp/screw-d02-cross-agent-ranked-noncmdi-cap3-validation` remains within the
one-retry budget at 12 prompts and 663,520 prompt characters.

The first capped Exponent CMS live sampling run,
`/tmp/screw-d02-morefixes-exponent-cap2-run`, benchmark run
`20260501-091647`, produced 7 vulnerable findings and 0 patched findings, but
the two patched Claude invocations failed JSON extraction. Treat the run as
useful localization evidence, not precision evidence. Its failure payload shows
nearby same-file findings for all 5 concrete misses; manual review found a real
span anchoring defect where the agent described the `activate_address` sink on
line 172 but returned lines 158-159. The prompt now requires findings to anchor
on the exact vulnerable expression/call, and executor reports surface failed or
timed-out invocation telemetry as warnings.

The capped localization rerun after that prompt/reporting change,
`/tmp/screw-d02-localization-exponent-cap2-run`, benchmark run
`20260501-094144`, recorded 3 completed Claude invocations and 1 failed JSON
extraction. It produced TP 1, FP 9, TN 405, FN 409, with 4 vulnerable findings
and 8 patched findings. The important signal is qualitative: the prior
`activate_address` localization defect moved to the actual
`addressController.php` sink line 172. The remaining failure payload at
`/tmp/screw-d02-localization-exponent-cap2-failure-inputs/sqli_failure_input.json`
still reports 5 missed spans, including one pure miss from the failed vulnerable
`administrationController.php` invocation. Patched findings require
fix-semantics review because the patched sample appears to retain other raw SQL
helper patterns. Keep this as prompt/localization and executor robustness
evidence, not `sqli.yaml` evidence.

Claude invocation parsing now accepts common nested or fenced findings
envelopes in `result`/`structured_output`. Failed post-Claude invocations also
write full stdout/stderr artifacts under `invocation_failures/` beside
`invocation_progress.jsonl`, with each failed progress event linking its
artifact. Use those artifacts to classify future failures before spending more
Claude calls or changing agent YAML.

Controlled Claude invocation now disables Claude Code tools with `--tools ""`.
The focused Plexus related-context run at
`/tmp/screw-d02-plexus-related-context-exec-run`, benchmark run
`20260501-132018`, produced a concrete failure artifact where Claude attempted
to call `Bash` during the vulnerable `Commandline.java` prompt and exhausted
the one-turn benchmark invocation. Benchmark runs should return structured
findings from the supplied prompt only; they should not spend turns on tool
permission flow.

The follow-up tool-disabled Plexus rerun at
`/tmp/screw-d02-plexus-tools-disabled-rerun`, benchmark run
`20260501-173750`, completed all 6 invocations with 0 failures, 0 timeouts,
and no stale active calls. It kept the patched side clean with 0 patched
findings. Metrics were TP 2, FP 2, TN 10, FN 8 from 4 vulnerable findings, so
use this run as runtime validation plus related-context patched-clean evidence,
not as a fresh CmdI YAML-training signal.

Exponent CMS fix-semantics review, verified 2026-05-01:
- Annotated payload:
  `/tmp/screw-d02-localization-exponent-cap2-fix-semantics-input.json`.
  It was generated from the full capped payload at
  `/tmp/screw-d02-localization-exponent-cap2-failure-inputs-full` and validates
  against `phase4-autoresearch-failure-input/v1`.
- `addressController.php:87` is likely residual-risk / incomplete-fix
  evidence: the patched snapshot still assigns request-derived
  `$this->params['user_id']` to `$userid` and concatenates it into
  `'user_id='.$userid` for `find()`. That code is unchanged by the CVE patch.
- `administrationController.php:129` is likely residual-risk /
  incomplete-fix evidence: the patched snapshot still derives `$basename` from
  request-selected `tables[]` and passes it to `dropTable()`, whose local
  implementation wraps the identifier in backticks but does not escape
  embedded identifier delimiters.
- `administrationController.php:184`, `:211`, and `:221` are fix-semantics
  ambiguous: the raw WHERE strings are present, but the evidence depends on
  whether stored `sectionref` / container metadata is attacker-writable and
  whether upstream framework paths normalize it before this repair workflow.
- `addressController.php:146`, `:152`, and `administrationController.php:227`
  are weak/speculative patched reports: they depend on model IDs or primary
  keys read back from the database rather than a proven request-controlled SQL
  string in the capped slice.
- Decision: keep `sqli.yaml` unchanged. The Exponent slice is useful evidence
  that fix quality and scoring labels are mixed in MoreFixes, but it is not
  clean precision-training evidence.

Phase 4 closure does not require manually processing every benchmark
vulnerability. It does require a reliable workflow, clear dataset
inclusions/exclusions, prompt-budget guardrails, case-level failure payloads,
and at least one broader representative validation that shows the accepted
rules and infrastructure changes do not introduce obvious precision
regressions.

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
- gate correction: `G5.8` now targets SQLi on `morefixes`; stale SSTI gates
  `G5.9` and `G5.10` are retired; `G5.11` resumes SSTI validation through the
  executable MoreFixes MLflow `CVE-2023-6709` / `CWE-1336` case;
- failure-input schema: future YAML changes must cite concrete missed findings
  or false positives;
- controlled-run scaffold: writes a blocked smoke plan by default and refuses
  executable plans unless Claude invocation is explicitly allowed and required
  datasets are ready;
- readiness checklist: explains which local datasets must be materialized before
  a controlled run can start;
- controlled executor reporting: records overall benchmark metrics,
  vulnerable/patched finding counts, and pre-execution prompt-budget estimates
  for each selected case;
- per-case prompt-budget reporting: groups preflight prompt counts, characters,
  tokens, and retry-adjusted costs by selected case so expensive live slices
  are obvious before Claude invocation;
- explicit controlled packaging caps: `--max-files-per-variant` can narrow
  vulnerable/patched files per selected case for reviewed sampling runs without
  changing default extractor behavior;
- sink-line anchoring prompt contract: benchmark prompts require returned
  spans to cover the named sink/query/template/shell/framework call instead of
  nearby function or block lines;
- failure-input payload generator: turns controlled-run misses and patched
  findings into schema-valid `phase4-autoresearch-failure-input/v1` payloads.
- invocation progress telemetry: records live Claude call start/completion,
  failure, timeout, and stale-active state for controlled executor runs.
- invocation failure artifacts: preserve full stdout/stderr for failed
  post-Claude parses or non-zero exits next to the progress log.

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
| `morefixes` | Yes | Ready; 2,601 `truth.sarif` files and code snapshots materialized locally; covers SQLi `G5.8` and SSTI `G5.11` |
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

Live controlled executor runs now write an invocation progress JSONL file in
the executor output directory:

```bash
uv run python benchmarks/scripts/show_invocation_progress.py \
  <executor-output-dir>/invocation_progress.jsonl
```

Use this while a run is active to see started, completed, failed, timed-out,
active, and stale Claude calls. A stale call means the last `started` event is
older than that call's timeout plus the helper's grace period; it is evidence
for interrupting or investigating the run without guessing from result files or
process listings alone.

For post-smoke validation, use `--selection-strategy expanded-stratified` with
higher `--max-cases-per-dataset` and `--max-cases-per-agent` caps. This
strategy selects up to the requested cap from each active dataset/agent pair,
warns when fewer trustworthy executable cases are available, and blocks only
when no executable case can be selected for a requested slice. It is intended
for representative validation, not for exhaustive per-CVE tuning.

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
Validation also assembles the exact per-file prompts and reports prompt
character/token estimates before any Claude call. The default execution guard
is `--max-prompt-chars 250000`, applied to the retry-budgeted prompt character
total. Use `--max-prompt-chars 0` only for an explicitly reviewed run.

Latest no-Claude budget validation, 2026-04-30:
- Output directory: `/tmp/screw-d02-prompt-budget-validation`.
- Input plan:
  `/tmp/screw-d02-plexus-related-context-nonossf-controlled/controlled_run_plan.json`.
- Prompt count: 34 actual per-file prompts for the five selected non-OSSF
  slices. This is higher than the case-pair "estimated calls" summary because
  multi-truth cases can produce several vulnerable/patched file prompts.
- Prompt chars: 1,427,680; retry-budgeted prompt chars at `--max-retries 3`:
  4,283,040.
- Estimated tokens: 356,935; retry-budgeted estimated tokens: 1,070,805.
- The validation emits `prompt_budget_exceeded` in warning mode. The same plan
  would be blocked in execution mode unless narrowed with filters or given an
  explicitly reviewed higher budget.

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
subscription path is used rather than API billing. Also inspect the validation
report's `Prompt Estimates` section first; the default prompt-budget guard is
there to prevent accidental high-token Claude Code plan consumption.

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

The controlled plan and executor now also support targeted case-level related
context for CmdI multi-file selections. In mixed consolidation runs, this keeps
the global related-context switch off while automatically marking the reviewed
Plexus CmdI case for related context. The executor report lists both the global
related-context mode and the exact related-context case IDs so reviewers can
confirm other slices stayed on single-primary-file prompts.

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

Cleaner rerun review of the five CmdI/Plexus misses:
- Payload reviewed:
  `/tmp/screw-d02-plexus-related-context-nonossf-rerun-failure-inputs/cmdi_failure_input.json`.
- Clean-run vulnerable findings are all in `BourneShell.java` on the actual
  vulnerable quoting behavior: `getExecutable()`/`getExecutionPreamble()` call
  `unifyQuotes()`, which uses double-quote-style shell quoting. Patched
  3.0.16 replaces this path with unconditional single-quote-style
  `quoteOneItem()` and keeps patched findings at zero.
- `Shell.java:40-409` and `Shell.java:132-178` are broad truth-span/scoring
  artifacts. The spans cover the base shell builder and `getRawCommandLine()`,
  but the concrete vulnerable behavior in this CVE is the Bourne-shell override
  and its quote model. The agent found the subclass behavior and stayed
  patched-clean, so broadening `cmdi.yaml` to force base-class hits would risk
  reviving patched `Shell.java` false positives.
- `Shell.java:266-285` is a bridge-span artifact. It assembles
  `getShellCommandLine()` by delegating to `getCommandLine()` and is useful for
  call-chain understanding, but it is not where the escaping semantics changed.
- `Commandline.java:483-496` is not a good YAML-training target. In the
  vulnerable version it returns `getExecutable()` plus arguments; in patched
  3.0.16 it returns the literal executable for non-shell execution while
  `getShellCommandline()` remains the shell path. Treat this as benchmark
  localization/scoring noise unless another case proves a reusable pattern.
- `Commandline.java:665-676` (`verifyShellState()`) remains the only plausible
  bridge-localization gap because it copies working directory and executable
  state into the shell object before shell command construction. A previous
  prompt trial for this class of helper regressed badly, so do not mutate
  `cmdi.yaml` from this single span. The better next improvement is scoring or
  failure-analysis support for related-file/call-chain credit, plus clearer
  bridge-span classification in payloads.
- Conclusion: keep `cmdi.yaml` at v1.0.1. Plexus is now patched-clean under
  related-context packaging; remaining recall loss is primarily truth-span and
  localization granularity, not evidence for broader CmdI knowledge.

Related-file failure diagnostics, verified 2026-04-30:
- Failure payload generation now records same-case related-file findings for
  cases that were executed with related context, using the
  `related_file_same_case` relationship. Same-file relationships remain
  separate as `nearby_same_file` and `same_file`.
- Regenerated payloads:
  `/tmp/screw-d02-plexus-related-file-diagnostics-failure-inputs/cmdi_failure_input.json`,
  `/tmp/screw-d02-plexus-related-file-diagnostics-failure-inputs/sqli_failure_input.json`,
  and `/tmp/screw-d02-plexus-related-file-diagnostics-failure-inputs/xss_failure_input.json`.
- CmdI/Plexus diagnostics now classify all five missed truth spans as
  `missed_with_related_file_findings` and zero as `pure_misses`. Each miss
  cites the three clean-run `BourneShell.java` findings that identify the
  vulnerable quote behavior. This makes the earlier review mechanically visible
  in the payload instead of relying on manual cross-file comparison.
- Related-file scoring diagnostics are now explicit in regenerated payloads at
  `/tmp/screw-d02-plexus-related-file-scoring-failure-inputs`. CmdI/Plexus
  still records 5 `exact_span_false_negatives`, but all 5 are
  `related_file_credit_candidates`, so
  `false_negatives_after_related_file_credit` is 0. Use this adjusted count
  only for failure analysis and calibration; exact benchmark TP/FN metrics stay
  unchanged.
- SQLi and XSS diagnostics are intentionally unchanged by this cross-file rule:
  SQLi still has five pure misses and one test-file-path miss, while XSS keeps
  the known AntiSamy test-file miss. Related-file findings are only attached
  when the executor actually ran the case with related context.

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

Focused SQLi/MoreFixes Rails LIMIT/OFFSET execution, verified 2026-04-29:
- Output directory:
  `/tmp/screw-d02-sqli-morefixes-rails-baseline-run`.
- Benchmark run ID: `20260429-181258`.
- Case:
  `morefixes-CVE-2008-4094-https_____github.com__rails__rails`.
- Result: TP 1, FP 1, TN 5, FN 4; TPR 20.0%, FPR 16.7%, precision 50.0%,
  F1 28.6%, accuracy 3.3%.
- Raw finding counts: 2 vulnerable-version findings, 0 patched-version
  findings. The agent correctly found vulnerable Rails
  `add_limit_offset!`, where `options[:limit]` and `options[:offset]` are
  interpolated directly into `LIMIT` / `OFFSET`, and patched Rails stayed
  clean after `sanitize_limit(limit)` and `offset.to_i`.
- No `sqli.yaml` change is accepted from this slice. The failure payload
  `/tmp/screw-d02-sqli-morefixes-rails-baseline-failure-inputs/sqli_failure_input.json`
  shows two missed truth spans in `adapter_test.rb` flagged as test-file
  paths, one with a missing source excerpt. The remaining non-test miss is
  line drift around `sanitize_limit`/comments while the agent already reported
  nearby `add_limit_offset!`. The extra vulnerable-side `add_lock!` report is
  outside this CVE truth and should be treated as potential over-reporting
  risk before broadening Rails structural-SQL guidance.

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

Non-OSSF consolidation execution, verified 2026-04-29:
- Output directory: `/tmp/screw-d02-nonossf-consolidation-run`.
- Benchmark run ID: `20260429-182422`.
- Command shape: filtered executor run over the five currently executable
  non-OSSF slices: AntiSamy/XSS, Zope/XSS, Plexus/CmdI, NHibernate/SQLi, and
  MoreFixes Rails/SQLi.
- No executor issues were reported. One NHibernate Claude invocation failed to
  return an extractable findings array during the run, but retry handling
  continued and the final report completed.
- Result summary: Zope stayed clean at TP 1, FP 0, TN 1, FN 0; NHibernate
  kept the accepted v1.0.1 shape at TP 3, FP 0, TN 25, FN 22; AntiSamy
  remained a test-file truth-span miss with no findings; Plexus produced
  vulnerable findings plus one patched `Shell.java` finding when run without
  related context; MoreFixes Rails produced the expected vulnerable
  `add_limit_offset!` finding but also patched `add_lock!` and
  `insert_fixture` findings.
- Generated consolidation failure payloads:
  `/tmp/screw-d02-nonossf-consolidation-failure-inputs/cmdi_failure_input.json`,
  `/tmp/screw-d02-nonossf-consolidation-failure-inputs/sqli_failure_input.json`,
  and `/tmp/screw-d02-nonossf-consolidation-failure-inputs/xss_failure_input.json`.
- Interpretation: do not mutate YAML from this aggregate run. Plexus should use
  `--include-related-context` in focused multi-file reruns because the earlier
  related-context run removed patched findings. Rails now has a precision and
  repeatability question: the focused Rails run had no patched findings, while
  the consolidation run flagged patched `add_lock!` and `insert_fixture`.
  Review those concrete false-positive examples before any future SQLi Rails
  guidance change.

Rails SQLi precision review, 2026-04-29:
- The MoreFixes Rails SARIF truth for CVE-2008-4094 is narrow: the real target
  is `add_limit_offset!` / `sanitize_limit` plus adapter tests for limit
  sanitization. `add_lock!` and `insert_fixture` are unchanged between the
  vulnerable and patched snapshots, so benchmark scoring correctly treats them
  as out-of-CVE findings.
- A fresh focused repeat at
  `/tmp/screw-d02-sqli-morefixes-rails-repeat-run`, benchmark run
  `20260429-190125`, reproduced the consolidation shape: 3 vulnerable findings
  and 2 patched findings. This makes the issue repeatable, not a one-off
  consolidation artifact.
- An initial broad `sqli.yaml` trial was rejected because it over-suppressed
  the slice to 0 vulnerable findings and 0 patched findings. The accepted
  `sqli.yaml` v1.0.2 refinement is narrower: Rails/ActiveRecord lock-clause
  and fixture helpers are context-required unless visible attacker-controlled
  data flows into the option/object, while vulnerable LIMIT/OFFSET appenders
  remain reportable.
- Focused v1.0.2 rerun:
  `/tmp/screw-d02-sqli-morefixes-rails-precision-v102b-run`, benchmark run
  `20260429-191014`. Result: TP 1, FP 0, TN 5, FN 4; TPR 20.0%, FPR 0.0%,
  precision 100.0%, F1 33.3%, accuracy 20.0%. Raw finding counts: 1
  vulnerable-version finding on `add_limit_offset!`, 0 patched-version
  findings. Generated failure payload:
  `/tmp/screw-d02-sqli-morefixes-rails-precision-v102b-failure-inputs/sqli_failure_input.json`.

Non-OSSF v1.0.2 consolidation execution, verified 2026-04-30:
- Output directory: `/tmp/screw-d02-nonossf-consolidation-v102-run`.
- Benchmark run ID: `20260430-055646`.
- No executor issues were reported.
- SQLi/Rails stayed fixed in the mixed run: TP 1, FP 0, TN 5, FN 4, with one
  vulnerable `add_limit_offset!` finding and zero patched findings.
- SQLi/NHibernate remained patched-clean but varied slightly on recall:
  TP 2, FP 0, TN 25, FN 23, with vulnerable findings on
  `AbstractCharType.ObjectToSQLString` and
  `AbstractStringType.ObjectToSQLString`.
- XSS/Zope remained clean at TP 1, FP 0, TN 1, FN 0. XSS/AntiSamy remained the
  known test-file truth-span miss with no findings.
- CmdI/Plexus worsened without related context: TP 2, FP 3, TN 8, FN 8, with
  three patched `Shell.java` findings. This confirms the next engineering
  slice should address multi-file evidence packaging for Plexus-style cases
  rather than another `cmdi.yaml` mutation.
- Generated consolidation failure payloads:
  `/tmp/screw-d02-nonossf-consolidation-v102-failure-inputs/cmdi_failure_input.json`,
  `/tmp/screw-d02-nonossf-consolidation-v102-failure-inputs/sqli_failure_input.json`,
  and `/tmp/screw-d02-nonossf-consolidation-v102-failure-inputs/xss_failure_input.json`.

CmdI/Plexus case-level related-context packaging, verified 2026-04-30:
- Controlled plan/output setup:
  `/tmp/screw-d02-plexus-related-context-nonossf-controlled`.
- Validation-only executor report:
  `/tmp/screw-d02-plexus-related-context-nonossf-validation`.
- The mixed validation report keeps global related context off and marks only
  `rc-java-plexus-utils-CVE-2017-1000487` as a related-context case. AntiSamy,
  Zope, NHibernate, and Rails remain single-primary-file prompts.
- Focused Plexus execution:
  `/tmp/screw-d02-plexus-related-context-plexus-run`, benchmark run
  `20260430-063651`. No executor issues were reported. Result: TP 1, FP 0,
  TN 10, FN 9; vulnerable findings 1; patched findings 0. One Claude response
  failed JSON extraction during the run, so treat recall as runtime-noisy.
- Mixed non-OSSF execution:
  `/tmp/screw-d02-plexus-related-context-nonossf-run`, benchmark run
  `20260430-064528`. No executor issues were reported and the report confirms
  related context was applied only to Plexus. Plexus produced 6 vulnerable
  findings and 0 patched findings, improving the previous mixed run's three
  patched `Shell.java` findings. Claude runtime/output failures occurred on
  Plexus and NHibernate, and Rails scored a vulnerable-side FP despite unchanged
  no-context packaging, so use this run as evidence that packaging is wired into
  consolidation, not as a clean benchmark-quality baseline.
- Cleaner mixed non-OSSF stability rerun:
  `/tmp/screw-d02-plexus-related-context-nonossf-rerun`, benchmark run
  `20260430-075117`. No executor issues or Claude retry/output failures were
  emitted. Plexus remained patched-clean with TP 3, FP 0, TN 10, FN 7 and raw
  finding counts of 3 vulnerable, 0 patched. Rails returned to the accepted
  v1.0.2 shape with TP 1, FP 0, TN 5, FN 4 and one vulnerable
  `add_limit_offset!` finding. NHibernate stayed patched-clean at TP 2, FP 0,
  TN 25, FN 23; Zope stayed clean; AntiSamy remained the known test-file
  truth-span miss.
- Focused 2026-05-01 Plexus validation:
  `/tmp/screw-d02-plexus-related-context-validation` confirmed the current plan
  still marks only Plexus for related context and estimated 6 prompts,
  342,987 prompt chars, and 85,749 estimated tokens at one retry. Live
  execution at `/tmp/screw-d02-plexus-related-context-exec-run`, benchmark run
  `20260501-132018`, returned 3 vulnerable findings and 0 patched findings,
  with TP 3, FP 0, TN 10, FN 7. It also recorded 1 failed vulnerable
  invocation and 1 vulnerable timeout; the failed invocation artifact showed
  Claude attempted a `Bash` tool call. Treat this as confirmation of
  related-context patched cleanliness plus runtime evidence for tool-free
  invocation, not as a cleaner benchmark-quality baseline than the 2026-04-30
  stability rerun.
- Tool-disabled Plexus rerun:
  `/tmp/screw-d02-plexus-tools-disabled-rerun`, benchmark run
  `20260501-173750`. No executor issues were reported. Invocation progress
  recorded 6 completed calls, 0 failed, 0 timed out, and 0 stale. Patched
  findings remained 0; vulnerable findings were 4, with TP 2, FP 2, TN 10,
  FN 8. This validates the `--tools ""` invocation fix and preserves the
  patched-clean related-context conclusion, while still leaving recall/scoring
  as Plexus truth-span evidence rather than CmdI YAML evidence.
- Cleaner-run failure payloads:
  `/tmp/screw-d02-plexus-related-context-nonossf-rerun-failure-inputs/cmdi_failure_input.json`,
  `/tmp/screw-d02-plexus-related-context-nonossf-rerun-failure-inputs/sqli_failure_input.json`,
  and `/tmp/screw-d02-plexus-related-context-nonossf-rerun-failure-inputs/xss_failure_input.json`.
  Diagnostics: CmdI has 5 pure misses and 0 false-positive findings; SQLi has
  5 pure misses, 1 test-file-path miss, and 0 false-positive findings; XSS has
  the known AntiSamy test-file miss and 0 false-positive findings.

Current no-Claude payload triage, verified 2026-04-30:
- Payload source:
  `/tmp/screw-d02-plexus-related-file-scoring-failure-inputs`.
- XSS/AntiSamy has one missed span in
  `OWASP.AntiSamyTests/Html/AntiSamyTest.cs` and it is flagged as
  `test_file_path`. Treat this as benchmark truth-span/test-fixture evidence,
  not as a new `xss.yaml` mutation target.
- CmdI/Plexus has 5 exact-span misses, all 5 are related-file credit
  candidates, and patched findings remain 0. Treat this as closed for current
  YAML purposes.
- SQLi/NHibernate remains patched-clean. The capped misses are a SQL builder
  test span, a test/helper dialect support method, a boolean literal helper,
  `ByteType.Set()` typed parameter assignment, and
  `CharBooleanType.ObjectToSQLString()`. The first four are not clean evidence
  for broader SQLi prompt changes; the last is a sibling renderer already in
  the accepted v1.0.1 pattern family. Do not mutate `sqli.yaml` from this
  capped payload alone.
- Conclusion: current non-OSSF payloads do not justify another agent YAML
  change. The next useful step is expanded stratified validation with explicit
  prompt-budget review, not further per-case tuning of these slices.

Expanded stratified validation planning, verified 2026-04-30:
- Controlled plan:
  `/tmp/screw-d02-expanded-stratified-controlled/controlled_run_plan.json`.
- Command shape: `--selection-strategy expanded-stratified
  --max-cases-per-dataset 3 --max-cases-per-agent 12
  --allow-claude-invocation`.
- Selected 7 cases total: the existing 1 executable case for each
  reality-check active dataset/agent pair, plus 3 MoreFixes SQLi cases.
- Reality-check C#/XSS, Python/XSS, Java/CmdI, and C#/SQLi each emitted
  `case_selection_incomplete` warnings because only one currently trustworthy
  executable case was selectable for the requested active gate/CWE slice.
- No-Claude executor validation:
  `/tmp/screw-d02-expanded-stratified-validation`.
  It measured 40 prompts, 1,638,863 prompt characters, and about 1,229,199
  retry-budgeted estimated tokens at `--max-retries 3`; live execution remains
  blocked by the default `--max-prompt-chars 250000` guard.
- Focused no-Claude validation of only the three MoreFixes SQLi cases:
  `/tmp/screw-d02-expanded-stratified-morefixes-validation`.
  It measured 10 prompts, 324,101 prompt characters, and about 243,090
  retry-budgeted estimated tokens. This is the smallest useful live candidate
  from the expanded plan, but it still requires explicit budget acceptance
  before raising the prompt-character guard.

Expanded MoreFixes SQLi live run, verified 2026-04-30:
- Output directory: `/tmp/screw-d02-expanded-stratified-morefixes-run`.
- Benchmark run ID: `20260430-125213`.
- Command shape: `--agent sqli` with three MoreFixes case filters,
  `--execute --allow-claude-invocation --max-prompt-chars 1000000`; run with
  `ANTHROPIC_API_KEY` unset.
- No executor issues were reported.
- Prompt budget: 10 prompts, 324,101 prompt characters, about 243,090
  retry-budgeted estimated tokens.
- Result: TP 1, FP 10, TN 8, FN 10; TPR 9.1%, FPR 55.6%, precision 9.1%,
  F1 9.1%, accuracy -46.5%.
- Finding counts: Rails retained the accepted shape with 1 vulnerable finding
  and 0 patched findings; `gesellix/titlelink` had 2 vulnerable and 2 patched
  findings; `lierdakil/click-reminder` had 3 vulnerable and 4 patched findings.
- Failure payload:
  `/tmp/screw-d02-expanded-stratified-morefixes-failure-inputs/sqli_failure_input.json`.
  Diagnostics: 5 capped misses, 5 capped patched findings, 2 test-file-path
  misses, 1 missing excerpt, and 1 nearby same-file related miss.
- Initial interpretation: this is not clean evidence for another SQLi YAML
  mutation. The `titlelink` patched snapshot replaces raw interpolation with
  `$database->quote(..., false)`, which needs human fix-semantics review before
  deciding whether patched reports are false positives or residual risk. The
  `click-reminder` patched snapshot adds a semicolon blacklist and numeric
  `iid` check but leaves `sid` interpolation, so its patched findings may be
  residual-risk or benchmark-fix-quality evidence rather than prompt
  overbreadth. Review these two cases before any YAML change.

Expanded MoreFixes SQLi fix-semantics review, verified 2026-04-30:
- `gesellix/titlelink`: vulnerable code directly interpolates `$phrase` into
  `LIKE '%$phrase%'` / `= '$phrase'`. The patched snapshot changes those
  expressions to `$database->quote('%'.$phrase.'%', false)` and
  `$database->quote($phrase, false)`. The local MoreFixes snapshot does not
  include the Joomla database implementation, so the exact meaning of the
  second `quote()` argument cannot be proven from local source. Treat the
  patched findings as **fix-semantics ambiguous**, not as accepted SQLi YAML
  false positives. A future decision needs Joomla API/version evidence showing
  whether `false` disables escaping or only controls surrounding quotes.
- `lierdakil/click-reminder`: the patched snapshot adds a semicolon blacklist
  in `db_query()` and validates `iid` with `is_numeric()`, but it still
  interpolates `$this->sid` into `checkSIDValid()` and `updateLastActivity()`
  SQL strings after `htmlspecialchars(..., ENT_QUOTES)`. That is HTML-context
  escaping, not a parameterized SQL defense, and the patch still uses string
  SQL execution. Treat the patched findings as **likely residual-risk /
  incomplete-fix evidence**, not prompt overbreadth.
- Decision: do not mutate `sqli.yaml` from this expanded MoreFixes run. The
  correct next action is to mark these two cases as needing benchmark
  fix-semantics review before they can be used as precision-training evidence.
- Failure payload schema now supports those review outcomes directly through
  `evidence_quality_flags`: `fix_semantics_ambiguous` and
  `residual_risk_or_incomplete_fix`. Diagnostics also count
  `false_positive_fix_semantics_ambiguous` and
  `false_positive_residual_risk_or_incomplete_fix`.
- Annotated payload:
  `/tmp/screw-d02-expanded-stratified-morefixes-fix-semantics-input.json`.
  It classifies the 2 `titlelink` patched findings as fix-semantics ambiguous
  and the 3 `click-reminder` patched findings as residual-risk/incomplete-fix
  evidence.

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
3. Review the prompt-budget estimate from validation before any live Claude
   execution. Narrow runs with `--agent` / `--case-id` first; only raise or
   disable `--max-prompt-chars` after explicitly accepting the budget.
4. Generate `phase4-autoresearch-failure-input/v1` payloads from controlled
   smoke reports.
5. Treat SQLi/Rails v1.0.2 as accepted after the mixed consolidation rerun.
6. Treat CmdI/Plexus related-context packaging and related-file scoring
   diagnostics as implemented for controlled consolidation. Use the adjusted
   diagnostics to avoid retraining on the current five Plexus misses, and do
   not mutate `cmdi.yaml` from them.
7. Treat the current AntiSamy, NHibernate, and Plexus payloads as exhausted for
   YAML-training purposes. Plan an expanded stratified validation set over
   trustworthy executable cases before considering additional agent knowledge
   changes.
8. Treat SSTI as resumed through MoreFixes `G5.11`. The focused MLflow
   `CVE-2023-6709` run at `/tmp/screw-d02-ssti-morefixes-mlflow-run`,
   benchmark run `20260501-084946`, is the current accepted real-CVE SSTI
   slice: TP 1, FP 0, TN 2, FN 1; vulnerable findings 1; patched findings 0;
   failure-input generation produced no concrete payloads. Do not mutate
   `ssti.yaml` from this slice.
9. Review the expanded stratified prompt budget before any live run. If a live
   run is approved, start with a narrow case-filtered slice rather than the
   full refreshed priority plan. Use the `Prompt Budget By Case` section in
   `/tmp/screw-d02-expanded-refresh-priority-validation-v2` to avoid spending a
   session on broad MoreFixes SQLi cases before their cost is accepted.
10. For high-cost MoreFixes cases, validate with `--max-files-per-variant`
    before live execution. Record capped runs as sampling evidence only, and do
    not compare their aggregate TP/FN counts against uncapped benchmark gates.
11. For capped Exponent CMS, the sink-line anchoring rerun is complete. It
    confirmed one localization improvement. JSON-extraction failures now
    produce artifacts for review. The patched-source review classified the
    slice as mixed residual-risk, ambiguity, and speculative findings, so do
    not mutate `sqli.yaml` from it.
