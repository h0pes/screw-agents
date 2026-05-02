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
- `G5.11` now covers SSTI through MoreFixes `CWE-1336`, with the current
  executable seed case
  `morefixes-CVE-2023-6709-https_____github.com__mlflow__mlflow`.
- Focused SSTI/MoreFixes MLflow validation is accepted as the first real-CVE
  SSTI executable slice: `/tmp/screw-d02-ssti-morefixes-mlflow-run`,
  benchmark run `20260501-084946`, produced TP 1, FP 0, TN 2, FN 1, with one
  vulnerable finding and zero patched findings. Failure-input generation at
  `/tmp/screw-d02-ssti-morefixes-mlflow-failure-inputs` produced no concrete
  payloads, so no `ssti.yaml` mutation is currently justified.

### Task 2 — Dataset Readiness And Extraction Closure

Status: readiness checklist implemented; active G5 datasets materialized in the
long-lived main checkout; generated dataset contents remain local and
intentionally ignored.

Resolve the plan's dataset readiness issues before any full run:
- `morefixes` is exposed as `morefixes`; `G5.8` was updated from the stale
  `morefixes-extract` name.
- MoreFixes also supplies the current active SSTI validation slice through
  `G5.11` (`ssti` / `CWE-1336`), initially anchored on MLflow
  `CVE-2023-6709`.
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
- review the executor's prompt-budget estimate before any execution; validation
  assembles the exact prompts without invoking Claude, and execution is blocked
  by default when the retry-budgeted prompt character total exceeds
  `--max-prompt-chars 250000`
- optionally restrict validation/execution to reviewed slices with `--agent`
  and/or `--case-id` when iterating on a concrete failure payload
- optionally include same-variant related truth files as prompt context with
  `--include-related-context` for multi-file benchmark cases
- use `--selection-strategy priority-stratified` for larger controlled samples
  when the first cases should favor explicit manifest priority, known
  exploitation metadata, CVSS/severity metadata, CVE-backed cases, richer
  truth-span counts, and recency; this strategy, like `expanded-stratified`,
  records incomplete or zero-case gate selections as warnings when the broader
  plan still has executable selections; keep `expanded-stratified` available
  when the goal is less opinionated representative coverage
- 2026-04-30 priority-stratified no-Claude probe:
  `/tmp/screw-d02-priority-stratified-executor-validation` selected 7
  executable cases and validated extraction, but estimated 90 prompts and about
  12.55M retry-budgeted prompt characters at `--max-retries 3`; do not execute
  the whole priority slice without narrowing filters or explicit budget review
- 2026-05-01 refreshed priority-stratified no-Claude probe after SSTI `G5.11`:
  `/tmp/screw-d02-expanded-refresh-priority-validation-v2` selected 7
  executable cases across XSS, CmdI, SQLi, and SSTI. Validation measured
  72 prompts, 3,134,010 prompt characters, and 9,402,030 retry-budgeted prompt
  characters at `--max-retries 3`. The report now includes a
  `Prompt Budget By Case` table so expensive slices are visible without ad hoc
  `jq` post-processing. The new Exponent CMS SQLi case alone costs 20 prompts,
  1,109,399 prompt characters, and 3,328,197 retry-budgeted prompt characters
  at three retries, so do not run it live until its budget is explicitly
  accepted or the packaging is narrowed.
- Controlled executor validation/execution now supports explicit
  `--max-files-per-variant` packaging for expensive exploratory slices. The
  default `0` preserves the extractor's normal cap. Use a non-zero value only
  for reviewed, case-filtered sampling runs where prompt budget matters more
  than full truth-file coverage. The first no-Claude cap-3 validation at
  `/tmp/screw-d02-morefixes-packaging-priority-cap3-validation` reduced the
  refreshed priority batch to 30 prompts and 4,494,636 retry-budgeted prompt
  characters at `--max-retries 3`. Exponent CMS alone dropped to 6 prompts and
  306,665 prompt characters with cap 3, and to 4 prompts and 247,637 prompt
  characters with cap 2 at
  `/tmp/screw-d02-morefixes-packaging-exponent-cap2-validation`.
- 2026-05-01 narrowed cross-agent live validation:
  `/tmp/screw-d02-cross-agent-noncmdi-cap3-run`, benchmark run
  `20260501-175446`, used XSS AntiSamy/Zope, SQLi NHibernate, and SSTI MLflow
  with cap 3 and one retry. It completed all 12 invocations with no failures,
  timeouts, or stale calls. Metrics were XSS AntiSamy TP 0 / FP 0 / TN 1 /
  FN 1, XSS Zope TP 1 / FP 0 / TN 1 / FN 0, SQLi NHibernate TP 0 / FP 0 /
  TN 25 / FN 25, and SSTI MLflow TP 1 / FP 0 / TN 2 / FN 1. The NHibernate
  result is packaging evidence, not SQLi YAML evidence: the initial
  `--max-files-per-variant` implementation truncated to low-signal
  test/support files before higher-signal production literal renderers.
- Controlled file caps now rank extracted files before truncation, preferring
  production-looking paths and higher matching truth-span counts while keeping
  deterministic original-order tie breaks. Focused no-Claude validation at
  `/tmp/screw-d02-nhibernate-ranked-cap3-validation-v3` now selects
  `Dialect`, `AbstractCharType`, and `AbstractStringType` for NHibernate cap 3.
  The updated cross-agent preflight at
  `/tmp/screw-d02-cross-agent-ranked-noncmdi-cap3-validation` remains at 12
  prompts and 663,520 prompt characters with no executor issues.
- 2026-05-02 live ranked-cap follow-up:
  `/tmp/screw-d02-cross-agent-ranked-noncmdi-cap3-run`, benchmark run
  `20260502-071201`, completed 12 of 12 invocations with no executor issues
  but still returned 0 NHibernate findings. Investigation found that the
  evaluator's live execution path still applied `max_files_per_variant` as a
  raw original-order slice, even though controlled validation and prompt
  estimates used the ranked cap. The ranked cap is now shared from
  `benchmarks.runner.code_extractor` and used by both controlled preflight and
  evaluator execution.
- Corrected focused NHibernate cap-5 execution at
  `/tmp/screw-d02-nhibernate-shared-ranked-cap5-run`, benchmark run
  `20260502-072639`, invoked the intended production files and completed all 10
  Claude calls with no failures, timeouts, or stale calls. Metrics returned to
  the accepted patched-clean shape: TP 2, FP 0, TN 25, FN 23, with vulnerable
  findings on `AbstractCharType.ObjectToSQLString` and
  `AbstractStringType.ObjectToSQLString`. Generated failure payload:
  `/tmp/screw-d02-nhibernate-shared-ranked-cap5-failure-inputs/sqli_failure_input.json`.
  Keep `sqli.yaml` unchanged.
- Repaired shared-cap cross-agent execution at
  `/tmp/screw-d02-cross-agent-shared-ranked-cap3-run`, benchmark run
  `20260502-074349`, completed all 12 invocations with no failures, timeouts,
  or stale calls. It restored SQLi/NHibernate to TP 2 / FP 0 / TN 25 / FN 23,
  kept XSS/Zope clean at TP 1 / FP 0 / TN 1 / FN 0, kept all patched finding
  counts at zero, and left AntiSamy as the known test-span miss. SSTI/MLflow
  missed in the mixed run, generating
  `/tmp/screw-d02-cross-agent-shared-ranked-cap3-failure-inputs/ssti_failure_input.json`,
  but the focused repeat at `/tmp/screw-d02-ssti-mlflow-repeat-run`, benchmark
  run `20260502-075355`, immediately restored TP 1 / FP 0 / TN 2 / FN 1 with
  the expected Jinja2 `from_string(...).render` finding and zero patched
  findings. Keep `ssti.yaml` unchanged unless broader SSTI sampling shows
  stable concrete misses.
- 2026-05-01 capped Exponent CMS live sampling run:
  `/tmp/screw-d02-morefixes-exponent-cap2-run`, benchmark run
  `20260501-091647`, used `--max-files-per-variant 2` and `--max-retries 1`.
  It produced 7 vulnerable findings and 0 patched findings, but both patched
  prompts failed JSON extraction in `invocation_progress.jsonl`, so the patched
  clean result is not precision evidence. The failure payload at
  `/tmp/screw-d02-morefixes-exponent-cap2-failure-inputs/sqli_failure_input.json`
  shows 5 missed spans, all with nearby same-file findings. Review found at
  least one real localization defect: the agent described the `activate_address`
  sink at line 172 but returned lines 158-159. The prompt now explicitly
  requires sink-expression line anchoring, and controlled executor reports warn
  when progress telemetry records failed or timed-out Claude calls.
- 2026-05-01 capped Exponent CMS localization rerun after sink-line anchoring:
  `/tmp/screw-d02-localization-exponent-cap2-run`, benchmark run
  `20260501-094144`, used the same cap-2, one-retry budget. The run recorded
  3 completed Claude invocations and 1 JSON-extraction failure, and the
  controlled executor report now surfaces that failed invocation as a warning.
  Metrics were TP 1, FP 9, TN 405, FN 409, with 4 vulnerable findings and
  8 patched findings. The rerun confirmed the concrete localization improvement
  for `addressController.php`: the `activate_address` finding now anchors on
  line 172 instead of nearby setup lines. Its failure payload at
  `/tmp/screw-d02-localization-exponent-cap2-failure-inputs/sqli_failure_input.json`
  still shows 5 missed spans, including 4 nearby same-file misses and 1 pure
  miss caused by the failed vulnerable `administrationController.php` prompt.
  Patched findings remain ambiguous because the patched sample appears to
  retain other raw SQL helper patterns, so this is not precision evidence and
  still does not justify a `sqli.yaml` mutation.
- Controlled Claude invocation parsing now handles common nested or fenced
  findings envelopes in `result`/`structured_output` instead of requiring a
  shallow array shape. When a live invocation fails after Claude returns, the
  invoker writes the full stdout/stderr to `invocation_failures/*.json` next
  to `invocation_progress.jsonl` and links the artifact from the failed
  progress event. Use those artifacts before deciding whether a future
  structured-output failure is parser noise, prompt drift, or a genuine model
  failure.
- Controlled Claude invocations now disable Claude Code tools with
  `--tools ""`. The Plexus related-context run at
  `/tmp/screw-d02-plexus-related-context-exec-run`, benchmark run
  `20260501-132018`, showed why: the vulnerable `Commandline.java` prompt
  previously failed after Claude attempted a `Bash` tool call and exhausted
  `--max-turns 1`. Benchmark calls should spend their single turn on producing
  structured findings, not on tool permission flow.
- The tool-disabled Plexus rerun at
  `/tmp/screw-d02-plexus-tools-disabled-rerun`, benchmark run
  `20260501-173750`, completed all 6 Claude invocations with no failures,
  timeouts, stale active calls, or failure artifacts. This verifies the
  `--tools ""` runtime fix. The run kept the patched side clean with
  0 patched findings, but scored TP 2, FP 2, TN 10, FN 8 from 4 vulnerable
  findings, so treat it as runtime validation and related-context
  patched-clean evidence, not as a new `cmdi.yaml` training signal.
- Exponent CMS fix-semantics review is recorded in the annotated payload at
  `/tmp/screw-d02-localization-exponent-cap2-fix-semantics-input.json` and
  validates against `phase4-autoresearch-failure-input/v1`. Review used the
  full 8 patched findings from
  `/tmp/screw-d02-localization-exponent-cap2-failure-inputs-full`. Two patched
  findings are **likely residual-risk / incomplete-fix evidence**:
  `addressController.php:87` still sends request-derived `user_id` into a raw
  `find()` WHERE fragment, and `administrationController.php:129` still passes
  request-selected table identifiers into `dropTable()` with only prefix
  stripping. Three patched findings are **fix-semantics ambiguous**:
  `administrationController.php:184`, `:211`, and `:221` depend on stored
  `sectionref`/container values and local snapshots do not prove whether the
  values are attacker-writable or sufficiently normalized before the repair
  workflow. The remaining patched findings at `addressController.php:146`,
  `:152`, and `administrationController.php:227` are weak/speculative because
  they depend on model IDs read back from the database or primary-key drift.
  Treat the Exponent slice as mixed benchmark/fix-semantics evidence, not as
  clean SQLi precision evidence.
- 2026-04-30 narrowed priority live run:
  `/tmp/screw-d02-priority-morefixes-thetis-run` executed one MoreFixes SQLi
  case (`morefixes-CVE-2015-2972-https_____github.com__sysphonic__thetis`) with
  `--max-retries 1`; result was TP 1, FP 9, TN 542, FN 546, vulnerable
  findings 6, patched findings 5; use the resulting payload for evidence
  review before considering any SQLi knowledge change
- 2026-05-02 next priority-stratified probe:
  `/tmp/screw-d02-next-priority-controlled` selected 8 executable cases after
  refreshing the broader plan. Full cap-3 validation at
  `/tmp/screw-d02-next-priority-cap3-validation` measured 36 prompts and about
  515k estimated tokens, so the whole batch remains too large for casual live
  execution. The narrowed Exponent CMS CVE-2016-7788 cap-2 live run at
  `/tmp/screw-d02-morefixes-exponent-7788-cap2-run`, benchmark run
  `20260502-081148`, completed 3 of 4 Claude invocations and timed out on
  vulnerable `eventController.php`. It also returned patched findings. Treat
  this as packaging/runtime/scoring evidence, not SQLi YAML evidence.
- Capped scoring is now file-scope aware. When `--max-files-per-variant` limits
  execution, evaluator metrics are computed only over truth files actually
  evaluated by the relevant vulnerable/patched variants, and failure-input
  missed examples exclude outside-cap truth spans. The regenerated Exponent
  CVE-2016-7788 payload at
  `/tmp/screw-d02-morefixes-exponent-7788-cap2-failure-inputs-cap-aware/sqli_failure_input.json`
  removes outside-cap `addressController.php` misses and leaves selected-file
  `ecomconfigController.php` misses plus selected patched findings.
- OSSF target-source extraction now supports local target-project clones under
  `benchmarks/external/ossf-cve-benchmark/repos/<owner>__<repo>` and reads the
  exact `prePatch.commit` / `postPatch.commit` refs from OSSF metadata.
  `benchmarks/scripts/materialize_ossf_targets.py` materializes selected target
  repos. Verified proof cases:
  `/tmp/screw-d02-ossf-fsgit-run`, benchmark `20260502-092046`, for
  CmdI/fs-git, and `/tmp/screw-d02-ossf-htmljanitor-run`, benchmark
  `20260502-092529`, for XSS/html-janitor. Both completed with no executor
  issues. Fs-git found the vulnerable shell `exec` chain but produced patched
  `CWE-88` argument-injection findings; html-janitor stayed patched-clean but
  missed the vulnerable `innerHTML` sink. Treat these as new concrete failure
  payloads, not aggregate YAML-mutation evidence. Manual review accepted the
  html-janitor example as reusable XSS sanitizer-design evidence and refined
  `xss.yaml` to v1.0.2: custom JavaScript sanitizers that parse
  caller-controlled HTML with active-document `innerHTML` before cleanup are
  reportable, while inert-document/template parsing is the patched
  discriminator. Manual review also accepted the fs-git patched findings as
  reusable CmdI argv precision evidence and refined `cmdi.yaml` to v1.0.2:
  after a patch moves from shell `exec` to non-shell `execFile("git", argv)`,
  CWE-88 requires a concrete dangerous option accepted at the user-controlled
  argument position. A fixed git subcommand with a ref/path operand is not
  enough by itself.
- Focused v1.0.2 CmdI/fs-git validation:
  `/tmp/screw-d02-ossf-fsgit-cmdi-v102-run`, benchmark `20260502-121340`,
  completed 2/2 invocations with no executor issues. It produced six
  vulnerable CWE-78 findings and zero patched findings. Failure-input
  generation produced no payloads because there were no concrete misses or
  patched false positives. The remaining unmatched vulnerable findings are
  scoring granularity against OSSF's single truth span, not patched precision
  noise.
- Focused v1.0.2 XSS/html-janitor validation:
  `/tmp/screw-d02-ossf-htmljanitor-xss-v102-run`, benchmark
  `20260502-093734`, completed 2/2 invocations with no executor issues. It
  produced one vulnerable finding and zero patched findings. The finding
  anchors the active-document `innerHTML` parse on `src/html-janitor.js:44`;
  OSSF truth anchors the CVE on adjacent `document.createElement('div')` line
  43, so metrics still report TP 0 / FN 1 even though the failure payload
  classifies the result as a nearby same-file finding rather than a pure miss.
- Cap-5 accepted-slice consolidation with OSSF:
  `/tmp/screw-d02-ossf-accepted-consolidation-cap5-run`, benchmark
  `20260502-122350`, completed 30/30 Claude invocations with no failed,
  timed-out, or stale calls. The reviewed OSSF fs-git/html-janitor cases were
  run with accepted Zope, Plexus, NHibernate, Rails, AntiSamy, and MLflow
  slices. All patched variants were clean with zero patched findings. Failure
  payloads at
  `/tmp/screw-d02-ossf-accepted-consolidation-cap5-failure-inputs` contain only
  vulnerable-side misses: known html-janitor adjacent-line scoring,
  related-finding Plexus spans, AntiSamy/Rails test/truth-span artifacts,
  patched-clean capped NHibernate misses, and a repeated mixed-run SSTI/MLflow
  miss. Review SSTI variance next before considering any `ssti.yaml` change.
- SSTI/MLflow variance review accepted `ssti.yaml` v1.0.1: public or
  plugin-facing APIs that accept template strings, store them in fields such as
  `self.template`, and later render them with non-sandboxed Jinja2
  `from_string(...).render(...)` are reportable even when visible in-file
  callers are hardcoded. The first focused trial at
  `/tmp/screw-d02-ssti-mlflow-public-template-v101-run`, benchmark
  `20260502-130038`, was rejected because it over-reported the patched
  `SandboxedEnvironment` path. The tightened rerun at
  `/tmp/screw-d02-ssti-mlflow-public-template-v101b-run`, benchmark
  `20260502-130521`, is accepted with TP 1 / FP 0 / TN 2 / FN 1, vulnerable
  findings 1, patched findings 0, and no generated failure-input payloads.
  Treat private/internal helpers with only compile-time constant template
  strings as safe, and treat `SandboxedEnvironment` as the patched
  discriminator unless there is a concrete sandbox bypass, unsafe globals,
  filters, tests, or a known vulnerable Jinja2 version.
- Post-v1.0.1 accepted-slice consolidation at
  `/tmp/screw-d02-ssti-v101-accepted-consolidation-cap5-run`, benchmark
  `20260502-152554`, reran the same eight accepted OSSF/non-OSSF cases with
  `--max-files-per-variant 5` and an explicit `--max-prompt-chars 1500000`
  budget. It completed 30/30 Claude invocations with no failed, timed-out, or
  stale calls. All patched variants stayed clean with zero patched findings.
  SSTI/MLflow now holds in mixed consolidation at TP 1 / FP 0 / TN 2 / FN 1,
  vulnerable findings 1 and patched findings 0; no SSTI failure-input payload
  was generated. Remaining generated payloads are CmdI/SQLi/XSS vulnerable-side
  diagnostics only, not new patched false-positive evidence.
- No-Claude SQLi review of the generated payload at
  `/tmp/screw-d02-ssti-v101-accepted-consolidation-cap5-failure-inputs/sqli_failure_input.json`
  closed the five pure misses as non-actionable for immediate YAML mutation.
  Rails' two remaining misses are `adapter_test.rb` truth spans, one with a
  missing excerpt, while the production `add_limit_offset!` LIMIT/OFFSET issue
  was detected and patched Rails stayed clean. NHibernate's three misses are
  mixed evidence: a fixed boolean literal helper, a typed parameter assignment
  span mislabeled by SARIF as `ObjectToSQLString`, and one sibling
  `CharBooleanType.ObjectToSQLString()` renderer under already-covered C# ORM
  literal guidance. Keep `sqli.yaml` v1.0.2 unchanged unless broader sampling
  shows a repeated unsafe literal-renderer miss without patched regressions.
- No-Claude CmdI review of the generated payload at
  `/tmp/screw-d02-ssti-v101-accepted-consolidation-cap5-failure-inputs/cmdi_failure_input.json`
  closed the five Plexus misses as non-actionable for immediate YAML mutation.
  The payload has no pure misses and no false-positive findings; all five
  missed truth spans have related findings, with three related-file credit
  candidates. The agent already found the root BourneShell quoting/preamble and
  `Runtime.exec` shell-wrapper sinks, while patched Plexus stayed clean. The
  remaining unmatched spans are broad helper/bridge locations around the same
  chain, so keep `cmdi.yaml` v1.0.2 unchanged and treat the residual as
  localization/scoring granularity before broader validation.
- Broader representative validation planning is refreshed on current `main`
  after the accepted SQLi/CmdI payload triages. Dry-run and controlled-plan
  artifacts are `/tmp/screw-d02-broader-representative-plan-v2` and
  `/tmp/screw-d02-broader-priority-controlled-v2`. The priority-stratified plan
  selects 9 executable cases across XSS, CmdI, SQLi, and SSTI. Full cap-5
  executor preflight at `/tmp/screw-d02-broader-priority-cap5-preflight-v2`
  measures 46 prompts, 2,275,045 prompt characters, and about 568,780 estimated
  tokens; it should not be the first live run.
- Execute broader validation in waves. Wave A: run only
  `morefixes-CVE-2015-2972-https_____github.com__sysphonic__thetis` with
  `--max-files-per-variant 3`; preflight
  `/tmp/screw-d02-broader-priority-thetis-cap3-preflight-v2` is 6 prompts,
  211,938 prompt characters, and fits the default prompt guard. Wave B: run
  `morefixes-CVE-2016-7781-https_____github.com__exponentcms__exponent-cms`
  only after explicit budget acceptance; cap-2 preflight
  `/tmp/screw-d02-broader-priority-exponent7781-cap2-preflight-v2` is 4
  prompts and 317,317 prompt characters, above the default guard, and includes
  large `eventController.php` prompts. Wave C: only after Wave A/B payloads are
  classified, consider the full 9-case cap-5 broader plan as a representative
  regression/sampling run, not full-corpus evidence.
- require explicit `--allow-claude-invocation` before a plan can become
  executable
- require a second executor-level `--allow-claude-invocation` with `--execute`
  before the executor can invoke Claude
- live executor runs write `invocation_progress.jsonl` in the executor output
  directory; use `benchmarks/scripts/show_invocation_progress.py` to distinguish
  active Claude calls from stale calls that have exceeded their timeout plus
  grace period
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
- The controlled plan now records targeted `related_context_case_ids` for CmdI
  multi-file selections, and the executor can pass those case IDs into the
  evaluator without enabling related context globally. This makes mixed
  consolidation apply related context to Plexus while leaving AntiSamy, Zope,
  NHibernate, and Rails on their existing prompt shape.
- The controlled executor now reports per-prompt character/token estimates and
  a retry-adjusted prompt budget before any Claude call. A no-Claude validation
  of the current five-slice non-OSSF plan at
  `/tmp/screw-d02-prompt-budget-validation` measured 34 actual per-file
  prompts, 1,427,680 prompt characters, and about 1,070,805 retry-budgeted
  estimated tokens at `--max-retries 3`. Future live runs should be narrowed
  or explicitly budget-approved before raising or disabling the default
  `--max-prompt-chars 250000` guard.
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
  is a sanitizer unit-test span, and the Zope miss needed manual review because
  its truth span is a framework namespace/evaluation helper rather than a
  direct HTML-output sink. That Zope review is now accepted as a narrow
  CVE-2009-5145 PageTemplates taint-preservation pattern: vulnerable code
  pushes raw `request` into `TemplateDict`/`RestrictedDTML`, while patched code
  applies `request.taintWrapper()` first.
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
- A filtered non-OSSF consolidation execution is verified at
  `/tmp/screw-d02-nonossf-consolidation-run`, benchmark run
  `20260429-182422`. It ran the five currently executable non-OSSF slices
  after OSSF source extraction was blocked: AntiSamy/XSS, Zope/XSS,
  Plexus/CmdI, NHibernate/SQLi, and MoreFixes Rails/SQLi. No executor issues
  were reported. Zope remained fully detected and patched-clean; NHibernate
  preserved the accepted low-recall/high-precision v1.0.1 behavior; AntiSamy
  remained a test-file truth-span miss. Plexus produced a patched `Shell.java`
  finding when run without related context, reinforcing that the Plexus slice
  should use `--include-related-context` before evaluating further CmdI
  changes. MoreFixes Rails produced patched `add_lock!` and `insert_fixture`
  findings in the consolidation run even though the earlier focused Rails run
  kept patched files clean. Treat this as a concrete SQLi precision and
  repeatability review item, not as an automatic YAML mutation trigger.
- Consolidation failure payloads were generated under
  `/tmp/screw-d02-nonossf-consolidation-failure-inputs`. They keep
  `yaml_mutation_allowed=false` and are the next evidence set to review before
  changing any agent YAML.
- After the accepted Rails SQLi v1.0.2 precision refinement, a second filtered
  non-OSSF consolidation execution is verified at
  `/tmp/screw-d02-nonossf-consolidation-v102-run`, benchmark run
  `20260430-055646`. SQLi/Rails stayed fixed in the mixed run with TP 1, FP 0,
  TN 5, FN 4, one vulnerable `add_limit_offset!` finding, and zero patched
  findings. SQLi/NHibernate remained patched-clean with TP 2, FP 0, TN 25,
  FN 23. XSS/Zope remained clean and AntiSamy remained the known test-file
  truth-span miss. CmdI/Plexus produced three patched `Shell.java` findings
  without related context, so the next D-02 slice should make multi-file
  evidence packaging available in consolidation runs before considering any
  further `cmdi.yaml` mutation.
- Updated consolidation failure payloads were generated under
  `/tmp/screw-d02-nonossf-consolidation-v102-failure-inputs`.
- CmdI/Plexus related-context packaging is now wired into controlled
  consolidation. Validation-only report
  `/tmp/screw-d02-plexus-related-context-nonossf-validation` shows global
  related context off with only `rc-java-plexus-utils-CVE-2017-1000487` marked
  for related context. Focused Plexus execution
  `/tmp/screw-d02-plexus-related-context-plexus-run`, benchmark run
  `20260430-063651`, produced 1 vulnerable finding and 0 patched findings with
  no executor issues, though one Claude response failed JSON extraction. Mixed
  non-OSSF execution
  `/tmp/screw-d02-plexus-related-context-nonossf-run`, benchmark run
  `20260430-064528`, produced 6 Plexus vulnerable findings and 0 patched
  findings while keeping related context scoped to Plexus. That mixed run had
  Claude runtime/output failures and a Rails vulnerable-side FP despite
  unchanged Rails packaging, so it proves the consolidation wiring but should
  not be used as clean YAML-training evidence.
- A cleaner mixed non-OSSF stability rerun at
  `/tmp/screw-d02-plexus-related-context-nonossf-rerun`, benchmark run
  `20260430-075117`, emitted no executor issues or Claude retry/output
  failures. Plexus remained patched-clean with TP 3, FP 0, TN 10, FN 7 and raw
  counts of 3 vulnerable findings, 0 patched findings. Rails returned to the
  accepted v1.0.2 shape: TP 1, FP 0, TN 5, FN 4, with one vulnerable
  `add_limit_offset!` finding and zero patched findings. Cleaner-run failure
  payloads are under
  `/tmp/screw-d02-plexus-related-context-nonossf-rerun-failure-inputs`; use
  those payloads, not the noisy previous mixed run, for any follow-on review.
- Focused Plexus related-context validation on 2026-05-01 at
  `/tmp/screw-d02-plexus-related-context-validation` confirmed the current
  non-OSSF plan still marks only
  `rc-java-plexus-utils-CVE-2017-1000487` for related context. The live run at
  `/tmp/screw-d02-plexus-related-context-exec-run`, benchmark run
  `20260501-132018`, used `--max-retries 1` and an explicit
  `--max-prompt-chars 350000` budget. It produced 3 vulnerable findings and
  0 patched findings, with metrics TP 3, FP 0, TN 10, FN 7. The run had
  1 failed vulnerable invocation and 1 vulnerable timeout, so treat it as
  additional packaging/runtime evidence, not a cleaner replacement for the
  2026-04-30 stability rerun.
- Tool-disabled focused Plexus rerun
  `/tmp/screw-d02-plexus-tools-disabled-rerun`, benchmark run
  `20260501-173750`, removed that runtime noise: progress telemetry recorded
  6 completed invocations, 0 failed, 0 timed out, and 0 stale. It kept
  patched findings at 0. Metrics were TP 2, FP 2, TN 10, FN 8, with 4
  vulnerable findings, so use this run to validate invocation behavior and
  patched cleanliness, not to tune CmdI YAML from aggregate scoring.
- Review of the clean CmdI/Plexus payload found no current `cmdi.yaml`
  mutation target. The three clean-run vulnerable findings correctly localize
  the real Bourne-shell quoting defect in `BourneShell.java`, and patched
  findings remain zero after 3.0.16 switches to single-quote-style
  `quoteOneItem()`. The missed `Shell.java` spans are broad base-class or
  delegation spans, `Commandline.getCommandline()` is a benchmark
  localization/scoring artifact rather than the shell quoting change, and
  `Commandline.verifyShellState()` is a plausible bridge-localization gap but
  not enough to justify another prompt change after the rejected over-reporting
  trial. Keep `cmdi.yaml` at v1.0.1; the next useful engineering work is
  scoring/failure-analysis support for related-file call-chain credit and
  bridge-span classification.
- Failure payload generation now records `related_file_same_case` findings for
  related-context cases. Regenerated payloads under
  `/tmp/screw-d02-plexus-related-file-diagnostics-failure-inputs` classify all
  five CmdI/Plexus misses as related-file misses, not pure misses, because each
  missed `Shell.java`/`Commandline.java` truth span cites the clean-run
  `BourneShell.java` findings. SQLi and XSS diagnostics remain unchanged
  because those cases did not run with related context.
- Failure payload diagnostics now also expose related-file scoring credit
  separately from strict truth-span scoring. Regenerated payloads under
  `/tmp/screw-d02-plexus-related-file-scoring-failure-inputs` keep CmdI/Plexus
  at 5 exact-span false negatives, but mark all 5 as
  `related_file_credit_candidates`, leaving 0 false negatives after
  related-file credit. This is diagnostic credit only; it does not rewrite the
  benchmark's exact span TP/FN metrics.
- No-Claude triage of those regenerated payloads found no further YAML-training
  target in the current capped examples. AntiSamy remains a test-file
  truth-span miss; Plexus is covered by related-file credit; and NHibernate's
  remaining capped examples are mostly test/helper/typed-parameter or sibling
  renderer spans that do not justify broadening `sqli.yaml` from this evidence
  alone. The next D-02 step should be expanded stratified validation over
  trustworthy executable cases, with prompt-budget review first.
- The controlled planner now supports `expanded-stratified` selection for that
  next step. The first no-Claude expanded plan at
  `/tmp/screw-d02-expanded-stratified-controlled` selected 7 executable cases:
  one each for the active reality-check slices plus 3 MoreFixes SQLi cases.
  Full expanded validation measured about 1,229,199 retry-budgeted estimated
  tokens, while the focused three-case MoreFixes SQLi subset measured about
  243,090. Do not run either live without explicit prompt-budget acceptance;
  if approved, start with the MoreFixes subset.
- The focused three-case MoreFixes SQLi subset was then run live at
  `/tmp/screw-d02-expanded-stratified-morefixes-run`, benchmark run
  `20260430-125213`, with `ANTHROPIC_API_KEY` unset and an explicitly raised
  `--max-prompt-chars 1000000` guard. Rails stayed patched-clean, but the two
  new cases produced patched findings: `gesellix/titlelink` reported 2
  vulnerable and 2 patched findings, and `lierdakil/click-reminder` reported 3
  vulnerable and 4 patched findings. The payload at
  `/tmp/screw-d02-expanded-stratified-morefixes-failure-inputs/sqli_failure_input.json`
  needs human fix-semantics review before any SQLi YAML change because the
  patched snapshots may still contain residual-risk patterns or incomplete
  benchmark fixes.
- Fix-semantics review classified those two new cases as unsuitable for SQLi
  YAML tuning right now. `gesellix/titlelink` is ambiguous because local
  snapshots do not include the Joomla database API needed to prove
  `$database->quote(..., false)` semantics. `lierdakil/click-reminder` is
  likely an incomplete fix or residual-risk case because the patched code still
  interpolates `$this->sid` into SQL after HTML-context escaping and a generic
  semicolon blacklist. Keep `sqli.yaml` unchanged and treat both cases as
  benchmark/fix-semantics review items.
- Failure payloads can now encode that review outcome with
  `fix_semantics_ambiguous` and `residual_risk_or_incomplete_fix` evidence
  flags. The annotated payload at
  `/tmp/screw-d02-expanded-stratified-morefixes-fix-semantics-input.json`
  reports 2 ambiguous patched findings and 3 residual-risk/incomplete-fix
  patched findings.
- SSTI real-CVE validation resumed through MoreFixes `G5.11`. The focused
  MLflow `CVE-2023-6709` run at
  `/tmp/screw-d02-ssti-morefixes-mlflow-run`, benchmark run
  `20260501-084946`, completed both Claude invocations with no failures,
  timeouts, or stale active calls. Metrics were TP 1, FP 0, TN 2, FN 1; the
  agent reported the vulnerable Jinja2 `Environment(...).from_string(...).render`
  sink and produced zero patched findings. The failure-input generator produced
  no concrete payloads, so treat the residual FN as duplicate/strict truth-span
  scoring noise unless a later broader SSTI run produces actionable examples.
- The next refreshed priority batch is planned but not live-executed:
  `/tmp/screw-d02-expanded-refresh-priority-controlled` and
  `/tmp/screw-d02-expanded-refresh-priority-validation-v2`. It confirms the
  first broader four-agent candidate set now includes SSTI, but also shows that
  large MoreFixes SQLi cases can dominate cost. Use the per-case prompt-budget
  table to pick narrow live runs; do not execute the full refreshed priority
  batch under the default budget.
- For high-cost MoreFixes cases, prefer a case-filtered validation with an
  explicit `--max-files-per-variant` cap before any live invocation. Treat
  capped results as representative sampling evidence, not full-case benchmark
  metrics. Capped scoring is now internally file-scope consistent, but it is
  still not equivalent to uncapped gate coverage.
- Do not mutate `sqli.yaml` from the capped Exponent CMS runs. Sink-line
  anchoring fixed one concrete localization defect. Structured-output failures
  now leave raw artifacts for review, and cap-aware scoring avoids charging the
  agent for files it never saw. The latest Exponent runs remain blocked by
  failed/timed-out invocations and mixed patched-source fix-semantics outcomes
  rather than reusable SQLi knowledge evidence.
- OSSF is no longer categorically blocked once target repos are materialized
  locally. Use `materialize_ossf_targets.py --case-id <ossf-CVE-...>` for
  narrow slices, validate first, then run live only within an explicit prompt
  budget. Review `/tmp/screw-d02-ossf-fsgit-failure-inputs` and
  `/tmp/screw-d02-ossf-htmljanitor-failure-inputs` before changing CmdI or XSS
  YAML.

Focused rerun example:

```bash
uv run python benchmarks/scripts/run_controlled_autoresearch.py \
  --controlled-plan <controlled_run_plan.json> \
  --output-dir <focused-output-dir> \
  --agent cmdi \
  --case-id rc-java-plexus-utils-CVE-2017-1000487 \
  --execute \
  --allow-claude-invocation
```
