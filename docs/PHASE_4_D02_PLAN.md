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
