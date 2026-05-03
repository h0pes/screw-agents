# Phase 4 Wave C Decision Ledger

> Status: Wave C live cap-5 results classified for next action.
> Last updated: 2026-05-03.

Wave C was not a clean pass/fail gate. It was a broader representative
validation probe after Wave A/B calibration. The purpose of this ledger is to
prevent repeated benchmark anecdotes from looking like unbounded churn.

Artifacts:

- Live run: `/tmp/screw-d02-broader-wave-c-cap5-run`
- Benchmark run: `20260503-075922`
- Executor report:
  `/tmp/screw-d02-broader-wave-c-cap5-run/controlled_executor_report.md`
- Failure payloads:
  `/tmp/screw-d02-broader-wave-c-cap5-failure-inputs`

Budget:

- 9 cases
- 46 prompts
- 2,341,159 prompt characters
- about 585,307 estimated tokens
- explicit accepted guard: 2,500,000 prompt characters

## Case Ledger

| Case | Agent | Wave C Counts | Regression? | Classification | Next Action |
|---|---|---:|---|---|---|
| `ossf-CVE-2017-0931` | XSS | 1 vulnerable / 0 patched | No | Accepted signal. OSSF source materialization is sufficient for this slice. | Keep `xss.yaml` unchanged. |
| `rc-csharp-antisamy-dotnet-CVE-2023-51652` | XSS | 0 / 0 | No | Known test-file/truth-span limitation. Failure payload flags `test_file_path`. | Keep as dataset/scoring noise unless future non-test AntiSamy evidence appears. |
| `rc-python-Zope-CVE-2009-5145` | XSS | 1 / 0 | No | Accepted signal preserved. | Keep `xss.yaml` unchanged. |
| `ossf-CVE-2017-16087` | CmdI | 5 / 0 | No | Positive vulnerable signal and patched-clean. Aggregate FP metrics are truth-span/scoring granularity noise from multiple findings. | Keep `cmdi.yaml` unchanged. |
| `rc-java-plexus-utils-CVE-2017-1000487` | CmdI | 7 / 0 | No | Patched-clean. Remaining misses are same-file/related-file call-chain granularity, not a clear agent knowledge regression. | Keep `cmdi.yaml` unchanged; improve scoring only if Phase 4 needs cleaner metrics. |
| `rc-csharp-nhibernate-core-CVE-2024-39677` | SQLi | 2 / 0 | No domain regression | Patched-clean. One vulnerable `Dialect.cs` invocation failed because Claude attempted `LSP.workspaceSymbol` and hit `error_max_turns`; other misses are mixed truth-span granularity and low-value selected spans. | Track as executor/tool-permission guardrail work, not `sqli.yaml` evidence. |
| `morefixes-CVE-2015-2972-https_____github.com__sysphonic__thetis` | SQLi | 5 / 2 | Expanded-slice issue, not focused-run regression | Earlier helper-context focused slice stayed 1 / 0. Wave C cap-5 included more files and exposed two patched findings. Both sampled patched findings are residual/raw-fragment risks still present in the patched snapshot. | Classify as `residual_risk_or_incomplete_fix`; do not mutate `sqli.yaml` from this alone. |
| `morefixes-CVE-2016-7781-https_____github.com__exponentcms__exponent-cms` | SQLi | 25 / 25 | No new regression | Wave B already showed symmetric vulnerable/patched findings. Wave C amplified the same fix-semantics and line-anchor behavior across more files. Sampled patched findings are line-anchor drift; many unsampled findings look like raw SQL patterns still present in patched code. | Do not mutate `sqli.yaml` until a reviewed payload proves prompt overbreadth rather than residual risk or line-anchor drift. |
| `morefixes-CVE-2023-6709-https_____github.com__mlflow__mlflow` | SSTI | 1 / 0 | No | Accepted SSTI signal preserved. No SSTI failure payload generated. | Keep `ssti.yaml` unchanged. |

## SQLi Payload Review

Generated payload:

- `/tmp/screw-d02-broader-wave-c-cap5-failure-inputs/sqli_failure_input.json`

Sampled patched findings:

| Case | File:Lines | Review Classification | Reason |
|---|---|---|---|
| Thetis | `email.rb:766-767` | `residual_risk_or_incomplete_fix` | The patched file still appends caller-supplied `add_con` as a raw SQL fragment before `Email.where(con)`. |
| Thetis | `application_controller.rb:128` | `residual_risk_or_incomplete_fix` | The wrapper still interpolates opaque SQL into `count_by_sql`; this is a raw-SQL escape hatch independent of the helper-context fix. |
| Exponent CMS | `eventController.php:514` | `line_anchor_drift` | The message names `delete_recurring()` and a concrete `find('first', 'id=' . $this->params['id'])` sink, but the returned span lands on the earlier `show()` comment block. |
| Exponent CMS | `eventController.php:530` | `line_anchor_drift` | The message names `delete_selected()` and a concrete request-parameter sink, but the returned span lands in unrelated template assignment code. |
| Exponent CMS | `eventController.php:660` | `line_anchor_drift` | The message names `ical()` and `$this->params['date_id']`, but the returned span lands on `build_daterange_sql()`. |

Sampled SQLi misses:

| Case | File:Lines | Review Classification | Reason |
|---|---|---|---|
| NHibernate | `Dialect.cs:1360-1363` | Executor failure / low-value selected span | The vulnerable prompt failed before a result because Claude attempted an LSP tool call and hit max turns. The selected truth span is boolean literal rendering, not the strongest SQLi evidence. |
| NHibernate | `AbstractStringType.cs:137-140` | Truth-span granularity | The agent found the same vulnerable renderer nearby at line 119, but did not match the exact selected truth span. |
| NHibernate | `ByteType.cs:54-58` | Dataset/truth-span review needed | The selected span is parameter binding/conversion code, not a clear SQLi literal-rendering sink. Do not tune SQLi prompt against this without truth review. |
| NHibernate | `CharBooleanType.cs:58-61` | Possible concrete miss | This is a literal renderer returning a quoted value. It may be the only sampled NHibernate miss worth future focused review, but it is not enough to mutate `sqli.yaml` by itself. |
| Thetis | `email.rb:620-651` | Broad truth-span granularity | The agent found nearby same-file SQLi patterns in `email.rb`; the selected truth span covers a broader method body. |

## Decision

Wave C does not justify immediate domain YAML mutation.

Accepted preserved signals:

- XSS html-janitor
- XSS Zope
- CmdI fs-git patched-clean
- CmdI Plexus patched-clean
- SSTI MLflow

Known non-regression noise:

- XSS AntiSamy test-file truth span
- CmdI Plexus related-file/same-file scoring granularity
- NHibernate `Dialect.cs` Claude LSP/max-turn executor failure
- Exponent CMS fix-semantics and line-anchor drift

Only possible future domain-review item:

- NHibernate `CharBooleanType.ObjectToSQLString`, but only after a focused
  review confirms it is not already covered by existing SQLi literal-renderer
  guidance and is not benchmark truth noise.

## Next Actions

1. Controlled-executor tool-use guardrail is implemented and validated. PR #88
   added prompt instructions forbidding LSP/language-server/workspace/filesystem
   tool use during one-turn benchmark invocations. Focused NHibernate validation
   at `/tmp/screw-d02-nhibernate-dialect-tool-guard-run`, benchmark
   `20260503-105134`, completed all 10 prompts with no executor issues. The
   previously failed vulnerable `Dialect.cs` prompt completed in about 62s with
   zero findings instead of attempting LSP; patched findings stayed at 0. The
   generated payload at
   `/tmp/screw-d02-nhibernate-dialect-tool-guard-failure-inputs/sqli_failure_input.json`
   now contains only 3 vulnerable misses and no patched findings.
2. If Phase 4 needs cleaner SQLi metrics, create a reviewed Wave C SQLi payload
   with evidence flags:
   - Thetis patched examples:
     `residual_risk_or_incomplete_fix`
   - Exponent sampled patched examples:
     `line_anchor_drift`
3. Use `docs/PHASE_4_CLOSURE_READINESS.md` as the current closure checklist.
   Do not run another broad Wave C-style validation unless a concrete new
   hypothesis cannot be answered from the existing artifacts.
