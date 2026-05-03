# Phase 4 Closure Readiness

> Status: closure-ready pending final Phase 4 signoff.
> Last updated: 2026-05-03.

Phase 4 D-02 is a calibration loop, not an obligation to manually tune every
benchmark CVE. Closure requires enough evidence to show that the benchmark
workflow can separate agent-knowledge gaps from dataset, scoring, prompt,
source-packaging, and runtime issues.

This document is the current closure checklist. It should be updated when a
new representative run, reviewed payload, or machinery fix changes the closure
decision.

## Closure Criteria

| Criterion | Status | Evidence | Remaining Work |
|---|---|---|---|
| Active dataset readiness is explicit | Met for current main checkout | D-02 readiness and materialization work restored active G5 datasets locally; OSSF target-source materialization works case-by-case. | Keep generated benchmark material ignored and rerun readiness before future live execution. |
| Source extraction refuses low-quality fallbacks | Met | OSSF source-quality runs are blocked unless target vulnerable/patched source snapshots are materialized; local OSSF target clones are now supported. | Materialize additional OSSF targets only as needed for future sampled validation. |
| Controlled executor has budget guardrails | Met | Preflight prompt-budget estimates, per-case budget tables, and `--max-prompt-chars` prevent accidental broad live runs. Wave C required explicit 2.5M prompt-character acceptance. | Keep broad live runs gated by explicit budget acceptance. |
| Controlled executor has packaging guardrails | Met | `--max-files-per-variant`, ranked file caps, helper-context packaging, and cap-aware scoring are implemented and validated. | Treat capped runs as sampling evidence, not full-case gate metrics. |
| Runtime failures produce reviewable artifacts | Met | Invocation progress logs, failure artifacts, structured-output robustness, disabled Claude tools, and prompt-level tool-use guardrails are implemented. | Reclassify any future failed invocation from artifacts before changing YAML. |
| Failure payloads support reviewed classifications | Met | `phase4-autoresearch-failure-input/v1` supports mutation-disabled examples and evidence flags for fix-semantics ambiguity, residual risk, and line-anchor drift. | Use reviewed payloads for future YAML decisions; do not mutate from aggregate metrics. |
| Accepted agent slices are preserved | Met for current accepted set | SQLi Rails/NHibernate/Thetis focused signals, CmdI fs-git/Plexus patched-clean signals, XSS html-janitor/Zope signals, and SSTI MLflow signal are recorded. | Preserve these as regression probes for future representative runs. |
| Broader representative validation completed | Met | Wave C cap-5 run covered 9 cases across XSS, CmdI, SQLi, and SSTI under explicit budget; `docs/PHASE_4_WAVE_C_LEDGER.md` classifies the result. | Do not repeat broad Wave C-style validation until a concrete new hypothesis exists. |
| Wave C runtime failure is addressed | Met | PR #88 added prompt-level tool-use prohibition; focused NHibernate rerun completed 10/10 prompts with no executor issues and 0 patched findings. | Watch for recurrence only. |
| Wave C SQLi patched findings are interpreted | Met | The Wave C ledger classifies sampled Thetis patched findings as residual raw-fragment risk and sampled Exponent findings as line-anchor drift. The optional machine-readable SQLi annotation is intentionally skipped for closure because the Markdown ledger is sufficient for the current decision. | Revisit only if future automation needs these classifications outside the ledger. |
| Domain YAML mutation decision is explicit | Met | Wave C and focused reruns do not justify immediate changes to `sqli.yaml`, `cmdi.yaml`, `xss.yaml`, or `ssti.yaml`. | Only revisit YAML after a reviewed payload exposes reusable domain-level knowledge. |

## Accepted Inclusions

These slices are accepted as active Phase 4 calibration evidence:

- XSS: OSSF html-janitor and Reality Check Zope.
- CmdI: OSSF fs-git and Reality Check Plexus.
- SQLi: Reality Check NHibernate, MoreFixes Rails, MoreFixes Thetis, and
  sampled Exponent CMS only as fix-semantics/line-anchor calibration evidence.
- SSTI: MoreFixes MLflow.

## Known Exclusions And Noise

These items should not block D-02 closure unless new evidence changes their
classification:

- AntiSamy: current miss is tied to test-file/truth-span limitations.
- Plexus: remaining misses are related-file or same-file call-chain scoring
  granularity after patched-clean validation.
- NHibernate: remaining exact-span misses include low-value truth spans and
  possible truth-span granularity; the Wave C `Dialect.cs` runtime failure is
  mitigated by the tool-use guardrail.
- Exponent CMS: patched findings mix line-anchor drift, raw SQL patterns still
  present in patched snapshots, and fix-semantics ambiguity.
- MoreFixes patched labels: some patched snapshots retain residual raw SQL
  helper patterns, so patched findings require fix-semantics review before
  they can be treated as prompt false positives.
- Rust SSTI: synthetic-only until a verified real advisory is found.

## Remaining Closure Path

Phase 4 can move toward closure without another broad live benchmark run.

1. Skip the optional machine-readable Wave C SQLi annotated payload for final
   closure. The Wave C ledger already records the Thetis/Exponent
   classifications in enough detail for the current closure decision.
2. Preserve Wave C and the accepted focused reruns as the regression baseline
   for the next phase.

Do not start Wave C again, Wave D, or a full executable corpus run unless there
is a concrete hypothesis that cannot be answered from the existing artifacts.
