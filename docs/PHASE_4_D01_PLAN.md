# Phase 4 Step 4.0 — D-01 Rust Benchmark Corpus Plan

> Status: draft execution plan, created at Phase 4 kickoff.
> Scope: Rust corpus construction before the autoresearch loop mutates agent
> YAML.

## Goal

Build a Rust benchmark corpus that can be consumed by the existing
CWE-1400-native benchmark runner without overstating Rust detection quality.

D-01 exists because Phase 0.5 deliberately deferred Rust validation: the four
initial injection agents had too few verified Rust CVEs, and RustSec category
labels were not reliable enough to use directly. Phase 4 must start by
refreshing the advisory inventory, reviewing candidates, and only then
materializing fixtures.

## Ground Rules

- GitHub Advisory Database CWE data is authoritative over RustSec category
  labels.
- RustSec `format-injection` is not a CWE. It must never map directly to SQLi,
  XSS, CmdI, or SSTI without GHSA/manual confirmation.
- Known CWE-77 data-race/soundness mislabels must be excluded from CmdI.
- Advisories already cited in agent YAML may be useful regression/training
  examples, but they are not clean holdout validation data.
- Rust SSTI has no verified real-CVE corpus in the current research; synthetic
  fixtures must be clearly labelled as synthetic.

## Task Breakdown

### Task 1 — Advisory Refresh And Candidate Manifest

Create a reproducible script that queries GitHub Advisory Database for Rust
advisories matching the D-01 CWE set:

- `CWE-77`
- `CWE-78`
- `CWE-79`
- `CWE-89`
- `CWE-94`
- `CWE-116`
- `CWE-1336`

The script writes `benchmarks/external/rust-advisory-candidates/rust_advisories.json`.
That file is generated benchmark input and stays untracked. The script itself
and its tests are tracked.

Acceptance:
- Deduplicates advisories returned by multiple CWE queries.
- Preserves `queried_cwes` and GHSA `cwes` separately.
- Marks known CWE-77 data-race mislabels as `exclude`.
- Marks known non-SSTI GHSA hits as `exclude`.
- Marks advisories referenced in existing YAML as training-contaminated.
- Has unit tests with mocked advisory payloads; no test reaches the network.

### Task 2 — Candidate Review Policy

Turn the generated candidate manifest into a reviewed D-01 candidate list.

Acceptance:
- Every candidate has one of: `include_real_cve`, `exclude`, `training_only`,
  `needs_manual_code_trace`.
- Every exclusion has a reason.
- Every included real-CVE candidate has CWE, repo, fix reference, vulnerable
  reference, affected file/function, and source URLs.

### Task 3 — Fixture Materialization

Materialize accepted real-CVE Rust cases under the benchmark external tree and
write bentoo-SARIF truth files.

Acceptance:
- Cases use the existing `BenchmarkCase` / `Finding` / SARIF schema.
- Vulnerable and patched code are pair-based.
- Method/function-level ground truth is present when the advisory supports it.
- Fixture provenance records advisory IDs, repo URL, vulnerable ref, patched
  ref, and extraction notes.

### Task 4 — Synthetic Rust SSTI Fixtures

Build labelled synthetic fixtures for Tera, MiniJinja, Askama, and
Handlebars-rust misuse patterns.

Acceptance:
- Synthetic fixtures are never represented as real CVEs.
- Fixture metadata states the template engine, misuse pattern, and why the
  pattern maps to CWE-1336.
- Safe counterparts are included for false-positive pressure.

### Task 5 — Runner Integration And Docs

Integrate the Rust corpus into the benchmark runner and update durable docs.

Acceptance:
- The corpus appears in benchmark listing/manifest flows.
- Tests validate manifest and SARIF parsing.
- `docs/PROJECT_STATUS.md`, `docs/DEFERRED_BACKLOG.md`, and this plan agree on
  D-01 status.
- Rust metric claims are explicitly scoped: real-CVE for SQLi/CmdI/XSS where
  available; synthetic-only for SSTI unless a real advisory appears during
  refresh.
