# benchmarks/fixtures — Smoke-Test Fixtures

These files are **smoke-test fixtures**, not validation datasets.

## Purpose

Each fixture verifies a specific piece of the screw-agents infrastructure:

- MCP server plumbing (tool registration, request routing)
- tree-sitter loading and AST parsing
- Agent YAML resolution and pattern matching

They are **not** used for detection-accuracy benchmarking and are **not**
part of any Phase 1 validation gate.

## Rust Fixtures

Pre-Phase-4 `rust_*.rs` files in `*/vulnerable/` and `*/safe/` subdirectories
carry a smoke-test provenance header:

```rust
// --- screw-agents smoke-test fixture (not for detection benchmarking) ---
// Per ADR-014 (docs/DECISIONS.md), Rust benchmark corpus is DEFERRED to Phase 4.
// This file verifies MCP plumbing + tree-sitter loading + agent-YAML resolution.
// Detection accuracy against this file is NOT part of any Phase 1 validation gate.
// Phase 4 corpus seed: docs/research/benchmark-tier4-rust-modern.md
// -----------------------------------------------------------------------
```

Per **ADR-014** (`docs/DECISIONS.md`), the Rust benchmark corpus is deferred to
Phase 4. The Phase 4 corpus seed is documented at
`docs/research/benchmark-tier4-rust-modern.md`.

Phase 4 D-01 adds explicit synthetic Rust SSTI fixtures. These use a
`synthetic Rust SSTI fixture` provenance header and are inventoried in
`benchmarks/data/rust-d01-synthetic-ssti.json`. They are not real CVEs and must
not be reported as CVE-backed validation.

See also **ADR-013** for the overall benchmark methodology and the Phase 4 gate
defined in PRD §12.

## Structure

```
fixtures/
├── cmdi/
│   ├── safe/      — true-negative fixtures (must NOT be flagged)
│   └── vulnerable/ — true-positive fixtures (MUST be flagged)
├── sqli/
│   ├── safe/
│   └── vulnerable/
├── ssti/
│   ├── safe/
│   └── vulnerable/
└── xss/
    ├── safe/
    └── vulnerable/
```

Each fixture file has a comment header identifying: the expected result
(TRUE POSITIVE / TRUE NEGATIVE), the CWE, the agent name, and the specific
pattern being exercised.
