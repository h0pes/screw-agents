# Benchmarks — screw-agents

Evaluation infrastructure for measuring agent detection quality (TPR, FPR, accuracy).

## Structure

- `fixtures/` — Small self-contained test cases (committed). Vulnerable and safe code snippets per vulnerability type.
- `suites/` — Downloaded benchmark suites (gitignored). Fetched by `bootstrap.sh`.
- `scoring/` — TPR/FPR calculation and report generation.

## Benchmark Suites

| Suite | Languages | Role |
|---|---|---|
| [flawgarden/reality-check](https://github.com/flawgarden/reality-check) | Java, C#, Go, Python | Primary — real-world CVEs |
| [flawgarden/BenchmarkJava-mutated](https://github.com/flawgarden/BenchmarkJava-mutated) | Java | Supplementary |

## Usage

```bash
# Download benchmark suites
./bootstrap.sh

# Run agent evaluation (Phase 5+)
# TODO: scoring tooling
```
