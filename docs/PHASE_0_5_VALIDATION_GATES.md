# Phase 0.5 → Phase 1 Validation Gates

> Authoritative acceptance criteria for Phase 1.7 (benchmark validation run).
> Phase 1 cannot close until all gates below are satisfied OR explicitly waived
> in a PR comment with ADR reference.

## Gate 1: Runner infrastructure passes its own tests

```bash
uv run pytest benchmarks/tests/ -v
```
**Required:** all tests green; no skipped tests; no deprecation warnings.

## Gate 2: All 8 ingested benchmarks report non-zero case counts

```bash
uv run python -m benchmarks.runner list
for manifest in benchmarks/external/manifests/*.manifest.json; do
    python -c "import json; d=json.load(open('$manifest')); print(f\"{d.get('dataset_name','?'):30} {d.get('case_count','?')} cases\")"
done
```
**Required:** ossf-cve-benchmark, reality-check-csharp, reality-check-python, reality-check-java, go-sec-code-mutated, skf-labs-mutated, crossvul, vul4j, morefixes-extract — ALL report `case_count > 0`.

## Gate 3: Deduplication applied

```bash
test -f benchmarks/external/manifests/_deduplicated.manifest.json
python -c "import json; d=json.load(open('benchmarks/external/manifests/_deduplicated.manifest.json')); print(f\"pre={d['pre_dedup_count']} post={d['post_dedup_count']}\")"
```
**Required:** `_deduplicated.manifest.json` exists; `post_dedup_count > 0`.

## Gate 4: Chronological and cross-project splits generated

```bash
test -f benchmarks/external/manifests/_chrono_split.manifest.json
test -f benchmarks/external/manifests/_cross_project_splits.manifest.json
```
**Required:** both split manifests present.

## Gate 5: Phase 1 agent detection rates (executed in Phase 1.7)

Once Phase 1 MCP agents exist, run:

```bash
uv run python -m benchmarks.runner run --agent xss --dataset ossf-cve-benchmark --dedup --chrono-cutoff 2024-01-01
```

**Required thresholds (ADR-013 derived):**

| Agent | Dataset | Gate | Metric | Threshold |
|---|---|---|---|---|
| xss | ossf-cve-benchmark (XSS subset) | G5.1 | TPR | ≥ 70% |
| xss | ossf-cve-benchmark (patched) | G5.2 | FPR | ≤ 25% |
| xss | reality-check-csharp | G5.3 | TPR on CWE-79 | ≥ 60% |
| xss | reality-check-python | G5.4 | TPR on CWE-79 | ≥ 60% |
| cmdi | ossf-cve-benchmark (CmdI subset) | G5.5 | TPR | ≥ 60% |
| cmdi | reality-check-java | G5.6 | TPR on CWE-78 | ≥ 50% |
| sqli | reality-check-csharp | G5.7 | TPR on CWE-89 | ≥ 50% |
| sqli | morefixes-extract | G5.8 | TPR on CWE-89 | ≥ 50% |
| ssti | go-sec-code-mutated | G5.9 | TPR on CWE-1336 | ≥ 70% |
| ssti | skf-labs-mutated | G5.10 | TPR on CWE-1336 | ≥ 70% |

**Rationale for sub-80% thresholds:** The SMU paper (Li et al. ESEC/FSE 2023)
showed that the best Java SAST tool (Horusec) hit only 12.7% TPR on real-world
Java CVEs. A 70% TPR on real-world XSS CVEs would be a significant result
relative to that baseline, and an 80% TPR would be unrealistic given
current-state SAST performance. We calibrate our gates to be rigorous but
achievable.

## Gate 6: No Rust claims in the Phase 1.7 report

Per ADR-014, the Phase 1.7 report MUST explicitly state:
> Rust detection quality not benchmarked — see ADR-014. Rust corpus construction
> is deferred to Phase 5 (step 5.0).

The report generator (`benchmarks/runner/report.py`) must emit this line when
the run summary does not include any Rust-language cases.

## Gate 7: Failure dump for each gate below threshold

For any gate in G5.* that falls below threshold, the report must list the
first 10 missed CVEs or false-flag cases so Phase 1 engineers can diagnose.
