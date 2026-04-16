# Deferred Items Backlog

> Cross-phase registry of items deferred from completed PRs. Each entry tags a target phase or trigger so future plan authors can pull these items in at the natural time. Append new entries as future PRs defer items beyond their immediate scope.

---

## Phase 3b Task 13 (init-trust extends trust.py)

### T4-M6 — Split `src/screw_agents/trust.py` into a package
**Source:** Phase 3a PR#1 punchlist (commit `27d147d`)
**File:** `src/screw_agents/trust.py` (~552 lines after Task 7.1)
**Why deferred:** Phase 3b Task 13 (init-trust CLI) will naturally extend trust.py with key-generation utilities. Splitting now would mean churning the file twice.
**Trigger:** When Phase 3b Task 13's implementation lands.
**Suggested split:**
- `trust/__init__.py` — re-exports
- `trust/canonical.py` — `canonicalize_exclusion`, `canonicalize_script`, `_canonical_json_bytes`, exclude sets
- `trust/sign.py` — `sign_content`
- `trust/verify.py` — `verify_signature`, `VerificationResult`, `_fingerprint_public_key`, `verify_exclusion`, `verify_script`, helper trio
- `trust/keys.py` — `_public_key_to_openssh_line`, future key generation
- `trust/config.py` — `load_config`, `_CONFIG_STUB_TEMPLATE`
**Note (T6-M7 subsumed here):** The line-count trajectory observation T6-M7 from the Phase 3a PR#1 punchlist points back to this same split — addressing T4-M6 will resolve T6-M7 too.

---

## Phase 4+ (autoresearch / scale)

### T5-M4 — Lazy fingerprint computation in `verify_signature`
**Source:** Phase 3a PR#1 punchlist (commit `27d147d`)
**File:** `src/screw_agents/trust.py` `_fingerprint_public_key` and `verify_signature`
**Why deferred:** Each successful verify computes the fingerprint even when the caller doesn't read `matched_key_fingerprint`. Trivial cost today; CLI batch verification could amplify.
**Trigger:** When batch verification becomes a measurable cost (Phase 4 autoresearch loop or Phase 7 multi-tenant MCP).
**Suggested fix:** Add `compute_fingerprint: bool = True` parameter to `verify_signature` OR make the fingerprint a `VerificationResult` cached property.

### T8-M4 — `record_exclusion` O(n²) verification cost
**Source:** Phase 3a PR#1 punchlist (commit `27d147d`)
**File:** `src/screw_agents/learning.py` `record_exclusion`
**Why deferred:** Tens of entries today; Phase 4+ autoresearch may record hundreds per run.
**Trigger:** When `record_exclusion` calls dominate a per-run profile.
**Suggested fix:** Cache verification results keyed on `(exclusion.id, exclusion.signature)` OR add a "skip re-verification on append" fast path.

### T9-I2 (record_exclusion path) — Atomic write in `learning.py`
**Source:** Phase 3a PR#1 punchlist (commit `27d147d`)
**File:** `src/screw_agents/learning.py` `record_exclusion` write
**Note:** CLI write paths (`cli/migrate_exclusions.py`, `cli/validate_exclusion.py`) already use `tmp.write_text + os.replace`. The `learning.py` `record_exclusion` path is the remaining non-atomic write.
**Why deferred:** Single-record write; risk window is small at current scale.
**Trigger:** When concurrent or high-frequency `record_exclusion` calls become possible.
**Suggested fix:** Mirror the CLI pattern — `tmp = path.with_suffix(".yaml.tmp"); tmp.write_text(...); os.replace(tmp, path)`.

### T10-I2 — Full-scan exclusion-load amplification
**Source:** Phase 3a PR#1 punchlist (commit `27d147d`)
**File:** `src/screw_agents/engine.py` `assemble_full_scan` / `assemble_domain_scan`
**Why deferred:** Both methods call `assemble_scan` in a list comprehension; each iteration reloads exclusions independently. For an N-agent full scan, that's N×(parse+verify) where 1 would suffice. Task 10's I1 fix halved per-iteration cost but didn't touch per-scan amplification.
**Trigger:** When full-scan latency becomes user-visible (Phase 4 autoresearch loop or large project benchmarks).
**Suggested fix:** Scan-scoped cache at `assemble_full_scan` / `assemble_domain_scan` level — load exclusions once, pass through `assemble_scan` via an optional `_preloaded_exclusions` parameter (~15 lines).

---

## Phase 7 (multi-process MCP server)

### T6-M1 — TOCTOU race on `load_config` stub creation
**Source:** Phase 3a PR#1 punchlist (commit `27d147d`)
**File:** `src/screw_agents/trust.py` `load_config` stub-write block
**Why deferred:** Single-process CLI is safe; concurrent `load_config` calls can only happen in multi-process MCP server.
**Trigger:** Phase 7 multi-process MCP server work.
**Suggested fix:** Use `os.open(path, O_CREAT | O_EXCL | O_WRONLY)` for atomic stub creation.

### T6-M4 — `load_config` `@lru_cache` with staleness invalidation
**Source:** Phase 3a PR#1 punchlist (commit `27d147d`)
**File:** `src/screw_agents/trust.py` `load_config`
**Why deferred:** Each call re-reads the file; fine for single-scan CLI; per-request disk hit in Phase 7 MCP server.
**Trigger:** Phase 7 MCP server profiling.
**Suggested fix:** `@lru_cache` keyed on `project_root` with mtime-based invalidation hook.

### T9-I1 — Concurrent `record_exclusion` race condition
**Source:** Phase 3a PR#1 punchlist (commit `27d147d`)
**File:** `src/screw_agents/learning.py` `record_exclusion`
**Why deferred:** Two concurrent calls both compute the same `next_seq` — second write overwrites the first. Single-process CLI never sees this.
**Trigger:** Phase 7 multi-process MCP risk surface.
**Suggested fix:** Wrap read-modify-write in `fcntl.flock` on a sibling `.lock` file. Lower-cost alternative: document the limitation in the docstring as "Not safe for concurrent invocation — external serialization required."

---

## Project-wide (not Phase-tagged)

### T10-M1 — `additionalProperties: false` on tool input schemas
**Source:** Phase 3a PR#1 punchlist (commit `27d147d`)
**File:** `src/screw_agents/engine.py` `list_tool_definitions` (and all sibling tool schemas)
**Why deferred:** None of the existing Phase 2+ tools set this. Adding it to `verify_trust` alone would be inconsistent — this is a project-wide tightening that needs a dedicated polish commit covering all tools.
**Trigger:** Dedicated schema-tightening polish commit, OR when a confused-deputy concern surfaces.
**Suggested fix:** Apply `"additionalProperties": false` uniformly across all Phase 2+ tool input schemas in one commit.

### T16-M1 — Typed sub-models for `PatternSuggestion.evidence` / `DirectorySuggestion.evidence`
**Source:** Phase 3a PR#2 Task 16 quality review (commit `bb3b7a0`)
**File:** `src/screw_agents/models.py`
**Why deferred:** Plan prescribes `dict[str, Any]`. Task 17/18/19 populate different evidence keys per feature, so typed sub-models need at least 2 variants. Deferring until the evidence-dict keys stabilize across Tasks 17–19 + Task 23 MCP output.
**Trigger:** When the MCP wire format for `aggregate_learning` is frozen (end of PR#2) OR when a downstream consumer breaks because of an evidence-key typo.
**Suggested fix:** Introduce `PatternEvidence` and `DirectoryEvidence` BaseModels; update aggregation.py to construct them; update tests. Enforces construction-time validation of evidence keys.

### T16-M2 — `generated_at: datetime` migration across all timestamp fields
**Source:** Phase 3a PR#2 Task 16 quality review (commit `bb3b7a0`)
**File:** `src/screw_agents/models.py` (`FPReport.generated_at`, `Exclusion.created`, and any future timestamp fields)
**Why deferred:** Task 16 inherits the str-convention from `Exclusion.created` (PR#1). Changing `FPReport.generated_at` alone would fragment the convention. A coordinated migration pass benefits from being one commit.
**Trigger:** When a malformed-timestamp bug surfaces, OR during a formatter-polish commit that already touches timestamp handling.
**Suggested fix:** Change all timestamp fields from `str` to `datetime`; add `model_config = ConfigDict(json_encoders={datetime: lambda v: v.strftime("%Y-%m-%dT%H:%M:%SZ")})` or use Pydantic v2's native json mode serializer; update tests that assert on string-literal timestamps.

### T16-M3 — `cwe: str` regex constraint consistency pass
**Source:** Phase 3a PR#2 Task 16 quality review (commit `bb3b7a0`)
**File:** all models with `cwe: str` fields — `FPPattern`, `PatternSuggestion`, `DirectorySuggestion` (wait — `DirectorySuggestion` has no `cwe` field; only `FPPattern` and `PatternSuggestion`), `ExclusionFinding`, `FindingClassification`
**Why deferred:** Today any string is accepted (e.g., `"CWE89"` and `"CWE-89"` both pass). Normalization drift is possible. Fix needs a coordinated pass across all `cwe` fields to avoid one-model-at-a-time inconsistency.
**Trigger:** When CWE-normalization drift actually bites (first mismatched comparison), OR during the T16-M2 timestamp migration (same scope of coordinated-model-constraint work).
**Suggested fix:** Apply `Field(pattern=r"^CWE-\d+$")` uniformly to every `cwe: str` field. Update tests that construct CWE values.

### T16-M4 — Max-length constraints on FPReport list fields
**Source:** Phase 3a PR#2 Task 16 quality review (commit `bb3b7a0`)
**File:** `src/screw_agents/models.py` `FPReport`, `FPPattern`
**Why deferred:** Aggregation (Task 19) already caps `top_fp_patterns` to `_FP_REPORT_TOP_N = 10` and `example_reasons` to `[:5]`. Model-layer max_length would be redundant belt-and-suspenders. Deferring until a bypass surfaces (e.g., a different aggregation caller that doesn't cap).
**Trigger:** When a non-aggregation caller constructs FPReport (e.g., Phase 4 autoresearch) and evidence shows unbounded lists reaching the model layer.
**Suggested fix:** Add `Field(max_length=N)` to `top_fp_patterns`, `example_reasons`, `evidence.files_affected`.

### T17-M1 — Cap `files_affected` list size in `aggregate_pattern_confidence`
**Source:** Phase 3a PR#2 Task 17 quality review (commit `9c6ec7e`)
**File:** `src/screw_agents/aggregation.py` `aggregate_pattern_confidence`
**Why deferred:** A bucket with hundreds of matching files produces a `PatternSuggestion.evidence.files_affected` list containing all of them — unbounded growth proportional to FP-marked files. Aggregation is the producer, so the cap belongs here, but real-world bucket sizes in current usage are small. Related to T16-M4 (model-layer bounds); the caller-side cap is complementary.
**Trigger:** When a project with many FPs-per-pattern makes the emitted report unwieldy (subagent truncates, Markdown renderer stalls), OR during the T16-M4 bounds pass.
**Suggested fix:** Truncate `files_affected` to the top 20 lexicographically and emit an `evidence["files_affected_truncated"]: True` + `"files_affected_total": len(group)` fields when truncation occurs.

### T18-M1 — Multi-level directory grouping for `aggregate_directory_suggestions`
**Source:** Phase 3a PR#2 Task 18 quality review (commit `ce0773e`)
**File:** `src/screw_agents/aggregation.py` `aggregate_directory_suggestions`
**Why deferred:** Current algorithm buckets by FIRST path component only — a repo with most files under `src/` collapses into one giant `src/` bucket, obliterating the "concentration" signal for sub-directories like `src/vendor/` or `src/services/`. The plan explicitly specifies first-segment grouping in §7.2 ("All 12 findings under `test/` were marked FP"), so the coarse granularity is by design for the initial release. Deferring the design question until user feedback shows whether sub-directory granularity is actually needed.
**Trigger:** User reports saying "the suggestion is too coarse — my whole src/ collapsed" OR Phase 4 autoresearch needs finer-grained signal.
**Suggested fix:** Extend signature with `granularity: Literal["top", "full"] = "top"` parameter. When `"full"`, use `os.path.dirname(file) + "/"` as the top_dir. Update tests to cover both modes. Or: emit suggestions at multiple granularities and let the subagent choose.

### T18-m1 — Sanitize `reason_distribution` keys in subagent render (Task 21 concern)
**Source:** Phase 3a PR#2 Task 18 quality review (commit `ce0773e`)
**File:** `plugins/screw/agents/screw-learning-analyst.md` (Task 21 subagent prompt)
**Why deferred:** The `evidence["reason_distribution"]` dict carries user-controlled reason strings as keys. They reach the rendered Markdown via the subagent. Task 18 doesn't sanitize at the data layer (reason is semantically text, not a code-pattern). The correct layer for escape-handling is the subagent prompt — instruct the LLM to render reasons as inline code (backticks) or truncate/escape.
**Trigger:** Task 21 implementation OR during the first real-world subagent run if a reason contains Markdown-structural characters.
**Suggested fix:** In `screw-learning-analyst.md`, add rule: "When rendering `evidence.reason_distribution` keys, wrap each reason in backticks to prevent Markdown injection from user-controlled exclusion-reason text."

### T16-N1 — `AggregateReport.generated_at` convenience field
**Source:** Phase 3a PR#2 Task 16 quality review (commit `bb3b7a0`)
**File:** `src/screw_agents/models.py` `AggregateReport`
**Why deferred:** `FPReport.generated_at` is already present; the wrapper doesn't need its own. Adding one now is YAGNI until a consumer actually demands a single authoritative timestamp for the whole report.
**Trigger:** When a consumer of `aggregate_learning` output (MCP caller, markdown formatter, etc.) needs a wrapper-level timestamp and can't satisfy it via `fp_report.generated_at`.
**Suggested fix:** Add `generated_at: str` (matching the inner FPReport convention pre-T16-M2, or `datetime` post-T16-M2) populated by `ScanEngine.aggregate_learning`.
