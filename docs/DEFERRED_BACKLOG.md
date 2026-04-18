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

### T1-M1 — `AdaptiveScriptMeta` runtime-flag fields (dual-layer defense pattern)
**Source:** Phase 3b PR #4 Task 1 quality review, 2026-04-18
**File:** `src/screw_agents/models.py` `AdaptiveScriptMeta`
**Why deferred:** Task 11-14 (executor + validate-script CLI) will need per-script trust state ("trusted", "warned", "quarantined", "allowed") on `AdaptiveScriptMeta`, mirroring the `Exclusion.quarantined` + `Exclusion.trust_state` runtime fields added in Phase 3a. Adding the fields speculatively in Task 1 was rejected — the exact field name and value set should be decided by the implementer who has the executor context.
**Trigger:** When Phase 3b Task 11 (executor pipeline) or Task 13 (validate-script CLI) needs per-script trust tracking.
**Suggested approach:** Mirror the `Exclusion` dual-layer defense exactly — `Field(default=..., exclude=True)` at the schema level + `_RUNTIME_ONLY_FIELDS` ClassVar set + `model_dump` override to catch caller-side `include=` edge cases (see `Exclusion._RUNTIME_ONLY_FIELDS` at `src/screw_agents/models.py` line ~262 and the `model_dump` override at line ~264 for the template). Don't skip the override — Pydantic v2's `include`/`exclude` precedence can let `include` win over field-level `exclude`, so the runtime override is the load-bearing second layer.
**Estimated scope:** ~30 LOC in models.py + 2-3 new tests. Trivial.

---

## Phase 3c (sandbox hardening follow-ups)

### T8-Sec1 — Real seccomp filter for the Linux sandbox
**Source:** Phase 3b PR #4 Task 8 quality reviews (commits `7d07dc2`, `be9ccfc`), 2026-04-18
**File:** `src/screw_agents/adaptive/sandbox/linux.py`
**Priority:** **HIGH** (security depth) — currently the sandbox relies on bwrap's namespace + capability isolation for syscall-level defense; capability drop (`CapEff = 0`) blocks the most dangerous syscalls (ptrace, raw sockets, etc.) but is broader than necessary and offers less defense-in-depth than a real BPF-based seccomp filter.

**Why deferred:** Implementing a proper seccomp filter requires either a libseccomp Python binding (`pyseccomp` or `seccomp-bpf`) or hand-rolling the BPF bytecode via `libc.prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, ...)`. Either path is significant work (~200-400 LOC, careful syscall allowlist tuning, per-Python-version compatibility testing). The Phase 3b sandbox already has structurally-correct multi-layer defense (17 properties locked by regression tests in `tests/test_adaptive_sandbox_linux_isolation.py`); seccomp is hardening, not gap closure.

**Trigger:** Any of:
- Before screw-agents reaches a deployment scale where a single sandbox compromise has high blast radius (e.g., shared CI runners, multi-tenant SaaS deployment)
- A real-world adversarial-script audit demands BPF-level syscall denylist
- Phase 3c is opened explicitly for sandbox hardening sweep
- A CVE in bwrap or the Linux user-ns implementation forces re-evaluation

**Suggested approach:**
1. Add `pyseccomp` to `pyproject.toml` (or `python-libseccomp` depending on what's maintained).
2. Build the syscall allowlist by running the existing isolation tests under `strace -ff` and recording every syscall the legitimate adaptive-script workflow needs (Python startup, stdlib imports, file reads, write to /findings, exit). Cross-reference with `tree-sitter`'s syscalls if scripts use it.
3. Apply the filter via `prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &filter)` in `_preexec()`, AFTER `prctl(PR_SET_NO_NEW_PRIVS, 1, ...)` (required for non-root seccomp).
4. Add explicit regression tests: `test_seccomp_blocks_unallowed_syscall` (e.g., script attempting `process_vm_readv` should fail with EPERM regardless of capabilities).
5. Document the allowlist in `linux.py` as the source of truth for "what the sandboxed Python actually needs at the kernel boundary".

**Estimated scope:** 250-400 LOC + 5-10 regression tests + dependency add. Medium PR.

### T8-Sec2 — preexec_fn thread-safety swap
**Source:** Phase 3b PR #4 Task 8 quality reviews (commits `7d07dc2`, `be9ccfc`), 2026-04-18
**File:** `src/screw_agents/adaptive/sandbox/linux.py` `_preexec()`
**Priority:** Low (currently single-threaded; conditional)

**Why deferred:** Python's `subprocess` `preexec_fn` runs in the FORKED child between `fork()` and `exec()`. If the parent process has multiple threads concurrently allocating memory, the fork can deadlock on the GIL or on `malloc`'s internal locks (POSIX-fork-after-thread anti-pattern). screw-agents is currently single-threaded — the orchestrator runs one sandbox at a time per request — so the deadlock risk is zero today. Becomes relevant if the executor is ever parallelized (Task 11 + future) or the MCP server moves to a multi-process / multi-threaded model (Phase 7 — see existing T6-M1, T6-M4, T9-I1 entries for related concurrency risks).

**Trigger:** Any of:
- Task 11's executor introduces threading (e.g., parallel script execution for batch scans)
- Phase 7 multi-process MCP server is implemented
- A `RuntimeWarning: preexec_fn not safe in multithreaded application` appears in logs

**Suggested approach:** Replace the `preexec_fn=_preexec` keyword with a fork-safe alternative. Two options:
1. **Python 3.11+ `process_group=0` API** — sets the process group atomically without preexec_fn; more limited (doesn't directly support setrlimit, but combined with `prctl` set up post-fork via setrlimit AFTER exec is workable). Cleanest for Python 3.11+ projects.
2. **`prlimit` shell wrapper** — invoke `prlimit --cpu=N --as=M --nproc=K --nofile=L --fsize=F bwrap ...` instead of bwrap directly. Trades a fork+exec for a small wrapper. Works on all Python versions.

Either path requires re-validating all 17 isolation properties (the rlimit values must still apply to the script process, not just to the wrapper).

**Estimated scope:** 50-100 LOC + re-validation of isolation tests. Small-to-medium PR.

### T9-Sec1 — Deduplicate host-side sandbox defenses into shared `_common.py`
**Source:** Phase 3b PR #4 Task 9 implementation, 2026-04-18
**File:** `src/screw_agents/adaptive/sandbox/_common.py` (new) + linux.py + macos.py
**Priority:** Low (code quality, not security gap)

**Why deferred:** T9's macos.py duplicates 3 host-side helpers from linux.py
verbatim (`_safe_read_findings`, `_clean_findings_path`,
`_check_findings_aggregate_size`) plus the related constants
(`_MAX_FILE_SIZE_BYTES`, `_MAX_OUTPUT_BYTES`, `_MAX_FINDINGS_AGGREGATE_BYTES`,
`_MAX_OPEN_FILES`). These are pure Python, platform-agnostic — they
operate on the host filesystem and the orchestrator's tempfiles. Refactoring
during T9 was rejected as out-of-scope (would have required re-validating
T8's shipped tests). Cleaner architecture: extract into
`sandbox/_common.py`; linux.py and macos.py import from there.

**Trigger:** Polish pass before PR #5 starts, OR when a third sandbox
backend lands (BSD jails? Windows when supported?), OR when the helpers
need a fix that would have to be applied in two places.

**Suggested approach:**
1. Create `src/screw_agents/adaptive/sandbox/_common.py` with the 3
   helpers + 4 constants (the platform-specific NPROC cap stays in each
   backend).
2. Import them in both linux.py and macos.py: `from screw_agents.adaptive.sandbox._common import _safe_read_findings, _clean_findings_path, _check_findings_aggregate_size, _MAX_FILE_SIZE_BYTES, ...`
3. Delete the duplicated code from each backend.
4. Re-run all sandbox tests (Linux + macOS skip on each other) to verify
   no behavioral change.

**Estimated scope:** ~80 LOC moved; net negative LOC. Trivial PR.

---

## Phase 4+ (autoresearch / scale)

### T-FULL-P1 — Paginate `assemble_full_scan` + apply lazy-fetch + agent-relevance filter
**Source:** X1-M1 (PR #9, 2026-04-17) — incremental dedup landed; full architectural fix deferred.
**File:** `src/screw_agents/engine.py` `assemble_full_scan`, `plugins/screw/agents/screw-full-review.md`
**Priority:** **HIGH** — `scan_full` is unusable at CWE-1400 expansion scale (41 agents per `docs/AGENT_CATALOG.md`).

**Why deferred:** X1-M1 shipped incremental improvements to `assemble_full_scan`:
- PR #9 T5: changed return shape from `list[dict]` to `dict` with top-level `prompts`
- PR #9 T14: dropped top-level `prompts` dict; per-agent entries carry only `{agent_name, code, meta, exclusions?}`; subagents fetch prompts lazily via `get_agent_prompt`

However, the function remains:
1. **Non-paginated** — returns all code for all files for all agents in a single response
2. **Agent-relevance blind** — invokes every registered agent regardless of whether the target contains code the agent can usefully analyze (e.g., PHP-specific agents on a Python-only target)

At CWE-1400 expansion scale (41 agents × ~5-7k tokens prompt each + all code), even lazy per-agent prompt fetch cannot prevent the cumulative subagent context from approaching practical limits:
- 41 agents × 5-7k tokens cached prompts = ~205-287k tokens
- Plus cumulative code across all files × 41 agent analyses
- Opus 1M context window fits it in theory, but practically wasteful and fragile

**Trigger:** Any of:
- A round-trip test confirms `scan_full` stalls on a realistic project at Phase 3b+ agent count (≥10)
- Phase 4 autoresearch uses `scan_full` in volume and trips budget limits
- A user reports `scan_full` failures due to payload size or context exhaustion

**Suggested fix (three components, ship as one or sequential PRs):**

1. **Pagination** — cursor-based over the flattened `(agent, file_chunk)` space. Cursor carries `{target_hash, agent_offset, file_offset}`. Same init-page/code-page split as `scan_domain` post-T13.
2. **Lazy per-agent prompt fetch** — scan_full response never includes `prompts`; orchestrator uses `get_agent_prompt` on first-encounter per agent, caches for reuse across pages. This is already the pattern T13-T16 applies to scan_domain.
3. **Agent-relevance pre-filter** — scan_full returns only agents whose `target_strategy.relevance_signals` match files present in the target. For example, on a Python-only target, skip LDAP/NoSQL/PHP-specific agents that would produce no findings anyway. Could halve active-agent count on typical targets. New `ScanEngine._filter_relevant_agents(codes, agents)` helper.

**Estimated scope:** ~500-700 LOC across engine.py, server.py, orchestrator prompts, tests. Separate focused PR (likely Phase 4 prerequisite).

### T-STAGING-ORPHAN-GC — Clean up orphaned `.screw/staging/` directories
**Source:** T-WRITE-SPLIT (PR #9, 2026-04-17) — staging-dir cleanup is per-session on finalize only; no sweeper for abandoned sessions
**File:** `src/screw_agents/staging.py`, new CLI subcommand or hook
**Priority:** Medium — benign bloat (each orphan is small), but accumulates over time with crashed/aborted scans

**Why deferred:** When `accumulate_findings` is called but `finalize_scan_results` is never called (subagent crashed, user aborted with Ctrl-C, scan timed out), the staging directory at `.screw/staging/{session_id}/` is not cleaned up. Current scope: single-process MCP server; orphan directories are benign but accumulate. Out of scope for PR #9's correctness fix.

**Trigger:** Any of:
- User reports `.screw/staging/` with many orphan directories
- Phase 4 autoresearch generates many scan sessions and staging bloat becomes visible
- A dedicated `screw-agents gc` CLI subcommand is added

**Suggested fix:**
1. Add `screw-agents gc-staging [--older-than N]` CLI subcommand that removes staging directories older than N hours (default 24h)
2. OR: have `finalize_scan_results` opportunistically sweep staging directories older than 24h on each call (cheap, no new surface)
3. Document the manual cleanup: `rm -rf .screw/staging/` is safe (only affects in-flight scans, which would fail at `finalize_scan_results` anyway)

**Estimated scope:** ~50-100 LOC (new CLI subcommand + unit tests + docs). Small PR.

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

### T3-M1 — Narrow exception handling in `adaptive/ast_walker.py` find_* helpers
**Source:** Phase 3b PR #4 Task 3 quality review, 2026-04-18
**File:** `src/screw_agents/adaptive/ast_walker.py` (`find_calls`, `find_imports`, `find_class_definitions`)
**Why deferred:** Each helper wraps the per-file `project.read_file(rel_path)` call in a bare `try/except Exception: continue`. This silently swallows real failures (UnicodeDecodeError on non-UTF-8 source, OSError on filesystem races) so adaptive scripts cannot tell "no findings" from "couldn't read this file." Acceptable inside the sandbox today (no logging infrastructure in adaptive scripts yet); becomes important when (a) adaptive scripts gain a logging surface or (b) a deliberately mis-encoded source file is suspected as a scanner-evasion vector.
**Trigger:** When adaptive scripts gain a logging hook (Phase 3b Task 11+) OR a non-UTF-8 source surfaces in benchmark fixtures OR a `SkipFile` sentinel is added.
**Suggested fix:** Replace `except Exception` with `except (UnicodeDecodeError, OSError)` and emit a structured log/sentinel that the executor can surface. Add a test fixture with non-UTF-8 source to lock in the new behavior.

### T-ORCHESTRATOR-SCHEMA — Backfill finding-object schema in domain orchestrator subagents
**Source:** X1-M1 PR#9 T6 quality review, 2026-04-17 (gap pre-existing, not introduced by T6)
**File:** `plugins/screw/agents/screw-injection.md` (and any future domain orchestrators)
**Priority:** Medium — determinism regression, not a correctness bug.

**Why deferred:** Single-agent orchestrators like `plugins/screw/agents/screw-sqli.md` carry the full finding-object JSON schema + field-population rules (line_start precision, verbatim CWE/OWASP copy, severity/confidence guidance). Domain orchestrators (currently just `screw-injection.md`, more will land in Phase 3b) delegate analysis to the per-agent prompts via `prompts[agent_name]` but don't carry an output-contract schema themselves. Two LLM sessions analyzing the same code under `/screw:injection` may produce differently-formatted findings (different field coverage, different severity interpretations). Pre-existing gap — not introduced by X1-M1. Worth addressing before Phase 3b multiplies the number of domain orchestrators (copy-paste amplifies the gap).

**Trigger:** Before Phase 3b adds a second or third domain orchestrator template, OR if a round-trip test shows cross-session finding-format drift under `/screw:injection`.

**Suggested fix:**
1. Extract the finding-object schema + field-population rules from `screw-sqli.md` into a reusable snippet (could live in a shared Markdown fragment or be duplicated verbatim for now).
2. Apply to `screw-injection.md` in Step 2 (the "Analyze All Accumulated Payloads" step).
3. Apply to future Phase 3b domain orchestrators.
4. Optional: add a lightweight round-trip test that invokes `/screw:injection` twice on a small fixture and asserts findings-format stability.

**Estimated scope:** ~50 LOC per orchestrator + optional test. Small PR.

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

### T19-N1 — Parameterize `aggregate_fp_report` `scope` and tuning constants
**Source:** Phase 3a PR#2 Task 19 quality review (commit `156508c`)
**File:** `src/screw_agents/aggregation.py` `aggregate_fp_report`
**Why deferred:** Currently `scope` is hardcoded `"project"` and `_FP_REPORT_TOP_N=10` / `_FP_REPORT_MIN_COUNT=3` / `_FP_REPORT_MAX_REASONS=5` are module constants. Phase 4 autoresearch may want `"global"` scope (cross-project rollups), and different consumers may want different top-N caps (Phase 4 per-agent vs. display per-report). Adding parameters now without a known consumer shape would be speculative; the FPReport model already supports `Literal["project", "global"]`.
**Trigger:** Phase 4 autoresearch implementation, OR when Task 20's MCP tool gets a second consumer that needs different tuning.
**Suggested fix:** Add `*, scope: Literal["project", "global"] = "project", top_n: int | None = None, min_count: int | None = None, max_reasons: int | None = None` kwargs — defaults fall through to the module constants.

### T-PLUGIN-M1 — Marketplace packaging: publish `screw-agents` to PyPI + plugin-scoped `.mcp.json`
**Source:** Phase 3a PR#2 plugin-namespace restructure (commit `31bac3a`)
**File:** `pyproject.toml`, `plugins/screw/.mcp.json` (to be created), `.mcp.json` (at repo root, project-scoped — may be removed once plugin-scoped path is live)
**Why deferred:** Today `.mcp.json` at repo root declares the MCP server as `uv run screw-agents serve --transport stdio`. That command only works when `pyproject.toml` is reachable (i.e., when Claude Code's cwd is the repo root). For marketplace distribution, Claude Code copies the plugin to `~/.claude/plugins/cache/...`, which does NOT include `pyproject.toml` — the server command would fail. The fix requires publishing `screw-agents` to PyPI and rewriting the MCP command to use `uvx screw-agents serve`, which works from anywhere.
**Trigger:** Before the first marketplace submission (Phase 7+ typical timing, but earlier if someone wants external users to install the plugin without cloning the repo).
**Suggested fix:**
1. Polish `pyproject.toml` for PyPI: add classifiers, long_description (point at README), fix any missing metadata.
2. Run `uv build` and `uv publish` (or `twine upload`) to push screw-agents to PyPI.
3. Add `plugins/screw/.mcp.json` with `{"mcpServers": {"screw-agents": {"command": "uvx", "args": ["screw-agents", "serve", "--transport", "stdio"]}}}`.
4. Optionally drop the project-scoped `.mcp.json` at repo root (or keep for editable-install dev mode).
5. Update `CONTRIBUTING.md` to document: "for marketplace install, plugin MCP uses the PyPI-published CLI."

### T-PLUGIN-M2 — Rename `screw-research` / `screw-review` skills to drop the redundant `screw-` prefix
**Source:** Phase 3a PR#2 plugin-namespace restructure (audit)
**File:** `plugins/screw/skills/screw-research/SKILL.md`, `plugins/screw/skills/screw-review/SKILL.md`, plus 33 files referencing these names (domains/*.yaml fixtures, docs, plans).
**Why deferred:** After the plugin-namespace fix, skill invocations are `/screw:screw-research` and `/screw:screw-review` — the `screw-` prefix is redundant because the plugin namespace already provides it. Renaming to `/screw:research` and `/screw:review` is cleaner, but the skill names appear in ~33 tracked files (domain YAMLs, plans, PRD, PHASE_*.md, DECISIONS.md, KNOWLEDGE_SOURCES.md, benchmark fixtures). Out of scope for PR#2's namespace cleanup; deserves a dedicated rename commit with its own audit pass.
**Trigger:** Any of: (a) a dedicated polish commit before the first marketplace submission, (b) a user-visible redundancy complaint, (c) alongside T-PLUGIN-M1.
**Suggested fix:**
1. `git mv plugins/screw/skills/screw-research plugins/screw/skills/research`; same for screw-review.
2. Update SKILL.md frontmatter `name:` fields if they reference the dirname.
3. Bulk find-replace: `screw-research` → `research`, `screw-review` → `review` across all tracked files. Careful: `screw-review` appears as a substring in other contexts — do a scoped replacement with per-file review.
4. Verify benchmark fixtures still reference the right skill (they're consumed by other tooling, not invoked as slash commands; likely no change needed).
5. Run `uv run pytest -q` to confirm no test regression.

### T21-m1 — Server-side reason backtick-wrapping in `aggregation.py`
**Source:** Phase 3a PR#2 round-trip test (commits `c468041` + `41bd19f`), 2026-04-16
**File:** `src/screw_agents/aggregation.py` (`aggregate_directory_suggestions`, `aggregate_fp_report`), `plugins/screw/agents/screw-learning-analyst.md`
**Why deferred:** T18-m1's subagent prompt rule (backtick-wrap reason strings from `evidence.reason_distribution` keys + `FPPattern.example_reasons`) was tightened to MANDATORY framing with negative examples during PR#2 (commit `41bd19f`). Observed behavior: Opus 4.6 renders reasons with backticks; Opus 4.7 renders them with double-quotes (partial adherence). Prompt-level enforcement can't deterministically control cross-model LLM output. The correct defense is structural: aggregation.py emits pre-wrapped reason strings, eliminating LLM discretion from the Markdown-injection boundary. Current state is not a vulnerability — fixture reasons are benign strings — but the defense is preventive against future attacker-influenced reasons.
**Trigger:** (a) Before PR#3 work starts is natural (same file, no merge conflicts), OR (b) when a reason string in the wild contains Markdown-structural characters that visibly leak through the report.
**Suggested fix:**
1. In `DirectorySuggestion.evidence`, add a parallel `reason_distribution_rendered: str` field (pre-formatted Markdown like `` `Full-text search` (11), `one-shot migration` (3) ``). Keep `reason_distribution: dict[str, int]` for programmatic consumers.
2. In `FPPattern`, add `example_reasons_rendered: list[str]` (each element already backtick-wrapped). Keep `example_reasons: list[str]` for machine use (Phase 4 autoresearch).
3. Update `plugins/screw/agents/screw-learning-analyst.md` to instruct the subagent to output `reason_distribution_rendered` and `example_reasons_rendered` fields VERBATIM (no further wrapping needed).
4. Update Task 23 integration test to assert the rendered fields contain backticks.
5. Simplify the T18-m1 MANDATORY rule in the subagent prompt — it becomes a single line referencing the pre-rendered fields, not a rule the LLM must apply.

### T21-m2 — Server-side trust-notice rendering
**Source:** Phase 3a PR#2 round-trip test (commits `c468041` + `41bd19f`), 2026-04-16
**File:** `src/screw_agents/engine.py` `aggregate_learning`, `plugins/screw/agents/screw-learning-analyst.md`
**Why deferred:** The trust-notice block in the subagent prompt is a 4-line template the LLM is supposed to output verbatim when `quarantine_count > 0`. Observed behavior: Opus 4.6 renders it cleanly; Opus 4.7 paraphrases (drops `⚠`, drops bold, truncates the `screw-agents migrate-exclusions` sentence). Tightening the prompt rule to "render character-for-character" (commit `41bd19f`) didn't fully pin down 4.7's behavior. Same class of issue as T21-m1 — prompt adherence is not a security boundary. The core fact (quarantine count > 0) IS communicated; only template fidelity drifts. Structural fix: have `aggregate_learning` include a pre-rendered `trust_notice_markdown` field when `quarantine_count > 0`, which the subagent outputs verbatim (LLM-generated → LLM-copied; less drift).
**Trigger:** Alongside T21-m1 (same file, same design pattern, same follow-up PR is natural).
**Suggested fix:**
1. In `ScanEngine.aggregate_learning`, when `trust_status["exclusion_quarantine_count"] > 0`, compose the trust-notice Markdown block server-side and attach it as `trust_status["notice_markdown"]: str`. Use the canonical template verbatim, interpolating the count.
2. Update subagent prompt: replace the "render character-for-character" rule with "output `trust_status.notice_markdown` verbatim as the FIRST content line when it is non-empty." Simpler rule, deterministic content.
3. Add a test to `tests/test_aggregate_learning_tool.py` asserting `notice_markdown` is present when quarantine_count > 0 AND absent otherwise.
4. Round-trip test should re-validate that the notice appears correctly across model versions.

### T16-N1 — `AggregateReport.generated_at` convenience field
**Source:** Phase 3a PR#2 Task 16 quality review (commit `bb3b7a0`)
**File:** `src/screw_agents/models.py` `AggregateReport`
**Why deferred:** `FPReport.generated_at` is already present; the wrapper doesn't need its own. Adding one now is YAGNI until a consumer actually demands a single authoritative timestamp for the whole report.
**Trigger:** When a consumer of `aggregate_learning` output (MCP caller, markdown formatter, etc.) needs a wrapper-level timestamp and can't satisfy it via `fp_report.generated_at`.
**Suggested fix:** Add `generated_at: str` (matching the inner FPReport convention pre-T16-M2, or `datetime` post-T16-M2) populated by `ScanEngine.aggregate_learning`.

### T21-m3 — Pydantic validator guard on `ExclusionInput.reason`
**Source:** Phase 3a PR#3 Task 0a (T21-m1) fix-up review, 2026-04-16
**File:** `src/screw_agents/models.py` `ExclusionInput.reason`
**Why deferred:** T21-m1's fix-up added a render-layer escape for backticks in `src/screw_agents/aggregation.py::_escape_reason_for_code_span`. Belt-and-suspenders would add a Pydantic validator on `ExclusionInput.reason` that rejects or strips backticks at storage time — guaranteeing every path that persists an exclusion carries a safe reason, not just the aggregation rendering path. Deferring because (a) the render-layer fix is already load-bearing for the current consumer, (b) storage-layer validation is a separate design decision (reject vs strip vs warn) that deserves its own PR, (c) existing exclusions-YAML data may contain backticks and would need migration.
**Trigger:** When a second consumer of `ExclusionInput.reason` renders to Markdown (e.g., Phase 3b adaptive-script rejection reasons piped through the same FP report — see `PHASE_3B_PLAN.md` Task 3b-18), OR when a data audit shows wild backticks in exclusions.yaml, OR during a dedicated data-integrity polish commit.
**Suggested fix:**
1. Add `@field_validator("reason")` to `ExclusionInput` that either strips backticks (silent sanitization) or raises ValueError (fail-closed). Recommend fail-closed so the user knows their reason was altered.
2. Provide a one-shot CLI migration (`screw-agents sanitize-exclusions`) that rewrites existing exclusions.yaml entries with sanitized reasons (preserving signatures via re-signing with the local key).
3. Remove the render-layer escape in aggregation.py as redundant (optional — can keep as defense-in-depth).

### T-ACCUMULATE-ONCE — UX polish: encourage single accumulate_findings call per scan
**Source:** Phase 3a X1-M1 round-trip testing (PR #9, 2026-04-17)
**File:** `plugins/screw/agents/screw-injection.md` (Step 3 critical rules), and other orchestrators if the pattern spreads
**Priority:** **Low** — UX annoyance, not a correctness issue

**Why deferred:** Final round-trip showed the subagent making 3 × `accumulate_findings` calls (one per agent batch), each carrying a cumulative findings payload. Each call required user confirmation with a "wall of text" approval prompt. The current `screw-injection.md` prompt explicitly permits multiple accumulate calls ("You MAY call this multiple times"). Narrowing to "prefer ONE accumulate call at the end with all findings" would reduce tool-call approvals from 4-6 to 2 in typical scans.

**Why not now:** The current behavior is correct (findings deduped by id; final output right). The wall-of-text approvals are annoying but not blocking. Tightening the prompt is a simple doc-only change, but without round-trip validation there's risk of over-constraining (e.g., if a subagent hits an LLM context limit partway through a scan, per-batch persistence is actually useful). Defer until: (a) users complain, OR (b) a round-trip test proves single-accumulate works reliably at current scale.

**Trigger:** Any of:
- User-visible complaint about approval-prompt fatigue during `/screw:scan domain ...`
- Round-trip test at larger scale (injection domain at full 10 agents per AGENT_CATALOG.md) shows single-accumulate is reliable
- Dedicated prompt-polish commit that tackles multiple orchestrator UX issues together

**Suggested fix:**
1. Update `plugins/screw/agents/screw-injection.md` Step 3a to soften "you MAY call this multiple times" → "prefer a SINGLE call at the end with all findings; multiple calls are safe (dedup by id) but each requires approval and is noisy".
2. Run round-trip. Confirm single-accumulate works.
3. Apply same softening to per-agent orchestrators if needed (they already call accumulate once since single-agent scans have only one batch).

**Estimated scope:** ~5-10 LOC of prompt text + round-trip validation.

---

## Shipped

### X1-M1 — Core-prompt deduplication in `scan_domain` paginated responses
**Source:** Phase 3a PR#3 manual round-trip test, 2026-04-17
**Shipped in:** PR #9 (`phase-3a-prompt-dedup`), merge commit `4685671`
**Final design:** `docs/specs/2026-04-17-prompt-dedup-x1-m1-design.md` (local, not in git)
**Plan:** `docs/PHASE_3A_X1_M1_PLAN.md`

**Solution:** Applied Option A′ (init page + code pages) to `assemble_domain_scan` and Option A (top-level `prompts` dedup) to `assemble_full_scan`. `assemble_scan` gained `include_prompt: bool = True` kwarg. Cursor schema unchanged. `assemble_full_scan` return type changed from `list[dict]` to `dict` — breaking change to `scan_full` MCP tool.

**Follow-ups:**
- `T-FULL-P1` (Phase 4+) — paginate `assemble_full_scan` and apply Option A'
- `T-ORCHESTRATOR-SCHEMA` (project-wide) — backfill finding-object schema in domain orchestrator subagents
- `T-WRITE-SPLIT` (Shipped in this PR) — split write_scan_results into accumulate + finalize
- `T-STAGING-ORPHAN-GC` (Phase 4+) — clean up orphaned .screw/staging/ directories
- `T-ACCUMULATE-ONCE` (project-wide, Low) — prompt polish to prefer single accumulate call

### T-WRITE-SPLIT — Split `write_scan_results` into `accumulate_findings` + `finalize_scan_results`
**Source:** Phase 3a X1-M1 round-trip testing (PR #9, 2026-04-17)
**Shipped in:** PR #9 (`phase-3a-prompt-dedup`), merge commit `4685671`
**Plan:** `docs/PHASE_3A_X1_M1_PLAN.md`

**Problem:** Round-trip testing after the lazy-fetch fix (T12-T16) revealed a second defect — subagents called `write_scan_results` once per agent-batch (4 times for a 4-agent injection scan). Overwrite semantics masked this as "just wasteful" (the final call had all findings), but each intermediate call triggered file rewrites + user approvals + tool-call tokens. Prompt-level "call once" discipline was not load-bearing.

**Solution:** Option D — architectural split into two tools:
- `accumulate_findings(project_root, findings_chunk, session_id?) -> {session_id, accumulated_count}` — incremental staging in `.screw/staging/{session_id}/findings.json`; dedup by finding.id on merge; atomic tmp+replace writes
- `finalize_scan_results(project_root, session_id, agent_names, scan_metadata?, formats?) -> {files_written, summary, exclusions_applied, trust_status}` — one-shot render+write; reads staging, applies exclusions, renders formats, cleans up staging; second call raises ValueError

The subagent's natural "persist after each batch" instinct is channeled into cheap `accumulate_findings` calls; `finalize_scan_results` is an explicit terminal event. The legacy `write_scan_results` function and MCP tool were removed.

**Follow-up:** `T-STAGING-ORPHAN-GC` (Phase 4+) — orphan cleanup for scans that accumulate but never finalize.
