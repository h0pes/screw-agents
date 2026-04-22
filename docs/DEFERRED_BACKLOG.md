# Deferred Items Backlog

> Cross-phase registry of items deferred from completed PRs. Each entry tags a target phase or trigger so future plan authors can pull these items in at the natural time. Append new entries as future PRs defer items beyond their immediate scope.

---

## Trust-layer polish (was "Phase 3b Task 13", re-scoped 2026-04-19)

### T4-M6 — Split `src/screw_agents/trust.py` into a package
**Source:** Phase 3a PR#1 punchlist (commit `27d147d`)
**File:** `src/screw_agents/trust.py` (~552 lines after Task 7.1)
**Why deferred:** ~~Phase 3b Task 13 (init-trust CLI) will naturally extend trust.py with key-generation utilities. Splitting now would mean churning the file twice.~~ REVISED 2026-04-19: Phase 3b T13 validate-script CLI was reviewed and found to only IMPORT existing trust.py functions, not extend them. The original split-avoidance rationale no longer applies; trigger revised accordingly.
**Trigger:** When trust.py gains new exported functions (e.g., Phase 3b T17 screw-script-reviewer or T18 subagent-prompt integration may need new helpers) OR during a dedicated polish commit. Phase 3b T13 validate-script CLI does NOT extend trust.py — it only imports `canonicalize_script`, `load_config`, `sign_content`, and the internal helpers — so T13 is no longer a valid trigger. REVISED 2026-04-19 (post-T18a): T18a (`sign_adaptive_script` + `lint_adaptive_script` MCP tools) does NOT extend trust.py either — it imports the same internal helpers and places the shared canonicalization wrapper at `src/screw_agents/adaptive/signing.py` (adaptive-specific signing lives with adaptive code). T18a is no longer a valid trigger.
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
**Why deferred:** ~~Task 11-14 (executor + validate-script CLI) will need per-script trust state ("trusted", "warned", "quarantined", "allowed") on `AdaptiveScriptMeta`, mirroring the `Exclusion.quarantined` + `Exclusion.trust_state` runtime fields added in Phase 3a. Adding the fields speculatively in Task 1 was rejected — the exact field name and value set should be decided by the implementer who has the executor context.~~ REVISED 2026-04-19: T11 (shipped in PR #4) and T13 (bundled in PR #5) were both reviewed and found to NOT need runtime-flag fields. T11's executor returns `AdaptiveScriptResult.stale` as a top-level runtime flag and does not annotate the meta model itself; T13's validate-script writes only persisted fields (`signed_by`, `signature`, `validated`, `sha256`). First likely trigger is T20 stale-script detection (runtime `stale` annotation) or T21 adaptive-cleanup (user-visible trust state).
**Trigger:** When the executor OR a CLI command needs to annotate `AdaptiveScriptMeta` at runtime (e.g., Phase 3b T20 stale-script detection may attach a `stale: True` runtime flag, or T21 adaptive-cleanup may want `quarantined`/`trust_state` annotations). Phase 3b T11 executor shipped without needing runtime state; T13 validate-script writes only persisted fields (`signed_by`, `signature`, `validated`, `sha256`). Neither is a trigger.
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

### T8-Sec3 — Rename `_SCRIPT_PROCESS_BUDGET` / `_BWRAP_HEADROOM` to reflect thread-counting semantics

**Source:** T8 latent-bug fix (commit `7cff916`, 2026-04-19)
**File:** `src/screw_agents/adaptive/sandbox/linux.py`
**Priority:** Low (naming consistency, not correctness)

**Why deferred:** Following the thread-counting bug fix (RLIMIT_NPROC accounts per-UID threads, not processes; `_compute_nproc_cap` was previously counting processes), the constants `_SCRIPT_PROCESS_BUDGET` and `_BWRAP_HEADROOM` semantically quantify thread-budget, not process-budget. Renaming is a cosmetic improvement with zero behavioral impact. Deferred because it's a symbol rename on module-private constants — trivial to do but noisy churn that doesn't carry its own commit weight.

**Trigger:** Any dedicated sandbox-cleanup polish commit, or alongside T8-Sec1 / T8-Sec2 (the other Phase 3c sandbox-hardening deferrals).

**Suggested fix:** Rename to `_SCRIPT_THREAD_BUDGET` and `_BWRAP_THREAD_HEADROOM`. Update docstrings + the inline comment block at lines 90-113 of `linux.py` + the in-function NOTE at the bottom of `_compute_nproc_cap`'s docstring. ~15 LOC diff.

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

### T19-M1 — Surface `merged_from_sources` in SARIF and CSV output
**Source:** Phase 3b T19 (commit `bff35b5`, 2026-04-19)
**File:** `src/screw_agents/formatter.py` `_format_sarif` + `format_csv`
**Priority:** Low — Markdown + JSON are the primary structured paths and both surface the field.

**What's shipped:** Phase 3b T19 adds `merged_from_sources: list[str] | None` to `Finding`. When a finding is the result of an augmentative merge (multiple scan sources detected the same `(file, line_start, cwe)`), the list carries `"<agent> (<severity>)"` entries in input order. Markdown renders a `**Sources:**` line after Description; JSON carries the field via `model_dump()` automatically.

**What is NOT shipped:** SARIF and CSV formatters do not render the field.
- **SARIF** has no natural top-level slot for multi-source attribution. The current SARIF `result` object surfaces a single `tool.driver.rules[]` entry per finding; multi-source would need to go into the `properties` bag (SARIF 2.1 schema allows arbitrary property extensions) or a synthetic `relatedLocations` block.
- **CSV** iterates a fixed column list. Adding a new column would break backward compat for positional parsers (spreadsheet imports, legacy tooling) that expect the current header row.

**Why deferred:** Markdown + JSON cover the primary structured-consumer path:
- Human reviewers read Markdown.
- Phase 4 autoresearch consumes JSON.
- Future SARIF consumers (GitHub Code Scanning, SonarQube) can fall back to the primary's `agent` field; multi-source attribution is useful but not correctness-critical.
- CSV consumers have stable columns today; breaking them for a secondary format is the wrong trade.

**Trigger:** Any of:
- Phase 4 autoresearch uses SARIF output in volume and needs source attribution for ranking/filtering
- A CSV consumer complains about losing source attribution when findings are merged
- Phase 4+ reporting uplift touches both formatters anyway

**Suggested fix:**
1. **SARIF** — embed `merged_from_sources` in the finding's `properties` bag under key `merged_from_sources`. Consumers who understand the bag surface it; others see the primary's `agent` field. This is the SARIF-idiomatic path for tool-specific extensions.
2. **CSV** — append an optional `merged_sources` column AT THE END of the existing column list (appending preserves backward compat for positional parsers that read by index up to the old column count). Empty string for unmerged findings; `"; "`-joined list for merged findings (same separator as other CSV-list fields, comma would collide with CSV delimiter).

**Estimated scope:** ~30 LOC + 2 tests (one SARIF assertion, one CSV assertion). Trivial.

### T19-M2 — Per-source exclusion matching for merged findings

**Source:** Phase 3b T19 quality review, 2026-04-19
**File:** `src/screw_agents/results.py` (exclusion-match call site around line 200)
+ `src/screw_agents/learning.py::match_exclusions`
**Priority:** Medium (pre-existing exclusion-model limitation, newly addressable post-T19)

**What's shipped (T19):** Augmentative merge by `(file, line_start, cwe)`.
Merged primary's `agent` field is the severity-winning source; other
sources listed in `merged_from_sources: list[str]`. `match_exclusions` at
`learning.py:363` still keys strict-equal on `agent`.

**What is NOT shipped:** when a merged finding's primary agent differs
from the exclusion's agent (e.g., user excluded `agent=sqli` but the
merge's primary is now `agent=adaptive_script:qb-check` because adaptive
outranked sqli on severity), the exclusion silently fails to match.
This is a PRE-EXISTING limitation (before T19, the same adaptive finding
would also not have matched the sqli exclusion because they were SEPARATE
findings with different agent labels), but T19 makes it newly ADDRESSABLE
because the structured `merged_from_sources` carries the information
needed to do per-source matching.

**Why deferred from T19:** T19 was scoped as "augmentative merge", not
"exclusion-semantics rework". Per-source exclusion matching is a change
in the exclusion-matching contract, not the merge contract, and deserves
its own review cycle with exclusion-model implications (e.g., what happens
when DIFFERENT sources have DIFFERENT matching exclusions? Does one
override the other? How does `exclusions_applied` in the render result
represent per-source suppression?).

**Trigger:** Any of:
- User reports "I excluded this SQLi finding and it came back" after
  enabling adaptive mode
- Phase 4 autoresearch needs to correlate exclusions with merged findings
- The exclusion-model audit that goes with Phase 4's FP learning loop

**Suggested fix:**
1. In `render_and_write`, when matching a Finding with non-None
   `merged_from_sources`, iterate ALL source agents (parsed from the
   list) and call `match_exclusions` for each. Suppress the finding if
   ANY source matches an exclusion.
2. Dependency on T19-M3: if `merged_from_sources` migrates from
   `list[str]` ("agent (severity)") to `list[dict]` ({"agent": ...,
   "severity": ...}), the per-source iteration becomes cleaner — no
   string parsing.
3. Add regression test: merged finding with agent=A primary,
   merged_from_sources includes agent=B. Exclusion keyed on agent=B
   must suppress the merged finding. Exclusion keyed on agent=A must
   also suppress it.
4. Update `exclusions_applied` in render result to carry the
   matched-source-agent (so downstream consumers understand why the
   merged finding was suppressed).

**Estimated scope:** ~40 LOC in `render_and_write` + per-source
iteration helper + 3 regression tests. Medium complexity due to the
exclusions_applied schema extension.

### T19-M3 — Structured `merged_from_sources` format (list[str] → list[dict])

**Source:** Phase 3b T19 quality review, 2026-04-19
**File:** `src/screw_agents/models.py::Finding.merged_from_sources` +
`src/screw_agents/results.py::_merge_findings_augmentatively` +
`src/screw_agents/formatter.py` (Markdown renderer) + tests

**Priority:** Low (current format works for display + known consumers)

**What's shipped (T19):** `merged_from_sources: list[str] | None` where
each string is formatted as `"<agent> (<severity>)"`. Works for Markdown
display and for JSON consumers who just read the list. Downstream SARIF
emission (T19-M1 deferral) and potential regex-parsing consumers would
find the string format fragile — nested parens in agent names would
break `rsplit(" (", 1)` parsing.

**Why deferred:** Migrating now is strictly an ergonomic improvement
with no current failing consumer. JSON-side structure is stable; the
LIST wrapper is the schema contract, element shape is the
evolvability concern.

**Trigger:** Any of:
- Phase 4 autoresearch consumes `merged_from_sources` and needs
  per-source severity programmatically
- SARIF emission (T19-M1) goes structured via the properties bag
- A consumer reports the format can't roundtrip an edge-case agent name

**Suggested fix:**
1. Change schema to `merged_from_sources: list[MergedSource] | None`
   where:
   ```python
   class MergedSource(BaseModel):
       agent: str
       severity: str
   ```
2. Update merge function to emit `MergedSource(agent=f.agent,
   severity=f.classification.severity)` instead of formatted strings.
3. Update Markdown renderer to format on the fly:
   `", ".join(f"{s.agent} ({s.severity})" for s in f.merged_from_sources)`.
4. Update all 9 T19 tests to expect structured objects (or use helper
   to convert for display assertion).
5. Update T19-M2 (per-source exclusion matching) to iterate structured
   sources rather than parse strings.
6. Backward-compat consideration: existing JSON output consumers who
   parse `list[str]` will break. Because `merged_from_sources` is
   Phase-3b-new, there are no shipped external consumers yet —
   migration has zero user impact right now. Later migration would
   be more expensive.

**Estimated scope:** ~100 LOC across 4 files + 9 test updates +
1 new model. Small PR.

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

### T11-N1 — Signature-path regression test for `execute_script`
**Source:** Phase 3b PR #4 Task 11 quality review (commit `da24076`), 2026-04-18
**File:** `tests/test_adaptive_executor.py`
**Priority:** Medium (Layer 3 integration untested end-to-end)

**Why deferred:** The executor's Layer 3 signature verification
(`verify_script(source, meta, config)`) is currently covered only via the
`skip_trust_checks=True` test gate plus `trust.py`'s existing unit-test
suite for `verify_script` itself. There is NO end-to-end test that
constructs a real Ed25519-signed script + metadata, runs it through
`execute_script(skip_trust_checks=False)`, and asserts `SignatureFailure`
on tampered signature / `AdaptiveScriptResult` on valid signature.
Requires a signing helper that generates a test fixture (private key →
sign script bytes → embed signature in meta YAML). Task 13 (init-trust
CLI) will ship a reusable signing helper which makes the fixture trivial
to write.

**Trigger:** When Task 13 (init-trust CLI) lands a reusable signing helper
OR when a regression in `trust.verify_script` integration is suspected.

**Suggested approach:**
1. Add a pytest fixture that generates an ephemeral Ed25519 keypair via
   `cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PrivateKey.generate()`.
2. Fixture signs a sample script + metadata (via `trust.sign_content` +
   `trust.canonicalize_script`).
3. Fixture seeds `.screw/config.yaml` with the corresponding public key
   as a `script_reviewer`.
4. Two tests: valid-signature happy path + tampered-signature `SignatureFailure`.

**Estimated scope:** ~60 LOC (fixture + 2 tests). Small PR.

### T11-M2 — Opt-in `require_all_target_patterns` metadata flag
**Source:** Phase 3b PR #4 Task 11 quality review (commit `da24076`), 2026-04-18
**File:** `src/screw_agents/adaptive/executor.py` `_is_stale` + `src/screw_agents/models.py` `AdaptiveScriptMeta`
**Priority:** Low (current semantic is acceptable Phase 3b default)

**Why deferred:** `_is_stale` currently returns False as soon as ANY
target_pattern matches at least one call site in the project. A script
declaring three target patterns where only one is present still runs
against "stale context" for the other two patterns. This is the liberal
"best-effort" default appropriate for Phase 3b's adaptive-script
generation model. Some future adaptive scripts may want strict semantics
("only run if ALL patterns still exist") to avoid producing irrelevant
findings against partially-obsolete code.

**Trigger:** When a real-world adaptive script produces noisy findings
because partial target_patterns are out-of-date, OR when autoresearch
(Phase 4) feedback flags the ANY semantic as a false-positive source.

**Suggested approach:**
1. Add `require_all_target_patterns: bool = False` to `AdaptiveScriptMeta`.
2. Update `_is_stale`: if the flag is True, require ALL patterns present
   (not ANY). Default False preserves current behavior.
3. Add a test covering each of the four combinations (flag on/off × patterns
   partial/complete).
4. Document in the adaptive-scripts authoring guide (Task 14+).

**Estimated scope:** ~20 LOC + 4 tests. Trivial.

### T11-N2 — `MetadataError` exception wrapper for meta-load failures
**Source:** Phase 3b PR #4 Task 11 quality review (commit `da24076`), 2026-04-18
**File:** `src/screw_agents/adaptive/executor.py`
**Priority:** Low (code polish, not functional)

**Why deferred:** `execute_script` currently propagates raw `yaml.YAMLError`
(from `yaml.safe_load(meta_path.read_text(...))`) and raw
`pydantic.ValidationError` (from `AdaptiveScriptMeta(**raw)`) to callers.
Both propagate cleanly but break the executor's otherwise-consistent
exception-family design (`LintFailure` / `HashMismatch` / `SignatureFailure`
are all executor-owned `RuntimeError` subclasses). Task 12's MCP tool
wiring will need to catch and surface these; a unified `MetadataError`
wrapper would give that layer a single exception-family to catch.

**Trigger:** When Task 12 implements the MCP tool wiring and needs to
surface meta-load errors cleanly to the subagent caller.

**Suggested approach:**
1. Add `MetadataError(RuntimeError)` to the executor module.
2. Wrap the two error sources in `execute_script`:
   ```python
   try:
       meta_raw = yaml.safe_load(meta_path.read_text(encoding="utf-8"))
   except yaml.YAMLError as exc:
       raise MetadataError(f"invalid YAML in {meta_path}: {exc}") from exc
   try:
       meta = AdaptiveScriptMeta(**meta_raw)
   except ValidationError as exc:
       raise MetadataError(f"malformed metadata in {meta_path}: {exc}") from exc
   ```
3. Task 12's MCP tool handler catches `MetadataError` alongside the
   other 3 executor exception types.
4. Add test `test_executor_wraps_meta_load_errors` that asserts
   `MetadataError` is raised on invalid YAML and on malformed meta.

**Estimated scope:** ~15 LOC + 2 tests. Trivial.

### T16-M1 — Server-side context-required match detection (vs LLM-reported)
**Source:** Phase 3b PR #5 Task 16 implementation, 2026-04-19
**File:** `src/screw_agents/gap_signal.py`, `src/screw_agents/engine.py`
**Priority:** Medium (Phase 4 refinement)

**What's shipped now:** Subagent LLMs call `record_context_required_match` when they investigate a `severity: context-required` pattern and decide not to emit a finding. The scan engine has no independent way to detect context-required matches; it trusts the LLM's self-report. This closes the adaptive E2E loop but puts the onus on the subagent prompt (T18) to be disciplined.

**Why defer to Phase 4:** Server-side detection of context-required pattern matches would require parsing each agent's `detection_heuristics.context_required` patterns, compiling them against scanned source, and recording every match programmatically — independent of LLM reasoning. That's a lot of heuristic-compilation infrastructure (regex vs tree-sitter pattern matching, per-language behavior, false-positive filtering) and belongs with Phase 4's autoresearch scaffolding that already needs pattern-match telemetry.

**Trigger:** When Phase 4 autoresearch scaffolding lands OR when subagent-prompt discipline for `record_context_required_match` proves unreliable in production (measured via the matches-per-scan metric not moving when scans clearly encounter context_required patterns).

**Suggested approach:** Extend `gap_signal.py` with a `compile_heuristic_patterns(agent: AgentDefinition) -> list[CompiledHeuristic]` helper, add `scan_for_context_required_matches(project_root, agent) -> list[ContextRequiredMatch]` that runs at scan time, call alongside the LLM-driven path, and merge into staging with the existing 4-tuple dedup.

**Estimated scope:** ~150-250 LOC + 6-10 tests. Medium. Depends on Phase 4 heuristic-compilation framework.

### T16-M2 — Multi-session context-required match correlation
**Source:** Phase 3b PR #5 Task 16 implementation, 2026-04-19
**File:** `src/screw_agents/staging.py`
**Priority:** Low (deferred unless cross-session analytics prove useful)

**What's shipped now:** `context_required_matches.json` is strictly per-session. Each scan's matches are consumed at finalize and deleted. There's no cross-session retention or correlation.

**Why defer:** Cross-session correlation (e.g., "this file has had a context-required match on line 42 across 3 scans — promote to persistent watchlist") is an analytics layer, not a coverage-gap-signal layer. Likely belongs alongside `learning/exclusions.yaml` as a second learning artifact once the autoresearch loop (Phase 4) is live. Premature work without clear Phase 4 semantics.

**Trigger:** When autoresearch (Phase 4) needs historical context-required match telemetry as a signal input, OR when a user asks for a "chronic gap" report similar to `aggregate_learning`'s FP report.

**Suggested approach:** New `.screw/learning/context_required_history.yaml` written at finalize (mirroring the `exclusions.yaml` stable-artifact pattern), one `ScanEngine.aggregate_context_required_patterns` method for chronic-gap reporting, never auto-deleted.

**Estimated scope:** ~100 LOC + 5 tests. Small. Can be implemented independently of autoresearch when/if the use case materializes.

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

---

## Phase 3b PR #5 round-trip test findings (2026-04-20)

Round-trip manual testing of `/screw:scan sqli src/ --adaptive` on a seeded QueryBuilder fixture surfaced one Critical architectural defect and four Important quality issues. C1 is tracked below as a Phase 3b-follow-up PR ship-blocker (must be fixed before adaptive mode is considered production-safe). I1-I4 + Minor are polish/hardening items that don't block PR #5's infrastructure value.

### C1 — CRITICAL: Human-approval flow regenerates script after approval (trust violation)

**Source:** Phase 3b PR #5 manual round-trip test, 2026-04-20
**File:** `plugins/screw/agents/screw-*.md` (adaptive-mode sections, 5 per-agent files + orchestrator), `plugins/screw/commands/scan.md`
**Priority:** **BLOCKER — must fix before adaptive mode is production-safe**

**What's shipped (broken):** T18b's subagent prompts assume the generating subagent pauses at the 5-section review, waits for user input (`approve <script-name>` / `reject <script-name>`), then continues into sign+execute. In Claude Code's architecture, subagents run to completion — they cannot pause. When the user types `approve`, the main session reports *"SendMessage isn't exposed in this session, so I'll resume the scan by spawning a fresh subagent with the approval decision and full script context"* and re-runs the pipeline from scratch. The fresh subagent's LLM regenerates a DIFFERENT adaptive script (confirmed empirically: script v1 used `read_source` + `find_calls(tree, method=...)`; script v2 used `parse_module` — completely different source). **The regenerated script is the one that gets signed and executed, NOT the one the human reviewed.** Layer 0d semantic review + 5-section human review both presupposed the approved source EQUALS the executed source. That invariant is broken.

**Why this is a ship-blocker:** a trusting user running `/screw:scan sqli src/ --adaptive` believes their approval decision applies to the source they read. In reality, LLM non-determinism means they're implicitly approving an unknown variant. Malicious target code could even exploit this: craft code where the "reviewed" script looks benign but a regeneration produces a variant with a subtle bypass. Defense-in-depth layers (1 AST lint, 2 SHA hash pin, 3 signature) all operate on the signed content — but the signing is done AFTER regeneration, so hash/signature match the regenerated content, not the reviewed content.

**Trigger:** Before the `/screw:scan ... --adaptive` flow is considered production-ready. This is the Phase 3b follow-up immediately after PR #5 merges.

**Suggested fix — staging architecture:**
1. Add new MCP tool `stage_adaptive_script(project_root, source, meta) -> {stage_id, stage_path}` that writes the unsigned script to `.screw/staging/{session_id}/adaptive-scripts/<stage_id>.{py,meta.yaml}` atomically.
2. Update T18b's subagent prompt: the generating subagent STAGES the script BEFORE composing the 5-section review. The review includes the `stage_id` as part of the script_name shown to the user.
3. Replace `sign_adaptive_script(source, meta, ...)` signature with `sign_staged_script(stage_id, ...)` OR keep both and make the subagent prompt specify which path to use. Signing path READS from staging + promotes to `.screw/custom-scripts/` — no source parameter means no regeneration possible.
4. Reject path: `reject <stage_id>` deletes the staging file. Separate from main approve path.
5. Cleanup: staging files orphan if user never approves/rejects — include in `/screw:adaptive-cleanup` stale-orphan sweep (Phase 4+ or a dedicated T-STAGING-ORPHAN-GC variant).

**Alternative (Option B) accepted during triage:** Document C1 as known experimental-mode limitation with loud warnings in the slash command + subagent prompts. Not recommended — the trust model being silently broken is worse than being feature-gated.

**Estimated scope:** 1-2 focused sessions. ~500-800 LOC across new MCP tool, staging module, T18b subagent prompts (5 per-agent files + orchestrator), tests (staging semantics + round-trip regression). Plan-sync + DEFERRED_BACKLOG cleanup on merge.

### I1 — Layer 0d screw-script-reviewer subagent not invoked (plugin-namespace bug)

**Source:** Phase 3b PR #5 manual round-trip test, 2026-04-20
**File:** `plugins/screw/agents/screw-sqli.md` (and screw-cmdi/ssti/xss identical-section copies) — the Task tool invocation in Step 3.5d-F
**Priority:** Important (Layer 0d defense gate is inactive — but framed as advisory-only per T17 design, not a security boundary)

**What's shipped:** T18b's per-agent subagent prompt invokes the Task tool with `subagent_type: "screw-script-reviewer"` (bare name). Claude Code registers the reviewer subagent under the plugin namespace as `screw:screw-script-reviewer` (verified via `/agents` during Step 4). The Task tool doesn't resolve the bare name — the subagent reports *"screw-script-reviewer subagent unavailable in this session"* and falls through with `semantic_review = not-run` in the 5-section review. The user sees the "not-run" status surfaced (good UX) but Layer 0d review is effectively inactive.

**Trigger:** Bundle with the C1 fix (same 5 T18b subagent files + orchestrator need editing).

**Suggested fix:** Change `subagent_type: "screw-script-reviewer"` to `subagent_type: "screw:screw-script-reviewer"` across all 5 per-agent subagent `.md` files. Add a format-smoke test asserting the namespace prefix is present. Verify via manual round-trip that Layer 0d fires.

**Estimated scope:** ~20 LOC across 5 prompt files + 1 test + manual verification. Trivial once C1's staging work is underway (same file set).

### I2 — Layer 1 AST lint doesn't validate imported SYMBOLS against adaptive.__all__

**Source:** Phase 3b PR #5 manual round-trip test, 2026-04-20
**File:** `src/screw_agents/adaptive/lint.py`
**Priority:** Important (defense-in-depth gap; executor catches this at runtime but too late for the review flow)

**What's shipped:** Layer 1 AST allowlist lint at `adaptive/lint.py` verifies imports come from `screw_agents.adaptive` (the MODULE) or Python stdlib. It does NOT verify that imported SYMBOLS are members of `screw_agents.adaptive.__all__`. An LLM-hallucinated import like `from screw_agents.adaptive import read_source` (where `read_source` isn't in `__all__`) passes lint (module is allowed) but fails at execution with `ImportError`. Confirmed empirically in the round-trip: the generated script imported `read_source` (and later `parse_module`), lint passed, sandbox reported `returncode=1` + 0 findings.

**Trigger:** Any of: (a) a dedicated Layer 1 hardening commit, (b) an E2E test that specifically probes the gap, (c) a user-reported frustration about "my adaptive script passed lint but fails at execution with cryptic ImportError".

**Suggested fix:**
1. In `lint.py`, parse `screw_agents.adaptive.__init__.py`'s `__all__` at lint time (cached — it's stable for the lifetime of the process).
2. For each `from screw_agents.adaptive import <name>` statement, verify `<name>` is in the cached `__all__`. Report a lint violation naming the unrecognized symbol.
3. Edge case: `import screw_agents.adaptive as X` + `X.unknown` — harder to catch at AST level; accept as follow-up.
4. Add test cases: `test_lint_rejects_unknown_import_symbol` + the positive-control equivalent.

**Estimated scope:** ~40 LOC + 3-4 tests. Small PR.

### I3 — Sandbox execution stderr not surfaced on failure

**Source:** Phase 3b PR #5 manual round-trip test, 2026-04-20
**File:** `src/screw_agents/adaptive/executor.py` + `src/screw_agents/adaptive/sandbox/linux.py` + the subagent prompt that renders execution results
**Priority:** Important (UX/debugging impact — a failed adaptive script returns "returncode=1, 0 findings, no stderr surfaced" giving the user nothing to diagnose)

**What's shipped:** The round-trip observed `execute_adaptive_script` returning a failure result with `returncode=1, wall_clock_s=73ms, killed_by_timeout=False` but the subagent's rendering said *"no stderr surfaced"*. The broken script (import error) would have produced a Python `ImportError` traceback to stderr — but the subagent either didn't receive it OR the subagent's output-render-template didn't include stderr field.

**Trigger:** Bundle with Phase 3c sandbox hardening (alongside T8-Sec1/Sec2/Sec3) OR as a dedicated UX fix.

**Suggested fix:**
1. Trace: does `sandbox/linux.py::run_in_sandbox` capture stderr? (It should — verified via `subprocess.run(..., capture_output=True)`.)
2. Trace: does `executor.py::execute_script` pass stderr through to `SandboxResult.stderr` cleanly?
3. Trace: does the subagent prompt (T18b's Step 3.5d-H sub-step 3) surface stderr when returncode != 0? If not, add it: "On execution failure, render `f.stderr.decode('utf-8', errors='replace')` in a fenced block so the user sees the diagnostic."
4. Add a round-trip-style test where a deliberately-broken script (bad import) is signed + executed, and assert the subagent's rendered output contains the ImportError text.

**Estimated scope:** ~30 LOC across executor/sandbox pass-through + subagent prompt render-on-failure branch + 1 test. Small.

### I4 — Failed adaptive script stays on disk at .screw/custom-scripts/ after execution failure

**Source:** Phase 3b PR #5 manual round-trip test, 2026-04-20
**File:** `plugins/screw/agents/screw-*.md` (execute-failure path in Step 3.5d-H)
**Priority:** Minor (current behavior is defensible — user can inspect the failed script; `/screw:adaptive-cleanup remove` gives them removal UX)

**What's shipped:** When `execute_adaptive_script` returns a failure result, the subagent's prompt (Step 3.5d-H) surfaces the failure message to the user and moves to the next gap OR to finalize. The signed `.py` + `.meta.yaml` pair remains on disk at `.screw/custom-scripts/<script_name>.py`. Future scans will count it as `script_active_count=1` in `verify_trust` (it IS validly signed) and `list_adaptive_scripts` will report it (with `stale=False` if `target_patterns` still matches).

**Design question:** is this the right behavior?
- **Arguments for keeping:** user can inspect the script to understand the bug, re-run manually, OR use `/screw:adaptive-cleanup remove` to delete it. The trust/cleanup surfaces handle it cleanly.
- **Arguments for auto-deleting:** a failed-at-execution script has zero utility and clutters the directory. A "Broken adaptive script removed automatically — check the execution log if you need to investigate" message is cleaner UX.

**Recommendation:** document the current keep-on-disk behavior explicitly in `/screw:adaptive-cleanup`'s help text and the 5-section review's post-execution wrap-up. Add a hint: "Execution failed — script retained at `.screw/custom-scripts/<name>.py` for inspection. Run `/screw:adaptive-cleanup remove <name>` to clear it." No code change; just prompt+docs.

**Estimated scope:** ~10 LOC across subagent prompts + command docstring. Trivial.

### I5-Minor — Prompt engineering to reduce LLM API hallucination

**Source:** Phase 3b PR #5 manual round-trip test, 2026-04-20
**File:** `plugins/screw/agents/screw-*.md` Step 3.5d-C generation-prompt template
**Priority:** Low (LLM non-determinism is fundamental; this is partial mitigation)

**What's shipped:** T18b's Step 3.5d-C generation-prompt paraphrase tells the LLM *"Import ONLY from `screw_agents.adaptive` and Python standard library."* It lists the 18 export names in the prompt section at lines 96-111 of the per-agent subagent files. The LLM STILL hallucinated `read_source` (not in the list) and `parse_module` (also not in the list). This suggests the current listing is not visually prominent enough during generation OR the LLM deprioritized it.

**Trigger:** Bundle with the C1 fix (prompt engineering already being iterated).

**Suggested fix:**
1. In the generation prompt (not just the reference section), embed the 18-export list AS the allowlist the LLM must use: *"You MUST use ONLY these 18 functions from screw_agents.adaptive: [list]. Any import of a name NOT in this list is a HARD FAIL — the AST lint will reject and execution will never happen."*
2. Add a negative examples block: *"Do NOT invent helper names like `read_source`, `parse_module`, `walk_module` — these don't exist. If you need to read a file, use `project.read_file(path)` via ProjectRoot. If you need to parse Python, use `parse_ast(source, language='python')`."*
3. Consider: generate script with a constrained LLM-as-compiler pattern where allowed names are tokenized/validated before emission. Out of scope for a prompt fix but worth noting.

**Estimated scope:** ~30 LOC of prompt content across 5 per-agent subagent files. Small but repetitive — may motivate extraction to a shared template if the discipline gets tedious (but Claude Code subagent isolation makes shared templates structurally hard; see the T18b byte-identical-section pattern).

### I6 — `adaptive-cleanup.md` `uv run python -c` fails when cwd ≠ worktree

**Source:** Phase 3b PR #5 manual round-trip Steps 7-9, 2026-04-20
**File:** `plugins/screw/commands/adaptive-cleanup.md` (both list + remove action Bash blocks)
**Priority:** Important (command broken out-of-box for the intended use case — user's project is outside the screw-agents install; LLM recovers but shouldn't have to)

**What's shipped:** The slash command's backend invocation is `uv run python -c "from screw_agents.cli.adaptive_cleanup import ..."` without `--project`. When the user's project is outside the screw-agents install directory (the normal case — users don't run scans INSIDE the screw-agents worktree), `uv run` walks up from cwd looking for `pyproject.toml`, finds none, creates an ephemeral project, and fails with `ModuleNotFoundError: No module named 'screw_agents'`.

**Observed empirically in round-trip:** Marco's test session cwd was `/tmp/screw-roundtrip-qb/`. First `/screw:adaptive-cleanup` invocation produced `ModuleNotFoundError`. The LLM controller recovered by `cd`'ing into the screw-agents worktree at `/home/marco/Programming/AI/screw-agents/.worktrees/phase-3b-pr5` first, then running `uv run python -c "..."` there but passing the test project path as arg to `list_adaptive_scripts(Path('/tmp/screw-roundtrip-qb').resolve())`. Graceful recovery but brittle — depends on LLM finding the worktree path via filesystem search and adapting the command.

**Trigger:** Bundle with C1's subagent prompt rework (same file set) OR as a standalone command-spec polish commit.

**Suggested fix:** Replace both Bash blocks in `adaptive-cleanup.md` (list + remove) with an invocation that's location-agnostic:

```bash
uv --project "$(python3 -c 'import screw_agents; import os; print(os.path.dirname(os.path.dirname(os.path.dirname(screw_agents.__file__))))')" run python -c "..."
```

Or simpler — rely on `UV_PROJECT_ENVIRONMENT` / `UV_PROJECT` env vars documented in the command body AND/OR make the MCP-tool-based path the primary. Better yet: expose `list_adaptive_scripts` / `remove_adaptive_script` as proper MCP tools via `engine.py` + `server.py` so the slash command goes through the MCP server (which already has the correct `--project` configured in `.mcp.json`). This matches the pattern of `sign_adaptive_script` / `detect_coverage_gaps` etc. — no `uv run` subshell needed.

**Related root cause:** same class of issue as the `.mcp.json` fix we applied during Step 4 of the round-trip (adapted the MCP server config to use `uv --project <worktree>` so cwd-independence works). The slash command's Bash backend needs the same treatment.

**Estimated scope:** ~10 LOC of markdown change if keeping Bash subshell; ~80 LOC if promoting list/remove to proper MCP tools (recommended — consistent architecture).

**Round-trip steps that passed despite the bug:** Steps 7 (list, not-stale), 8 (list, stale), 9 (remove + confirm gate) all completed correctly after LLM recovery. The adaptive-cleanup backend logic itself is sound — it's only the command-invocation envelope that needs fixing.

### Round-trip test validation summary (2026-04-20)

Despite C1 (adaptive-mode approval flow broken) and I1-I6 (six smaller findings), the round-trip manual tests confirmed the following PR #5 subsystems work correctly:

**Confirmed working:**
- Trust infrastructure end-to-end (init-trust → validate-script / sign_adaptive_script → verify_script at execution-time Layer 3). Signature round-trip passes.
- MCP tool layer: `scan_sqli`, `record_context_required_match`, `accumulate_findings`, `detect_coverage_gaps`, `lint_adaptive_script`, `sign_adaptive_script`, `execute_adaptive_script`, `finalize_scan_results` — all fire correctly with session_id threading intact.
- YAML finding rendering with `coverage_gaps` field in finalize response (T16).
- Augmentative merge infrastructure (T19) — exercised in T22 unit test; not hit at runtime during round-trip because the adaptive script failed before producing findings.
- T21 `list_adaptive_scripts` with per-script stale detection: toggles `not stale` → `⚠ stale — 0 of N target_patterns match call sites: <patterns>` correctly when target_patterns call sites are removed.
- T21 `remove_adaptive_script` with MANDATORY confirmation gate. Exact-match "yes" required; `.py` + `.meta.yaml` atomically removed.
- T21 slash-command rendering: `signing: ✓ signed (by <email>)`, `⚠ stale — <reason>`, discoverability prompt for stale scripts, all fire as specified.

**Broken (blocks adaptive-mode production use):**
- C1 — approval flow regenerates script after "approve"; user reviews v1, signs+executes v2. Trust model violation.

**Defects that degrade but don't block:**
- I1 — Layer 0d reviewer not invoked (plugin namespace bug in Task subagent_type)
- I2 — Layer 1 lint doesn't validate imported symbols against adaptive.__all__
- I3 — execute failure surfaces "no stderr" instead of the actual ImportError traceback
- I4 — failed adaptive scripts retained on disk (documentation-only fix)
- I5 — LLM hallucinates API names despite prompt listing exports
- I6 — adaptive-cleanup.md `uv run` fails when cwd ≠ worktree (LLM recovers)

**PR #5 merge recommendation:**
Ship Option A per the initial triage:
1. Merge PR #5 as-is to preserve the 770+ tests and infrastructure value (T13-T22 + sandbox fix).
2. Gate adaptive-mode with a loud experimental warning in the slash command body — see commit messages for suggested wording.
3. Track C1 as the immediate next follow-up PR before promoting adaptive mode to production-ready. Staging architecture is the fix.
4. I1-I6 can batch into the same C1-fix PR (most touch the same file set) or land as a standalone polish PR.

---

## Phase 3b PR #6 follow-ups (Opus re-review polish)

> Items surfaced by the Opus 4.7 re-review of T1 + T2 on 2026-04-21. All are cosmetic polish or test-coverage gaps that don't block C1 trust-path correctness (which is proven by the 817-test suite + C1 regression test `test_sign_output_passes_executor_verification`). Scheduled for picking up during the next polish sweep, next test-hygiene sweep, or a dedicated cleanup commit.

### BACKLOG-PR6-01 — Nested `TargetGap` TypedDict inside `PendingApproval.target_gap`
**Source:** Phase 3b PR #6 T1 Opus re-review (I-opus-4), 2026-04-21
**File:** `src/screw_agents/models.py` — `PendingApproval` TypedDict
**Why deferred:** Cosmetic typing improvement; no runtime impact. `target_gap: dict` with an inline comment documenting shape (`{type, file, line, agent}`) works at runtime but skips static type checking. The rest of `models.py` uses nested TypedDicts/BaseModels consistently — this is one departure.
**Trigger:** Next polish pass touching `models.py`, OR before Phase 4 autoresearch if it consumes `target_gap` programmatically and wants static guarantees.
**Suggested approach:** Define `class TargetGap(TypedDict): type: str; file: str; line: int; agent: str` and change `target_gap: dict` to `target_gap: TargetGap`. Update test-fixture dicts to conform.
**Estimated scope:** ~15 LOC + 1 test.

### BACKLOG-PR6-02 — Nested TypedDicts for `StaleStagingReport.scripts_removed` and `.tampered_preserved`
**Source:** Phase 3b PR #6 T1 Opus re-review (I-opus-5), 2026-04-21
**File:** `src/screw_agents/models.py` — `StaleStagingReport` TypedDict
**Why deferred:** Same as BACKLOG-PR6-01. `list[dict]` with a trailing shape comment compiles but doesn't enforce keys. These fields are the return shape for `sweep_stale_staging` landing in T6; typed shape matters when CLI or autoresearch consumes the report.
**Trigger:** T6 implementation (`sweep_stale_staging` engine method) — natural point to tighten since the code producing these dicts is being written.
**Suggested approach:** Define `class RemovedScriptEntry(TypedDict)` with `script_name, session_id, reason, age_days` and `class TamperedPreservedEntry(TypedDict)` with `script_name, session_id, evidence_path, age_days`. Change the two `list[dict]` fields to use these types.
**Estimated scope:** ~25 LOC + 1 test.

### BACKLOG-PR6-03 — Rollback test asserts meta_tmp cleanup
**Source:** Phase 3b PR #6 T1 Opus re-review (M-opus-1), 2026-04-21
**File:** `tests/test_adaptive_staging.py` — `test_write_staged_files_rolls_back_py_on_meta_failure`
**Why deferred:** Test coverage gap. The rollback loop in `write_staged_files` iterates `(meta_tmp, py_path)`, but the test only asserts `.py` absence. `meta_tmp` cleanup is load-bearing for disk-state hygiene on restart. Currently verified empirically but not asserted in the test.
**Trigger:** Next test-coverage sweep.
**Suggested approach:** Add two assertions to the existing rollback test:
```python
assert not (stage_dir / "test-script.meta.yaml.tmp").exists()
assert list(stage_dir.iterdir()) == []
```
**Estimated scope:** 2-3 LOC.

### BACKLOG-PR6-04 — UTF-8 / CRLF / long-content round-trip test for staging.py
**Source:** Phase 3b PR #6 T1 Opus re-review (M-opus-2), 2026-04-21
**File:** `tests/test_adaptive_staging.py`
**Why deferred:** Current `test_read_staged_files_returns_str_roundtrip` uses pure-ASCII content. A unicode / CRLF / long-content round-trip would guard against someone swapping `Path.write_text(encoding="utf-8")` for a lossy encoder or forgetting the explicit encoding argument.
**Trigger:** Next test-coverage sweep.
**Suggested approach:** Add a test that writes a source containing unicode (`"# café\nprint('ünîcôdé')\n"`), CRLF line endings, and content >PIPE_BUF (e.g., 8KB), then reads back and asserts byte-identical.
**Estimated scope:** ~20 LOC.

### BACKLOG-PR6-05 — Valid-edge-cases test writes into same dir across iterations
**Source:** Phase 3b PR #6 T1 Opus re-review (M-opus-3), 2026-04-21
**File:** `tests/test_adaptive_staging.py` — `test_write_staged_files_accepts_valid_script_name_edge_cases`
**Why deferred:** Minor test quality — the test writes 4 names sequentially into the same `session_id` dir. `os.replace` is overwrite-atomic so the test passes, but it doesn't fully test iteration independence. Refactoring to parametrize or separate tmp_path per iteration would make the test cleaner.
**Trigger:** Next test-coverage sweep.
**Estimated scope:** ~5 LOC refactor.

### BACKLOG-PR6-06 — `staging.py` module docstring event-type list scope clarification
**Source:** Phase 3b PR #6 T1 Opus re-review (M-opus-4), 2026-04-21
**File:** `src/screw_agents/adaptive/staging.py` — module-level docstring (lines 1-32)
**Why deferred:** The docstring lists registry event types (`staged`, `promoted`, `rejected`, `tamper_detected`, `swept`, etc.) as if registry-write is part of this module. T1 only provides `resolve_registry_path`; append/query land in T3, sweep in T6. A one-line note ("Event-type catalog listed here for reference; append/read lands in T3, sweep in T6") would prevent reader confusion.
**Trigger:** Next docstring polish pass OR after T3 lands (when the module actually implements registry write — the event-type list would then be authoritative).
**Estimated scope:** 1-2 line docstring clarification.

### BACKLOG-PR6-07 — `test_public_api_count_is_under_29` function-name / assertion inconsistency
**Source:** Phase 3b PR #6 T2 Opus re-review (M-2), 2026-04-21
**File:** `tests/test_adaptive_public_api.py`
**Why deferred:** Function `test_public_api_count_is_under_29` asserts `public_count <= 28` (mathematically equivalent for integers but visually jarring). Docstring says "Over 28 is a red flag." Rename to `test_public_api_count_is_at_most_28` OR change assertion to `< 29` for consistency.
**Trigger:** Next test-hygiene sweep.
**Estimated scope:** 1-line rename or assertion style change.

### BACKLOG-PR6-08 — `adaptive/__init__.py` stale "under 25 exports" docstring
**Source:** Phase 3b PR #6 T2 Opus re-review (M-3), 2026-04-21
**File:** `src/screw_agents/adaptive/__init__.py`
**Why deferred:** Module docstring claims "under 25 exports" but `EXPECTED_PUBLIC_API` curated set has 18 entries; total `dir(adaptive)` after T1+T2 is 28 (18 curated + 10 internal submodule bindings). Docstring has been drifting since T18a added `signing`; T1 + T2 each added a submodule without refreshing the claim.
**Trigger:** Next docstring polish pass OR whenever editing `adaptive/__init__.py`.
**Suggested replacement:** "(18 curated exports in EXPECTED_PUBLIC_API; total `dir(adaptive)` includes ~10 internal submodule bindings)".
**Estimated scope:** 2-3 line docstring update.

### BACKLOG-PR6-14 — `append_registry_entry` `fsync` omission rationale
**Source:** Phase 3b PR #6 T3 Opus re-review (M1), 2026-04-21
**File:** `src/screw_agents/adaptive/staging.py` — `append_registry_entry`
**Why deferred:** Current `os.write` is followed by `os.close` with no `os.fsync`. On a power-loss between write and kernel flush, the registry entry is lost. The staged `.py` + `.meta.yaml` remain, so T6 sweep reconciles — but the contract isn't documented in the function docstring. Either add `os.fsync(fd)` before close (perf cost, correct for forensic audit log) OR document the sweep-reconciles rationale.
**Trigger:** When deployment moves beyond single-process dev workflow, OR when a forensic incident requires stronger durability.
**Suggested fix:** Add a one-line comment and optionally `os.fsync(fd)` before `os.close(fd)`. If adding fsync, mirror the same call pattern in any future registry writers (promote, reject, sweep).
**Estimated scope:** 2 LOC + 1 comment + 1 optional test.

### BACKLOG-PR6-15 — `session_id_short = session_id[:12]` magic number
**Source:** Phase 3b PR #6 T3 Opus re-review (M2), 2026-04-21
**File:** `src/screw_agents/engine.py` — `stage_adaptive_script`
**Why deferred:** The 12-char prefix is chosen to match the review header display format (plan spec §3.1). Code has no comment explaining the choice. Future reader wonders "why 12".
**Trigger:** Next docstring polish pass OR when the review header format changes.
**Suggested fix:** Add a one-line comment: `# 12 chars = display-friendly session prefix for the T18b review header`.
**Estimated scope:** 1 LOC comment.

### BACKLOG-PR6-16 — Collision check ignores meta content
**Source:** Phase 3b PR #6 T3 Opus re-review (M3), 2026-04-21
**File:** `src/screw_agents/engine.py` — `stage_adaptive_script` collision-check
**Why deferred:** Idempotency check compares source `sha256` only. If source matches but meta differs, the existing meta file is silently overwritten. Defensible (only source bytes get signed and executed) but a caller expecting meta-divergence to be an error may be surprised.
**Trigger:** If a user reports surprising re-stage behavior when they changed meta but kept source, OR a security reviewer flags this as a tamper channel.
**Suggested fix:** Either (a) document the behavior explicitly in the docstring: "Meta differences are silently overwritten on re-stage; only source bytes participate in the collision check." — OR (b) hash `(source, meta_yaml)` together for the collision check (stricter, but breaks idempotency when callers legitimately update meta).
**Estimated scope:** 3-5 LOC docstring OR ~15 LOC behavioral change + test.

### BACKLOG-PR6-17 — `staging.py` module docstring event-type list is forward-looking
**Source:** Phase 3b PR #6 T3 Opus re-review (M4), 2026-04-21
**File:** `src/screw_agents/adaptive/staging.py` — module docstring
**Why deferred:** The docstring enumerates 7 event types (`staged`, `promoted`, `promoted_via_fallback`, `promoted_confirm_stale`, `rejected`, `tamper_detected`, `swept`). At commit `a568f56`, only `staged` has a producer. T4 adds `promoted` variants + `tamper_detected`; T5 adds `rejected`; T6 adds `swept`. A reader confused by the gap would be helped by "(T3 produces: staged; T4-T6 produce the rest)".
**Trigger:** After T6 ships (when all producers exist) OR next docstring polish pass.
**Suggested fix:** Either add the scope-clarifying comment, or wait until T6 when the comment becomes authoritative.
**Estimated scope:** 1-2 line docstring update.

### BACKLOG-PR6-18 — Parametrize redundant slash cases
**Source:** Phase 3b PR #6 T3 Opus re-review (M5), 2026-04-21
**File:** `tests/test_adaptive_staging.py` — `test_stage_adaptive_script_rejects_threat_session_ids`
**Why deferred:** Parametrize includes both `"../etc/passwd"` and `"foo/bar"` — both exercise the slash character-class rejection. Harmless duplication (each would catch a regression independently). Could be consolidated to one slash test OR kept as both (each represents a distinct threat model: traversal attempt vs generic path separator).
**Trigger:** Next test-hygiene sweep.
**Estimated scope:** 1-line parametrize removal OR 2-line rationale comment clarifying why both.

### BACKLOG-PR6-19 — `confirm_sha_prefix` entropy (8 hex chars = 32 bits)
**Source:** Phase 3b PR #6 T4 pre-audit (C2), 2026-04-21
**File:** `src/screw_agents/engine.py` — `promote_staged_script` fallback path
**Why deferred:** The fallback-path confirmation phrase uses `script_sha256[:8]` (8 hex chars = 32 bits of entropy). Birthday-collision attack threshold is ~65,536 attempts. Not exploitable in practice — the UX is "user already typed approve {name} once; now re-typing a modified phrase" and the attacker must also overwrite the staging .py with matching source. But 32-bit entropy on a security-relevant confirmation is light.
**Trigger:** Next security-review sweep of the approve flow, OR if a real-world incident suggests the fallback path needs stronger confirmation.
**Suggested fix:** raise to 12 hex chars (48 bits, ~17M attempts for birthday) OR use a longer prefix (16 chars = 64 bits). Test + prompt text + docstring update + ~5 LOC.
**Estimated scope:** 10 LOC + 1-2 tests + prompt text updates in `plugins/screw/agents/screw-*.md`.

### BACKLOG-PR6-20 — `invalid_staged_meta` does not write TAMPERED marker
**Source:** Phase 3b PR #6 T4 pre-audit (C5), 2026-04-21
**File:** `src/screw_agents/engine.py` — `promote_staged_script` invalid-meta branch
**Why deferred:** When `yaml.safe_load(meta_yaml)` fails (line ~2151-2157), promote returns `invalid_staged_meta` but does NOT touch the filesystem — no TAMPERED marker, no audit event. A tampered meta is arguably the same class of threat as a tampered .py (both invalidate the staging contract), so asymmetric treatment is defensible but not obviously correct.
**Trigger:** If an attacker is observed targeting .meta.yaml specifically (rather than .py), OR next trust-path threat-model refresh.
**Suggested fix:** on `yaml.YAMLError`, touch a `.METATAMPERED` marker + append a `meta_tampered` (or reuse `tamper_detected` with an evidence_type field) audit event. Same forensic-preservation pattern as the sha-mismatch tamper path.
**Estimated scope:** 15 LOC + 1 test.

### BACKLOG-PR6-21 — Fallback-path UX: reviewer-responsibility disclaimer
**Source:** Phase 3b PR #6 T4 Opus re-review (I-opus-3), 2026-04-21
**File:** `src/screw_agents/engine.py` — `promote_staged_script` fallback-path error message
**Why deferred:** The `fallback_required` response message hands the user the sha prefix and instructs them to paste it back. A user who did not personally review the staged bytes can copy-paste their way to a confirm. This is a design tradeoff (Q3 spec accepted) rather than a vulnerability, but the UX should explicitly name the reviewer's responsibility.
**Trigger:** Next UX polish pass on the approve-flow slash commands, OR if a user reports confusion / a post-incident review flags the UX.
**Suggested fix:** append to the fallback message body: "You are confirming the staging bytes' sha matches what you reviewed at stage time. If you did not personally review these bytes, run `reject` instead."
**Estimated scope:** ~5 LOC message text change + 1 format-smoke test assertion update.

### BACKLOG-PR6-22 — `sign_adaptive_script` retirement / C1-closure migration
**Source:** Phase 3b PR #6 T4 Opus re-review (I-opus-2), 2026-04-21
**File:** `src/screw_agents/engine.py` — `sign_adaptive_script`; `src/screw_agents/server.py` dispatcher; `plugins/screw/agents/screw-{sqli,cmdi,ssti,xss}.md` subagent prompts
**Why deferred:** T4 closed C1 for the staged-path approve flow via `promote_staged_script`. The direct `sign_adaptive_script` MCP tool still accepts `source` / `meta` arguments — the regeneration vector at the MCP boundary. Fully closing C1 requires: (a) migrating subagent prompts to always use stage→promote, (b) retiring or dev-gating the direct-sign path, (c) updating the autoresearch hook (BACKLOG-PR6-13) to the staged path as well.
**Trigger:** After subagent prompt migrations ship (T15-T17), AND autoresearch scaffolding uses staged path.
**Suggested approach:** Phased retirement — (1) add deprecation warning to `sign_adaptive_script` responses pointing to the staged path; (2) remove from default tool set, keep as `screw-agents migrate-sign` CLI for legacy flows; (3) eventually delete.
**Estimated scope:** ~50 LOC deprecation shim + multi-file prompt migrations + tests + release notes.

### BACKLOG-PR6-23 — Tamper-path `append_registry_entry` failure handling
**Source:** Phase 3b PR #6 T4 Opus re-review (I-opus-5), 2026-04-21
**File:** `src/screw_agents/engine.py` — `promote_staged_script` tamper branch
**Why deferred:** If `append_registry_entry(tamper_entry)` fails (filesystem error) during tamper handling, the marker file is touched but the audit event is missing, and the `ValueError` escapes before the caller receives the tamper-detected error-dict. Tamper path is rare but critical; slightly more resilient surface is defensible.
**Trigger:** If a real-world incident shows a tamper case followed by a registry-write failure leaving ops with incomplete forensic evidence, OR next trust-path polish pass.
**Suggested fix:** wrap `append_registry_entry(tamper_entry)` in try/except ValueError; log the append failure (stderr / warn) but still return the tamper-detected error-dict with marker path.
**Estimated scope:** ~10 LOC + 1 monkey-patch test.

### BACKLOG-PR6-24 — Promoted-audit append failure rationale comment
**Source:** Phase 3b PR #6 T4 Opus re-review (I-opus-4), 2026-04-21
**File:** `src/screw_agents/engine.py` — `promote_staged_script` success path (after sign + delete)
**Why deferred:** The final `append_registry_entry(promoted_entry)` at the end of promote is intentionally NOT wrapped — filesystem errors escape loud for ops to see. But the symmetry with the Step 8 swallowed-delete comment would help future readers; add an explicit comment documenting the choice.
**Trigger:** Next docstring polish pass.
**Suggested fix:** add a 3-line comment: "Step 9: append promoted audit event. If this raises, the sign already succeeded (custom-scripts is ground truth); the missing audit entry is recoverable by reconciling custom-scripts/ against the registry. We do NOT swallow here — ops needs to see the filesystem error loudly."
**Estimated scope:** 3 LOC comment.

### BACKLOG-PR6-25 — Lazy imports style consistency in `promote_staged_script`
**Source:** Phase 3b PR #6 T4 Opus re-review (I-opus-6), 2026-04-21
**File:** `src/screw_agents/engine.py` — `promote_staged_script` method body
**Why deferred:** `promote_staged_script` imports `yaml`, `datetime`, and staging/signing helpers inside the method body. Other engine methods (e.g., `stage_adaptive_script` as implemented in T3) keep these at module scope. Style inconsistency; not a correctness issue. No circular-import concern visible.
**Trigger:** Next readability polish pass, OR if a contributor trips over the inconsistent style.
**Suggested fix:** hoist lazy imports to module scope; verify no circular imports introduced.
**Estimated scope:** ~15 LOC import consolidation + verification.

### BACKLOG-PR6-26 — Future-dated `staged_at` test coverage
**Source:** Phase 3b PR #6 T4 Opus re-review (I-opus-8), 2026-04-21
**File:** `tests/test_adaptive_staging.py`
**Why deferred:** No test for clock-skew: `staged_at` in the future. Current behavior: `age` is negative; `age > timedelta(hours=24)` is False; staleness check is skipped; promote succeeds. Not a security concern (negative age means "staged recently"), but the behavior should be documented by a test.
**Trigger:** Next test-coverage sweep.
**Suggested fix:** add `test_promote_future_staged_at_proceeds_without_stale_error` asserting the promote path proceeds cleanly when `staged_at` is in the future.
**Estimated scope:** ~20 LOC test.

### BACKLOG-PR6-27 — `confirm_stale` schema `default` key
**Source:** Phase 3b PR #6 T4 Opus re-review (I-opus-9), 2026-04-21
**File:** `src/screw_agents/engine.py` — `promote_staged_script` tool schema
**Why deferred:** Tool schema does not include `"default": false` for `confirm_stale`; method implementation defaults to False; dispatcher reads `args.get("confirm_stale", False)`. Functionally correct but not self-documenting from the schema alone.
**Trigger:** Next schema polish pass OR T22 additionalProperties sweep (if it also audits default keys).
**Suggested fix:** add `"default": false` to the `confirm_stale` schema block.
**Estimated scope:** 1-2 LOC.

### BACKLOG-PR6-28 — `promote_staged_script` method-length refactor
**Source:** Phase 3b PR #6 T4 Opus re-review (I-opus-10), 2026-04-21
**File:** `src/screw_agents/engine.py` — `promote_staged_script` (~340 LOC)
**Why deferred:** Method is long. The staleness check (~60 LOC), fallback path (~40 LOC), and primary/tamper branch (~40 LOC) are distinct phases and could extract cleanly into `_check_staleness`, `_resolve_via_fallback`, `_handle_tamper` private helpers. This would simplify unit-testing those branches in isolation. The method IS readable as written, but a refactor would aid maintainability.
**Trigger:** Next readability polish pass, OR if a future T5/T6/T7 task touches the same method and the size becomes a merge-conflict risk.
**Suggested fix:** extract three private helpers; update tests to exercise them directly where helpful; preserve public signature.
**Estimated scope:** ~100 LOC refactor + test reorganization.

### BACKLOG-PR6-29 — `adaptive_prompts.json` tmp-file naming uses `with_suffix`
**Source:** Phase 3b PR #6 T5 pre-audit (N1), 2026-04-21
**File:** `src/screw_agents/engine.py` — `reject_staged_script`
**Why deferred:** The tmp file for atomic JSON write uses `prompts_path.with_suffix(".json.tmp")`. Works correctly for `.json` (single-suffix), but inconsistent with T1's string-concat tmp-naming discipline (locked in to avoid the `.meta.yaml` double-suffix bug). Defensive consistency would prefer `prompts_path.parent / f"{prompts_path.name}.tmp"`.
**Trigger:** Next consistency-polish pass touching engine.py tmp-write sites.
**Suggested fix:** replace `with_suffix` with string-concat form.
**Estimated scope:** 1-line change + possibly a code comment.

### BACKLOG-PR6-30 — Silent swallow of `adaptive_prompts.json` write failures lacks impact comment
**Source:** Phase 3b PR #6 T5 pre-audit (N2), 2026-04-21
**File:** `src/screw_agents/engine.py` — `reject_staged_script`
**Why deferred:** The `try/except (PermissionError, OSError): pass` around the `adaptive_prompts.json` update is documented as "best-effort; not critical to the reject flow's correctness". True, but what IS lost: T18b decline-tracking for this specific target — the scan may re-propose the same script next run. Comment should spell out the user-visible impact so an operator reading the code understands what gets skipped on filesystem failure.
**Trigger:** Next readability polish pass.
**Suggested fix:** expand the comment to "best-effort; on failure, T18b decline-tracking for this target is lost — the target may be re-proposed on next scan. Reject succeeds regardless since the audit entry in pending-approvals.jsonl already recorded the decision."
**Estimated scope:** 2-3 line comment.

### BACKLOG-PR6-31 — No test for rejecting a script already in promoted lifecycle state
**Source:** Phase 3b PR #6 T5 pre-audit (N4), 2026-04-21
**File:** `tests/test_adaptive_staging.py`
**Why deferred:** `reject_staged_script` operates only on staging files — it doesn't check registry lifecycle. If a script was already promoted but staging files somehow exist (shouldn't happen in practice per T4's `delete_staged_files` cleanup, but possible after sweep race or hand-edit), reject would still delete staging and emit a `rejected` event. This is semantically ambiguous ("you promoted AND rejected?") but benign — reject acts on stage state, not on custom-scripts. Worth a test documenting the behavior.
**Trigger:** Next test-hygiene sweep OR if an incident surfaces unexpected post-promote reject behavior.
**Suggested fix:** add `test_reject_after_promote_is_noop_on_custom_scripts` — promote a script, manually re-plant staging files, reject, assert staging is deleted AND custom-scripts artifact is untouched.
**Estimated scope:** ~25 LOC test.

### BACKLOG-PR6-32 — Local `import json` shadows module-level `_json` alias
**Source:** Phase 3b PR #6 T5 Opus re-review (B-T5-1), 2026-04-21
**File:** `src/screw_agents/engine.py` — `reject_staged_script` (and possibly `promote_staged_script`)
**Why deferred:** engine.py imports `json as _json` at module top (line 13) to avoid shadowing. `reject_staged_script` does a local `import json` inside the method body. Functionally correct (Python resolves local binding), but inconsistent with module style.
**Trigger:** Next engine.py style consistency pass.
**Suggested fix:** drop the local `import json`; rely on module-level `_json`; rename uses.
**Estimated scope:** ~3 LOC.

### BACKLOG-PR6-33 — Happy-path reject test missing full schema assertion
**Source:** Phase 3b PR #6 T5 Opus re-review (B-T5-3), 2026-04-21
**File:** `tests/test_adaptive_staging.py` — `test_reject_staged_script_deletes_files_and_audits`
**Why deferred:** Test asserts `rej["reason"]` but not `rejected_at`, `schema_version`, `script_name`, `session_id`. `validate_pending_approval` catches absence at write-time, so absence would fail elsewhere — but explicit schema assertions are cheap regression insurance.
**Trigger:** Next test-hygiene sweep.
**Estimated scope:** ~5 LOC.

### BACKLOG-PR6-34 — Extract decline-tracking update into private helper
**Source:** Phase 3b PR #6 T5 Opus re-review (B-T5-4), 2026-04-21
**File:** `src/screw_agents/engine.py` — `reject_staged_script`
**Why deferred:** The ~20-line block that updates `adaptive_prompts.json` is a self-contained concern ("remember this script was declined so it's not re-proposed"). Extracting to `_record_decline_in_prompts_file(project_root, script_name)` would shorten the main method and co-locate the best-effort policy.
**Trigger:** Next readability polish pass OR when T18b gets its own module.
**Estimated scope:** ~25 LOC refactor.

### BACKLOG-PR6-35 — No test for fresh-stage-between-rejects corner case
**Source:** Phase 3b PR #6 T5 Opus re-review (B-T5-5), 2026-04-21
**File:** `tests/test_adaptive_staging.py`
**Why deferred:** If between first and second reject, a fresh stage happens with same `(script_name, session_id)`, second reject would delete the FRESH stage. Semantically correct ("reject acts on whatever is currently staged for that name+session") but not tested.
**Trigger:** Next test-hygiene sweep.
**Suggested fix:** add `test_reject_after_fresh_restage_deletes_fresh_stage` — stage, reject, stage again, reject again, assert the second fresh stage is deleted and two `rejected` audit events appear.
**Estimated scope:** ~25 LOC test.

### BACKLOG-PR6-36 — `invalid_session_id` error-dict omits helper-readable `session_id` field
**Source:** Phase 3b PR #6 T5 Opus re-review (minor observation), 2026-04-21
**File:** `src/screw_agents/engine.py` — `reject_staged_script`, `stage_adaptive_script`, `promote_staged_script`
**Why deferred:** Error dicts for invalid session_id include the rejected value in `message` but not as a dedicated `session_id` field. Callers pattern-matching on `response["session_id"]` get KeyError on error paths. Minor UX.
**Trigger:** Next error-taxonomy polish pass.
**Suggested fix:** include `session_id` (or `rejected_session_id` if the raw one is ugly) as a dedicated field on the error dict. Apply uniformly across T3/T4/T5 error paths.
**Estimated scope:** ~10 LOC + test updates.

### BACKLOG-PR6-37 — `sweep_stale` inline walk vs `fallback_walk_for_script` helper
**Source:** Phase 3b PR #6 T6 pre-audit (N1), 2026-04-21
**File:** `src/screw_agents/adaptive/staging.py` — `sweep_stale` + `fallback_walk_for_script`
**Why deferred:** `sweep_stale` uses inline `staging_root.iterdir()` + per-session `adapt_dir.glob("*.py")` walk. T3 added `fallback_walk_for_script(project_root, *, script_name)` for promote's fallback path. Different semantics (per-script lookup vs all-scripts scan), so direct reuse doesn't fit, but a shared `walk_all_staging` helper could consolidate the iteration pattern if a third consumer appears.
**Trigger:** If a T25+ task introduces a third iterator over `.screw/staging/**`.
**Suggested fix:** extract `walk_all_staging(project_root) -> Iterator[tuple[session_id, py_path]]`; use from sweep_stale; leave fallback_walk_for_script's per-script optimization intact.
**Estimated scope:** ~15 LOC extraction.

### BACKLOG-PR6-38 — Use `ScrewConfig.staging_max_age_days` field instead of raw YAML read
**Source:** Phase 3b PR #6 T6 pre-audit (N2), 2026-04-21
**File:** `src/screw_agents/engine.py` — `_read_staging_max_age_days`
**Why deferred:** T4-part-2 (I1) added `ScrewConfig.staging_max_age_days: int = Field(default=14, ge=1, le=365)` to the Pydantic schema. T6's `_read_staging_max_age_days` reads raw YAML via `yaml.safe_load` + `.get()` as fallback (symmetric with T4's `_read_stale_staging_hours`). Could route through `load_config(project_root)` → Pydantic validation → then fall back to raw YAML only if Pydantic fails. Gives schema-validated default path.
**Trigger:** Next config-read polish pass; or when T6 behavior surprises a user due to silent schema bypass.
**Suggested fix:** attempt `load_config(project_root).staging_max_age_days`; on ValidationError or config absence, fall back to current raw-YAML path.
**Estimated scope:** ~10 LOC + 1 test.

### BACKLOG-PR6-39 — `sweep_stale` does not preserve TAMPERED files past max_age_days explicitly
**Source:** Phase 3b PR #6 T6 pre-audit follow-up, 2026-04-21
**File:** `src/screw_agents/adaptive/staging.py` — `sweep_stale` + `_classify_sweep_reason`
**Why deferred:** Current logic: if TAMPERED marker exists AND age < max_age_days, preserve (report in tampered_preserved). If age >= max_age_days, fall through and sweep. This treats tamper evidence as "expires eventually". A stronger stance: tamper files NEVER auto-sweep; require explicit operator action (e.g., `screw-agents forensics-acknowledge <session> <script>`).
**Trigger:** If a post-incident review shows the auto-sweep expired useful forensic evidence, OR during Phase 4+ forensic-tooling work.
**Suggested fix:** add `force_sweep_tampered: bool = False` kwarg to `sweep_stale_staging`; default False means tampered files NEVER swept regardless of age.
**Estimated scope:** ~15 LOC + 2 tests.

### BACKLOG-PR6-40 — `_read_staging_max_age_days` exception breadth asymmetric with T4
**Source:** Phase 3b PR #6 T6 Opus review (M-T6-1), 2026-04-21
**File:** `src/screw_agents/engine.py` — `_read_staging_max_age_days`
**Why deferred:** T6's helper catches `(PermissionError, OSError, ValueError)`. T4's sibling `_read_stale_staging_hours` catches `(ValueError, TypeError, OSError, yaml.YAMLError)`. Malformed YAML in T6's helper will crash sweep instead of falling back to 14.
**Trigger:** Next config-read polish pass.
**Suggested fix:** broaden to match T4's exception tuple; consolidate to a shared `_read_config_int(key, default, lo, hi)` helper.
**Estimated scope:** ~5 LOC.

### BACKLOG-PR6-41 — Orphaned TAMPERED marker when .py missing
**Source:** Phase 3b PR #6 T6 Opus review (M-T6-2 / M-T6-9), 2026-04-21
**File:** `src/screw_agents/adaptive/staging.py` — `sweep_stale`
**Why deferred:** If `.py` is deleted but `.TAMPERED` marker remains (crash mid-sweep, manual user delete), sweep's `glob("*.py")` never iterates → marker never cleaned up → session dir pinned as non-empty forever.
**Trigger:** Observed in production OR when session-dir cleanup becomes a reliability concern.
**Suggested fix:** after the per-script loop, glob `"*.TAMPERED"` and unlink any orphans whose corresponding `.py` is absent.
**Estimated scope:** ~10 LOC + 1 test.

### BACKLOG-PR6-42 — `sessions_scanned` counter has no test coverage
**Source:** Phase 3b PR #6 T6 Opus review (M-T6-3), 2026-04-21
**File:** `tests/test_adaptive_staging.py` — sweep test suite
**Why deferred:** The `sessions_scanned` field is returned in every sweep response but no test asserts it. Silent regression potential.
**Trigger:** Next test-hygiene sweep.
**Suggested fix:** extend an existing sweep test to stage in 3 sessions and assert `response["sessions_scanned"] == 3`.
**Estimated scope:** ~5 LOC.

### BACKLOG-PR6-43 — No positive test for `swept` event shape
**Source:** Phase 3b PR #6 T6 Opus review (M-T6-4), 2026-04-21
**File:** `tests/test_adaptive_staging.py`
**Why deferred:** Dry-run test asserts registry UNCHANGED (negative case). No test verifies the real-path `swept` entry has all required fields per `_REQUIRED_FIELDS_BY_EVENT["swept"]`.
**Trigger:** Next test-hygiene sweep.
**Suggested fix:** add `test_sweep_appends_well_formed_swept_event` — reads JSONL tail after sweep, asserts event has {event, script_name, session_id, swept_at, sweep_reason, schema_version}.
**Estimated scope:** ~15 LOC.

### BACKLOG-PR6-44 — No test for tampered+expired→sweep transition
**Source:** Phase 3b PR #6 T6 Opus review (M-T6-5), 2026-04-21
**File:** `tests/test_adaptive_staging.py`
**Why deferred:** `test_sweep_preserves_tampered_files` covers `age=10d, max=14d → preserve`. The spec path `tamper_detected + age >= max → swept (marker removed)` is implemented but unverified.
**Trigger:** Next test-hygiene sweep.
**Suggested fix:** stage → mark TAMPERED → age to 30d → sweep with max=14d → assert .py + marker both gone + `swept` event with reason `stale_orphan`.
**Estimated scope:** ~25 LOC.

### BACKLOG-PR6-45 — No test for `completed_orphan` path
**Source:** Phase 3b PR #6 T6 Opus review (M-T6-6), 2026-04-21
**File:** `tests/test_adaptive_staging.py`
**Why deferred:** `_TERMINAL_EVENTS` classifier returns `completed_orphan` when registry has promoted/rejected/swept event but staging files are still present. Defensive-GC claim unverified by tests.
**Trigger:** Next test-hygiene sweep.
**Suggested fix:** construct the mocked partial state (promote, then replant staging files), run sweep with large max_age_days, assert files swept with reason `completed_orphan`.
**Estimated scope:** ~25 LOC.

### BACKLOG-PR6-46 — Outer `staging_root.iterdir()` not snapshotted
**Source:** Phase 3b PR #6 T6 Opus review (M-T6-7), 2026-04-21
**File:** `src/screw_agents/adaptive/staging.py` — `sweep_stale`
**Why deferred:** Inner loop uses `list(adapt_dir.glob("*.py"))` defensively. Outer loop is a raw generator. Current code only mutates the CURRENT session_dir, which CPython os.scandir handles, but asymmetric defense is a readability smell.
**Trigger:** Next readability polish pass.
**Suggested fix:** wrap outer iteration in `list(staging_root.iterdir())` for symmetry.
**Estimated scope:** 1 LOC + comment.

### BACKLOG-PR6-47 — `sweep_stale` length (~120 LOC) refactor candidate
**Source:** Phase 3b PR #6 T6 Opus review (M-T6-8), 2026-04-21
**File:** `src/screw_agents/adaptive/staging.py` — `sweep_stale`
**Why deferred:** Function is long. The per-script inner block could extract to `_process_staging_script(...)` returning `(removed | preserved | None)`. Simplifies unit-testing those branches in isolation.
**Trigger:** Next readability polish pass, OR when a future task touches `sweep_stale` and the size becomes a merge-conflict risk.
**Estimated scope:** ~30 LOC refactor.

### BACKLOG-PR6-48 — Session with only TAMPERED marker (no .py) not cleaned
**Source:** Phase 3b PR #6 T6 Opus review (M-T6-9), 2026-04-21
**File:** `src/screw_agents/adaptive/staging.py` — `sweep_stale`
**Why deferred:** Edge case where `.py` unlink succeeded but marker unlink failed (or user manually deleted `.py`). Marker never cleaned up, session dir never removed. Related to BACKLOG-PR6-41 but distinct scenario.
**Trigger:** Post-incident review OR M-PR6-41 implementation (both fixed together).
**Estimated scope:** bundled with BACKLOG-PR6-41.

### BACKLOG-PR6-49 — Stale docstring in `cli/adaptive_cleanup.py:16-19` after `_check_stale` relocation
**Source:** Phase 3b PR #6 T7 Opus code-review (M-T7-1), 2026-04-22
**File:** `src/screw_agents/cli/adaptive_cleanup.py:16-19`
**Why deferred:** The module-level docstring still says "If the executor's `_is_stale` semantic ever changes, update `_check_stale` here to match", but after T7's plan-fix #1 the `_check_stale` definition lives in `adaptive/executor.py` and this file only re-exports it. A reader grepping the file for a `def _check_stale` body finds nothing — contradicts the docstring. Not a correctness bug (re-export works). T9 deletes this file entirely, so the drift is short-lived.
**Trigger:** Naturally resolved when T9 deletes `cli/adaptive_cleanup.py`.
**Estimated scope:** 0 LOC (auto-resolves). If fixed earlier: ~4 LOC docstring rewrite.

### BACKLOG-PR6-50 — `except Exception` inside `_check_stale` (verbatim-lift of pre-T7 code)
**Source:** Phase 3b PR #6 T7 Opus spec review (M2), 2026-04-22
**File:** `src/screw_agents/adaptive/executor.py:260` (relocated from `cli/adaptive_cleanup.py:249` in T7)
**Why deferred:** The per-pattern `find_calls` call is wrapped in `except Exception:` to tolerate tree-sitter parse failures on any single file without failing the whole stale-check. Plan §T7 mandated verbatim lift (no behavioral changes during the move). Narrowing to a specific tree-sitter exception class is a follow-up concern that belongs with the broader T3-M1 narrow-exception work, not the move itself.
**Trigger:** Next adaptive-exception sweep OR when `find_calls` grows richer error types worth distinguishing.
**Estimated scope:** ~3 LOC (narrow the except; add a test that a single tree-sitter failure doesn't derail siblings).
