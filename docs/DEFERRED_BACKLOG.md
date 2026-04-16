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
