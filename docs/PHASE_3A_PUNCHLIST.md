# Phase 3a PR#1 — Deferred Polish Punchlist

> **Purpose:** consolidated tracking of non-blocking code-review findings deferred during Phase 3a PR#1 implementation. Every item has been triaged as "not a merge blocker for the task that surfaced it" but "worth addressing before PR#1 opens or as part of a natural cleanup pass".
>
> **When to consume:** before opening PR#1, OR when a downstream task naturally touches the affected file, OR as a dedicated polish commit after Task 15 lands.
>
> **Source:** code-quality reviews for Tasks 2-9 during the phase-3a-trust-learning-cleanup branch implementation. Each item is namespaced `T{N}-{level}{N}` where N is the source task number and the level is `I` (Important) or `M` (Minor). `RR` suffix indicates items from a re-review of a fix-up commit.

---

## How to use this punchlist

1. **Read the "Priority items" section first** — these have cross-task dependencies and should be addressed before specific downstream tasks land.
2. **Check the "Resolved" items** to avoid duplicating work that's already been picked up.
3. **When dispatching polish work**, group items by file (minimizes context-switching) or by severity (Important before Minor).
4. **Delete resolved items from this file** as they're addressed, rather than marking them strikethrough. Keep the punchlist lean.

---

## Timing strategy

**Best timings for a consolidated cleanup pass:**

- **Before PR#1 opens** — single focused polish commit after Task 15 lands. Recommended for style/docstring/test items.
- **Ride-along with Task 10/11/12** — some items have natural homes in specific downstream tasks (flagged inline below).
- **Phase 3b Task 13 (init-trust CLI)** — will naturally extend/restructure `trust.py`. Items like T4-M6 (file split) and some Task 7 polish fit here.
- **Phase 3a closeout doc / Phase 4+** — performance and scale concerns (T8-M4, T9-M4) defer here.

**Estimated total effort:** ~90 minutes focused pass to clear the full punchlist, or ~30 minutes for the Important-only subset.

---

## Priority items (address BEFORE specific downstream tasks)

### T5-M1 — Rename `matched_key_identity` → `matched_key_fingerprint`

**Source:** Task 5 code-quality review (commit `aee0c24`)
**File:** `src/screw_agents/trust.py` (VerificationResult dataclass, ~line 120)

**Problem:** "identity" in security context implies uniqueness and stable attribution, but the field is a 16-char base64-encoded SHA-256 prefix (96 bits) — display-only per its own docstring. Callers who see "identity" in scan-report JSON will reasonably assume it's a key identifier they can trust.

**Why priority:** Tasks 10 and 11 will surface this field in user-facing scan reports. Rename BEFORE those tasks consume it, otherwise it's a breaking rename after downstream code already depends on the misleading name.

**Fix:** Rename the field on `VerificationResult`, update the assignment in `verify_signature` (~line 155), update the one test assertion that references it. ~5 lines of edits + 1 test assertion update.

**When:** Before Task 10 dispatch.

---

### T6-I1, T6-I2, T9-I3 — Task 11 friendly-error-surfacing cluster

**Sources:**
- T6-I1 (`24804b6` → `fc1e74b`): `load_config` raises opaque `FileExistsError` when `.screw` path exists as a file, not directory
- T6-I2 (`24804b6` → `fc1e74b`): `load_config` leaks bare `PermissionError` on read-only filesystems
- T9-I3 (`94c3c5f` → `6a46a9b`): `record_exclusion` leaks untyped `OSError` / `PermissionError` when `_get_or_create_local_private_key` raises

**File:** `src/screw_agents/results.py` (Task 11 scope)

**Why priority:** Task 11 is explicitly about user-facing error surfacing in scan reports. Wrap these three cases in `ValueError` / context-wrapped `RuntimeError` with actionable messages at the Task 11 boundary, instead of doing it piecemeal in each upstream function.

**Fix:** Task 11 catches `OSError`/`PermissionError`/`FileExistsError` from `trust.load_config` / `learning.record_exclusion` / `learning.load_exclusions` and surfaces them as friendly scan-report messages like:

- "A `.screw` file exists at `/path/to/project/.screw` but is not a directory. Remove or rename it before running `screw-agents`."
- "Cannot write `.screw/config.yaml`: permission denied. Check directory permissions or run with appropriate user."
- "Cannot read/create local signing key at `.screw/local/keys/screw-local.ed25519`: permission denied."

**When:** During Task 11 implementation.

---

### T8-warn-policy-visibility — Task 11 must solve

**Source:** Task 8 code-quality review (commit `71b10a1`)

**Problem:** After Task 8, signed-and-valid exclusions and unsigned-under-warn-policy exclusions both end up with `quarantined=False`. They're indistinguishable from the `Exclusion` object alone. Task 11 needs this distinction to emit "N exclusions applied with warning" messages in scan reports.

**Two fix options for Task 11 to pick:**

1. **Re-run verification in Task 11** — recompute which entries are signed+valid vs unsigned-warn. Expensive (full Ed25519 verify on each entry at report time).
2. **Add a runtime-only `_trust_state` field to `Exclusion`** — enum `{"trusted", "warned", "quarantined", "allowed"}` with `Field(exclude=True)`. Task 8's `_apply_trust_policy` populates it in the same pass as `quarantined`. Task 11 reads the field directly. ~5 lines in `models.py` + ~10 lines in `learning.py`.

My recommendation: option 2 (runtime-only field). Cheaper, clearer.

**When:** During Task 11 implementation.

---

### T8-I1 — `load_exclusions` side-effect docstring note

**Source:** Task 8 code-quality review (commit `71b10a1`)
**File:** `src/screw_agents/learning.py` `load_exclusions`

**Problem:** `load_exclusions` now transitively creates `.screw/config.yaml` via `load_config` when entries are present. That's a write side effect for a "load" function — surprising for read-only callers.

**Fix:** Add a "Side effects" section to the `load_exclusions` docstring:

```
Side effects:
    May create `.screw/` directory and `.screw/config.yaml` stub via
    `trust.load_config` if exclusions exist but the config file is missing.
    Empty projects (no exclusions file) are purely read-only.
```

OR (stronger fix) add a `read_only: bool = False` parameter to `trust.load_config`, have `load_exclusions` pass `read_only=True`, and return `ScrewConfig()` defaults (fail-safe) instead of writing the stub when the config is missing in read-only mode.

**When:** Single polish commit OR ride-along with Task 10/11.

---

### T8-I2 — `_apply_trust_policy` restructure to single-assignment

**Source:** Task 8 code-quality review (commit `71b10a1`)
**File:** `src/screw_agents/learning.py` `_apply_trust_policy`

**Problem:** The function only ever SETS `quarantined=True` — success branches rely on the default `False` from `model_validate`. Fragile: a future refactor that re-uses an existing `Exclusion` would silently keep a stale `True`.

**Fix:** Restructure to compute once, assign once:

```python
def _apply_trust_policy(exclusion: Exclusion, *, config: ScrewConfig) -> None:
    quarantine: bool
    if exclusion.signature is None or exclusion.signed_by is None:
        quarantine = config.legacy_unsigned_exclusions == "reject"
    else:
        quarantine = not verify_exclusion(exclusion, config=config).valid
    exclusion.quarantined = quarantine
```

~8 lines replacing ~12 lines.

**When:** Single polish commit.

---

## Task 2 — 5 items (commits `1479272` + `480d533`)

### T2-I2 — Test class placement
**File:** `tests/test_models.py`
**Problem:** Task 2's tests are module-level functions; `TestExclusionModels` class already exists with 9 cohesive Exclusion tests.
**Fix:** Move `test_exclusion_signing_fields_optional`, `test_exclusion_with_signing_fields`, `test_exclusion_model_dump_*`, `test_exclusion_include_*` into `TestExclusionModels`. Also consolidates with Task 1's module-level tests during the same pass.

### T2-I3 — YAML dict-based backwards-compat test
**File:** `tests/test_models.py`
**Problem:** Current backwards-compat test constructs `Exclusion` via kwargs; doesn't mirror `learning.py:50` production path (YAML dict → `Exclusion(**entry)`).
**Fix:** Add a variant test that parses from a dict.

### T2-M2 — Test name polish
**File:** `tests/test_models.py` line ~336
**Problem:** `test_exclusion_with_signing_fields` is grammatical but uninformative.
**Fix:** Rename to `test_exclusion_signing_fields_round_trip` or `test_signed_exclusion_preserves_signature`.

### T2-M3 — ExclusionInput docstring note
**File:** `src/screw_agents/models.py` `ExclusionInput` class
**Problem:** The extras-asymmetry between `ExclusionInput` (no `extra="forbid"`) and `Exclusion` (has it) is intentional but undocumented.
**Fix:** Add docstring note: "Parent is the write-side input shape with default Pydantic extras handling; `Exclusion` child has `extra='forbid'` for signing-integrity surface."

### T2-RR-Minor — Loose `**kwargs` signature on `Exclusion.model_dump` override
**File:** `src/screw_agents/models.py` `Exclusion.model_dump`
**Problem:** Hides Pydantic v2's typed keyword-only signature from IDE/static analysis.
**Fix:** Mirror `BaseModel.model_dump`'s typed signature explicitly. Stylistic only.

---

## Task 3 — 4 items (commits `6329c55` + `e6e6dec`)

### T3-M2 — `canonicalize_script` meta filtering non-recursive
**File:** `src/screw_agents/trust.py` `_SCRIPT_META_CANONICAL_EXCLUDE`
**Problem:** The filter only strips top-level keys. A future script schema nesting signature-like fields (e.g., `meta["provenance"] = {...signed_by...}`) would leak them into the canonical form.
**Fix:** Add docstring note on `_SCRIPT_META_CANONICAL_EXCLUDE`: "NOTE: top-level filtering only — script metadata schemas MUST NOT nest signature-related fields in sub-dicts. Phase 3b Task 13's script metadata shape is flat by design."

### T3-M3 — Lists preserve insertion order, not sorted
**File:** `src/screw_agents/trust.py` `_canonical_json_bytes` docstring
**Problem:** `sort_keys=True` sorts dict keys but NOT list elements. A future caller building a list from a `set(...)` would produce non-deterministic canonical bytes.
**Fix:** One-line note in docstring: "Lists preserve element order — callers must build lists deterministically (not from sets or dict views)."

### T3-M4 — No empty-meta test
**File:** `tests/test_trust.py`
**Problem:** No test for `canonicalize_script(source="x", meta={})` — edge case worth pinning.
**Fix:** Add a regression test: `assert canonicalize_script(source="x", meta={}) == b'{"meta":{},"source":"x"}'`.

### T3-M6 — `_EXCLUSION_CANONICAL_EXCLUDE` must-be-set contract
**File:** `src/screw_agents/trust.py` `_EXCLUSION_CANONICAL_EXCLUDE` constant
**Problem:** The constant must be a `set` (not frozenset/dict/tuple) for `Exclusion.model_dump`'s override's `isinstance(exclude, set)` branch to work. Hidden contract.
**Fix:** One-line comment: "must be a set — `Exclusion.model_dump` unions this with the runtime-flag exclude."

### ~~T3-M5~~ — RESOLVED
Module docstring was rewritten in Task 4.1 Option C refactor (commit `12892e8`). No action needed.

---

## Task 4 — 3 items (commits `d2ac79d` + `12892e8` Option C refactor)

### T4-M3 — `sign_content` empty-canonical validation
**File:** `src/screw_agents/trust.py` `sign_content`
**Problem:** `sign_content(b"")` works (Ed25519 happily signs empty messages) but is almost certainly an upstream bug (bad canonicalizer, empty Exclusion).
**Fix:** Add `if not canonical: raise ValueError("sign_content: canonical payload is empty — refusing to sign")`. Defensive.

### T4-M6 — File split for `trust.py`
**File:** `src/screw_agents/trust.py`
**Problem:** Now at ~552 lines after Task 7.1 Model A refactor (was 71 at Task 3, 115 at Task 4.1, 180 at Task 5, 268 at Task 6, 352 at Task 7, 552 at Task 7.1). Well past the ~300-line split threshold.
**Fix:** Split into:
- `trust/__init__.py` (re-exports)
- `trust/canonical.py` (canonicalize_exclusion, canonicalize_script, _canonical_json_bytes, exclude sets)
- `trust/sign.py` (sign_content)
- `trust/verify.py` (verify_signature, VerificationResult, _fingerprint_public_key, verify_exclusion, verify_script, _find_matching_reviewer, _load_public_keys_with_reviewers)
- `trust/keys.py` (_public_key_to_openssh_line, future key generation utilities)
- `trust/config.py` (load_config, _CONFIG_STUB_TEMPLATE)

**When:** Phase 3b Task 13 (init-trust CLI) will naturally extend `trust.py` with key-generation code. Split at that point to avoid churning the file twice.

### T4-M7 — Test imports hoist
**File:** `tests/test_trust.py`
**Problem:** Function-scoped imports (plan literal) made sense during TDD cycle when imports should fail at test-run time. Now that TDD is stable, hoisting to module top is cleaner.
**Fix:** Move `from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey`, `from screw_agents.trust import ...`, etc. to the top of `test_trust.py`. Low value; do during any other test file reorg.

---

## Task 5 — 6 items (commit `aee0c24`)

### T5-M1 — SEE PRIORITY ABOVE

### T5-M2 — Narrow `except Exception` in `verify_signature`
**File:** `src/screw_agents/trust.py` `verify_signature` loop (~line 152)
**Problem:** `except Exception: continue` is deliberately broad but may swallow unexpected library errors that indicate a programming bug.
**Fix:** Narrow to `(InvalidSignature, ValueError)`:
```python
from cryptography.exceptions import InvalidSignature
# ...
except (InvalidSignature, ValueError):
    continue
```
Fail-closed behavior preserved; unexpected errors propagate loudly.

### T5-M3 — Drop redundant `base64.binascii.Error`
**File:** `src/screw_agents/trust.py` `verify_signature` base64-decode except tuple
**Problem:** In Python 3.11+, `binascii.Error` is a subclass of `ValueError`, so `except ValueError` suffices.
**Fix:** Simplify `except (ValueError, base64.binascii.Error):` → `except ValueError:`. Stylistic.

### T5-M4 — `_fingerprint_public_key` cost profile
**File:** `src/screw_agents/trust.py` `_fingerprint_public_key`
**Problem:** Each successful `verify_signature` computes the fingerprint even when the caller doesn't read `matched_key_identity`. Trivial cost today, but Task 12-14 CLI batch verification could amplify.
**Fix (future):** Make the fingerprint lazy via `VerificationResult` cached property, OR add `compute_fingerprint: bool = True` parameter to `verify_signature`. Defer until batch verification is actually introduced.

### ~~T5-M5~~ — NO ACTION
Intentionally NOT adding `VerificationResult.__bool__`. Explicit `if result.valid:` is preferred — prevents `if verify_signature(...):` footgun that would hide the `reason` field.

### T5-M6 — Duplicate `Ed25519PrivateKey` imports across tests
**File:** `tests/test_trust.py`
**Problem:** 4+ tests have `from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey` inside their bodies.
**Fix:** Extract a pytest fixture: `@pytest.fixture def ed25519_keypair(): priv = Ed25519PrivateKey.generate(); return priv, priv.public_key()`. Hoist the import to module top.

### T5-M7 — `test_verify_signature_empty_allowed_keys` couples to `sign_content`
**File:** `tests/test_trust.py` `test_verify_signature_empty_allowed_keys`
**Problem:** Test generates a key and signs content, then passes `public_keys=[]`. The signing work is wasted — the empty-keys branch runs before signature validation. Test couples two things (`sign_content` works + empty keys rejects) that should be independent.
**Fix:** Use a literal base64 signature: `signature = "AAAA"` and assert on the empty-keys path only.

---

## Task 6 — 9 items (commits `24804b6` + `fc1e74b`)

### T6-I1, T6-I2 — SEE PRIORITY ABOVE (Task 11 cluster)

### T6-M1 — TOCTOU race on stub creation
**File:** `src/screw_agents/trust.py` `load_config` stub-write block
**Problem:** Two concurrent `load_config` calls could both see missing config, both write the stub, and clobber each other mid-write. Not a problem for Phase 3a single-process CLI; concerning for Phase 7 multi-process MCP server.
**Fix (future):** Use `os.open(path, O_CREAT | O_EXCL | O_WRONLY)` for atomic stub creation. Defer until Phase 7.

### T6-M2 — Stub template schema-version comment
**File:** `src/screw_agents/trust.py` `_CONFIG_STUB_TEMPLATE`
**Problem:** `version: 1` is present but no explanation. Users editing old files will wonder whether to bump.
**Fix:** Add comment line: `# version: schema version. Do not bump manually — screw-agents migrates on upgrade.`

### T6-M3 — Stub template doesn't document `trusted_reviewers_file`
**File:** `src/screw_agents/trust.py` `_CONFIG_STUB_TEMPLATE`
**Problem:** Task 1 added `trusted_reviewers_file: str | None = None` to `ScrewConfig`, but the stub doesn't mention it. Users with 10+ reviewers will want the external file option.
**Fix:** Add commented example:
```yaml
# Optional: factor reviewer lists out to an external SSH allowed_signers file.
# When set, exclusion_reviewers / script_reviewers above are merged with this.
# trusted_reviewers_file: .screw/allowed_signers
```

### T6-M4 — `load_config` not idempotent
**File:** `src/screw_agents/trust.py` `load_config`
**Problem:** Each call re-reads the file. Fine for single-scan CLI; per-request disk hit in Phase 7 MCP server.
**Fix (future):** Add `@lru_cache` keyed on `project_root`, with a staleness-invalidation hook. Defer to Phase 7.

### T6-M5 — Test coverage gaps
**File:** `tests/test_trust.py`
**Missing tests:**
- `test_load_config_raises_when_dot_screw_is_file` (requires T6-I1 fix)
- `test_load_config_raises_on_readonly_directory` (requires T6-I2 fix; skip on Windows)
- `test_load_config_stub_is_valid_yaml_and_schema` (direct template assertion)
- `test_load_config_idempotent_does_not_rewrite` (mtime check)
- `test_load_config_empty_file_uses_defaults` (pin the `data is None → {}` path)

### T6-M6 — Test imports at function scope
**File:** `tests/test_trust.py`
Same as T4-M7 and T5-M6. Consolidate during a test-file reorg.

### T6-M7 — `trust.py` line count trajectory
Informational. See T4-M6 for the split plan.

### ~~T6-I3~~ — RESOLVED
UTF-8 encoding added in commit `fc1e74b`.

---

## Task 7 — 4 items (commits `75d0c2f` + `6cabfa2` Model A fix-up)

### T7-M1 — Parse SSH wire format via `struct.unpack`
**File:** `src/screw_agents/trust.py` `_load_public_keys_with_reviewers` (~line 323)
**Problem:** `raw_key = key_bytes_with_header[19 : 19 + 32]` is a magic-number slice (4 + 11 + 4 = 19). Fragile for any future non-ed25519 key-type support.
**Fix:** Parse the wire format properly:
```python
import struct
pos = 0
(alg_len,) = struct.unpack_from(">I", key_bytes_with_header, pos); pos += 4
alg = key_bytes_with_header[pos:pos+alg_len]; pos += alg_len
if alg != b"ssh-ed25519": continue
(key_len,) = struct.unpack_from(">I", key_bytes_with_header, pos); pos += 4
raw_key = key_bytes_with_header[pos:pos+key_len]
if len(raw_key) != 32: continue
```
~6 lines replacing 3. More robust.

### T7-M3 — `_public_key_to_openssh_line` docstring clarity
**File:** `src/screw_agents/trust.py` `_public_key_to_openssh_line`
**Problem:** Docstring says "used by tests plus `init-trust`" but `init-trust` is Task 12, which doesn't exist yet.
**Fix:** Update to "used by tests plus init-trust (Task 12)" or "used by tests; Task 12 init-trust will consume this for key registration."

### T7-M4 — `_sample_exclusion(signed=True)` parameter naming
**File:** `tests/test_trust.py` `_sample_exclusion` helper (~line 33)
**Problem:** `_sample_exclusion(signed=True)` returns an exclusion with placeholder signature `"U1NIU0lH..."` that never reaches verification. Misleading — a reader expects "signed=True" to mean "cryptographically signed and verifiable".
**Fix:** Rename to `_sample_exclusion(with_placeholder_signature=True)`.

### T7-Obs1 — Task 5's redundant local `serialization` import
**File:** `src/screw_agents/trust.py` `_fingerprint_public_key`
**Problem:** Task 5's `_fingerprint_public_key` has an inline `from cryptography.hazmat.primitives import serialization` import. Task 7 added a module-level import of the same thing. The local import is now redundant dead code.
**Fix:** Remove the local import inside `_fingerprint_public_key`. Touches Task 5 code, so defer to a polish pass.

---

## Task 8 — 4 items (commit `71b10a1`)

### T8-I1, T8-I2 — SEE PRIORITY ABOVE
### T8-warn-policy-visibility — SEE PRIORITY ABOVE (Task 11 territory)

### T8-M1 — Mixed-batch test
**File:** `tests/test_learning.py` `TestLoadExclusionsSignatureVerification`
**Problem:** The 3 Task 8 tests cover reject-quarantine, warn-pass-through, and valid-signed INDIVIDUALLY. Missing a mixed-batch test where an exclusions file contains BOTH a signed-valid entry AND an unsigned-reject entry, asserting both quarantine states are set independently in the same load.
**Fix:** Add `test_load_exclusions_mixed_signed_and_unsigned_policy_applies_per_entry`. ~25 lines. Pins iteration semantics — catches a future bug where a refactor short-circuits on first quarantine.

### T8-M4 — `record_exclusion` O(n²) verification cost
**File:** `src/screw_agents/learning.py` `record_exclusion`
**Problem:** Every `record_exclusion` call triggers `load_exclusions` which verifies every existing signed entry. For N signed entries, the k-th `record_exclusion` call does O(k) verifications. Cumulative cost over file lifetime is O(n²).
**Why defer:** Phase 3a is small-scale (tens of entries). Phase 4+ autoresearch may record hundreds per run.
**Fix (future):** Cache verification results keyed on `(exclusion.id, exclusion.signature)`, OR skip re-verification when the caller is just appending. Defer until scale matters.

---

## Task 9 — 13 items (commits `94c3c5f` + `6a46a9b` fingerprint fix-up)

Task 9.1 already fixed **C-1** (first-reviewer heuristic → fingerprint-based signer selection). All Important and Minor items below are deferred.

### T9-I1 — Race condition on concurrent `record_exclusion`
**File:** `src/screw_agents/learning.py` `record_exclusion`
**Problem:** Two concurrent calls both read `existing` with N entries, both compute `next_seq = N + 1`, both produce `fp-YYYY-MM-DD-(N+1)`. The second write overwrites the first → unique ID violated, one entry lost.
**Fix:** Wrap read-modify-write in `fcntl.flock` on a sibling `.lock` file. Or (lower-cost) document the limitation in the docstring: "Not safe for concurrent invocation — external serialization required."
**When:** Single polish commit OR when Phase 7 MCP server introduces multi-process risk.

### T9-I2 — Atomic file write
**File:** `src/screw_agents/learning.py` `record_exclusion` write path
**Problem:** `path.write_text(...)` is not atomic. A crash mid-write leaves a partial YAML file. Next `load_exclusions` raises `ValueError` and ALL exclusions become inaccessible.
**Fix:** ~3 lines:
```python
tmp = path.with_suffix(".yaml.tmp")
tmp.write_text(yaml.dump(data, ...), encoding="utf-8")
os.replace(tmp, path)  # atomic on POSIX
```
**When:** High-value, low-cost fix. Single polish commit.

### T9-I3 — SEE PRIORITY ABOVE (Task 11 cluster)

### T9-I4 — Redundant `load_config` call
**File:** `src/screw_agents/learning.py` `record_exclusion` (~line 175 and 186)
**Problem:** `record_exclusion` calls `load_exclusions` (which internally calls `load_config`) AND then directly calls `load_config` again. Two disk reads + two YAML parses per `record_exclusion` call.
**Fix:** Add optional `config: ScrewConfig | None = None` parameter to `load_exclusions`. `record_exclusion` loads config once, passes it to `load_exclusions`.
**When:** Single polish commit.

### T9-M1 — Fallback signer email validity
**File:** `src/screw_agents/learning.py` `record_exclusion` fallback branch
**Problem:** `f"local@{project_root.name}"` may not be valid RFC-5321 if `project_root.name` contains spaces, `@`, Unicode, etc.
**Fix:** Sanitize OR hardcode `local@screw-agents.local`:
```python
safe_name = re.sub(r"[^a-zA-Z0-9._-]", "-", project_root.name) or "project"
signer_email = f"local@{safe_name}"
```

### T9-M2 — `chmod(0o600)` no-op on Windows
**File:** `src/screw_agents/learning.py` `_get_or_create_local_private_key`
**Problem:** On Windows, `Path.chmod(0o600)` only sets the read-only bit. The local private key file is world-readable to any local account.
**Fix:** Platform guard with loud warning:
```python
import sys
if sys.platform == "win32":
    warnings.warn(
        "Local signing key created on Windows without ACL restriction; "
        "file may be readable by other local accounts.",
        stacklevel=2,
    )
else:
    key_path.chmod(0o600)
```
Proper DACL implementation via pywin32 is a follow-up.

### T9-M3 — Key directory permissions
**File:** `src/screw_agents/learning.py` `_get_or_create_local_private_key`
**Problem:** `.screw/local/keys/` is created with default umask (world-executable). The key file is `0o600`, but directory traversal is permitted.
**Fix:** `try: key_dir.chmod(0o700); except OSError: pass` after `mkdir`. Best-effort defense-in-depth.

### T9-M4 — `SCREW_FORCE_LOCAL_KEY` test comment clarity
**File:** `tests/test_learning.py` `TestRecordExclusionSignsOnWrite`
**Problem:** The env var is a no-op placeholder; comments don't explain WHY it's set.
**Fix:** Tighten comment to explain "reserved for Task 12's init-trust which will probe `~/.ssh/id_ed25519`; set here to document the future contract."

### T9-M5 — `_get_or_create_local_private_key` generate-then-reread
**File:** `src/screw_agents/learning.py` `_get_or_create_local_private_key`
**Problem:** When a fresh key is generated, the code writes it to disk and immediately re-reads it. The generated `priv` object is already usable.
**Fix:** Skip the round-trip:
```python
if not key_path.exists():
    # ... generate and write ...
    # priv is already usable from Ed25519PrivateKey.generate()
else:
    priv = Ed25519PrivateKey.from_private_bytes(key_path.read_bytes())
pub_line = _public_key_to_openssh_line(priv.public_key(), ...)
```
Micro-optimization + cleaner flow.

### ~~T9-M6~~ — RESOLVED
Multi-reviewer test was added as part of the C-1 fix in commit `6a46a9b` (`test_record_exclusion_multi_reviewer_picks_matching_key`).

### T9-M7 — Pre-init-trust fallback test
**File:** `tests/test_learning.py` `TestRecordExclusionSignsOnWrite`
**Problem:** No test exercises the branch where `config.exclusion_reviewers` is empty → fallback to `f"local@{project_root.name}"` → entry quarantined on reload (expected pre-init-trust UX).
**Fix:** Add `test_record_exclusion_without_reviewers_uses_fallback_email`:
```python
def test_record_exclusion_without_reviewers_uses_fallback_email(self, tmp_path, monkeypatch):
    """Without init-trust, record_exclusion stamps fallback email and entry quarantines on reload."""
    monkeypatch.setenv("SCREW_FORCE_LOCAL_KEY", "1")
    excl_input = ExclusionInput(...)
    saved = record_exclusion(tmp_path, excl_input)
    assert saved.signed_by == f"local@{tmp_path.name}"
    assert saved.signature is not None
    loaded = load_exclusions(tmp_path)
    assert loaded[0].quarantined is True  # no matching reviewer → quarantine
```
Documents the "didn't run init-trust" UX explicitly.

### T9-M8 — `_pub_line` discard comment
**File:** `src/screw_agents/learning.py` `record_exclusion`
**Problem:** The line `priv, _pub_line = _get_or_create_local_private_key(project_root)` discards `_pub_line` without explanation.
**Fix:** One-line comment:
```python
# pub_line unused here — Task 12's init-trust is the explicit registration
# path into config.exclusion_reviewers.
priv, _pub_line = _get_or_create_local_private_key(project_root)
```

### T9-M9 — Silent coupling with Task 12: no warning on fallback
**File:** `src/screw_agents/learning.py` `record_exclusion`
**Problem:** When `matching_reviewer is None` (pre-init-trust), the fallback branch runs silently. User gets no indication that their exclusion will be quarantined on the next scan.
**Fix:** Emit a warning:
```python
if matching_reviewer is not None:
    signer_email = matching_reviewer.email
else:
    signer_email = f"local@{project_root.name}"
    warnings.warn(
        f"No matching reviewer found for local signing key; exclusion {exclusion_id} "
        f"will be quarantined on next load. Run `screw-agents init-trust` to register "
        f"the local key.",
        stacklevel=2,
    )
```

---

## Summary — Item count by task

| Task | Total items | Priority items | Deferred | Resolved |
|---|---:|---:|---:|---:|
| Task 2 | 5 | 0 | 5 | 0 |
| Task 3 | 5 | 0 | 4 | 1 (T3-M5) |
| Task 4 | 3 | 0 | 3 | 0 |
| Task 5 | 7 | 1 (T5-M1) | 5 | 1 (T5-M5 no-action) |
| Task 6 | 10 | 2 (T6-I1, T6-I2) | 7 | 1 (T6-I3) |
| Task 7 | 4 | 0 | 4 | 0 |
| Task 8 | 4 | 3 (T8-I1, T8-I2, warn-policy) | 1 | 0 |
| Task 9 | 14 | 1 (T9-I3) | 12 | 1 (T9-M6) |
| **Total** | **52** | **7** | **41** | **4** |

**Active deferred items to address: 48** (41 deferred + 7 priority items to address before specific downstream tasks).

Priority items must land before their downstream-task dependencies. Deferred items can batch into a single polish commit before PR#1 opens, or ride-along with natural cleanup touches.
