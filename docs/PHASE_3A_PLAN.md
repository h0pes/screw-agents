# Phase 3a: Foundation, Learning, Cleanup — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship Phase 3a across three PRs — unified SSH-based content trust infrastructure (with Phase 2 exclusions retrofit), learning aggregation + feedback loop, and Phase 2 E2E carryover cleanup — landing before Phase 3b (adaptive analysis scripts) begins.

**Architecture:** SSH-key-based signing establishes a uniform trust boundary for everything in `.screw/` that affects scan integrity. Phase 2's exclusions are retrofitted onto this trust model; Phase 3b will consume the same infrastructure for adaptive scripts. Learning aggregation is purely additive, reading the (now signed) exclusions database and producing three report types via a new on-demand MCP tool. Carryover cleanup resolves three items surfaced in Phase 2 E2E testing: `scan_domain` pagination, formatter polish, and the long-deferred CSV output format.

**Tech Stack:** Python 3.11+ (Pydantic, PyYAML, `cryptography` for Ed25519 fallback), OpenSSH (`ssh-keygen -Y sign` / `-Y verify`), Markdown (Claude Code agents/skills/commands), `uv` for package management, `pytest` for testing.

**Spec:** `docs/specs/2026-04-13-phase-3-adaptive-analysis-learning-design.md` (local, not in git)

**Companion research:** `docs/research/phase-3-sandbox-research.md` (local, informs Phase 3b)

**Phase 3b plan:** `docs/PHASE_3B_PLAN.md` — to be written after Phase 3a ships. Phase 3b depends on infrastructure this plan builds (signing, `script_reviewers` in `.screw/config.yaml`, `verify_script` helper); its exact task breakdown may be refined based on how Phase 3a lands.

**Key references for implementers:**
- `src/screw_agents/models.py` — existing Pydantic models (Finding, FindingTriage, Exclusion, etc.)
- `src/screw_agents/learning.py` — Phase 2 exclusion storage + matching (to be extended in PR #1)
- `src/screw_agents/engine.py` — ScanEngine with assemble_scan, format_output
- `src/screw_agents/server.py` — MCP server with _dispatch_tool, list_tool_definitions
- `src/screw_agents/formatter.py` — format_findings (json/sarif/markdown) — extended in PR #3
- `src/screw_agents/results.py` — write_scan_results MCP tool (Phase 2 PR #5)
- `tests/conftest.py` — shared fixtures (domains_dir, fixtures_dir)
- `plugins/screw/agents/screw-sqli.md` — existing subagent format reference
- `plugins/screw/skills/screw-review/SKILL.md` — existing skill format reference
- `docs/PHASE_2_PLAN.md` — Phase 2 plan for style reference

---

## Three PRs, Sequential

```
PR #1: Trust Infrastructure + Exclusions Retrofit
  ├── Tasks 1-15
  ├── Goal: uniform SSH-signing-based content trust for .screw/
  ├── Exit: all exclusions signed or explicitly quarantined; tests green
  │
  ▼ (PR #1 merged, validated)
  │
PR #2: Learning Aggregation + On-Demand Surface
  ├── Tasks 16-23
  ├── Goal: pattern/directory/FP-report aggregation via /screw:learning-report
  ├── Exit: full aggregation flow exercised with seeded exclusions
  │
  ▼ (PR #2 merged, validated)
  │
PR #3: Carryover Cleanup (X1 + X2 + X3)
  ├── Tasks 24-35
  ├── X1: scan_domain cursor pagination
  ├── X2: formatter polish (JSON null / SARIF shortDescription / Markdown CWE names)
  ├── X3: CSV output format
  └── Exit: Phase 2 E2E known limitations addressed; all tests green
```

Each PR is independently reviewable and mergeable. PR #2 depends on PR #1's signed exclusions; PR #3 is independent of PR #1 and PR #2 and could in principle ship first, but the numbering preserves review-effort ordering (biggest design-heavy PR first, smallest cleanup PR last).

---

## File Map

### New files

| File | Responsibility | PR |
|---|---|---|
| `src/screw_agents/trust.py` | Signing/verification helpers, canonicalization, config loading | PR #1 |
| `tests/test_trust.py` | Unit tests for trust module | PR #1 |
| `src/screw_agents/cli/__init__.py` | CLI subcommand dispatch (new package) | PR #1 |
| `src/screw_agents/cli/init_trust.py` | `screw-agents init-trust` subcommand | PR #1 |
| `src/screw_agents/cli/migrate_exclusions.py` | `screw-agents migrate-exclusions` subcommand | PR #1 |
| `src/screw_agents/cli/validate_exclusion.py` | `screw-agents validate-exclusion <id>` | PR #1 |
| `tests/test_cli_trust.py` | Integration tests for CLI trust subcommands | PR #1 |
| `src/screw_agents/aggregation.py` | Learning aggregation pipeline (3 feature reports) | PR #2 |
| `tests/test_aggregation.py` | Unit tests for aggregation module | PR #2 |
| `plugins/screw/agents/screw-learning-analyst.md` | Subagent that presents aggregation reports conversationally | PR #2 |
| `plugins/screw/commands/learning-report.md` | `/screw:learning-report` slash command | PR #2 |
| `tests/test_aggregation_integration.py` | End-to-end tests for aggregation flow | PR #2 |
| `tests/test_pagination.py` | Integration tests for `scan_domain` cursor pagination | PR #3 |
| `tests/test_csv_format.py` | Unit tests for CSV formatter | PR #3 |

### Modified files

| File | Change | PR |
|---|---|---|
| `src/screw_agents/models.py` | Add `ReviewerKey`, `ScrewConfig`; extend `Exclusion` with `signed_by`, `signature`, `signature_version`, `quarantined` | PR #1 |
| `src/screw_agents/learning.py` | Verify signatures on load; sign on record; quarantine-aware return | PR #1 |
| `src/screw_agents/engine.py` | Include `trust_status` in scan responses; cursor pagination in `scan_domain`; `short_description` in YAML meta | PR #1, PR #3 |
| `src/screw_agents/server.py` | Wire `verify_trust`, `aggregate_learning` MCP tools; pass cursor through to engine | PR #1, PR #2, PR #3 |
| `src/screw_agents/results.py` | Surface trust status in scan reports; support CSV format in `write_scan_results` | PR #1, PR #3 |
| `src/screw_agents/formatter.py` | Add `format_csv`; null for empty `impact`/`exploitability`; richer SARIF shortDescription; full CWE names in Markdown | PR #3 |
| `pyproject.toml` | Add `cryptography` dependency for Ed25519 fallback; register `screw-agents` console script | PR #1 |
| `plugins/screw/agents/screw-sqli.md` | Updated prompt to surface `trust_status`; mention `/screw:learning-report` | PR #1, PR #2 |
| `plugins/screw/agents/screw-cmdi.md` | Same updates | PR #1, PR #2 |
| `plugins/screw/agents/screw-ssti.md` | Same updates | PR #1, PR #2 |
| `plugins/screw/agents/screw-xss.md` | Same updates | PR #1, PR #2 |
| `plugins/screw/agents/screw-injection.md` | Same updates, plus cursor pagination loop instructions | PR #1, PR #2, PR #3 |
| `plugins/screw/agents/screw-full-review.md` | Same updates | PR #1, PR #2, PR #3 |
| `domains/injection-input-handling/sqli.yaml` | Add `short_description` field to agent meta | PR #3 |
| `domains/injection-input-handling/cmdi.yaml` | Add `short_description` field | PR #3 |
| `domains/injection-input-handling/ssti.yaml` | Add `short_description` field | PR #3 |
| `domains/injection-input-handling/xss.yaml` | Add `short_description` field | PR #3 |

---

## Dependency Graph (Phase 3a)

```
PR #1: Trust Infrastructure
═══════════════════════════

Task 1 (models: ReviewerKey, ScrewConfig)
    │
    ├─► Task 2 (models: extend Exclusion)
    │       │
    │       ▼
    ├─► Task 3 (trust.py: canonicalize_exclusion, canonicalize_script)
    │       │
    │       ▼
    ├─► Task 4 (trust.py: sign_content wrapper — ssh-keygen + cryptography fallback)
    │       │
    │       ▼
    ├─► Task 5 (trust.py: verify_signature wrapper)
    │       │
    │       ▼
    ├─► Task 6 (trust.py: load_config + auto-generate stub)
    │       │
    │       ▼
    ├─► Task 7 (trust.py: verify_exclusion, verify_script)
    │       │
    │       ▼
    ├─► Task 8 (learning.py: extend load_exclusions with verification)
    │       │
    │       ▼
    ├─► Task 9 (learning.py: extend record_exclusion with signing)
    │       │
    │       ▼
    ├─► Task 10 (engine.py + server.py: verify_trust MCP tool + trust_status in scan responses)
    │       │
    │       ▼
    ├─► Task 11 (results.py: surface trust status in Markdown/JSON scan reports)
    │       │
    │       ▼
    ├─► Task 12 (cli: init-trust subcommand)
    │       │
    │       ▼
    ├─► Task 13 (cli: migrate-exclusions subcommand)
    │       │
    │       ▼
    ├─► Task 14 (cli: validate-exclusion subcommand)
    │       │
    │       ▼
    └─► Task 15 (subagent prompts: surface quarantined counts)

PR #2: Learning Aggregation
═══════════════════════════

Task 16 (aggregation.py: Pydantic models)
    │
    ├─► Task 17 (aggregation.py: aggregate_pattern_confidence)
    │       │
    │       ▼
    ├─► Task 18 (aggregation.py: aggregate_directory_suggestions)
    │       │
    │       ▼
    ├─► Task 19 (aggregation.py: aggregate_fp_report)
    │       │
    │       ▼
    ├─► Task 20 (server.py: aggregate_learning MCP tool)
    │       │
    │       ▼
    ├─► Task 21 (screw-learning-analyst subagent markdown)
    │       │
    │       ▼
    ├─► Task 22 (learning-report slash command)
    │       │
    │       ▼
    └─► Task 23 (integration test: seeded exclusions → full aggregation flow)

PR #3: Carryover Cleanup
════════════════════════

Task 24 (X1: add cursor parameter to scan_domain engine + server)
    │
    ▼
Task 25 (X1: subagent prompt updates for pagination loop)
    │
    ▼
Task 26 (X1: integration test with large fixture set)
    │
    ▼
Task 27 (X2.1: null defaults for Finding.impact and Finding.exploitability)
    │
    ▼
Task 28 (X2.1: update JSON formatter + regression tests)
    │
    ▼
Task 29 (X2.2: short_description in YAML agent meta schema)
    │
    ▼
Task 30 (X2.2: populate short_description in 4 existing YAML agents)
    │
    ▼
Task 31 (X2.2: SARIF formatter uses short_description)
    │
    ▼
Task 32 (X2.3: CWE long-name lookup table)
    │
    ▼
Task 33 (X2.3: Markdown formatter uses full CWE names)
    │
    ▼
Task 34 (X3: format_csv function + write_scan_results CSV support)
    │
    ▼
Task 35 (X3: integration test for CSV output)
```

---

## PR #1: Trust Infrastructure + Exclusions Retrofit

**PR goal:** establish SSH-key-based content trust for `.screw/`, retrofit Phase 2 exclusions onto it. At merge, every exclusion is either signed + verified or explicitly quarantined with clear user-facing surfacing.

**Key design properties:**
- Trust root is the git repository (`.screw/config.yaml` declares trusted keys)
- Split reviewer lists from day one: `exclusion_reviewers` and `script_reviewers` (Phase 3b will use the second list)
- Default for unsigned legacy content: `reject`
- Primary signing path: `ssh-keygen -Y sign` / `-Y verify`
- Fallback signing path: Python `cryptography` Ed25519 when OpenSSH unavailable

**PR #1 exit criteria:**
- All tests green
- Full round-trip: `init-trust` → `record_exclusion` → reload process → verified
- Phase 2 regression tests still pass
- Quarantined content is never silently applied or dropped

---

### Task 1: `ReviewerKey` and `ScrewConfig` Pydantic Models

**Files:**
- Modify: `src/screw_agents/models.py`
- Test: `tests/test_models.py` (extend existing)

- [ ] **Step 1: Write failing tests for the new models**

Add to `tests/test_models.py`:

```python
from screw_agents.models import ReviewerKey, ScrewConfig


def test_reviewer_key_roundtrip():
    key = ReviewerKey(
        name="Marco",
        email="marco@example.com",
        key="ssh-ed25519 AAAAC3Nz... marco@arch",
    )
    assert key.name == "Marco"
    assert key.email == "marco@example.com"
    assert key.key.startswith("ssh-ed25519 ")


def test_screw_config_defaults():
    config = ScrewConfig()
    assert config.version == 1
    assert config.exclusion_reviewers == []
    assert config.script_reviewers == []
    assert config.adaptive is False
    assert config.legacy_unsigned_exclusions == "reject"
    assert config.trusted_reviewers_file is None


def test_screw_config_with_reviewers():
    config = ScrewConfig(
        exclusion_reviewers=[
            ReviewerKey(name="Marco", email="marco@example.com", key="ssh-ed25519 X marco@arch"),
        ],
        script_reviewers=[
            ReviewerKey(name="Marco", email="marco@example.com", key="ssh-ed25519 X marco@arch"),
        ],
        adaptive=True,
    )
    assert len(config.exclusion_reviewers) == 1
    assert config.adaptive is True


def test_screw_config_rejects_invalid_legacy_policy():
    import pytest
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        ScrewConfig(legacy_unsigned_exclusions="nonsense")
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_models.py::test_reviewer_key_roundtrip tests/test_models.py::test_screw_config_defaults tests/test_models.py::test_screw_config_with_reviewers tests/test_models.py::test_screw_config_rejects_invalid_legacy_policy -v`

Expected: FAIL with `ImportError: cannot import name 'ReviewerKey' from 'screw_agents.models'`

- [ ] **Step 3: Implement the models**

Add to `src/screw_agents/models.py` (near the other config/meta models):

```python
from typing import Literal


class ReviewerKey(BaseModel):
    """A single trusted reviewer's identity and public key."""

    name: str
    email: str
    key: str  # SSH public key in OpenSSH format (e.g., "ssh-ed25519 AAAA... user@host")


class ScrewConfig(BaseModel):
    """Project-level screw-agents configuration stored in .screw/config.yaml."""

    version: int = 1
    exclusion_reviewers: list[ReviewerKey] = []
    script_reviewers: list[ReviewerKey] = []
    adaptive: bool = False
    legacy_unsigned_exclusions: Literal["reject", "warn", "allow"] = "reject"
    trusted_reviewers_file: str | None = None
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_models.py::test_reviewer_key_roundtrip tests/test_models.py::test_screw_config_defaults tests/test_models.py::test_screw_config_with_reviewers tests/test_models.py::test_screw_config_rejects_invalid_legacy_policy -v`

Expected: 4 passed

- [ ] **Step 5: Commit**

```bash
git add src/screw_agents/models.py tests/test_models.py
git commit -m "feat(phase3a): add ReviewerKey and ScrewConfig Pydantic models"
```

---

### Task 2: Extend `Exclusion` with Signing Fields

**Files:**
- Modify: `src/screw_agents/models.py`
- Test: `tests/test_models.py` (extend)

- [ ] **Step 1: Write failing tests for extended Exclusion**

Add to `tests/test_models.py`:

```python
def test_exclusion_signing_fields_optional():
    """Phase 2 exclusions without signatures still parse (backwards compat)."""
    excl = Exclusion(
        id="fp-2026-04-14-001",
        created="2026-04-14T10:00:00Z",
        agent="sqli",
        finding=ExclusionFinding(
            file="src/services/user_service.py",
            line=42,
            code_pattern="db.text_search(*)",
            cwe="CWE-89",
        ),
        reason="uses parameterized internals",
        scope=ExclusionScope(type="pattern", pattern="db.text_search(*)"),
    )
    assert excl.signed_by is None
    assert excl.signature is None
    assert excl.signature_version == 1
    assert excl.quarantined is False


def test_exclusion_with_signing_fields():
    excl = Exclusion(
        id="fp-2026-04-14-002",
        created="2026-04-14T10:00:00Z",
        agent="sqli",
        finding=ExclusionFinding(
            file="src/auth.py", line=12, code_pattern="*", cwe="CWE-89"
        ),
        reason="test",
        scope=ExclusionScope(type="exact_line", path="src/auth.py"),
        signed_by="marco@example.com",
        signature="U1NIU0lH...",
        signature_version=1,
    )
    assert excl.signed_by == "marco@example.com"
    assert excl.signature is not None
    assert excl.quarantined is False
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_models.py::test_exclusion_signing_fields_optional tests/test_models.py::test_exclusion_with_signing_fields -v`

Expected: FAIL with `TypeError: unexpected keyword argument 'signed_by'`

- [ ] **Step 3: Extend the Exclusion model**

In `src/screw_agents/models.py`, locate the existing `Exclusion` class and add four fields:

```python
class Exclusion(BaseModel):
    # ... existing Phase 2 fields ...
    id: str
    created: str
    agent: str
    finding: ExclusionFinding
    reason: str
    scope: ExclusionScope
    times_suppressed: int = 0
    last_suppressed: str | None = None

    # new in Phase 3a — signing
    signed_by: str | None = None
    signature: str | None = None
    signature_version: int = 1

    # runtime flag (not persisted to YAML)
    quarantined: bool = False

    model_config = {"extra": "forbid"}
```

Note: `quarantined` is a runtime flag. Add a `model_dump` override to exclude it when serializing to YAML (or use `model_dump(exclude={"quarantined"})` at call sites — Step 3 of Task 9 will handle this).

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_models.py -v`

Expected: all tests pass (including Phase 2 regression tests)

- [ ] **Step 5: Commit**

```bash
git add src/screw_agents/models.py tests/test_models.py
git commit -m "feat(phase3a): extend Exclusion model with signing fields"
```

---

### Task 3: Trust Module Skeleton + Canonicalization

**Files:**
- Create: `src/screw_agents/trust.py`
- Create: `tests/test_trust.py`

- [ ] **Step 1: Write failing tests for canonicalization**

Create `tests/test_trust.py`:

```python
"""Unit tests for screw_agents.trust — signing, verification, canonicalization."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from screw_agents.models import (
    Exclusion,
    ExclusionFinding,
    ExclusionScope,
)
from screw_agents.trust import (
    canonicalize_exclusion,
    canonicalize_script,
)


def _sample_exclusion(*, signed: bool = False) -> Exclusion:
    return Exclusion(
        id="fp-2026-04-14-001",
        created="2026-04-14T10:00:00Z",
        agent="sqli",
        finding=ExclusionFinding(
            file="src/services/user_service.py",
            line=42,
            code_pattern="db.text_search(*)",
            cwe="CWE-89",
        ),
        reason="uses parameterized internals",
        scope=ExclusionScope(type="pattern", pattern="db.text_search(*)"),
        signed_by="marco@example.com" if signed else None,
        signature="U1NIU0lH..." if signed else None,
    )


def test_canonicalize_exclusion_is_deterministic():
    excl = _sample_exclusion()
    out1 = canonicalize_exclusion(excl)
    out2 = canonicalize_exclusion(excl)
    assert out1 == out2
    assert isinstance(out1, bytes)


def test_canonicalize_exclusion_excludes_signature_fields():
    """Canonical form must not include signature-related fields; otherwise signing loops forever."""
    unsigned = _sample_exclusion(signed=False)
    signed = _sample_exclusion(signed=True)
    assert canonicalize_exclusion(unsigned) == canonicalize_exclusion(signed)


def test_canonicalize_exclusion_excludes_runtime_flags():
    """`quarantined` is a runtime flag, not part of the signed content."""
    excl = _sample_exclusion()
    excl_quarantined = _sample_exclusion()
    excl_quarantined.quarantined = True
    assert canonicalize_exclusion(excl) == canonicalize_exclusion(excl_quarantined)


def test_canonicalize_exclusion_changes_when_content_changes():
    a = _sample_exclusion()
    b = _sample_exclusion()
    b.reason = "different reason"
    assert canonicalize_exclusion(a) != canonicalize_exclusion(b)


def test_canonicalize_script_is_deterministic():
    source = "from screw_agents.adaptive import emit_finding\n\ndef analyze(project):\n    pass\n"
    meta = {
        "name": "test-script",
        "created": "2026-04-14T10:00:00Z",
        "target_patterns": ["QueryBuilder.execute"],
    }
    out1 = canonicalize_script(source=source, meta=meta)
    out2 = canonicalize_script(source=source, meta=meta)
    assert out1 == out2


def test_canonicalize_script_excludes_signature_keys():
    source = "def analyze(project): pass\n"
    meta_unsigned = {"name": "s", "target_patterns": ["x"]}
    meta_signed = {
        "name": "s",
        "target_patterns": ["x"],
        "signed_by": "marco@example.com",
        "signature": "U1NI...",
    }
    assert canonicalize_script(source=source, meta=meta_unsigned) == canonicalize_script(
        source=source, meta=meta_signed
    )
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_trust.py -v`

Expected: FAIL with `ModuleNotFoundError: No module named 'screw_agents.trust'`

- [ ] **Step 3: Create the trust module skeleton with canonicalization**

Create `src/screw_agents/trust.py`:

```python
"""Content trust for .screw/ — SSH-key-based signing and verification.

Phase 3a establishes a uniform trust boundary for everything in .screw/ that
affects scan integrity. Exclusions (Phase 2, retrofit) and adaptive scripts
(Phase 3b, new) both go through this module.

The trust root is the git repository itself: .screw/config.yaml declares
trusted signing keys, and its integrity is rooted in commit history.

Primary signing path: `ssh-keygen -Y sign` / `ssh-keygen -Y verify` via subprocess.
Fallback signing path: Python `cryptography` Ed25519 when OpenSSH is not available.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from screw_agents.models import Exclusion

# Canonical form excludes these keys when hashing/signing exclusions.
_EXCLUSION_CANONICAL_EXCLUDE = {
    "signed_by",
    "signature",
    "signature_version",
    "quarantined",
}

# Canonical form excludes these keys when hashing/signing script metadata.
_SCRIPT_META_CANONICAL_EXCLUDE = {
    "signed_by",
    "signature",
    "signature_version",
}


def canonicalize_exclusion(exclusion: Exclusion) -> bytes:
    """Return the canonical JSON byte form of an exclusion for signing.

    Deterministic: identical inputs produce identical outputs across Python
    versions, OS platforms, and repeated calls. Signature-related fields and
    runtime flags are excluded — they must never affect the signed content.
    """
    data = exclusion.model_dump(exclude=_EXCLUSION_CANONICAL_EXCLUDE)
    return _canonical_json_bytes(data)


def canonicalize_script(*, source: str, meta: dict[str, Any]) -> bytes:
    """Return the canonical byte form of a script + metadata pair for signing.

    The canonical form is `{"source": <str>, "meta": <dict minus signing keys>}`
    serialized as sorted-key JSON. Both the source text and metadata contribute
    to the signature so either changing alone invalidates it.
    """
    filtered_meta = {k: v for k, v in meta.items() if k not in _SCRIPT_META_CANONICAL_EXCLUDE}
    payload = {"source": source, "meta": filtered_meta}
    return _canonical_json_bytes(payload)


def _canonical_json_bytes(data: Any) -> bytes:
    """Sorted-key, compact-separator JSON with UTF-8 encoding.

    This is NOT RFC 8785 JCS — we use `json.dumps(..., sort_keys=True, separators=(',', ':'))`
    which is deterministic for the data shapes we sign (dicts/lists/strings/ints/bools/None).
    If we need stronger canonicalization later (Unicode normalization, number handling edge
    cases), swap the implementation here — callers are stable.
    """
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_trust.py -v`

Expected: 6 passed

- [ ] **Step 5: Commit**

```bash
git add src/screw_agents/trust.py tests/test_trust.py
git commit -m "feat(phase3a): trust module skeleton with canonicalization"
```

---

### Task 4: Signing Wrapper — ssh-keygen + cryptography Fallback

**Files:**
- Modify: `src/screw_agents/trust.py`
- Modify: `tests/test_trust.py`
- Modify: `pyproject.toml`

- [ ] **Step 1: Add `cryptography` as a runtime dependency**

In `pyproject.toml`, add to `dependencies` (the main runtime list, not dev):

```toml
dependencies = [
    "mcp>=1.0",
    "tree-sitter>=0.23",
    "tree-sitter-python>=0.23",
    "tree-sitter-javascript>=0.23",
    "tree-sitter-typescript>=0.23",
    "tree-sitter-go>=0.23",
    "tree-sitter-rust>=0.23",
    "tree-sitter-java>=0.23",
    "tree-sitter-ruby>=0.23",
    "tree-sitter-php>=0.23",
    "tree-sitter-c>=0.23",
    "tree-sitter-cpp>=0.23",
    "pyyaml>=6.0",
    "pydantic>=2.0",
    "cryptography>=42.0",
]
```

(Exact list should match your current `pyproject.toml` — add only the `cryptography` line if the others differ.)

Then run: `uv sync`

Expected: `cryptography` installed into the venv.

- [ ] **Step 2: Write failing tests for `sign_content`**

Add to `tests/test_trust.py`:

```python
def test_sign_content_returns_base64_signature(tmp_path: Path):
    # Generate a throwaway Ed25519 SSH key for the test using cryptography.
    # Test covers the cryptography-fallback path directly to avoid depending on
    # ssh-keygen being on PATH in CI.
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    priv = Ed25519PrivateKey.generate()

    from screw_agents.trust import sign_content

    canonical = b"test content to sign"
    signature = sign_content(canonical, private_key=priv, key_comment="test@example")

    assert isinstance(signature, str)
    assert len(signature) > 0
    # Cryptography fallback emits base64 over raw Ed25519 signature bytes.
    # The shape is opaque here; verification test (next task) exercises round-trip.


def test_sign_content_deterministic_for_same_input(tmp_path: Path):
    """Ed25519 signatures are deterministic — same key + same message → same signature."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    priv = Ed25519PrivateKey.generate()

    from screw_agents.trust import sign_content

    canonical = b"identical content"
    sig1 = sign_content(canonical, private_key=priv, key_comment="t@e")
    sig2 = sign_content(canonical, private_key=priv, key_comment="t@e")
    assert sig1 == sig2
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `uv run pytest tests/test_trust.py::test_sign_content_returns_base64_signature tests/test_trust.py::test_sign_content_deterministic_for_same_input -v`

Expected: FAIL with `ImportError: cannot import name 'sign_content'`

- [ ] **Step 4: Implement `sign_content` with cryptography fallback**

Add to `src/screw_agents/trust.py`:

```python
import base64
import shutil
import subprocess
import tempfile
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


def ssh_keygen_available() -> bool:
    """Return True if `ssh-keygen` is on PATH."""
    return shutil.which("ssh-keygen") is not None


def sign_content(
    canonical: bytes,
    *,
    private_key: Ed25519PrivateKey | None = None,
    key_path: Path | None = None,
    key_comment: str = "screw-agents",
    namespace: str = "screw-agents",
) -> str:
    """Sign canonical bytes and return a base64-encoded signature.

    Two paths:
      1. `key_path` provided AND `ssh-keygen` on PATH → shell out to `ssh-keygen -Y sign`
      2. `private_key` provided (Ed25519PrivateKey) → cryptography-library signing

    Callers should prefer path 1 for user-facing CLI commands (which consume the user's
    existing SSH key). Path 2 is for tests and for environments without OpenSSH.

    The `namespace` argument is used by ssh-keygen's domain separation. Exclusions
    use "screw-exclusions"; scripts use "screw-scripts".
    """
    if key_path is not None and ssh_keygen_available():
        return _sign_with_ssh_keygen(canonical, key_path=key_path, namespace=namespace)
    if private_key is not None:
        return _sign_with_cryptography(canonical, private_key=private_key)
    raise ValueError(
        "sign_content requires either key_path (with ssh-keygen on PATH) or private_key"
    )


def _sign_with_ssh_keygen(canonical: bytes, *, key_path: Path, namespace: str) -> str:
    """Sign via `ssh-keygen -Y sign` subprocess. Writes to a tempfile because
    ssh-keygen reads the content to sign from a file."""
    with tempfile.NamedTemporaryFile(mode="wb", delete=False) as tf:
        tf.write(canonical)
        tf_path = Path(tf.name)
    try:
        result = subprocess.run(
            [
                "ssh-keygen",
                "-Y",
                "sign",
                "-f",
                str(key_path),
                "-n",
                namespace,
                str(tf_path),
            ],
            check=True,
            capture_output=True,
        )
        # ssh-keygen writes the signature to <input>.sig
        sig_path = tf_path.with_suffix(tf_path.suffix + ".sig")
        sig_bytes = sig_path.read_bytes()
        sig_path.unlink()
        return base64.b64encode(sig_bytes).decode("ascii")
    finally:
        tf_path.unlink(missing_ok=True)


def _sign_with_cryptography(canonical: bytes, *, private_key: Ed25519PrivateKey) -> str:
    """Sign via the cryptography library — raw Ed25519 signature, base64 encoded."""
    signature_bytes = private_key.sign(canonical)
    return base64.b64encode(signature_bytes).decode("ascii")
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `uv run pytest tests/test_trust.py::test_sign_content_returns_base64_signature tests/test_trust.py::test_sign_content_deterministic_for_same_input -v`

Expected: 2 passed

- [ ] **Step 6: Commit**

```bash
git add src/screw_agents/trust.py tests/test_trust.py pyproject.toml uv.lock
git commit -m "feat(phase3a): sign_content with ssh-keygen and cryptography backends"
```

---

### Task 5: Verification Wrapper — Round-Trip

**Files:**
- Modify: `src/screw_agents/trust.py`
- Modify: `tests/test_trust.py`

- [ ] **Step 1: Write failing tests for `verify_signature` round-trip**

Add to `tests/test_trust.py`:

```python
def test_verify_signature_accepts_valid_signature():
    """Sign with cryptography, verify with cryptography — round-trip success."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from screw_agents.trust import sign_content, verify_signature, VerificationResult

    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()

    canonical = b"valid content"
    signature = sign_content(canonical, private_key=priv, key_comment="t@e")

    result = verify_signature(canonical, signature, public_keys=[pub])
    assert isinstance(result, VerificationResult)
    assert result.valid is True
    assert result.reason is None


def test_verify_signature_rejects_tampered_content():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from screw_agents.trust import sign_content, verify_signature

    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()

    canonical = b"original content"
    signature = sign_content(canonical, private_key=priv, key_comment="t@e")

    tampered = b"MODIFIED content"
    result = verify_signature(tampered, signature, public_keys=[pub])
    assert result.valid is False
    assert "content mismatch" in result.reason.lower() or "invalid" in result.reason.lower()


def test_verify_signature_rejects_untrusted_key():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from screw_agents.trust import sign_content, verify_signature

    signing_priv = Ed25519PrivateKey.generate()
    other_priv = Ed25519PrivateKey.generate()

    canonical = b"content"
    signature = sign_content(canonical, private_key=signing_priv, key_comment="t@e")

    result = verify_signature(canonical, signature, public_keys=[other_priv.public_key()])
    assert result.valid is False


def test_verify_signature_empty_allowed_keys():
    """With no allowed keys, verification must fail."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from screw_agents.trust import sign_content, verify_signature

    priv = Ed25519PrivateKey.generate()
    canonical = b"content"
    signature = sign_content(canonical, private_key=priv, key_comment="t@e")

    result = verify_signature(canonical, signature, public_keys=[])
    assert result.valid is False
    assert "no trusted keys" in result.reason.lower()
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_trust.py -k "verify_signature" -v`

Expected: FAIL with `ImportError: cannot import name 'verify_signature'`

- [ ] **Step 3: Implement `VerificationResult` + `verify_signature`**

Add to `src/screw_agents/trust.py`:

```python
from dataclasses import dataclass


@dataclass(frozen=True)
class VerificationResult:
    """Result of a signature verification attempt."""

    valid: bool
    reason: str | None = None  # populated when valid is False
    matched_key_identity: str | None = None  # populated when valid is True


def verify_signature(
    canonical: bytes,
    signature: str,
    *,
    public_keys: list[Ed25519PublicKey],
) -> VerificationResult:
    """Verify a base64-encoded signature against a list of allowed public keys.

    Tries each public key until one succeeds. This is compatible with the
    cryptography-fallback signing path (Task 4). For ssh-keygen-produced
    signatures, the SSH-sig wire format would need parsing; Phase 3a uses
    cryptography-backed verification uniformly when invoked from Python code.
    CLI-driven verification that needs full `ssh-keygen -Y verify` semantics
    lives in the CLI subcommands (Task 12-14).
    """
    if not public_keys:
        return VerificationResult(valid=False, reason="no trusted keys configured")

    try:
        signature_bytes = base64.b64decode(signature, validate=True)
    except (ValueError, base64.binascii.Error):
        return VerificationResult(valid=False, reason="signature is not valid base64")

    for pub in public_keys:
        try:
            pub.verify(signature_bytes, canonical)
            return VerificationResult(valid=True, matched_key_identity=_fingerprint_public_key(pub))
        except Exception:  # InvalidSignature from cryptography
            continue

    return VerificationResult(valid=False, reason="signature invalid or content mismatch")


def _fingerprint_public_key(public_key: Ed25519PublicKey) -> str:
    """Short fingerprint of an Ed25519 public key for logging/diagnostics.

    Returns SHA-256 of the raw public key bytes, base64-encoded, first 16 chars.
    NOT cryptographic identity — for display only. Do not use as a trust anchor.
    """
    import hashlib

    from cryptography.hazmat.primitives import serialization

    raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    digest = hashlib.sha256(raw).digest()
    return base64.b64encode(digest).decode("ascii")[:16]
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_trust.py -v`

Expected: all tests pass (including Task 3 and Task 4 tests)

- [ ] **Step 5: Commit**

```bash
git add src/screw_agents/trust.py tests/test_trust.py
git commit -m "feat(phase3a): verify_signature with cryptography round-trip"
```

---

### Task 6: `load_config` with Auto-Generated Stub

**Files:**
- Modify: `src/screw_agents/trust.py`
- Modify: `tests/test_trust.py`

- [ ] **Step 1: Write failing tests for config loading**

Add to `tests/test_trust.py`:

```python
def test_load_config_returns_defaults_when_missing(tmp_path: Path):
    """When .screw/config.yaml is missing, load_config auto-generates a stub and
    returns defaults with reject policy. The stub is written to disk with comments."""
    from screw_agents.trust import load_config

    config = load_config(tmp_path)
    assert config.version == 1
    assert config.exclusion_reviewers == []
    assert config.script_reviewers == []
    assert config.adaptive is False
    assert config.legacy_unsigned_exclusions == "reject"

    # Stub file was created
    stub_path = tmp_path / ".screw" / "config.yaml"
    assert stub_path.exists()
    content = stub_path.read_text()
    assert "trusted" in content.lower()  # contains guidance comments


def test_load_config_parses_existing_file(tmp_path: Path):
    from screw_agents.trust import load_config

    (tmp_path / ".screw").mkdir()
    (tmp_path / ".screw" / "config.yaml").write_text(
        """
version: 1
exclusion_reviewers:
  - name: Marco
    email: marco@example.com
    key: "ssh-ed25519 AAAAC3Nz marco@arch"
script_reviewers:
  - name: Marco
    email: marco@example.com
    key: "ssh-ed25519 AAAAC3Nz marco@arch"
adaptive: true
legacy_unsigned_exclusions: warn
"""
    )
    config = load_config(tmp_path)
    assert len(config.exclusion_reviewers) == 1
    assert config.exclusion_reviewers[0].email == "marco@example.com"
    assert config.adaptive is True
    assert config.legacy_unsigned_exclusions == "warn"


def test_load_config_rejects_malformed_yaml(tmp_path: Path):
    from screw_agents.trust import load_config

    (tmp_path / ".screw").mkdir()
    (tmp_path / ".screw" / "config.yaml").write_text("this is: not: valid: yaml: at: all: [[[")

    with pytest.raises(ValueError, match="config.yaml"):
        load_config(tmp_path)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_trust.py -k "load_config" -v`

Expected: FAIL with `ImportError: cannot import name 'load_config'`

- [ ] **Step 3: Implement `load_config`**

Add to `src/screw_agents/trust.py`:

```python
import yaml

from screw_agents.models import ScrewConfig

_CONFIG_STUB = """\
# screw-agents project configuration
# See docs/PHASE_3A_PLAN.md and docs/specs/ for trust model details.
#
# trusted_reviewers declare the SSH keys permitted to sign content in .screw/.
# Exclusion and script signing are SEPARATE trust domains (split lists).
#
# To register your local key, run: screw-agents init-trust
version: 1

# Reviewers authorized to sign .screw/learning/exclusions.yaml entries.
# Uncomment and add your key after running `screw-agents init-trust`.
exclusion_reviewers: []

# Reviewers authorized to sign .screw/custom-scripts/*.py adaptive scripts.
# Phase 3b feature — leave empty until adaptive scripts are enabled.
script_reviewers: []

# Adaptive analysis mode (Phase 3b). Default: false.
adaptive: false

# Policy for legacy unsigned exclusions (from Phase 2 before signing was introduced):
#   reject  — quarantine unsigned entries; user must re-sign via `screw-agents migrate-exclusions`
#   warn    — apply unsigned entries with a loud warning (90-day deprecation window)
#   allow   — silently apply unsigned entries (NOT RECOMMENDED)
legacy_unsigned_exclusions: reject
"""


def load_config(project_root: Path) -> ScrewConfig:
    """Load .screw/config.yaml, auto-generating a stub if missing.

    Args:
        project_root: project root directory.

    Returns:
        Parsed ScrewConfig. If the file did not exist, a stub is written and
        defaults are returned.

    Raises:
        ValueError: if the file exists but is malformed.
    """
    config_path = project_root / ".screw" / "config.yaml"
    if not config_path.exists():
        config_path.parent.mkdir(parents=True, exist_ok=True)
        config_path.write_text(_CONFIG_STUB)
        return ScrewConfig()

    try:
        raw = yaml.safe_load(config_path.read_text())
    except yaml.YAMLError as exc:
        raise ValueError(f"Malformed .screw/config.yaml at {config_path}: {exc}") from exc

    if raw is None:
        return ScrewConfig()

    try:
        return ScrewConfig(**raw)
    except Exception as exc:
        raise ValueError(f"Invalid .screw/config.yaml at {config_path}: {exc}") from exc
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_trust.py -v`

Expected: all Task 3-6 tests pass

- [ ] **Step 5: Commit**

```bash
git add src/screw_agents/trust.py tests/test_trust.py
git commit -m "feat(phase3a): load_config with auto-generated stub"
```

---

### Task 7: `verify_exclusion` and `verify_script`

**Files:**
- Modify: `src/screw_agents/trust.py`
- Modify: `tests/test_trust.py`

- [ ] **Step 1: Write failing tests for exclusion/script verification**

Add to `tests/test_trust.py`:

```python
def test_verify_exclusion_valid_signature_returns_trusted(tmp_path: Path):
    """Full round-trip: sign an exclusion, build a config with the matching key,
    verify_exclusion returns valid=True."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from screw_agents.models import ReviewerKey, ScrewConfig
    from screw_agents.trust import (
        _public_key_to_openssh_line,
        canonicalize_exclusion,
        sign_content,
        verify_exclusion,
    )

    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    key_line = _public_key_to_openssh_line(pub, comment="marco@test")

    excl = _sample_exclusion()
    canonical = canonicalize_exclusion(excl)
    signature = sign_content(canonical, private_key=priv, key_comment="marco@test")
    excl.signed_by = "marco@example.com"
    excl.signature = signature

    config = ScrewConfig(
        exclusion_reviewers=[
            ReviewerKey(name="Marco", email="marco@example.com", key=key_line)
        ]
    )

    result = verify_exclusion(excl, config=config)
    assert result.valid is True


def test_verify_exclusion_unsigned_returns_invalid(tmp_path: Path):
    from screw_agents.models import ScrewConfig
    from screw_agents.trust import verify_exclusion

    excl = _sample_exclusion()  # no signature
    config = ScrewConfig()
    result = verify_exclusion(excl, config=config)
    assert result.valid is False
    assert "unsigned" in (result.reason or "").lower()


def test_verify_exclusion_untrusted_signer_returns_invalid(tmp_path: Path):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from screw_agents.models import ScrewConfig
    from screw_agents.trust import canonicalize_exclusion, sign_content, verify_exclusion

    priv = Ed25519PrivateKey.generate()
    excl = _sample_exclusion()
    excl.signature = sign_content(canonicalize_exclusion(excl), private_key=priv, key_comment="x")
    excl.signed_by = "attacker@example.com"

    config = ScrewConfig()  # empty exclusion_reviewers → no trusted keys
    result = verify_exclusion(excl, config=config)
    assert result.valid is False


def test_verify_script_round_trip(tmp_path: Path):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from screw_agents.models import ReviewerKey, ScrewConfig
    from screw_agents.trust import (
        _public_key_to_openssh_line,
        canonicalize_script,
        sign_content,
        verify_script,
    )

    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    key_line = _public_key_to_openssh_line(pub, comment="marco@test")

    source = "from screw_agents.adaptive import emit_finding\n\ndef analyze(project):\n    pass\n"
    meta = {"name": "test", "target_patterns": ["X"], "sha256": "abc"}

    canonical = canonicalize_script(source=source, meta=meta)
    signature = sign_content(canonical, private_key=priv, key_comment="marco@test")

    meta_signed = {**meta, "signed_by": "marco@example.com", "signature": signature}

    config = ScrewConfig(
        script_reviewers=[
            ReviewerKey(name="Marco", email="marco@example.com", key=key_line)
        ]
    )
    result = verify_script(source=source, meta=meta_signed, config=config)
    assert result.valid is True
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_trust.py -k "verify_exclusion or verify_script" -v`

Expected: FAIL with `ImportError: cannot import name 'verify_exclusion'`

- [ ] **Step 3: Implement exclusion/script verification**

Add to `src/screw_agents/trust.py`:

```python
from cryptography.hazmat.primitives import serialization


def verify_exclusion(exclusion: Exclusion, *, config: ScrewConfig) -> VerificationResult:
    """Verify an exclusion's signature against the project's exclusion_reviewers.

    Returns VerificationResult. Exclusions with no signature return valid=False
    with reason 'unsigned' — the caller (learning.py) applies the legacy policy.
    """
    if exclusion.signature is None or exclusion.signed_by is None:
        return VerificationResult(valid=False, reason="unsigned")

    canonical = canonicalize_exclusion(exclusion)
    public_keys = _load_public_keys(config.exclusion_reviewers)
    return verify_signature(canonical, exclusion.signature, public_keys=public_keys)


def verify_script(
    *,
    source: str,
    meta: dict[str, Any],
    config: ScrewConfig,
) -> VerificationResult:
    """Verify a script's signature against the project's script_reviewers.

    Returns VerificationResult. Scripts with no signature return valid=False
    with reason 'unsigned'.
    """
    signature = meta.get("signature")
    signed_by = meta.get("signed_by")
    if signature is None or signed_by is None:
        return VerificationResult(valid=False, reason="unsigned")

    canonical = canonicalize_script(source=source, meta=meta)
    public_keys = _load_public_keys(config.script_reviewers)
    return verify_signature(canonical, signature, public_keys=public_keys)


def _load_public_keys(reviewers: list[ReviewerKey]) -> list[Ed25519PublicKey]:
    """Parse the ssh-ed25519 lines in reviewer entries into Ed25519PublicKey objects.

    Ignores any non-Ed25519 keys (for Phase 3a we only support Ed25519 — RSA/ECDSA
    can be added later if needed). Malformed entries are skipped with a warning.
    """
    pubs: list[Ed25519PublicKey] = []
    for reviewer in reviewers:
        try:
            # Parse the OpenSSH public-key line format: "ssh-ed25519 <base64> <comment>"
            parts = reviewer.key.strip().split()
            if len(parts) < 2 or parts[0] != "ssh-ed25519":
                continue
            key_bytes_with_header = base64.b64decode(parts[1], validate=True)
            # The SSH wire format for ed25519 is:
            #   uint32 len("ssh-ed25519") + "ssh-ed25519" + uint32 len(key) + key_bytes (32 B)
            # Skip the header (4 + 11 + 4 = 19 bytes) and take the 32-byte raw key.
            raw_key = key_bytes_with_header[19:19 + 32]
            if len(raw_key) != 32:
                continue
            pubs.append(Ed25519PublicKey.from_public_bytes(raw_key))
        except Exception:
            continue
    return pubs


def _public_key_to_openssh_line(public_key: Ed25519PublicKey, *, comment: str) -> str:
    """Encode an Ed25519PublicKey as a single-line OpenSSH public key.

    Format: "ssh-ed25519 <base64(wire_format)> <comment>"
    This is the inverse of _load_public_keys and is used by tests plus `init-trust`.
    """
    raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    # SSH wire format: len("ssh-ed25519")=11, key_len=32
    wire = (
        len("ssh-ed25519").to_bytes(4, "big")
        + b"ssh-ed25519"
        + (32).to_bytes(4, "big")
        + raw
    )
    return f"ssh-ed25519 {base64.b64encode(wire).decode('ascii')} {comment}"


# Forward-declare names used above so the module parses top-down cleanly.
from screw_agents.models import ReviewerKey  # noqa: E402
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_trust.py -v`

Expected: all Task 3-7 tests pass

- [ ] **Step 5: Commit**

```bash
git add src/screw_agents/trust.py tests/test_trust.py
git commit -m "feat(phase3a): verify_exclusion and verify_script"
```

---

### Task 8: `learning.load_exclusions` Verifies Signatures

**Files:**
- Modify: `src/screw_agents/learning.py`
- Modify: `tests/test_learning.py`

- [ ] **Step 1: Write failing tests for signature-aware loading**

Add to `tests/test_learning.py`:

```python
def test_load_exclusions_quarantines_unsigned_under_reject_policy(tmp_path: Path):
    """Unsigned exclusions with reject policy are returned with quarantined=True."""
    from screw_agents.learning import load_exclusions

    screw = tmp_path / ".screw"
    (screw / "learning").mkdir(parents=True)
    (screw / "learning" / "exclusions.yaml").write_text(
        """
exclusions:
  - id: "fp-2026-04-14-001"
    created: "2026-04-14T10:00:00Z"
    agent: sqli
    finding:
      file: "src/a.py"
      line: 10
      code_pattern: "*"
      cwe: "CWE-89"
    reason: "legacy unsigned"
    scope:
      type: "exact_line"
      path: "src/a.py"
"""
    )
    # Default config → legacy_unsigned_exclusions: reject
    (screw / "config.yaml").write_text("version: 1\nlegacy_unsigned_exclusions: reject\n")

    exclusions = load_exclusions(tmp_path)
    assert len(exclusions) == 1
    assert exclusions[0].quarantined is True


def test_load_exclusions_applies_unsigned_under_warn_policy(tmp_path: Path):
    from screw_agents.learning import load_exclusions

    screw = tmp_path / ".screw"
    (screw / "learning").mkdir(parents=True)
    (screw / "learning" / "exclusions.yaml").write_text(
        """
exclusions:
  - id: "fp-2026-04-14-001"
    created: "2026-04-14T10:00:00Z"
    agent: sqli
    finding:
      file: "src/a.py"
      line: 10
      code_pattern: "*"
      cwe: "CWE-89"
    reason: "legacy unsigned"
    scope:
      type: "exact_line"
      path: "src/a.py"
"""
    )
    (screw / "config.yaml").write_text("version: 1\nlegacy_unsigned_exclusions: warn\n")

    exclusions = load_exclusions(tmp_path)
    assert len(exclusions) == 1
    assert exclusions[0].quarantined is False  # warn → still applied


def test_load_exclusions_returns_valid_signed_as_trusted(tmp_path: Path):
    """Full round-trip: sign → write → load → verify → not quarantined."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from screw_agents.learning import load_exclusions
    from screw_agents.models import Exclusion, ExclusionFinding, ExclusionScope
    from screw_agents.trust import (
        _public_key_to_openssh_line,
        canonicalize_exclusion,
        sign_content,
    )

    priv = Ed25519PrivateKey.generate()
    pub_line = _public_key_to_openssh_line(priv.public_key(), comment="marco@test")

    excl = Exclusion(
        id="fp-2026-04-14-001",
        created="2026-04-14T10:00:00Z",
        agent="sqli",
        finding=ExclusionFinding(file="src/a.py", line=10, code_pattern="*", cwe="CWE-89"),
        reason="signed entry",
        scope=ExclusionScope(type="exact_line", path="src/a.py"),
    )
    sig = sign_content(canonicalize_exclusion(excl), private_key=priv, key_comment="marco@test")
    excl.signed_by = "marco@example.com"
    excl.signature = sig

    screw = tmp_path / ".screw"
    (screw / "learning").mkdir(parents=True)

    import yaml as _yaml

    data = {"exclusions": [excl.model_dump(exclude={"quarantined"})]}
    (screw / "learning" / "exclusions.yaml").write_text(
        _yaml.dump(data, default_flow_style=False, sort_keys=False)
    )

    (screw / "config.yaml").write_text(
        f"""version: 1
exclusion_reviewers:
  - name: Marco
    email: marco@example.com
    key: "{pub_line}"
legacy_unsigned_exclusions: reject
"""
    )

    exclusions = load_exclusions(tmp_path)
    assert len(exclusions) == 1
    assert exclusions[0].quarantined is False
    assert exclusions[0].signed_by == "marco@example.com"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_learning.py -k "load_exclusions" -v`

Expected: FAIL — existing `load_exclusions` does not know about signatures/quarantine

- [ ] **Step 3: Extend `learning.load_exclusions`**

Modify `src/screw_agents/learning.py`:

```python
from screw_agents.trust import load_config, verify_exclusion


def load_exclusions(project_root: Path) -> list[Exclusion]:
    """Read and verify exclusions from .screw/learning/exclusions.yaml.

    Returns every exclusion in the file. Each entry carries a `quarantined` flag
    that the engine must respect: quarantined entries are NOT applied to findings.

    Policy decisions (legacy_unsigned_exclusions) come from .screw/config.yaml.

    Args:
        project_root: project root directory.

    Returns:
        List of Exclusion objects, each with .quarantined set appropriately.

    Raises:
        ValueError: if the exclusions YAML is malformed.
    """
    path = project_root / _EXCLUSIONS_PATH
    if not path.exists():
        return []

    try:
        raw = yaml.safe_load(path.read_text())
    except yaml.YAMLError as exc:
        raise ValueError(f"Malformed exclusions YAML at {path}: {exc}") from exc

    if raw is None or not isinstance(raw, dict):
        return []

    entries = raw.get("exclusions", [])
    if not entries:
        return []

    config = load_config(project_root)
    exclusions: list[Exclusion] = []
    for entry in entries:
        excl = Exclusion(**entry)
        result = verify_exclusion(excl, config=config)
        if result.valid:
            excl.quarantined = False
        else:
            # Invalid signature, unsigned entry, or untrusted signer.
            if result.reason == "unsigned":
                if config.legacy_unsigned_exclusions == "reject":
                    excl.quarantined = True
                elif config.legacy_unsigned_exclusions == "warn":
                    excl.quarantined = False  # still applied, warning surfaced elsewhere
                else:  # "allow"
                    excl.quarantined = False
            else:
                # Signed but invalid or untrusted — always quarantine.
                excl.quarantined = True
        exclusions.append(excl)

    return exclusions
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_learning.py -v`

Expected: all tests pass (including Phase 2 regression tests)

- [ ] **Step 5: Commit**

```bash
git add src/screw_agents/learning.py tests/test_learning.py
git commit -m "feat(phase3a): learning.load_exclusions verifies signatures"
```

---

### Task 9: `learning.record_exclusion` Signs on Write

**Files:**
- Modify: `src/screw_agents/learning.py`
- Modify: `tests/test_learning.py`

- [ ] **Step 1: Write failing tests for signed recording**

Add to `tests/test_learning.py`:

```python
def test_record_exclusion_signs_with_local_key(tmp_path: Path, monkeypatch):
    """record_exclusion should sign the new entry using the key resolved for the
    current user — either from ssh-keygen (if configured) or from a generated
    local Ed25519 key under .screw/local/keys/."""
    from screw_agents.learning import record_exclusion
    from screw_agents.models import ExclusionFinding, ExclusionInput, ExclusionScope

    # Force cryptography fallback by monkeypatching ssh-keygen detection off
    monkeypatch.setattr("screw_agents.trust.ssh_keygen_available", lambda: False)

    excl_input = ExclusionInput(
        agent="sqli",
        finding=ExclusionFinding(
            file="src/a.py", line=10, code_pattern="*", cwe="CWE-89"
        ),
        reason="test signed write",
        scope=ExclusionScope(type="exact_line", path="src/a.py"),
    )

    saved = record_exclusion(tmp_path, excl_input)
    assert saved.signed_by is not None
    assert saved.signature is not None
    assert saved.signature_version == 1

    # Round-trip: reload, verify, not quarantined
    from screw_agents.learning import load_exclusions

    loaded = load_exclusions(tmp_path)
    assert len(loaded) == 1
    assert loaded[0].quarantined is False


def test_record_exclusion_generates_local_key_on_first_use(tmp_path: Path, monkeypatch):
    """If no local key exists in .screw/local/keys/, record_exclusion generates one."""
    from screw_agents.learning import record_exclusion
    from screw_agents.models import ExclusionFinding, ExclusionInput, ExclusionScope

    monkeypatch.setattr("screw_agents.trust.ssh_keygen_available", lambda: False)

    excl_input = ExclusionInput(
        agent="sqli",
        finding=ExclusionFinding(file="src/a.py", line=10, code_pattern="*", cwe="CWE-89"),
        reason="key bootstrap",
        scope=ExclusionScope(type="exact_line", path="src/a.py"),
    )
    record_exclusion(tmp_path, excl_input)

    key_dir = tmp_path / ".screw" / "local" / "keys"
    assert key_dir.exists()
    # At least one key file was written
    assert any(key_dir.iterdir())
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_learning.py -k "record_exclusion_signs or record_exclusion_generates" -v`

Expected: FAIL — existing `record_exclusion` does not sign

- [x] **Step 3: Add key bootstrapping + signing to `record_exclusion`**

> **NOTE (moved to Task 2 follow-up commit, fix of Task 2 `1479272`):** The
> `quarantined` runtime-only field is enforced at two layers:
> (1) `Field(default=False, exclude=True)` on the field declaration — schema-
>     level exclude that covers `model_dump()`, `model_dump(mode="json")`, and
>     `model_dump_json()` via Pydantic v2's Rust-backed serializer (Layer 1).
> (2) `Exclusion.model_dump` override — Python-side second layer that catches
>     `include={"quarantined"}` edge cases and unknown `exclude=` shapes
>     (list/tuple fallback).
>
> Three regression tests guard the defense:
>   - `tests/test_models.py::test_exclusion_model_dump_excludes_quarantined`
>   - `tests/test_models.py::test_exclusion_model_dump_json_excludes_quarantined`
>   - `tests/test_models.py::test_exclusion_include_does_not_leak_quarantined`
>
> Task 9 Step 3 is now a verification-only step: re-run the three tests. The
> call-site `e.model_dump(exclude={"quarantined"})` shown below is redundant
> but left in place as additional defense-in-depth.

Modify `src/screw_agents/learning.py`:

```python
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

from screw_agents.trust import (
    canonicalize_exclusion,
    load_config,
    sign_content,
    _public_key_to_openssh_line,
)

_LOCAL_KEY_DIR = Path(".screw") / "local" / "keys"
_LOCAL_PRIV_NAME = "screw-local.ed25519"


def _get_or_create_local_private_key(project_root: Path) -> tuple[Ed25519PrivateKey, str]:
    """Return the local Ed25519 private key, generating one if absent.

    Returns (private_key, openssh_public_key_line) so callers can both sign and
    add the public key to .screw/config.yaml if needed.
    """
    key_dir = project_root / _LOCAL_KEY_DIR
    key_path = key_dir / _LOCAL_PRIV_NAME

    if not key_path.exists():
        key_dir.mkdir(parents=True, exist_ok=True)
        priv = Ed25519PrivateKey.generate()
        key_path.write_bytes(
            priv.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
        key_path.chmod(0o600)

    priv_bytes = key_path.read_bytes()
    priv = Ed25519PrivateKey.from_private_bytes(priv_bytes)
    pub_line = _public_key_to_openssh_line(
        priv.public_key(), comment=f"screw-local@{project_root.name}"
    )
    return priv, pub_line


def record_exclusion(project_root: Path, exclusion: ExclusionInput) -> Exclusion:
    """Record a new exclusion in .screw/learning/exclusions.yaml, signed with the local key.

    Creates the directory and file if they don't exist. Assigns a unique ID with
    format fp-YYYY-MM-DD-NNN (sequential per day). Signs the canonical form with
    the local Ed25519 key (auto-generated in .screw/local/keys/ on first use).

    If the local key is not yet in the project's exclusion_reviewers, the caller
    is responsible for adding it via `screw-agents init-trust`. This function
    does NOT auto-register keys into config.yaml — that is an explicit action.
    """
    path = project_root / _EXCLUSIONS_PATH
    path.parent.mkdir(parents=True, exist_ok=True)

    existing = load_exclusions(project_root) if path.exists() else []

    now = datetime.now(timezone.utc)
    date_str = now.strftime("%Y-%m-%d")
    today_prefix = f"fp-{date_str}-"
    today_ids = [e.id for e in existing if e.id.startswith(today_prefix)]
    next_seq = len(today_ids) + 1
    exclusion_id = f"{today_prefix}{next_seq:03d}"

    # Determine the signer identity. Prefer config.yaml's first exclusion_reviewer
    # (the user who ran init-trust); otherwise fall back to "local@<project>".
    config = load_config(project_root)
    if config.exclusion_reviewers:
        signer_email = config.exclusion_reviewers[0].email
    else:
        signer_email = f"local@{project_root.name}"

    saved = Exclusion(
        id=exclusion_id,
        created=now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        agent=exclusion.agent,
        finding=exclusion.finding,
        reason=exclusion.reason,
        scope=exclusion.scope,
        times_suppressed=0,
        last_suppressed=None,
        signed_by=signer_email,
        signature=None,  # filled below
        signature_version=1,
    )

    # Sign the canonical form
    priv, _pub_line = _get_or_create_local_private_key(project_root)
    canonical = canonicalize_exclusion(saved)
    saved.signature = sign_content(canonical, private_key=priv, key_comment=signer_email)

    existing.append(saved)
    data = {
        "exclusions": [e.model_dump(exclude={"quarantined"}) for e in existing]
    }
    path.write_text(yaml.dump(data, default_flow_style=False, sort_keys=False))

    return saved
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_learning.py -v`

Expected: all tests pass

- [ ] **Step 5: Commit**

```bash
git add src/screw_agents/learning.py tests/test_learning.py
git commit -m "feat(phase3a): learning.record_exclusion signs with local Ed25519 key"
```

---

### Task 10: `verify_trust` MCP Tool + `trust_status` in Scan Responses

**Files:**
- Modify: `src/screw_agents/engine.py`
- Modify: `src/screw_agents/server.py`
- Create: `tests/test_phase3a_trust_tool.py`

- [ ] **Step 1: Write failing tests for the new MCP tool**

Create `tests/test_phase3a_trust_tool.py`:

```python
"""Tests for the verify_trust MCP tool and trust_status in scan responses."""

from __future__ import annotations

from pathlib import Path

import pytest

from screw_agents.engine import ScanEngine


def test_verify_trust_empty_project(tmp_path: Path):
    """A fresh project with no exclusions returns zero counts."""
    engine = ScanEngine.from_defaults()
    result = engine.verify_trust(project_root=tmp_path)
    assert result["exclusion_quarantine_count"] == 0
    assert result["exclusion_active_count"] == 0
    assert result["script_quarantine_count"] == 0
    assert result["script_active_count"] == 0


def test_verify_trust_reports_quarantined_unsigned(tmp_path: Path):
    """An unsigned exclusion + reject policy → quarantine count of 1."""
    screw = tmp_path / ".screw"
    (screw / "learning").mkdir(parents=True)
    (screw / "learning" / "exclusions.yaml").write_text(
        """
exclusions:
  - id: "fp-2026-04-14-001"
    created: "2026-04-14T10:00:00Z"
    agent: sqli
    finding:
      file: "src/a.py"
      line: 10
      code_pattern: "*"
      cwe: "CWE-89"
    reason: "unsigned"
    scope:
      type: "exact_line"
      path: "src/a.py"
"""
    )
    (screw / "config.yaml").write_text(
        "version: 1\nlegacy_unsigned_exclusions: reject\n"
    )

    engine = ScanEngine.from_defaults()
    result = engine.verify_trust(project_root=tmp_path)
    assert result["exclusion_quarantine_count"] == 1
    assert result["exclusion_active_count"] == 0


def test_scan_sqli_response_includes_trust_status(tmp_path: Path):
    """scan_sqli response metadata includes trust_status from engine."""
    engine = ScanEngine.from_defaults()
    # We don't need real source files for this test — just verify the response shape
    result = engine.assemble_scan(
        agent_name="sqli",
        target={"type": "glob", "pattern": str(tmp_path / "**")},
        project_root=tmp_path,
    )
    assert "trust_status" in result
    assert "exclusion_quarantine_count" in result["trust_status"]
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_phase3a_trust_tool.py -v`

Expected: FAIL with `AttributeError: 'ScanEngine' object has no attribute 'verify_trust'`

- [ ] **Step 3: Add `verify_trust` method on ScanEngine**

In `src/screw_agents/engine.py`, add a new method on `ScanEngine`:

```python
from screw_agents.learning import load_exclusions


def verify_trust(self, *, project_root: Path) -> dict[str, int]:
    """Compute a summary of trust status for the project's .screw/ content.

    Returns counts of active vs quarantined entries for both exclusions and
    scripts. Phase 3a populates exclusion counts; script counts always return 0
    until Phase 3b adds the custom-scripts subsystem.
    """
    exclusions = load_exclusions(project_root)
    exclusion_quarantine_count = sum(1 for e in exclusions if e.quarantined)
    exclusion_active_count = len(exclusions) - exclusion_quarantine_count

    return {
        "exclusion_quarantine_count": exclusion_quarantine_count,
        "exclusion_active_count": exclusion_active_count,
        "script_quarantine_count": 0,
        "script_active_count": 0,
    }
```

Then, in `assemble_scan`, `assemble_domain_scan`, and `assemble_full_scan`, add `trust_status` to the response metadata:

```python
def assemble_scan(self, *, agent_name: str, target: dict, project_root: Path | None = None) -> dict:
    # ... existing assembly logic ...
    response = {
        "core_prompt": ...,
        "code": ...,
        "resolved_files": ...,
        "meta": ...,
        "exclusions": ...,
    }
    if project_root is not None:
        response["trust_status"] = self.verify_trust(project_root=project_root)
    return response
```

Make the same change in `assemble_domain_scan` and `assemble_full_scan`.

- [ ] **Step 4: Wire the `verify_trust` MCP tool in `server.py`**

In `src/screw_agents/server.py`, add a new tool registration:

```python
# In list_tool_definitions():
Tool(
    name="verify_trust",
    description=(
        "Return a summary of .screw/ content trust status — counts of "
        "active vs quarantined exclusions and (Phase 3b) adaptive scripts. "
        "Use this to surface trust issues in the scan report header."
    ),
    inputSchema={
        "type": "object",
        "properties": {
            "project_root": {
                "type": "string",
                "description": "Absolute path to the project root",
            },
        },
        "required": ["project_root"],
    },
),

# In _dispatch_tool():
elif name == "verify_trust":
    project_root = Path(arguments["project_root"])
    result = self.engine.verify_trust(project_root=project_root)
    return [TextContent(type="text", text=json.dumps(result))]
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `uv run pytest tests/test_phase3a_trust_tool.py -v`

Expected: 3 passed

- [ ] **Step 6: Commit**

```bash
git add src/screw_agents/engine.py src/screw_agents/server.py tests/test_phase3a_trust_tool.py
git commit -m "feat(phase3a): verify_trust MCP tool and trust_status in scan responses"
```

---

### Task 11: Surface Trust Status in `write_scan_results` Output

**Files:**
- Modify: `src/screw_agents/results.py`
- Modify: `tests/test_results.py`

- [ ] **Step 1: Write failing test for trust status in scan report**

Add to `tests/test_results.py`:

```python
def test_write_scan_results_includes_trust_status_in_markdown(tmp_path: Path):
    """When exclusions are quarantined, the Markdown report header shows counts
    and a pointer to the quarantine-review CLI command."""
    from screw_agents.results import write_scan_results

    # Seed a quarantined unsigned exclusion (reject policy is default)
    screw = tmp_path / ".screw"
    (screw / "learning").mkdir(parents=True)
    (screw / "learning" / "exclusions.yaml").write_text(
        """
exclusions:
  - id: "fp-2026-04-14-001"
    created: "2026-04-14T10:00:00Z"
    agent: sqli
    finding:
      file: "src/a.py"
      line: 10
      code_pattern: "*"
      cwe: "CWE-89"
    reason: "legacy unsigned"
    scope:
      type: "exact_line"
      path: "src/a.py"
"""
    )

    result = write_scan_results(
        project_root=tmp_path,
        agent_names=["sqli"],
        findings=[],
        scan_metadata={"agent": "sqli", "target": "src/**", "timestamp": "2026-04-14T10:00:00Z"},
    )
    md_file = Path(result["files_written"]["markdown"])
    content = md_file.read_text()
    assert "Trust verification" in content
    assert "1 exclusion" in content  # at least one quarantined
    assert "screw-agents validate-exclusion" in content
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_results.py::test_write_scan_results_includes_trust_status_in_markdown -v`

Expected: FAIL — current `write_scan_results` does not emit a trust section

- [ ] **Step 3: Add trust section to Markdown output in `write_scan_results`**

Modify `src/screw_agents/results.py`. After the existing Markdown rendering code, add a trust-status section between the header and the findings body:

```python
from screw_agents.engine import ScanEngine


def _render_trust_section(project_root: Path) -> str:
    """Render a Markdown section summarizing .screw/ trust status."""
    engine = ScanEngine.from_defaults()
    status = engine.verify_trust(project_root=project_root)

    quarantine = status["exclusion_quarantine_count"]
    active = status["exclusion_active_count"]
    script_quarantine = status["script_quarantine_count"]
    script_active = status["script_active_count"]

    if quarantine == 0 and script_quarantine == 0:
        return ""  # nothing to surface

    lines = ["", "## Trust verification", ""]
    if quarantine > 0:
        noun = "exclusion" if quarantine == 1 else "exclusions"
        lines.append(
            f"- **{quarantine} {noun} quarantined** "
            f"(unsigned or signed by untrusted key)"
        )
        lines.append(
            "  - Review each with `screw-agents validate-exclusion <id>` "
            "or run `screw-agents migrate-exclusions` to sign them in bulk"
        )
    if active > 0:
        lines.append(f"- {active} trusted exclusions applied")
    if script_quarantine > 0:
        lines.append(
            f"- **{script_quarantine} adaptive script(s) quarantined** "
            "(Phase 3b — see `screw-agents validate-script <name>`)"
        )
    if script_active > 0:
        lines.append(f"- {script_active} trusted adaptive scripts loaded")
    lines.append("")
    return "\n".join(lines)
```

Then, in `write_scan_results`, splice the trust section into the Markdown after the scan metadata header and before the findings table. Locate the existing Markdown composition and modify:

```python
# Existing code composes markdown_content from scan metadata + findings
# Add the trust section between header and findings:
trust_section = _render_trust_section(project_root)
markdown_content = scan_header + trust_section + findings_body
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_results.py -v`

Expected: all tests pass (including Phase 2 regression tests)

- [ ] **Step 5: Commit**

```bash
git add src/screw_agents/results.py tests/test_results.py
git commit -m "feat(phase3a): surface trust status in write_scan_results Markdown output"
```

---

### Task 12: `screw-agents init-trust` CLI Subcommand

**Files:**
- Create: `src/screw_agents/cli/__init__.py`
- Create: `src/screw_agents/cli/init_trust.py`
- Create: `tests/test_cli_trust.py`
- Modify: `pyproject.toml` (register console script)

- [ ] **Step 1: Register the console script entry point**

In `pyproject.toml`, add:

```toml
[project.scripts]
screw-agents = "screw_agents.cli:main"
```

- [ ] **Step 2: Write failing test for init-trust**

Create `tests/test_cli_trust.py`:

```python
"""Integration tests for the screw-agents CLI trust subcommands."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from screw_agents.cli.init_trust import run_init_trust


def test_init_trust_creates_config_with_local_key(tmp_path: Path):
    """First run: generates an Ed25519 key under .screw/local/keys/, writes the
    public key into both exclusion_reviewers and script_reviewers lists in
    .screw/config.yaml, and reports success."""
    result = run_init_trust(
        project_root=tmp_path,
        name="Marco",
        email="marco@example.com",
    )
    assert result["status"] == "created"

    config_path = tmp_path / ".screw" / "config.yaml"
    assert config_path.exists()
    config_data = yaml.safe_load(config_path.read_text())

    assert len(config_data["exclusion_reviewers"]) == 1
    assert config_data["exclusion_reviewers"][0]["email"] == "marco@example.com"
    assert len(config_data["script_reviewers"]) == 1
    assert config_data["script_reviewers"][0]["email"] == "marco@example.com"

    # Key file exists
    key_dir = tmp_path / ".screw" / "local" / "keys"
    assert key_dir.exists()


def test_init_trust_is_idempotent(tmp_path: Path):
    """Running init-trust twice does not duplicate the reviewer entry."""
    run_init_trust(project_root=tmp_path, name="Marco", email="marco@example.com")
    result = run_init_trust(project_root=tmp_path, name="Marco", email="marco@example.com")
    assert result["status"] == "already_registered"

    config_data = yaml.safe_load((tmp_path / ".screw" / "config.yaml").read_text())
    assert len(config_data["exclusion_reviewers"]) == 1
    assert len(config_data["script_reviewers"]) == 1
```

- [ ] **Step 3: Run test to verify it fails**

Run: `uv run pytest tests/test_cli_trust.py -v`

Expected: FAIL with `ModuleNotFoundError: No module named 'screw_agents.cli'`

- [ ] **Step 4: Implement the CLI subcommand**

Create `src/screw_agents/cli/__init__.py`:

```python
"""screw-agents command-line interface."""

from __future__ import annotations

import argparse
import sys


def main() -> int:
    parser = argparse.ArgumentParser(prog="screw-agents")
    subparsers = parser.add_subparsers(dest="command", required=True)

    init_trust_p = subparsers.add_parser("init-trust", help="Register local SSH key with project")
    init_trust_p.add_argument("--name", required=True)
    init_trust_p.add_argument("--email", required=True)
    init_trust_p.add_argument("--project-root", type=str, default=".")

    migrate_p = subparsers.add_parser(
        "migrate-exclusions", help="Sign legacy unsigned exclusions"
    )
    migrate_p.add_argument("--project-root", type=str, default=".")
    migrate_p.add_argument("--yes", action="store_true", help="Skip per-entry confirmation")

    validate_p = subparsers.add_parser(
        "validate-exclusion", help="Re-sign a quarantined exclusion after review"
    )
    validate_p.add_argument("exclusion_id")
    validate_p.add_argument("--project-root", type=str, default=".")

    args = parser.parse_args()

    from pathlib import Path

    project_root = Path(args.project_root).resolve()

    if args.command == "init-trust":
        from screw_agents.cli.init_trust import run_init_trust

        result = run_init_trust(project_root=project_root, name=args.name, email=args.email)
        print(result["message"])
        return 0 if result["status"] in ("created", "already_registered") else 1

    if args.command == "migrate-exclusions":
        from screw_agents.cli.migrate_exclusions import run_migrate_exclusions

        result = run_migrate_exclusions(project_root=project_root, skip_confirm=args.yes)
        print(result["message"])
        return 0

    if args.command == "validate-exclusion":
        from screw_agents.cli.validate_exclusion import run_validate_exclusion

        result = run_validate_exclusion(
            project_root=project_root, exclusion_id=args.exclusion_id
        )
        print(result["message"])
        return 0 if result["status"] == "validated" else 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
```

Create `src/screw_agents/cli/init_trust.py`:

```python
"""Implementation of `screw-agents init-trust`."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from screw_agents.learning import _get_or_create_local_private_key
from screw_agents.models import ReviewerKey, ScrewConfig
from screw_agents.trust import _public_key_to_openssh_line, load_config


def run_init_trust(
    *, project_root: Path, name: str, email: str
) -> dict[str, Any]:
    """Register the local Ed25519 key in the project's trusted-reviewers lists.

    Creates .screw/config.yaml if missing. Adds the local key to BOTH
    exclusion_reviewers and script_reviewers (single-user workflow default).
    If the email is already registered, returns status='already_registered'.
    """
    config = load_config(project_root)

    # Generate or load the local key, producing the OpenSSH public-key line.
    _priv, pub_line = _get_or_create_local_private_key(project_root)

    # Idempotent: check if already registered by email.
    already = any(r.email == email for r in config.exclusion_reviewers) and any(
        r.email == email for r in config.script_reviewers
    )
    if already:
        return {
            "status": "already_registered",
            "message": f"{email} is already registered in both reviewer lists.",
        }

    new_reviewer = ReviewerKey(name=name, email=email, key=pub_line)
    if not any(r.email == email for r in config.exclusion_reviewers):
        config.exclusion_reviewers = list(config.exclusion_reviewers) + [new_reviewer]
    if not any(r.email == email for r in config.script_reviewers):
        config.script_reviewers = list(config.script_reviewers) + [new_reviewer]

    config_path = project_root / ".screw" / "config.yaml"
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text(yaml.dump(config.model_dump(), default_flow_style=False, sort_keys=False))

    return {
        "status": "created",
        "message": (
            f"Registered {email} in .screw/config.yaml.\n"
            f"Local key stored at .screw/local/keys/screw-local.ed25519 (mode 0600).\n"
            f"You can now sign exclusions with `screw-agents migrate-exclusions`."
        ),
    }
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `uv run pytest tests/test_cli_trust.py -v`

Expected: 2 passed

- [ ] **Step 6: Commit**

```bash
git add src/screw_agents/cli/__init__.py src/screw_agents/cli/init_trust.py tests/test_cli_trust.py pyproject.toml
git commit -m "feat(phase3a): screw-agents init-trust CLI subcommand"
```

---

### Task 13: `screw-agents migrate-exclusions` CLI Subcommand

**Files:**
- Create: `src/screw_agents/cli/migrate_exclusions.py`
- Modify: `tests/test_cli_trust.py`

- [ ] **Step 1: Write failing test for migration**

Add to `tests/test_cli_trust.py`:

```python
def test_migrate_exclusions_signs_unsigned_entries(tmp_path: Path):
    """migrate-exclusions iterates unsigned entries, signs them with the local key,
    and rewrites exclusions.yaml."""
    from screw_agents.cli.init_trust import run_init_trust
    from screw_agents.cli.migrate_exclusions import run_migrate_exclusions
    from screw_agents.learning import load_exclusions

    run_init_trust(project_root=tmp_path, name="Marco", email="marco@example.com")

    # Seed a legacy unsigned exclusion
    (tmp_path / ".screw" / "learning").mkdir(parents=True, exist_ok=True)
    (tmp_path / ".screw" / "learning" / "exclusions.yaml").write_text(
        """
exclusions:
  - id: "fp-2026-04-14-001"
    created: "2026-04-14T10:00:00Z"
    agent: sqli
    finding:
      file: "src/a.py"
      line: 10
      code_pattern: "*"
      cwe: "CWE-89"
    reason: "legacy unsigned"
    scope:
      type: "exact_line"
      path: "src/a.py"
"""
    )

    result = run_migrate_exclusions(project_root=tmp_path, skip_confirm=True)
    assert result["status"] == "success"
    assert result["signed_count"] == 1

    loaded = load_exclusions(tmp_path)
    assert len(loaded) == 1
    assert loaded[0].quarantined is False
    assert loaded[0].signed_by == "marco@example.com"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_cli_trust.py::test_migrate_exclusions_signs_unsigned_entries -v`

Expected: FAIL with `ModuleNotFoundError: No module named 'screw_agents.cli.migrate_exclusions'`

- [ ] **Step 3: Implement the migration subcommand**

Create `src/screw_agents/cli/migrate_exclusions.py`:

```python
"""Implementation of `screw-agents migrate-exclusions`."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from screw_agents.learning import (
    _EXCLUSIONS_PATH,
    _get_or_create_local_private_key,
)
from screw_agents.models import Exclusion
from screw_agents.trust import canonicalize_exclusion, load_config, sign_content


def run_migrate_exclusions(*, project_root: Path, skip_confirm: bool) -> dict[str, Any]:
    """Sign every currently-unsigned exclusion with the local Ed25519 key.

    Reads the raw YAML (bypasses load_exclusions to avoid quarantine filtering),
    signs entries that lack a signature, writes the updated YAML back.
    """
    path = project_root / _EXCLUSIONS_PATH
    if not path.exists():
        return {"status": "no_exclusions", "signed_count": 0, "message": "No exclusions to migrate."}

    raw = yaml.safe_load(path.read_text())
    if not raw or not raw.get("exclusions"):
        return {"status": "no_exclusions", "signed_count": 0, "message": "No exclusions to migrate."}

    config = load_config(project_root)
    if not config.exclusion_reviewers:
        return {
            "status": "error",
            "signed_count": 0,
            "message": (
                "No exclusion_reviewers configured. "
                "Run `screw-agents init-trust` first."
            ),
        }

    signer_email = config.exclusion_reviewers[0].email
    priv, _ = _get_or_create_local_private_key(project_root)

    signed_count = 0
    for entry in raw["exclusions"]:
        if entry.get("signature"):
            continue  # already signed
        if not skip_confirm:
            print(f"\nSign exclusion {entry['id']}?")
            print(f"  agent: {entry['agent']}")
            print(f"  file: {entry['finding']['file']}:{entry['finding']['line']}")
            print(f"  reason: {entry['reason']}")
            response = input("  [y/N]: ").strip().lower()
            if response != "y":
                continue

        # Build an Exclusion object from the raw entry, then canonicalize + sign
        excl = Exclusion(**entry)
        canonical = canonicalize_exclusion(excl)
        signature = sign_content(canonical, private_key=priv, key_comment=signer_email)
        entry["signed_by"] = signer_email
        entry["signature"] = signature
        entry["signature_version"] = 1
        signed_count += 1

    path.write_text(yaml.dump(raw, default_flow_style=False, sort_keys=False))

    return {
        "status": "success",
        "signed_count": signed_count,
        "message": f"Signed {signed_count} legacy exclusions with {signer_email}.",
    }
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_cli_trust.py -v`

Expected: 3 passed

- [ ] **Step 5: Commit**

```bash
git add src/screw_agents/cli/migrate_exclusions.py tests/test_cli_trust.py
git commit -m "feat(phase3a): screw-agents migrate-exclusions CLI subcommand"
```

---

### Task 14: `screw-agents validate-exclusion` CLI Subcommand

**Files:**
- Create: `src/screw_agents/cli/validate_exclusion.py`
- Modify: `tests/test_cli_trust.py`

- [ ] **Step 1: Write failing test for per-entry validation**

Add to `tests/test_cli_trust.py`:

```python
def test_validate_exclusion_signs_single_entry(tmp_path: Path):
    """validate-exclusion <id> signs one specific quarantined entry."""
    from screw_agents.cli.init_trust import run_init_trust
    from screw_agents.cli.validate_exclusion import run_validate_exclusion
    from screw_agents.learning import load_exclusions

    run_init_trust(project_root=tmp_path, name="Marco", email="marco@example.com")

    (tmp_path / ".screw" / "learning").mkdir(parents=True, exist_ok=True)
    (tmp_path / ".screw" / "learning" / "exclusions.yaml").write_text(
        """
exclusions:
  - id: "fp-2026-04-14-001"
    created: "2026-04-14T10:00:00Z"
    agent: sqli
    finding:
      file: "src/a.py"
      line: 10
      code_pattern: "*"
      cwe: "CWE-89"
    reason: "legacy"
    scope:
      type: "exact_line"
      path: "src/a.py"
  - id: "fp-2026-04-14-002"
    created: "2026-04-14T10:00:00Z"
    agent: sqli
    finding:
      file: "src/b.py"
      line: 20
      code_pattern: "*"
      cwe: "CWE-89"
    reason: "legacy"
    scope:
      type: "exact_line"
      path: "src/b.py"
"""
    )

    result = run_validate_exclusion(project_root=tmp_path, exclusion_id="fp-2026-04-14-001")
    assert result["status"] == "validated"

    loaded = load_exclusions(tmp_path)
    by_id = {e.id: e for e in loaded}
    assert by_id["fp-2026-04-14-001"].quarantined is False
    assert by_id["fp-2026-04-14-002"].quarantined is True  # untouched
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_cli_trust.py::test_validate_exclusion_signs_single_entry -v`

Expected: FAIL with `ModuleNotFoundError`

- [ ] **Step 3: Implement the validate-exclusion subcommand**

Create `src/screw_agents/cli/validate_exclusion.py`:

```python
"""Implementation of `screw-agents validate-exclusion <id>`."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from screw_agents.learning import (
    _EXCLUSIONS_PATH,
    _get_or_create_local_private_key,
)
from screw_agents.models import Exclusion
from screw_agents.trust import canonicalize_exclusion, load_config, sign_content


def run_validate_exclusion(
    *, project_root: Path, exclusion_id: str
) -> dict[str, Any]:
    """Sign a single exclusion by id. Used to unquarantine an entry after human
    review of its content (user opens the YAML, confirms the reason and scope
    look correct, then runs this command to re-sign).
    """
    path = project_root / _EXCLUSIONS_PATH
    if not path.exists():
        return {
            "status": "not_found",
            "message": f"Exclusions file does not exist at {path}",
        }

    raw = yaml.safe_load(path.read_text())
    if not raw or not raw.get("exclusions"):
        return {"status": "not_found", "message": "No exclusions in file."}

    target_entry = None
    for entry in raw["exclusions"]:
        if entry.get("id") == exclusion_id:
            target_entry = entry
            break

    if target_entry is None:
        return {
            "status": "not_found",
            "message": f"No exclusion with id '{exclusion_id}' found.",
        }

    config = load_config(project_root)
    if not config.exclusion_reviewers:
        return {
            "status": "error",
            "message": "No exclusion_reviewers configured. Run `screw-agents init-trust` first.",
        }

    signer_email = config.exclusion_reviewers[0].email
    priv, _ = _get_or_create_local_private_key(project_root)

    excl = Exclusion(**target_entry)
    canonical = canonicalize_exclusion(excl)
    signature = sign_content(canonical, private_key=priv, key_comment=signer_email)

    target_entry["signed_by"] = signer_email
    target_entry["signature"] = signature
    target_entry["signature_version"] = 1

    path.write_text(yaml.dump(raw, default_flow_style=False, sort_keys=False))

    return {
        "status": "validated",
        "message": f"Signed exclusion {exclusion_id} with {signer_email}.",
    }
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_cli_trust.py -v`

Expected: 4 passed

- [ ] **Step 5: Commit**

```bash
git add src/screw_agents/cli/validate_exclusion.py tests/test_cli_trust.py
git commit -m "feat(phase3a): screw-agents validate-exclusion CLI subcommand"
```

---

### Task 15: Subagent Prompts Surface Quarantined Counts

**Files:**
- Modify: `plugins/screw/agents/screw-sqli.md`
- Modify: `plugins/screw/agents/screw-cmdi.md`
- Modify: `plugins/screw/agents/screw-ssti.md`
- Modify: `plugins/screw/agents/screw-xss.md`
- Modify: `plugins/screw/agents/screw-injection.md`
- Modify: `plugins/screw/agents/screw-full-review.md`

- [ ] **Step 1: Read the current screw-sqli prompt to locate the workflow section**

Run: (Read plugins/screw/agents/screw-sqli.md)

Identify the section that describes the 4-step workflow post-Phase-2 (scan → analyze → write_scan_results → present). This is the section to extend.

- [ ] **Step 2: Add a trust-status check step to every agent prompt**

Edit each of the six agent markdown files. Inside the "Workflow" or "Steps" section, add a new step between the existing analysis step and the `write_scan_results` step:

```markdown
### Step: Check trust status

After receiving the scan response, inspect `trust_status` in the metadata:

- If `exclusion_quarantine_count > 0`, include a line in your conversational
  summary: "⚠ N exclusions quarantined — see `screw-agents migrate-exclusions`
  or review individual entries with `screw-agents validate-exclusion <id>`."
- If `script_quarantine_count > 0` (Phase 3b feature), include a similar line
  pointing to `screw-agents validate-script <name>`.
- If both counts are zero, omit the trust section from the user-facing summary.

The `write_scan_results` MCP tool will also render a Trust Verification section
in the Markdown report automatically — your conversational summary is a
user-visible teaser for what's in the detailed report.
```

Apply this change to all 6 agent files: screw-sqli.md, screw-cmdi.md, screw-ssti.md, screw-xss.md, screw-injection.md, screw-full-review.md.

- [ ] **Step 3: Verify no existing E2E tests break**

Run: `uv run pytest -v`

Expected: all tests pass (subagent markdown changes don't break Python tests; full E2E verification is manual and deferred to PR #1 merge validation)

- [ ] **Step 4: Commit**

```bash
git add plugins/screw/agents/
git commit -m "feat(phase3a): subagent prompts surface trust quarantine counts"
```

---

## PR #1 Exit Checklist

Before merging PR #1:

- [ ] All unit tests green: `uv run pytest tests/test_trust.py tests/test_learning.py tests/test_models.py tests/test_phase3a_trust_tool.py tests/test_cli_trust.py tests/test_results.py -v`
- [ ] Phase 2 regression tests still green: `uv run pytest tests/test_phase2_server.py tests/test_results.py -v`
- [ ] Full round-trip manual test:
  1. `cd /tmp && mkdir fresh-project && cd fresh-project`
  2. `unset ANTHROPIC_API_KEY`
  3. `uv run screw-agents init-trust --name "Marco" --email marco@test`
  4. Claude Code: `/screw:scan sqli some/fixture/dir` and mark a finding as FP
  5. Verify `.screw/learning/exclusions.yaml` contains `signed_by` and `signature` fields
  6. Re-run scan: exclusion is trusted, not quarantined
  7. Manually remove the `signature` field from the YAML
  8. Re-run scan: Markdown report shows "1 exclusion quarantined"
  9. `uv run screw-agents validate-exclusion fp-2026-04-14-001`
  10. Re-run scan: exclusion is trusted again
- [ ] **Downstream impact review**: open `docs/PHASE_3B_PLAN.md` and scan the "Upstream Dependencies from Phase 3a" section. Reconcile any PR #1 changes (trust module signatures, `ScrewConfig` shape, Exclusion model fields, `verify_script` signature, CLI subcommand names, `.screw/config.yaml` schema) against the 3b tasks that reference them. If any drift exists, update `PHASE_3B_PLAN.md` in the same commit or a targeted follow-up.
- [ ] PR #1 description references Phase 3a spec §4, §5, §7.1

---

## PR #2: Learning Aggregation + On-Demand Surface

**PR goal:** surface cross-scan patterns from the exclusions database as actionable reports via a new MCP tool and conversational subagent. Ships Features 1, 2, 4 from PRD §11.2 layer 3; Feature 3 is deferred to Phase 6 (see spec §14 P3-D1).

**Design properties:**
- On-demand only: reports never run automatically after scans
- All three features share one aggregation pipeline, three different projections
- Data source: signed `.screw/learning/exclusions.yaml` (from PR #1)
- New subagent `screw-learning-analyst` presents reports conversationally
- New slash command `/screw:learning-report` triggers the subagent

**PR #2 exit criteria:**
- All three reports produce correct output for seeded exclusions
- Integration test exercises the full flow: seed exclusions → call aggregate_learning → verify output structure
- Subagent markdown is reviewable and routes to the new MCP tool

---

### Task 16: Aggregation Pydantic Models

**Files:**
- Modify: `src/screw_agents/models.py`
- Modify: `tests/test_models.py`

- [ ] **Step 1: Write failing tests for the aggregation models**

Add to `tests/test_models.py`:

```python
def test_pattern_suggestion_model():
    from screw_agents.models import PatternSuggestion

    sugg = PatternSuggestion(
        pattern="db.text_search(*)",
        agent="sqli",
        cwe="CWE-89",
        evidence={"exclusion_count": 12, "files_affected": ["a.py", "b.py"]},
        suggestion="Consider adding to project-wide safe patterns.",
        confidence="high",
    )
    assert sugg.pattern == "db.text_search(*)"
    assert sugg.confidence == "high"


def test_directory_suggestion_model():
    from screw_agents.models import DirectorySuggestion

    sugg = DirectorySuggestion(
        directory="test/",
        agent="sqli",
        evidence={"total_findings": 12, "all_fp": True},
        suggestion="Add test/** directory exclusion.",
        confidence="high",
    )
    assert sugg.directory == "test/"


def test_fp_pattern_and_fp_report():
    from screw_agents.models import FPPattern, FPReport

    pattern = FPPattern(
        agent="sqli",
        cwe="CWE-89",
        pattern="execute\\(f\"",
        fp_count=47,
        example_reasons=["static query", "test fixture"],
        candidate_heuristic_refinement="lower confidence on bounded f-strings",
    )
    report = FPReport(
        generated_at="2026-04-14T10:00:00Z",
        scope="project",
        top_fp_patterns=[pattern],
    )
    assert report.top_fp_patterns[0].fp_count == 47


def test_aggregate_report_model():
    from screw_agents.models import AggregateReport, FPReport

    report = AggregateReport(
        pattern_confidence=[],
        directory_suggestions=[],
        fp_report=FPReport(generated_at="2026-04-14T10:00:00Z", scope="project", top_fp_patterns=[]),
    )
    assert report.pattern_confidence == []
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_models.py -k "pattern_suggestion or directory_suggestion or fp_pattern or aggregate_report" -v`

Expected: FAIL with ImportError

- [ ] **Step 3: Add the aggregation models**

Add to `src/screw_agents/models.py`:

```python
class PatternSuggestion(BaseModel):
    """Feature 1 output: project-wide safe pattern candidates."""

    pattern: str
    agent: str
    cwe: str
    evidence: dict[str, Any]
    suggestion: str
    confidence: Literal["low", "medium", "high"]


class DirectorySuggestion(BaseModel):
    """Feature 2 output: directory-scope exclusion candidates."""

    directory: str
    agent: str
    evidence: dict[str, Any]
    suggestion: str
    confidence: Literal["low", "medium", "high"]


class FPPattern(BaseModel):
    """A single false-positive pattern in the FP report."""

    agent: str
    cwe: str
    pattern: str
    fp_count: int
    example_reasons: list[str]
    candidate_heuristic_refinement: str


class FPReport(BaseModel):
    """Feature 4 output: false-positive signal for Phase 4 autoresearch."""

    generated_at: str
    scope: Literal["project", "global"]
    top_fp_patterns: list[FPPattern]


class AggregateReport(BaseModel):
    """Unified output of the three aggregation features."""

    pattern_confidence: list[PatternSuggestion]
    directory_suggestions: list[DirectorySuggestion]
    fp_report: FPReport
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_models.py -v`

Expected: all tests pass

- [ ] **Step 5: Commit**

```bash
git add src/screw_agents/models.py tests/test_models.py
git commit -m "feat(phase3a): aggregation Pydantic models"
```

---

### Task 17: `aggregate_pattern_confidence` (Feature 1)

**Files:**
- Create: `src/screw_agents/aggregation.py`
- Create: `tests/test_aggregation.py`

- [ ] **Step 1: Write failing tests for pattern aggregation**

Create `tests/test_aggregation.py`:

```python
"""Unit tests for screw_agents.aggregation — learning reports."""

from __future__ import annotations

import pytest

from screw_agents.aggregation import aggregate_pattern_confidence
from screw_agents.models import Exclusion, ExclusionFinding, ExclusionScope


def _excl(
    *, id: str, agent: str, pattern: str, file: str, line: int, reason: str
) -> Exclusion:
    return Exclusion(
        id=id,
        created="2026-04-14T10:00:00Z",
        agent=agent,
        finding=ExclusionFinding(file=file, line=line, code_pattern=pattern, cwe="CWE-89"),
        reason=reason,
        scope=ExclusionScope(type="pattern", pattern=pattern),
    )


def test_aggregate_pattern_confidence_groups_by_pattern():
    """12 exclusions matching the same pattern collapse to one PatternSuggestion."""
    exclusions = [
        _excl(id=f"fp-2026-04-14-{i:03d}", agent="sqli", pattern="db.text_search(*)",
              file=f"src/s{i}.py", line=10, reason="safe internal")
        for i in range(12)
    ]
    suggestions = aggregate_pattern_confidence(exclusions)
    assert len(suggestions) == 1
    assert suggestions[0].pattern == "db.text_search(*)"
    assert suggestions[0].agent == "sqli"
    assert suggestions[0].evidence["exclusion_count"] == 12
    assert suggestions[0].confidence == "high"  # 12 >= threshold for high


def test_aggregate_pattern_confidence_ignores_singletons():
    """A pattern seen only once is not a project-wide convention."""
    exclusions = [
        _excl(id="fp-2026-04-14-001", agent="sqli", pattern="one_off(*)",
              file="src/a.py", line=10, reason="special case")
    ]
    suggestions = aggregate_pattern_confidence(exclusions)
    assert len(suggestions) == 0


def test_aggregate_pattern_confidence_threshold_boundary():
    """At least 3 occurrences required for a suggestion; threshold is inclusive."""
    exclusions = [
        _excl(id=f"fp-2026-04-14-{i:03d}", agent="sqli", pattern="same(*)",
              file=f"src/s{i}.py", line=10, reason="safe")
        for i in range(3)
    ]
    suggestions = aggregate_pattern_confidence(exclusions)
    assert len(suggestions) == 1
    assert suggestions[0].confidence in ("low", "medium")  # 3 is at the low end


def test_aggregate_pattern_confidence_skips_quarantined():
    """Quarantined exclusions are not included in the aggregation."""
    exclusions = [
        _excl(id=f"fp-2026-04-14-{i:03d}", agent="sqli", pattern="same(*)",
              file=f"src/s{i}.py", line=10, reason="safe")
        for i in range(5)
    ]
    exclusions[0].quarantined = True
    exclusions[1].quarantined = True
    suggestions = aggregate_pattern_confidence(exclusions)
    assert len(suggestions) == 1
    assert suggestions[0].evidence["exclusion_count"] == 3
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_aggregation.py -v`

Expected: FAIL with `ModuleNotFoundError: No module named 'screw_agents.aggregation'`

- [ ] **Step 3: Implement `aggregate_pattern_confidence`**

Create `src/screw_agents/aggregation.py`:

```python
"""Learning aggregation — cross-scan pattern reports from the exclusions database.

Phase 3a ships Features 1, 2, 4 from PRD §11.2 layer 3. Feature 3 (high-value
target suggestions) is deferred to Phase 6 because it requires a new data source
(confirmed findings, not just rejections).

All three features share the same data pipeline — they're different projections
of the same signed exclusions database.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
from typing import Literal

from screw_agents.models import (
    DirectorySuggestion,
    Exclusion,
    FPPattern,
    FPReport,
    PatternSuggestion,
)

# Thresholds for confidence levels on pattern-confidence suggestions.
_PATTERN_MIN_COUNT = 3
_PATTERN_HIGH_COUNT = 10


def aggregate_pattern_confidence(exclusions: list[Exclusion]) -> list[PatternSuggestion]:
    """Group exclusions by their code_pattern and produce project-wide safe-pattern suggestions.

    Only trusted (non-quarantined) exclusions are considered. A pattern must appear
    in at least _PATTERN_MIN_COUNT exclusions to generate a suggestion.
    """
    buckets: dict[tuple[str, str, str], list[Exclusion]] = defaultdict(list)
    for excl in exclusions:
        if excl.quarantined:
            continue
        key = (excl.agent, excl.finding.code_pattern, excl.finding.cwe)
        buckets[key].append(excl)

    suggestions: list[PatternSuggestion] = []
    for (agent, pattern, cwe), group in buckets.items():
        if len(group) < _PATTERN_MIN_COUNT:
            continue

        files_affected = sorted({e.finding.file for e in group})
        confidence: Literal["low", "medium", "high"]
        if len(group) >= _PATTERN_HIGH_COUNT:
            confidence = "high"
        elif len(group) >= _PATTERN_MIN_COUNT + 2:
            confidence = "medium"
        else:
            confidence = "low"

        suggestions.append(
            PatternSuggestion(
                pattern=pattern,
                agent=agent,
                cwe=cwe,
                evidence={
                    "exclusion_count": len(group),
                    "files_affected": files_affected,
                    "first_seen": min(e.created for e in group),
                    "last_seen": max(e.created for e in group),
                },
                suggestion=(
                    f"Consider adding {pattern} to the project-wide safe patterns list "
                    f"for {agent}."
                ),
                confidence=confidence,
            )
        )
    return suggestions
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_aggregation.py -v`

Expected: 4 passed

- [ ] **Step 5: Commit**

```bash
git add src/screw_agents/aggregation.py tests/test_aggregation.py
git commit -m "feat(phase3a): aggregate_pattern_confidence (Feature 1)"
```

---

### Task 18: `aggregate_directory_suggestions` (Feature 2)

**Files:**
- Modify: `src/screw_agents/aggregation.py`
- Modify: `tests/test_aggregation.py`

- [ ] **Step 1: Write failing tests for directory aggregation**

Add to `tests/test_aggregation.py`:

```python
def test_aggregate_directory_suggestions_groups_by_common_prefix():
    """Exclusions concentrated in a single directory produce a suggestion."""
    from screw_agents.aggregation import aggregate_directory_suggestions

    exclusions = [
        _excl(id=f"fp-2026-04-14-{i:03d}", agent="sqli", pattern=f"p{i}",
              file=f"test/subdir/test_{i}.py", line=10, reason="test fixture")
        for i in range(8)
    ]
    suggestions = aggregate_directory_suggestions(exclusions)
    assert len(suggestions) >= 1
    dirs = {s.directory for s in suggestions}
    assert "test/" in dirs or "test/subdir/" in dirs


def test_aggregate_directory_suggestions_requires_min_count():
    from screw_agents.aggregation import aggregate_directory_suggestions

    exclusions = [
        _excl(id="fp-2026-04-14-001", agent="sqli", pattern="p", file="test/a.py", line=10, reason="r")
    ]
    suggestions = aggregate_directory_suggestions(exclusions)
    assert len(suggestions) == 0
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_aggregation.py -k "directory_suggestions" -v`

Expected: FAIL with ImportError

- [ ] **Step 3: Implement `aggregate_directory_suggestions`**

Add to `src/screw_agents/aggregation.py`:

```python
_DIR_MIN_COUNT = 3


def aggregate_directory_suggestions(exclusions: list[Exclusion]) -> list[DirectorySuggestion]:
    """Detect directories where exclusions concentrate, suggesting directory-scope exclusions.

    Groups exclusions by top-level directory (first path component) per agent.
    Directories with >= _DIR_MIN_COUNT exclusions produce a suggestion.
    """
    buckets: dict[tuple[str, str], list[Exclusion]] = defaultdict(list)
    for excl in exclusions:
        if excl.quarantined:
            continue
        top_dir = excl.finding.file.split("/", 1)[0] + "/"
        key = (excl.agent, top_dir)
        buckets[key].append(excl)

    suggestions: list[DirectorySuggestion] = []
    for (agent, directory), group in buckets.items():
        if len(group) < _DIR_MIN_COUNT:
            continue

        reason_counts: dict[str, int] = defaultdict(int)
        for e in group:
            reason_counts[e.reason] += 1

        confidence: Literal["low", "medium", "high"]
        if len(group) >= 10:
            confidence = "high"
        elif len(group) >= _DIR_MIN_COUNT + 2:
            confidence = "medium"
        else:
            confidence = "low"

        suggestions.append(
            DirectorySuggestion(
                directory=directory,
                agent=agent,
                evidence={
                    "total_findings_in_directory": len(group),
                    "all_marked_false_positive": True,
                    "reason_distribution": dict(reason_counts),
                    "files_affected": sorted({e.finding.file for e in group}),
                },
                suggestion=(
                    f"Add directory-scope exclusion for {directory}** "
                    f"(top reason: '{max(reason_counts, key=reason_counts.get)}')."
                ),
                confidence=confidence,
            )
        )
    return suggestions
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_aggregation.py -v`

Expected: all 6 tests pass

- [ ] **Step 5: Commit**

```bash
git add src/screw_agents/aggregation.py tests/test_aggregation.py
git commit -m "feat(phase3a): aggregate_directory_suggestions (Feature 2)"
```

---

### Task 19: `aggregate_fp_report` (Feature 4 — Phase 4 Signal)

**Files:**
- Modify: `src/screw_agents/aggregation.py`
- Modify: `tests/test_aggregation.py`

- [ ] **Step 1: Write failing tests for FP report**

Add to `tests/test_aggregation.py`:

```python
def test_aggregate_fp_report_surfaces_top_patterns():
    """The FP report sorts patterns by count and includes example reasons."""
    from screw_agents.aggregation import aggregate_fp_report

    exclusions = [
        _excl(id=f"fp-2026-04-14-{i:03d}", agent="sqli", pattern="execute(f\"",
              file=f"src/s{i}.py", line=10, reason="static query")
        for i in range(15)
    ] + [
        _excl(id=f"fp-2026-04-14-{i+100:03d}", agent="sqli", pattern="raw_sql(*)",
              file=f"src/s{i}.py", line=20, reason="test fixture")
        for i in range(5)
    ]

    report = aggregate_fp_report(exclusions)
    assert report.scope == "project"
    assert len(report.top_fp_patterns) >= 1
    # Top pattern should be execute(f" with count 15
    assert report.top_fp_patterns[0].fp_count == 15
    assert report.top_fp_patterns[0].pattern == "execute(f\""
    assert "static query" in report.top_fp_patterns[0].example_reasons


def test_aggregate_fp_report_empty_when_no_exclusions():
    from screw_agents.aggregation import aggregate_fp_report

    report = aggregate_fp_report([])
    assert report.top_fp_patterns == []
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_aggregation.py -k "fp_report" -v`

Expected: FAIL with ImportError

- [ ] **Step 3: Implement `aggregate_fp_report`**

Add to `src/screw_agents/aggregation.py`:

```python
_FP_REPORT_TOP_N = 10
_FP_REPORT_MIN_COUNT = 3


def aggregate_fp_report(exclusions: list[Exclusion]) -> FPReport:
    """Produce a ranked list of FP patterns suitable for consumption by Phase 4 autoresearch.

    Groups by (agent, cwe, code_pattern). Returns the top _FP_REPORT_TOP_N buckets
    with count >= _FP_REPORT_MIN_COUNT, ranked by count descending.
    """
    buckets: dict[tuple[str, str, str], list[Exclusion]] = defaultdict(list)
    for excl in exclusions:
        if excl.quarantined:
            continue
        key = (excl.agent, excl.finding.cwe, excl.finding.code_pattern)
        buckets[key].append(excl)

    ranked = sorted(
        ((k, v) for k, v in buckets.items() if len(v) >= _FP_REPORT_MIN_COUNT),
        key=lambda kv: len(kv[1]),
        reverse=True,
    )[:_FP_REPORT_TOP_N]

    patterns: list[FPPattern] = []
    for (agent, cwe, pattern), group in ranked:
        reasons = list({e.reason for e in group})[:5]
        patterns.append(
            FPPattern(
                agent=agent,
                cwe=cwe,
                pattern=pattern,
                fp_count=len(group),
                example_reasons=reasons,
                candidate_heuristic_refinement=(
                    f"{agent} agent may benefit from lower confidence on pattern '{pattern}' "
                    f"(seen in {len(group)} exclusions with reasons like '{reasons[0] if reasons else 'n/a'}')"
                ),
            )
        )

    return FPReport(
        generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        scope="project",
        top_fp_patterns=patterns,
    )
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_aggregation.py -v`

Expected: all 8 tests pass

- [ ] **Step 5: Commit**

```bash
git add src/screw_agents/aggregation.py tests/test_aggregation.py
git commit -m "feat(phase3a): aggregate_fp_report (Feature 4 — Phase 4 signal)"
```

---

### Task 20: `aggregate_learning` MCP Tool

**Files:**
- Modify: `src/screw_agents/engine.py`
- Modify: `src/screw_agents/server.py`
- Create: `tests/test_aggregate_learning_tool.py`

- [ ] **Step 1: Write failing test for the MCP tool**

Create `tests/test_aggregate_learning_tool.py`:

```python
"""Integration tests for the aggregate_learning MCP tool."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from screw_agents.engine import ScanEngine


def test_aggregate_learning_with_seeded_exclusions(tmp_path: Path):
    """Seed the exclusions file and call the engine method directly."""
    from screw_agents.cli.init_trust import run_init_trust
    from screw_agents.learning import record_exclusion
    from screw_agents.models import ExclusionFinding, ExclusionInput, ExclusionScope

    run_init_trust(project_root=tmp_path, name="Marco", email="marco@example.com")

    # Seed 12 exclusions for the same pattern → triggers pattern-confidence suggestion
    for i in range(12):
        record_exclusion(
            tmp_path,
            ExclusionInput(
                agent="sqli",
                finding=ExclusionFinding(
                    file=f"src/s{i}.py", line=10, code_pattern="db.text_search(*)", cwe="CWE-89"
                ),
                reason="safe internal",
                scope=ExclusionScope(type="pattern", pattern="db.text_search(*)"),
            ),
        )

    engine = ScanEngine.from_defaults()
    report = engine.aggregate_learning(project_root=tmp_path, report_type="all")
    assert "pattern_confidence" in report
    assert len(report["pattern_confidence"]) == 1
    assert report["pattern_confidence"][0]["pattern"] == "db.text_search(*)"
    assert "fp_report" in report
    assert len(report["fp_report"]["top_fp_patterns"]) >= 1


def test_aggregate_learning_filters_report_type(tmp_path: Path):
    """report_type='pattern_confidence' returns only that section."""
    engine = ScanEngine.from_defaults()
    report = engine.aggregate_learning(
        project_root=tmp_path, report_type="pattern_confidence"
    )
    assert "pattern_confidence" in report
    assert "directory_suggestions" not in report
    assert "fp_report" not in report
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_aggregate_learning_tool.py -v`

Expected: FAIL with `AttributeError: 'ScanEngine' object has no attribute 'aggregate_learning'`

- [ ] **Step 3: Add `aggregate_learning` method on ScanEngine**

In `src/screw_agents/engine.py`, add:

```python
from screw_agents.aggregation import (
    aggregate_directory_suggestions,
    aggregate_fp_report,
    aggregate_pattern_confidence,
)
from screw_agents.learning import load_exclusions


def aggregate_learning(
    self,
    *,
    project_root: Path,
    report_type: str = "all",
) -> dict[str, Any]:
    """Compute learning reports from the project's exclusions database.

    Args:
        project_root: project root directory.
        report_type: one of "all", "pattern_confidence", "directory_suggestions", "fp_report".

    Returns:
        Dict containing the requested report sections. Sections not requested
        are omitted entirely (not empty — absent). "all" returns all three.
    """
    exclusions = load_exclusions(project_root)

    result: dict[str, Any] = {}
    if report_type in ("all", "pattern_confidence"):
        result["pattern_confidence"] = [
            s.model_dump() for s in aggregate_pattern_confidence(exclusions)
        ]
    if report_type in ("all", "directory_suggestions"):
        result["directory_suggestions"] = [
            s.model_dump() for s in aggregate_directory_suggestions(exclusions)
        ]
    if report_type in ("all", "fp_report"):
        result["fp_report"] = aggregate_fp_report(exclusions).model_dump()

    return result
```

- [ ] **Step 4: Register the MCP tool in `server.py`**

In `src/screw_agents/server.py`:

```python
# In list_tool_definitions():
Tool(
    name="aggregate_learning",
    description=(
        "Compute learning reports from the project's exclusions database. "
        "Returns pattern-confidence suggestions, directory-scope exclusion "
        "candidates, and a false-positive report for agent refinement. "
        "This is on-demand only; do NOT call after every scan."
    ),
    inputSchema={
        "type": "object",
        "properties": {
            "project_root": {"type": "string"},
            "report_type": {
                "type": "string",
                "enum": ["all", "pattern_confidence", "directory_suggestions", "fp_report"],
                "default": "all",
            },
        },
        "required": ["project_root"],
    },
),

# In _dispatch_tool():
elif name == "aggregate_learning":
    project_root = Path(arguments["project_root"])
    report_type = arguments.get("report_type", "all")
    result = self.engine.aggregate_learning(
        project_root=project_root, report_type=report_type
    )
    return [TextContent(type="text", text=json.dumps(result))]
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `uv run pytest tests/test_aggregate_learning_tool.py -v`

Expected: 2 passed

- [ ] **Step 6: Commit**

```bash
git add src/screw_agents/engine.py src/screw_agents/server.py tests/test_aggregate_learning_tool.py
git commit -m "feat(phase3a): aggregate_learning MCP tool"
```

---

### Task 21: `screw-learning-analyst` Subagent

**Files:**
- Create: `plugins/screw/agents/screw-learning-analyst.md`

- [ ] **Step 1: Write the subagent markdown file**

Create `plugins/screw/agents/screw-learning-analyst.md`:

```markdown
---
name: screw-learning-analyst
description: Analyzes the project's accumulated .screw/learning/exclusions.yaml data and presents learning insights — safe-pattern candidates, directory-scope exclusion suggestions, and a false-positive report. Invoked on demand via /screw:learning-report.
tools:
  - mcp__screw-agents__aggregate_learning
  - mcp__screw-agents__record_exclusion
---

# screw-learning-analyst

You are the learning analyst for screw-agents. Your job is to surface cross-scan
patterns from the project's accumulated exclusions database and help the user
act on them.

## Workflow

When invoked by `/screw:learning-report` or when a user asks for "learning
insights" / "aggregation report" / "false positive summary":

1. **Fetch the aggregate report.**
   Call `aggregate_learning(project_root=<absolute path to project root>, report_type="all")`.
   The response is a dict with three sections: `pattern_confidence`,
   `directory_suggestions`, `fp_report`.

2. **Present each section conversationally.**
   - **Pattern Confidence**: "You've marked N exclusions matching pattern X as FP.
     Consider adding it to the project's safe patterns."
   - **Directory Suggestions**: "All N findings in directory/ were marked FP.
     Suggest adding a directory-scope exclusion."
   - **FP Report**: "Top false-positive patterns for each agent (signal for
     future YAML tuning)."

3. **Offer follow-up actions.**
   If the user wants to accept a directory suggestion, call `record_exclusion`
   with the suggested scope. Ask for confirmation first.

## Rules

- This tool is ON-DEMAND only. Do not call `aggregate_learning` as part of any
  other workflow. Only run it when explicitly asked.
- Empty reports (no suggestions) are a valid response. Say "No actionable
  patterns yet — keep triaging and check back after you've accumulated more
  exclusions."
- Never silently accept a suggestion. Always confirm with the user before
  calling `record_exclusion` on their behalf.
- If `aggregate_learning` returns a `trust_status` section indicating quarantined
  exclusions, mention it: "Note: some exclusions are quarantined and not counted
  in this report. Review them with `screw-agents validate-exclusion <id>`."

## Output format

Present reports in Markdown sections:

```
## Pattern Confidence Suggestions
- **db.text_search(*)** (sqli, CWE-89, 12 exclusions across 8 files)
  Suggestion: Add to project-wide safe patterns.
  Confidence: high

## Directory Suggestions
- **test/** (sqli, 12 findings all marked FP)
  Suggestion: Add directory-scope exclusion for `test/**`.
  Confidence: high

## False-Positive Report (Phase 4 signal)
- **execute(f"** (sqli, CWE-89): 47 false positives
  Example reasons: static query, test fixture, bounded f-string
  Refinement candidate: lower confidence on bounded f-strings
```
```

- [ ] **Step 2: Commit**

```bash
git add plugins/screw/agents/screw-learning-analyst.md
git commit -m "feat(phase3a): screw-learning-analyst subagent"
```

---

### Task 22: `/screw:learning-report` Slash Command

**Files:**
- Create: `plugins/screw/commands/learning-report.md`

- [ ] **Step 1: Write the slash command markdown**

Create `plugins/screw/commands/learning-report.md`:

```markdown
---
description: Surface cross-scan learning insights from .screw/learning/exclusions.yaml — pattern-confidence suggestions, directory-scope exclusion candidates, and a false-positive report for future agent tuning.
---

# /screw:learning-report

Delegate to the `screw-learning-analyst` subagent:

"Present the learning report for this project by calling `aggregate_learning` on
the current project root. Show pattern-confidence suggestions, directory-scope
exclusion candidates, and the false-positive report. Offer to act on any
actionable suggestions by calling `record_exclusion` (with confirmation)."

## Notes

- This command is on-demand only. It does NOT run automatically after scans.
- The report is computed from signed exclusions only. Quarantined entries are
  excluded; run `screw-agents validate-exclusion <id>` to re-validate them.
- If there are fewer than 3 exclusions matching a pattern or directory, no
  suggestion is produced — the thresholds are conservative to avoid noise.
```

- [ ] **Step 2: Commit**

```bash
git add plugins/screw/commands/learning-report.md
git commit -m "feat(phase3a): /screw:learning-report slash command"
```

---

### Task 23: End-to-End Integration Test for Aggregation Flow

**Files:**
- Create: `tests/test_aggregation_integration.py`

- [ ] **Step 1: Write an integration test that exercises the full flow**

Create `tests/test_aggregation_integration.py`:

```python
"""End-to-end integration tests for Phase 3a PR #2 learning aggregation."""

from __future__ import annotations

from pathlib import Path

import pytest

from screw_agents.cli.init_trust import run_init_trust
from screw_agents.engine import ScanEngine
from screw_agents.learning import record_exclusion
from screw_agents.models import ExclusionFinding, ExclusionInput, ExclusionScope


def test_full_aggregation_flow_signed_exclusions(tmp_path: Path):
    """End-to-end: init-trust → record N exclusions → aggregate → validate all 3 reports."""
    # 1. Initialize trust
    run_init_trust(project_root=tmp_path, name="Marco", email="marco@example.com")

    # 2. Record 12 exclusions matching the same pattern
    for i in range(12):
        record_exclusion(
            tmp_path,
            ExclusionInput(
                agent="sqli",
                finding=ExclusionFinding(
                    file=f"src/services/s{i}.py",
                    line=42,
                    code_pattern="db.text_search(*)",
                    cwe="CWE-89",
                ),
                reason="full-text search with parameterized internals",
                scope=ExclusionScope(type="pattern", pattern="db.text_search(*)"),
            ),
        )

    # 3. Record 5 exclusions concentrated in test/ directory
    for i in range(5):
        record_exclusion(
            tmp_path,
            ExclusionInput(
                agent="sqli",
                finding=ExclusionFinding(
                    file=f"test/test_a{i}.py",
                    line=10,
                    code_pattern=f"fixture_query{i}(*)",
                    cwe="CWE-89",
                ),
                reason="test fixture data",
                scope=ExclusionScope(type="exact_line", path=f"test/test_a{i}.py"),
            ),
        )

    # 4. Aggregate via the engine
    engine = ScanEngine.from_defaults()
    report = engine.aggregate_learning(project_root=tmp_path, report_type="all")

    # 5. Verify all three sections
    assert "pattern_confidence" in report
    assert "directory_suggestions" in report
    assert "fp_report" in report

    # Pattern confidence: the db.text_search pattern is surfaced
    patterns = {s["pattern"] for s in report["pattern_confidence"]}
    assert "db.text_search(*)" in patterns

    # Directory suggestions: test/ is surfaced
    dirs = {s["directory"] for s in report["directory_suggestions"]}
    assert "test/" in dirs

    # FP report: at least one pattern surfaced
    assert len(report["fp_report"]["top_fp_patterns"]) >= 1


def test_empty_exclusions_empty_reports(tmp_path: Path):
    """With no exclusions, all three sections are present but empty."""
    engine = ScanEngine.from_defaults()
    report = engine.aggregate_learning(project_root=tmp_path, report_type="all")

    assert report["pattern_confidence"] == []
    assert report["directory_suggestions"] == []
    assert report["fp_report"]["top_fp_patterns"] == []
```

- [ ] **Step 2: Run test to verify it passes**

Run: `uv run pytest tests/test_aggregation_integration.py -v`

Expected: 2 passed

- [ ] **Step 3: Commit**

```bash
git add tests/test_aggregation_integration.py
git commit -m "test(phase3a): end-to-end integration test for aggregation flow"
```

---

## PR #2 Exit Checklist

- [ ] All tests green: `uv run pytest tests/test_aggregation.py tests/test_aggregate_learning_tool.py tests/test_aggregation_integration.py -v`
- [ ] Manual test: In Claude Code, `/screw:learning-report` produces a report section or a "no patterns yet" message
- [ ] **Downstream impact review**: open `docs/PHASE_3B_PLAN.md` and scan the "Upstream Dependencies from Phase 3a" section. Reconcile any PR #2 changes (`aggregate_learning` MCP tool schema, aggregation Pydantic model shapes, `screw-learning-analyst` subagent description, FPReport structure) against 3b tasks. 3b's script rejection flow feeds rejection reasons into the FP report — verify the data-flow contract still holds.
- [ ] PR #2 description references Phase 3a spec §7.2

---

## PR #3: Carryover Cleanup (X1 + X2 + X3)

**PR goal:** resolve three items surfaced during Phase 2 E2E testing's "Known Limitations" section.

- **X1**: `scan_domain` cursor pagination (resolves 47k–277k-token response problem)
- **X2**: Formatter polish (JSON null consistency, SARIF shortDescription, Markdown full CWE names)
- **X3**: CSV output format (long-deferred from Phase 2)

The three items are independent — they can be implemented and committed in any order within this PR. Tasks are numbered X1 first for review ergonomics.

**PR #3 exit criteria:**
- `scan_domain` responses never exceed the MCP tool-response budget (~20k tokens per page)
- Finding JSON output uses `null` consistently for optional fields
- SARIF output contains human-readable `shortDescription` sourced from agent meta
- Markdown output uses full CWE names (`CWE-89 — SQL Injection`) in section headings
- CSV output format works via `write_scan_results` with `format: "csv"`
- Phase 2 regression tests still green

---

### Task 24: Cursor Pagination Foundation in `scan_domain`

**Files:**
- Modify: `src/screw_agents/engine.py`
- Modify: `src/screw_agents/server.py`
- Create: `tests/test_pagination.py`

- [ ] **Step 1: Write failing tests for cursor pagination shape**

Create `tests/test_pagination.py`:

```python
"""Tests for scan_domain cursor pagination (Phase 3a PR #3 X1)."""

from __future__ import annotations

from pathlib import Path

import pytest

from screw_agents.engine import ScanEngine


def test_scan_domain_empty_cursor_starts_at_first_page(tmp_path: Path):
    """An empty cursor parameter reproduces the Phase 2 behavior (first page)."""
    engine = ScanEngine.from_defaults()
    result = engine.assemble_domain_scan(
        domain_name="injection-input-handling",
        target={"type": "glob", "pattern": str(tmp_path / "**")},
        project_root=tmp_path,
        cursor=None,
        page_size=50,
    )
    assert "agents" in result
    assert "next_cursor" in result
    # next_cursor may be None (no more pages) for an empty tmp_path


def test_scan_domain_pagination_returns_distinct_pages(tmp_path: Path):
    """With seeded fixture files, page 1 and page 2 contain different results."""
    # Create 100 files to force pagination
    src = tmp_path / "src"
    src.mkdir()
    for i in range(100):
        (src / f"file_{i}.py").write_text(f"# fixture {i}\n")

    engine = ScanEngine.from_defaults()
    page1 = engine.assemble_domain_scan(
        domain_name="injection-input-handling",
        target={"type": "glob", "pattern": str(src / "*.py")},
        project_root=tmp_path,
        cursor=None,
        page_size=30,
    )
    assert page1["next_cursor"] is not None

    page2 = engine.assemble_domain_scan(
        domain_name="injection-input-handling",
        target={"type": "glob", "pattern": str(src / "*.py")},
        project_root=tmp_path,
        cursor=page1["next_cursor"],
        page_size=30,
    )

    # The resolved_files list in page 2 should NOT overlap with page 1
    # (each page covers a different slice of the file list)
    files_page1 = set()
    files_page2 = set()
    for agent_result in page1.get("agents", {}).values():
        files_page1.update(agent_result.get("resolved_files", []))
    for agent_result in page2.get("agents", {}).values():
        files_page2.update(agent_result.get("resolved_files", []))
    assert files_page1.isdisjoint(files_page2) or not files_page1 or not files_page2


def test_scan_domain_cursor_is_opaque_token(tmp_path: Path):
    """The cursor must be a string — subagents treat it as an opaque value."""
    engine = ScanEngine.from_defaults()
    result = engine.assemble_domain_scan(
        domain_name="injection-input-handling",
        target={"type": "glob", "pattern": str(tmp_path / "**")},
        project_root=tmp_path,
        cursor=None,
        page_size=50,
    )
    if result["next_cursor"] is not None:
        assert isinstance(result["next_cursor"], str)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_pagination.py -v`

Expected: FAIL — current `assemble_domain_scan` does not accept `cursor` or `page_size`

- [ ] **Step 3: Extend `assemble_domain_scan` with pagination**

Modify `src/screw_agents/engine.py`:

```python
import base64
import json as _json


def assemble_domain_scan(
    self,
    *,
    domain_name: str,
    target: dict,
    project_root: Path | None = None,
    cursor: str | None = None,
    page_size: int = 50,
) -> dict:
    """Assemble a scan across all agents in a domain, with cursor-based pagination.

    The cursor is an opaque base64-encoded JSON token encoding
    {"target_hash": str, "offset": int}. Empty/None cursor starts at offset 0.

    Args:
        domain_name: CWE-1400 domain name (e.g., "injection-input-handling").
        target: target spec dict (see PRD §5).
        project_root: optional project root for exclusions + trust.
        cursor: opaque pagination token from a previous call.
        page_size: max number of resolved files per page.

    Returns:
        Dict with keys:
            agents: per-agent scan responses for this page's file slice
            next_cursor: string token for the next page, or None if done
            trust_status: same as assemble_scan
    """
    # Resolve the full file list once
    all_files = self.resolver.resolve(target=target)

    # Hash the target for cursor stability
    target_hash = self._target_hash(target)

    # Decode cursor
    if cursor:
        try:
            decoded = _json.loads(base64.urlsafe_b64decode(cursor).decode("utf-8"))
            if decoded.get("target_hash") != target_hash:
                raise ValueError(
                    "cursor is from a different target_hash; refusing to use"
                )
            offset = int(decoded["offset"])
        except Exception as exc:
            raise ValueError(f"Invalid cursor: {exc}") from exc
    else:
        offset = 0

    # Slice the file list to this page
    page_files = all_files[offset:offset + page_size]
    next_offset = offset + len(page_files)
    if next_offset < len(all_files):
        next_cursor = base64.urlsafe_b64encode(
            _json.dumps({"target_hash": target_hash, "offset": next_offset}).encode("utf-8")
        ).decode("ascii")
    else:
        next_cursor = None

    # Run each agent in the domain against the page's file slice
    page_target = {"type": "file_list", "files": page_files}
    agents_responses = {}
    for agent_name in self.registry.list_agents_in_domain(domain_name):
        agents_responses[agent_name] = self.assemble_scan(
            agent_name=agent_name,
            target=page_target,
            project_root=project_root,
        )

    result: dict[str, Any] = {
        "agents": agents_responses,
        "next_cursor": next_cursor,
        "page_size": page_size,
        "total_files": len(all_files),
        "offset": offset,
    }
    if project_root is not None:
        result["trust_status"] = self.verify_trust(project_root=project_root)
    return result


def _target_hash(self, target: dict) -> str:
    """Deterministic hash of a target spec for cursor stability."""
    import hashlib

    canonical = _json.dumps(target, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]
```

Also ensure `resolver.resolve` supports a `file_list` target type — if not, add it:

```python
# In resolver.py, in the resolve() dispatcher:
if target["type"] == "file_list":
    return target["files"]
```

- [ ] **Step 4: Update `server.py` to pass cursor through**

In `src/screw_agents/server.py`, update the `scan_domain` tool schema and dispatcher to accept `cursor` and `page_size`:

```python
# In list_tool_definitions() → scan_domain Tool:
inputSchema={
    "type": "object",
    "properties": {
        "domain_name": {"type": "string"},
        "target": {"type": "object"},
        "project_root": {"type": "string"},
        "cursor": {
            "type": ["string", "null"],
            "description": (
                "Opaque pagination token from a previous scan_domain call. "
                "Pass null or omit on the first call. When next_cursor is "
                "null in the response, pagination is complete."
            ),
            "default": None,
        },
        "page_size": {
            "type": "integer",
            "description": "Max resolved files per page. Defaults to 50.",
            "default": 50,
        },
    },
    "required": ["domain_name", "target"],
},

# In _dispatch_tool():
elif name == "scan_domain":
    domain_name = arguments["domain_name"]
    target = arguments["target"]
    project_root = Path(arguments["project_root"]) if arguments.get("project_root") else None
    cursor = arguments.get("cursor")
    page_size = arguments.get("page_size", 50)
    result = self.engine.assemble_domain_scan(
        domain_name=domain_name,
        target=target,
        project_root=project_root,
        cursor=cursor,
        page_size=page_size,
    )
    return [TextContent(type="text", text=json.dumps(result))]
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `uv run pytest tests/test_pagination.py -v`

Expected: 3 passed

- [ ] **Step 6: Commit**

```bash
git add src/screw_agents/engine.py src/screw_agents/server.py src/screw_agents/resolver.py tests/test_pagination.py
git commit -m "feat(phase3a): scan_domain cursor pagination (X1)"
```

---

### Task 25: Update Subagent Prompts for Pagination Loop

**Files:**
- Modify: `plugins/screw/agents/screw-injection.md`
- Modify: `plugins/screw/agents/screw-full-review.md`

- [ ] **Step 1: Add a pagination-handling section to each orchestrator prompt**

Edit `plugins/screw/agents/screw-injection.md`. Find the existing `scan_domain` workflow step and add a pagination loop:

```markdown
### Step: Paginate through scan_domain results

After calling `scan_domain` with the user's target, inspect the response:

1. Process the findings from `agents.<agent_name>` for each agent in the response
2. Check `next_cursor` in the response:
   - If `next_cursor` is `null`, pagination is complete — proceed to write_scan_results
   - If `next_cursor` is a string, call `scan_domain` again with:
     - The SAME `domain_name`, `target`, `project_root`
     - `cursor` set to the returned value
     - (optionally) the same `page_size`
   - Accumulate findings across pages before calling `write_scan_results`
3. After all pages are consumed, merge findings and call `write_scan_results` ONCE
   with the full accumulated findings list

Do NOT call `write_scan_results` per-page — it overwrites the previous page's
output file. Accumulate first, then write once.

If a single page's response exceeds ~15k tokens, that's the expected behavior
— pagination is working as designed. Just loop and accumulate.
```

Apply the same update to `screw-full-review.md`.

- [ ] **Step 2: Commit**

```bash
git add plugins/screw/agents/screw-injection.md plugins/screw/agents/screw-full-review.md
git commit -m "docs(phase3a): subagent prompts handle scan_domain pagination loop"
```

---

### Task 26: Integration Test for Pagination End-to-End

**Files:**
- Modify: `tests/test_pagination.py`

- [ ] **Step 1: Write an integration test that walks all pages**

Add to `tests/test_pagination.py`:

```python
def test_pagination_walks_all_files_without_duplicates(tmp_path: Path):
    """Full pagination loop: starting from None cursor, walk until next_cursor is None."""
    src = tmp_path / "src"
    src.mkdir()
    total_files = 150
    for i in range(total_files):
        (src / f"file_{i}.py").write_text(f"# fixture {i}\n")

    engine = ScanEngine.from_defaults()
    all_visited: set[str] = set()
    cursor: str | None = None
    pages_consumed = 0

    while True:
        result = engine.assemble_domain_scan(
            domain_name="injection-input-handling",
            target={"type": "glob", "pattern": str(src / "*.py")},
            project_root=tmp_path,
            cursor=cursor,
            page_size=25,
        )
        pages_consumed += 1
        for agent_result in result["agents"].values():
            for path in agent_result.get("resolved_files", []):
                assert path not in all_visited, f"duplicate file across pages: {path}"
                all_visited.add(path)

        if result["next_cursor"] is None:
            break
        cursor = result["next_cursor"]

        # Safety: don't loop forever in a broken impl
        assert pages_consumed < 20, "pagination did not terminate"

    assert len(all_visited) == total_files
```

- [ ] **Step 2: Run the test**

Run: `uv run pytest tests/test_pagination.py::test_pagination_walks_all_files_without_duplicates -v`

Expected: PASS

- [ ] **Step 3: Commit**

```bash
git add tests/test_pagination.py
git commit -m "test(phase3a): pagination walks all files without duplicates"
```

---

### Task 27: X2.1 — Null Defaults for `Finding.impact` and `Finding.exploitability`

**Files:**
- Modify: `src/screw_agents/models.py`
- Modify: `tests/test_models.py`

- [ ] **Step 1: Write failing test**

Add to `tests/test_models.py`:

```python
def test_finding_impact_default_is_none():
    """Phase 2 used empty strings; Phase 3a uses None for consistency with SARIF nullability."""
    from screw_agents.models import Finding

    finding = Finding(
        file="src/a.py",
        line=10,
        cwe="CWE-89",
        agent="sqli",
        severity="high",
        message="test",
        code_snippet="db.execute(user_input)",
    )
    assert finding.impact is None
    assert finding.exploitability is None
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_models.py::test_finding_impact_default_is_none -v`

Expected: FAIL (current default is `""`)

- [ ] **Step 3: Change the defaults in `Finding`**

In `src/screw_agents/models.py`, locate the `Finding` class and change:

```python
class Finding(BaseModel):
    # ... existing fields ...
    impact: str | None = None         # was: impact: str = ""
    exploitability: str | None = None # was: exploitability: str = ""
    # ... remaining fields ...
```

- [ ] **Step 4: Run the test**

Run: `uv run pytest tests/test_models.py -v`

Expected: all tests pass

- [ ] **Step 5: Commit**

```bash
git add src/screw_agents/models.py tests/test_models.py
git commit -m "fix(phase3a): Finding.impact and exploitability default to None (X2.1)"
```

---

### Task 28: X2.1 — JSON Formatter Emits `null`

**Files:**
- Modify: `src/screw_agents/formatter.py`
- Modify: `tests/test_formatter.py`

- [ ] **Step 1: Write failing test**

Add to `tests/test_formatter.py`:

```python
def test_json_formatter_emits_null_for_none_fields():
    """Optional fields left as None must serialize to `null` in JSON, not empty string."""
    import json

    from screw_agents.formatter import format_findings
    from screw_agents.models import Finding

    finding = Finding(
        file="src/a.py",
        line=10,
        cwe="CWE-89",
        agent="sqli",
        severity="high",
        message="test",
        code_snippet="db.execute(x)",
    )
    out = format_findings([finding], format="json", scan_metadata={"agent": "sqli"})
    parsed = json.loads(out)
    assert parsed["findings"][0]["impact"] is None
    assert parsed["findings"][0]["exploitability"] is None
```

- [ ] **Step 2: Run test to verify it passes (since Pydantic will handle this automatically)**

Run: `uv run pytest tests/test_formatter.py::test_json_formatter_emits_null_for_none_fields -v`

Expected: PASS (Pydantic `model_dump()` emits `None` as `null` in JSON by default)

- [ ] **Step 3: If the test fails, adjust the formatter**

If `format_findings` is manually filling empty strings, locate the JSON branch and change:

```python
# In the JSON formatter path, ensure finding.model_dump() is used directly
# without any post-processing that would convert None to "".
```

- [ ] **Step 4: Re-run full test suite**

Run: `uv run pytest -v`

Expected: all tests pass

- [ ] **Step 5: Commit**

```bash
git add src/screw_agents/formatter.py tests/test_formatter.py
git commit -m "fix(phase3a): JSON formatter emits null for None fields (X2.1)"
```

---

### Task 29: X2.2 — `short_description` Field in YAML Agent Meta Schema

**Files:**
- Modify: `src/screw_agents/models.py`
- Modify: `tests/test_models.py`

- [ ] **Step 1: Write failing test**

Add to `tests/test_models.py`:

```python
def test_agent_meta_has_short_description_field():
    from screw_agents.models import AgentMeta

    meta = AgentMeta(
        cwe=["CWE-89"],
        capec=[],
        owasp=[],
        sources=[],
        short_description="SQL injection via unsafe string concatenation in database queries",
    )
    assert meta.short_description.startswith("SQL injection")


def test_agent_meta_short_description_optional_for_backcompat():
    from screw_agents.models import AgentMeta

    meta = AgentMeta(cwe=["CWE-89"], capec=[], owasp=[], sources=[])
    assert meta.short_description is None
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_models.py -k "short_description" -v`

Expected: FAIL

- [ ] **Step 3: Add the field to `AgentMeta`**

In `src/screw_agents/models.py`, locate `AgentMeta` and add:

```python
class AgentMeta(BaseModel):
    # ... existing fields ...
    short_description: str | None = None
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_models.py -v`

Expected: all tests pass

- [ ] **Step 5: Commit**

```bash
git add src/screw_agents/models.py tests/test_models.py
git commit -m "feat(phase3a): AgentMeta.short_description field (X2.2)"
```

---

### Task 30: X2.2 — Populate `short_description` in 4 Existing YAML Agents

**Files:**
- Modify: `domains/injection-input-handling/sqli.yaml`
- Modify: `domains/injection-input-handling/cmdi.yaml`
- Modify: `domains/injection-input-handling/ssti.yaml`
- Modify: `domains/injection-input-handling/xss.yaml`

- [ ] **Step 1: Add `short_description` to each YAML agent's `meta` section**

In `domains/injection-input-handling/sqli.yaml`, in the `meta:` section:

```yaml
meta:
  cwe:
    - CWE-89
  # ... other existing fields ...
  short_description: "SQL injection via unsafe string concatenation, interpolation, or ORM raw query misuse reaching database query execution paths"
```

In `cmdi.yaml`:

```yaml
meta:
  short_description: "OS command injection via unsanitized user input reaching shell execution, subprocess calls, or argument construction"
```

In `ssti.yaml`:

```yaml
meta:
  short_description: "Server-side template injection via user input reaching template engine rendering without sandboxing or autoescape"
```

In `xss.yaml`:

```yaml
meta:
  short_description: "Cross-site scripting via unsanitized user input reflected into HTML, JavaScript, or other browser-executed contexts"
```

- [ ] **Step 2: Write a verification test**

Add to `tests/test_registry.py` (or create if absent):

```python
def test_all_phase1_agents_have_short_description():
    from screw_agents.registry import AgentRegistry

    registry = AgentRegistry.from_defaults()
    for agent_name in ("sqli", "cmdi", "ssti", "xss"):
        agent = registry.get(agent_name)
        assert agent.meta.short_description is not None
        assert len(agent.meta.short_description) > 20  # not trivial
```

- [ ] **Step 3: Run tests**

Run: `uv run pytest tests/test_registry.py::test_all_phase1_agents_have_short_description -v`

Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add domains/injection-input-handling/*.yaml tests/test_registry.py
git commit -m "feat(phase3a): populate short_description in 4 Phase 1 YAML agents (X2.2)"
```

---

### Task 31: X2.2 — SARIF Formatter Uses `short_description`

**Files:**
- Modify: `src/screw_agents/formatter.py`
- Modify: `tests/test_formatter.py`

- [ ] **Step 1: Write failing test**

Add to `tests/test_formatter.py`:

```python
def test_sarif_short_description_uses_agent_meta(tmp_path):
    """SARIF shortDescription.text should come from agent.meta.short_description,
    not from cwe_name."""
    import json

    from screw_agents.formatter import format_findings
    from screw_agents.models import Finding

    finding = Finding(
        file="src/a.py",
        line=10,
        cwe="CWE-89",
        agent="sqli",
        severity="high",
        message="test",
        code_snippet="db.execute(x)",
    )
    out = format_findings([finding], format="sarif", scan_metadata={"agent": "sqli"})
    parsed = json.loads(out)
    rules = parsed["runs"][0]["tool"]["driver"]["rules"]
    assert len(rules) >= 1
    short = rules[0]["shortDescription"]["text"]
    # The sqli agent's short_description mentions "SQL injection"
    assert "SQL injection" in short
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_formatter.py::test_sarif_short_description_uses_agent_meta -v`

Expected: FAIL (current implementation uses cwe_name)

- [ ] **Step 3: Update the SARIF formatter**

In `src/screw_agents/formatter.py`, locate the SARIF rule construction and change:

```python
# Before:
"shortDescription": {"text": cwe_name},

# After:
"shortDescription": {
    "text": (
        registry.get(agent_name).meta.short_description
        or f"{cwe_id} — {cwe_name}"
    )
},
```

Ensure the formatter has access to the `AgentRegistry` — pass it in via the `format_findings` signature if not already available, or lazily load from defaults.

- [ ] **Step 4: Run tests**

Run: `uv run pytest tests/test_formatter.py -v`

Expected: all tests pass

- [ ] **Step 5: Commit**

```bash
git add src/screw_agents/formatter.py tests/test_formatter.py
git commit -m "fix(phase3a): SARIF shortDescription uses agent meta (X2.2)"
```

---

### Task 32: X2.3 — CWE Long-Name Lookup Table

**Files:**
- Modify: `src/screw_agents/formatter.py` (or create a new `src/screw_agents/cwe_names.py`)
- Modify: `tests/test_formatter.py`

- [ ] **Step 1: Write failing test**

Add to `tests/test_formatter.py`:

```python
def test_cwe_long_name_lookup():
    from screw_agents.cwe_names import CWE_LONG_NAMES

    assert CWE_LONG_NAMES["CWE-89"] == "SQL Injection"
    assert CWE_LONG_NAMES["CWE-78"] == "OS Command Injection"
    assert CWE_LONG_NAMES["CWE-79"] == "Cross-site Scripting"
    assert CWE_LONG_NAMES["CWE-1336"] == "Improper Neutralization of Special Elements Used in a Template Engine"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_formatter.py::test_cwe_long_name_lookup -v`

Expected: FAIL with ImportError

- [ ] **Step 3: Create the lookup module**

Create `src/screw_agents/cwe_names.py`:

```python
"""CWE long-name lookup table for user-facing output.

Only covers the CWEs currently in the Phase 1 active set. Extend as new agents
are added in Phase 6.
"""

CWE_LONG_NAMES: dict[str, str] = {
    "CWE-78": "OS Command Injection",
    "CWE-79": "Cross-site Scripting",
    "CWE-89": "SQL Injection",
    "CWE-94": "Code Injection",
    "CWE-1336": "Improper Neutralization of Special Elements Used in a Template Engine",
}


def long_name(cwe_id: str) -> str:
    """Return the long name for a CWE id, or the id itself if unknown."""
    return CWE_LONG_NAMES.get(cwe_id, cwe_id)
```

- [ ] **Step 4: Run the test**

Run: `uv run pytest tests/test_formatter.py::test_cwe_long_name_lookup -v`

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/screw_agents/cwe_names.py tests/test_formatter.py
git commit -m "feat(phase3a): CWE long-name lookup table (X2.3)"
```

---

### Task 33: X2.3 — Markdown Formatter Uses Full CWE Names

**Files:**
- Modify: `src/screw_agents/formatter.py`
- Modify: `tests/test_formatter.py`

- [ ] **Step 1: Write failing test**

Add to `tests/test_formatter.py`:

```python
def test_markdown_section_heading_uses_full_cwe_name():
    from screw_agents.formatter import format_findings
    from screw_agents.models import Finding

    finding = Finding(
        file="src/a.py",
        line=10,
        cwe="CWE-89",
        agent="sqli",
        severity="high",
        message="test",
        code_snippet="db.execute(x)",
    )
    out = format_findings([finding], format="markdown", scan_metadata={"agent": "sqli"})
    # Section heading should contain both the CWE id and the long name
    assert "CWE-89" in out
    assert "SQL Injection" in out
    assert "## CWE-89 — SQL Injection" in out or "### CWE-89 — SQL Injection" in out
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_formatter.py::test_markdown_section_heading_uses_full_cwe_name -v`

Expected: FAIL (current implementation uses short cwe_name)

- [ ] **Step 3: Update the Markdown formatter**

In `src/screw_agents/formatter.py`, locate the Markdown section-heading generation and change:

```python
from screw_agents.cwe_names import long_name

# Before:
md_lines.append(f"## {cwe_name}")

# After:
md_lines.append(f"## {cwe_id} — {long_name(cwe_id)}")
```

- [ ] **Step 4: Run tests**

Run: `uv run pytest tests/test_formatter.py -v`

Expected: all tests pass

- [ ] **Step 5: Commit**

```bash
git add src/screw_agents/formatter.py tests/test_formatter.py
git commit -m "fix(phase3a): Markdown formatter uses full CWE names (X2.3)"
```

---

### Task 34: X3 — `format_csv` Function + `write_scan_results` CSV Support

**Files:**
- Modify: `src/screw_agents/formatter.py`
- Modify: `src/screw_agents/results.py`
- Create: `tests/test_csv_format.py`

- [ ] **Step 1: Write failing tests for CSV output**

Create `tests/test_csv_format.py`:

```python
"""Tests for CSV output format (Phase 3a PR #3 X3)."""

from __future__ import annotations

import csv
import io
from pathlib import Path

import pytest

from screw_agents.formatter import format_csv
from screw_agents.models import Finding, FindingTriage


def test_format_csv_empty_findings():
    out = format_csv([], scan_metadata={"agent": "sqli"})
    # Header row only
    reader = csv.reader(io.StringIO(out))
    rows = list(reader)
    assert len(rows) == 1
    assert rows[0] == [
        "file", "line", "cwe", "agent", "severity", "message",
        "code_snippet", "excluded", "exclusion_ref",
    ]


def test_format_csv_single_finding():
    finding = Finding(
        file="src/a.py",
        line=10,
        cwe="CWE-89",
        agent="sqli",
        severity="high",
        message="SQLi via concatenation",
        code_snippet="db.execute('SELECT ' + user_input)",
    )
    out = format_csv([finding], scan_metadata={"agent": "sqli"})
    reader = csv.reader(io.StringIO(out))
    rows = list(reader)
    assert len(rows) == 2  # header + 1 row
    data_row = rows[1]
    assert data_row[0] == "src/a.py"
    assert data_row[1] == "10"
    assert data_row[2] == "CWE-89"
    assert data_row[3] == "sqli"
    assert data_row[4] == "high"
    assert "SQLi" in data_row[5]


def test_format_csv_includes_exclusion_status():
    finding = Finding(
        file="src/a.py",
        line=10,
        cwe="CWE-89",
        agent="sqli",
        severity="high",
        message="test",
        code_snippet="code",
        triage=FindingTriage(excluded=True, exclusion_ref="fp-2026-04-14-001"),
    )
    out = format_csv([finding], scan_metadata={"agent": "sqli"})
    reader = csv.reader(io.StringIO(out))
    rows = list(reader)
    data_row = rows[1]
    assert data_row[7] == "True"  # excluded column
    assert data_row[8] == "fp-2026-04-14-001"  # exclusion_ref


def test_write_scan_results_csv_format(tmp_path: Path):
    """write_scan_results writes a .csv file when format=csv."""
    from screw_agents.results import write_scan_results

    finding = Finding(
        file="src/a.py", line=10, cwe="CWE-89", agent="sqli",
        severity="high", message="test", code_snippet="code",
    )
    result = write_scan_results(
        project_root=tmp_path,
        agent_names=["sqli"],
        findings=[finding],
        scan_metadata={"agent": "sqli", "timestamp": "2026-04-14T10:00:00Z"},
        formats=["json", "markdown", "csv"],
    )
    assert "csv" in result["files_written"]
    csv_path = Path(result["files_written"]["csv"])
    assert csv_path.exists()
    assert csv_path.suffix == ".csv"
    content = csv_path.read_text()
    assert "src/a.py" in content
    assert "CWE-89" in content
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_csv_format.py -v`

Expected: FAIL with `ImportError: cannot import name 'format_csv'`

- [ ] **Step 3: Implement `format_csv`**

Add to `src/screw_agents/formatter.py`:

```python
import csv as _csv
import io as _io


_CSV_COLUMNS = [
    "file", "line", "cwe", "agent", "severity", "message",
    "code_snippet", "excluded", "exclusion_ref",
]


def format_csv(findings: list[Finding], scan_metadata: dict) -> str:
    """Serialize findings to CSV. Output-only — not a valid input format.

    Nested fields (triage, remediation, bypass notes) are dropped by design.
    Use JSON or SARIF for round-trip fidelity.
    """
    buf = _io.StringIO()
    writer = _csv.writer(buf, quoting=_csv.QUOTE_MINIMAL)
    writer.writerow(_CSV_COLUMNS)

    for finding in findings:
        excluded = False
        exclusion_ref = ""
        if finding.triage is not None:
            excluded = finding.triage.excluded
            exclusion_ref = finding.triage.exclusion_ref or ""

        writer.writerow([
            finding.file,
            str(finding.line),
            finding.cwe,
            finding.agent,
            finding.severity,
            finding.message,
            finding.code_snippet,
            str(excluded),
            exclusion_ref,
        ])

    return buf.getvalue()
```

- [ ] **Step 4: Extend `write_scan_results` to support CSV**

Modify `src/screw_agents/results.py`. Locate the format-dispatch section and add CSV:

```python
from screw_agents.formatter import format_csv, format_findings

# In write_scan_results:
def write_scan_results(
    *,
    project_root: Path,
    agent_names: list[str],
    findings: list[Finding],
    scan_metadata: dict,
    formats: list[str] = ["json", "markdown"],
) -> dict:
    # ... existing exclusion matching + directory creation ...

    files_written: dict[str, str] = {}
    timestamp_slug = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H-%M-%S")

    if "json" in formats:
        json_output = format_findings(findings, format="json", scan_metadata=scan_metadata)
        json_path = findings_dir / f"{prefix}-{timestamp_slug}.json"
        json_path.write_text(json_output)
        files_written["json"] = str(json_path)

    if "markdown" in formats:
        md_output = format_findings(findings, format="markdown", scan_metadata=scan_metadata)
        md_output = _render_trust_section(project_root) + md_output  # from Task 11
        md_path = findings_dir / f"{prefix}-{timestamp_slug}.md"
        md_path.write_text(md_output)
        files_written["markdown"] = str(md_path)

    if "csv" in formats:
        csv_output = format_csv(findings, scan_metadata=scan_metadata)
        csv_path = findings_dir / f"{prefix}-{timestamp_slug}.csv"
        csv_path.write_text(csv_output)
        files_written["csv"] = str(csv_path)

    # ... existing return structure, updated to include files_written dict ...
```

Update the MCP tool schema for `write_scan_results` in `server.py`:

```python
# Tool schema: add "csv" to the formats enum
"formats": {
    "type": "array",
    "items": {"type": "string", "enum": ["json", "markdown", "csv"]},
    "default": ["json", "markdown"],
},
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `uv run pytest tests/test_csv_format.py -v`

Expected: 4 passed

- [ ] **Step 6: Commit**

```bash
git add src/screw_agents/formatter.py src/screw_agents/results.py src/screw_agents/server.py tests/test_csv_format.py
git commit -m "feat(phase3a): format_csv and write_scan_results CSV support (X3)"
```

---

### Task 35: End-to-End Integration Test for All Three Carryover Items

**Files:**
- Create: `tests/test_phase3a_carryover_e2e.py`

- [ ] **Step 1: Write the integration test**

Create `tests/test_phase3a_carryover_e2e.py`:

```python
"""End-to-end integration tests for Phase 3a PR #3 carryover cleanup."""

from __future__ import annotations

import csv
import io
import json
from pathlib import Path

import pytest

from screw_agents.engine import ScanEngine
from screw_agents.models import Finding
from screw_agents.results import write_scan_results


def test_scan_domain_pagination_with_large_target(tmp_path: Path):
    """Pagination completes without error on a directory of 100+ files."""
    src = tmp_path / "src"
    src.mkdir()
    for i in range(120):
        (src / f"f{i}.py").write_text(f"# file {i}\n")

    engine = ScanEngine.from_defaults()
    cursor: str | None = None
    all_files: set[str] = set()
    pages = 0
    while pages < 10:
        result = engine.assemble_domain_scan(
            domain_name="injection-input-handling",
            target={"type": "glob", "pattern": str(src / "*.py")},
            project_root=tmp_path,
            cursor=cursor,
            page_size=30,
        )
        for agent_result in result["agents"].values():
            all_files.update(agent_result.get("resolved_files", []))
        pages += 1
        if result["next_cursor"] is None:
            break
        cursor = result["next_cursor"]

    assert len(all_files) == 120


def test_write_scan_results_all_three_formats(tmp_path: Path):
    """Running write_scan_results with all three formats writes all three files."""
    finding = Finding(
        file="src/a.py", line=10, cwe="CWE-89", agent="sqli",
        severity="high", message="test", code_snippet="db.execute(x)",
    )
    result = write_scan_results(
        project_root=tmp_path,
        agent_names=["sqli"],
        findings=[finding],
        scan_metadata={"agent": "sqli", "timestamp": "2026-04-14T10:00:00Z"},
        formats=["json", "markdown", "csv"],
    )

    assert set(result["files_written"].keys()) == {"json", "markdown", "csv"}

    # JSON has null impact (X2.1)
    json_data = json.loads(Path(result["files_written"]["json"]).read_text())
    assert json_data["findings"][0]["impact"] is None

    # Markdown has full CWE name (X2.3)
    md_content = Path(result["files_written"]["markdown"]).read_text()
    assert "CWE-89" in md_content
    assert "SQL Injection" in md_content

    # CSV is valid (X3)
    csv_content = Path(result["files_written"]["csv"]).read_text()
    reader = csv.reader(io.StringIO(csv_content))
    rows = list(reader)
    assert len(rows) == 2  # header + 1 row
    assert "CWE-89" in rows[1]
```

- [ ] **Step 2: Run the test**

Run: `uv run pytest tests/test_phase3a_carryover_e2e.py -v`

Expected: 2 passed

- [ ] **Step 3: Commit**

```bash
git add tests/test_phase3a_carryover_e2e.py
git commit -m "test(phase3a): E2E coverage for PR #3 carryover cleanup"
```

---

## PR #3 Exit Checklist

- [ ] All tests green: `uv run pytest tests/test_pagination.py tests/test_csv_format.py tests/test_phase3a_carryover_e2e.py tests/test_formatter.py tests/test_models.py tests/test_registry.py -v`
- [ ] Phase 2 regression tests still green
- [ ] Manual test in Claude Code: `/screw:scan sqli benchmarks/fixtures/sqli/vulnerable/` on a large fixture directory completes without token-limit errors
- [ ] Manual test: `write_scan_results` with `format: "csv"` produces a valid CSV file under `.screw/findings/`
- [ ] **Downstream impact review**: open `docs/PHASE_3B_PLAN.md` and scan the "Upstream Dependencies from Phase 3a" section. Reconcile any PR #3 changes (`scan_domain` cursor pagination signature, `Finding.impact`/`Finding.exploitability` being `None`, `format_csv` availability in `write_scan_results`, SARIF `shortDescription` shape, Markdown CWE-naming convention) against 3b tasks that reference them. 3b's adaptive findings flow through the same `Finding` model and `write_scan_results` tool — any schema drift must be mirrored.
- [ ] PR #3 description references Phase 3a spec §7.3

---

## Phase 3a Completion Criteria

When all three PRs are merged:

1. **Signing infrastructure live.** Every exclusion in `.screw/learning/exclusions.yaml` is either signed by a trusted reviewer or explicitly quarantined.
2. **Learning reports available.** `/screw:learning-report` produces the three aggregation outputs on demand.
3. **Carryover items resolved.** `scan_domain` pagination, formatter polish, and CSV output format all working.
4. **All tests green.** No regression from Phase 2 behavior.
5. **Manual E2E validation complete.** Run through the full round-trip manual test (PR #1 exit checklist) plus a sample `/screw:learning-report` invocation on seeded exclusions.
6. **PROJECT_STATUS.md updated.** Mark Phase 3a complete with PR references and exit dates.
7. **Phase 3b plan written.** Draft `docs/PHASE_3B_PLAN.md` based on the stable Phase 3a infrastructure.

Only after step 7 does Phase 3b implementation begin — matching the strict sequential phase rule.

---

## Self-Review Checklist (for the plan author)

- [ ] Every task in the spec §7 has a corresponding task in this plan
- [ ] Every PR has an exit checklist and maps cleanly to spec sections
- [ ] No `TBD`, `TODO`, or `implement later` in any step
- [ ] Every code step shows the actual code, not a description
- [ ] Type names and function signatures are consistent across tasks
- [ ] File paths are exact (no relative ambiguity)
- [ ] Commit messages are concrete and tied to the task
- [ ] Deferred items from the spec are flagged in this plan

---

*End of Phase 3a implementation plan.*
