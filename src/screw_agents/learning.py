"""Persistent false-positive learning — exclusion storage and matching.

Phase 2 implements layers 1-2 of PRD §11.2:
  Layer 1: Exclusion storage in .screw/learning/exclusions.yaml
  Layer 2: Pre-scan filtering via scope-based matching

Layers 3 (aggregation) and 4 (feedback loop) are Phase 3 scope.
"""

from __future__ import annotations

import fnmatch
import re
import sys
import warnings
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal
import yaml

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from screw_agents.models import Exclusion, ExclusionInput, ScrewConfig
from screw_agents.trust import (
    _find_matching_reviewer,
    _fingerprint_public_key,
    _load_public_keys_with_reviewers,
    _public_key_to_openssh_line,
    canonicalize_exclusion,
    load_config,
    sign_content,
    verify_exclusion,
)

_EXCLUSIONS_PATH = Path(".screw") / "learning" / "exclusions.yaml"
_LOCAL_KEY_DIR = Path(".screw") / "local" / "keys"
_LOCAL_PRIV_NAME = "screw-local.ed25519"


def _get_or_create_local_private_key(
    project_root: Path,
) -> tuple[Ed25519PrivateKey, str]:
    """Return the local Ed25519 private key, generating one if absent.

    On first use, creates `.screw/local/keys/screw-local.ed25519` with 0600 perms
    containing the raw private key bytes (32 bytes). Subsequent calls load the
    existing key.

    Returns (private_key, openssh_public_key_line) so callers can both sign and
    register the public key in .screw/config.yaml via init-trust.

    Phase 3b Task 13 (script signing) consumes this helper directly — the shape
    is listed as an upstream dependency in PHASE_3B_PLAN.md.
    """
    key_dir = project_root / _LOCAL_KEY_DIR
    key_path = key_dir / _LOCAL_PRIV_NAME

    if not key_path.exists():
        key_dir.mkdir(parents=True, exist_ok=True)
        # T9-M3 — best-effort tighten directory perms to user-only access.
        # Defense-in-depth: even though the key file itself is 0o600, an
        # attacker who can traverse `.screw/local/keys/` can still observe
        # the file's existence and metadata. Swallow OSError (e.g., on
        # filesystems that don't support POSIX modes like FAT/exFAT or
        # under platform-specific failures) — the key file's own perms
        # remain the primary defense.
        try:
            key_dir.chmod(0o700)
        except OSError:
            pass
        priv = Ed25519PrivateKey.generate()
        key_path.write_bytes(
            priv.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
        # T9-M2 — chmod(0o600) is a no-op on Windows (only the read-only bit
        # is set). On Windows, the key file is readable by every local
        # account. Warn loudly so users understand the gap. Proper Windows
        # DACL implementation via pywin32 is a follow-up.
        if sys.platform == "win32":
            warnings.warn(
                f"Local signing key created on Windows without ACL restriction "
                f"at {key_path}; file may be readable by other local accounts. "
                f"For multi-user systems, store the key on a path with "
                f"restricted DACLs.",
                stacklevel=2,
            )
        else:
            key_path.chmod(0o600)
        # T9-M5 — `priv` from Ed25519PrivateKey.generate() is already usable;
        # no need to round-trip through disk read.
    else:
        priv_bytes = key_path.read_bytes()
        priv = Ed25519PrivateKey.from_private_bytes(priv_bytes)

    pub_line = _public_key_to_openssh_line(
        priv.public_key(), comment=f"screw-local@{project_root.name}"
    )
    return priv, pub_line


def load_exclusions(
    project_root: Path,
    *,
    config: ScrewConfig | None = None,
) -> list[Exclusion]:
    """Read exclusions from .screw/learning/exclusions.yaml with signature verification.

    For each exclusion:
      - Unsigned entries → apply the project's `legacy_unsigned_exclusions` policy
        (reject/warn/allow). Under `reject`, the entry is returned with
        `quarantined=True`. Under `warn` and `allow`, it is returned with
        `quarantined=False` (the scan reporter surfaces warn-policy entries).
      - Signed entries → call `verify_exclusion` (Model A — signature + signer
        identity cross-check). Any failure (mismatch, untrusted key, identity
        mismatch) sets `quarantined=True`.

    The full list is returned — quarantined AND trusted entries. The caller
    (engine.py, results.py) decides what to do with quarantined entries
    (skip them in pre-scan filtering, count them in scan reports, etc.).

    Args:
        project_root: Project root directory.
        config: Optional pre-loaded ScrewConfig. When provided, the per-call
            `load_config(project_root)` is skipped (saves one disk read +
            YAML parse). Used by `record_exclusion` to avoid loading config
            twice on the write path. T9-I4.

    Returns:
        List of Exclusion objects. Empty list if file doesn't exist.

    Raises:
        ValueError: If the YAML is malformed or unparseable.

    Side effects:
        May create `.screw/` directory and `.screw/config.yaml` stub via
        `trust.load_config` when exclusions exist AND no config is supplied.
        Empty projects (no exclusions file) are purely read-only — the early
        return on a missing exclusions file short-circuits before the
        config-load side effect. Callers that pre-load config see no
        side effect from this function.
    """
    path = project_root / _EXCLUSIONS_PATH
    if not path.exists():
        return []

    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ValueError(f"Malformed exclusions YAML at {path}: {exc}") from exc

    if raw is None or not isinstance(raw, dict):
        return []

    entries = raw.get("exclusions", [])
    if not entries:
        return []

    # Load project config — auto-generates the stub (with fail-safe
    # `legacy_unsigned_exclusions: reject`) if the file is missing.
    # T9-I4 — accept caller-supplied config to avoid double-load on the
    # record_exclusion write path.
    if config is None:
        config = load_config(project_root)

    result: list[Exclusion] = []
    for entry in entries:
        exclusion = Exclusion.model_validate(entry)
        _apply_trust_policy(exclusion, config=config)
        result.append(exclusion)

    return result


def _apply_trust_policy(exclusion: Exclusion, *, config: ScrewConfig) -> None:
    """Set `exclusion.trust_state` and `exclusion.quarantined` based on
    verification + legacy policy.

    Called by `load_exclusions` for each loaded entry. Mutates the exclusion
    in-place. Both fields are declared with `exclude=True` on the pydantic
    model, so these runtime flags are never persisted to YAML on write.

    Policy (single-assignment — `quarantined` is derived from `trust_state`):
      - Unsigned (no signature or no signed_by):
          reject → trust_state='quarantined'
          warn   → trust_state='warned'
          allow  → trust_state='allowed'
      - Signed: call `verify_exclusion`; any `valid=False` (bad signature,
        untrusted key, identity mismatch) → trust_state='quarantined'.
        `valid=True` → trust_state='trusted'.
      - quarantined is computed as (trust_state == 'quarantined').
    """
    state: Literal["trusted", "warned", "quarantined", "allowed"]

    if exclusion.signature is None or exclusion.signed_by is None:
        policy = config.legacy_unsigned_exclusions
        state = {
            "reject": "quarantined",
            "warn": "warned",
            "allow": "allowed",
        }[policy]
    else:
        verification = verify_exclusion(exclusion, config=config)
        state = "trusted" if verification.valid else "quarantined"

    exclusion.trust_state = state
    exclusion.quarantined = state == "quarantined"


def record_exclusion(project_root: Path, exclusion: ExclusionInput) -> Exclusion:
    """Record a new exclusion in .screw/learning/exclusions.yaml, signed with the local key.

    Creates the directory and file if they don't exist. Assigns a unique ID with
    format fp-YYYY-MM-DD-NNN (sequential per day). Signs the canonical form with
    the local Ed25519 key (auto-generated in .screw/local/keys/ on first use).

    The `signed_by` field is set to the email of the reviewer whose public key
    fingerprint matches the local signing key. This matches Task 7.1 Model A
    verification semantics — the claimed signer must actually own the signing
    key. If no reviewer matches (pre-`init-trust`), fall back to
    `local@<project_name>` and accept that the entry will be quarantined on
    reload until the key is registered.
    """
    path = project_root / _EXCLUSIONS_PATH
    path.parent.mkdir(parents=True, exist_ok=True)

    # T9-I4 — load config ONCE, share with load_exclusions (saves one
    # disk read + YAML parse on the write path).
    config = load_config(project_root)

    existing = (
        load_exclusions(project_root, config=config) if path.exists() else []
    )

    now = datetime.now(timezone.utc)
    date_str = now.strftime("%Y-%m-%d")
    today_prefix = f"fp-{date_str}-"
    today_ids = [e.id for e in existing if e.id.startswith(today_prefix)]
    next_seq = len(today_ids) + 1
    exclusion_id = f"{today_prefix}{next_seq:03d}"

    # Load the local signing key FIRST so we can pick the matching reviewer.
    # pub_line is unused here — Task 12's init-trust is the explicit
    # registration path into config.exclusion_reviewers; record_exclusion
    # only signs and never registers.
    priv, _pub_line = _get_or_create_local_private_key(project_root)

    # Determine the signer identity by matching the local key's fingerprint to
    # a reviewer entry in config.yaml. Under Task 7.1's Model A verification,
    # `signed_by` must equal the email of the reviewer whose key matches this
    # signature — otherwise reload triggers an identity mismatch and quarantine.
    # T9-I4 — config was loaded above; reuse it.
    keys_with_reviewers, _dropped = _load_public_keys_with_reviewers(
        config.exclusion_reviewers
    )
    local_fingerprint = _fingerprint_public_key(priv.public_key())
    matching_reviewer = _find_matching_reviewer(
        local_fingerprint, keys_with_reviewers
    )

    if matching_reviewer is not None:
        signer_email = matching_reviewer.email
    else:
        # Pre-init-trust: no reviewer's key matches our local key. The entry
        # will be quarantined on reload until `screw-agents init-trust` registers
        # this machine's key in exclusion_reviewers.
        #
        # T9-M1 — sanitize project_root.name for RFC-5321 compliance.
        # Project directory names can legitimately contain spaces, '@',
        # Unicode, etc. Collapse anything outside the safe local-part
        # alphabet ([A-Za-z0-9._-]) to '-'. Falls back to 'project' if
        # sanitization yields the empty string.
        safe_name = re.sub(r"[^a-zA-Z0-9._-]", "-", project_root.name) or "project"
        signer_email = f"local@{safe_name}"
        # T9-M9 — emit a UserWarning so the user understands their entry will
        # be quarantined on reload (silent fallback was a footgun).
        warnings.warn(
            f"No matching reviewer found for local signing key fingerprint "
            f"{local_fingerprint}; exclusion {exclusion_id} will be quarantined "
            f"on next load. Run `screw-agents init-trust` to register the "
            f"local key.",
            stacklevel=2,
        )

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

    # Sign the canonical form with the local Ed25519 key (loaded above)
    canonical = canonicalize_exclusion(saved)
    saved.signature = sign_content(canonical, private_key=priv)

    existing.append(saved)
    # T11-N1 — no `exclude=` here. The Exclusion.model_dump override
    # (in models.py) unconditionally strips the runtime-only fields
    # (`_RUNTIME_ONLY_FIELDS = {"quarantined", "trust_state"}`) regardless
    # of caller args. Passing `exclude={"quarantined"}` here mis-implied that
    # only `quarantined` would be stripped, hiding the trust_state strip
    # behind the override.
    data = {
        "exclusions": [e.model_dump() for e in existing]
    }
    path.write_text(
        yaml.dump(data, default_flow_style=False, sort_keys=False),
        encoding="utf-8",
    )

    return saved


def match_exclusions(
    exclusions: list[Exclusion],
    *,
    file: str,
    line: int,
    code: str,
    agent: str,
    function: str | None = None,
) -> list[Exclusion]:
    """Return exclusions that match a finding's context.

    Args:
        exclusions: All loaded exclusions.
        file: File path of the finding.
        line: Line number of the finding.
        code: Code content at the finding location.
        agent: Agent name that produced the finding.
        function: Optional function name containing the finding.

    Returns:
        List of matching Exclusion objects.

    Note:
        Quarantined exclusions (``exc.quarantined is True``) are excluded
        from matching unconditionally. This is the policy gate that enforces
        the integrity boundary established by Phase 3a's signing
        infrastructure: an entry that failed cryptographic verification, or
        that is unsigned under the ``reject`` policy, MUST NOT silently
        suppress findings in scan reports. Without this filter, a tampered
        exclusion remains visible to the report writer and produces a
        contradictory output ("1 quarantined" alongside "1 suppressed via
        the same id"). Discovered during Phase 3a PR#1 round-trip manual
        test.
    """
    matches: list[Exclusion] = []
    for exc in exclusions:
        if exc.quarantined:
            continue
        if exc.agent != agent:
            continue
        if _scope_matches(exc, file=file, line=line, code=code, function=function):
            matches.append(exc)
    return matches


def _scope_matches(
    exc: Exclusion,
    *,
    file: str,
    line: int,
    code: str,
    function: str | None,
) -> bool:
    """Check if an exclusion's scope matches the given finding context."""
    scope = exc.scope
    scope_type = scope.type

    if scope_type == "exact_line":
        return scope.path == file and exc.finding.line == line

    if scope_type == "pattern":
        if scope.pattern is None:
            return False
        return fnmatch.fnmatch(code, f"*{scope.pattern}*")

    if scope_type == "file":
        return scope.path == file

    if scope_type == "directory":
        if scope.path is None:
            return False
        dir_path = scope.path.rstrip("/") + "/"
        return file.startswith(dir_path)

    if scope_type == "function":
        return scope.path == file and scope.name == function

    return False
