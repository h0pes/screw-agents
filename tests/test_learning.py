"""Tests for the learning module — exclusion storage and matching."""

import pytest
import yaml
from pathlib import Path

from screw_agents.learning import load_exclusions, record_exclusion, match_exclusions
from screw_agents.models import Exclusion, ExclusionInput, ExclusionFinding, ExclusionScope


@pytest.fixture
def project_root(tmp_path):
    """A temporary project root with .screw/learning/ directory."""
    return tmp_path


@pytest.fixture
def exclusion_input_pattern():
    """A sample ExclusionInput with pattern scope."""
    return ExclusionInput(
        agent="sqli",
        finding=ExclusionFinding(
            file="src/api.py", line=42, code_pattern="db.text_search(*)", cwe="CWE-89"
        ),
        reason="db.text_search() uses parameterized queries internally",
        scope=ExclusionScope(type="pattern", pattern="db.text_search(*)"),
    )


@pytest.fixture
def exclusion_input_file():
    """A sample ExclusionInput with file scope."""
    return ExclusionInput(
        agent="xss",
        finding=ExclusionFinding(
            file="src/generated.py", line=10, code_pattern="render(*)", cwe="CWE-79"
        ),
        reason="generated code, not user-facing",
        scope=ExclusionScope(type="file", path="src/generated.py"),
    )


class TestLoadExclusions:
    def test_load_nonexistent_returns_empty(self, project_root):
        result = load_exclusions(project_root)
        assert result == []

    def test_load_empty_file(self, project_root):
        learning_dir = project_root / ".screw" / "learning"
        learning_dir.mkdir(parents=True)
        (learning_dir / "exclusions.yaml").write_text("exclusions: []\n")
        result = load_exclusions(project_root)
        assert result == []

    def test_load_valid_exclusions(self, project_root):
        learning_dir = project_root / ".screw" / "learning"
        learning_dir.mkdir(parents=True)
        data = {
            "exclusions": [
                {
                    "id": "fp-2026-04-11-001",
                    "created": "2026-04-11T14:35:00Z",
                    "agent": "sqli",
                    "finding": {
                        "file": "src/api.py",
                        "line": 42,
                        "code_pattern": "db.query(*)",
                        "cwe": "CWE-89",
                    },
                    "reason": "safe",
                    "scope": {"type": "pattern", "pattern": "db.query(*)"},
                    "times_suppressed": 0,
                    "last_suppressed": None,
                }
            ]
        }
        (learning_dir / "exclusions.yaml").write_text(yaml.dump(data))
        result = load_exclusions(project_root)
        assert len(result) == 1
        assert result[0].id == "fp-2026-04-11-001"
        assert result[0].agent == "sqli"

    def test_load_malformed_yaml_raises(self, project_root):
        learning_dir = project_root / ".screw" / "learning"
        learning_dir.mkdir(parents=True)
        (learning_dir / "exclusions.yaml").write_text(": : invalid yaml [[[")
        with pytest.raises(ValueError, match="[Mm]alformed"):
            load_exclusions(project_root)


class TestRecordExclusion:
    def test_record_creates_file_and_dirs(self, project_root, exclusion_input_pattern):
        result = record_exclusion(project_root, exclusion_input_pattern)
        assert result.id.startswith("fp-")
        assert result.agent == "sqli"
        assert result.times_suppressed == 0
        path = project_root / ".screw" / "learning" / "exclusions.yaml"
        assert path.exists()
        loaded = load_exclusions(project_root)
        assert len(loaded) == 1
        assert loaded[0].id == result.id

    def test_record_appends_to_existing(self, project_root, exclusion_input_pattern, exclusion_input_file):
        first = record_exclusion(project_root, exclusion_input_pattern)
        second = record_exclusion(project_root, exclusion_input_file)
        assert first.id != second.id
        loaded = load_exclusions(project_root)
        assert len(loaded) == 2

    def test_record_sequential_ids_same_day(self, project_root, exclusion_input_pattern, exclusion_input_file):
        first = record_exclusion(project_root, exclusion_input_pattern)
        second = record_exclusion(project_root, exclusion_input_file)
        first_seq = int(first.id.split("-")[-1])
        second_seq = int(second.id.split("-")[-1])
        assert second_seq == first_seq + 1

    def test_record_sets_created_timestamp(self, project_root, exclusion_input_pattern):
        result = record_exclusion(project_root, exclusion_input_pattern)
        assert "T" in result.created
        assert result.created.endswith("Z")


class TestMatchExclusions:
    def _make_exclusion(self, scope_type, agent="sqli", **scope_kwargs):
        return Exclusion(
            id="fp-2026-04-11-001",
            created="2026-04-11T14:35:00Z",
            agent=agent,
            finding=ExclusionFinding(
                file="src/api.py", line=42, code_pattern="db.query(*)", cwe="CWE-89"
            ),
            reason="test",
            scope=ExclusionScope(type=scope_type, **scope_kwargs),
        )

    def test_exact_line_match(self):
        exc = self._make_exclusion("exact_line", path="src/api.py")
        matches = match_exclusions([exc], file="src/api.py", line=42, code="db.query(x)", agent="sqli")
        assert len(matches) == 1

    def test_exact_line_no_match_different_line(self):
        exc = self._make_exclusion("exact_line", path="src/api.py")
        matches = match_exclusions([exc], file="src/api.py", line=99, code="db.query(x)", agent="sqli")
        assert len(matches) == 0

    def test_exact_line_no_match_different_file(self):
        exc = self._make_exclusion("exact_line", path="src/api.py")
        matches = match_exclusions([exc], file="src/other.py", line=42, code="db.query(x)", agent="sqli")
        assert len(matches) == 0

    def test_pattern_match(self):
        exc = self._make_exclusion("pattern", pattern="db.text_search(*)")
        matches = match_exclusions([exc], file="src/any.py", line=10, code="result = db.text_search(user_input)", agent="sqli")
        assert len(matches) == 1

    def test_pattern_no_match(self):
        exc = self._make_exclusion("pattern", pattern="db.text_search(*)")
        matches = match_exclusions([exc], file="src/any.py", line=10, code="cursor.execute(query)", agent="sqli")
        assert len(matches) == 0

    def test_file_match(self):
        exc = self._make_exclusion("file", path="src/generated.py")
        matches = match_exclusions([exc], file="src/generated.py", line=1, code="anything", agent="sqli")
        assert len(matches) == 1

    def test_file_no_match(self):
        exc = self._make_exclusion("file", path="src/generated.py")
        matches = match_exclusions([exc], file="src/other.py", line=1, code="anything", agent="sqli")
        assert len(matches) == 0

    def test_directory_match(self):
        exc = self._make_exclusion("directory", path="test/")
        matches = match_exclusions([exc], file="test/test_api.py", line=1, code="anything", agent="sqli")
        assert len(matches) == 1

    def test_directory_nested_match(self):
        exc = self._make_exclusion("directory", path="test/")
        matches = match_exclusions([exc], file="test/unit/test_deep.py", line=1, code="anything", agent="sqli")
        assert len(matches) == 1

    def test_directory_no_match(self):
        exc = self._make_exclusion("directory", path="test/")
        matches = match_exclusions([exc], file="src/api.py", line=1, code="anything", agent="sqli")
        assert len(matches) == 0

    def test_function_match(self):
        exc = self._make_exclusion("function", path="src/api.py", name="get_user")
        matches = match_exclusions(
            [exc], file="src/api.py", line=42, code="anything", agent="sqli", function="get_user"
        )
        assert len(matches) == 1

    def test_function_no_match_different_function(self):
        exc = self._make_exclusion("function", path="src/api.py", name="get_user")
        matches = match_exclusions(
            [exc], file="src/api.py", line=42, code="anything", agent="sqli", function="delete_user"
        )
        assert len(matches) == 0

    def test_wrong_agent_no_match(self):
        exc = self._make_exclusion("file", path="src/api.py", agent="sqli")
        matches = match_exclusions([exc], file="src/api.py", line=1, code="anything", agent="xss")
        assert len(matches) == 0

    def test_multiple_exclusions_partial_match(self):
        exc1 = self._make_exclusion("file", path="src/api.py")
        exc2 = self._make_exclusion("file", path="src/other.py")
        matches = match_exclusions([exc1, exc2], file="src/api.py", line=1, code="anything", agent="sqli")
        assert len(matches) == 1


class TestLoadExclusionsSignatureVerification:
    """Task 8 — load_exclusions applies the trust policy layer on load."""

    def test_load_exclusions_quarantines_unsigned_under_reject_policy(self, tmp_path: Path):
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

    def test_load_exclusions_applies_unsigned_under_warn_policy(self, tmp_path: Path):
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

    def test_load_exclusions_returns_valid_signed_as_trusted(self, tmp_path: Path):
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
        sig = sign_content(canonicalize_exclusion(excl), private_key=priv)
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

    def test_load_exclusions_mixed_signed_and_unsigned_policy_applies_per_entry(
        self, tmp_path: Path
    ):
        """T8-M1 — a single exclusions file with BOTH a signed-valid entry AND
        an unsigned-reject entry. Both quarantine states must be set
        independently in the same load — pins iteration semantics so a future
        refactor that short-circuits on the first quarantine is caught.
        """
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

        signed_excl = Exclusion(
            id="fp-2026-04-14-001",
            created="2026-04-14T10:00:00Z",
            agent="sqli",
            finding=ExclusionFinding(
                file="src/a.py", line=10, code_pattern="*", cwe="CWE-89"
            ),
            reason="properly signed",
            scope=ExclusionScope(type="exact_line", path="src/a.py"),
        )
        sig = sign_content(canonicalize_exclusion(signed_excl), private_key=priv)
        signed_excl.signed_by = "marco@example.com"
        signed_excl.signature = sig

        screw = tmp_path / ".screw"
        (screw / "learning").mkdir(parents=True)

        import yaml as _yaml

        unsigned_entry = {
            "id": "fp-2026-04-14-002",
            "created": "2026-04-14T10:00:00Z",
            "agent": "sqli",
            "finding": {
                "file": "src/b.py",
                "line": 20,
                "code_pattern": "*",
                "cwe": "CWE-89",
            },
            "reason": "legacy unsigned",
            "scope": {"type": "exact_line", "path": "src/b.py"},
        }
        data = {
            "exclusions": [
                signed_excl.model_dump(exclude={"quarantined"}),
                unsigned_entry,
            ]
        }
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
        assert len(exclusions) == 2
        # Order is preserved by load_exclusions iteration
        assert exclusions[0].id == "fp-2026-04-14-001"
        assert exclusions[0].quarantined is False  # signed-valid → trusted
        assert exclusions[1].id == "fp-2026-04-14-002"
        assert exclusions[1].quarantined is True  # unsigned + reject → quarantined


class TestLoadExclusionsTrustState:
    """Task 11 — _apply_trust_policy sets both trust_state and quarantined."""

    def _write_unsigned_entry(self, tmp_path: Path, policy: str) -> None:
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
        (screw / "config.yaml").write_text(
            f"version: 1\nlegacy_unsigned_exclusions: {policy}\n"
        )

    def test_unsigned_reject_policy_sets_trust_state_quarantined(self, tmp_path: Path):
        """Under reject policy (default), unsigned entries get trust_state='quarantined'."""
        self._write_unsigned_entry(tmp_path, "reject")
        loaded = load_exclusions(tmp_path)
        assert len(loaded) == 1
        assert loaded[0].trust_state == "quarantined"
        assert loaded[0].quarantined is True

    def test_unsigned_warn_policy_sets_trust_state_warned(self, tmp_path: Path):
        """Under warn policy, unsigned entries get trust_state='warned' and
        quarantined=False (applied with warning)."""
        self._write_unsigned_entry(tmp_path, "warn")
        loaded = load_exclusions(tmp_path)
        assert len(loaded) == 1
        assert loaded[0].trust_state == "warned"
        assert loaded[0].quarantined is False

    def test_unsigned_allow_policy_sets_trust_state_allowed(self, tmp_path: Path):
        """Under allow policy, unsigned entries get trust_state='allowed'."""
        self._write_unsigned_entry(tmp_path, "allow")
        loaded = load_exclusions(tmp_path)
        assert len(loaded) == 1
        assert loaded[0].trust_state == "allowed"
        assert loaded[0].quarantined is False

    def test_signed_valid_sets_trust_state_trusted(self, tmp_path: Path):
        """Signed-and-valid entries get trust_state='trusted'."""
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

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
            finding=ExclusionFinding(
                file="src/a.py", line=10, code_pattern="*", cwe="CWE-89"
            ),
            reason="signed",
            scope=ExclusionScope(type="exact_line", path="src/a.py"),
        )
        sig = sign_content(canonicalize_exclusion(excl), private_key=priv)
        excl.signed_by = "marco@example.com"
        excl.signature = sig

        screw = tmp_path / ".screw"
        (screw / "learning").mkdir(parents=True)

        data = {"exclusions": [excl.model_dump()]}
        (screw / "learning" / "exclusions.yaml").write_text(
            yaml.dump(data, default_flow_style=False, sort_keys=False)
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

        loaded = load_exclusions(tmp_path)
        assert len(loaded) == 1
        assert loaded[0].trust_state == "trusted"
        assert loaded[0].quarantined is False

    def test_signed_invalid_sets_trust_state_quarantined(self, tmp_path: Path):
        """Signed-but-invalid entries (signer not registered) get
        trust_state='quarantined'."""
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        from screw_agents.models import Exclusion, ExclusionFinding, ExclusionScope
        from screw_agents.trust import canonicalize_exclusion, sign_content

        # Sign with a key that is NOT in the config.yaml reviewers list.
        priv = Ed25519PrivateKey.generate()

        excl = Exclusion(
            id="fp-2026-04-14-001",
            created="2026-04-14T10:00:00Z",
            agent="sqli",
            finding=ExclusionFinding(
                file="src/a.py", line=10, code_pattern="*", cwe="CWE-89"
            ),
            reason="signed but untrusted",
            scope=ExclusionScope(type="exact_line", path="src/a.py"),
        )
        sig = sign_content(canonicalize_exclusion(excl), private_key=priv)
        excl.signed_by = "attacker@example.com"
        excl.signature = sig

        screw = tmp_path / ".screw"
        (screw / "learning").mkdir(parents=True)

        data = {"exclusions": [excl.model_dump()]}
        (screw / "learning" / "exclusions.yaml").write_text(
            yaml.dump(data, default_flow_style=False, sort_keys=False)
        )
        # No reviewers → any signed entry fails verification
        (screw / "config.yaml").write_text(
            "version: 1\nlegacy_unsigned_exclusions: reject\n"
        )

        loaded = load_exclusions(tmp_path)
        assert len(loaded) == 1
        assert loaded[0].trust_state == "quarantined"
        assert loaded[0].quarantined is True


class TestRecordExclusionSignsOnWrite:
    """Task 9 — record_exclusion signs new entries with the local Ed25519 key."""

    def test_record_exclusion_signs_with_local_key(self, tmp_path: Path, monkeypatch):
        """record_exclusion signs new entries with the local Ed25519 key.

        Simulates the init-trust flow: generate the local key, register its public
        key as an exclusion_reviewer in .screw/config.yaml, then record the exclusion.
        The round-trip (record → load → verify) must succeed under Task 7.1 Model A.
        """
        from screw_agents.learning import (
            _get_or_create_local_private_key,
            load_exclusions,
            record_exclusion,
        )
        from screw_agents.models import ExclusionFinding, ExclusionInput, ExclusionScope

        # SCREW_FORCE_LOCAL_KEY is a no-op placeholder today. Reserved for
        # Task 12's init-trust which will probe `~/.ssh/id_ed25519` and prefer
        # an existing user key over generating a project-local one. Setting it
        # here documents the future contract — when probing lands, this env
        # var will force the project-local path so the test stays hermetic
        # and never inadvertently consumes a developer's real SSH key.
        monkeypatch.setenv("SCREW_FORCE_LOCAL_KEY", "1")

        # Simulate `init-trust`: generate the local key and register it in config.yaml
        # BEFORE record_exclusion runs. Task 12's init-trust CLI will do this for real;
        # here we do it manually because Task 9 is the write path, not the registration path.
        _priv, pub_line = _get_or_create_local_private_key(tmp_path)
        signer_email = f"local@{tmp_path.name}"

        screw_dir = tmp_path / ".screw"
        screw_dir.mkdir(parents=True, exist_ok=True)
        (screw_dir / "config.yaml").write_text(
            f"""version: 1
legacy_unsigned_exclusions: reject
exclusion_reviewers:
  - name: Local
    email: {signer_email}
    key: "{pub_line}"
""",
            encoding="utf-8",
        )

        excl_input = ExclusionInput(
            agent="sqli",
            finding=ExclusionFinding(
                file="src/a.py", line=10, code_pattern="*", cwe="CWE-89"
            ),
            reason="test signed write",
            scope=ExclusionScope(type="exact_line", path="src/a.py"),
        )

        saved = record_exclusion(tmp_path, excl_input)
        assert saved.signed_by == signer_email
        assert saved.signature is not None
        assert saved.signature_version == 1

        # Round-trip: reload, verify passes, not quarantined
        loaded = load_exclusions(tmp_path)
        assert len(loaded) == 1
        assert loaded[0].quarantined is False
        assert loaded[0].signed_by == signer_email

    def test_record_exclusion_generates_local_key_on_first_use(
        self, tmp_path: Path, monkeypatch
    ):
        """If no local key exists in .screw/local/keys/, record_exclusion generates one.

        This test does NOT exercise the round-trip — it only verifies that the key
        file is created on first use. The round-trip test above handles the full flow.
        """
        from screw_agents.learning import record_exclusion
        from screw_agents.models import ExclusionFinding, ExclusionInput, ExclusionScope

        monkeypatch.setenv("SCREW_FORCE_LOCAL_KEY", "1")

        excl_input = ExclusionInput(
            agent="sqli",
            finding=ExclusionFinding(
                file="src/a.py", line=10, code_pattern="*", cwe="CWE-89"
            ),
            reason="key bootstrap",
            scope=ExclusionScope(type="exact_line", path="src/a.py"),
        )
        record_exclusion(tmp_path, excl_input)

        key_dir = tmp_path / ".screw" / "local" / "keys"
        assert key_dir.exists()
        # At least one key file was written
        assert any(key_dir.iterdir())

    def test_record_exclusion_multi_reviewer_picks_matching_key(
        self, tmp_path: Path, monkeypatch
    ):
        """With multiple reviewers, record_exclusion must pick the reviewer whose key
        actually matches the local signing key — NOT blindly pick exclusion_reviewers[0].

        Scenario: config has [Marco, Alice]. Alice is the machine owner (her key is
        the local signing key). Under the first-reviewer heuristic, signed_by would
        be set to marco@example.com, then Model A identity check would fail on reload
        (signature matches Alice's key, but claim says Marco). The fingerprint-based
        selector picks Alice correctly.
        """
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        from screw_agents.learning import (
            _get_or_create_local_private_key,
            load_exclusions,
            record_exclusion,
        )
        from screw_agents.models import ExclusionFinding, ExclusionInput, ExclusionScope
        from screw_agents.trust import _public_key_to_openssh_line

        monkeypatch.setenv("SCREW_FORCE_LOCAL_KEY", "1")

        # Generate a "marco" key that is NOT the local key
        marco_priv = Ed25519PrivateKey.generate()
        marco_pub_line = _public_key_to_openssh_line(
            marco_priv.public_key(), comment="marco@test"
        )

        # Generate the local key — this is what record_exclusion will sign with
        _local_priv, local_pub_line = _get_or_create_local_private_key(tmp_path)

        # Register BOTH reviewers in config.yaml, with Marco FIRST and Alice (local) SECOND.
        # The first-reviewer heuristic would pick Marco (wrong); fingerprint matching must pick Alice.
        alice_email = f"alice@{tmp_path.name}"
        screw_dir = tmp_path / ".screw"
        screw_dir.mkdir(parents=True, exist_ok=True)
        (screw_dir / "config.yaml").write_text(
            f"""version: 1
legacy_unsigned_exclusions: reject
exclusion_reviewers:
  - name: Marco
    email: marco@example.com
    key: "{marco_pub_line}"
  - name: Alice
    email: {alice_email}
    key: "{local_pub_line}"
""",
            encoding="utf-8",
        )

        excl_input = ExclusionInput(
            agent="sqli",
            finding=ExclusionFinding(
                file="src/a.py", line=10, code_pattern="*", cwe="CWE-89"
            ),
            reason="test multi-reviewer fingerprint selection",
            scope=ExclusionScope(type="exact_line", path="src/a.py"),
        )

        saved = record_exclusion(tmp_path, excl_input)

        # The first-reviewer heuristic would have picked marco@example.com (WRONG).
        # Fingerprint-based logic picks Alice because HER key matches the local key.
        assert saved.signed_by == alice_email
        assert saved.signed_by != "marco@example.com"

        # Round-trip: Model A identity cross-check succeeds because Alice's signature
        # matches Alice's claimed email.
        loaded = load_exclusions(tmp_path)
        assert len(loaded) == 1
        assert loaded[0].quarantined is False
        assert loaded[0].signed_by == alice_email

    def test_record_exclusion_without_reviewers_uses_fallback_email(
        self, tmp_path: Path, monkeypatch
    ):
        """T9-M7 — without init-trust, record_exclusion stamps the fallback
        email (`local@<sanitized-project-name>`) and the entry quarantines on
        reload because no reviewer key matches the local key. Documents the
        "didn't run init-trust" UX explicitly so a future change that flips
        the fallback path is caught.
        """
        import warnings

        from screw_agents.learning import load_exclusions, record_exclusion
        from screw_agents.models import ExclusionFinding, ExclusionInput, ExclusionScope

        monkeypatch.setenv("SCREW_FORCE_LOCAL_KEY", "1")

        excl_input = ExclusionInput(
            agent="sqli",
            finding=ExclusionFinding(
                file="src/a.py", line=10, code_pattern="*", cwe="CWE-89"
            ),
            reason="pre-init-trust attempt",
            scope=ExclusionScope(type="exact_line", path="src/a.py"),
        )

        # T9-M9 — record_exclusion emits a UserWarning on the fallback path.
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            saved = record_exclusion(tmp_path, excl_input)
            fallback_warnings = [
                w for w in caught if "init-trust" in str(w.message)
            ]
            assert fallback_warnings, "expected fallback-email warning when no reviewer matches"

        # The fallback signer email is `local@<sanitized-project-name>`.
        # Sanitization rules (T9-M1) collapse anything outside [A-Za-z0-9._-]
        # to '-'; pin only the prefix so this test stays robust across tmp_path
        # naming conventions on different platforms.
        assert saved.signed_by is not None
        assert saved.signed_by.startswith("local@")
        assert saved.signature is not None

        # On reload, no reviewer email matches the fallback → quarantine.
        loaded = load_exclusions(tmp_path)
        assert len(loaded) == 1
        assert loaded[0].quarantined is True
